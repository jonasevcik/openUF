--[[
	Client-assisted RF environment enrichment (802.11k beacon reports).

	WHY THIS EXISTS

	scan_radio_table (see inform.lua) is built from `iw dev <if> scan dump`,
	the kernel's PASSIVE BSS cache. That cache is filled from beacons the radio
	overhears on the channel it is already serving, so the Environment tab only
	ever shows near-channel neighbours: measured on an AX3000T, 6 BSSes on a
	2.4 GHz radio parked on ch 11, and exactly 1 on a 5 GHz radio on ch 44 --
	its own. openUF will not dwell off-channel behind a client's back to fix
	that; a real off-channel sweep on the same board cost 12% packet loss to an
	associated client for the ~3 s it ran.

	Ubiquiti does not solve this for free either. Their own docs describe three
	paths: a manual "Airtime Scan"/RF Scan that "may interrupt client
	connectivity while in progress", a dedicated Scanning Radio on the models
	that ship a third radio, and Channel AI, which "scans the surrounding
	wireless environment using neighbor reports and automated RRM scans".

	This module implements that last path, and only that one. In an 802.11k
	beacon measurement the CLIENT leaves the channel, scans, and reports what
	it saw; the AP never stops serving. It is the one enrichment that costs the
	AP nothing.

	WHAT IT ACTUALLY BUYS, measured live 2026-09-02

	A single beacon request to one capable client returned 15 BSSes at once,
	across 2.4 GHz channels 1/3/4/6/7/9/10/11 AND 5 GHz channels 36/44/48 --
	from a client associated on a 5 GHz radio. One client's report therefore
	enriches BOTH radios, which is why merge_into() keys on the reported
	channel's band rather than on the interface the request went out of.

	AND WHAT IT DOES NOT

	Support is a client-by-client lottery, so this can only ever supplement the
	passive cache, never replace it. Of 13 real clients surveyed across two
	APs: 9 advertised no 802.11k at all (rrm=0), 3 advertised beacon-active +
	beacon-passive and answered in full, and 1 advertised beacon-table only,
	acknowledged the request at the MAC layer (BEACON-REQ-TX-STATUS ack=1) and
	then never sent a report. Beacon-table alone is therefore NOT treated as
	capable here -- see capable_stations().

	A beacon report also carries less than a scan does: a BSSID, a channel and
	an RCPI, but no SSID, no security and no channel width. Entries that the
	passive cache already knows keep the cache's richer version; entries only
	the client can see are reported with what there is. The controller renders
	a missing WiFi Name as the BSSID, so they are still useful rows.
]]--

local M = {}

-- Injectable seams, mirroring ucihelper/bcfilter.
M._popen = function(cmd)
	local f = io.popen(cmd)
	if not f then return nil end
	local out = f:read("*a")
	f:close()
	return out
end
M._exec  = function(cmd) return os.execute(cmd) end
M._now   = function() return os.time() end

-- Where the background collector parks hostapd's ubus notifications.
M.EVENT_FILE = "/tmp/openuf-rrm.jsonl"

-- hostapd delivers a beacon report as a ubus NOTIFICATION on the per-BSS
-- object, not as a broadcast event. `ubus listen` -- which catches broadcasts
-- -- therefore sees nothing at all here, however long it waits; only
-- `ubus subscribe hostapd.<iface>` receives them. Confirmed live: a listen
-- across two requests captured zero notifications while a subscribe over the
-- same window captured 22 beacon-reports.
local SUBSCRIBE_MATCH = "ubus subscribe hostapd"

-- 802.11 RCPI is a 0.5-dBm-step scale anchored at -110 dBm (IEEE 802.11-2020
-- 9.4.2.38), so dBm = rcpi/2 - 110. Sanity-checked against reality on the
-- capture this module was written from: the reporting client sat on the
-- living-room AP's own 2.4 GHz BSS and gave it rcpi=124 -> -48 dBm, while the
-- furthest neighbour came back rcpi=32 -> -94 dBm.
function M.rcpi_to_dbm(rcpi)
	rcpi = tonumber(rcpi)
	if not rcpi then return nil end
	return math.floor(rcpi / 2 - 110)
end

-- Band for a reported channel, in the controller's own radio vocabulary.
-- Beacon reports name a channel but never a frequency, and a client answering
-- on one band routinely reports the other, so this is what decides which
-- radio's scan_table an entry belongs to.
function M.band_of_channel(ch)
	ch = tonumber(ch)
	if not ch then return nil end
	if ch >= 1 and ch <= 14 then return "ng" end
	if ch >= 32 then return "na" end
	return nil
end

-- Centre frequency for a reported channel. Beacon reports carry a channel
-- number only, while scan_table entries carry both -- and the Environment
-- tab's spectrum chart plots the frequency.
function M.freq_of_channel(ch)
	ch = tonumber(ch)
	if not ch then return nil end
	if ch == 14 then return 2484 end
	if ch >= 1 and ch <= 13 then return 2407 + 5 * ch end
	if ch >= 32 then return 5000 + 5 * ch end
	return nil
end

-- RM Enabled Capabilities bits (IEEE 802.11-2020 9.4.2.44), as hostapd's
-- get_clients exposes them in the first byte of "rrm".
local RRM_BEACON_PASSIVE = 0x10  -- bit 4
local RRM_BEACON_ACTIVE  = 0x20  -- bit 5

-- Stations on this BSS that can actually go and look. Deliberately requires
-- passive or active measurement and NOT beacon-table: a table-only client
-- reports from a cache it may never have filled, and the one real example
-- observed acked every request and answered none. hostapd agrees about the
-- direction -- asking a table-only client for a passive measurement is
-- refused by hostapd itself with "does not support passive beacon report",
-- before anything reaches the air.
function M.capable_stations(ifname)
	if not ifname then return {} end
	local out = M._popen("ubus call hostapd." .. ifname .. " get_clients 2>/dev/null") or ""
	local stations = {}
	for mac, block in out:gmatch('"(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)":%s*(%b{})') do
		local rrm = tonumber(block:match('"rrm":%s*%[%s*(%d+)')) or 0
		if rrm % (RRM_BEACON_PASSIVE * 2) >= RRM_BEACON_PASSIVE
		   or rrm % (RRM_BEACON_ACTIVE * 2) >= RRM_BEACON_ACTIVE then
			stations[#stations + 1] = mac
		end
	end
	table.sort(stations)  -- deterministic, so round-robin actually rotates
	return stations
end

-- Ask one station for a full sweep. mode 1 is ACTIVE measurement: the client
-- probes rather than only listening, which is what makes it report BSSes on
-- channels it is not sitting on. channel 255 means "every channel in this
-- operating class". op_class defaults to 115 (5 GHz U-NII-1); dual-band clients
-- observed here ignore its band restriction and answer for 2.4 GHz too, but a
-- 2.4 GHz-only client answers a 5 GHz class with report mode 0x02
-- ("incapable") and an all-zero BSSID -- nothing usable at all. So the caller
-- (inform._rrm_tick) passes 81, the 2.4 GHz class, for a station on a 2.4 GHz
-- BSS, and the dual-band bonus stays a bonus rather than the mechanism.
--
-- Fire-and-forget by design: the report comes back asynchronously as a ubus
-- notification minutes-to-never later, and is picked up by harvest().
function M.request(ifname, sta, opts)
	if not ifname or not sta then return false end
	opts = opts or {}
	local cmd = string.format(
		"ubus call hostapd.%s rrm_beacon_req " ..
		"'{\"addr\":\"%s\",\"mode\":%d,\"op_class\":%d,\"channel\":255,\"duration\":%d}' " ..
		">/dev/null 2>&1",
		ifname, sta, opts.mode or 1, opts.op_class or 115, opts.duration or 50)
	M._exec(cmd)
	return true
end

-- Is the background collector alive? It is a plain `ubus subscribe` child, so
-- this doubles as the restart trigger: the subscription dies whenever one of
-- the hostapd objects it named goes away, which a `wifi reload` does on every
-- config push.
function M.collector_running()
	local out = M._popen("pgrep -f '" .. SUBSCRIBE_MATCH .. "' 2>/dev/null") or ""
	return out:match("%d") ~= nil
end

-- Every hostapd BSS object currently on ubus.
function M.hostapd_objects()
	local out = M._popen("ubus list 2>/dev/null") or ""
	local objs = {}
	for line in out:gmatch("[^\n]+") do
		local o = line:match("^(hostapd%.[%w%-%._]+)%s*$")
		if o then objs[#objs + 1] = o end
	end
	table.sort(objs)
	return objs
end

-- (Re)start the collector across every current BSS. Safe to call on every
-- cycle: it is a no-op while one is running.
function M.collector_ensure()
	if M.collector_running() then return false end
	local objs = M.hostapd_objects()
	if #objs == 0 then return false end
	M._exec("ubus subscribe " .. table.concat(objs, " ") ..
		" >> " .. M.EVENT_FILE .. " 2>/dev/null &")
	return true
end

function M.collector_stop()
	M._exec("pkill -f '" .. SUBSCRIBE_MATCH .. "' 2>/dev/null")
	M._exec("rm -f " .. M.EVENT_FILE .. " 2>/dev/null")
end

-- Drain the notification file into neighbour records.
--
-- Parsed with patterns rather than cjson on purpose: the notification carries
-- a "start-time" holding a raw 64-bit TSF that real clients emit past what a
-- double represents (-7160986498777481216 was observed), and nothing here
-- needs it. Matching only the fields we use sidesteps the question entirely.
--
-- The file is read whole and then truncated. The collector holds it O_APPEND,
-- so a notification written between the read and the truncate is lost rather
-- than corrupted -- acceptable for opportunistic enrichment, and the next
-- request re-reports the same neighbourhood anyway.
function M.harvest()
	local f = io.open(M.EVENT_FILE, "r")
	if not f then return {}, {} end
	local blob = f:read("*a") or ""
	f:close()
	local t = io.open(M.EVENT_FILE, "w")
	if t then t:close() end

	local now, seen, out = M._now(), {}, {}
	-- Every station that produced an ANSWER, alongside the neighbours it
	-- reported. The caller uses it to tell a station that answers from one
	-- that only ever acknowledges: hostapd notifies over ubus only when a
	-- report BODY arrived, so a bodiless refusal never reaches this file at
	-- all and its ABSENCE is the only signal there is. A bodied refusal
	-- (rep-mode non-zero) is a station declining too, so it does not count
	-- here either.
	local reporters = {}
	for body in blob:gmatch('"beacon%-report":%s*(%b{})') do
		local address  = body:match('"address":"(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)"')
		local bssid    = body:match('"bssid":"(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)"')
		local channel  = tonumber(body:match('"channel":(%-?%d+)'))
		local rcpi     = tonumber(body:match('"rcpi":(%-?%d+)'))
		-- rep-mode is the measurement report mode: any non-zero value means
		-- the client refused, was incapable, or the measurement was
		-- unavailable, and those arrive with an all-zero BSSID. Reporting one
		-- would put 00:00:00:00:00:00 on ch 0 in the Environment tab.
		local repmode  = tonumber(body:match('"rep%-mode":(%-?%d+)')) or 0
		if address and repmode == 0 then reporters[address:lower()] = true end
		local band     = M.band_of_channel(channel)
		if bssid and band and repmode == 0
		   and bssid ~= "00:00:00:00:00:00" and not seen[bssid] then
			seen[bssid] = true
			out[#out + 1] = {
				bssid   = bssid,
				channel = channel,
				band    = band,
				signal  = M.rcpi_to_dbm(rcpi),
				seen_at = now,
			}
		end
	end
	return out, reporters
end

-- Merge harvested neighbours into one radio's scan_table.
--
-- `entries` is the payload-shaped list already built from the passive scan
-- cache; anything the cache knows wins, because it carries an SSID, a security
-- mode and a width that a beacon report simply does not have. Only genuinely
-- new BSSIDs on this radio's band are appended.
--
-- opts.max_age drops stale records: the controller's rogue-AP ingestion
-- silently discards any entry whose age is 30 or more, so a record held past
-- that would be payload weight nobody reads. Reporting each one for a cycle or
-- two and letting it fall out mirrors what a real scan produces, and the
-- controller keeps its own history of what it was told.
function M.merge_into(entries, neighbours, opts)
	entries = entries or {}
	opts    = opts or {}
	local band    = opts.band
	local now     = opts.now or M._now()
	local max_age = opts.max_age or 30
	local have = {}
	for _, e in ipairs(entries) do
		if e.bssid then have[e.bssid] = true end
	end
	for _, n in ipairs(neighbours or {}) do
		local age = now - (n.seen_at or now)
		if age < 0 then age = 0 end
		if n.band == band and not have[n.bssid] and age < max_age then
			have[n.bssid] = true
			entries[#entries + 1] = {
				mac        = n.bssid,
				bssid      = n.bssid,
				radio      = opts.radio,
				radio_name = opts.radio_name,
				-- `band` is the field the Environment tab filters on
				-- unconditionally; an entry without it vanishes with no
				-- visible cause. See inform.lua's note on the same field.
				band       = opts.radio,
				channel    = n.channel,
				freq       = M.freq_of_channel(n.channel),
				rssi       = n.signal,
				signal     = n.signal,
				-- A beacon report carries no SSID, no security mode and no
				-- width. Each of those absences is handled differently, and the
				-- difference matters:
				--
				-- bw is set to 20 because every AP occupies at least its 20 MHz
				-- primary channel, so it is a floor rather than a guess -- and
				-- because the Environment tab's unconditional filter indexes
				-- T.R[band][bw>0 ? bw : <a per-band default>]: a falsy bw falls
				-- through to a default this controller build may not define, and
				-- an undefined index drops the row silently. 20 is confirmed to
				-- render; nil is not.
				bw         = 20,
				age        = age,
				-- security is left ABSENT, not defaulted. There is no floor to
				-- fall back on here: writing "open" would state, in the operator's
				-- rogue-AP view, that a neighbour is unencrypted when nothing
				-- measured it. Observed live -- four WPA2 neighbours reported by a
				-- client all rendered as "open" before this was removed. A blank
				-- cell is the honest answer, and no filter keys on this field.
				security   = nil,
				essid      = nil,
			}
		end
	end
	return entries
end

return M
