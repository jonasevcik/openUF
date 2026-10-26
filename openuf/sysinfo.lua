--[[
	System metrics reader for the inform JSON payload.

	All I/O functions are injectable via M._read_file and M._run_cmd so that
	unit tests can substitute fixture data without touching the real filesystem.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable: override in tests to return fixture file contents
M._read_file = util.read_file

-- Injectable: override in tests to return fixture command output
M._run_cmd = util.capture


-- ─── Lookup pass ────────────────────────────────────────────────────────────
--
-- The same seam ucihelper.begin_pass/end_pass provides, for the same reason:
-- build_json asks several of the functions below the SAME question once per
-- socket, and the answer cannot change inside one payload. `/proc/net/arp` was
-- read five times per heartbeat and `/tmp/dhcp.leases` four (once per
-- downstream socket, from both mac_table and switch_mac_table, plus one more
-- for the default gateway), and the switch's whole ARL table was walked once
-- per socket to keep the handful of entries on it.
--
-- Scoped to a pass rather than given a TTL: both files are genuinely live
-- between heartbeats, and none of this may outlast the payload it was read
-- for. It also makes that payload internally CONSISTENT -- without it two
-- sockets in one inform can disagree about a host's IP.
--
-- Outside a pass every function below behaves exactly as it did before, which
-- is what keeps the test suite's per-test _read_file/_run_cmd stubs
-- independent of one another. inform.build_json opens the pass and closes it
-- on return; inform._tick closes it again even when build_json throws.
M._pass       = false
M._pass_cache = nil
function M.begin_pass() M._pass = true;  M._pass_cache = {} end
function M.end_pass()   M._pass = false; M._pass_cache = nil end

-- Run fn() once per pass, keyed by `key`. Outside a pass fn() runs every time.
-- A false/nil result is memoized as such (wrapped, so "computed and empty" is
-- distinguishable from "not computed"): a missing /tmp/dhcp.leases must not be
-- re-opened once per socket either.
local function pass_memo(key, fn)
	local cache = M._pass and M._pass_cache
	if cache then
		local hit = cache[key]
		if hit ~= nil then return hit[1] end
	end
	local value = fn()
	if cache then cache[key] = {value} end
	return value
end

-- One read of the kernel's ARP cache per pass. Both readers of it below --
-- _ip_by_mac for the wired-host join, _default_gateway_mac for the uplink
-- question -- go through this, so the file is opened once per payload rather
-- than once per socket plus one.
local function arp_text()
	return pass_memo("arp_text", function() return M._read_file("/proc/net/arp") end)
end

-- A {[mac] = port} map inverted into {[port] = {macs}}, multicast/broadcast
-- dropped on the address's own bit and each bucket sorted (pairs() order is
-- undefined; the payload must be stable).
--
-- Both wired-host sources hand us that exact shape -- the switch's ARL table
-- and the bridge's FDB -- and both were scanned WHOLE once per socket to keep
-- the entries on that one, O(sockets x hosts) on a switch that may have
-- learned a couple of hundred. One inversion answers every socket.
--
-- Memoized on the map TABLE, not on a name: build_json fetches one dump per
-- heartbeat and hands the same table to every socket, so a pass given a fresh
-- dump buckets it afresh rather than serving the previous one.
local function hosts_by_port(map)
	return pass_memo(map, function()
		local by_port = {}
		for mac, port in pairs(map) do
			local first_octet = tonumber(mac:sub(1, 2), 16)
			if first_octet and first_octet % 2 == 0 then
				local bucket = by_port[port]
				if not bucket then bucket = {}; by_port[port] = bucket end
				bucket[#bucket + 1] = mac
			end
		end
		for _, bucket in pairs(by_port) do table.sort(bucket) end
		return by_port
	end)
end

-- Returns uptime in seconds (as a number) by parsing /proc/uptime.
--
-- Read once per pass: build_json reports it once and scan_table reads it again
-- per radio, as the CLOCK_BOOTTIME reference for each BSS's "last seen" -- so
-- it was three opens a heartbeat on a two-radio box. It is a monotonic counter
-- whose drift across one payload is under a second, and reading it twice
-- inside one payload was the less consistent of the two anyway.
function M.uptime()
	return pass_memo("uptime", function()
		local s = M._read_file("/proc/uptime")
		if not s then return 0 end
		local secs = tonumber(s:match("^(%S+)"))
		return secs and math.floor(secs) or 0
	end)
end

-- Returns {total_kb, free_kb, buffers_kb} by parsing /proc/meminfo.
function M.meminfo()
	local s = M._read_file("/proc/meminfo")
	if not s then return {total_kb = 0, free_kb = 0, buffers_kb = 0} end
	local total = tonumber(s:match("MemTotal:%s+(%d+)"))
	local free  = tonumber(s:match("MemFree:%s+(%d+)"))
	local bufs  = tonumber(s:match("Buffers:%s+(%d+)"))
	return {
		total_kb   = total or 0,
		free_kb    = free  or 0,
		buffers_kb = bufs  or 0,
	}
end

-- The 1, 5 and 15 minute load averages as /proc/loadavg prints them
-- ("0.05"), strings as UniFi firmware sends them in sys_stats.
function M.loadavg()
	local s = M._read_file("/proc/loadavg") or ""
	local a, b, c = s:match("^(%S+)%s+(%S+)%s+(%S+)")
	if not a then return "0.00", "0.00", "0.00" end
	return a, b, c
end

-- Previous /proc/stat sample for delta-based CPU% (see M.cpu_percent).
-- Exposed for tests to reset/inspect between calls.
M._prev_cpu = nil

-- Returns CPU usage percent (0-100) since the previous call, by delta-
-- sampling the aggregate "cpu" line in /proc/stat (matches the real
-- inform payload's system-stats.cpu, which is a live percentage -- not to
-- be confused with a load average, a different metric real devices don't
-- report under this field). Returns 0 on the first call, since there's no
-- prior sample to diff against yet.
function M.cpu_percent()
	local s = M._read_file("/proc/stat")
	if not s then return 0 end
	local cpu_line = s:match("^cpu%s+([^\n]+)")
	if not cpu_line then return 0 end

	local fields = {}
	for n in cpu_line:gmatch("%d+") do
		fields[#fields + 1] = tonumber(n)
	end
	if #fields < 4 then return 0 end

	-- Fields: user nice system idle iowait irq softirq [steal guest guest_nice]
	local idle = fields[4] + (fields[5] or 0)
	local total = 0
	for _, v in ipairs(fields) do total = total + v end

	local pct = 0
	if M._prev_cpu then
		local total_delta = total - M._prev_cpu.total
		local idle_delta  = idle  - M._prev_cpu.idle
		if total_delta > 0 then
			pct = math.floor((total_delta - idle_delta) * 100 / total_delta + 0.5)
		end
	end
	M._prev_cpu = {total = total, idle = idle}
	return pct
end

-- Returns a table of interface stats from /proc/net/dev.
-- Each entry: {name, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors}
function M.interfaces()
	local s = M._read_file("/proc/net/dev")
	if not s then return {} end
	local ifaces = {}
	for line in s:gmatch("[^\n]+") do
		-- Skip header lines
		if line:find(":") then
			local name = line:match("^%s*(%S-):")
			local rx_bytes, rx_packets, rx_errors,
			      tx_bytes, tx_packets, tx_errors =
				line:match(":%s*(%d+)%s+(%d+)%s+(%d+)%s+%d+%s+%d+%s+%d+%s+%d+%s+%d+%s+"
				         .. "(%d+)%s+(%d+)%s+(%d+)")
			if name then
				local mac = ""
				local mac_raw = M._read_file("/sys/class/net/" .. name .. "/address")
				if mac_raw then mac = mac_raw:match("^([%x:]+)") or "" end
				ifaces[#ifaces + 1] = {
					name       = name,
					mac        = mac,
					rx_bytes   = tonumber(rx_bytes)   or 0,
					rx_packets = tonumber(rx_packets) or 0,
					rx_errors  = tonumber(rx_errors)  or 0,
					tx_bytes   = tonumber(tx_bytes)   or 0,
					tx_packets = tonumber(tx_packets) or 0,
					tx_errors  = tonumber(tx_errors)  or 0,
				}
			end
		end
	end
	return ifaces
end

-- Converts a WiFi frequency in MHz to its channel number (2.4/5/6GHz bands).
-- Returns nil for frequencies outside all three ranges.
function M.channel_from_freq(freq)
	freq = tonumber(freq)
	if not freq then return nil end
	if freq == 2484 then return 14 end
	if freq >= 2412 and freq <= 2472 then return math.floor((freq - 2407) / 5) end
	if freq >= 5955 and freq <= 7115 then return math.floor((freq - 5950) / 5) end
	if freq >= 5000 and freq <= 5895 then return math.floor((freq - 5000) / 5) end
	return nil
end

-- The key of an `iw` dump line: the text before its first colon, without the
-- indent and the " * " bullet ("\t\t * channel width: 1" -> "channel width").
-- The three dump parsers below look each line's key up first and try only the
-- pattern written for that key. They used to try every pattern on every line,
-- which on the Archer C5 cost about 13 matches per line of scan dump and made
-- these parsers most of a heartbeat's CPU. Each pattern is still the one it
-- was, so a line its key routes to reads exactly as before. It now also reads
-- only from its own line: an SSID such as "x freq: 2412" no longer sets the
-- neighbour's frequency. A plain find for the colon: a pattern that also
-- strips the indent backtracks over it on every line without one, which cost
-- more than the patterns it saves.
local function dump_key(line)
	local colon = line:find(":", 1, true)
	return colon and line:sub(line:match("^[%s%*]*()"), colon - 1)
end

-- survey dump key -> {field, pattern}. Anchored to (whitespace-then-)start of
-- line so "channel busy time:" doesn't also match inside the separate
-- "extension channel busy time:" field iw emits on wider channels.
local SURVEY_FIELDS = {
	["noise"]                 = {"noise",             "noise:%s+(-?%d+)"},
	["channel active time"]   = {"channel_time",      "^%s*channel active time:%s+(%d+)"},
	["channel busy time"]     = {"channel_time_busy", "^%s*channel busy time:%s+(%d+)"},
	["channel receive time"]  = {"channel_time_rx",   "^%s*channel receive time:%s+(%d+)"},
	["channel transmit time"] = {"channel_time_tx",   "^%s*channel transmit time:%s+(%d+)"},
}

-- Returns per-radio channel utilisation from `iw dev <ifname> survey dump`.
-- Returns a table: {freq, noise, channel_time, channel_time_busy, channel_time_rx, channel_time_tx}
function M.radio_stats(ifname)
	if not ifname then return {} end
	local output = M._run_cmd("iw dev " .. ifname .. " survey dump")
	local result = {}
	local current = nil
	for line in output:gmatch("[^\n]+") do
		local key = dump_key(line)
		local freq = key == "frequency" and line:match("frequency:%s+(%d+)")
		if freq then
			if current then result[#result + 1] = current end
			-- iw marks the operating channel's entry "[in use]" on this same
			-- line. It is the ONLY entry whose counters describe the radio's
			-- actual airtime -- every other one is a scan dwell of a few
			-- milliseconds -- so callers wanting utilisation must pick it out
			-- rather than assume a position (see _in_use_survey in inform.lua).
			current = {freq = tonumber(freq), in_use = line:find("[in use]", 1, true) ~= nil}
		elseif current then
			-- Field names matched against the real iw(8) binary's own format
			-- strings ("channel active/busy/receive/transmit time:", not
			-- "channel time[/busy/rx/tx]:") -- confirmed via `strings
			-- /usr/sbin/iw`; the previous patterns never matched any real
			-- iw output on any hardware, so channel utilisation always
			-- silently reported 0%/absent regardless of actual airtime.
			local f = SURVEY_FIELDS[key]
			local v = f and line:match(f[2])
			if v then current[f[1]] = tonumber(v) end
		end
	end
	if current then result[#result + 1] = current end
	return result
end

-- Derives {generation, nss} from a station dump's "tx bitrate: ..." line.
-- `generation` is one of "n"/"ac"/"ax"/"be"/nil (nil for legacy, pre-MCS
-- rates) -- the caller combines it with the radio's own band to produce a
-- final `radio_proto` ("legacy" + "na" => "a", "legacy" + "ng" => "g"),
-- since sysinfo.lua has no band context of its own here.
-- `nss` (spatial streams) comes directly from the VHT-NSS/HE-NSS/EHT-NSS
-- token when present; for plain HT (bare "MCS N", no VHT-/HE-/EHT- prefix)
-- it's derived as floor(N/8)+1, matching the real HT MCS index layout (MCS
-- 0-7 = 1 stream, 8-15 = 2 streams, ...). Real controller ingestion (see
-- com.ubnt.service.devmgr.TtZhv, confirmed via decompile) reads both
-- `radio_proto` and `nss` as independent per-station wire fields -- neither
-- is derived from tx_mcs/rx_mcs alone on the controller's side, which is why
-- sending only tx_mcs/rx_mcs left every station showing as generation "g"
-- (the controller's own fallback default) with no MIMO/stream count at all.
local function _bitrate_generation_nss(line)
	if line:find("EHT%-MCS") then
		local nss = line:match("EHT%-NSS%s+(%d+)")
		return "be", nss and tonumber(nss) or nil
	end
	if line:find("HE%-MCS") then
		local nss = line:match("HE%-NSS%s+(%d+)")
		return "ax", nss and tonumber(nss) or nil
	end
	if line:find("VHT%-MCS") then
		local nss = line:match("VHT%-NSS%s+(%d+)")
		return "ac", nss and tonumber(nss) or nil
	end
	local mcs = line:match("MCS%s+(%d+)")
	if mcs then
		return "n", math.floor(tonumber(mcs) / 8) + 1
	end
	return nil, nil
end

-- A u32 station counter read as signed, floored at 0. mt76 as shipped in
-- OpenWrt 25.12 (2026.03.19~39c960c3, mt7915 tx-free path) adds
-- FIELD_GET(COUNT) - 1 to tx_retries and tx_failed with no guard for a count
-- of 0, so a fresh station's counters can read 4294967295; upstream later
-- made it `count ? count - 1 : 0`. Passed on, one such reading added exactly
-- 2^32 to the controller's per-band totals (the Office AP showed 47 billion
-- tx packets and 50 % retries). No real retry count gets near 2^31.
function M.u32_count(v)
	if v and v >= 2147483648 then return 0 end
	return v
end

-- station dump key -> {field, pattern, u32 counter}.
-- signal is ANCHORED, and this matters: `iw` emits "avg ack signal:\t-95 dBm"
-- further down the same station block, which an unanchored "signal:%s+" also
-- matches -- and being later, it overwrote the real reading. Every client was
-- reported at the ack-signal value (-95 dBm on this driver) no matter its
-- actual RSSI. That feeds the Clients list, the vap's avg_client_signal, the
-- satisfaction estimate AND Minimum RSSI enforcement, which would have
-- deauthed every client on the radio the moment the feature was switched on.
-- The per-chain suffix ("-53 [-76, -53, -66] dBm") is ignored -- the first
-- number is the combined RSSI.
local STA_FIELDS = {
	["signal"]         = {"signal",        "^%s*signal:%s+(-?%d+)"},
	["signal avg"]     = {"signal_avg",    "^%s*signal avg:%s+(-?%d+)"},
	["tx bytes"]       = {"tx_bytes",      "tx bytes:%s+(%d+)"},
	["rx bytes"]       = {"rx_bytes",      "rx bytes:%s+(%d+)"},
	["tx packets"]     = {"tx_packets",    "tx packets:%s+(%d+)"},
	["rx packets"]     = {"rx_packets",    "rx packets:%s+(%d+)"},
	["tx retries"]     = {"tx_retries",    "tx retries:%s+(%d+)", true},
	["tx failed"]      = {"tx_failed",     "tx failed:%s+(%d+)",  true},
	["inactive time"]  = {"inactive_ms",   "inactive time:%s+(%d+)"},
	["connected time"] = {"connected_sec", "connected time:%s+(%d+)"},
}
-- "tx bitrate"/"rx bitrate" -> the patterns and fields of that direction.
local BITRATE = {}
for _, d in ipairs({"tx", "rx"}) do
	BITRATE[d .. " bitrate"] = {
		rate_pat = d .. " bitrate:%s+(%S+)", mcs_pat = d .. " bitrate:.*MCS%s+(%d+)",
		rate = d .. "_bitrate", mcs = d .. "_mcs", gen = d .. "_generation",
		nss = d .. "_nss", width = d .. "_width",
	}
end

-- Returns a table of connected stations from `iw dev <ifname> station dump`.
-- Each entry: {mac, signal, signal_avg, tx_bitrate, rx_bitrate, tx_mcs,
--              rx_mcs, tx_generation, tx_nss, rx_generation, rx_nss,
--              tx_bytes, rx_bytes, tx_packets, rx_packets, tx_retries,
--              tx_failed, inactive_ms, connected_sec, tx_width, rx_width}
-- signal is the last frame's, signal_avg mac80211's running average.
-- tx_retries/tx_failed: iw(8) only exposes TX-side retry/failure counters
-- (802.11 ARQ is TX-side by nature) -- there is no rx-side equivalent in
-- `station dump` output, confirmed via `strings /usr/sbin/iw`.
function M.sta_table(ifname)
	if not ifname then return {} end
	local output = M._run_cmd("iw dev " .. ifname .. " station dump")
	local clients = {}
	local cur = nil
	for line in output:gmatch("[^\n]+") do
		local mac = line:match("^Station (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if mac then
			if cur then clients[#clients + 1] = cur end
			cur = {mac = mac}
		elseif cur then
			local key = dump_key(line)
			local b = BITRATE[key]
			if b then
				-- tx_mcs/rx_mcs: only for 11n/ac/ax rates -- legacy (pre-MCS)
				-- rates have no "MCS N" suffix, so these stay nil for those,
				-- same as other optional fields below.
				local rate = line:match(b.rate_pat)
				local mcs  = line:match(b.mcs_pat)
				if rate then cur[b.rate] = tonumber(rate) end
				if mcs  then cur[b.mcs]  = tonumber(mcs)  end
				cur[b.gen], cur[b.nss] = _bitrate_generation_nss(line)
				-- "80MHz"; iw prints no width token for 20 MHz rates.
				cur[b.width] = tonumber(line:match("(%d+)MHz")) or 20
			else
				local f = STA_FIELDS[key]
				local v = f and line:match(f[2])
				if v then
					v = tonumber(v)
					if f[3] then v = M.u32_count(v) end
					cur[f[1]] = v
				end
			end
		end
	end
	if cur then clients[#clients + 1] = cur end
	return clients
end

-- The kernel driver behind a wireless netdev ("ath9k", "ath10k_pci",
-- "mt798x-wmac"), or nil. It does not change while the board runs, so it is
-- read once per netdev.
M._driver_cache = {}
function M.wifi_driver(ifname)
	if not ifname then return nil end
	if M._driver_cache[ifname] == nil then
		M._driver_cache[ifname] = util.driver_of(ifname, M._read_file) or false
	end
	return M._driver_cache[ifname] or nil
end

-- Whether a station is dozing right now (UniFi firmware's sta `state` bit
-- 0x10, which the controller turns into powersave_enabled): true/false, or nil
-- when this radio cannot say. mac80211 keeps the PS_STA flag itself only when
-- the driver leaves power-save tracking to it; a driver that sets AP_LINK_PS
-- in hwflags takes that job over, and neither ath10k nor mt76 reports back
-- (both APs, 2026-10-10: ath9k showed PS_STA on a dozing client, ath10k and
-- mt798x never once in 10 s across 17 stations). There, false would be a
-- guess. Needs debugfs, which OpenWrt mounts.
M._ps_phy_cache = {}
function M.sta_powersave(ifname, mac)
	if not ifname or not mac then return nil end
	local phy = M._ps_phy_cache[ifname]
	if phy == nil then
		phy = (M._read_file("/sys/class/net/" .. ifname .. "/phy80211/name") or ""):match("^%s*(%S+)")
		if phy then
			local hw = M._read_file("/sys/kernel/debug/ieee80211/" .. phy .. "/hwflags")
			if not hw or hw:find("AP_LINK_PS", 1, true) then phy = nil end
		end
		M._ps_phy_cache[ifname] = phy or false
	end
	if not phy then return nil end
	local flags = M._read_file("/sys/kernel/debug/ieee80211/" .. phy .. "/netdev:"
		.. ifname .. "/stations/" .. mac:lower() .. "/flags")
	if not flags then return nil end
	for word in flags:gmatch("%S+") do
		if word == "PS_STA" then return true end
	end
	return false
end

-- A radio's transmit-timeout and carrier-sense-timeout interrupt counts since
-- the driver loaded: UniFi firmware's athstats ast_txto and ast_cst, which its
-- athstats tool labels "global txmit timeout interrupts" and "carrier sense
-- timeout interrupts" (firmware-confirmed for 4.0.15). ath9k counts the same
-- two hardware interrupts as GTT and CST in debugfs. ath10k (its firmware
-- keeps a tx timeout count, but no carrier-sense one) and mt76 have no such
-- pair: nil there.
function M.radio_timeouts(ifname)
	if not ifname then return nil end
	local phy = (M._read_file("/sys/class/net/" .. ifname .. "/phy80211/name") or ""):match("^%s*(%S+)")
	if not phy then return nil end
	local s = M._read_file("/sys/kernel/debug/ieee80211/" .. phy .. "/ath9k/interrupt")
	if not s then return nil end
	local gtt = tonumber(s:match("GTT:%s*(%d+)"))
	local cst = tonumber(s:match("CST:%s*(%d+)"))
	if not (gtt and cst) then return nil end
	return gtt, cst
end

-- Each station's AKM suite on the given hostapd BSSes, as hostapd prints it
-- ("00-0f-ac-9"), keyed by lower-case MAC. One hostapd_cli run for all of them.
-- The second result is the set of stations hostapd listed at all, so a
-- station it listed without an AKM (an open network) can be told from one
-- it never answered for.
function M.sta_akms(bsses)
	local out, listed = {}, {}
	local names = {}
	for _, b in ipairs(bsses or {}) do
		if b:match("^[%w%-%._]+$") then names[#names + 1] = b end
	end
	if #names == 0 then return out, listed end
	local text = M._run_cmd("for b in " .. table.concat(names, " ")
		.. "; do hostapd_cli -i $b all_sta; done")
	local cur
	for line in text:gmatch("[^\n]+") do
		local mac = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*$")
		if mac then
			cur = mac:lower()
			listed[cur] = true
		elseif cur then
			local akm = line:match("^AKMSuiteSelector=(%S+)")
			if akm then out[cur] = akm:lower() end
		end
	end
	return out, listed
end

-- A station's AKM is fixed for the life of its association, so it is asked
-- of hostapd once per association, not every heartbeat. An association is
-- the station's BSS plus its start (uptime minus iw's connected time); a
-- start that moved by more than the slack is a new association, which
-- covers a reconnect between two heartbeats that iw's counter alone could
-- hide. A station unseen for AKM_IDLE seconds is forgotten.
M.AKM_IDLE = 300
M.AKM_START_SLACK = 5
M._akm_cache = {}   -- [mac] = {bss = ifname, start = s, akm = akm|false, seen = s}

-- stas: {{mac = , bss = , conn = connected seconds}, ...}. Returns sta_akms'
-- map for those stations, running hostapd_cli only on BSSes that hold a
-- station with no current answer.
function M.sta_akms_cached(stas)
	local now_up = M.uptime()
	local bsses, want = {}, {}
	if now_up <= 0 then -- no clock to date associations by: ask every time
		for _, s in ipairs(stas) do
			if not want[s.bss] then want[s.bss] = true; bsses[#bsses + 1] = s.bss end
		end
		return (M.sta_akms(bsses))
	end
	local cache = M._akm_cache
	for mac, e in pairs(cache) do
		if e.seen + M.AKM_IDLE < now_up then cache[mac] = nil end
	end
	local out = {}
	for _, s in ipairs(stas) do
		local mac = s.mac:lower()
		local e = cache[mac]
		if e and s.conn and e.bss == s.bss
			and math.abs(now_up - s.conn - e.start) <= M.AKM_START_SLACK then
			e.seen = now_up
			out[mac] = e.akm or nil
		elseif not want[s.bss] then
			want[s.bss] = true; bsses[#bsses + 1] = s.bss
		end
	end
	if #bsses == 0 then return out end
	local akms, listed = M.sta_akms(bsses)
	listed = listed or {}
	for _, s in ipairs(stas) do
		if want[s.bss] then
			local mac = s.mac:lower()
			out[mac] = akms[mac]
			-- Only an answer hostapd gave is kept: a station it did not list
			-- (it failed, or the station came after iw's read) is asked again.
			if listed[mac] and s.conn then
				cache[mac] = {bss = s.bss, start = now_up - s.conn,
					akm = akms[mac] or false, seen = now_up}
			end
		end
	end
	return out
end

-- AKM suites that use Fast BSS Transition (IEEE 802.11-2020 table 9-151:
-- 3 FT-802.1X, 4 FT-PSK, 9 FT-SAE, 13 FT-802.1X-SHA384, 19 FT-PSK-SHA384,
-- 25 FT-SAE-EXT-KEY).
local FT_AKMS = {["00-0f-ac-3"] = true, ["00-0f-ac-4"] = true, ["00-0f-ac-9"] = true,
	["00-0f-ac-13"] = true, ["00-0f-ac-19"] = true, ["00-0f-ac-25"] = true}
function M.akm_is_ft(akm)
	return akm ~= nil and FT_AKMS[akm] == true
end

-- Sibling-AP recognition. The controller decides whether a scanned BSS is
-- one of its own from the REPORTING AP's word alone, never from the site's
-- vap_tables (decompiled 10.6.101, com.ubnt.service.aS.rhAW): a scan entry
-- tagged is_unifi=true is resolved to a device by its serialno and, if that
-- device is adopted in the site, recorded as a UniFi neighbour; an untagged
-- one is a rogue whenever its SSID is one of the site's. Real UniFi APs learn
-- the tag from a Ubiquiti vendor IE in each other's beacons. openUF had no
-- such IE, so every openUF AP showed up in AirView as a third-party AP
-- impersonating the network -- seen live, all six sibling BSSes at home had
-- is_rogue=true while the vap_tables the controller held were correct.
--
-- So every openUF VAP beacons this IE, carrying its device's identity MAC:
--   dd 0d | 02 6f 55 (OUI) | 6f 55 46 ("oUF") | 01 (version) | 6-byte MAC
-- The OUI is deliberately NOT a Ubiquiti one (UniFi firmware's own element uses
-- 00:15:6d, see PROTOCOL-VALIDATION.md) -- a real UniFi AP parsing our layout as
-- theirs would read garbage -- and the magic makes a collision with any real
-- user of 02:6f:55 harmless in both directions.
M.PEER_IE_OUI   = "02:6f:55"
M.PEER_IE_MAGIC = "6f5546"
M.PEER_IE_VER   = "01"

-- The hostapd vendor_elements value (the whole element as hex) announcing
-- mac ("xx:xx:xx:xx:xx:xx"), or nil when mac is not a MAC.
function M.peer_ie_hex(mac)
	if type(mac) ~= "string" then return nil end
	local hex = mac:lower():gsub(":", "")
	if not hex:match("^%x+$") or #hex ~= 12 then return nil end
	return "dd0d" .. M.PEER_IE_OUI:gsub(":", "") .. M.PEER_IE_MAGIC
		.. M.PEER_IE_VER .. hex
end

-- Reading it back cannot go through `iw`: OpenWrt's default iw build strips
-- the printer for vendor elements it does not know, so ours never appears in
-- `iw scan dump` output, with or without -u. Checked live 2026-09-26 on both
-- boards (iw 6.17): not one "Vendor specific" line across a dozen neighbours,
-- while the same kernel scan cache, read over nl80211, held our element.
-- ucode's nl80211 module is what OpenWrt's own wifi scripts are built on, so
-- it is present wherever those are. The script prints "<bssid> <mac>" per
-- sibling BSS and nothing else; any failure (no ucode, no module) is simply
-- no siblings.
--
-- A real UniFi AP is a sibling too, on a site that mixes the two: without the
-- tag, openUF reported its BSSes as rogues whenever they carried a site SSID.
-- UniFi firmware's own element (firmware-confirmed for 4.0.15, umac.ko
-- ieee80211_add_ubnt_ie + libubnt's scan parser; seen live in 2026 on a
-- neighbour's current-firmware AP):
--   dd <len> | 00 15 6d | 00 01 01 (UniFi AP) | flags | 01 02 <system id>
--            | TLVs from body offset 11: 81 06 <serialno = device MAC>, ...
-- The TLVs are walked, not indexed: current firmware adds tags 4.0.15 did not
-- have (0x89, a UUID). Only the tag-0x81 MAC is used; the flags are ignored.
local function ucode_bytes(hex)
	return (hex:gsub("(%x%x)", "\\x%1"))
end

-- The ucode function pm(d): the MAC an element body d announces, or null.
-- Kept separate so it can be run on a device against fixed inputs.
function M.peer_match_ucode()
	local head = ucode_bytes(M.PEER_IE_OUI:gsub(":", "") .. M.PEER_IE_MAGIC .. M.PEER_IE_VER)
	return 'function mac(d,o){let m=[];for(let i=o;i<o+6;i++)push(m,sprintf("%02x",ord(d,i)));return join(":",m);}'
		.. 'function pm(d){let n=length(d);'
		.. 'if(n==13&&substr(d,0,7)=="' .. head .. '")return mac(d,7);'
		.. 'if(n<11||ord(d,0)!=0||ord(d,1)!=0x15||ord(d,2)!=0x6d'
		.. '||ord(d,3)!=0||ord(d,4)!=1||ord(d,5)!=1)return null;'
		.. 'for(let i=11;i+2<=n;i+=2+ord(d,i+1)){'
		.. 'if(ord(d,i)==0x81&&ord(d,i+1)==6&&i+8<=n)return mac(d,i+2);}'
		.. 'return null;}'
end

-- The reader's last line, printed once it has walked the whole scan cache.
-- A dump that returned nothing at all prints no such line: nl80211 answers an
-- empty cache and a failed request alike (null, checked on the C5), and the
-- reader only runs when `iw` has just listed BSSes, so null is the failure.
M.PEER_SCAN_DONE = "openuf-peer-scan-done"

function M.peer_scan_cmd(ifname)
	if type(ifname) ~= "string" or not ifname:match("^[%w%.%-_]+$") then return nil end
	local script = M.peer_match_ucode()
		.. 'let nl=require("nl80211");'
		.. 'let r=nl.request(nl.const.NL80211_CMD_GET_SCAN,nl.const.NLM_F_DUMP,{dev:"' .. ifname .. '"});'
		.. 'for(let x in (r||[])){let b=x.bss;if(!b)continue;'
		.. 'for(let l in [b.information_elements||[],b.beacon_ies||[]]){let hit=null;'
		.. 'for(let e in l){if(e.type==221){hit=pm(e.data);if(hit)break;}}'
		.. 'if(hit){print(b.bssid," ",hit,"\\n");break;}}}'
		.. 'if(r!=null)print("' .. M.PEER_SCAN_DONE .. '\\n");'
	return "ucode -e '" .. script .. "' 2>/dev/null"
end

-- {bssid = identity MAC} for every BSS in ifname's scan cache that carries
-- the sibling-AP element, and whether the reader ran to its end: without the
-- closing line (no ucode, no nl80211 module, killed) a BSS missing from the
-- map is unknown, not a stranger.
function M.peer_macs(ifname)
	local cmd = M.peer_scan_cmd(ifname)
	if not cmd then return {}, false end
	local out = M._run_cmd(cmd) or ""
	local peers = {}
	for bssid, mac in out:gmatch(
			"(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x) (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)") do
		peers[bssid:lower()] = mac:lower()
	end
	return peers, out:find(M.PEER_SCAN_DONE, 1, true) ~= nil
end

-- The reader is a ucode fork that loads the nl80211 module, and it was made
-- per radio per heartbeat to learn something that only changes when a BSS
-- does. So its answer is kept per BSSID, and the
-- reader runs only when the scan holds a BSSID it has no live answer for. A
-- sibling is kept an hour. A stranger is kept ten minutes, so that a BSS which
-- starts carrying the element under the same BSSID (a neighbour upgraded to
-- openUF, or one that beaconed before it knew its identity) is picked up in
-- that time. A stranger is only recorded from a reader that ran to its end.
M.PEER_TTL_SIBLING  = 3600
M.PEER_TTL_STRANGER = 600
M._peer_cache = {}   -- [ifname] = {[bssid] = {mac = mac|false, until_up = s}}

local function peer_tag(ifname, nets, now_up)
	if now_up <= 0 then -- no clock to age entries by: read every time
		local peers = M.peer_macs(ifname)
		for _, n in ipairs(nets) do n.peer_mac = peers[n.bssid:lower()] end
		return
	end
	local cache = M._peer_cache[ifname] or {}
	M._peer_cache[ifname] = cache
	for bssid, e in pairs(cache) do
		if e.until_up <= now_up then cache[bssid] = nil end
	end
	local stale = false
	for _, n in ipairs(nets) do
		if not cache[n.bssid:lower()] then stale = true break end
	end
	if stale then
		local peers, done = M.peer_macs(ifname)
		for _, n in ipairs(nets) do
			local bssid = n.bssid:lower()
			if peers[bssid] then
				cache[bssid] = {mac = peers[bssid], until_up = now_up + M.PEER_TTL_SIBLING}
			elseif done then
				cache[bssid] = {mac = false, until_up = now_up + M.PEER_TTL_STRANGER}
			end
		end
	end
	for _, n in ipairs(nets) do
		local e = cache[n.bssid:lower()]
		n.peer_mac = e and e.mac or nil
	end
end

-- Returns a table of neighboring wireless networks visible to ifname, by
-- parsing `iw dev <ifname> scan dump` -- the kernel's already-cached BSS
-- list from cfg80211, not a fresh scan (that's what the spectrum-scan cmd
-- handler's separate `iw dev <ifname> scan` call triggers; reading the
-- cache here is cheap and non-disruptive enough to do on every inform,
-- unlike a real scan).
-- Each entry: {bssid, essid, freq, channel, signal, security, age, bw,
-- peer_mac} -- peer_mac only for a sibling openUF or UniFi AP (see peer_ie_hex).
-- `bw` is channel width in MHz. The controller's Environment tab's "Ch. Width"
-- column reads this field directly and renders nothing at all when it's
-- missing (confirmed live 2026-07-14) -- default to 20 (legacy-safe, valid
-- for both bands) when a neighbor advertises nothing, rather than leaving the
-- column blank. Where it comes from is described at flush() below: iw's
-- "BSS operating channel width:" summary line where one is printed, and the
-- operation elements themselves otherwise, because iw 6.17 -- what both our
-- boards run -- prints no such summary line at all.
-- `age` is seconds elapsed since last seen, from iw's own "last seen: N ms
-- ago" line -- NOT a substitute for an absolute last_seen timestamp. The
-- controller's rogue-AP ingestion (com.ubnt.service.aO.hhFgUVZPT, confirmed
-- live 2026-07-14) reads `age`, not `last_seen`, and derives the absolute
-- last_seen itself as (report_time - age); it also silently drops any entry
-- with age >= 30 as stale before it ever reaches the rogue-AP list, so this
-- must be a small, genuinely-fresh number, not whatever we last computed.
-- iw prints an SSID with every byte that is not printable ASCII -- all UTF-8,
-- a backslash, a leading or trailing space -- as \xNN, so "Café Guest" reached
-- the Environment tab as the literal "Caf\xc3\xa9 Guest", and the controller's
-- evil-twin check (essid in the site's SSIDs) could not match such a name.
-- Decoding is unambiguous because the backslash is itself escaped. A hidden
-- network (empty, or NUL-filled) gets no essid at all: the tab then shows the
-- BSSID, and no NUL bytes go into the JSON.
local function unescape_iw_ssid(s)
	s = s:gsub("\\x(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
	if s == string.rep(string.char(0), #s) then return nil end
	return s
end

-- Channel width in MHz from a BSS's operation elements: the VHT Operation
-- width field and centre segments, and the HT Operation secondary channel
-- offset ("above"/"below", anything else = none). How the fields combine is
-- described in scan_table's flush() below. Shared with rrmscan.lua, which
-- reads the same two elements out of a client's beacon report.
function M.channel_width(vht_w, vht_seg1, vht_seg2, ht_sec)
	if vht_w and vht_w >= 1 then
		local seg2 = vht_seg2 or 0
		if vht_w == 2 or (vht_w == 1 and seg2 > 0
				and math.abs(seg2 - (vht_seg1 or 0)) == 8) then
			return 160
		end
		return 80
	elseif ht_sec == "above" or ht_sec == "below" then
		return 40
	end
	return 20
end

-- scan dump key -> what that line sets: on the BSS (cur) or in the per-BSS
-- evidence (ev) that flush() resolves into bw and security.
local SCAN_LINE = {
	-- Operation-element width evidence. The VHT line is anchored on
	-- "* channel width:" so that the HT capability line sitting two lines
	-- below it cannot match: that one reads "* STA channel width: 20 MHz" on
	-- a 20 MHz neighbour, and reading its 20 as a VHT width field would report
	-- the BSS as 80 MHz. (Its key differs too, "STA channel width".)
	["channel width"] = function(line, cur, ev)
		local w = line:match("^%s*%*%s+channel width:%s+(%d+)")
		if w then ev.vht_w = tonumber(w) end
	end,
	["center freq segment 1"] = function(line, cur, ev)
		local s1 = line:match("center freq segment 1:%s+(%d+)")
		if s1 then ev.vht_seg1 = tonumber(s1) end
	end,
	["center freq segment 2"] = function(line, cur, ev)
		local s2 = line:match("center freq segment 2:%s+(%d+)")
		if s2 then ev.vht_seg2 = tonumber(s2) end
	end,
	["secondary channel offset"] = function(line, cur, ev)
		local sec = line:match("secondary channel offset:%s+(%a+)")
		if sec then ev.ht_sec = sec end
	end,
	["freq"] = function(line, cur)
		local freq = line:match("freq:%s+(%d+)")
		if freq then
			cur.freq    = tonumber(freq)
			cur.channel = M.channel_from_freq(freq)
		end
	end,
	-- Anchored for the same reason as the station-dump copy above,
	-- defensively: scan output carries no ack-signal lines today.
	["signal"] = function(line, cur)
		local signal = line:match("^%s*signal:%s+(-?%d+)")
		if signal then cur.signal = tonumber(signal) end
	end,
	["SSID"] = function(line, cur)
		local ssid = line:match("^\tSSID:%s?(.*)$")
		if ssid and not cur.essid then cur.essid = unescape_iw_ssid(ssid) end
	end,
	-- iw also prints the driver's BOOTTIME stamp: "last seen: 662754.792s
	-- [boottime]". Some entries carry ONLY that form -- seen on our own
	-- AX3000T -- which the "ms ago" pattern never matched, so their age
	-- stayed at the 0 default and every such neighbour was reported as seen
	-- this instant, however stale. The "ms ago" line wins when both are
	-- printed for one BSS (it is what the controller's own staleness rule is
	-- written against, and it is printed second); this fills in when it is
	-- the only one.
	["last seen"] = function(line, cur, ev, now_up)
		local last_ms = line:match("last seen:%s+(%d+) ms ago")
		local last_bt = line:match("last seen:%s+([%d%.]+)s %[boottime%]")
		if last_ms then
			cur.age = math.floor(tonumber(last_ms) / 1000)
		elseif last_bt and cur.age == nil and now_up > 0 then
			cur.age = math.max(0, math.floor(now_up - tonumber(last_bt)))
		end
	end,
	["BSS operating channel width"] = function(line, cur)
		local bw = line:match("BSS operating channel width:%s+(%d+) MHz")
		if bw then cur.bw = tonumber(bw) end
	end,
	["capability"] = function(line, cur, ev)
		if line:find("capability:.*Privacy") then ev.privacy = true end
	end,
	["RSN"] = function(line, cur, ev)
		if line:find("^\tRSN:") then ev.rsn = true end
	end,
	["WPA"] = function(line, cur, ev)
		if line:find("^\tWPA:") then ev.wpa = true end
	end,
}

function M.scan_table(ifname)
	if not ifname then return {} end
	local output = M._run_cmd("iw dev " .. ifname .. " scan dump")
	-- For the [boottime] form of "last seen" below: /proc/uptime and the
	-- driver's stamp are both on the CLOCK_BOOTTIME axis.
	local now_up = M.uptime()
	local nets = {}
	local cur = nil
	-- Per BSS: the security elements seen, and the width evidence from the
	-- operation elements (see flush()).
	local ev = {}

	local function flush()
		if not cur then return end
		if not cur.age then cur.age = 0 end
		-- Channel width. The "BSS operating channel width: N MHz" summary line
		-- is printed by only some iw builds -- iw 6.17 prints no such line at
		-- all, and that is what BOTH our boards run (Archer C5 on ath79 and
		-- AX3000T on filogic, checked 2026-09-09), so every neighbour went out
		-- as 20 MHz. Two real 80 MHz APs next door were reported as 20.
		--
		-- What that iw does print is the operation elements themselves:
		--   VHT operation:  * channel width: 1 (80 MHz)
		--                   * center freq segment 1: 42
		--                   * center freq segment 2: 0
		--   HT operation:   * secondary channel offset: above|below|no secondary
		--
		-- VHT width field 1 with a NON-ZERO segment 2 is either 160 MHz (the
		-- two segments 8 channels apart, the modern encoding) or a
		-- non-contiguous 80+80 (further apart, reported as its 80 MHz primary
		-- segment, since the controller's vocabulary is 20/40/80/160). Fields
		-- 2 and 3 are the deprecated direct encodings of the same two. Width
		-- field 0 means "20 or 40", which the HT secondary channel offset
		-- resolves; nothing at all means 20.
		if not cur.bw then
			cur.bw = M.channel_width(ev.vht_w, ev.vht_seg1, ev.vht_seg2, ev.ht_sec)
		end
		if ev.rsn then cur.security = "wpa2"
		elseif ev.wpa then cur.security = "wpa"
		elseif ev.privacy then cur.security = "wep"
		else cur.security = "open" end
		nets[#nets + 1] = cur
	end

	for line in output:gmatch("[^\n]+") do
		local bssid = line:match("^BSS (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if bssid then
			flush()
			cur = {bssid = bssid}
			ev = {}
		elseif cur then
			local on_line = SCAN_LINE[dump_key(line)]
			if on_line then on_line(line, cur, ev, now_up) end
		end
	end
	flush()
	if #nets > 0 then peer_tag(ifname, nets, now_up) end
	return nets
end

-- Returns hardware/PHY capability fields for ifname's radio, by resolving
-- its wiphy index via `iw dev <ifname> info` and parsing `iw phy phyN info`.
-- These are NOT derived from anything else already in the payload -- the
-- real controller's AP-inform processor (com.ubnt.service.devmgr.
-- PGOcbDWlbnYQdFW, confirmed via decompile) copies is_11ac/is_11ax/is_11be/
-- has_dfs/has_fccdfs/has_ht160/has_eht240/has_eht320/nss directly off each
-- incoming radio_table entry, independent of radio_caps/radio_caps2; openUF
-- never sent any of them, which is why the Radios (channel-planning) tab's
-- MIMO/capability filters excluded the device entirely ("We Couldn't Find a
-- Match") despite everything else being wired correctly.
-- Each field is read from the OpenWrt board's own real driver/firmware
-- capability report, not invented -- an arbitrary board running openUF may
-- be far weaker or stronger than the U6-InWall it impersonates. Also
-- returns `channel`, the live negotiated channel number (more authoritative
-- than UCI's own config value, which is often the string "auto").
-- Cached: whether this device's hostapd build can actually do WPA3-SAE.
-- nil = not probed yet.
M._sae_supported_cache = nil

-- Does this system support WPA3/SAE?
--
-- Reported to the controller as radio_table[].wpa3_supported, which is what
-- gates WPA3 for the device: without it a WPA2/WPA3 WLAN is silently
-- downgraded to plain WPA2 for this AP (see PROTOCOL-VALIDATION.md). So it
-- must be answered honestly -- claiming it on a build whose hostapd has no
-- SAE would make the controller push a config the radio cannot run.
--
-- Probed from the wifi config generator rather than by parsing a binary:
-- OpenWrt 24+ ships ucode wifi scripts that name the auth types they can
-- emit ('sae', 'psk-sae'), and older releases express the same in
-- hostapd.sh. Both are plain file reads, no process spawn.
function M.sae_supported()
	if M._sae_supported_cache ~= nil then return M._sae_supported_cache end
	local found = false
	local ucode = M._read_file("/usr/share/ucode/wifi/ap.uc")
	if ucode and ucode:find("psk-sae", 1, true) then found = true end
	if not found then
		local legacy = M._read_file("/lib/netifd/hostapd.sh")
		if legacy and legacy:find("sae", 1, true) then found = true end
	end
	M._sae_supported_cache = found
	return found
end

M._owe_supported_cache = nil

-- Can this device run an Enhanced Open (OWE) WLAN, including its transition
-- mode?
--
-- Claimed to the controller as radio_caps2 bit 0x8; without it an OWE WLAN is
-- not provisioned at all, and a transition one goes out as plain open. Both
-- halves are needed. `hostapd -v<feature>` exits 0 only when the running
-- hostapd build has that feature compiled in (it exits 1 on a name it does not
-- know), and transition mode is written as one wifi-iface with
-- owe_transition=1, which only the ucode generator (24.10+) expands into the
-- hidden OWE BSS plus the open one.
function M.owe_supported()
	if M._owe_supported_cache ~= nil then return M._owe_supported_cache end
	local found = false
	local gen = M._read_file("/usr/share/ucode/wifi/hostapd.uc")
	if gen and gen:find("owe_transition", 1, true) then
		found = M._run_cmd("/usr/sbin/hostapd -vowe >/dev/null 2>&1 && echo yes")
			:find("yes", 1, true) ~= nil
	end
	M._owe_supported_cache = found
	return found
end

M._ppsk_supported_cache = nil

-- Can this device run Private Pre-Shared Keys: several passphrases on one
-- SSID, each putting its client on its own VLAN?
--
-- Claimed to the controller as wifi_caps 0x100000; without it a PPSK WLAN is
-- skipped entirely. Both halves are needed. The generator must turn
-- wifi-station sections into a wpa_psk_file with vlanid= (ap.uc,
-- iface_wpa_stations, OpenWrt 24.10+), and hostapd must be built with VLAN
-- support: a build without it has no "from wpa_psk_file" log string and would
-- ignore every key's VLAN. There is no -v<feature> probe for VLAN, so the
-- binary is searched once.
function M.ppsk_supported()
	if M._ppsk_supported_cache ~= nil then return M._ppsk_supported_cache end
	local found = false
	local gen = M._read_file("/usr/share/ucode/wifi/ap.uc")
	if gen and gen:find("vlanid=", 1, true) then
		found = M._run_cmd("grep -qF 'from wpa_psk_file' /usr/sbin/hostapd && echo yes")
			:find("yes", 1, true) ~= nil
	end
	M._ppsk_supported_cache = found
	return found
end

M._eap_supported_cache = nil

-- Can this device run WPA-Enterprise (802.1X): hostapd as a RADIUS client,
-- authenticating each station against the controller's RADIUS servers?
--
-- Deliberately NOT a capability bit and NOT a provisioning gate. The
-- controller puts no capability gate on a WPA2-Enterprise WLAN (verified in
-- 10.6.106's ubntconf/LsyaJoEysWb), so such a WLAN arrives whether or not
-- openUF could honour it, and refusing it here would only hide the problem.
-- This answers one question -- should apply_config warn? -- because a device
-- running a basic wpad brings the BSS up and then authenticates nobody, with
-- nothing logged anywhere. Both halves are needed: the generator must know the
-- server options (ap.uc, iface_authentication_server) and the binary must
-- carry the RADIUS client.
function M.eap_supported()
	if M._eap_supported_cache ~= nil then return M._eap_supported_cache end
	local found = false
	local gen = M._read_file("/usr/share/ucode/wifi/ap.uc")
	if gen and gen:find("auth_server_addr", 1, true) then
		found = M._run_cmd("grep -qF 'auth_server_addr' /usr/sbin/hostapd && echo yes")
			:find("yes", 1, true) ~= nil
	end
	M._eap_supported_cache = found
	return found
end

M._hs20_supported_cache = nil

--- Can this device run Hotspot 2.0 / Passpoint: ANQP/GAS answers, the
--- Interworking element and the HS 2.0 indication element?
---
--- Claimed to the controller as fw_caps 0x800000 (supportHotspot2). Unlike
--- M.eap_supported this IS a capability bit, because the controller drops a
--- Hotspot 2.0 WLAN outright without it ("Hotspot 2 cannot provision OSEN on
--- ... " in 10.6.106's ubntconf/LsyaJoEysWb), so claiming it where it cannot be
--- honoured would produce a WLAN that advertises Passpoint and answers no ANQP
--- query. Both halves are needed: the generator must know the interworking
--- options (ap.uc, iface_interworking/iface_hs20, OpenWrt 24.10+) and the
--- binary must be built with CONFIG_HS20 -- a build without it has no
--- hs20_conn_capab option and would ignore every hs20_* line.
function M.hs20_supported()
	if M._hs20_supported_cache ~= nil then return M._hs20_supported_cache end
	local found = false
	local gen = M._read_file("/usr/share/ucode/wifi/ap.uc")
	if gen and gen:find("iw_enabled", 1, true) then
		found = M._run_cmd("grep -qF 'hs20_conn_capab' /usr/sbin/hostapd && echo yes")
			:find("yes", 1, true) ~= nil
	end
	M._hs20_supported_cache = found
	return found
end

-- `iw phy phyN info` is tens of kilobytes and was fetched and parsed for every
-- radio on every heartbeat, although it describes the HARDWARE plus the
-- regulatory domain and changes only with the latter. Cached per phy with a
-- TTL: long enough to take the fetch AND the parse off the 10-second path,
-- short enough that a regdomain change is reflected within minutes.
-- (ucihelper keeps its own, separately invalidated cache of `iw phy` for its
-- clamping decisions.) `iw dev <if> info` is NOT cached -- it carries the live
-- channel and TX power, which is the point of reading it every time.
M.PHY_INFO_TTL = 300
M._phy_info_cache = {}

-- Everything M.radio_caps() reports that comes from the phy dump rather than
-- from the live interface. Split out and cached alongside the text it is
-- derived from, because caching the TEXT alone still left ~8 scans and a
-- gmatch over 40-odd kilobytes running per radio per heartbeat -- on a 560 MHz
-- MIPS SoC that parse was the largest thing left on the path, and it produces
-- the same answer for exactly as long as the text does.
local function parse_phy_info(phy_info)
	local has_dfs = phy_info:find("radar detection") ~= nil
	local caps = {
		is_11ac    = phy_info:find("VHT Capabilities") ~= nil,
		is_11ax    = (phy_info:find("HE PHY Capabilities") ~= nil) or (phy_info:find("HE MAC Capabilities") ~= nil),
		is_11be    = phy_info:find("EHT PHY Capabilities") ~= nil,
		has_dfs    = has_dfs,
		has_fccdfs = has_dfs,
		has_ht160  = false,
		has_eht240 = false,
		has_eht320 = false,
	}

	local width_line = phy_info:match("Supported Channel Width:%s*([^\n]*)")
	if width_line and width_line:find("160 MHz") then
		caps.has_ht160 = true
	end

	local nss = phy_info:match("HT TX Max spatial streams:%s*(%d+)")
	if not nss then
		-- Fall back to counting "N streams: MCS ..." lines (VHT/HE MCS-set
		-- tables list one line per supported spatial stream, "not supported"
		-- for streams beyond the radio's capability) when the more direct
		-- summary line isn't present.
		local max_streams = 0
		for n in phy_info:gmatch("(%d+) streams:%s*MCS") do
			local count = tonumber(n)
			if count and count > max_streams then max_streams = count end
		end
		if max_streams > 0 then nss = max_streams end
	end
	if not nss then
		-- Last resort, and the only one an HT-only radio has: the supported HT
		-- MCS index range ("HT TX/RX MCS rate indexes supported: 0-23"). The
		-- HT MCS layout is 8 indexes per spatial stream (0-7 = 1 stream,
		-- 8-15 = 2, 16-23 = 3), the same mapping _bitrate_generation_nss
		-- already applies to per-station HT rates.
		--
		-- Neither of the two sources above exists on a plain 802.11n phy:
		-- there is no "HT TX Max spatial streams" summary line, and the
		-- "N streams: MCS" lines belong to the VHT/HE MCS-set tables, which
		-- an HT-only radio has none of. So every 2.4GHz-only radio fell
		-- through to the default and was reported as 1x1 -- confirmed against
		-- a real controller, which showed this board's 3-stream ath9k radio
		-- as "1x1 WiFi 4".
		local hi = phy_info:match("HT TX/RX MCS rate indexes supported:%s*%d+%-(%d+)")
		if hi then
			local n = math.floor(tonumber(hi) / 8) + 1
			if n > 0 then nss = n end
		end
	end
	caps.nss = nss and tonumber(nss) or 1

	return caps
end

-- Returns the phy dump's text and the hardware capabilities parsed out of it.
function M._phy_info(phy)
	local now = M._time()
	local c = M._phy_info_cache[phy]
	if c and (now - c.at) < M.PHY_INFO_TTL then return c.text, c.caps end
	local text = M._run_cmd("iw phy phy" .. phy .. " info")
	if not text or text == "" then return text, nil end
	local caps = parse_phy_info(text)
	M._phy_info_cache[phy] = {text = text, caps = caps, at = now}
	return text, caps
end

-- The secondary 20 MHz channel's side of the primary, as the QCA driver
-- reports it (getparam chextoffset; UniFi firmware sends it as vap
-- extchannel): 1 above, -1 below, 0 without one. Above 40 MHz it is the
-- primary's partner in its 40 MHz half, so halve the block around the
-- primary until 40 MHz is left (80 MHz at 5530, primary 5520: 40 MHz at
-- 5510, so -1).
function M.ext_offset(freq, width, center)
	if not (freq and width and center) or width < 40 then return 0 end
	while width > 40 do
		width = width / 2
		if freq < center then center = center - width / 2
		else center = center + width / 2 end
	end
	return freq < center and 1 or -1
end

-- What `iw dev <ifname> info` says about one interface. Inside a pass every
-- radio's answer comes off one `iw dev`, which lists each interface under a
-- `phy#N` header with the same lines `info` prints minus `wiphy N`; that line
-- is put back, so callers read either text alike. An interface the dump does
-- not list is asked for on its own.
local function iw_dev_info(ifname)
	local by_ifname = M._pass and pass_memo("iw_dev", function()
		local map, phy, lines = {}, nil, nil
		for line in (M._run_cmd("iw dev") or ""):gmatch("[^\n]+") do
			local p = line:match("^phy#(%d+)")
			if p then
				phy, lines = p, nil
			elseif line:match("^\t%S") then
				-- A new interface entry; an unnamed one (a P2P device) is
				-- skipped whole rather than read as part of the last.
				local name = line:match("^\tInterface (%S+)")
				lines = nil
				if name and phy then
					lines = {"Interface " .. name, "\twiphy " .. phy}
					map[name] = lines
				end
			elseif lines then
				lines[#lines + 1] = line:sub(2)
			end
		end
		for name, l in pairs(map) do map[name] = table.concat(l, "\n") .. "\n" end
		return map
	end)
	return by_ifname and by_ifname[ifname] or M._run_cmd("iw dev " .. ifname .. " info")
end

function M.radio_caps(ifname)
	if not ifname then return {} end
	local dev_info = iw_dev_info(ifname)
	local phy = dev_info:match("wiphy%s+(%d+)")
	if not phy then return {} end
	local phy_info, static = M._phy_info(phy)
	if not phy_info or phy_info == "" or not static then return {} end

	-- The hardware half comes off the cached phy dump; copied rather than
	-- returned directly, since callers merge their own fields into what they
	-- get back (build_json writes radio_caps/wpa3_supported onto it).
	local caps = {}
	for k, v in pairs(static) do caps[k] = v end

	-- The live negotiated channel ("channel 6 (2437 MHz), width: ...") is
	-- more authoritative than UCI's own config value, which is frequently
	-- "auto" (a config *intent*, not a number) -- the controller has no use
	-- for the literal string "auto" here and was left showing channel 0.
	local channel = dev_info:match("channel%s+(%d+)")
	-- The live TX power ("txpower 23.00 dBm"), for exactly the same reason as
	-- the channel above: UCI carries no `txpower` option at all while the
	-- controller's Transmit Power is set to Auto (absent = driver default),
	-- so the payload's tx_power was nil and the Radios view reported every
	-- radio as transmitting at 0 dBm -- confirmed against a real controller,
	-- with the hardware actually at 23 dBm (5GHz) and 17 dBm (2.4GHz).
	-- Floored to whole dBm, which is the unit the field is in.
	local txpower = tonumber(dev_info:match("txpower%s+([%d%.]+)"))
	caps.channel  = channel and tonumber(channel) or nil
	caps.tx_power = txpower and math.floor(txpower) or nil
	-- Live channel width in MHz ("width: 80 MHz"), for the satisfaction
	-- estimate's rate ceiling. Not a wire field: build_json takes it off.
	caps.width    = tonumber(dev_info:match("width:%s+(%d+)"))
	-- Which side of the primary the secondary 20 MHz sits: 1 above, -1
	-- below, 0 at 20 MHz. Not a radio_table field: build_json moves it to
	-- each vap's extchannel.
	caps.extchannel = M.ext_offset(tonumber(dev_info:match("channel%s+%d+%s+%((%d+) MHz%)")),
		caps.width, tonumber(dev_info:match("center1:%s+(%d+)")))

	return caps
end

-- First-seen timestamps for wired hosts, keyed by "<source> mac" -- used to
-- derive `uptime` in M.mac_table()/M.switch_mac_table() the same way
-- sta_table's connected_sec comes from iw (which has no equivalent concept
-- for a learned MAC).
-- Injectable/resettable by tests, same pattern as M._prev_cpu above.
M._mac_first_seen = {}
M._mac_last_seen  = {}
M._time = os.time

-- How long a host stays remembered after it was last seen. See M._note_seen.
M.MAC_FORGET_AFTER = 3600
-- How often the forget sweep walks the tables. It ran once per sighting, so a
-- heartbeat with N wired hosts walked them N times.
M.MAC_SWEEP_EVERY = 60
M._mac_swept_at = nil

-- Record that key was seen now; returns when it was FIRST seen. Also the only
-- place the two tables ever shrink: a host not seen for an hour is forgotten,
-- so a daemon that runs for months does not keep every MAC that ever crossed
-- the bridge.
--
-- The sweep runs at most once a minute; `key` itself is checked every time:
-- a host back after an hour away starts a fresh uptime instead of reporting
-- the wall-clock time since it was first seen, which for a host that was gone
-- for most of it is not an uptime at all. That is also what a real switch
-- reports for a re-learned MAC.
function M._note_seen(key, now)
	local swept = M._mac_swept_at
	if not swept or now - swept >= M.MAC_SWEEP_EVERY or now < swept then
		M._mac_swept_at = now
		for k, last in pairs(M._mac_last_seen) do
			if now - last > M.MAC_FORGET_AFTER then
				M._mac_last_seen[k]  = nil
				M._mac_first_seen[k] = nil
			end
		end
	end
	local first, last = M._mac_first_seen[key], M._mac_last_seen[key]
	if first and last and now - last > M.MAC_FORGET_AFTER then first = nil end
	if not first then
		first = now
		M._mac_first_seen[key] = now
	end
	M._mac_last_seen[key] = now
	return first
end

-- MAC -> IP from /proc/net/arp (the header line has no MAC and is skipped by
-- the pattern itself). Shared by both wired-host sources below.
function M._ip_by_mac()
	return pass_memo("ip_by_mac", function()
		local by_mac = {}
		local arp_out = arp_text()
		if arp_out then
			for line in arp_out:gmatch("[^\n]+") do
				local ip, mac = line:match("^(%S+)%s+%S+%s+%S+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
				if ip and mac then by_mac[mac:lower()] = ip end
			end
		end
		return by_mac
	end)
end

-- MAC -> hostname from dnsmasq's lease file, when this device runs the DHCP
-- server (format: "<expiry> <mac> <ip> <hostname> <client-id>"). An AP usually
-- is not, so this is empty far more often than not.
function M._hostname_by_mac()
	return pass_memo("hostname_by_mac", function()
		local by_mac = {}
		local leases_out = M._read_file("/tmp/dhcp.leases")
		if leases_out then
			for line in leases_out:gmatch("[^\n]+") do
				local mac, hostname = line:match("^%d+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+%S+%s+(%S+)")
				if mac and hostname and hostname ~= "*" then
					by_mac[mac:lower()] = hostname
				end
			end
		end
		return by_mac
	end)
end

-- Returns a table of wired hosts learned on ifname's bridge port, by
-- combining three sources also present on a real OpenWrt AP:
--   `bridge fdb show dev <ifname>` -- authoritative MAC<->port mapping.
--   `/proc/net/arp`                -- MAC -> IP.
--   `/tmp/dhcp.leases`             -- MAC -> hostname (only present when this
--                                    device is also the DHCP server; an AP
--                                    usually is not, so hostname is optional).
-- Each entry: {mac, ip, hostname, age, uptime}
--
-- Only dynamically-learned entries on this exact ifname are host candidates:
-- lines containing "self" are the interface's own local addresses, and
-- "permanent" entries are statically configured (this is also how bridge
-- reports multicast/broadcast group addresses) -- neither is a real client.
-- A multicast-bit check on the MAC's first octet is kept as a second filter
-- in case a caller's mocked/real bridge output ever omits those markers.
--
-- `bridge` is optional and names the bridge ifname is enslaved to. Given one,
-- the hosts come from the single `bridge fdb show br <bridge>` that
-- M.bridge_fdb_ports already ran for the uplink question -- one dump of the
-- kernel FDB carries every port's hosts, and it applies the identical
-- master/self/permanent filter, so `bridge fdb show dev <socket>` per socket
-- was re-dumping a strict subset of it. On the AX3000T's four sockets that was
-- four forks per heartbeat for data already in hand. Without a bridge (every
-- direct caller, and the tests) it forks per socket exactly as before.
-- The MACs an nftables tap has seen ingressing each socket, as
-- {[ifname] = {mac, ...}}, from one `nft list set`.
--
-- This exists because of a hardware fact, not a software preference. A socket
-- openUF moves into a VLAN bridge must have MAC learning turned OFF or the
-- switch ASIC hardware-drops the replies coming back to it (switchvlan.lua's
-- dsa_apply documents the measurement). Learning off empties the bridge FDB for
-- that socket, and the FDB is where every other wired-host answer comes from --
-- so for exactly those sockets there is no kernel table left to read, and the
-- hosts behind them stopped being reported at all.
--
-- The tap is the observation point that survives: switchvlan installs bridge
-- prerouting rules that file each frame's source address into dynamic sets with
-- timeouts matching the bridge's own FDB ageing, so an unplugged client expires
-- the way it used to. Two sets, read from one dump of the table:
--
--     set portmacs {
--         elements = { "lan2" . 00:00:5e:00:53:07 expires 4m59s990ms }
--     }
--     set portips {
--         elements = { "lan2" . 00:00:5e:00:53:07 . 192.0.2.20 expires 5m }
--     }
--
-- Captured verbatim from nftables v1.1.6 on the real board, not guessed. The
-- quoted ifname is what makes the pattern unambiguous against the `type ifname
-- . ether_addr` lines and the `iifname { "lan2" }` rules in the same dump, and
-- the presence of a third `. <dotted quad>` component is what tells the two
-- sets' elements apart without tracking which set block we are inside.
--
-- The address half is what keeps the controller's network label right: it
-- classifies a wired client by the IP its reporter supplies, and an assigned
-- socket is on a VLAN this AP holds no address on, so /proc/net/arp will never
-- answer for it.
--
-- One dump per pass, and only asked for at all when a caller knows it has a
-- socket in this position -- see mac_table's `allow_tap`.
M.NFT_LEARN_TABLE = "bridge openuf_learn"

-- Seconds left on a dynamic element, from the `expires 4m59s980ms` suffix nft
-- prints. Every element carries the same timeout, so what is left is a direct
-- proxy for how recently the tap last saw that host -- which is how a MAC that
-- has held two addresses inside one timeout window resolves to the current one.
-- Note `ms` must be tested before `m`/`s`, or 980ms reads as 980 minutes.
local function nft_expires_secs(rest)
	local t = rest:match("expires%s+(%S+)")
	if not t then return nil end
	local secs = 0
	for n, unit in t:gmatch("(%d+)(%a+)") do
		local mult = (unit == "ms" and 0.001) or (unit == "s" and 1)
			or (unit == "m" and 60) or (unit == "h" and 3600)
			or (unit == "d" and 86400) or 0
		secs = secs + tonumber(n) * mult
	end
	return secs
end

-- {macs = {[ifname] = {mac, ...}}, ips = {[ifname] = {[mac] = ip}}} from one
-- `nft list table`. One table rather than two return values on purpose:
-- pass_memo caches a single value, so a second result would be silently lost
-- on every call after the first of a pass.
function M.nft_tap()
	return pass_memo("nft_tap", function()
		local macs, ips, fresh = {}, {}, {}
		local out = M._run_cmd("nft list table " .. M.NFT_LEARN_TABLE)
		if not out or out == "" then return {macs = macs, ips = ips} end
		for ifname, mac, rest in
			out:gmatch('"([^"]+)"%s*%.%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)([^,\n]*)') do
			-- Same multicast-bit filter the FDB and ARL sources apply. A
			-- source address can never be multicast, so this only ever
			-- rejects a malformed dump -- kept for the same reason it is
			-- kept there.
			local first_octet = tonumber(mac:sub(1, 2), 16)
			if first_octet and first_octet % 2 == 0 then
				mac = mac:lower()
				local ip = rest:match("^%s*%.%s*(%d+%.%d+%.%d+%.%d+)")
				if ip then
					local seen = ips[ifname]
					if not seen then
						seen = {}; ips[ifname] = seen; fresh[ifname] = {}
					end
					local age = nft_expires_secs(rest) or 0
					local best = fresh[ifname][mac]
					-- Freshest wins, and on a tie the lower address, so the
					-- payload cannot flip between two live answers from one
					-- heartbeat to the next.
					if best == nil or age > best
						or (age == best and ip < seen[mac]) then
						seen[mac], fresh[ifname][mac] = ip, age
					end
				else
					local bucket = macs[ifname]
					if not bucket then bucket = {}; macs[ifname] = bucket end
					bucket[#bucket + 1] = mac
				end
			end
		end
		for _, bucket in pairs(macs) do table.sort(bucket) end
		return {macs = macs, ips = ips}
	end)
end

-- MACs -> the {mac, ip, hostname, age, uptime} rows port_table publishes.
-- Shared by both of mac_table's sources so the tap's rows are indistinguishable
-- from the FDB's: same ARP/lease join, same _note_seen-derived uptime.
-- `tap_ips` is {[mac] = ip} for this socket, used only where the ARP cache has
-- nothing: /proc/net/arp is the AP's own L3 view and is authoritative wherever
-- it can answer, but it can never answer for a socket on a VLAN the AP holds no
-- address on -- which is exactly the socket the tap exists for.
local function hosts_from_macs(ifname, macs, tap_ips)
	local ip_by_mac       = M._ip_by_mac()
	local hostname_by_mac = M._hostname_by_mac()

	local now = M._time()
	local hosts = {}
	for _, mac in ipairs(macs) do
		local first_seen = M._note_seen(ifname .. " " .. mac, now)
		hosts[#hosts + 1] = {
			mac      = mac,
			ip       = ip_by_mac[mac:lower()]
				or (tap_ips and tap_ips[mac:lower()]) or nil,
			hostname = hostname_by_mac[mac:lower()],
			-- age: seconds since last observed on this fdb -- 0 since this
			-- call just observed it fresh (matches TtZhv's use of `age` to
			-- pick the more-recently-seen of two ports reporting the same
			-- client, favoring whichever port's dump is being processed).
			age      = 0,
			uptime   = math.floor(now - first_seen),
		}
	end
	return hosts
end

-- `allow_tap` opts this socket into the nft fallback above, and is the caller's
-- job because only the caller knows a socket is in the position that needs it
-- (its bridge is not the uplink's -- i.e. openUF moved it). Left off, a board
-- with no assigned socket never forks `nft` at all. The FDB always wins: the
-- tap is consulted only when the kernel had nothing to say.
function M.mac_table(ifname, bridge, allow_tap)
	if not ifname then return {} end
	local macs
	if bridge then
		macs = hosts_by_port(M.bridge_fdb_ports(bridge))[ifname]
	else
		local fdb_out = M._run_cmd("bridge fdb show dev " .. ifname)
		macs = {}
		for line in fdb_out:gmatch("[^\n]+") do
			if not line:find("self") and not line:find("permanent") and line:find("master") then
				local mac = line:match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
				if mac then
					local first_octet = tonumber(mac:sub(1, 2), 16)
					if first_octet and first_octet % 2 == 0 then
						macs[#macs + 1] = mac
					end
				end
			end
		end
	end
	local tap
	if allow_tap then
		tap = M.nft_tap()
		if not macs or #macs == 0 then macs = tap.macs[ifname] end
	end
	if not macs or #macs == 0 then return {} end
	return hosts_from_macs(ifname, macs, tap and tap.ips[ifname] or nil)
end

-- === swconfig: what the CPU netdev cannot tell you =========================
--
-- On the ath79 boards openUF targets, every ethernet socket sits behind a
-- switch ASIC and the kernel sees only the CPU port. sysfs therefore answers
-- questions about the internal SoC<->switch link (always 1000/full), not about
-- the socket a cable is actually in, and the bridge FDB attributes every wired
-- host to the one CPU netdev. Both were reported as port facts and both were
-- wrong on real hardware -- a TL-WDR3500 whose uplink socket had negotiated
-- 100baseT reported GbE, while the gateway's own view of the same link said FE.
--
-- The switch knows all of it, and one `swconfig dev <sw> show` returns the lot:
-- per-port link/speed/duplex, per-port pvid, the ARL table (MAC -> physical
-- port), and -- where the driver exposes them -- per-port MIB byte counters.

-- Parses one `swconfig dev <device> show` into
--   {ports = {[phys] = {up, speed, full_duplex, pvid, rx_bytes, tx_bytes}},
--    arl   = {[mac] = phys}}
-- Both tables are empty when swconfig is missing or the board has no switch,
-- which is the signal callers use to stay on the netdev-only path.
--
-- Two line shapes both start with "Port <n>:" and must not be confused: an ARL
-- entry ("Port 4: MAC aa:bb:..", listed under the global attributes, one line
-- per learned host) and a port section header ("Port 4:" alone, followed by
-- indented attributes). The MAC is the discriminator.
--
-- MIB counters are optional: the AR8327 in an Archer C5 reports "mib: ???"
-- (its ar8xxx_mib_poll_interval is 0) while the AR9344 in a WDR3500 prints a
-- RxGoodByte/TxByte block. Only those two counters exist even there -- there
-- is no per-port packet or error count to be had from this interface.
function M.switch_status(device)
	local status = {ports = {}, arl = {}}
	local out = M._run_cmd("swconfig dev " .. (device or "switch0") .. " show")
	if not out or out == "" then return status end

	local cur   -- physical port whose section is being parsed
	for line in out:gmatch("[^\n]+") do
		local arl_port, arl_mac =
			line:match("^Port (%d+):%s+MAC%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		local header = line:match("^Port (%d+):%s*$")
		if arl_mac then
			status.arl[arl_mac:lower()] = tonumber(arl_port)
		elseif header then
			cur = tonumber(header)
			status.ports[cur] = {up = false}
		elseif line:match("^VLAN %d+:") then
			cur = nil   -- the VLAN table follows the port sections
		elseif cur and status.ports[cur] then
			local p = status.ports[cur]
			local pvid = line:match("^%s*pvid:%s*(%d+)")
			if pvid then p.pvid = tonumber(pvid) end
			local state = line:match("^%s*link:%s*port:%d+%s+link:(%a+)")
			if state then
				p.up = (state == "up")
				if p.up then
					local speed = line:match("speed:(%d+)baseT")
					p.speed = speed and tonumber(speed) or nil
					p.full_duplex = line:match("(%a+)%-duplex") ~= "half"
				end
			end
			local rx = line:match("^RxGoodByte%s*:%s*(%d+)")
			if rx then p.rx_bytes = tonumber(rx) end
			local tx = line:match("^TxByte%s*:%s*(%d+)")
			if tx then p.tx_bytes = tonumber(tx) end
		end
	end
	return status
end

-- Uplink detection is deliberately MEASURED rather than declared (see
-- M.uplink_phys_port): a modelmap constant is wrong the moment someone moves
-- the cable. But one of its inputs is not a measurement of the cable at all
-- and was re-asked every ten seconds anyway: the default route's gateway IP
-- (an `ip route` fork). It changes only when the network is reconfigured.
-- (Which bridge a netdev sits in is a sysfs read, cheap enough to ask live.)
--
-- Cached with the same TTL discipline as PHY_INFO_TTL. What stays live is the
-- part that actually follows the cable: the gateway's MAC is looked up in the
-- ARP cache every time, and resolved against the ARL/FDB every time, so a
-- moved cable is still picked up on the next heartbeat.
--
-- A nil answer is NOT cached. "No default route yet" is an ordinary state
-- during boot, before DHCP has settled; caching it would leave the device
-- unable to find its uplink for the next five minutes.
M.UPLINK_TTL = 300
M._uplink_cache = {}
local function uplink_memo(key, fn)
	local now = M._time()
	local c = M._uplink_cache[key]
	if c and (now - c.at) < M.UPLINK_TTL then return c.value end
	local value = fn()
	if value ~= nil then M._uplink_cache[key] = {value = value, at = now} end
	return value
end

-- The MAC of the default gateway: its IP from the default route, then that
-- IP's hardware address from the kernel's ARP cache. Lowercased. nil whenever
-- any link of the chain is missing -- no default route, no ARP entry yet.
--
-- This is the "which way is the controller" question, and both uplink
-- detectors below are only different ways of asking the switch where that MAC
-- lives: swconfig's ARL table on ath79, the bridge FDB on DSA.
function M._default_gateway_mac()
	local gw_ip = uplink_memo("default_gw_ip", function()
		return tostring(M._run_cmd("ip route show default") or "")
			:match("default%s+via%s+(%d+%.%d+%.%d+%.%d+)")
	end)
	if not gw_ip then return nil end
	local arp_out = arp_text()
	if not arp_out then return nil end
	for line in arp_out:gmatch("[^\n]+") do
		local ip, mac = line:match("^(%S+)%s+%S+%s+%S+%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if ip == gw_ip and mac then return mac:lower() end
	end
	return nil
end

-- Which physical switch port the uplink cable is in, from an ARL table as
-- returned by M.switch_status().arl -- the port the default gateway's MAC was
-- learned on. Verified against both real boards: the same gateway MAC appears
-- on physical port 4 of one AP and port 2 of the other, matching the cabling.
--
-- Deliberately measured rather than declared in the modelmap. These boards are
-- deployed as APs with the cable in whichever LAN socket is convenient, and a
-- wrong answer is not a cosmetic error: a socket wrongly treated as downstream
-- makes the AP report the entire LAN segment, gateway included, as hosts
-- plugged into it. Returns nil whenever any link of the chain is missing, and
-- callers must then fall back to the netdev-only port rather than guess.
function M.uplink_phys_port(arl)
	if type(arl) ~= "table" then return nil end
	local gw_mac = M._default_gateway_mac()
	return gw_mac and arl[gw_mac] or nil
end

-- === DSA: the same questions, asked of the bridge ==========================
--
-- A DSA board (mediatek/filogic, and every other 21.02+ target) has no
-- swconfig and no ARL to read. It does not need one: each socket is its own
-- netdev, so sysfs answers link speed and duplex per socket honestly rather
-- than describing an internal CPU link, and the bridge FDB answers the one
-- thing sysfs cannot -- which socket a MAC sits behind.
--
-- Confirmed on a Xiaomi Mi Router AX3000T, whose four sockets are the netdevs
-- wan/lan2/lan3/lan4, all enslaved to br-lan.

-- The bridge a netdev is enslaved to, or nil when it is not a bridge port.
function M.bridge_of(ifname)
	return util.master_of(ifname, M._read_file)
end

-- {[mac] = port_ifname} for every host the bridge has LEARNED, from one
-- `bridge fdb show br <bridge>`. The DSA analogue of switch_status().arl.
--
-- Same filter discipline as M.mac_table, and for the same reasons. The
-- load-bearing half is "permanent": the port's own address arrives as
-- `<mac> dev wan master br-lan permanent` -- a master line like any other,
-- separable only by that word, and counting it would put the AP's own socket
-- MAC in its own client list. The "self" half is belt-and-braces (the
-- AX3000T lists every learned MAC a second time as "dev wan self", but those
-- lines carry no "master" and are already excluded).
function M.bridge_fdb_ports(bridge)
	if not bridge then return {} end
	-- Memoized for the length of a pass: this one dump answers the uplink
	-- question AND every socket's own host list (see M.mac_table), which
	-- otherwise forked `bridge fdb show dev <socket>` once per socket for a
	-- strict subset of what is already here.
	return pass_memo("fdb_br:" .. bridge, function()
	local ports = {}
	local out = M._run_cmd("bridge fdb show br " .. bridge)
	if not out or out == "" then return ports end
	for line in out:gmatch("[^\n]+") do
		if line:find("master") and not line:find("self")
			and not line:find("permanent") then
			local mac, port = line:match(
				"^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+dev%s+(%S+)")
			if mac and port then ports[mac:lower()] = port end
		end
	end
	return ports
	end)
end

-- Which bridge port -- i.e. which socket -- the uplink cable is in, as an
-- ifname. Same contract as M.uplink_phys_port: measured, never declared, and
-- nil rather than a guess when the chain cannot be completed.
function M.uplink_bridge_port(bridge)
	local gw_mac = M._default_gateway_mac()
	if not gw_mac then return nil end
	return M.bridge_fdb_ports(bridge)[gw_mac]
end

-- The wired hosts learned on one physical switch port, in the same shape
-- M.mac_table() returns ({mac, ip, hostname, age, uptime}) so port_table's
-- consumer does not care which source a port's hosts came from.
--
-- Multicast/broadcast MACs are filtered on the address's own multicast bit --
-- the ARL has no "self"/"permanent" markers to lean on the way `bridge fdb`
-- does. The device's own MACs and its wireless stations are filtered by the
-- caller, which is where both sets are already known.
function M.switch_mac_table(phys, arl)
	if phys == nil or type(arl) ~= "table" then return {} end
	local macs = hosts_by_port(arl)[phys]
	if not macs or #macs == 0 then return {} end

	local ip_by_mac       = M._ip_by_mac()
	local hostname_by_mac = M._hostname_by_mac()

	local now = M._time()
	local hosts = {}
	for _, mac in ipairs(macs) do
		local first_seen = M._note_seen("swport" .. tostring(phys) .. " " .. mac, now)
		hosts[#hosts + 1] = {
			mac      = mac,
			ip       = ip_by_mac[mac],
			hostname = hostname_by_mac[mac],
			age      = 0,
			uptime   = math.floor(now - first_seen),
		}
	end
	return hosts
end

return M
