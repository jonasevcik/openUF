--[[
	System metrics reader for the inform JSON payload.

	All I/O functions are injectable via M._read_file and M._run_cmd so that
	unit tests can substitute fixture data without touching the real filesystem.
]]--

local M = {}

-- Injectable: override in tests to return fixture file contents
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- Injectable: override in tests to return fixture command output
M._run_cmd = function(cmd)
	local h = io.popen(cmd .. " 2>/dev/null")
	if not h then return "" end
	local s = h:read("*a")
	h:close()
	return s or ""
end


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
function M.uptime()
	local s = M._read_file("/proc/uptime")
	if not s then return 0 end
	local secs = tonumber(s:match("^(%S+)"))
	return secs and math.floor(secs) or 0
end

-- Returns load averages as {one, five, fifteen} by parsing /proc/loadavg.
function M.loadavg()
	local s = M._read_file("/proc/loadavg")
	if not s then return {one = 0, five = 0, fifteen = 0} end
	local one, five, fifteen = s:match("^(%S+)%s+(%S+)%s+(%S+)")
	return {
		one     = tonumber(one)     or 0,
		five    = tonumber(five)    or 0,
		fifteen = tonumber(fifteen) or 0,
	}
end

-- Returns {total_kb, free_kb} by parsing /proc/meminfo.
function M.meminfo()
	local s = M._read_file("/proc/meminfo")
	if not s then return {total_kb = 0, free_kb = 0} end
	local total = tonumber(s:match("MemTotal:%s+(%d+)"))
	local free  = tonumber(s:match("MemFree:%s+(%d+)"))
	return {
		total_kb = total or 0,
		free_kb  = free  or 0,
	}
end

-- Previous /proc/stat sample for delta-based CPU% (see M.cpu_percent).
-- Exposed for tests to reset/inspect between calls.
M._prev_cpu = nil

-- Returns CPU usage percent (0-100) since the previous call, by delta-
-- sampling the aggregate "cpu" line in /proc/stat (matches the real
-- inform payload's system-stats.cpu, which is a live percentage -- not to
-- be confused with M.loadavg(), a different metric real devices don't
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

-- Returns per-radio channel utilisation from `iw dev <ifname> survey dump`.
-- Returns a table: {freq, noise, channel_time, channel_time_busy, channel_time_rx, channel_time_tx}
function M.radio_stats(ifname)
	if not ifname then return {} end
	local output = M._run_cmd("iw dev " .. ifname .. " survey dump")
	local result = {}
	local current = nil
	for line in output:gmatch("[^\n]+") do
		local freq = line:match("frequency:%s+(%d+)")
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
			-- Anchored to (whitespace-then-)start of line so "channel busy
			-- time:" doesn't also match inside the separate "extension
			-- channel busy time:" field iw emits on wider channels.
			local noise   = line:match("noise:%s+(-?%d+)")
			local ct      = line:match("^%s*channel active time:%s+(%d+)")
			local ct_busy = line:match("^%s*channel busy time:%s+(%d+)")
			local ct_rx   = line:match("^%s*channel receive time:%s+(%d+)")
			local ct_tx   = line:match("^%s*channel transmit time:%s+(%d+)")
			if noise   then current.noise              = tonumber(noise)   end
			if ct      then current.channel_time       = tonumber(ct)      end
			if ct_busy then current.channel_time_busy  = tonumber(ct_busy) end
			if ct_rx   then current.channel_time_rx    = tonumber(ct_rx)   end
			if ct_tx   then current.channel_time_tx    = tonumber(ct_tx)   end
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

-- Returns a table of connected stations from `iw dev <ifname> station dump`.
-- Each entry: {mac, signal, tx_bitrate, rx_bitrate, tx_mcs, rx_mcs,
--              tx_generation, tx_nss, rx_generation, rx_nss, tx_bytes,
--              rx_bytes, tx_packets, rx_packets, tx_retries, tx_failed,
--              inactive_ms, connected_sec}
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
			-- ANCHORED, and this matters: `iw` emits "avg ack signal:\t-95 dBm"
			-- further down the same station block, which an unanchored
			-- "signal:%s+" also matches -- and being later, it overwrote the
			-- real reading. Every client was reported at the ack-signal value
			-- (-95 dBm on this driver) no matter its actual RSSI. That feeds
			-- the Clients list, the vap's avg_client_signal, the satisfaction
			-- estimate AND Minimum RSSI enforcement, which would have deauthed
			-- every client on the radio the moment the feature was switched
			-- on. ("last ack signal:-95" escaped only by luck: no space after
			-- the colon.) The per-chain suffix ("-53 [-76, -53, -66] dBm") is
			-- ignored -- the first number is the combined RSSI.
			local signal     = line:match("^%s*signal:%s+(-?%d+)")
			local tx_rate    = line:match("tx bitrate:%s+(%S+)")
			local rx_rate    = line:match("rx bitrate:%s+(%S+)")
			-- tx_mcs/rx_mcs: only present on their respective bitrate line,
			-- and only for 11n/ac/ax rates -- legacy (pre-MCS) rates have no
			-- "MCS N" suffix, so these stay nil for those, same as other
			-- optional fields below.
			local tx_mcs     = line:match("tx bitrate:.*MCS%s+(%d+)")
			local rx_mcs     = line:match("rx bitrate:.*MCS%s+(%d+)")
			if line:find("tx bitrate:") then
				cur.tx_generation, cur.tx_nss = _bitrate_generation_nss(line)
			elseif line:find("rx bitrate:") then
				cur.rx_generation, cur.rx_nss = _bitrate_generation_nss(line)
			end
			local tx_bytes   = line:match("tx bytes:%s+(%d+)")
			local rx_bytes   = line:match("rx bytes:%s+(%d+)")
			local tx_pkts    = line:match("tx packets:%s+(%d+)")
			local rx_pkts    = line:match("rx packets:%s+(%d+)")
			local tx_retries = line:match("tx retries:%s+(%d+)")
			local tx_failed  = line:match("tx failed:%s+(%d+)")
			local inactive   = line:match("inactive time:%s+(%d+)")
			local connected  = line:match("connected time:%s+(%d+)")
			if signal    then cur.signal      = tonumber(signal)     end
			if tx_rate   then cur.tx_bitrate  = tonumber(tx_rate)    end
			if rx_rate   then cur.rx_bitrate  = tonumber(rx_rate)    end
			if tx_mcs    then cur.tx_mcs      = tonumber(tx_mcs)     end
			if rx_mcs    then cur.rx_mcs      = tonumber(rx_mcs)     end
			if tx_bytes  then cur.tx_bytes    = tonumber(tx_bytes)   end
			if rx_bytes  then cur.rx_bytes    = tonumber(rx_bytes)   end
			if tx_pkts   then cur.tx_packets  = tonumber(tx_pkts)    end
			if rx_pkts   then cur.rx_packets  = tonumber(rx_pkts)    end
			if tx_retries then cur.tx_retries = tonumber(tx_retries) end
			if tx_failed  then cur.tx_failed  = tonumber(tx_failed)  end
			if inactive  then cur.inactive_ms = tonumber(inactive)   end
			if connected then cur.connected_sec = tonumber(connected) end
		end
	end
	if cur then clients[#clients + 1] = cur end
	return clients
end

-- Returns a table of neighboring wireless networks visible to ifname, by
-- parsing `iw dev <ifname> scan dump` -- the kernel's already-cached BSS
-- list from cfg80211, not a fresh scan (that's what the spectrum-scan cmd
-- handler's separate `iw dev <ifname> scan` call triggers; reading the
-- cache here is cheap and non-disruptive enough to do on every inform,
-- unlike a real scan).
-- Each entry: {bssid, essid, freq, channel, signal, security, age, bw}
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
function M.scan_table(ifname)
	if not ifname then return {} end
	local output = M._run_cmd("iw dev " .. ifname .. " scan dump")
	-- For the [boottime] form of "last seen" below: /proc/uptime and the
	-- driver's stamp are both on the CLOCK_BOOTTIME axis.
	local now_up = M.uptime()
	local nets = {}
	local cur = nil
	local seen_rsn, seen_wpa, seen_privacy = false, false, false
	-- Width evidence from the operation elements, per BSS. See flush().
	local vht_w, vht_seg1, vht_seg2, ht_sec = nil, nil, nil, nil

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
			if vht_w and vht_w >= 1 then
				local seg2 = vht_seg2 or 0
				if vht_w == 2 or (vht_w == 1 and seg2 > 0
						and math.abs(seg2 - (vht_seg1 or 0)) == 8) then
					cur.bw = 160
				else
					cur.bw = 80
				end
			elseif ht_sec == "above" or ht_sec == "below" then
				cur.bw = 40
			else
				cur.bw = 20
			end
		end
		if seen_rsn then cur.security = "wpa2"
		elseif seen_wpa then cur.security = "wpa"
		elseif seen_privacy then cur.security = "wep"
		else cur.security = "open" end
		nets[#nets + 1] = cur
	end

	for line in output:gmatch("[^\n]+") do
		local bssid = line:match("^BSS (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if bssid then
			flush()
			cur = {bssid = bssid}
			seen_rsn, seen_wpa, seen_privacy = false, false, false
			vht_w, vht_seg1, vht_seg2, ht_sec = nil, nil, nil, nil
		elseif cur then
			-- Operation-element width evidence, consumed by flush(). The VHT
			-- line is anchored on "* channel width:" so that the HT capability
			-- line sitting two lines below it cannot match: that one reads
			-- "* STA channel width: 20 MHz" on a 20 MHz neighbour, and an
			-- unanchored pattern would read the 20 as a VHT width field and
			-- report the BSS as 80 MHz.
			local w = line:match("^%s*%*%s+channel width:%s+(%d+)")
			if w then vht_w = tonumber(w) end
			local s1 = line:match("center freq segment 1:%s+(%d+)")
			if s1 then vht_seg1 = tonumber(s1) end
			local s2 = line:match("center freq segment 2:%s+(%d+)")
			if s2 then vht_seg2 = tonumber(s2) end
			local sec = line:match("secondary channel offset:%s+(%a+)")
			if sec then ht_sec = sec end
			local freq     = line:match("freq:%s+(%d+)")
			-- Anchored for the same reason as the station-dump copy above,
			-- defensively: scan output carries no ack-signal lines today.
			local signal   = line:match("^%s*signal:%s+(-?%d+)")
			local ssid     = line:match("^\tSSID:%s?(.*)$")
			local last_ms  = line:match("last seen:%s+(%d+) ms ago")
			-- iw also prints the driver's BOOTTIME stamp: "last seen:
			-- 662754.792s [boottime]". Some entries carry ONLY that form --
			-- seen on our own AX3000T -- which the pattern above never
			-- matched, so their age stayed at the 0 default and every such
			-- neighbour was reported as seen this instant, however stale. The
			-- "ms ago" line wins when both are printed for one BSS (it is what
			-- the controller's own staleness rule is written against, and it
			-- is printed second); this fills in when it is the only one.
			local last_bt  = line:match("last seen:%s+([%d%.]+)s %[boottime%]")
			local bw       = line:match("BSS operating channel width:%s+(%d+) MHz")
			if freq then
				cur.freq    = tonumber(freq)
				cur.channel = M.channel_from_freq(freq)
			end
			if signal then cur.signal = tonumber(signal) end
			if ssid and not cur.essid then cur.essid = ssid end
			if last_ms then
				cur.age = math.floor(tonumber(last_ms) / 1000)
			elseif last_bt and cur.age == nil and now_up > 0 then
				cur.age = math.max(0, math.floor(now_up - tonumber(last_bt)))
			end
			if bw then cur.bw = tonumber(bw) end
			if line:find("capability:.*Privacy") then seen_privacy = true end
			if line:find("^\tRSN:") then seen_rsn = true end
			if line:find("^\tWPA:") then seen_wpa = true end
		end
	end
	flush()
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

function M.radio_caps(ifname)
	if not ifname then return {} end
	local dev_info = M._run_cmd("iw dev " .. ifname .. " info")
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

-- Record that key was seen now; returns when it was FIRST seen. Also the only
-- place the two tables ever shrink: a host not seen for an hour is forgotten,
-- so a daemon that runs for months does not keep every MAC that ever crossed
-- the bridge.
--
-- The sweep runs BEFORE this sighting is recorded, so it applies to `key`
-- itself as well: a host back after an hour away starts a fresh uptime instead
-- of reporting the wall-clock time since it was first seen, which for a host
-- that was gone for most of it is not an uptime at all. That is also what a
-- real switch reports for a re-learned MAC.
function M._note_seen(key, now)
	for k, last in pairs(M._mac_last_seen) do
		if now - last > M.MAC_FORGET_AFTER then
			M._mac_last_seen[k]  = nil
			M._mac_first_seen[k] = nil
		end
	end
	local first = M._mac_first_seen[key]
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
		local arp_out = M._read_file("/proc/net/arp")
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
function M.mac_table(ifname, bridge)
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
	if not macs or #macs == 0 then return {} end

	local ip_by_mac       = M._ip_by_mac()
	local hostname_by_mac = M._hostname_by_mac()

	local now = M._time()
	local hosts = {}
	for _, mac in ipairs(macs) do
		local first_seen = M._note_seen(ifname .. " " .. mac, now)
		hosts[#hosts + 1] = {
			mac      = mac,
			ip       = ip_by_mac[mac:lower()],
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

-- The MAC of the default gateway: its IP from the default route, then that
-- IP's hardware address from the kernel's ARP cache. Lowercased. nil whenever
-- any link of the chain is missing -- no default route, no ARP entry yet.
--
-- This is the "which way is the controller" question, and both uplink
-- detectors below are only different ways of asking the switch where that MAC
-- lives: swconfig's ARL table on ath79, the bridge FDB on DSA.
function M._default_gateway_mac()
	local gw_ip = tostring(M._run_cmd("ip route show default") or "")
		:match("default%s+via%s+(%d+%.%d+%.%d+%.%d+)")
	if not gw_ip then return nil end
	local arp_out = M._read_file("/proc/net/arp")
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
-- /sys/class/net/<if>/master symlinks to the enslaving device.
function M.bridge_of(ifname)
	if not ifname then return nil end
	local m = M._run_cmd("readlink /sys/class/net/" .. ifname .. "/master")
	m = type(m) == "string" and m:match("([^/%s]+)%s*$") or nil
	if m and m ~= "" and m ~= ifname then return m end
	return nil
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
