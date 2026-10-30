--[[
	UniFi inform protocol client.

	Sends encrypted JSON payloads to the controller via HTTP POST every 10
	seconds (the standard UniFi heartbeat interval).  Parses and dispatches
	the controller's response.

	Binary packet format (TNBU, "UBNT" reversed):
	  Offset  Len  Field
	   0       4   Magic: 0x54 0x4E 0x42 0x55 ("TNBU")
	   4       4   Packet version (uint32 BE) — always 0
	   8       6   Device MAC
	  14       2   Flags (uint16 BE):
	               0x01 = payload encrypted (AES-128-CBC or GCM)
	               0x02 = payload zlib-compressed
	               0x08 = use AES-128-GCM instead of CBC (requires 0x01)
	  16      16   AES IV
	  32       4   Data version (uint32 BE) — always 1 (= JSON payload)
	  36       4   Payload length (uint32 BE)
	  40+      *   Payload (may be compressed then encrypted)
]]--

-- socket is lazy-loaded inside http_post/run so the module can be required
-- in test environments that do not have luasocket installed.
local cjson  = require("cjson")

-- Load sibling modules (relative paths for when run from openuf/ dir or installed)
local function _require_sibling(name)
	local paths = {name .. ".lua", "openuf/" .. name .. ".lua"}
	for _, p in ipairs(paths) do
		local f = io.open(p, "r")
		if f then f:close(); return dofile(p) end
	end
	error("cannot find module: " .. name)
end

local crypto    = _require_sibling("crypto")
local state     = _require_sibling("state")
local sysinfo   = _require_sibling("sysinfo")
local lldp      = _require_sibling("lldp")
local ucihelper = _require_sibling("ucihelper")
local led       = _require_sibling("led")
local netconfig = _require_sibling("netconfig")
local firewall  = _require_sibling("firewall")
local usteer    = _require_sibling("usteer")
local switchvlan = _require_sibling("switchvlan")
local rrmscan   = _require_sibling("rrmscan")
local roamassist = _require_sibling("roamassist")
local sysconf   = _require_sibling("sysconf")
local l2guard   = _require_sibling("l2guard")
local airtime   = _require_sibling("airtime")
local assoctrack = _require_sibling("assoctrack")
local guestportal = _require_sibling("guestportal")
local satisfaction = _require_sibling("satisfaction")
local minrssi   = _require_sibling("minrssi")
local loadbalance = _require_sibling("loadbalance")
local wlansched = _require_sibling("wlansched")
local stun      = _require_sibling("stun")
local shaper    = _require_sibling("shaper")
local rrbguard  = _require_sibling("rrbguard")

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()
local bit = util.bit()

-- Injectable: expose internal modules so tests can inject fixtures
-- _crypto included: without the seam, a test file's own crypto instance (its
-- separate dofile) is stubbed while build_packet/parse_packet keep using this
-- private one -- which once made a fixed-IV stub silently ineffective and a
-- whole encryption assertion vacuous.
M._crypto    = crypto
M._state     = state
M._sysinfo   = sysinfo
M._ucihelper = ucihelper
M._plugins   = _require_sibling("plugins")
M._lldp      = lldp
M._led       = led
M._netconfig = netconfig
M._firewall  = firewall
M._usteer    = usteer
M._switchvlan = switchvlan
M._rrmscan    = rrmscan
-- A beacon report's width is decided exactly as the scan cache's is.
if rrmscan and sysinfo then rrmscan._channel_width = sysinfo.channel_width end
M._roamassist = roamassist
M._minrssi    = minrssi
M._loadbalance = loadbalance
M._wlansched  = wlansched
M._shaper     = shaper
M._airtime    = airtime
M._sysconf    = sysconf
M._l2guard    = l2guard
M._assoctrack = assoctrack
M._guestportal = guestportal
M._satisfaction = satisfaction
M._stun      = stun
M._rrbguard  = rrbguard

-- In-memory only: 802.11k beacon-report neighbours, keyed by BSSID, plus the
-- flat list build_json merges from. Clients report asynchronously and only
-- some of them ever answer, so this is a best-effort side-channel that
-- supplements the passive scan cache -- see rrmscan.lua for the whole story.
M._rrm_cache        = {}
M._rrm_neighbours   = {}
M._rrm_next_request = 0
M._rrm_rr           = 0

-- Stations asked for a beacon report that have not answered, keyed by MAC:
-- {n = unanswered requests so far, at = when the last one went out}. A
-- station's RRM capability bits are not a promise -- a client can advertise
-- passive, active AND table measurement and still answer every variant with
-- report mode 0x02, "incapable". hostapd does not notify a bodiless refusal
-- over ubus, so from here such a station is simply one that never reports,
-- and asking it again every interval forever would only ever cost it an ack.
-- After RRM_MAX_UNANSWERED asks with nothing back it is left alone for
-- RRM_BENCH_SECONDS, then tried once more. Any report from it clears the count.
M._rrm_asked         = {}
M.RRM_MAX_UNANSWERED = 2
M.RRM_BENCH_SECONDS  = 6 * 3600

-- How often to ask ONE station for a sweep. An active beacon measurement takes
-- the client off-channel for roughly duration x channels (~1.3 s for a full
-- operating class at 50 TU), so this is deliberately slow: the point is to
-- keep the Environment tab honest, not to poll. Hourly, because hostapd writes
-- every report it receives to syslog as a hex line (~15 per answer, outside
-- openUF's control): at 600 s they took 72-78% of a 128 KB logread buffer,
-- live 2026-10-13. The controller keeps a reported neighbour ~24 h (rogueap
-- rows 22 h old still listed), so an hourly refresh loses no row.
M.RRM_REQUEST_INTERVAL = 3600

-- How often the background collector is checked for life. That check forks
-- `pgrep -f`, and ran on every 10-second heartbeat -- but the subscription
-- only dies when one of the hostapd objects it named goes away, which is a
-- config push, not a ten-second event. _tick re-arms it immediately after a
-- config IS applied (see M._rrm_collector_next), so recovery stays instant
-- exactly where it matters and the steady state costs nothing.
M.RRM_COLLECTOR_CHECK_INTERVAL = 60
M._rrm_collector_next = 0
-- ... and once that check reports no collector, there is nothing left for it
-- to find: only collector_ensure starts one, and it clears this. A site that
-- wants no subscriber (DFS only, or nothing on at all) therefore pgreps once,
-- not once a minute forever. _reap_collector owns both.
M._collector_reaped = false

-- Connection tracking for the controller's WiFi Connectivity view (see
-- assoctrack.lua). _vap_by_ifname maps a hostapd BSS netdev to the vap_table
-- `name` the controller resolves an event's `vap` against -- refreshed by every
-- build_json. _notif_identity is the device-identifying subset of the last
-- payload, which every notif inform repeats: the lab controller accepted a
-- notif carrying only these fields and filed its stats under this AP.
M._vap_by_ifname     = {}
M._notif_identity    = nil
M._assoc_installed   = false
-- Notif informs are one POST each. A burst of reconnects (an AP restart roams
-- everybody back) is drained over a few cycles instead of in one.
M.NOTIFS_PER_CYCLE   = 8
-- Roam reports (assoctrack.lua) cannot wait for the heartbeat: the controller
-- pairs a departure with an arrival only within 10 s, and calls the roam
-- failed when the departure arrived more than a second ahead. While
-- connection tracking is on, _idle wakes this often to read the collector's
-- file and sends any roam report at once. _roam_fast and _roam_st are set by
-- each _tick; _pre_blob holds what _idle drained, for the heartbeat's
-- beacon-report harvest, and only while that harvest runs (_roam_keep). It
-- is a list of chunks, joined once by the harvest: _idle drains ~60 times a
-- heartbeat, and appending to one string recopied it each time.
M.ROAM_POLL_S        = 0.25
M._roam_fast         = false
M._roam_keep         = false
M._roam_st           = nil
M._pre_blob          = nil
-- Whether any radio was on a DFS channel on the last build_json, which is
-- what decides the control-socket monitors are worth running even with
-- 802.11k enrichment off: they are the only producer of the radar event.
M._dfs_radio         = false

-- Matches rrmscan.merge_into's own cutoff, which exists because the
-- controller's rogue-AP ingestion silently drops any entry with age >= 30.
local RRM_MAX_AGE = 30

-- In-memory only (not persisted to state.json): per-radio spectrum-scan
-- results, keyed by radio name. Ephemeral live data, same category as
-- radio_stats()/sta_table() which are also recomputed rather than stored.
M._spectrum_cache = {}

-- In-memory only, keyed by client MAC: each station's WiFi Experience window
-- (satisfaction.lua) and when it was last seen.
M._sta_stats_cache = {}
-- ...and how long an unseen station stays in it. See the sweep in build_json.
M.STA_STATS_FORGET_AFTER = 600

-- In-memory only, keyed by radio name: the in-use survey counters at the last
-- inform and the utilisation computed from them. See _windowed_cu.
M._cu_cache = {}

-- Injectable: override in tests to control elapsed time deterministically.
M._time = os.time

-- Injectable: override in tests to return fixture command output
M._run_cmd = util.capture

-- Injectable: sysfs reader for the per-netdev link attributes below.
M._read_file = util.read_file

-- Negotiated link speed in Mbit/s for a netdev, or nil when the kernel can't
-- report one (interface down, or a virtual device with no PHY -- reading
-- /sys/class/net/<if>/speed on a down interface returns an error, which
-- io.read surfaces as nil or an unparseable string, both handled here).
function M._link_speed(ifname)
	if not ifname then return nil end
	local n = tonumber((tostring(M._read_file(
		"/sys/class/net/" .. ifname .. "/speed") or ""):match("(-?%d+)") or ""))
	-- The kernel reports -1 for "unknown"; treat that as no reading.
	if n and n > 0 then return n end
	return nil
end

-- "full"/"half"/nil, from the same sysfs directory.
function M._link_duplex(ifname)
	if not ifname then return nil end
	local s = M._read_file("/sys/class/net/" .. ifname .. "/duplex")
	return s and s:match("^%s*(%a+)") or nil
end

-- Does the port have a link partner? Reads sysfs `carrier` (1/0), falling back
-- to `operstate` ("up"/"down"), and returns nil when neither is readable.
--
-- A port's mere existence in /proc/net/dev is NOT link state: an unused socket
-- is present, counted, and utterly idle. Reporting it as up was visible on a
-- real TL-WDR3500, whose eth1 (the unused WAN socket) went out as
-- "up, 1000 Mbps" while carrier was 0 and the kernel reported speed -1.
function M._link_up(ifname)
	if not ifname then return nil end
	local carrier = M._read_file("/sys/class/net/" .. ifname .. "/carrier")
	if carrier then
		local n = tonumber((carrier:match("(%d+)") or ""))
		if n then return n == 1 end
	end
	local state = M._read_file("/sys/class/net/" .. ifname .. "/operstate")
	if state then return state:match("^%s*(%a+)") == "up" end
	return nil
end

-- A token that changes whenever the state file changes, or nil when the file
-- cannot be read. Compared for equality only -- callers never interpret it --
-- so its type is free to vary.
--
-- The token is the file's own CONTENTS. This used to try `stat -c %Y` first
-- and keep the contents as a fallback, which cost a fork on the very first
-- line of every heartbeat and bought nothing:
--
--   * it cannot be relied on anyway. BusyBox gates `-c` behind
--     FEATURE_STAT_FORMAT and some builds omit the stat applet entirely
--     (confirmed on a real TL-WDR3500 with no stat at all), so on those boards
--     the fork was guaranteed to fail and this line ran regardless -- every
--     ten seconds, forever.
--   * the contents are the STRONGER test. mtime has one-second granularity,
--     so two writes inside the same second are indistinguishable by it.
--   * state.json is a few hundred bytes, and it is what M._state.load() is
--     about to read anyway.
--
-- So the fork bought strictly less correctness than the free path it fell back
-- to. The one thing lost with it is detecting a change to a file too large to
-- want to re-read; state.json is not that file, and never will be.
function M._state_mtime(path)
	return M._read_file(path)
end

-- Whether `user`'s password is locked, read off /etc/shadow (`passwd -l`
-- prefixes the hash with "!"). nil when the file or the user cannot be read,
-- which the caller treats as "unknown, act anyway".
M.SHADOW_FILE = "/etc/shadow"
function M._account_locked(user)
	local shadow = M._read_file(M.SHADOW_FILE)
	if not shadow then return nil end
	for line in shadow:gmatch("[^\n]+") do
		local name, hash = line:match("^([^:]+):([^:]*):")
		if name == user then return hash:sub(1, 1) == "!" end
	end
	return nil
end

-- The controller's heartbeat interval. Every `noop` carries `interval`, the
-- cadence the controller wants (PROTOCOL-VALIDATION.md, "Response _types");
-- real firmware adopts it, and openUF used to run a fixed 10 s and throw the
-- field away. Clamped, because pre-adoption responses arrive in plain HTTP
-- under the well-known key: a forged noop must not be able to make the device
-- hammer the controller or go quiet for an hour. nil (no field, or not a
-- number) means "back to the device's own cadence".
M.INTERVAL_MIN = 5
M.INTERVAL_MAX = 300
M._controller_interval = nil

function M._sane_interval(v)
	v = tonumber(v)
	if not v or v ~= v then return nil end
	if v < M.INTERVAL_MIN then return M.INTERVAL_MIN end
	if v > M.INTERVAL_MAX then return M.INTERVAL_MAX end
	return math.floor(v)
end

-- Locks or unlocks the temporary SSH bootstrap account (see conf.lua's
-- bootstrap_adopt_user and USAGE.md's SSH prerequisite section) to match
-- the device's current adopted state. No-op if user is nil/false (feature
-- not enabled). Reads the current state first: BusyBox passwd is harmless on
-- an already-locked account but not silent -- it logs "password for <user>
-- is already locked" to auth.err, and this runs on every config push, so an
-- adopted AP's log filled with it. When the state cannot be read the command
-- is issued regardless.
function M._sync_bootstrap_account(adopted, user)
	if not user then return end
	local locked = M._account_locked(user)
	if adopted then
		if locked == true then return end
		M._run_cmd("passwd -l '" .. user .. "'")
	else
		if locked == false then return end
		M._run_cmd("passwd -u '" .. user .. "'")
	end
end

-- Packet constants
local MAGIC        = "TNBU"
local PKT_VERSION  = 1   -- confirmed by amd989/unifi-gateway and fxkr reverse-engineering
local DATA_VERSION = 1

-- Inform flags
local FLAG_ENCRYPTED  = 0x01
local FLAG_COMPRESSED = 0x02
local FLAG_SNAPPY     = 0x04  -- Snappy compression (amd989 prefers it; we send zlib only)
local FLAG_GCM        = 0x08

-- Injectable: override in tests to skip real HTTP
M._http_post = nil

-- ─── Binary helpers ───────────────────────────────────────────────────────────

local function uint32_be(n)
	return string.char(
		bit.band(bit.rshift(n, 24), 0xFF),
		bit.band(bit.rshift(n, 16), 0xFF),
		bit.band(bit.rshift(n,  8), 0xFF),
		bit.band(n,                 0xFF)
	)
end

local function uint16_be(n)
	return string.char(
		bit.band(bit.rshift(n, 8), 0xFF),
		bit.band(n,                0xFF)
	)
end

local function parse_uint32_be(s, offset)
	local b1, b2, b3, b4 = string.byte(s, offset, offset + 3)
	return bit.bor(
		bit.lshift(b1 or 0, 24),
		bit.lshift(b2 or 0, 16),
		bit.lshift(b3 or 0,  8),
		          (b4 or 0)
	)
end

local function parse_uint16_be(s, offset)
	local hi, lo = string.byte(s, offset, offset + 1)
	return (hi or 0) * 256 + (lo or 0)
end

local function mac_bytes(mac_str)
	-- "aa:bb:cc:dd:ee:ff" → 6-byte binary string
	local bytes = {}
	for h in mac_str:gmatch("[0-9a-fA-F]+") do
		bytes[#bytes + 1] = string.char(tonumber(h, 16))
	end
	if #bytes ~= 6 then error("mac_bytes: invalid MAC: " .. tostring(mac_str)) end
	return table.concat(bytes)
end

-- 32 hex chars = 16 bytes = a valid AES-128 key (matches syswrapper.lua's check)
local function is_hex32(s)
	return type(s) == "string" and #s == 32 and s:match("^[0-9a-fA-F]+$") ~= nil
end

-- Exactly "aa:bb:cc:dd:ee:ff". Wire-supplied MACs -- the MAC filter's ACL, the
-- Multicast/Broadcast Blocker's allow-list -- end up inside nft and
-- hostapd_cli command lines (bcfilter.lua, firewall.lua) or in UCI lists
-- hostapd parses, so anything not of this shape is refused at the boundary
-- rather than escaped. The controller is authenticated once adopted, but
-- before that the inform channel is plain HTTP under the well-known default
-- key and a forged setparam is within reach of anyone on the path; this is
-- what keeps that from becoming a shell.
local is_mac = util.is_mac

-- The only tokens wireless.<n>.bcfilt.bypass_types can carry (the controller
-- writes the whole string as one literal, so this is the closed vocabulary,
-- not a sample). Each maps to one nft exemption in bcfilter.lua; the value is
-- documentation only, the key is what matters. NSNA is IPv6 Neighbour
-- Solicitation/Advertisement -- ARP's IPv6 equivalent, which is why the
-- controller pairs the two.
local BCFILT_BYPASS_TYPES = {
	ARP    = "ether type arp",
	NSNA   = "ICMPv6 neighbour solicitation/advertisement",
	DHCPV4 = "UDP 67/68 over IPv4",
	DHCPV6 = "UDP 546/547 over IPv6",
}

-- ─── Packet builder ──────────────────────────────────────────────────────────

-- A native zlib binding, looked up once: a failed require is not remembered
-- by Lua, so asking per packet walked every package.path and cpath entry on
-- every inform and notification. false = none (OpenWrt ships none).
local _zlib
local function zlib_binding()
	if _zlib == nil then
		local ok, z = pcall(require, "zlib")
		_zlib = ok and type(z) == "table" and z or false
	end
	return _zlib
end

-- The pure-Lua inflater, loaded on the first compressed response only.
local _inflate
local function inflater()
	_inflate = _inflate or _require_sibling("inflate")
	return _inflate
end

-- Build a TNBU binary packet from a JSON string.
-- st: state table (authkey, mac, use_gcm)
-- GCM AAD = first 40 bytes of the packet header (per amd989/unifi-gateway encode_inform)
function M.build_packet(json_str, st)
	local crypto = M._crypto  -- injectable seam, see the module top
	local use_gcm = st.use_gcm and crypto.gcm_available()
	local payload = json_str

	-- Compress with zlib if available
	local flags = FLAG_ENCRYPTED
	local zlib = zlib_binding()
	if zlib and zlib.compress then
		local compressed = zlib.compress(payload)
		if compressed and #compressed < #payload then
			payload = compressed
			flags = bit.bor(flags, FLAG_COMPRESSED)
		end
	end
	if use_gcm then flags = bit.bor(flags, FLAG_GCM) end

	local iv      = crypto.random_iv(16)
	local mac_bin = mac_bytes(st.mac or "00:00:00:00:00:00")

	-- 36-byte fixed prefix (before payload_len field)
	local prefix = MAGIC
		.. uint32_be(PKT_VERSION)
		.. mac_bin
		.. uint16_be(flags)
		.. iv
		.. uint32_be(DATA_VERSION)

	local ciphertext
	if use_gcm then
		-- GCM: payload len = compressed len + 16-byte tag; assemble full 40-byte AAD first
		local aad = prefix .. uint32_be(#payload + 16)
		local ct, tag = crypto.aes_gcm_encrypt(st.authkey, iv, payload, aad)
		ciphertext = ct .. tag
		return aad .. ciphertext
	else
		ciphertext = crypto.aes_cbc_encrypt(st.authkey, iv, payload)
		return prefix .. uint32_be(#ciphertext) .. ciphertext
	end
end

-- ─── Packet parser ───────────────────────────────────────────────────────────

-- Parse and decrypt a TNBU binary packet.
-- Returns json_str, flags.  Raises on magic mismatch or decryption failure.
function M.parse_packet(raw, st)
	local crypto = M._crypto  -- injectable seam, see the module top
	if #raw < 40 then
		error("inform: packet too short (" .. #raw .. " bytes)")
	end

	local magic = raw:sub(1, 4)
	if magic ~= MAGIC then
		error("inform: bad magic: " .. magic:gsub(".", function(c)
			return string.format("\\x%02x", string.byte(c))
		end))
	end

	-- pkt_version = parse_uint32_be(raw, 5)  -- currently unused
	-- mac         = raw:sub(9, 14)            -- currently unused
	local flags      = parse_uint16_be(raw, 15)
	local iv         = raw:sub(17, 32)
	-- data_version = parse_uint32_be(raw, 33) -- currently unused
	local payload_len = parse_uint32_be(raw, 37)
	local payload     = raw:sub(41, 40 + payload_len)

	if #payload < payload_len then
		error("inform: truncated payload")
	end

	-- Decrypt
	if bit.band(flags, FLAG_ENCRYPTED) ~= 0 then
		local key = st.authkey
		if bit.band(flags, FLAG_GCM) ~= 0 then
			-- AAD = full 40-byte packet header (per amd989/unifi-gateway decode_inform)
			local aad = raw:sub(1, 40)
			local ct  = payload:sub(1, #payload - 16)
			local tag = payload:sub(#payload - 15)
			payload = crypto.aes_gcm_decrypt(key, iv, ct, tag, aad)
		else
			payload = crypto.aes_cbc_decrypt(key, iv, payload)
		end
	end

	-- Decompress — Snappy (0x04) is not supported; zlib (0x02) is.
	if bit.band(flags, FLAG_SNAPPY) ~= 0 then
		error("inform: controller sent snappy-compressed response; lua-snappy not supported")
	end
	if bit.band(flags, FLAG_COMPRESSED) ~= 0 then
		local done = false
		-- Prefer a native zlib binding if the host happens to have one...
		local zlib = zlib_binding()
		if zlib and zlib.decompress then
			local ok_d, out = pcall(zlib.decompress, payload)
			if ok_d and out then payload = out; done = true end
		end
		-- ...otherwise fall back to the in-tree pure-Lua inflater (OpenWrt 25.12
		-- ships no Lua zlib binding, so this is the normal path there).
		if not done then
			payload = inflater().zlib_decompress(payload)
		end
	end

	return payload, flags
end

-- ─── JSON payload builder ────────────────────────────────────────────────────

-- ISO 3166-1 alpha-2 -> numeric, for the payload's country_code field. The
-- wifi-device's UCI `country` option (the regdomain OpenWrt programs) is the
-- source; best-effort coverage of common regulatory domains -- an unlisted
-- code falls back to 840 (US), the old hardcoded value, rather than sending
-- nothing.
local ISO3166_NUMERIC = {
	US = 840, CA = 124, MX = 484, BR = 76, AU = 36, NZ = 554, JP = 392,
	CN = 156, KR = 410, IN = 356, GB = 826, IE = 372, DE = 276, FR = 250,
	NL = 528, BE = 56, LU = 442, AT = 40, CH = 756, IT = 380, ES = 724,
	PT = 620, DK = 208, SE = 752, NO = 578, FI = 246, IS = 352, PL = 616,
	CZ = 203, SK = 703, HU = 348, SI = 705, HR = 191, RO = 642, BG = 100,
	GR = 300, EE = 233, LV = 428, LT = 440, UA = 804, TR = 792, ZA = 710,
	SG = 702, TW = 158, HK = 344, TH = 764, MY = 458, ID = 360, PH = 608,
	VN = 704, IL = 376, AE = 784, SA = 682, AR = 32, CL = 152, CO = 170,
}

-- The same map inverted, for the inbound direction: the controller pushes its
-- site's regulatory domain as a NUMERIC code (system_cfg's
-- radio.<n>.countrycode), while UCI's `country` option wants the alpha-2 one.
-- Built from the table above so the two directions can never disagree.
local ISO3166_ALPHA = {}
for alpha, numeric in pairs(ISO3166_NUMERIC) do ISO3166_ALPHA[numeric] = alpha end

-- cjson encodes an empty Lua table as a JSON OBJECT ({}), but the payload's
-- list fields (vap_table, scan_radio_table, mac_table, ...) must serialize
-- as ARRAYS ([]) -- the controller's DTOs type them as lists, and {} for an
-- empty list is a wire-format ambiguity no decoded-side test could ever see.
-- empty_array_mt is feature-detected: a modern lua-cjson tags the table so
-- it encodes as []; an older target build silently keeps the old behavior
-- rather than erroring. Non-empty tables are unambiguous either way.
local _EMPTY_ARRAY_MT = type(cjson) == "table" and cjson.empty_array_mt or nil
local function arr(t)
	if _EMPTY_ARRAY_MT and next(t) == nil then
		return setmetatable(t, _EMPTY_ARRAY_MT)
	end
	return t
end

-- Belt for arr()'s braces: the TARGET's lua-cjson (OpenWrt's 2.1.0-era build,
-- confirmed on the validation container) has neither empty_array_mt nor the
-- empty_array sentinel, so the metatable route degrades to {} exactly where
-- it matters most. This post-pass rewrites '"<field>":{}' to '"<field>":[]'
-- for the known list fields on the ENCODED string -- version-independent.
-- Safe against false positives: cjson escapes quotes inside string values,
-- so the unescaped '"field":{}' shape cannot occur inside one.
-- One pass over the payload, not one per field: each gsub copies the whole
-- encoded string. And a plain find for the '":{}' itself rather than a gsub
-- on the field name: that tried a match at every quote in the payload (about
-- 1800 of them, 19 ms on the Archer C5) to find the few empty objects.
local _ARRAY_FIELDS = {
	if_table = '"if_table":[]', radio_table = '"radio_table":[]',
	radio_table_stats = '"radio_table_stats":[]', vap_table = '"vap_table":[]',
	scan_radio_table = '"scan_radio_table":[]', port_table = '"port_table":[]',
	lldp_table = '"lldp_table":[]', sta_table = '"sta_table":[]',
	mac_table = '"mac_table":[]', scan_table = '"scan_table":[]',
}
function M._fix_empty_arrays(json_str)
	local out, from, at = nil, 1, 1
	while true do
		local s = json_str:find('":{}', at, true)
		if not s then break end
		-- The field name ends at s-1; the longest listed one is 17 bytes.
		local name = json_str:sub(math.max(1, s - 24), s - 1):match('"([%w_]+)$')
		local repl = name and _ARRAY_FIELDS[name]
		if repl then
			out = out or {}
			out[#out + 1] = json_str:sub(from, s - #name - 2)
			out[#out + 1] = repl
			from = s + 4
		end
		at = s + 4
	end
	if not out then return json_str end
	out[#out + 1] = json_str:sub(from)
	return table.concat(out)
end

-- One port's `mac_table`: the wired hosts a source reports, minus the two sets
-- that are never wired clients of this AP -- its own netdev MACs, and the
-- stations currently associated to its radios (a wireless client bridged into
-- br-lan genuinely shows up in the bridge FDB and the switch ARL too).
-- `source` is sysinfo.mac_table(ifname, bridge, allow_tap) or
-- sysinfo.switch_mac_table(phys, arl), so it takes up to three arguments; a
-- failing source yields no hosts rather than aborting the payload.
--
-- `vlan` stamps every row with the VLAN the socket carries, and is what decides
-- which NETWORK the controller files these clients under. It walks the site's
-- layer-2 networks and keeps a reported host only where the network's VLAN id
-- equals the row's `vlan`, defaulting to 1:
--
--     if (network.getVlan() != host.getInt("vlan", 1)) continue;
--
-- (confirmed in the 10.6 controller's wired-client processor). Omitted, every
-- host defaults to 1 and lands in the untagged network no matter which socket
-- reported it -- so a client on a socket openUF assigned to a VLAN was filed
-- under the management LAN while its port, IP and the Ports view's own Native
-- VLAN column all said otherwise. It is also half of the controller's dedup key
-- for these rows (`mac` .. `vlan`), so one host reachable on two VLANs stays two
-- rows rather than collapsing into one.
--
-- Left nil for the management VLAN: the controller drops a `vlan` of 1 on
-- arrival, so sending it says nothing and costs bytes on every heartbeat.
local function _filter_hosts(source, a, b, c, vlan, self_macs, station_macs)
	local hosts = {}
	local ok, found = pcall(source, a, b, c)
	if not ok or type(found) ~= "table" then return hosts end
	for _, host in ipairs(found) do
		if not self_macs[host.mac] and not station_macs[host.mac] then
			hosts[#hosts + 1] = {
				mac      = host.mac,
				ip       = host.ip,
				hostname = host.hostname,
				age      = host.age,
				uptime   = host.uptime,
				vlan     = vlan,
			}
		end
	end
	return hosts
end

-- Pick the survey entry describing the channel the radio is actually on.
--
-- `iw dev <if> survey dump` emits one entry per channel the phy supports, in
-- the phy's own frequency order -- so the operating channel is wherever it
-- happens to fall (entry 11 of 13 for 2.4GHz ch11, entry 3 of 24 for 5GHz
-- ch44), essentially never first. Every other entry is a scan dwell holding
-- a few milliseconds of accumulated time, so deriving utilisation from
-- stats[1] divided a busy figure by a ~3 ms active time: confirmed live on
-- both APs, a genuinely 24%-busy 2.4GHz channel was reported to the
-- controller as 100% and a 1.9%-busy 5GHz channel as 75%, which is what made
-- the APs look like they were drowning in interference. The same wrong entry
-- also supplied the noise floor Minimum RSSI was (wrongly) converted with.
--
-- Falls back to the first entry when nothing is marked, which keeps drivers
-- (and test doubles) that omit the marker behaving exactly as before.
local function _in_use_survey(stats)
	if type(stats) ~= "table" then return nil end
	for _, s in ipairs(stats) do
		if s.in_use then return s end
	end
	return stats[1]
end

-- Channel utilisation (cu_total/cu_self_rx/cu_self_tx, percent) over the
-- time since the previous inform, not since the radio came up.
--
-- The survey counters accumulate from bring-up, so busy/active is a lifetime
-- average: an 11-hour-old 2.4 GHz radio kept reporting 25% whatever the air
-- was doing now. A UniFi AP reports the last ~1 s. Its driver (umac.ko,
-- ieee80211_beacon_chanutil_update2) diffs the MIB rx_clear/rx_frame/
-- tx_frame/cycle counters every 10 beacon intervals and stores each as
-- round(delta * 100 / cycle_delta). Firmware-confirmed for 4.0.15. The
-- window here is one inform interval: the nearest sample openUF has.
--
-- The first reading, a channel change, or counters that went backwards (the
-- radio restarted) fall back to the counters as they stand, which is then
-- everything since that restart. A reading with no new active time (two
-- builds within the same millisecond, or a driver that stalls the counters)
-- repeats the previous result rather than inventing 0%.
local function _windowed_cu(name, s)
	local now = {
		freq   = s.freq,
		active = s.channel_time or 0,
		busy   = s.channel_time_busy or 0,
		rx     = s.channel_time_rx or 0,
		tx     = s.channel_time_tx or 0,
	}
	local prev = name and M._cu_cache[name]
	local d = now
	if prev and prev.freq == now.freq and now.active >= prev.active
	   and now.busy >= prev.busy and now.rx >= prev.rx and now.tx >= prev.tx then
		if now.active == prev.active then
			now.out = prev.out
			M._cu_cache[name] = now
			return prev.out[1], prev.out[2], prev.out[3]
		end
		d = {
			active = now.active - prev.active,
			busy   = now.busy - prev.busy,
			rx     = now.rx - prev.rx,
			tx     = now.tx - prev.tx,
		}
	end
	local function pct(x)
		if d.active <= 0 then return 0 end
		return math.min(100, math.floor(x * 100 / d.active + 0.5))
	end
	now.out = {pct(d.busy), pct(d.rx), pct(d.tx)}
	if name then M._cu_cache[name] = now end
	return now.out[1], now.out[2], now.out[3]
end

-- Build the inform JSON payload.
-- st: current state table
-- cfg: device configuration (from conf.lua)
-- ufhw: ufmodel table
function M.build_json(st, cfg, ufhw)
	local uap = ufhw and ufhw.uap or {}

	-- Opened before the first sysinfo call, not partway down: this payload's
	-- very first question -- the uptime -- is one scan_table asks again per
	-- radio, and measuring a real heartbeat on hardware showed it still being
	-- read twice because the pass started below it. Nothing in here may
	-- outlive the payload; _tick closes it again even if this function throws.
	if M._sysinfo.begin_pass then M._sysinfo.begin_pass() end

	-- Collect sysinfo
	local uptime     = M._sysinfo.uptime()
	local meminfo    = M._sysinfo.meminfo()
	local cpu_pct    = M._sysinfo.cpu_percent()
	local load1, load5, load15
	if M._sysinfo.loadavg then load1, load5, load15 = M._sysinfo.loadavg() end
	local stun_ip, stun_port = M._stun.fields(M._stun_c)
	local mem_pct    = meminfo.total_kb > 0
	                    and math.floor((meminfo.total_kb - meminfo.free_kb) * 100 / meminfo.total_kb + 0.5)
	                    or 0
	local ifaces    = M._sysinfo.interfaces()
	local lldp_nbrs = M._lldp.neighbors()

	-- Build if_table
	local if_table = {}
	for _, iface in ipairs(ifaces) do
		if_table[#if_table + 1] = {
			name        = iface.name,
			mac         = iface.mac,
			rx_bytes    = iface.rx_bytes,
			tx_bytes    = iface.tx_bytes,
			rx_packets  = iface.rx_packets,
			tx_packets  = iface.tx_packets,
			rx_errors   = iface.rx_errors,
			tx_errors   = iface.tx_errors,
		}
	end

	-- radio_table and vap_table require UCI (not available in test context)
	local radio_table       = {}
	local radio_table_stats = {}
	local vap_table         = {}
	-- 802.11k merge inputs, built on first use; see the scan_table merge.
	local rrm_skip, rrm_site
	local scan_radio_table  = {}
	local derived_country   = nil  -- from the radios' UCI regdomain, below

	local mac_str = st.mac or "00:00:00:00:00:00"

	-- Wireless station MACs, collected below while building vap_table --
	-- subtracted from port_table's mac_table entries further down so a
	-- wireless client bridged into br-lan (and thus also visible in the
	-- bridge FDB) is never double-reported as a wired client too.
	local station_macs = {}
	-- WiFi Experience tallies, one per VAP, filled by the per-VAP station
	-- loop further down: all of them for the device's score, and per radio
	-- for that radio's (see satisfaction.lua).
	local sat_tallies, sat_tallies_by_radio = {}, {}
	-- The device's own MACs (its netdevs) -- excluded from port_table's
	-- mac_table for the same reason: without this, the AP would report
	-- itself as a wired client of its own switch.
	local self_macs = {[mac_str] = true}
	for _, iface in ipairs(ifaces) do
		if iface.mac and iface.mac ~= "" then self_macs[iface.mac] = true end
	end

	-- ufuci: VAP/radio info (require("uci") calls inside it can legitimately
	-- fail off-target, so individual calls are still pcall-wrapped below)
	local ufuci = M._ucihelper
	local own_uci_pass = false
	if ufuci and ufuci.get_vap_table then
		-- One `ubus call network.wireless status` for the whole payload: every
		-- get_ifname_for_radio/vap below (one per VAP in get_vap_table, one
		-- per radio, one per VAP again) otherwise re-runs it for the same
		-- answer -- ten identical forks per heartbeat on a two-radio,
		-- four-SSID box. Feature-detected: test doubles inject a ucihelper
		-- without it. _tick() opens the pass for its whole cycle, and then
		-- this joins it; called on its own, this opens one and closes it on
		-- return. _tick() ends the pass even when this function throws.
		own_uci_pass = ufuci.begin_pass and ufuci.begin_pass()
		local ok_v, rv = pcall(ufuci.get_vap_table)
		if ok_v then vap_table = rv end
		-- The modelmap's hwassign restricts which radios are reported; absent,
		-- every wifi-device in UCI is (see get_radio_table). It lives at
		-- dev.openuf.uap in the modelmap while cfg here is dev.conf, so the
		-- entry point merges it in as cfg.uap -- same pattern as cfg.config.
		local hwassign = cfg and cfg.uap and cfg.uap.hwassign
		local ok_r, rr = pcall(ufuci.get_radio_table, hwassign)
		if ok_r then radio_table = rr end

		-- One walk of radio_table for the two facts derived from it, both of
		-- them per-device rather than per-radio:
		--
		--   country_code -- the regulatory domain, off the first radio that
		--   declares one (UCI sets the same country on every wifi-device).
		--   Was hardcoded 840 (US) for every deployment.
		--
		--   dfs_radio -- is any radio somewhere a radar hit can happen? Read
		--   off the configured channel rather than the live one on purpose:
		--   "auto" has no channel here and ACS can land on a DFS channel
		--   either way, so an auto radio counts, and the monitors then run
		--   for a 2.4-only board too. Cheap: they are one hostapd_cli per
		--   BSS, idle until an event.
		--
		-- Neither answer can change again once it is settled, so the walk
		-- stops as soon as both are -- which on both reference boards is the
		-- first radio, since UCI gives every wifi-device the country.
		-- `country_done`, not `derived_country ~= nil`: the first radio that
		-- declares a country settles the question even when the name is not
		-- in the table, which is what the separate loop did by breaking.
		local dfs_radio, country_done = false, false
		for _, r in ipairs(radio_table) do
			if r.country and not country_done then
				derived_country = ISO3166_NUMERIC[tostring(r.country):upper()]
				country_done = true
			end
			if not dfs_radio then
				local ch = tostring(r.channel or "")
				if ch == "" or ch == "auto" or ch == "0" then
					-- r.radio is get_radio_table's band ("ng"/"na");
					-- build_json only re-derives `band` further down, after
					-- this point.
					if r.radio ~= "ng" then dfs_radio = true end
				elseif M._rrmscan and M._rrmscan.is_dfs_channel
					and M._rrmscan.is_dfs_channel(ch) then
					dfs_radio = true
				end
			end
			if country_done and dfs_radio then break end
		end
		M._dfs_radio = dfs_radio

		-- Live per-radio channel utilization, parallel to radio_table (matches
		-- real UniFi's split of static config vs. live stats). Also kept in
		-- radio_cu_stats, keyed by radio name, so each vap_table entry on
		-- that radio can carry the same cu_* figures -- confirmed via
		-- decompile (com.ubnt.service.system.XrjNIQhefUEBuL's archived-field
		-- schema registry) that cu_interf/cu_self_tx/cu_self_rx live in the
		-- same per-VAP schema group as avg_client_signal, not solely in
		-- radio_table_stats: live-tested against a real controller, adding
		-- them only to radio_table_stats left the archiver's client_signal_avg
		-- populating every cycle while cu_interf/cu_total never appeared at
		-- all despite being sent correctly.
		local radio_cu_stats = {}
		-- radio_table_stats entries, keyed by UCI radio name, so the VAP loop
		-- can attach per-radio TX counters after summing them per station.
		local radio_stats_by_name = {}
		-- Minimum RSSI enforcement data, keyed by radio name (e.g. "radio0"),
		-- consumed by the per-station loop below -- kept as absolute dBm
		-- thresholds (converted from the wire's fixed encoding in this same
		-- loop) so the enforcement check further down is a plain
		-- sta.signal comparison.
		local minrssi_threshold_by_radio = {}
		-- Load balance's client cap, keyed by radio name; only radios that
		-- have it on.
		local maxsta_by_radio = {}
		-- Live noise floor per radio, for satisfaction.
		local noise_by_radio = {}
		-- Live secondary-channel side per radio, for each vap's extchannel.
		local extchan_by_radio = {}
		for _, radio in ipairs(radio_table) do
			local ok_if, ifname = pcall(ufuci.get_ifname_for_radio, radio.name)
			if ok_if and ifname then
				-- Hardware capability fields the controller's radio_table
				-- ingestion expects independently of everything else here
				-- (is_11ac/is_11ax/is_11be/has_dfs/has_fccdfs/has_ht160/
				-- has_eht240/has_eht320/nss) -- see sysinfo.radio_caps()
				-- for the decompile citation. Missing these is why the
				-- Radios tab excluded the device entirely.
				local ok_caps, caps = pcall(M._sysinfo.radio_caps, ifname)
				if ok_caps and caps then
					caps.width = nil
					extchan_by_radio[radio.name] = caps.extchannel
					caps.extchannel = nil
					for k, v in pairs(caps) do radio[k] = v end
					-- The live negotiated channel is band-authoritative once
					-- ACS has picked one: UCI's config value may be the
					-- literal "auto", for which get_radio_table's config-first
					-- derivation can still misreport the band when the
					-- section carries neither `band` nor `hwmode`. Re-derive
					-- here so every downstream consumer of radio.radio in
					-- this loop (scan_radio_table band, athstats bucketing)
					-- inherits the correction. Feature-detected: test mocks
					-- inject a ucihelper without band_for_channel.
					if caps.channel and ufuci.band_for_channel then
						radio.radio = ufuci.band_for_channel(caps.channel)
					end
					-- radio_caps: a genuine SEPARATE integer field on
					-- radio_table (confirmed via decompile,
					-- com.ubnt.service.devmgr.PGOcbDWlbnYQdFW/
					-- tFhABnrHYJqvjaoEa: `uCthhvfQNZ2.put("radio_caps",
					-- uCthhvfQNZ3.getInt("radio_caps", 0))` -- an int, not the
					-- flattened is_11ac/nss/etc. booleans above, and distinct
					-- from radio_caps2) -- confirmed 2026-07-14 from the
					-- controller's own React bundle (swai chunk) that the
					-- Radios tab's MIMO column/filter computes
					-- `mimo: e7(radio.radio_caps)` from exactly this field.
					-- The controller's Java side only ever passes this int
					-- through verbatim (no server-side bit-decode found in
					-- the decompile); the decode into "1x1".."4x4" happens
					-- client-side only. openUF previously always sent 0 (the
					-- field was never populated), which is why every radio's
					-- MIMO column stayed blank and the 1x1-4x4 filter
					-- checkboxes excluded every radio outright rather than
					-- just filtering incorrectly. The exact bit layout isn't
					-- simply "value == nss" (confirmed live: radio_caps=2
					-- still showed blank/excluded) -- it's a bitmask, reverse
					-- engineered by calling the controller's own live e7()
					-- decoder directly (via its webpack module cache) with a
					-- sweep of single-bit values: bit 3 (0x8) -> "1x1", bit 4
					-- (0x10) -> "2x2", bit 5 (0x20) -> "3x3", bit 26
					-- (0x4000000) -> "4x4", checked in that highest-first
					-- priority order when multiple bits are set (all
					-- confirmed against the live decoder, not guessed).
					local RADIO_CAPS_MIMO_BIT = {
						[1] = 0x8,
						[2] = 0x10,
						[3] = 0x20,
						[4] = 0x4000000,
					}
					radio.radio_caps = RADIO_CAPS_MIMO_BIT[caps.nss or 1] or RADIO_CAPS_MIMO_BIT[1]
					-- wpa3_supported: reported only when hostapd can really
					-- do SAE, so we never claim what the radio cannot run.
					-- Truthful -- but the controller does NOT read it, and it
					-- does NOT unlock WPA3.
					--
					-- Confirmed live on 10.4.57 by reading back the persisted
					-- device: radio_caps survives the round trip verbatim
					-- (nss=3 -> 0x20 comes back as radio_caps=32), while
					-- wpa3_supported and owe_supported come back UNDEFINED --
					-- the controller drops them on ingestion entirely.
					--
					-- Decompiling the only class that mentions wpa3_supported
					-- (com.ubnt.net.k.aI.jRsSex, a record of wpa3Supported/
					-- band6GHzSupported/oweSupported) shows it is CONSTRUCTED,
					-- never parsed: its single caller builds it from an
					-- injected com.ubnt.service.wifi.AcrQJeJCScLn service and
					-- takes the device object as a parameter it then ignores.
					-- It is an outbound/API description of what the site
					-- supports, not an inform ingestion path.
					--
					-- An earlier commit here claimed setting this field flipped
					-- a push from WPA-PSK to SAE. That was a coincidental
					-- config regeneration: it has never reproduced, including
					-- across a clean re-adoption with the field present from
					-- the first inform.
					--
					-- Kept because it is accurate (these radios really do have
					-- SAE) and harmless, and another controller version may yet
					-- read it -- but nothing here unlocks WPA3 on 10.4.57. See
					-- PROTOCOL-VALIDATION.md's WPA3 section.
					if M._sysinfo.sae_supported and M._sysinfo.sae_supported() then
						radio.wpa3_supported = true
					else
						radio.wpa3_supported = false
					end
					radio.owe_supported       = false
					-- radio_caps2 bit 0x1: THE WPA3 GATE. Traced end to
					-- end through the 10.4.57 bytecode:
					--
					--   config gen (QSAkfnbfInKJ) calls radio.CVir()
					--   CVir()  = (1 & ZPjpXpgFhJSgqk().orElse(0)) == 1
					--   ZPjpXpgFhJSgqk() -> impl field iBjnA
					--   iBjnA <- builder field SuUD
					--   SuUD  <- setter rMxwXnPhhdotvjERKoA(int)
					--   which the radio parser feeds from "radio_caps2"
					--
					-- radio_caps goes to a DIFFERENT field (builder kJeOrfqt
					-- -> impl DbisCuTqoItCGd -> accessor FJaWnIAautY), which
					-- is the MIMO column and nothing else. So the capability
					-- that decides WPA3 lives in the one radio field openUF
					-- never sent -- it arrived as 0 on every inform, and 0
					-- fails the bit test, so every WPA3 WLAN was downgraded.
					-- Gated on real SAE support for the same reason as
					-- wpa3_supported: never claim what hostapd cannot run.
					--
					-- Bit 0x2 is FT with WPA3 (10.6.101: radio DTO
					-- ytajcagDggPuTaL(), tested in the per-radio security
					-- filter plVcFpIybmrpXclX). Without it the controller
					-- forces wpa3_fast_roaming off on every SAE WLAN, and on
					-- a WPA3-only one fast_roaming_enabled too, so no 802.11r
					-- goes out. hostapd runs FT-SAE wherever it runs SAE.
					--
					-- Bit 0x8 is Enhanced Open (radio DTO NoFWvUa(), same
					-- filter). Without it an OWE WLAN is not provisioned at
					-- all and an OWE transition WLAN goes out as plain open.
					-- Probed separately: hostapd can have SAE without OWE.
					if M._sysinfo.sae_supported and M._sysinfo.sae_supported() then
						radio.radio_caps2 = 0x3
					else
						radio.radio_caps2 = 0
					end
					if M._sysinfo.owe_supported and M._sysinfo.owe_supported() then
						radio.radio_caps2 = radio.radio_caps2 + 0x8
					end
				end
				local ok_rs, stats = pcall(M._sysinfo.radio_stats, ifname)
				local in_use = ok_rs and _in_use_survey(stats) or nil
				noise_by_radio[radio.name] = in_use and in_use.noise
				-- min_rssi (outbound, dBm): the stored raw wire value less the
				-- controller's fixed +95 encoding (openuf/minrssi.lua). Not the
				-- live noise floor: the controller has none to encode with, and
				-- noise readings differ by 12 dB between drivers (ath9k -107,
				-- ath10k -95, mt76 -90).
				-- min_rssi_raw can legitimately be missing with the flag set
				-- (inconsistent UCI, e.g. a hand-edit or interrupted write) --
				-- without the guard this was arithmetic on nil, killing the
				-- whole inform build.
				if radio.min_rssi_enabled and radio.min_rssi_raw then
					radio.min_rssi = M._minrssi.dbm(radio.min_rssi_raw)
					minrssi_threshold_by_radio[radio.name] = radio.min_rssi
				end
				if in_use then
					-- in_use: the channel the radio is actually on
					local cu_total, cu_self_rx, cu_self_tx = _windowed_cu(radio.name, in_use)
					local entry = {
						name        = radio.name,
						channel     = radio.channel,
						cu_total    = cu_total,
						cu_self_rx  = cu_self_rx,
						cu_self_tx  = cu_self_tx,
						-- cu_interf: airtime busy for reasons other than this
						-- radio's own tx/rx (other-BSS/non-WiFi interference).
						-- The stat archiver (com.ubnt.service.system.
						-- QDcGUYAmLvJwylXw, confirmed via decompile) reads
						-- this as a sibling of cu_total/cu_self_rx/cu_self_tx
						-- and silently drops the whole per-band bucket without
						-- it -- this is why "Avg. Interference" stayed blank
						-- even though cu_total was already being sent.
						cu_interf   = math.max(0, cu_total - cu_self_rx - cu_self_tx),
					}
					radio_cu_stats[radio.name] = {
						cu_total   = entry.cu_total,
						cu_self_rx = entry.cu_self_rx,
						cu_self_tx = entry.cu_self_tx,
						cu_interf  = entry.cu_interf,
					}
					-- athstats: the ACTUAL source the stat archiver reads for
					-- these four fields, confirmed via decompiling
					-- com.ubnt.service.system.x.htDMji -- it iterates
					-- radio_table (not radio_table_stats, not vap_table) and
					-- SKIPS a radio entirely if it lacks this nested
					-- "athstats" sub-object (`if
					-- (!uCthhvfQNZ.containsField("athstats")) continue;`),
					-- then reads cu_total/cu_self_rx/cu_self_tx/satisfaction/
					-- cu_interf off it (named after the legacy Atheros ath9k/
					-- ath10k driver stats struct UniFi firmware historically
					-- exposed under this name, kept for newer radios too).
					-- radio_table_stats/vap_table's copies of these same
					-- fields are real and used by other code paths (the live
					-- wifi-stats/radios REST API, per-VAP display) but this
					-- nested copy is what the periodic archiver needs --
					-- omitting it is why "Avg. Interference"/"Avg. Airtime"
					-- stayed blank even with correct data everywhere else.
					radio.athstats = {
						cu_total   = cu_total,
						cu_self_rx = cu_self_rx,
						cu_self_tx = cu_self_tx,
						cu_interf  = entry.cu_interf,
					}
					-- Hardware tx and carrier-sense timeouts, raw counts as
					-- the firmware sends them. The controller diffs them per
					-- inform and logs "Possible interference" when either
					-- rises faster than 10/s (at most every 5 min per radio).
					-- ath9k only; elsewhere absent, as on a radio that never
					-- times out.
					local ok_to, txto, cst = pcall(M._sysinfo.radio_timeouts, ifname)
					if ok_to and txto then
						radio.athstats.ast_txto = txto
						radio.athstats.ast_cst = cst
					end
					-- Cached spectrum-scan result, if a "spectrum-scan" cmd
					-- was handled for this radio (see cmd dispatch below).
					-- On the radio_table entry, beside athstats: the
					-- controller builds its own radio_table_stats from the
					-- inform's radio_table and reads spectrum_table from
					-- there (devmgr PGOcbDWlbnYQdFW). Sent in
					-- radio_table_stats, it was dropped.
					-- spectrum_table_time is the scan's AGE in seconds: the
					-- controller stores now - value and the UI shows that as
					-- the scan's epoch ("scanned N ago"). An epoch here would
					-- read as 1970.
					local sscan = M._spectrum_cache[radio.name]
					if sscan then
						radio.spectrum_table      = sscan.table
						radio.spectrum_table_time = math.max(0, os.time() - sscan.table_time)
					end
					radio_table_stats[#radio_table_stats + 1] = entry
					-- Keep the entry addressable so the VAP/station loop below
					-- can attach this radio's TX counters once it has summed
					-- them -- see radio_tx_stats.
					radio_stats_by_name[radio.name] = entry
				end
				-- Neighboring wireless networks visible to this radio --
				-- confirmed real field names via the decompiled controller's
				-- ingestion DTO (com.ubnt.service.aO.bLwwMKkr, literally
				-- named "PeerScan"): a top-level scan_radio_table, one entry
				-- per radio, each carrying that radio's own scan_table list.
				-- Feeds the controller's Insights -> AirView -> Environment
				-- view (backed by stat/rogueap) -- a different, previously
				-- unimplemented feature from the RF/spectrum-scan cmd above,
				-- which only ever reported channel utilization, never which
				-- neighboring SSIDs/BSSIDs were actually detected. See
				-- PROTOCOL-VALIDATION.md for the full derivation.
				local ok_sc, nets = pcall(M._sysinfo.scan_table, ifname)
				if ok_sc and nets then
					local scan_table = {}
					for _, net in ipairs(nets) do
						scan_table[#scan_table + 1] = {
							mac        = net.bssid,
							bssid      = net.bssid,
							radio      = radio.radio,
							radio_name = radio.name,
							-- Confirmed from the controller's own React bundle
							-- (2026-07-14, react-app-wrapper chunk): the
							-- Environment tab's list is fed through an
							-- unconditional filter keyed on `band` (a field
							-- distinct from `radio`, but taking the exact same
							-- enum values -- "ng"/"na"/"6e", confirmed from the
							-- bundle's own enum definition) -- any entry
							-- missing `band` fails that filter silently, with
							-- no error and no visible UI cause, regardless of
							-- every visible sidebar filter's state.
							band       = radio.radio,
							channel    = net.channel,
							freq       = net.freq,
							rssi       = net.signal,
							signal     = net.signal,
							-- The Environment tab's "Ch. Width" column reads
							-- this directly and renders nothing at all when
							-- it's falsy/missing (confirmed live 2026-07-14).
							bw         = net.bw or 20,
							-- NOT last_seen: the controller derives the
							-- absolute last_seen itself from report_time -
							-- age, and its rogue-AP detection silently
							-- drops any entry with age >= 30 as stale
							-- (confirmed live 2026-07-14, see
							-- PROTOCOL-VALIDATION.md) -- age must be
							-- seconds actually elapsed, not omitted.
							age        = net.age or 0,
							security   = net.security,
							essid      = net.essid,
						}
						-- A sibling openUF or UniFi AP, identified by the IE it
						-- beacons (sysinfo.peer_ie_hex, peer_match_ucode). is_unifi + serialno is what
						-- the controller resolves to an adopted device; without
						-- them every BSS of ours carrying a site SSID was
						-- listed as an impersonating third-party AP.
						if net.peer_mac then
							local e = scan_table[#scan_table]
							e.is_unifi = true
							e.serialno = net.peer_mac
						end
					end
					-- 802.11k enrichment: BSSes a CLIENT went off-channel
					-- and saw, which this radio never could from its own
					-- passive cache. Merged on the reported channel's BAND,
					-- not on the interface the request went out of, because a
					-- client sitting on 5 GHz routinely reports 2.4 GHz too --
					-- so one report fills both radios' lists. Anything the
					-- passive cache already knows wins, since a beacon report
					-- carries no SSID, security or width. See rrmscan.lua.
					-- A client reports this AP and its siblings like any other
					-- BSS: those are skipped (own BSSIDs from vap_table,
					-- siblings from usteer), and the site's SSIDs are passed so
					-- an unrecognised BSS carrying one is not raised as a rogue.
					-- Built once per payload, only when there is something to
					-- merge.
					if M._rrmscan and #M._rrm_neighbours > 0 then
						if not rrm_skip then
							rrm_skip, rrm_site = {}, {}
							local ok_sb, sib = pcall(M._rrmscan.sibling_bssids)
							if ok_sb and type(sib) == "table" then
								for b in pairs(sib) do rrm_skip[b] = true end
							end
							for _, v in ipairs(vap_table) do
								if type(v.bssid) == "string" and v.bssid ~= "" then
									rrm_skip[v.bssid:lower()] = true
								end
								if v.essid then rrm_site[v.essid] = true end
							end
						end
						pcall(M._rrmscan.merge_into, scan_table,
							M._rrm_neighbours, {
								band       = radio.radio,
								radio      = radio.radio,
								radio_name = radio.name,
								max_age    = RRM_MAX_AGE,
								skip       = rrm_skip,
								site_ssids = rrm_site,
							})
					end
					scan_radio_table[#scan_radio_table + 1] = {
						radio      = radio.radio,
						name       = radio.name,
						scan_table = arr(scan_table),
					}
				end
			end
			-- Internal fields, never payload members. Cleared out here (not
			-- inside the ifname branch above) so they can't leak into the
			-- serialized radio_table when ifname resolution fails.
			maxsta_by_radio[radio.name] = radio.loadbalance_maxsta
			radio.min_rssi_raw = nil
			radio.country      = nil  -- consumed into country_code above
			radio.loadbalance_maxsta = nil
		end

		-- Live connected-client counts, nested per-vap as sta_table -- matches
		-- the real controller's vap-stats DTO, which nests connected clients
		-- inside each vap_table entry rather than a flat top-level table
		-- (confirmed against unifi-network-application:10.4.57's own
		-- bytecode; see PROTOCOL-VALIDATION.md's outbound payload
		-- field reference).
		-- Live-corrected per-radio entries, keyed by UCI device name, for the
		-- vap loop below. The radio loop above overwrote each entry's channel
		-- with the live negotiated iw value and re-derived its band from it;
		-- vap_table's own channel/radio are still UCI config echoes (possibly
		-- the literal "auto", and stringly-typed), which left vap_table/
		-- sta_table disagreeing with radio_table inside one payload.
		local radio_live_by_name = {}
		for _, radio in ipairs(radio_table) do
			radio_live_by_name[radio.name] = radio
		end
		local now = M._time()
		-- Roaming Assistant: one observation per station on a vap that has
		-- it on, decided on after the loop (see openuf/roamassist.lua).
		local roam_obs = {}
		-- Minimum RSSI: one observation per station on a radio that has it
		-- on, decided on after the loop (see openuf/minrssi.lua).
		local minrssi_obs = {}
		-- Load balance: every station on a radio that has it on.
		local lb_obs = {}
		-- Every station, for the roam reports' view of who is here
		-- (assoctrack.observe).
		local here_obs = {}
		-- WiFi Speed Limit: what each netdev lists and its WLAN's limits,
		-- for _shaper_resync after this inform is built.
		local shape_obs = {complete = true, by_ifname = {}, where = {}, conn = {}}
		for _, vap in ipairs(vap_table) do
			local live = radio_live_by_name[vap.radio_name]
			if live then
				if live.channel then vap.channel = live.channel end
				if live.radio then vap.radio = live.radio end
				-- Same UCI-echo problem as channel: get_vap_table reads the
				-- `txpower` option, which does not exist while Transmit Power
				-- is Auto, so the vap's copy stayed nil even after the radio
				-- entry picked up the driver's real value.
				if live.tx_power then vap.tx_power = live.tx_power end
			end
			-- Only when non-zero, as the firmware sends it. The controller
			-- copies it into radio_table_stats, where the UI centres a
			-- 2.4 GHz 40 MHz channel at channel + 2 * extchannel.
			local ext = extchan_by_radio[vap.radio_name]
			vap.extchannel = ext ~= 0 and ext or nil
			-- Resolve THIS vap's netdev, not the radio's first one.
			-- get_ifname_for_radio() returns whichever interface netifd
			-- lists first, which is the same thing only on a single-SSID
			-- radio. With two WLANs on one radio every secondary vap
			-- inherited the first vap's station dump: a brand-new IoT SSID
			-- with nobody on it reported nine connected clients, all of them
			-- the other WLAN's, complete with the other network's IP
			-- addresses. Every per-vap figure derived from `stas` below --
			-- num_sta, the traffic and retry counters, satisfaction -- was
			-- wrong the same way, and the device-level aggregates
			-- double-counted those stations once per vap on the radio.
			--
			-- get_ifname_for_vap() matches on SSID within the radio's
			-- interface list and needs no extra data (same ubus call, same
			-- cjson dependency). When it cannot resolve -- no cjson, an
			-- older netifd that omits config.ssid, a radio with several
			-- interfaces and no match -- the vap reports NO clients rather
			-- than someone else's: an empty sta_table understates, a
			-- borrowed one invents associations that never happened.
			-- `essid` is what get_vap_table() calls it -- the vap has no
			-- `ssid` field, and passing one silently resolves to nil, which
			-- would empty every sta_table instead of fixing anything.
			--
			-- An Enhanced Open transition VAP is two BSSes, the hidden OWE
			-- one and the open one, and its clients are the union of both.
			local ok_if, ifnames = pcall(ufuci.get_ifnames_for_vap,
				vap.radio_name, vap.essid)
			-- sta_ifname[i] is the hostapd BSS stas[i] is on, for the kick
			-- and Roaming Assistant below. A private pre-shared key's VLAN
			-- netdev lists its own stations but has no hostapd of its own,
			-- so those go to the VAP's.
			local stas, sta_ifname = {}, {}
			for _, ifname in ipairs(ok_if and ifnames or {}) do
				local ok_sta, rv2 = pcall(M._sysinfo.sta_table, ifname)
				if ok_sta then
					local bss = ufuci.bss_ifname and ufuci.bss_ifname(ifname) or ifname
					if vap.name then M._vap_by_ifname[bss] = vap.name end
					-- Stations are shaped on the netdev that lists them: a
					-- private pre-shared key's VLAN netdev carries its
					-- stations' frames, not the VAP's.
					local so = {down = vap.ratelimit_down, up = vap.ratelimit_up, macs = {}}
					shape_obs.by_ifname[ifname] = so
					for _, sta in ipairs(rv2) do
						here_obs[#here_obs + 1] = {mac = sta.mac, ifname = bss,
							signal = sta.signal_avg or sta.signal, inactive_ms = sta.inactive_ms}
						-- Behind another AP since its sta_roam; hostapd just
						-- has not noticed yet (assoctrack.roamed_away).
						local gone = M._assoctrack
							and M._assoctrack.roamed_away(sta.mac, uptime, sta.inactive_ms)
						if not gone then
							stas[#stas + 1] = sta
							sta_ifname[#stas] = bss
							if type(sta.mac) == "string" then
								local m = sta.mac:lower()
								so.macs[#so.macs + 1] = m
								shape_obs.where[m] = ifname
								shape_obs.conn[m] = tonumber(sta.connected_sec)
							end
						end
					end
				else
					shape_obs.complete = false
				end
			end
			vap.num_sta = #stas
			-- Per-VAP traffic/retry counters ("Air Stats" in the controller
			-- UI) -- confirmed real field names via the decompiled vap-stats
			-- DTO (cVbZoFIZsWYaVCquTr$QCtdvLKOBb): rx_bytes/rx_packets/
			-- tx_bytes/tx_packets/tx_retries/tx_dropped, aggregated here by
			-- summing each connected station's own counters (iw(8) doesn't
			-- expose a single already-aggregated per-radio/per-VAP counter,
			-- only per-station ones). rx_dropped/rx_errors/tx_errors/
			-- have no source data anywhere in iw's output (ARQ retry/failure
			-- counters are inherently TX-side only) -- left unset rather than
			-- invented.
			local vap_rx_bytes, vap_tx_bytes = 0, 0
			local vap_rx_packets, vap_tx_packets = 0, 0
			local vap_tx_retries, vap_tx_dropped = 0, 0
			local signal_sum, signal_count = 0, 0
			-- This VAP's WiFi Experience tally (see sat_tallies above).
			local sat = M._satisfaction
			local tally = sat.tally()
			sat_tallies[#sat_tallies + 1] = tally
			sat_tallies_by_radio[vap.radio_name] = sat_tallies_by_radio[vap.radio_name] or {}
			table.insert(sat_tallies_by_radio[vap.radio_name], tally)
			-- tx failed counts dropped frames on most drivers but failed
			-- attempts on mt76 (satisfaction.failed_is_dropped/dropped).
			local failed_is_dropped = sat.failed_is_dropped(
				M._sysinfo.wifi_driver and M._sysinfo.wifi_driver(ok_if and ifnames[1]))
			-- Each station's AKM from hostapd, for is_11r below.
			local akms = {}
			if #stas > 0 and M._sysinfo.sta_akms_cached then
				local list = {}
				for i, sta in ipairs(stas) do
					if type(sta.mac) == "string" then
						list[#list + 1] = {mac = sta.mac, bss = sta_ifname[i],
							conn = tonumber(sta.connected_sec)}
					end
				end
				local ok_akm, rv_akm = pcall(M._sysinfo.sta_akms_cached, list)
				if ok_akm and type(rv_akm) == "table" then akms = rv_akm end
			end
			local noise = noise_by_radio[vap.radio_name]
			if type(noise) ~= "number" or noise >= 0 then noise = nil end
			local sta_table = {}
			for sta_i, sta in ipairs(stas) do
				local ifname = sta_ifname[sta_i]
				station_macs[sta.mac] = true
				vap_rx_bytes    = vap_rx_bytes    + (sta.rx_bytes or 0)
				vap_tx_bytes    = vap_tx_bytes    + (sta.tx_bytes or 0)
				vap_rx_packets  = vap_rx_packets  + (sta.rx_packets or 0)
				vap_tx_packets  = vap_tx_packets  + (sta.tx_packets or 0)
				vap_tx_retries  = vap_tx_retries  + (sta.tx_retries or 0)
				local sta_dropped = sat.dropped(failed_is_dropped, sta.tx_failed, sta.tx_retries)
				vap_tx_dropped  = vap_tx_dropped  + (sta_dropped or 0)
				if sta.signal then
					signal_sum   = signal_sum + sta.signal
					signal_count = signal_count + 1
				end
				-- "Minimum RSSI" is per radio: every vap on it shares the
				-- threshold. The driver's average, as stamgr's own reading
				-- is smoothed; a station below it is Minimum RSSI's, not
				-- Roaming Assistant's.
				local minrssi_threshold = minrssi_threshold_by_radio[vap.radio_name]
				local minrssi_signal = sta.signal_avg or sta.signal
				if minrssi_threshold and minrssi_signal then
					minrssi_obs[#minrssi_obs + 1] = {ifname = ifname, mac = sta.mac,
						signal = minrssi_signal, threshold = minrssi_threshold}
				end
				if maxsta_by_radio[vap.radio_name] then
					lb_obs[#lb_obs + 1] = {radio = vap.radio_name, ifname = ifname,
						mac = sta.mac, inactive_ms = sta.inactive_ms}
				end
				local below_minrssi = minrssi_threshold and minrssi_signal
					and minrssi_signal < minrssi_threshold
				if not below_minrssi and vap.roam_assist_rssi and sta.signal then
					roam_obs[#roam_obs + 1] = {
						ifname = ifname, ssid = vap.essid, mac = sta.mac,
						signal = sta.signal, connected_sec = sta.connected_sec,
						threshold = vap.roam_assist_rssi,
					}
				end
				local prev = M._sta_stats_cache[sta.mac]
				-- The client panel's "TX Retries": the controller diffs this
				-- station's tx_retries and wifi_tx_attempts (with the byte and
				-- packet counters) every inform, keeps the positive deltas and
				-- overwrites wifi_tx_retries_percentage with
				-- retries / (retries + attempts + dropped) of those deltas
				-- (devmgr TtZhv, wifi.k bLwwMKkr). Every retry rate it computes
				-- has that denominator, and the session archive fills
				-- wifi_tx_attempts from wifi_tx_packets: attempts are the
				-- frames sent, retries not included. Without tx_retries here
				-- the delta was 0 and every client read 0.0 %. Lifetime
				-- values; WiFi Experience uses its own per-minute window.
				local wifi_tx_attempts = sta.tx_packets or 0
				local tries = wifi_tx_attempts + (sta.tx_retries or 0) + (sta_dropped or 0)
				local wifi_tx_retries_pct = 0
				if tries > 0 then
					wifi_tx_retries_pct = (sta.tx_retries or 0) * 100 / tries
				end
				-- WiFi Experience, the firmware's formula (satisfaction.lua):
				-- SNR from the averaged signal, the last tx/rx rates, and the
				-- retry term over the last completed minute.
				local win = sat.window(prev and prev.sat_window, {
					packets = sta.tx_packets, retries = sta.tx_retries,
					dropped = sta_dropped or 0,
				}, now)
				M._sta_stats_cache[sta.mac] = { time = now, sat_window = win }
				local mov = win.mov or {}
				local satisfaction_now, satisfaction_reason, anomalies = sat.score{
					snr = sat.snr(sta.signal_avg or sta.signal, noise),
					tx_kbps = sta.tx_bitrate and math.floor(sta.tx_bitrate * 1000 + 0.5),
					rx_kbps = sta.rx_bitrate and math.floor(sta.rx_bitrate * 1000 + 0.5),
					tries = mov.tries, retries = mov.retries, dropped = mov.dropped,
				}
				if satisfaction_now then
					tally.add(satisfaction_now, satisfaction_reason, anomalies)
				end
				-- Station state bit 0x10 = dozing, the only bit the controller
				-- reads (powersave_enabled). Absent where the radio can't tell.
				local ps_ok, ps = pcall(M._sysinfo.sta_powersave or function() end, ifname, sta.mac)
				local sta_state
				if ps_ok and ps ~= nil then sta_state = ps and 0x10 or 0 end

				sta_table[#sta_table + 1] = {
					active     = true,
					mac        = sta.mac,
					-- Guest portal state; see M._guest_sta_authorized.
					authorized = M._guest_sta_authorized(st, vap, sta.mac),
					ap_mac     = mac_str,
					channel    = vap.channel,
					radio      = vap.radio,
					-- rssi is the SNR in dB, as UniFi firmware sends it
					-- (fill_stainfo_json, firmware-confirmed for 3.9.27 to
					-- 4.0.15: signal = rssi + max(noise, -96)); the
					-- controller's readers test it against 5 and convert it
					-- with -95. noise is the radio's floor in dBm.
					signal     = sta.signal,
					rssi       = sat.snr(sta.signal, noise),
					noise      = noise,
					state      = sta_state,
					-- Only when true, as the firmware sends it: the station
					-- holds a Fast BSS Transition AKM.
					is_11r     = M._sysinfo.akm_is_ft
						and M._sysinfo.akm_is_ft(akms[sta.mac:lower()]) or nil,
					-- No capacity/throughput/linkscore/multicast: UniFi
					-- firmware sends none of them (fill_stainfo_json,
					-- firmware-confirmed for 3.9.27 to 4.0.15), and the 10.x
					-- controller reads them only off a mesh uplink's entry.
					-- Cumulative per-client counters -- confirmed real field
					-- names via the decompiled vapInformProcessor
					-- (com.ubnt.service.devmgr.c.KHUkYjHujLgFBD), which
					-- copies exactly these names off each incoming sta_table
					-- entry ("channel","radio","name","signal","rssi",
					-- "tx_rate","rx_rate","tx_packets","rx_packets",
					-- "tx_bytes","rx_bytes") and computes its own bytes-d/
					-- rate-d deltas between informs -- so unlike throughput
					-- above, these must be sent as raw cumulative counters,
					-- not pre-computed rates.
					rx_bytes   = sta.rx_bytes or 0,
					tx_bytes   = sta.tx_bytes or 0,
					rx_packets = sta.rx_packets or 0,
					tx_packets = sta.tx_packets or 0,
					-- tx_rate/rx_rate: controller's tx_rate/rx_rate are in
					-- Kbps (matches real-device captures, e.g. tx_rate:
					-- 39000 for a 39 Mbps MCS rate); iw reports Mbit/s.
					tx_rate    = sta.tx_bitrate and math.floor(sta.tx_bitrate * 1000) or 0,
					rx_rate    = sta.rx_bitrate and math.floor(sta.rx_bitrate * 1000) or 0,
					-- uptime/idletime: iw's "connected time"/"inactive time"
					-- are the same concepts: seconds associated, seconds
					-- since last activity. Only set uptime when iw actually
					-- reports connected time (older iw builds omit it).
					uptime     = sta.connected_sec,
					idletime   = sta.inactive_ms and math.floor(sta.inactive_ms / 1000) or nil,
					-- tx_mcs/rx_mcs: confirmed real field names (not
					-- "tx_mcs_index", which is only the ucore-message wire
					-- name) via the decompiled wireless-client model
					-- (com.ubnt.service.l.e.AQODNNoMmBlFpWXX) and unpoller/
					-- unifi's REST client struct. iw's bitrate lines already
					-- print this ("144.4 MBit/s MCS 15 short GI"); only set
					-- when iw actually reports an MCS-based rate (legacy
					-- pre-11n rates have none).
					tx_mcs     = sta.tx_mcs,
					rx_mcs     = sta.rx_mcs,
					-- radio_proto: still sent for the disconnect-time session
					-- archive (com.ubnt.service.devmgr.TtZhv reads this string
					-- directly when a client disconnects), but it is NOT what
					-- drives the live, still-connected display -- confirmed by
					-- decompiling the actual live-update path
					-- (com.ubnt.service.devmgr.HCKpgcBFPLu, a KrlpWXOulbN
					-- implementation) down to com.ubnt.g.s.jRsSex, whose
					-- generation logic ignores any "radio_proto" string
					-- entirely and instead derives it from boolean per-station
					-- capability flags -- is_11be/is_11ax/is_11ac/is_11n/
					-- is_11b -- falling through to the lowest ("g" on 2.4GHz,
					-- "a" on 5GHz) when none are set. That's why sending only
					-- radio_proto left every live client showing "g"/"a" and
					-- why nss (read directly, no derivation) worked
					-- immediately: these booleans were the missing piece.
					is_11n     = sta.tx_generation == "n",
					is_11ac    = sta.tx_generation == "ac",
					is_11ax    = sta.tx_generation == "ax",
					is_11be    = sta.tx_generation == "be",
					radio_proto = sta.tx_generation or (vap.radio == "na" and "a" or "g"),
					nss         = sta.tx_nss or 1,
					tx_retries       = sta.tx_retries,
					wifi_tx_attempts = wifi_tx_attempts,
					wifi_tx_dropped  = sta_dropped,
					wifi_tx_retries_percentage = wifi_tx_retries_pct,
					-- WiFi Experience (satisfaction.lua). The controller
					-- computes none of it: it stores what the AP sends.
					-- satisfaction_reason is the bit of the term that set the
					-- score, anomalies the bitmask of every weak term; both
					-- are on the controller's client model (getOptionalLong).
					satisfaction        = satisfaction_now,
					satisfaction_now    = satisfaction_now,
					satisfaction_reason = satisfaction_reason,
					anomalies           = anomalies,
				}
			end
			vap.sta_table  = arr(sta_table)
			vap.rx_bytes   = vap_rx_bytes
			vap.tx_bytes   = vap_tx_bytes
			vap.rx_packets = vap_rx_packets
			vap.tx_packets = vap_tx_packets
			vap.tx_retries = vap_tx_retries
			vap.tx_dropped = vap_tx_dropped
			-- Per-RADIO TX counters, accumulated across every VAP on it.
			--
			-- radio_table_stats carried only name/channel/cu_* -- no TX
			-- counters at all -- and the controller does not fill them from
			-- the vap_table copies it already has. Instead its stored entry
			-- ended up with tx_packets=243, tx_retries=0 and, from those,
			-- tx_retries_pct=100, which the Devices view renders as a
			-- permanent "TX Retries: High (100%)" on an AP whose real retry
			-- rate is a few percent. Confirmed against a live 10.4.57
			-- controller, on both APs.
			-- wifi_tx_attempts / wifi_tx_dropped: the pair the controller
			-- aggregates upward into stat.ap ("<band>-wifi_tx_attempts",
			-- "radio0-wifi_tx_attempts", "user-...-wifi_tx_attempts") and
			-- divides to get a retry/failure rate. openUF sent them per
			-- STATION only, so every aggregate sat at 0 and the division
			-- degenerated -- which is what pinned "TX Retries: High (100%)"
			-- on the Devices view even though the signal-bucketed attempt
			-- counters, derived from the same per-station data, were populated
			-- correctly. Attempts are the frames sent, retries not included,
			-- the same definition sta_table uses (the controller's rate is
			-- retries / (retries + attempts + dropped)); dropped is the
			-- driver's own drop count (satisfaction.dropped: tx_failed, less
			-- the retries that mt76 folds into it).
			vap.wifi_tx_attempts = vap_tx_packets
			vap.wifi_tx_dropped  = vap_tx_dropped
			local rstat = radio_stats_by_name[vap.radio_name]
			if rstat then
				rstat.wifi_tx_attempts =
					(rstat.wifi_tx_attempts or 0) + vap.wifi_tx_attempts
				rstat.wifi_tx_dropped =
					(rstat.wifi_tx_dropped or 0) + vap.wifi_tx_dropped
				rstat.tx_packets = (rstat.tx_packets or 0) + vap_tx_packets
				rstat.tx_retries = (rstat.tx_retries or 0) + vap_tx_retries
				rstat.tx_dropped = (rstat.tx_dropped or 0) + vap_tx_dropped
				rstat.rx_packets = (rstat.rx_packets or 0) + vap_rx_packets
				rstat.tx_bytes   = (rstat.tx_bytes   or 0) + vap_tx_bytes
				rstat.rx_bytes   = (rstat.rx_bytes   or 0) + vap_rx_bytes
				-- Retries as a share of every try (sent + retried + dropped),
				-- the controller's own definition, which sta_table's
				-- wifi_tx_retries_percentage uses too. Left absent while
				-- nothing has been transmitted, rather than reported as 0% or
				-- 100% of nothing.
				local tries = rstat.tx_packets + rstat.tx_retries + rstat.tx_dropped
				if tries > 0 then
					rstat.tx_retries_pct =
						math.floor(rstat.tx_retries * 100 / tries + 0.5)
				end
			end
			-- avg_client_signal: mean RSSI (dBm, negative) of currently
			-- associated clients on this VAP. The stat archiver (decompiled
			-- com.ubnt.service.system.QDcGUYAmLvJwylXw) reads this exact
			-- field name directly off each vap_table entry -- alongside the
			-- existing num_sta -- to compute the "Avg. Signal" column; it is
			-- NOT derived server-side from per-client signal the way
			-- "weakest_clients_signal_avg" is, so omitting it left that
			-- column permanently blank regardless of per-client signal
			-- already being sent correctly.
			if signal_count > 0 then
				vap.avg_client_signal = math.floor(signal_sum / signal_count)
			end
			-- satisfaction: the mean of this VAP's clients' own scores. The
			-- controller does NOT derive it from the per-client values it
			-- already has -- with this absent, the Devices list showed
			-- "No Clients" in the Experience column on an AP with eight
			-- connected clients, all of them individually scored (96, 82,
			-- 93 ...) in the Clients view. -1 with no clients, as the
			-- firmware sends it; the controller's stat archiver skips -1.
			-- The two bar charts count this VAP's clients per anomaly and
			-- per limiting term (fill_wireless_info_full in the firmware).
			vap.satisfaction = tally.mean()
			vap.anomalies_bar_chart = tally.chart(sat.ANOMALY_KEYS)
			vap.reasons_bar_chart = tally.chart(sat.REASON_KEYS)
			-- cu_total/cu_self_rx/cu_self_tx/cu_interf: same per-radio channel-
			-- utilization figures as radio_table_stats, duplicated onto each
			-- VAP on that radio -- see radio_cu_stats above for why.
			local cu = radio_cu_stats[vap.radio_name]
			if cu then
				vap.cu_total   = cu.cu_total
				vap.cu_self_rx = cu.cu_self_rx
				vap.cu_self_tx = cu.cu_self_tx
				vap.cu_interf  = cu.cu_interf
			end
			vap.roam_assist_rssi = nil  -- internal, consumed above
			vap.ratelimit_down, vap.ratelimit_up = nil, nil
			if not ok_if then shape_obs.complete = false end
		end
		M._shape_obs = shape_obs
		-- Minimum RSSI's kick: one-shot deauth (ucihelper.kick_station), no
		-- block; hostapd's rssi_reject_assoc_rssi keeps the client from
		-- coming straight back.
		local ok_mr, mr_kicks = pcall(M._minrssi.tick, minrssi_obs, now)
		local kicked = {}
		for _, k in ipairs(ok_mr and mr_kicks or {}) do
			-- Before the kick: its disassociation is reported the moment
			-- hostapd announces it, carrying why (assoctrack roam reports).
			if M._assoctrack then
				pcall(M._assoctrack.note_kick, k.mac, M._assoctrack.KICK_MIN_RSSI)
			end
			pcall(ufuci.kick_station, k.ifname, k.mac)
			kicked[k.mac] = true
		end
		-- Load balance's kick: the most idle stations above the radio's cap,
		-- not counting the ones Minimum RSSI just kicked (openuf/loadbalance.lua).
		if #lb_obs > 0 then
			local ok_lb, lb_kicks = pcall(M._loadbalance.kicks, lb_obs, maxsta_by_radio, kicked)
			for _, k in ipairs(ok_lb and lb_kicks or {}) do
				pcall(ufuci.kick_station, k.ifname, k.mac)
			end
		end
		if M._roamassist and #roam_obs > 0 then
			pcall(M._roamassist.tick, roam_obs, now,
				{diff_db = cfg and cfg.config and cfg.config.roam_assist_diff_db,
				 on_steer = M._assoctrack and function(mac)
					M._assoctrack.note_kick(mac, M._assoctrack.KICK_ROAM_ASSIST)
				 end})
		end
		if M._assoctrack then pcall(M._assoctrack.observe, here_obs, uptime) end
		-- Each radio's WiFi Experience, beside its channel utilisation in
		-- athstats: the controller builds radio_table_stats' satisfaction
		-- from athstats.satisfaction (default -1, devmgr), and the firmware
		-- fills it from the radio's VAPs (calc_radio_satisfaction).
		for _, radio in ipairs(radio_table) do
			if radio.athstats then
				radio.athstats.satisfaction =
					M._satisfaction.rollup(sat_tallies_by_radio[radio.name] or {})
			end
		end
		-- Forget stations not seen for ten minutes. Each entry is tiny, but
		-- the table is keyed by CLIENT MAC and was never emptied, so on a
		-- daemon that runs for months in a place with transient clients it
		-- only ever grew. A station back after that long is a fresh
		-- association, and the 0-throughput first sample is the honest figure
		-- for it anyway. Assigning nil during pairs() is defined behaviour.
		for mac, prev in pairs(M._sta_stats_cache) do
			if now - prev.time > M.STA_STATS_FORGET_AFTER then
				M._sta_stats_cache[mac] = nil
			end
		end
	end

	-- port_table: the device's own ethernet ports plus, per non-uplink port,
	-- the wired hosts learned behind it. Confirmed via decompiled
	-- controller 10.4.57 (com.ubnt.service.devmgr.PGOcbDWlbnYQdFW /
	-- DyonYyyYJkiyv / TtZhv, see PROTOCOL-VALIDATION.md) that this is only
	-- processed at all when Device.isSwitch() is true for the reported
	-- model -- which it is for U6IW (registered in the controller's model
	-- registry with 5 ports and a switch feature flag), so this is not
	-- optional for that model: an empty/missing port_table means zero
	-- wired clients can ever appear, and the device's Ports view stays
	-- empty, regardless of what's actually bridged into br-lan.
	local ports = (cfg and cfg.net and cfg.net.ports) or {
		{idx = 1, ifname = (cfg and cfg.net and cfg.net.wan_cpueth) or "eth0", uplink = true},
		{idx = 2, ifname = (cfg and cfg.net and cfg.net.lan_cpueth) or "eth1"},
	}
	local iface_by_name = {}
	for _, iface in ipairs(ifaces) do iface_by_name[iface.name] = iface end

	-- On a swconfig board the kernel sees only the CPU port, so every fact a
	-- netdev can offer about "the port" is really a fact about the internal
	-- SoC<->switch link. Ask the switch instead when the board has one and the
	-- uplink socket can be identified; anything short of that stays on the
	-- netdev path below rather than guessing which socket is which (see
	-- sysinfo.switch_status / sysinfo.uplink_phys_port).
	local sw = {ports = {}, arl = {}}
	if cfg and cfg.vlan and cfg.vlan.ports then
		local ok_sw, s = pcall(M._sysinfo.switch_status, cfg.vlan.device)
		if ok_sw and type(s) == "table" then sw = s end
	end
	local uplink_phys = nil
	if next(sw.ports) then
		local ok_up, phys = pcall(M._sysinfo.uplink_phys_port, sw.arl)
		if ok_up then uplink_phys = phys end
	end

	-- On a DSA board there is no switch to ask and no ARL to read, but every
	-- socket is its own netdev and the bridge they are all enslaved to knows
	-- which one the gateway is behind. Same measurement, different source --
	-- and the same reason for measuring it: a modelmap constant is wrong the
	-- moment someone moves the cable, and a socket wrongly treated as
	-- downstream reports the whole LAN segment as hosts plugged into it.
	--
	-- Only honoured when it names a socket this board actually reports.
	-- Otherwise no entry would be flagged at all and the uplink would publish
	-- a mac_table of the entire far side -- worse than the static fallback.
	local uplink_ifname = nil
	-- Kept in scope for the port loop: the FDB dump uplink_bridge_port already
	-- takes of this bridge carries the hosts of every socket ENSLAVED TO IT
	-- too, so those sockets are served from it rather than forking a
	-- `bridge fdb show dev <socket>` of its own.
	--
	-- "Enslaved to it" is the load-bearing half, and this was read as "every
	-- socket" -- which is true right up until openUF moves one. A socket the
	-- controller assigns to a port VLAN is moved out of the management bridge
	-- into br-openuf<vid> (switchvlan.dsa_apply), and asking the UPLINK
	-- bridge's FDB about it finds nothing, because it is not a port of that
	-- bridge any more. The socket then published an empty mac_table and the
	-- controller credited its client to whatever else had seen the MAC -- the
	-- gateway, which sees everything. Each socket is asked about its own
	-- bridge in the port loop below.
	local uplink_bridge = nil
	if not next(sw.ports) then
		local lan = cfg and cfg.net and cfg.net.lan_cpueth
		local ok_br, br = pcall(M._sysinfo.bridge_of, lan)
		if ok_br and br then
			uplink_bridge = br
			local ok_up, name = pcall(M._sysinfo.uplink_bridge_port, br)
			if ok_up and name then
				for _, p in ipairs(ports) do
					if p.ifname == name then uplink_ifname = name break end
				end
			end
		end
	end
	local mgmt_vlan = (cfg and cfg.net and cfg.net.lan_vlanid) or 1
	local cpu_iface = iface_by_name[cfg and cfg.net and cfg.net.lan_cpueth]

	local port_table = {}
	for _, p in ipairs(ports) do
		local phys = uplink_phys and M._switchvlan
			and M._switchvlan.resolve_swport(cfg, p.swport) or nil
		local link = phys and sw.ports[phys] or nil

		local entry
		if link then
			-- Per-socket: the speed, duplex and link state of the physical
			-- socket a cable is actually in, and the uplink flag on whichever
			-- socket the default gateway is reached through.
			local is_uplink = (phys == uplink_phys)
			-- Per-port MIB counters where the switch driver exposes them (an
			-- AR9344 does; an AR8327 with mib polling off does not), and only
			-- bytes -- swconfig has no per-port packet or error count. The
			-- uplink falls back to the CPU netdev's counters, which for that
			-- one socket are a fair proxy: everything the CPU sent or received
			-- crossed it. A downstream socket has no such stand-in, and its
			-- share of the CPU netdev's total is not knowable, so it reports 0
			-- rather than a made-up number.
			local rx_bytes, tx_bytes = link.rx_bytes, link.tx_bytes
			local counted_iface = nil
			if not (rx_bytes or tx_bytes) and is_uplink then
				counted_iface = cpu_iface
				rx_bytes = counted_iface and counted_iface.rx_bytes
				tx_bytes = counted_iface and counted_iface.tx_bytes
			end
			entry = {
				port_idx    = p.idx,
				name        = "Port " .. tostring(p.idx),
				media       = "GE",
				up          = link.up,
				enable      = true,
				speed       = link.up and (link.speed or 1000) or 0,
				full_duplex = link.up and (link.full_duplex ~= false) or false,
				is_uplink   = is_uplink,
				speed_caps  = 0,
				port_poe    = false,
				poe_caps    = 0,
				rx_bytes    = rx_bytes or 0,
				tx_bytes    = tx_bytes or 0,
				rx_packets  = counted_iface and counted_iface.rx_packets or 0,
				tx_packets  = counted_iface and counted_iface.tx_packets or 0,
				rx_errors   = counted_iface and counted_iface.rx_errors  or 0,
				tx_errors   = counted_iface and counted_iface.tx_errors  or 0,
			}
			-- Hosts from the switch's own ARL table -- which socket each MAC
			-- sits on, the one thing the bridge FDB cannot say. Suppressed on
			-- the uplink (that socket faces the controller's network: every
			-- host on the far side would be reported as plugged into this AP,
			-- and see the netdev branch below for why not even the gateway
			-- alone may be reported there) and on any socket whose pvid is
			-- not the management VLAN -- the
			-- Archer C5's WAN socket is live but stranded on VLAN 2, and a
			-- host there is not reachable on the LAN it would be listed in.
			if not is_uplink and (link.pvid == nil or link.pvid == mgmt_vlan) then
				entry.mac_table = arr(_filter_hosts(
					M._sysinfo.switch_mac_table, phys, sw.arl, nil, nil,
					self_macs, station_macs))
			end
		else
			-- Netdev-only: no switch, no swconfig, or no identifiable uplink.
			-- Link state from the kernel, not from the netdev merely existing:
			-- an unused socket exists in /proc/net/dev and is idle, and
			-- reporting it as a live port misleads the Ports view. Falls back
			-- to existence only when sysfs cannot answer.
			local iface = iface_by_name[p.ifname]
			local link_up = M._link_up(p.ifname)
			if link_up == nil then link_up = (iface ~= nil) end
			entry = {
				port_idx    = p.idx,
				name        = "Port " .. tostring(p.idx),
				media       = "GE",
				up          = link_up,
				enable      = true,
				-- Negotiated link speed/duplex, read from the netdev rather
				-- than asserted: these were hardcoded 1000/full, so the
				-- controller's Ports view showed "GbE" for every device on
				-- every board no matter what the link had actually negotiated.
				-- A port with no link has no negotiated speed: 0, not the
				-- fallback. The kernel reports -1 for a down interface, which
				-- _link_speed already discards, so without this the fallback
				-- claimed a gigabit link on a socket with nothing in it.
				speed       = (not link_up) and 0 or (M._link_speed(p.ifname) or 1000),
				full_duplex = link_up and (M._link_duplex(p.ifname) ~= "half") or false,
				-- Detected where the bridge could answer (DSA), declared
			-- otherwise. Never both: a board that detects an uplink has
			-- already agreed the flag is not board truth.
			is_uplink   = (uplink_ifname ~= nil and p.ifname == uplink_ifname)
				or (uplink_ifname == nil and p.uplink) or false,
				speed_caps  = 0,
				port_poe    = false,
				poe_caps    = 0,
				rx_bytes    = iface and iface.rx_bytes   or 0,
				tx_bytes    = iface and iface.tx_bytes   or 0,
				rx_packets  = iface and iface.rx_packets or 0,
				tx_packets  = iface and iface.tx_packets or 0,
				rx_errors   = iface and iface.rx_errors  or 0,
				tx_errors   = iface and iface.tx_errors  or 0,
			}
			-- Wired clients are only reported on downstream (non-uplink)
			-- ports -- the controller itself skips client creation on ports
			-- flagged is_uplink, since that port faces the controller's own
			-- network, not an end host.
			--
			-- Do NOT be tempted to report just the gateway here, however
			-- reasonable "the device on the other end of this cable" sounds,
			-- and however visibly a real UniFi gateway does it on its own
			-- uplink port. openUF knows which MAC that is -- finding it is how
			-- the uplink socket was identified in the first place -- and
			-- reporting it would populate the Ports view's Connection column.
			-- It would also invert the topology. The controller matches every
			-- MAC on a port against its adopted devices, and a port carrying
			-- exactly one known device files that device in this one's
			-- `downlink_table`; the guard that would stop it is
			--     bl9 = !is_uplink && isUplinkMac(neighbour)
			-- which disables itself on precisely the port where it is needed.
			-- The gateway would hang beneath every AP that reported it.
			--
			-- A real gateway gets away with it because its upstream is the
			-- ISP's router, which is not an adopted device and so never
			-- reaches that branch. openUF cannot tell the two cases apart
			-- from the device, and the failure mode is a wrong map of the
			-- network, so it reports nothing on the uplink at all.
			if not entry.is_uplink then
				-- This socket's bridge, which is the uplink's for every socket
				-- openUF has not moved. bridge_of is TTL-cached and
				-- bridge_fdb_ports is memoized per bridge NAME for the pass,
				-- so the common case resolves to the same string and reuses
				-- the dump already taken -- no extra fork. A socket in
				-- br-openuf<vid> costs one dump of that bridge instead.
				--
				-- nil (not a bridge port at all) is passed through rather than
				-- papered over with the uplink's: mac_table then forks
				-- `bridge fdb show dev <socket>`, which is the right answer
				-- for an unbridged socket and an empty one for a bridged
				-- socket looked up in the wrong bridge.
				local ok_sb, sock_bridge = pcall(M._sysinfo.bridge_of, p.ifname)
				if not ok_sb then sock_bridge = nil end
				-- A socket in a bridge that is not the uplink's is one openUF
				-- moved, which is the only case where MAC learning is off and
				-- the FDB has nothing to say -- so it is the only case allowed
				-- to fall back to switchvlan's nft tap. Every other board never
				-- forks `nft` at all.
				local allow_tap = (uplink_bridge ~= nil and sock_bridge ~= nil
					and sock_bridge ~= uplink_bridge)
				-- Which VLAN this socket carries, read off the bridge openUF
				-- moved it into rather than plumbed down from the push: that
				-- bridge IS the VLAN (ucihelper names it br-openuf<vid>), so
				-- the socket's own enslavement is the most direct statement of
				-- it available, and it cannot disagree with where the frames
				-- actually go. nil for a socket still in the management
				-- bridge, which is the same thing as VLAN 1.
				local port_vlan = sock_bridge
					and tonumber(sock_bridge:match("^br%-openuf(%d+)$")) or nil
				if port_vlan == mgmt_vlan then port_vlan = nil end
				entry.mac_table = arr(_filter_hosts(
					M._sysinfo.mac_table, p.ifname, sock_bridge, allow_tap,
					port_vlan, self_macs, station_macs))
			end
		end
		port_table[#port_table + 1] = entry
	end

	-- lldp_table (field names confirmed against the real controller's OXMua
	-- DTO -- see PROTOCOL-VALIDATION.md's outbound payload field
	-- reference)
	local lldp_table = {}
	for _, nbr in ipairs(lldp_nbrs) do
		lldp_table[#lldp_table + 1] = {
			chassis_descr   = nbr.system_desc,
			chassis_id      = nbr.chassis_id,
			local_port_name = nbr.port,
			local_port_idx  = nbr.local_port_idx,
			is_wired        = true,  -- LLDP is inherently a wired-link protocol
			port_id         = nbr.port_id,
			port_descr      = nbr.port_descr,
		}
	end

	-- Read once for the two capability masks below (fw_caps 0x800000 and
	-- fw2_caps 0x80000 are the same probe, and sysinfo caches it for the
	-- process, so this is only about not asking the same question twice).
	local hs20_ok = M._sysinfo.hs20_supported and M._sysinfo.hs20_supported()

	local payload = {
		_type            = "state",
		["default"]      = not st.adopted,
		["state"]        = st.adopted and 2 or 0,  -- 2=connected, 0=unadopted (per amd989)
		locating         = st.locating or false,
		mac              = mac_str,
		serial           = mac_str:gsub(":", ""),
		model            = uap.model or "U6IW",
		platform         = uap.platform or "U6IW",
		hostname         = st.hostname or "openUF",
		ip               = st.ip or "0.0.0.0",
		inform_url       = st.inform_url,
		cfgversion       = st.cfgversion,
		uptime           = uptime,
		time             = os.time(),
		-- Bare firmware version string only -- NOT model-prefixed. The
		-- controller compares this against its firmware catalog's own
		-- "version" field (e.g. "6.8.2.15592") with a strict, unnormalized
		-- string equality check; a prefixed value like "U6IW.6.8.2.15592"
		-- never matches even when the numeric version is identical, so the
		-- device is permanently shown as needing an update. `fw.pre` (e.g.
		-- "U6IW.") is a separate, correct field used only by announce.lua's
		-- L2 discovery "firmware version verbose" TLV -- do not reuse it here.
		version          = uap.fw and uap.fw.ver or "6.6.55",
		required_version = uap.required_version or "6.0.0",
		bootrom_version  = uap.bootver or "",
		country_code     = st.country_code or derived_country or 840,
		mem_total        = meminfo.total_kb * 1024,
		mem_used         = (meminfo.total_kb - meminfo.free_kb) * 1024,
		-- Bit 0x10 (16): Device.hasQCASwitch() in the decompiled controller
		-- is exactly hasFirmwareCapability(16), and PGOcbDWlbnYQdFW gates the
		-- Ports view's projection of port_table into the device DTO on it.
		-- Wired-client ingestion itself is gated only on isSwitch() (a
		-- model-registry property, not this bit), so wired clients can
		-- appear without this -- but the Ports view needs it.
		-- Bit 0x100 (256): Device.hasOWRTSwitch() -- exactly
		-- hasFirmwareCapability(256), literally "OpenWrt switch" as opposed
		-- to a genuine QCA hardware switch ASIC (fitting, since that's
		-- exactly what this is). Without it, the REST API's per-port VLAN
		-- validator (com.ubnt.ace.api.e.VVyiC, only reachable once
		-- hasQCASwitch() above is true) unconditionally rejects any port
		-- whose forward mode resolves to the default "all" -- i.e. every
		-- port that has never had `forward` explicitly set -- with
		-- api.err.VlanTaggingUnsupportedByDevice, before ever touching
		-- vlan_caps or anything port-specific. Confirmed live: assigning a
		-- port's Native VLAN/Network failed with exactly that error at
		-- fw_caps=0x10, and succeeded once this bit was added (0x110) --
		-- reproduced directly against the REST endpoint, bypassing the UI,
		-- to rule out unrelated causes. See PROTOCOL-VALIDATION.md's
		-- "Capability bitmasks" for the full derivation (traced through
		-- an obfuscation-induced macOS case-folding extraction bug along
		-- the way).
		-- Bit 0x1000 (4096): supportMultiBlockWlanSchedule(). A WiFi
		-- Blackout Schedule with several on-blocks in one day then goes
		-- out as schedule_<day>.<i>, one key per block; without it every
		-- block shares the bare schedule_<day> key and only the last one
		-- survives the parse (lab capture, 10.4.57). The schedule itself is
		-- wlansched.lua. 0x400000 (schedule_invert) stays unclaimed: the
		-- controller then inverts the blackout windows into on-times
		-- itself, the form the 4.0.15 firmware reads.
		-- Bit 0x800000 (8388608): supportHotspot2(). Without it the
		-- controller refuses to provision a WLAN with a Hotspot 2.0
		-- profile attached AT ALL -- ubntconf/LsyaJoEysWb returns null
		-- for it, logging "Hotspot 2 cannot provision OSEN on ..." --
		-- so the whole aaa.<n>.hs20.* keyspace is unreachable without
		-- the claim. Claimed only where hostapd can actually answer
		-- ANQP (sysinfo.hs20_supported: the ucode generator knows the
		-- interworking options AND the binary was built with
		-- CONFIG_HS20), because the alternative to a dropped WLAN is a
		-- WLAN that advertises Passpoint and answers nothing.
		-- Bit 0x100000 (1048576): RADIUS Dynamic Authorization (RFC 5176
		-- CoA / Disconnect-Request). The config writer tests this one inline
		-- rather than through a named Device helper (10.6.106
		-- com/ubnt/service/config/VAZShipWTNxlo:567), and with it a WLAN
		-- whose RADIUS profile has accounting on, and which has either
		-- "RADIUS DAS" or Hotspot 2.0 enabled, gets
		-- aaa.<n>.radius.das.{status,port,client,secret}. Claimed since
		-- 2026-10-27: openUF needs no CoA listener of its own, because
		-- hostapd IS one -- radius_das_port/radius_das_client are real
		-- wifi-iface options on 25.12, and a Disconnect-Request from the
		-- RADIUS server then deauthenticates the station. See _wire_radius
		-- for the keys, and for why radius.dad.* is declined.
		-- Bit 0x80000000 (Integer.MIN_VALUE): MAC-based VLANs, the per-client
		-- "Virtual Network Override". Device.supportsMacBasedVlans() =
		-- hasFirmwareCapability(Integer.MIN_VALUE), and the emitter
		-- (ubntconf/fdwW) needs it AND a site-wide quorum: a ubios gateway that
		-- claims the bit or is one of 23 listed models, and NO client-bearing AP
		-- or switch in the site that fails to claim it. One AP without the bit
		-- therefore switched the feature off for every device in the site --
		-- which is where openUF stood until 2026-10-27.
		--
		-- SIGNED, deliberately: the sum is written as a negative number because
		-- fw_caps is a Java `int` on the controller side (a genuine gateway
		-- reports its own caps negative for the same reason), and 0x80101110
		-- sent as 2148537104 is out of range for the deserializer. Subtracting
		-- 0x80000000 from a positive sum is exactly what setting the sign bit
		-- means in two's complement.
		fw_caps          = 0x101110 - 0x80000000
			+ (hs20_ok and 0x800000 or 0),
		-- wifi_caps, the first WiFi bitmask. Bit 0x4 is
		-- Device.supportBandsteering(): without it the controller never emits
		-- the device-level bandsteering.* block (the AP's own Band Steering
		-- setting). Bit 0x8, supportVapBasedBandsteering(), keeps that block
		-- enabled when some WLAN has no 2.4/5 GHz pair; without it one
		-- single-band WLAN switches the device's steering off. See
		-- _parse_bandsteering_system_cfg. Decompiled from controller
		-- 10.6.101, captured on 10.4.57. Bit 0x20 is supportATFConfig():
		-- without it no atf.* block (Airtime Fairness) is sent; claimed only
		-- where mac80211's airtime_flags can be switched (airtime.lua). Bit
		-- 0x100000 is supportWpaPpsk(): without it a WLAN with Private
		-- Pre-Shared Keys is skipped entirely ("PPSK is not supported ...
		-- will be skipped"); claimed only where hostapd can put each key on
		-- its own VLAN (sysinfo.ppsk_supported). The other bits gate features
		-- openUF does not implement (PROTOCOL-VALIDATION.md, Capability
		-- bitmasks).
		wifi_caps        = 0x1C + ((M._airtime and M._airtime.supported()) and 0x20 or 0)
			+ ((M._sysinfo.ppsk_supported and M._sysinfo.ppsk_supported()) and 0x100000 or 0),
		-- Bit 0x40 (64): Device.supportAdvertisingDeviceNameInBeacon() in the
		-- decompiled controller is exactly hasWifiCapability2(64) -- i.e. bit
		-- 6 of a SECOND capability bitmask, wifi_caps2, entirely separate
		-- from fw_caps/wifi_caps above. Confirmed by decompiling
		-- com/ubnt/service/config's WLAN-config-generator method: it only
		-- emits wireless.<n>.advertise_ap_name into system_cfg at all when
		-- this bit is set -- otherwise the "Show Access Point Name in
		-- Beacon" WLAN toggle is silently dropped, which is exactly what a
		-- live capture showed (toggling it produced zero system_cfg/mgmt_cfg
		-- diff, and the controller didn't even bother re-pushing config on
		-- the next change) before this bit was added.
		--
		-- Bit 0x20 (32): Device.supportsAssistedRoaming(). Without it the
		-- controller never emits a WLAN's "Roaming Assistant"
		-- (wireless.<n>.btm_disassoc.*), which openuf/roamassist.lua
		-- implements. Decompiled from controller 10.6.101.
		--
		-- Bit 0x2000 (8192): Device.supportsRoamTopologyStats(). With it on
		-- both APs the controller stops deriving roams from sta_table moves
		-- (always "Success", no tags) and takes them from this AP's roam
		-- reports alone (assoctrack.lua: association / sta_leave / sta_roam
		-- notifs, which carry Fast Roaming, failures and the Roaming
		-- Assistant and Minimum RSSI tags). Claimed only while those are
		-- sent: without the reports the bit would make roams vanish.
		--
		-- Bit 0x10 (16): Device.supportsAcsDfs(). It gates TWO per-radio keys
		-- at once -- the whole block that emits them sits behind this one
		-- check (10.6.106,
		-- com/ubnt/service/config/ubntconf/PFljhxhmKJyhpeIhf): the 5 GHz
		-- radio's radio.<n>.acsdfs (may auto-channel land on a DFS channel)
		-- and, for any radio on Auto, radio.<n>.blklst (the site's channel
		-- blacklist for that band). Without it a site that excludes channels
		-- -- which the DEFAULT "conservative" preset does, blacklisting
		-- everything but 1/6/11 on 2.4 GHz -- is silently dropped and ACS
		-- picks whatever it likes. Claimed because both have real consumers
		-- here: wifi-device acs_exclude_dfs and chanlist (see
		-- ucihelper.rf_config).
		--
		-- Bit 0x400000: Device.supportsMulticastSuppressor(). Gates the
		-- WLAN's wireless.<n>.multicast.suppressor key -- the "Multicast
		-- Suppression" control, which is the same WLAN setting the old
		-- "Multicast and Broadcast Blocker" was: 10.6.106's own UI bundle
		-- maps mode=aggressive onto bc_filter_enabled + bc_filter_list (the
		-- bcfilt.* keys openUF already enforces) and mode=conservative onto
		-- this key ALONE. Without the bit a WLAN set to Conservative pushes
		-- nothing at all. See bcfilter.lua for what each mode does.
		--
		-- No other bit is claimed: wifi_caps2 also gates real-hardware-only
		-- features (Mesh MLO parent/child and others, see
		-- PROTOCOL-VALIDATION.md) that openUF does not implement.
		wifi_caps2       = 0x400070 + (M._assoc_enabled(st, cfg) and 0x2000 or 0),
		-- fw2_caps, a THIRD firmware bitmask (hyFnQ.getFirmware2Capabilities
		-- reads the field "fw2_caps"), sent only for its one needed bit.
		--
		-- Bit 0x80000 (524288): supportsRadSec(). openUF does NOT implement
		-- RadSec, and this is claimed anyway, for one reason: the REST
		-- validator that admits a Hotspot 2.0 profile onto a WLAN
		-- (com/ubnt/service/W/ctfbDsCjrxgkv) tests
		-- supportsHotspot2Passpoint() = supportHotspot2() AND
		-- supportsRadSec(), and rejects the whole request with
		-- api.err.DevicePasspointNotSupported otherwise -- so on 10.6.106
		-- Passpoint is unreachable without it, bit 0x800000 or not.
		-- Claimed only alongside that bit (same probe) so it never appears
		-- on a device that cannot do Passpoint at all.
		--
		-- What claiming it actually changes on the wire: for a RADIUS server
		-- whose profile has TLS on, the controller adds
		-- aaa.<n>.radius.{auth,acct}.<k>.{ca_cert,client_cert,private_key,
		-- private_key_passwd} -- FILENAMES of files it transfers by another
		-- channel. _wire_radius drops such a server with a log rather than
		-- speaking plain RADIUS to a RadSec port. That is strictly better
		-- than the behaviour without the bit, where the same server arrives
		-- as a bare ip/port/secret, indistinguishable from a plaintext one,
		-- and its shared secret goes out in the clear.
		fw2_caps         = hs20_ok and 0x80000 or 0,
		-- Device-level (not per-radio -- see radio_table_stats above)
		-- Device-level Experience: the VAP scores weighted by their client
		-- counts (calc_ap_satisfaction, see satisfaction.lua). The controller
		-- does not aggregate the per-client scores it already holds, so
		-- without this the Devices list reads "No Clients" however many are
		-- connected. -1 with no clients, as the firmware sends it: the
		-- controller copies this field only when present, so leaving it out
		-- kept the last score on an AP whose clients had all left.
		satisfaction     = M._satisfaction.rollup(sat_tallies),
		-- True from the spectrum-scan cmd until its sweep has run (see
		-- _tick). The controller refuses another scan while it is true.
		-- (spectrum_scan_timestamp is not sent: the controller stamps it
		-- itself, in ms, from quick-scan results.)
		spectrum_scanning = M._spectrum_pending and true or false,
		-- Guest portal: the controller refuses to authorize a guest on an AP
		-- that reported no guest_token ("Missing Guest Token in AP[..]
		-- during guest authorization"). Only while the portal is on.
		guest_token      = (type(st.guest_portal) == "table" and st.guest_portal.enabled)
			and st.guest_token or nil,
		-- Real devices report this under the hyphenated key "system-stats"
		-- with {cpu, mem, uptime} as percentage/uptime strings -- confirmed
		-- against a real captured USG inform payload (stephanlascar/
		-- unifi-gateway, poc/real_inform_payload_exemple.json).
		-- UniFi firmware sends sys_stats beside it (prepare_system_stats,
		-- firmware-confirmed for 3.9.27 to 4.0.15): /proc/loadavg's three
		-- strings and sysinfo()'s totalram, totalram - freeram and
		-- bufferram in bytes. The controller stores it; the UI shows the
		-- load averages as the device's Load Average.
		sys_stats = {
			loadavg_1  = load1,
			loadavg_5  = load5,
			loadavg_15 = load15,
			mem_total  = meminfo.total_kb * 1024,
			mem_used   = (meminfo.total_kb - meminfo.free_kb) * 1024,
			mem_buffer = (meminfo.buffers_kb or 0) * 1024,
		},
		-- The address the controller sends its STUN connection request to
		-- (stun.lua): the mapped address of the last Binding Response, both
		-- strings as the firmware sends them, and only while STUN runs.
		connect_request_ip   = stun_ip,
		connect_request_port = stun_port,
		["system-stats"] = {
			cpu    = tostring(cpu_pct),
			mem    = tostring(mem_pct),
			uptime = tostring(uptime),
		},
		if_table         = arr(if_table),
		radio_table      = arr(radio_table),
		radio_table_stats = arr(radio_table_stats),
		vap_table        = arr(vap_table),
		scan_radio_table = arr(scan_radio_table),
		port_table       = arr(port_table),
		lldp_table       = arr(lldp_table),
	}

	if own_uci_pass and ufuci.end_pass then ufuci.end_pass() end
	if M._sysinfo.end_pass then M._sysinfo.end_pass() end
	M._notif_identity = {
		mac = payload.mac, serial = payload.serial, model = payload.model,
		platform = payload.platform, hostname = payload.hostname, ip = payload.ip,
		inform_url = payload.inform_url, cfgversion = payload.cfgversion,
		version = payload.version, required_version = payload.required_version,
		["default"] = payload["default"], state = payload.state,
		locating = payload.locating, uptime = payload.uptime,
	}
	return M._fix_empty_arrays(cjson.encode(payload))
end

-- Maps an OpenWrt htmode ("HT20", "HT40+", "VHT80", "HE160", ...) to a
-- channel width in MHz. Falls back to 20 for unrecognized/missing modes.
local function _width_from_htmode(htmode)
	if type(htmode) ~= "string" then return 20 end
	local n = htmode:match("(%d+)")
	return n and tonumber(n) or 20
end

-- The channel widths a spectrum_table lists for a radio: 20 and 40 MHz on
-- 2.4 GHz, 20/40/80 elsewhere, and up to the radio's configured width when
-- that is wider (160 or 320).
function M._spectrum_widths(radio)
	local widths = { 20, 40 }
	local band = radio and radio.radio
	if band ~= "ng" then widths[#widths + 1] = 80 end
	local cfg = _width_from_htmode(radio and radio.ht)
	local w = widths[#widths]
	while w < cfg do
		w = w * 2
		widths[#widths + 1] = w
	end
	return widths
end

-- radio.<n>.ieee_mode: the controller's per-radio 802.11 mode + channel width,
-- as a single madwifi/Ubiquiti-style compound token -- "11" + band ("ng"/"na")
-- + PHY and width ("ht20", "ht40", "vht80", "he80", ...). CONFIRMED live
-- 2026-07-18: a stock dual-band AP sends radio.1.ieee_mode=11nght20 (2.4GHz)
-- and radio.2.ieee_mode=11naht40 (5GHz), and flipping the per-device radio
-- setting Devices -> [AP] -> Settings -> Radios -> "2.4 GHz Channel Width"
-- from 20 to 40 changes exactly this key to 11nght40 (alongside
-- radio.<n>.cwm.mode 0->1, a redundant "channel width management" flag the
-- same width is already encoded in). This is the only channel-width signal on
-- the wire -- an earlier version of openUF parsed no mode key at all, so
-- ucihelper.rf_config()'s htmode mapping was unreachable and channel width
-- silently never applied despite USAGE.md claiming it did.
--
-- Returns an OpenWrt htmode string ("HT20"/"HT40"/"VHT80"/"HE80"/...), or nil
-- for an absent or unrecognized token, which leaves htmode unchanged (same
-- "absent -> nil -> leave alone" convention as channel/txpower above).
-- Longest suffix first: "eht"/"vht" must win over the "ht" they end with.
local _IEEE_MODE_PHY = {
	{ "eht", "EHT" }, { "vht", "VHT" }, { "he", "HE" }, { "ht", "HT" },
}
local _IEEE_MODE_WIDTHS = { ["20"] = true, ["40"] = true, ["80"] = true,
	["160"] = true, ["320"] = true }

local function _htmode_from_ieee_mode(ieee_mode)
	if type(ieee_mode) ~= "string" then return nil end
	local head, width = ieee_mode:match("^(11%a+)(%d+)$")
	if not (head and _IEEE_MODE_WIDTHS[width]) then return nil end

	-- The two letters after the "11" are the band ("ng"/"na"), the rest is
	-- the PHY token. The band is not used to pick a channel -- OpenWrt
	-- derives that from the channel, and the controller can send
	-- channel=auto while still naming a band here -- but it IS what says
	-- which radio's capabilities to read below.
	local band, token = head:match("^11(%a%a)(%a*)$")

	-- A plain "ht" is not a request for 802.11n. It is all this wire format
	-- has ever said: the vocabulary is Atheros-era (the same push calls the
	-- VAPs ath0/ath1/ath2), and a real controller sends "11naht40" to a real
	-- U6-InWall, which runs it as HE40. The token carries the BAND and the
	-- WIDTH; the PHY generation is the device's own business, and reading
	-- the "ht" literally pinned an 802.11ax radio to 802.11n forever --
	-- confirmed live on an AX3000T, whose 5GHz radio came up HT40 on
	-- hardware that does HE160.
	--
	-- So: honour an explicit vht/he/eht token if one ever arrives, and
	-- otherwise run the best PHY the band's hardware has. Unknown
	-- capabilities (no `iw`, unparseable output) fall back to the literal
	-- reading rather than guessing upward -- same contract as clamp_htmode,
	-- which still caps the result downward from here.
	if band and token == "ht" then
		local best = M._ucihelper and M._ucihelper.best_phy
			and M._ucihelper.best_phy(band)
		if best then return best .. width end
	end

	for _, phy in ipairs(_IEEE_MODE_PHY) do
		local kind, prefix = phy[1], phy[2]
		if head:sub(-#kind) == kind then return prefix .. width end
	end
	return nil
end

-- WiFi/radio config (SSID, security, per-radio channel/TX power) arrives via
-- system_cfg as a flat, hostapd/OpenWrt-style key=value blob -- NOT as the
-- resp.vap_table/radio_table/network_table JSON that ucihelper.apply_config()
-- was originally built and unit-tested against. Confirmed live against a
-- real controller (10.4.57): creating a WiFi network produces keys like
-- "aaa.1.ssid", "aaa.1.wpa.psk", "aaa.1.wpa=2", "wireless.1.parent=radio0",
-- "radio.1.phyname=radio0", "radio.1.channel=auto" -- a real controller
-- never sends resp.vap_table/radio_table/network_table at all, which meant
-- apply_config() (gated on resp.network_table) never actually ran against
-- one. This translates the flat blob into the {radio_table, vap_table}
-- shape apply_config() expects, so its already-correct, already-tested
-- VLAN-join/fast-roaming/mobility-domain logic can be reused unchanged
-- rather than reimplemented against the raw wire format.
--
-- Security derivation reads the akm set from aaa.<n>.wpa.key.<k>.mgmt (not
-- just aaa.<n>.wpa, which is only the WPA protocol version and stays "2"
-- even for a WPA2/WPA3 transition WLAN): SAE present -> sae/sae-mixed,
-- else WPA2-PSK. Confirmed live for the WPA2-PSK case (wpa=2 +
-- wpa.key.1.mgmt=WPA-PSK -> "wpa2").
--
-- WPA3 is gated on the DEVICE claiming it: a radio_table entry must report
-- `wpa3_supported = true` (see build_json) or the controller silently
-- downgrades a WPA2/WPA3 WLAN to plain WPA2 for that device, before the
-- config is even generated. Confirmed live against a 10.4.57 gateway --
-- setting that one field flipped the very next push from
-- `wpa.key.1.mgmt=WPA-PSK` to `SAE`, and brought the whole
-- wpa3.support/wpa3.transition/wpa3.ft.status/sae.* block with it.
--
-- Once it does arrive, `SAE` comes as the ONLY akm -- there is no WPA-PSK
-- alongside it even in transition mode -- so the akm set alone cannot tell
-- transition from WPA3-only. wpa3.transition is what distinguishes them, and
-- is read below.
--
-- Two earlier readings recorded here were wrong: that the PMF keys carry the
-- WPA3-mixed signal (they do not -- PMF is just PMF), and that a radio_caps
-- capability bit gates it (neither radio_caps nor radio_caps2 bit 0x1 has any
-- effect; both were tested live).
local function _wire_bool(v)
	if v == nil then return nil end
	return v == "1" or v == "true" or v == "enabled"
end

-- A whole number of seconds (aaa.<n>.wpa.group_rekey), as a string for UCI;
-- nil when absent or malformed.
local function _wire_group_rekey(v)
	if type(v) ~= "string" or not v:match("^%d+$") or #v > 9 then return nil end
	return tostring(tonumber(v))
end

-- A positive whole number (aaa.<n>.sae.anti_clogging / .sae.sync), as a string
-- for UCI; nil when absent, zero or malformed (the controller sends > 0 only).
local function _wire_posint(v)
	if type(v) ~= "string" or not v:match("^%d+$") or #v > 9 then return nil end
	local n = tonumber(v)
	return n > 0 and tostring(n) or nil
end

-- aaa.<n>.wpa.1.pairwise: the WLAN's pairwise cipher, as the controller's own
-- authoritative answer rather than openUF's derivation from the akm set.
-- CONFIRMED live 2026-10-26 against 10.6.106 by diffing system_cfg across the
-- wlanconf's `wpa_enc` field (REST-only; the 10.6 UI has no control): the
-- generator maps the enum {auto, ccmp, gcmp, ccmp-256, gcmp-256} through
-- com.ubnt.i.b.aL.kYktyHCkPVCBdJC, where `auto` becomes "CCMP" -- or
-- "TKIP CCMP" on a WPA1 WLAN -- and every other value is the name upper-cased.
-- Observed on the wire: CCMP (auto/ccmp), CCMP-256, GCMP. `gcmp-256` is
-- refused by the controller's own validator and normalised back to auto, so it
-- cannot arrive; it is mapped anyway because the enum carries it and a later
-- build may let it through.
--
-- The return value is the cipher token for OpenWrt's `encryption` string
-- (iface.uc's second `+` token), NOT a hostapd wpa_pairwise value.
-- "CCMP" returns nil on purpose: it is what every WLAN openUF provisions gets
-- by default (iface.uc's final `wpa_pairwise ??= 'CCMP'`), so carrying it
-- would add a suffix that changes nothing and mask a genuine default.
--
-- "TKIP CCMP" is deliberately declined: it appears only on a WPA1-mode WLAN,
-- openUF maps no controller security value to WPA1 at all, and TKIP is
-- forbidden by both WPA2 and WPA3 certification. Anything else unrecognised is
-- nil, which leaves the default in place rather than writing a cipher the
-- driver may not have.
local PAIRWISE_SUFFIX = {
	["CCMP-256"] = "ccmp256",
	["GCMP"]     = "gcmp",
	["GCMP-256"] = "gcmp256",
}

local function _wire_pairwise(v)
	if type(v) ~= "string" then return nil end
	return PAIRWISE_SUFFIX[v:upper()]
end

-- aaa.<n>.sae.groups.<k>.group, in index order, as hostapd's space-separated
-- sae_groups; nil unless sae.has_groups is on and every entry is a number.
local function _wire_sae_groups(a)
	if not _wire_bool(a["sae.has_groups"]) then return nil end
	local idxs = {}
	for k in pairs(a) do
		local i = k:match("^sae%.groups%.(%d+)%.group$")
		if i then idxs[#idxs + 1] = tonumber(i) end
	end
	table.sort(idxs)
	local out = {}
	for _, i in ipairs(idxs) do
		local g = a["sae.groups." .. i .. ".group"]
		if not g:match("^%d+$") or #g > 3 then return nil end
		out[#out + 1] = g
	end
	return #out > 0 and table.concat(out, " ") or nil
end

-- aaa.<n>.radius.* -- the 802.1X / WPA-Enterprise RADIUS configuration.
--
-- The controller DOES send this, contrary to what openUF assumed until
-- 2026-10-26: the AP config builder (10.6.106
-- com/ubnt/service/config/VAZShipWTNxlo) emits
--   aaa.<n>.radius.auth.<k>.{ip,port,secret}   k = 1..4
--   aaa.<n>.radius.acct.<k>.{ip,port,secret}   k = 1..4, accounting only
--   aaa.<n>.interim_update.{status,interval}   interval defaults to 3600
--   aaa.<n>.dynamic_vlan                       0 | 1 optional | 2 required
--   aaa.<n>.nas_identifier
-- and UAP firmware 6.8.2's own hostapd generator (ubntbox) turns them into
-- auth_server_addr/port/shared_secret, acct_server_*,
-- radius_acct_interim_interval, dynamic_vlan and nas_identifier. The
-- eligibility filter (ubntconf/LsyaJoEysWb) puts NO device capability gate on
-- a WPA2-Enterprise WLAN, so this arrives whether or not openUF asks for it.
--
-- Since 2026-10-27 this also carries RADIUS MAC authentication and Dynamic
-- Authorization; see the macacl and das blocks below.
--
-- Deliberately NOT read (and tested for, so nothing downstream keys on them):
--   * radius.dad.*  -- the SECOND shape of Dynamic Authorization: a top-level
--     aaa.radius.dad.{status,port,loglevel} plus per-client
--     aaa.<n>.radius.dad.client.<k>.{cidr,secret}. UAP firmware 6.8.2 turns
--     those into `radius_das_client=127.0.0.1 <secret>` -- the AP accepts the
--     request from its OWN mcad, which relays what it received from the
--     network and does the CIDR check itself. openUF has no such relay, so
--     pointing hostapd at 127.0.0.1 would make it answer nobody. The das.*
--     shape names the client directly and is the one openUF implements; the
--     controller sends both whenever either applies.
--   * radius.macacl.{format,emptypassword} -- how the AP renders the MAC as
--     the RADIUS User-Name/User-Password. Both are options of UniFi's own
--     patched hostapd (6.8.2 writes `macaddr_format=%s` from a printf format
--     string -- the wire really does carry e.g.
--     "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X" -- and `mac_acl_empty_passwd=%d`).
--     Neither string exists in OpenWrt's hostapd binary on either AP, which
--     always sends lower-case colon-separated for both attributes. A RADIUS
--     server configured for another format will reject the client, so this is
--     a real limitation rather than a cosmetic one -- see USAGE.md.
--   * radius.auth|acct.<k>.{ca_cert,client_cert,private_key,private_key_passwd}
--     -- RadSec. The controller sends only FILENAMES, for files it transfers
--     by another channel, so it cannot be completed here. Their presence is
--     what marks a server as RadSec (there is no .tls key), and such a server
--     is dropped rather than contacted with its secret in the clear. They
--     arrive only because openUF claims fw2_caps 0x80000 for the Passpoint
--     gate; see build_json.
--
-- Returns a table, or nil plus a reason naming what was missing. Secrets are
-- never written to any log line.
local function _wire_radius(a)
	local function servers(kind, default_port)
		local idxs = {}
		for k in pairs(a) do
			local i = k:match("^radius%." .. kind .. "%.(%d+)%.ip$")
			if i then idxs[#idxs + 1] = tonumber(i) end
		end
		table.sort(idxs)
		local out = {}
		for _, i in ipairs(idxs) do
			local pfx = "radius." .. kind .. "." .. i .. "."
			local ip, secret = a[pfx .. "ip"], a[pfx .. "secret"]
			local port = _wire_posint(a[pfx .. "port"]) or default_port
			local why
			-- RadSec. There is NO aaa.<n>.radius.<kind>.<k>.tls key: the
			-- emitter writes only the cert FILENAMES, and only when
			-- supportsRadSec() (fw2_caps 0x80000, which openUF claims for the
			-- Passpoint gate -- see build_json). Their presence is therefore
			-- the whole discriminator, and the server is dropped rather than
			-- contacted with a shared secret in the clear.
			if a[pfx .. "ca_cert"] or a[pfx .. "client_cert"]
					or a[pfx .. "private_key"] then
				why = "RadSec (TLS) is not supported"
			elseif not netconfig.is_ipv4(ip) then
				why = "no usable IPv4 address"
			elseif type(secret) ~= "string" or secret == "" or #secret > 64 then
				why = "missing or oversized shared secret"
			end
			if why then
				io.stderr:write(("inform: dropping RADIUS %s server %d -- %s\n")
					:format(kind, i, why))
			else
				out[#out + 1] = {ip = ip, port = port, secret = secret}
			end
		end
		return out
	end

	local auth = servers("auth", "1812")
	if #auth == 0 then return nil, "no usable RADIUS authentication server" end

	local dynamic_vlan = a.dynamic_vlan
	if dynamic_vlan ~= "1" and dynamic_vlan ~= "2" then dynamic_vlan = nil end

	-- Dynamic Authorization (RFC 5176): the RADIUS server may send a
	-- Disconnect-Request or a CoA-Request for a station already online. One
	-- client and one shared secret, which is all hostapd can express
	-- (radius_das_client holds both, separated by a space), and all the
	-- controller sends in this shape -- das.client is the FIRST accounting
	-- server's address, written once (VAZShipWTNxlo:973).
	local das
	if _wire_bool(a["radius.das.status"]) then
		local ip, secret = a["radius.das.client"], a["radius.das.secret"]
		local why
		if not netconfig.is_ipv4(ip) then
			why = "no usable IPv4 client address"
		elseif type(secret) ~= "string" or secret == "" or #secret > 64 then
			why = "missing or oversized shared secret"
		elseif secret:find("%c") then
			-- The secret is the REST of the radius_das_client line, so a space
			-- inside it is harmless; a newline would end the line and let what
			-- follows be read as further hostapd options.
			why = "a control character in the shared secret"
		end
		if why then
			io.stderr:write(("inform: ignoring RADIUS Dynamic Authorization -- %s\n")
				:format(why))
		else
			-- The controller's own port is 3800 + the WLAN's section index, so
			-- each BSS gets its own UDP socket. 3799 is the RFC 5176 default and
			-- what the firmware falls back to.
			das = {client = ip, secret = secret,
				port = _wire_posint(a["radius.das.port"]) or "3799"}
		end
	end

	return {
		auth = auth,
		das = das,
		acct = servers("acct", "1813"),
		-- Only when the controller says so: absent means "do not send interim
		-- accounting updates", not "use 3600".
		interim_interval = _wire_bool(a["interim_update.status"])
			and (_wire_posint(a["interim_update.interval"]) or "3600") or nil,
		dynamic_vlan = dynamic_vlan,
		nas_id = a.nas_identifier,
	}
end

-- aaa.<n>.accept_mac.* -- MAC-based VLANs ("Virtual Network Override").
--
-- Per CLIENT, not per WLAN: the controller's own UI calls it Virtual Network
-- Override and it lives on the client, which is why the SAME list reaches every
-- WLAN in the site. The emitter (10.6.106
-- com/ubnt/service/config/ubntconf/fdwW) groups every user object carrying
-- virtual_network_override_enabled by its override network, then writes, per
-- WLAN index n:
--   aaa.<n>.accept_mac.status=enabled      (once, before the first entry)
--   aaa.<n>.accept_mac.<k>.mac             k = 1..
--   aaa.<n>.accept_mac.<k>.vlanid          that network's VLAN id
-- (a switch identity gets the same list as switch.vnet.<n>.{name,vlan,mac.<k>}).
--
-- TWO gates, and the second one is site-wide -- see build_json for fw_caps
-- 0x80000000, and PROTOCOL-VALIDATION.md for the gateway/AP/switch quorum.
--
-- status is NOT the discriminator and is deliberately not read: the writer
-- emits it from inside the same loop that writes the first entry, so it is
-- present exactly when there is at least one entry and absent exactly when
-- there is none. The entries are the whole signal.
local function _wire_mac_vlans(a)
	local out, seen = {}, {}
	local k = 1
	while a["accept_mac." .. k .. ".mac"] do
		local mac = tostring(a["accept_mac." .. k .. ".mac"]):lower()
		local vid = tonumber(a["accept_mac." .. k .. ".vlanid"])
		local why
		if not is_mac(mac) then
			why = "not a MAC address"
		elseif not vid or vid ~= math.floor(vid) or vid < 1 or vid > 4094 then
			why = "VLAN id out of range"
		elseif seen[mac] then
			-- A client has one override network, so the controller cannot send
			-- the same MAC twice. If it ever did, two accept-list lines for one
			-- station would leave hostapd's bsearch to pick one of them.
			why = "a duplicate of an earlier entry"
		end
		if why then
			io.stderr:write(("inform: dropping MAC-based VLAN entry %d -- %s\n")
				:format(k, why))
		else
			seen[mac] = true
			out[#out + 1] = {mac = mac, vid = vid}
		end
		k = k + 1
	end
	return #out > 0 and out or nil
end

-- Free text from a controller-side profile (a venue or operator name, a realm,
-- a URL) on its way to a hostapd config FILE. A control character -- a newline
-- above all -- would end the line and let the rest be read as further hostapd
-- options, so anything carrying one is dropped rather than sanitised. 128 is
-- the controller's own cap on every one of these fields.
local function _wire_text(v, maxlen)
	if type(v) ~= "string" or v == "" or #v > (maxlen or 128) then return nil end
	if v:find("%c") then return nil end
	return v
end

-- A whole number within [lo, hi], as a string; nil when absent or out of range.
local function _wire_range(v, lo, hi)
	if type(v) ~= "string" or not v:match("^%d+$") or #v > 10 then return nil end
	local n = tonumber(v)
	if n < lo or n > hi then return nil end
	return tostring(n)
end

-- One pass over the WLAN's key table for every indexed Hotspot 2.0 block.
--
-- The tokenizer keeps the whole dotted tail as one flat key, so a sub-indexed
-- block has to be recovered by re-matching it (same shape as sae.groups /
-- wpa.psk_file). _wire_indexed used to do that re-match itself, walking every
-- key of `a` per call -- and _wire_hs20 calls it seven times plus once per NAI
-- realm, so a Passpoint WLAN paid ~10 full scans of the same table per push.
--
-- Instead, index once. Every indexed hs20 key is `hs20.<prefix>.<i>.<leaf>`,
-- or `hs20.<i>.<leaf>` for roaming_consortium, where <prefix> may itself carry
-- an index (nai_realm.<i>.eap_method.auth). <leaf> is dotless and anchored, so
-- <i> is always the key's LAST indexed level -- which is what puts each
-- realm's auth parameters in a bucket of their own. Keys with no index
-- (hs20.status, hs20.metrics.*) are read by name and so are skipped here.
local function _wire_hs20_index(a)
	local idx = {}
	for k in pairs(a) do
		if k:sub(1, 5) == "hs20." then
			local prefix, i, leaf = k:match("^hs20%.(.+)%.(%d+)%.([^.]+)$")
			if not prefix then
				i, leaf = k:match("^hs20%.(%d+)%.([^.]+)$")
				prefix = i and ""
			end
			if prefix then
				local bucket = prefix .. "/" .. leaf
				local l = idx[bucket]
				if l then l[#l + 1] = tonumber(i)
				else idx[bucket] = {tonumber(i)} end
			end
		end
	end
	return idx
end

-- The indices filed under <prefix>/<leaf> by _wire_hs20_index, in index order,
-- as whatever `build` makes of each. nil when none of them survives.
local function _wire_indexed(idx, prefix, leaf, build)
	local idxs = idx[prefix .. "/" .. leaf]
	if not idxs then return nil end
	table.sort(idxs)
	local out = {}
	for _, i in ipairs(idxs) do
		local e = build(i)
		if e then out[#out + 1] = e end
	end
	return #out > 0 and out or nil
end

-- aaa.<n>.hs20.* -- Hotspot 2.0 / Passpoint.
--
-- Reachable only because openUF claims fw_caps 0x800000 and fw2_caps 0x80000
-- (see build_json): without them the controller drops the whole WLAN.
--
-- The emitter (10.6.106 com/ubnt/service/config/VAZShipWTNxlo) knows a wider
-- keyspace than the controller can actually be made to send. A WLAN's Hotspot
-- 2.0 settings live in the wlanconf's own embedded `hotspot2` object, and
-- api/fields/WlanConf.json's schema for it is a SUBSET of the standalone
-- api/fields/Hotspot2Conf.json template: it has no hessid, anqp_domain_id,
-- network_auth_type/url, disable_dgaf, deauth_req_timeout, t_c_filename/
-- timestamp, osu_ssid, osu.*, icon.*, gas_comeback_delay/gas_frag_limit or
-- qos.map.*/qos.exception.* at all. A full-profile push (lab capture, every
-- field the subset allows filled) carried exactly the keys read below and
-- none of the others. So the rest is deliberately NOT read: there is no
-- producer to test a consumer against.
--
-- Independently unimplementable even if they did arrive:
--   * osu.* / icon.*  -- the installed hostapd (wpad-mbedtls 2025.08.26,
--     hostapd v2.12-devel) carries no osu_server_uri, osu_ssid or hs20_icon
--     option at all: the OSU/OSEN online-signup pieces are not built in.
--     Verified by string search on /usr/sbin/hostapd on both APs.
--   * t_c_filename / t_c_timestamp -- hostapd serves the Terms and Conditions
--     file from disk, and the controller transfers it by another channel.
--
-- Returns a table, or nil when Hotspot 2.0 is off for this WLAN.
local function _wire_hs20(a)
	if not _wire_bool(a["hs20.status"]) then return nil end

	local function k(suffix) return a["hs20." .. suffix] end
	local idx = _wire_hs20_index(a)

	local hs = {
		-- Interworking element. access_network_type is the 4-bit ANQP field
		-- (0 private, 2 chargeable public, 3 free public ...).
		access_network_type = _wire_range(k("access_network_type"), 0, 15),
		internet            = _wire_bool(k("internet")),
		asra                = _wire_bool(k("asra")),
		uesa                = _wire_bool(k("uesa")),
		venue_group         = _wire_range(k("venue_group"), 0, 11),
		venue_type          = _wire_range(k("venue_type"), 0, 255),
		-- Downstream Group-Addressed Forwarding. Sent twice, as
		-- aaa.<n>.hs20.disable_dgaf and wireless.<n>.dgaf_disable, from the
		-- same wlanconf field; this one is read and the other ignored.
		disable_dgaf        = _wire_bool(k("disable_dgaf")),
		deauth_req_timeout  = _wire_range(k("deauth_req_timeout"), 1, 3600),
		-- IP Address Type Availability: (v4 << 2) | v6, already combined by
		-- the controller (ipaddr_type_avail_v4 0-7, _v6 0-2).
		ipaddr_type_avail   = _wire_range(k("network_availability"), 0, 31),
		-- Already a comma-separated list on the wire, which is exactly
		-- hostapd's domain_name format.
		domain_name         = _wire_text(k("hs20_domain_name_list"), 1024),
	}

	-- aaa.<n>.hs20.esr is sent and deliberately dropped: the live ucode
	-- generator (ap.uc, iface_interworking) never appends `esr`, although the
	-- schema declares iw_esr as an alias for it, so the option would be stored
	-- in UCI and silently discarded. Writing it would be a consumer keyed on a
	-- producer that does not exist.

	hs.venue_name = _wire_indexed(idx, "venue_name", "name", function(i)
		local p = "hs20.venue_name." .. i .. "."
		local lang, name = _wire_text(a[p .. "lang"], 3), _wire_text(a[p .. "name"])
		if not (lang and name) then return nil end
		return {lang = lang, name = name, url = _wire_text(a[p .. "url"], 1024)}
	end)

	hs.nai_realm = _wire_indexed(idx, "nai_realm", "name", function(i)
		local p = "hs20.nai_realm." .. i .. "."
		if a[p .. "status"] and not _wire_bool(a[p .. "status"]) then return nil end
		local name = _wire_text(a[p .. "name"])
		local eap  = _wire_range(a[p .. "eap_method"], 1, 255)
		if not (name and eap) then return nil end
		-- The auth parameters are a THIRD level down, under
		-- aaa.<n>.hs20.nai_realm.<i>.eap_method.auth.<j>.{id,val}.
		local auth = _wire_indexed(idx, "nai_realm." .. i
			.. ".eap_method.auth", "id", function(j)
			local q = p .. "eap_method.auth." .. j .. "."
			local id  = _wire_range(a[q .. "id"], 1, 255)
			local val = _wire_range(a[q .. "val"], 0, 255)
			if not (id and val) then return nil end
			return {id = id, val = val}
		end)
		return {
			encoding = _wire_range(a[p .. "encoding"], 0, 1) or "0",
			name = name, eap_method = eap, auth = auth,
		}
	end)

	-- Note the index position: the key is hs20.<k>.roaming_consortium, not
	-- hs20.roaming_consortium.<k>.
	hs.roaming_consortium = _wire_indexed(idx, "", "roaming_consortium",
		function(i)
			local oi = a["hs20." .. i .. ".roaming_consortium"]
			-- An Organization Identifier is 3 to 15 octets of hex (hostapd
			-- rejects anything else outright).
			if type(oi) ~= "string" or not oi:match("^%x+$")
					or #oi % 2 ~= 0 or #oi < 6 or #oi > 30 then
				return nil
			end
			return oi
		end)

	hs.cell_net = _wire_indexed(idx, "3gpp", "mcc", function(i)
		local p = "hs20.3gpp." .. i .. "."
		local mcc, mnc = a[p .. "mcc"], a[p .. "mnc"]
		-- Kept as sent, not renormalised: a two-digit MNC is not a
		-- three-digit one with a leading zero.
		if type(mcc) ~= "string" or not mcc:match("^%d%d%d$") then return nil end
		if type(mnc) ~= "string" or not mnc:match("^%d%d%d?$") then return nil end
		return {mcc = mcc, mnc = mnc}
	end)

	hs.friendly_name = _wire_indexed(idx, "friendly_name", "text",
		function(i)
			local p = "hs20.friendly_name." .. i .. "."
			local lang = _wire_text(a[p .. "language"], 3)
			local text = _wire_text(a[p .. "text"])
			if not (lang and text) then return nil end
			return {lang = lang, text = text}
		end)

	hs.conn_capab = _wire_indexed(idx, "capab", "protocol", function(i)
		local p = "hs20.capab." .. i .. "."
		local proto = _wire_range(a[p .. "protocol"], 1, 255)
		local port  = _wire_range(a[p .. "port"], 0, 65535)
		-- hostapd wants a number: 0 closed, 1 open, 2 unknown.
		local STATUS = {closed = "0", open = "1", unknown = "2"}
		local status = STATUS[a[p .. "status"] or ""]
		if not (proto and port and status) then return nil end
		return {protocol = proto, port = port, status = status}
	end)

	if _wire_bool(a["hs20.metrics.status"]) then
		local m = {}
		local ok = true
		-- info is the WAN Info bitfield the controller has already assembled
		-- from link status + symmetric + at-capacity. The four rate/load
		-- fields are 0 when the admin left them unset, which is also
		-- hostapd's "unknown", so 0 is kept rather than dropped.
		for field, hi in pairs({info = 255, downlink_speed = 4294967295,
				uplink_speed = 4294967295, downlink_load = 255,
				uplink_load = 255, measurement = 65535}) do
			local v = _wire_range(a["hs20.metrics." .. field], 0, hi)
			if v then m[field] = v else ok = false end
		end
		if ok then hs.wan_metrics = m end
	end

	return hs
end

-- Tri-state read of a `status` key for the radio/VAP disable controls:
--   nil       -> the key was absent; leave whatever UCI already has alone
--   false     -> explicitly enabled
--   true      -> explicitly disabled
-- The absent case matters: a blob that never carries the key must not
-- re-enable a radio or SSID the user disabled by hand in /etc/config/wireless.
local function _wire_status_disabled(v)
	if v == nil then return nil end
	return v == "disabled"
end

function M._parse_wifi_system_cfg(sys_raw)
	local aaa, wireless, radio, stamgr, macacl = {}, {}, {}, {}, {}
	local global_countrycode = nil
	local qos_vap = {}
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		-- qos.vap.<m>: "WiFi Speed Limit". Needs its own pattern rather than
		-- the generic <section>.<idx>.<key> one below, since the index sits a
		-- level down (qos.vap.1.*, alongside qos.if.<n>.* and qos.ebt.<n>.*).
		local qidx, qkey, qv = line:match("^qos%.vap%.(%d+)%.([^=]+)=(.*)$")
		if qidx then
			qidx = tonumber(qidx)
			qos_vap[qidx] = qos_vap[qidx] or {}
			qos_vap[qidx][qkey] = qv
		end
		local section, idx, key, v = line:match("^(aaa)%.(%d+)%.([^=]+)=(.*)$")
		if not section then section, idx, key, v = line:match("^(wireless)%.(%d+)%.([^=]+)=(.*)$") end
		if not section then section, idx, key, v = line:match("^(radio)%.(%d+)%.([^=]+)=(.*)$") end
		-- stamgr.<n>: per-radio "Station Manager" block, indexed the same as
		-- radio.<n> -- confirmed live 2026-07-14 (Devices -> [AP] -> Radios ->
		-- "Minimum RSSI" checkbox+slider, NOT a WLAN-level setting): toggling
		-- it emits stamgr.<n>.radio (band, "ng"/"na"), stamgr.<n>.minrssi.status
		-- and stamgr.<n>.minrssi.rssi, alongside Load balance's
		-- stamgr.<n>.loadbalance.status/maxsta sharing the same block.
		-- The whole block is simply absent when disabled (no explicit
		-- status=false), same convention as every other optional section here.
		if not section then section, idx, key, v = line:match("^(stamgr)%.(%d+)%.([^=]+)=(.*)$") end
		-- macacl.<m>: the "MAC Address Filter". CONFIRMED live 2026-07-18 by
		-- enabling the control with one allow-listed MAC and diffing system_cfg
		-- -- this whole top-level section appeared at once, and it is keyed by
		-- devname (ath0/ath2), NOT by the wireless.<n> index: only the two ath
		-- devices belonging to the filtered WLAN got blocks, numbered 1 and 2
		-- while the WLAN is wireless.1/wireless.3. Hence the devname join below.
		--
		-- The obvious-looking wireless.<n>.mac_acl.status/.policy keys are NOT
		-- this feature: they sit at enabled/deny with the control off and did
		-- not move in the diff -- the same decoy shape as
		-- radio.<n>.bcmc_l2_filter.status was for the broadcast blocker.
		-- aaa.<n>.radius.macacl.status is the separate RADIUS MAC
		-- Authentication control, read in the vap build below.
		if not section then section, idx, key, v = line:match("^(macacl)%.(%d+)%.([^=]+)=(.*)$") end
		if section then
			local tbl = (section == "aaa" and aaa) or (section == "wireless" and wireless)
				or (section == "radio" and radio) or (section == "macacl" and macacl) or stamgr
			idx = tonumber(idx)
			tbl[idx] = tbl[idx] or {}
			tbl[idx][key] = v
		end
		-- The site's regulatory domain, as an ISO 3166-1 NUMERIC code. Sent
		-- both unindexed and per radio ("radio.countrycode=203",
		-- "radio.1.countrycode=203" for a Czechia site -- confirmed live on a
		-- real controller). The per-radio copy is captured by the indexed
		-- pattern above; this catches the unindexed one as a fallback, so a
		-- controller sending only the global still sets the regdomain.
		if not section then
			local cc = line:match("^radio%.countrycode=(%d+)$")
			if cc then global_countrycode = tonumber(cc) end
		end
	end

	local function sorted_indices(t)
		local keys = {}
		for k in pairs(t) do keys[#keys + 1] = k end
		table.sort(keys)
		return keys
	end

	local radio_table = {}
	for _, idx in ipairs(sorted_indices(radio)) do
		local r = radio[idx]
		if r.phyname then
			local entry = {
				name     = r.phyname,
				-- Regulatory domain, numeric on the wire -> UCI's alpha-2
				-- `country`. Nothing wrote this before, so a device kept
				-- whatever regdomain OpenWrt booted with (typically the
				-- unconfigured world domain) while REPORTING 840/US back --
				-- get_radio_table reads UCI `country` to derive country_code
				-- and falls back to US when it is unset. A site in Czechia
				-- therefore ran radios on US channel and power limits and saw
				-- "US" in the UI. An unmapped numeric leaves UCI alone rather
				-- than guessing a regdomain.
				country  = ISO3166_ALPHA[tonumber(r.countrycode) or global_countrycode or -1],
				-- "auto" passes through verbatim: UCI channel=auto is OpenWrt's
				-- ACS request (hostapd surveys the band at bring-up and picks
				-- the least-busy channel). Dropping it to nil instead would
				-- leave a previously pushed fixed channel in UCI, silently
				-- overriding the user's switch back to Auto. Absent/garbage
				-- still -> nil, leaving UCI alone.
				channel  = tonumber(r.channel) or (r.channel == "auto" and "auto" or nil),
				-- "auto" passes through as a sentinel like channel above, but
				-- lands differently: UCI has no auto txpower value (absent
				-- option = driver default/max), so rf_config DELETES the
				-- option for it. Dropping it to nil instead stranded the last
				-- fixed dBm in UCI, silently overriding the user's switch
				-- back to Auto. Absent/garbage still -> nil, leaving UCI alone.
				tx_power = tonumber(r.txpower) or (r.txpower == "auto" and "auto" or nil),
				-- nil for an absent/unrecognized token, leaving htmode alone.
				htmode   = _htmode_from_ieee_mode(r.ieee_mode),
				-- Per-radio disable (Devices -> [AP] -> Radios -> Transmit
				-- Power -> Disabled). CONFIRMED live 2026-07-19: that control
				-- moves radio.<n>.status enabled->disabled together with
				-- txpower_mode=disabled, virtual.1.status and every
				-- wireless.<n>.status on the radio.
				--
				-- Deliberately tri-state: nil when the key is ABSENT, so a
				-- capture that never carries it cannot re-enable a radio the
				-- user disabled by hand in /etc/config/wireless. Only an
				-- explicit enabled/disabled writes anything.
				--
				-- Reading r.status (indexed) and never the unindexed
				-- radio.status is what keeps the radio-less
				-- "# no wlan provisioned as no radio found" blob -- which
				-- carries radio.status=disabled with no phyname anywhere --
				-- from disabling every radio on the device.
				--
				-- NB: written as a statement below rather than inline, because
				-- `(x ~= nil) and (x == "disabled") or nil` silently collapses
				-- the enabled case to nil in Lua's and/or.
				disabled = _wire_status_disabled(r.status),
			}
			local sm = stamgr[idx]
			-- minrssi.rssi is NOT plain dBm -- confirmed live (UI "-80 dBm"
			-- wire-encoded as 15, "-85 dBm" as 10) and in the controller's
			-- generator: raw = max(dBm + 95, 1). Kept as raw wire units here;
			-- openuf/minrssi.lua converts.
			-- Explicit tri-state, never nil for a parsed radio: an absent
			-- stamgr block is the wire's disable convention (the whole block
			-- simply disappears when the checkbox is off), so it must produce
			-- an explicit `false` -> rf_config writes minrssi_enabled=0.
			-- Leaving it nil instead let a stale minrssi_enabled=1 from an
			-- earlier push survive in UCI -- and since build_json derives its
			-- enforcement thresholds from UCI (get_radio_table), openUF kept
			-- deauthing weak clients forever after the user turned the
			-- feature off. Writing the explicit off is safe here:
			-- minrssi_enabled/minrssi_rssi are openUF-invented options nothing
			-- else configures, and the radio-less "# no wlan provisioned" blob
			-- never reaches apply_config (gated on a nonempty radio_table).
			entry.min_rssi_enabled = (sm ~= nil and sm["minrssi.status"] == "true")
			if entry.min_rssi_enabled then
				entry.min_rssi = tonumber(sm["minrssi.rssi"])
			end
			-- Load balance (openuf/loadbalance.lua): the cap, or an explicit
			-- false when off, for the same reason as min_rssi_enabled. Like
			-- the firmware (stamgr -n 0 unless loadbalance.status is true),
			-- a missing or non-positive maxsta is off.
			local maxsta = sm ~= nil and sm["loadbalance.status"] == "true"
				and tonumber(sm["loadbalance.maxsta"])
			entry.loadbalance_maxsta = (maxsta and maxsta > 0) and math.floor(maxsta) or false
			-- Auto-channel narrowing, both keys emitted only to a device
			-- claiming wifi_caps2 0x10 (Device.supportsAcsDfs(), see
			-- build_json) and both from the site's Radio settings, not the
			-- WLAN's. Decompiled from 10.6.106
			-- (com/ubnt/service/config/ubntconf/PFljhxhmKJyhpeIhf) and
			-- cross-read against U7LR 6.8.2's own consumers:
			--
			--   radio.<n>.acsdfs=enabled|disabled -- 5 GHz radio only, from
			--     radios_configuration[radio=na].dfs. Firmware: with it off,
			--     wifitool block_acs_channel over the whole DFS list.
			--     openUF: wifi-device acs_exclude_dfs, hostapd's own flag.
			--   radio.<n>.blklst=2,3,4,...        -- only while the radio is
			--     on Auto, from the site's channels_blacklist for this band
			--     (the "conservative" preset blacklists everything but 1/6/11
			--     on 2.4 GHz, which is what a default site carries). Firmware:
			--     wifitool block_acs_channel <list>. hostapd has no blacklist,
			--     only chanlist, so ucihelper inverts it against the phy's own
			--     channel list.
			--
			-- Tri-state like the rest of this block: absent acsdfs leaves UCI
			-- alone (it never arrives for 2.4 GHz), and an absent blklst is
			-- the wire's "nothing excluded" -- which has to tear down a
			-- chanlist openUF wrote earlier, so it reaches rf_config as nil
			-- and is handled there against openUF's own stamp.
			if r.acsdfs == "enabled" or r.acsdfs == "disabled" then
				entry.acs_exclude_dfs = (r.acsdfs == "disabled")
			end
			if r.blklst then
				local blocked = {}
				for ch in tostring(r.blklst):gmatch("%d+") do
					blocked[#blocked + 1] = tonumber(ch)
				end
				if #blocked > 0 then entry.acs_blacklist = blocked end
			end
			radio_table[#radio_table + 1] = entry
		end
	end

	-- MAC Address Filter, keyed by the vap's wire devname (ath0/ath1/...).
	-- Wire shape, all confirmed live 2026-07-18:
	--   macacl.status=enabled            -- global gate
	--   macacl.<m>.devname=ath0          -- join key
	--   macacl.<m>.status=enabled
	--   macacl.<m>.acl.status=enabled
	--   macacl.<m>.acl.policy=allow      -- allow|deny (UI "Filter Type")
	--   macacl.<m>.acl.<k>.mac=02:11:22:33:44:55
	--   macacl.<m>.acl.<k>.status=enabled
	--   macacl.<m>.acl.<k>.type=user
	-- Like bcfilt, <k> is 1-based and carries no meaning beyond grouping, so
	-- the list is sorted for a stable, comparable result. Entries are taken
	-- only when both the block and the entry are enabled; type is "user" for
	-- hand-entered MACs (the only kind this UI produces).
	local mac_filter_by_dev = {}
	for _, e in pairs(macacl) do
		if e.devname and e.status == "enabled" and e["acl.status"] == "enabled" then
			local macs = {}
			for k, val in pairs(e) do
				local ki = k:match("^acl%.(%d+)%.mac$")
				if ki and e["acl." .. ki .. ".status"] == "enabled" then
					-- The list becomes a UCI maclist hostapd parses, where a
					-- malformed entry fails the whole BSS. The controller's UI
					-- cannot produce one, so dropping it -- loudly -- is the
					-- safe reading.
					if is_mac(val) then
						macs[#macs + 1] = val
					else
						io.stderr:write(("inform: macacl: ignoring malformed MAC %q\n")
							:format(tostring(val)))
					end
				end
			end
			table.sort(macs)
			mac_filter_by_dev[e.devname] = {
				policy = e["acl.policy"],
				macs   = macs,
			}
		end
	end

	-- "WiFi Speed Limit", keyed by the vap's wire devname -- same join as the
	-- MAC filter above. Wire shape, confirmed live 2026-07-18 by creating a
	-- speed-limit profile (33 Mbps down / 17 Mbps up) and assigning it to a
	-- WLAN:
	--   qos.status=enabled
	--   qos.vap.<m>.devname=ath0
	--   qos.vap.<m>.dwnlink.maxspeed=33000     -- kbps (UI Mbps x 1000)
	--   qos.vap.<m>.dwnlink.minspeed=33000
	--   qos.vap.<m>.uplink.1.maxspeed=17000    -- kbps
	--
	-- The discriminator is the presence of *maxspeed*, not qos.status (which
	-- is global) and not the block itself: an UNLIMITED vap still gets a
	-- qos.vap.<m> block, carrying only minspeed set to that radio's raw
	-- devspeed (570 on 2.4 GHz, 2400 on 5 GHz in the capture). Reading the
	-- block's existence as "limited" would cap every WLAN at its own PHY rate.
	--
	-- This is a per-VAP aggregate cap, not a per-client one: the limit applies
	-- to the whole netdev, which is what makes a single tc qdisc sufficient.
	--
	-- The accompanying qos.ebt.<n>.cmd entries are literal ebtables fragments
	-- the stock firmware would replay to fwmark each VAP. openUF implements
	-- the intent with tc instead (see shaper.lua) rather than replaying them.
	local ratelimit_by_dev = {}
	for _, q in pairs(qos_vap) do
		local down = tonumber(q["dwnlink.maxspeed"])
		local up   = tonumber(q["uplink.1.maxspeed"])
		if q.devname and (down or up) then
			ratelimit_by_dev[q.devname] = {down = down, up = up}
		end
	end

	-- Aggregate every aaa.<n>.wpa.key.<k>.mgmt entry (transition mode can
	-- list WPA-PSK and SAE either space-joined on one key or across separate
	-- keys).
	local function akm_of(a)
		local akm = ""
		for k, val in pairs(a) do
			if k:match("^wpa%.key%.%d+%.mgmt$") then akm = akm .. " " .. val end
		end
		return akm
	end

	-- Enhanced Open (OWE) transition mode arrives as a PAIR of VAPs per radio
	-- with the same SSID: an open one with no akm at all, and a hidden one with
	-- `wpa.key.1.mgmt=OWE`. Each names the other's devname in owe_devname.
	-- OpenWrt builds that pair from ONE wifi-iface (encryption=owe plus
	-- owe_transition=1), so the open half becomes the VAP and the hidden half
	-- is dropped here. Provisioning both as they stand is not an option: they
	-- share radio and SSID, so they would collapse into one UCI section, and
	-- the hidden one would win. Captured on 10.4.57 with radio_caps2 0xB
	-- (PROTOCOL-VALIDATION.md).
	local aaa_by_dev = {}
	for _, a in pairs(aaa) do
		if a.devname then aaa_by_dev[a.devname] = a end
	end
	local owe_hidden_half = {}
	for _, a in pairs(aaa) do
		local partner = a.owe_devname and aaa_by_dev[a.owe_devname]
		if partner and not akm_of(a):find("OWE", 1, true)
				and akm_of(partner):find("OWE", 1, true) then
			owe_hidden_half[a.owe_devname] = true
		end
	end

	local vap_table = {}
	for _, idx in ipairs(sorted_indices(wireless)) do
		local w = wireless[idx]
		local a = aaa[idx] or {}

		-- Hoisted out of the security branch below because the WPA-Enterprise
		-- check needs it before anything else is decided.
		local akm = akm_of(a)
		local owe_transition = a.owe_devname ~= nil and owe_hidden_half[a.owe_devname] == true

		-- WPA-Enterprise (802.1X, mgmt "WPA-EAP"). Provisioned since 2026-10-26
		-- from the aaa.<n>.radius.* block (see _wire_radius above). It is still
		-- skipped when that block names no usable authentication server: left to
		-- fall through, an Enterprise WLAN matches neither the SAE nor the PSK
		-- branch and lands on security="wpa2", producing a psk2 section with a
		-- nil key -- a VAP hostapd refuses to bring up, with nothing logged
		-- anywhere. A missing WLAN an admin can diagnose beats a broken one that
		-- looks provisioned.
		local is_enterprise = akm:find("EAP", 1, true) ~= nil
		-- RADIUS MAC authentication (the WLAN's own "MAC Authentication", a
		-- RADIUS lookup of the client's MAC before it may associate). On the
		-- wire for EVERY WLAN as radius.macacl.status, so the value is the
		-- whole discriminator; the writer has no capability gate on it
		-- (VAZShipWTNxlo:639, `if (radius_mac_auth_enabled)`), and it brings
		-- the same radius.auth.<k>.* block an Enterprise WLAN gets -- which is
		-- why the WLAN need not be Enterprise for _wire_radius to have work.
		local mac_auth = _wire_bool(a["radius.macacl.status"]) or false
		local radius, radius_err
		if is_enterprise or mac_auth then radius, radius_err = _wire_radius(a) end
		if is_enterprise and not radius and w.ssid then
			io.stderr:write(("inform: skipping WLAN %q -- WPA-Enterprise (%s): %s\n")
				:format(w.ssid, (akm:gsub("^%s+", "")), radius_err))
		end
		-- Warn-only. There is no capability bit to gate 802.1X on, so this must
		-- not change what gets provisioned: a basic wpad brings the BSS up and
		-- then authenticates nobody, logging nothing of its own.
		local no_radius_client = M._sysinfo and M._sysinfo.eap_supported
			and not M._sysinfo.eap_supported()
		if is_enterprise and radius and w.ssid and no_radius_client then
			io.stderr:write(("inform: WLAN %q is WPA-Enterprise, but this hostapd has "
				.. "no RADIUS client (a full wpad is needed) -- clients will not "
				.. "authenticate\n"):format(w.ssid))
		end
		-- MAC authentication fails CLOSED, unlike the warning above. It is an
		-- access control: provisioning the WLAN without it would let every
		-- client the admin meant to screen straight on, and on an open WLAN that
		-- is the only thing standing between the network and anyone in range.
		-- So the WLAN is dropped instead, loudly. (With no RADIUS client in
		-- hostapd the BSS would not come up anyway: auth_server_addr is an
		-- unknown option to a basic wpad, which refuses the whole config.)
		local mac_auth_broken = false
		if mac_auth and (not radius or no_radius_client) then
			mac_auth_broken = true
			if w.ssid then
				io.stderr:write(("inform: skipping WLAN %q -- it requires RADIUS MAC "
					.. "authentication, and %s\n"):format(w.ssid,
					radius and "this hostapd has no RADIUS client (a full wpad is "
						.. "needed)" or radius_err))
			end
		end

		-- Hotspot 2.0 / Passpoint. Only ever on an EAP WLAN: hostapd refuses
		-- a config with hs20=1 and anything but WPA2-Enterprise/CCMP ("HS 2.0:
		-- WPA2-Enterprise/CCMP configuration is required for Hotspot 2.0
		-- functionality", confirmed against hostapd v2.12-devel), and the
		-- controller offers Passpoint on a wpaeap/OSEN WLAN only. A block
		-- arriving on any other WLAN is dropped with a line rather than
		-- written out to produce a BSS hostapd will not start.
		local hs20
		if is_enterprise then
			hs20 = _wire_hs20(a)
		elseif _wire_bool(a["hs20.status"]) and w.ssid then
			io.stderr:write(("inform: WLAN %q carries Hotspot 2.0 but is not "
				.. "WPA-Enterprise -- ignoring the hs20 block\n"):format(w.ssid))
		end

		-- A UID IoT WLAN whose keys come from RADIUS only. Claiming
		-- wifi_caps 0x100000 (PPSK) lets it through too, with
		-- aaa.<n>.wpa.psk_radius = 0/1/2 (disabled/optional/required, the
		-- same values as hostapd's wpa_psk_radius; enum decompiled from
		-- 10.6.101, not seen on the wire). Still skipped, and not covered by
		-- the 802.1X support above: this is a *PSK* WLAN whose keys come from
		-- RADIUS (hostapd's wpa_psk_radius), a different feature from EAP, and
		-- the push names no server for it -- so "required" is a WLAN nobody
		-- could join. "optional" keeps working on its local keys.
		local radius_psk_only = a["wpa.psk_radius"] == "2"
		if radius_psk_only and w.ssid then
			io.stderr:write(("inform: skipping WLAN %q -- its keys come from RADIUS "
				.. "(wpa.psk_radius=2), and openUF has no RADIUS configuration on "
				.. "this wire protocol\n"):format(w.ssid))
		end

		-- WPA3 rides on its OWN keys, shared by the EAP and the PSK branch
		-- below: the akm set alone cannot tell transition from WPA3-only.
		local wpa3_support    = _wire_bool(a["wpa3.support"])
		local wpa3_transition = _wire_bool(a["wpa3.transition"])

		if w.ssid and w.parent and (not is_enterprise or radius) and not radius_psk_only
				and not mac_auth_broken
				and not (a.devname and owe_hidden_half[a.devname]) then
			local security = "open"
			-- Enhanced Open: the akm is the only marker. It carries no
			-- aaa.<n>.wpa and no psk. The pmf.* keys that do come along
			-- cannot reach hostapd: OpenWrt's ap.uc forces ieee80211w=2 on
			-- an OWE BSS and writes 0 on the open transition BSS.
			if is_enterprise then
				-- 802.1X. The encryption value each of these maps to is
				-- verified against the LIVE generator (25.12's
				-- /usr/share/ucode/wifi/, since /lib/netifd/wireless/mac80211.sh
				-- is itself a ucode script): iface.uc takes auth_type from the
				-- first `+` token of `encryption`, so wpa2+ccmp -> eap,
				-- wpa3 -> eap2, wpa3-mixed -> eap-eap2, wpa3-192 -> eap192.
				-- 192-bit is tested first: it implies wpa3.support.
				if _wire_bool(a["wpa3.enhanced_192"])
						or akm:find("SUITE-B-192", 1, true) then
					security = "wpa3-enterprise-192"
				elseif wpa3_support and wpa3_transition then
					security = "wpa2/wpa3-enterprise"
				elseif wpa3_support then
					security = "wpa3-enterprise"
				else
					security = "wpa2-enterprise"
				end
			elseif owe_transition or (a.wpa == nil and akm:find("OWE", 1, true)) then
				security = "owe"
			elseif a.wpa == "2" or a.wpa == "3" then
				local has_sae = akm:find("SAE", 1, true) ~= nil
				local has_psk = akm:find("PSK", 1, true) ~= nil
				-- WPA3 rides on its OWN keys, and the akm set alone cannot
				-- tell transition from WPA3-only: a WPA2/WPA3 transition WLAN
				-- sends `wpa.key.1.mgmt=SAE` *by itself* -- no WPA-PSK
				-- alongside it -- and marks the transition separately with
				-- `wpa3.transition=enabled`. Reading only the akm would
				-- therefore provision a transition WLAN as pure WPA3 and drop
				-- every WPA2-only client on the network (IoT devices above
				-- all). These two keys are authoritative where present.
				if wpa3_support and wpa3_transition then security = "wpa2/wpa3"
				elseif wpa3_support then security = "wpa3"
				elseif has_sae and has_psk then security = "wpa2/wpa3"
				elseif has_sae then security = "wpa3"
				elseif a.wpa == "3" then security = "wpa3"
				else security = "wpa2" end
			end
			-- VLAN-tagged SSIDs bridge onto a per-VLAN bridge device named
			-- "br0.<vlan>" (vs. plain "br0" for untagged) -- confirmed live:
			-- assigning a WiFi network to a VLAN-tagged network in the
			-- controller UI changes aaa.<n>.br.devname from "br0" to
			-- "br0.20" and adds companion vlan.*/bridge.*/netconf.* blocks
			-- declaring the VLAN subinterface and its bridge (which
			-- ucihelper.ensure_vlan_network() already creates on its own,
			-- so only the VLAN id itself needs extracting here).
			local vlan_id = tonumber((a["br.devname"] or ""):match("^br0%.(%d+)$"))

			-- "Multicast and Broadcast Blocker" (REST bc_filter_enabled /
			-- bc_filter_list). CONFIRMED live 2026-07-18 by REST-toggling it
			-- and diffing system_cfg -- the whole block appeared at once:
			--   wireless.<n>.bcfilt.status=enabled
			--   wireless.<n>.bcfilt.<k>.mac=01:00:5e:00:00:fb
			--   wireless.<n>.bcfilt.<k>.status=enabled
			-- on BOTH band entries of the WLAN. <k> is 1-based and does NOT
			-- follow the REST list's order (adding a second MAC renumbered the
			-- first), so the index carries no meaning beyond grouping and the
			-- list is sorted here for a stable, comparable result.
			--
			-- Two candidate keys that were already on the wire turned out NOT
			-- to be this feature -- radio.<n>.bcmc_l2_filter.status (sits at
			-- enabled with the control off) and wireless.<n>.multicast.inspect
			-- -- neither moved in the diff.
			--
			-- bcfilt.status is emitted whenever the control is on, including
			-- with an empty allow-list; the per-entry keys only appear once
			-- the list is non-empty.
			-- Tri-state on purpose: absent (nil) is not the same as
			-- "disabled" here -- see wpa3_fast_roaming_enabled below.
			local wpa3_ft
			if a["wpa3.ft.status"] ~= nil then
				wpa3_ft = (a["wpa3.ft.status"] == "enabled")
			end

			local bcfilt_macs
			for k, val in pairs(w) do
				local idx = k:match("^bcfilt%.(%d+)%.mac$")
				if idx and _wire_bool(w["bcfilt." .. idx .. ".status"]) then
					-- These go into an `nft add element` command line
					-- (bcfilter.lua), so only a real MAC may pass.
					if is_mac(val) then
						bcfilt_macs = bcfilt_macs or {}
						bcfilt_macs[#bcfilt_macs + 1] = val
					else
						io.stderr:write(("inform: bcfilt: ignoring malformed MAC %q\n")
							:format(tostring(val)))
					end
				end
			end
			if bcfilt_macs then table.sort(bcfilt_macs) end
			-- wireless.<n>.bcfilt.bypass_types: the frame types the blocker must
			-- let through. CONFIRMED live 2026-10-27 in the lab, as exactly
			-- "ARP|NSNA|DHCPV4|DHCPV6" -- the controller writes that string as a
			-- literal (10.6.106, com/ubnt/service/config/ubntconf/EYFcHmSpOqr),
			-- so those four tokens are the whole vocabulary it can send today.
			-- It is emitted only for a WLAN whose Multicast Suppression is
			-- "Aggressive" on a device claiming wifi_caps2 0x400000, which is why
			-- openUF never saw it before: without it the blocker drops ARP and
			-- DHCP too, and bcfilter.lua's header called that deliberate fidelity
			-- to Ubiquiti's older documentation. The controller now says the
			-- opposite in its own UI -- "Aggressive blocks all except DHCP and
			-- ARP" -- so the tokens are honoured.
			--
			-- Parsed as a set, upper-cased, with unknown tokens named and
			-- dropped rather than guessed at: each one has to become an nft
			-- match, so a token with no mapping cannot be silently "allowed".
			local bcfilt_bypass
			for raw in tostring(w["bcfilt.bypass_types"] or ""):gmatch("[^|]+") do
				-- A fresh local, not the loop variable: Lua 5.5 makes the
				-- generic-for control variable const and refuses the assignment
				-- outright, while 5.1 (the target) accepts it -- so the dev box
				-- is the strict one here for once.
				local tok = raw:gsub("^%s+", ""):gsub("%s+$", ""):upper()
				if tok ~= "" then
					if BCFILT_BYPASS_TYPES[tok] then
						bcfilt_bypass = bcfilt_bypass or {}
						bcfilt_bypass[tok] = true
					else
						io.stderr:write(("inform: bcfilt: ignoring unknown bypass type %q\n")
							:format(tok))
					end
				end
			end

			-- Private Pre-Shared Keys: several passphrases on one SSID, each
			-- landing its client on its own VLAN. Pushed only to a device
			-- claiming wifi_caps 0x100000 (see build_json). Captured on 10.4.57:
			--   aaa.<n>.dynamic_vlan=1
			--   aaa.<n>.wpa.psk_file.status=enabled
			--   aaa.<n>.wpa.psk_file.<k>.psk=<passphrase>
			--   aaa.<n>.wpa.psk_file.<k>.vlanid=<vid>
			-- vlanid is left out for a key on a VLAN-1 network: that client
			-- stays on the VAP's own network. aaa.<n>.wpa.psk still comes
			-- along, a random passphrase the controller generates for the
			-- WLAN, and is provisioned like any other key.
			-- `not is_enterprise`: an EAP BSS authenticates against RADIUS and
			-- must never carry local private keys (nor a passphrase, see
			-- x_passphrase below).
			local ppsk
			if _wire_bool(a["wpa.psk_file.status"]) and security ~= "open"
					and security ~= "owe" and not is_enterprise then
				local idxs = {}
				for k in pairs(a) do
					local i = k:match("^wpa%.psk_file%.(%d+)%.psk$")
					if i then idxs[#idxs + 1] = tonumber(i) end
				end
				table.sort(idxs)
				for _, i in ipairs(idxs) do
					local key = a["wpa.psk_file." .. i .. ".psk"]
					local vid_raw = a["wpa.psk_file." .. i .. ".vlanid"]
					local vid = tonumber(vid_raw)
					-- hostapd's own limits: a passphrase is 8..63 characters,
					-- or the PSK itself as 64 hex digits.
					local key_ok = (#key >= 8 and #key <= 63)
						or (#key == 64 and key:match("^%x+$") ~= nil)
					local vid_ok = vid_raw == nil
						or (vid ~= nil and vid == math.floor(vid) and vid >= 1 and vid <= 4094)
					if key_ok and vid_ok then
						ppsk = ppsk or {}
						ppsk[#ppsk + 1] = {key = key, vid = vid}
					else
						io.stderr:write(("inform: WLAN %q: skipping private pre-shared key %d "
							.. "(%s)\n"):format(w.ssid, i,
							key_ok and ("bad VLAN id " .. tostring(vid_raw))
								or "passphrase is not 8-63 characters or 64 hex digits"))
					end
				end
			end

			-- aaa.<n>.sae.psk.<k>.{psk,mac,vlan,id}: SAE passwords bound to a
			-- station (wlanconf sae_psk; 10.x emitter XWWFgnDBrNRLQZ). Entry
			-- ff:ff:ff:ff:ff:ff is the WLAN's own key, already the WLAN's
			-- passphrase. UniFi firmware writes the rest as sae_password=
			-- lines (6.8.2 ubntbox); OpenWrt's wifi-station writes the same
			-- key to the SAE and the PSK file, so they join the private keys.
			if security ~= "open" and security ~= "owe" and not is_enterprise then
				local idxs = {}
				for k in pairs(a) do
					local i = k:match("^sae%.psk%.(%d+)%.psk$")
					if i then idxs[#idxs + 1] = tonumber(i) end
				end
				table.sort(idxs)
				for _, i in ipairs(idxs) do
					local pre = "sae.psk." .. i .. "."
					local key = a[pre .. "psk"]
					local mac_raw = a[pre .. "mac"]
					local mac = mac_raw and mac_raw:lower()
					local vid_raw = a[pre .. "vlan"]
					local vid = tonumber(vid_raw)
					local key_ok = (#key >= 8 and #key <= 63)
						or (#key == 64 and key:match("^%x+$") ~= nil)
					local vid_ok = vid_raw == nil
						or (vid ~= nil and vid == math.floor(vid) and vid >= 1 and vid <= 4094)
					local mac_ok = mac == nil or is_mac(mac)
					if mac ~= "ff:ff:ff:ff:ff:ff" then
						if key_ok and vid_ok and mac_ok then
							local dup = false
							for _, e in ipairs(ppsk or {}) do
								if e.key == key and e.vid == vid and e.mac == mac then dup = true end
							end
							if not dup then
								ppsk = ppsk or {}
								ppsk[#ppsk + 1] = {key = key, vid = vid, mac = mac}
							end
						else
							io.stderr:write(("inform: WLAN %q: skipping SAE key %d (%s)\n")
								:format(w.ssid, i, not key_ok
									and "passphrase is not 8-63 characters or 64 hex digits"
									or (not vid_ok and "bad VLAN id " .. tostring(vid_raw)
										or "bad station MAC " .. tostring(mac_raw))))
						end
					end
				end
			end

			vap_table[#vap_table + 1] = {
				ssid                  = w.ssid,
				radio                 = w.parent,
				security              = security,
				owe_transition        = owe_transition or nil,
				-- aaa.<n>.id is the controller's wlanconf ObjectId; the
				-- controller only accepts a vap_table entry whose "id" echoes
				-- it back (vapInformProcessor drops usage=user vaps without
				-- one, taking the nested sta_table -- and thus every wireless
				-- client -- with them).
				wlanconf_id           = a.id,
				-- wireless.<n>.is_guest: the WLAN is a guest network
				-- (PROTOCOL-VALIDATION.md, "Guest portal (Hotspot)").
				-- Always present, "true"/"false". Read by _guest_wlans,
				-- not by UCI.
				is_guest              = _wire_bool(w.is_guest) or false,
				-- An EAP WLAN has no passphrase. The controller leaves
				-- aaa.<n>.wpa.psk absent on one, but forcing nil here keeps a
				-- stray key from ever reaching an EAP BSS.
				x_passphrase          = (not is_enterprise) and a["wpa.psk"] or nil,
				-- 802.1X / WPA-Enterprise: see _wire_radius above for the wire
				-- keys, what is deferred, and why. Also set on a non-EAP WLAN
				-- that has RADIUS MAC authentication on, which brings the same
				-- server block; nil when the WLAN has neither.
				radius                = radius,
				-- aaa.<n>.radius.macacl.status: the client's MAC is checked
				-- against RADIUS before it may associate (hostapd's
				-- macaddr_acl=2). Independent of the security type -- an
				-- Enterprise WLAN can carry it too -- and never true without a
				-- usable `radius` beside it, since the WLAN is dropped instead.
				mac_auth              = mac_auth or nil,
				-- aaa.<n>.accept_mac.*: MAC-based VLANs, the controller's
				-- per-client "Virtual Network Override". See _wire_mac_vlans
				-- for the wire shape and why `status` is not the discriminator.
				mac_vlans             = _wire_mac_vlans(a),
				-- Hotspot 2.0 / Passpoint: see _wire_hs20 above for the wire
				-- keys, what the controller cannot be made to send, and why.
				-- nil unless this WLAN has a Hotspot 2.0 profile attached.
				hs20                  = hs20,
				fast_roaming_enabled  = (a["ft.status"] == "enabled"),
				-- aaa.<n>.wpa3.ft.status: FT for the SAE akm specifically,
				-- a SEPARATE toggle from ft.status. Confirmed from the
				-- emitter (com.ubnt.service.config.ubntconf.OXMua, first
				-- key it writes): emitted unconditionally -- "enabled" or
				-- "disabled" -- whenever the WLAN goes out as SAE, from
				-- the wlanconf's isWpa3SaeFastRoamingEnabled(). nil when
				-- absent, which is every non-SAE push, so a plain WPA2
				-- WLAN is unaffected. See apply_wifi_config for why the
				-- two toggles are merged rather than honoured separately.
				wpa3_fast_roaming_enabled = wpa3_ft,
				-- aaa.<n>.iapp_key: the WLAN's 802.11r key-holder secret,
				-- the wlanconf's x_iapp_key -- 128 random bits the
				-- controller generates per WLAN and sends whenever
				-- iapp_enabled (default on), whatever ft.status says. UniFi
				-- firmware hands it to its patched hostapd as iapp_key=,
				-- which wraps every inter-AP FT frame with it (see
				-- PROTOCOL-VALIDATION.md, "802.11r key holders"). Only a
				-- well-formed key is carried; anything else is nil, and
				-- apply_config falls back to OpenWrt's own derivation.
				iapp_key              = type(a.iapp_key) == "string"
					and #a.iapp_key == 32 and a.iapp_key:match("^%x+$")
					and a.iapp_key:lower() or nil,
				-- aaa.<n>.wpa.group_rekey: GTK rekey interval in seconds, from
				-- the wlanconf's group_rekey (default 3600; 0 for WDS/element
				-- WLANs), sent only in the WPA branch (10.x generator
				-- eWivisHeQsnaqDtx). UniFi firmware writes it to hostapd as
				-- wpa_group_rekey= (firmware-confirmed for 4.0.15). 0 = off.
				group_rekey           = _wire_group_rekey(a["wpa.group_rekey"]),
				-- aaa.<n>.sae.{anti_clogging,sync,groups}: SAE tuning. The firmware
				-- writes them to hostapd as sae_anti_clogging_threshold=, sae_sync=
				-- and sae_groups= (firmware-confirmed for 6.8.2 ubntbox).
				sae_anti_clogging     = _wire_posint(a["sae.anti_clogging"]),
				sae_sync              = _wire_posint(a["sae.sync"]),
				sae_groups            = _wire_sae_groups(a),
				-- aaa.<n>.11k.status: the wlanconf's rrm_enabled (default
				-- false; REST-only, the 10.6 UI has no control), "enabled" or
				-- "disabled" on every WLAN (10.x generator eWivisHeQsnaqDtx).
				-- UniFi firmware runs `iwpriv <ath> rrm 0|1` with it
				-- (firmware-confirmed for 4.0.15). nil when absent.
				rrm                   = _wire_bool(a["11k.status"]),
				-- aaa.<n>.auth_cache: opportunistic key caching / PMKSA
				-- caching, from the wlanconf's `auth_cache` (REST-only, the
				-- 10.6 UI has no control), DEFAULT ENABLED. CONFIRMED live
				-- 2026-10-26 against 10.6.106 by diffing system_cfg across the
				-- field. Emitted only in the generator's WPA branch that also
				-- writes wpa.key.1.mgmt + wpa.psk (10.6 VAZShipWTNxlo), and
				-- only ever observed on a WPA-Enterprise WLAN -- a WPA2-PSK
				-- WLAN's aaa block carries no auth_cache at all, which is
				-- consistent with OKC being an 802.1X notion. Maps onto
				-- OpenWrt's `okc` wifi-iface option (schema-confirmed on
				-- 25.12; ap.uc's own default is on for sae/owe and for FT).
				-- nil when absent, so a PSK WLAN is left alone.
				okc                   = _wire_bool(a.auth_cache),
				-- aaa.<n>.tdls_prohibit: forbid direct station-to-station
				-- (TDLS) links, from the wlanconf's `tdls_prohibit` (REST-only),
				-- default disabled, on every aaa block. CONFIRMED live
				-- 2026-10-26 the same way. Maps 1:1 onto OpenWrt's
				-- `tdls_prohibit` wifi-iface option (schema-confirmed on 25.12).
				tdls_prohibit         = _wire_bool(a.tdls_prohibit),
				-- aaa.<n>.country_beacon: advertise the regulatory domain in
				-- beacons (the 802.11d Country information element), from the
				-- wlanconf's `country_beacon` (REST-only), default disabled,
				-- on every aaa block. CONFIRMED live 2026-10-26 the same way.
				-- OpenWrt's counterpart, `ieee80211d`, is a wifi-DEVICE
				-- option, so apply_config has to collapse the per-BSS wire key
				-- to one setting per radio -- see its aggregation.
				country_beacon        = _wire_bool(a.country_beacon),
				-- aaa.<n>.wpa.1.pairwise: the pairwise cipher the controller
				-- actually chose -- see _wire_pairwise for the enum, what
				-- reaches the wire and why CCMP comes back as nil.
				pairwise              = _wire_pairwise(a["wpa.1.pairwise"]),
				vlan_enabled          = vlan_id ~= nil,
				vlan                  = vlan_id,
				-- {key=, vid=} per private pre-shared key, in wire order;
				-- nil when the WLAN has none.
				ppsk                  = ppsk,
				-- aaa.<n>.bss_transition: CONFIRMED live 2026-07-15 (toggled
				-- "BSS Transition (802.11v)" in the Behavior Controls panel,
				-- diffed system_cfg via debug_dump_file) -- present on every
				-- aaa.<n> block for the WLAN, "enabled"/"disabled" string,
				-- flips independently of Fast Roaming/other toggles. Maps
				-- 1:1 onto hostapd/UCI's own current option name -- no
				-- translation needed, unlike the deprecated ieee80211v
				-- alias ucihelper used to (incorrectly) emit.
				bss_transition        = _wire_bool(a.bss_transition),
					-- aaa.<n>.pmf.status / pmf.mode: 802.11w Protected
					-- Management Frames. CONFIRMED live 2026-07-18 (Humans+IoT
					-- validation, diffed system_cfg via debug_dump_file): the
					-- controller always emits these on the aaa.<n> block --
					-- status="enabled"/"disabled", mode=0|1|2 (0=disabled,
					-- 1=optional, 2=required, mapping 1:1 onto hostapd's
					-- ieee80211w). For a "WPA2/WPA3" mixed WLAN on this madwifi
					-- model the WPA3-transition intent is carried entirely by
					-- these fields (wpa stays =2, wpa.key.1.mgmt stays WPA-PSK),
					-- so dropping them silently collapsed mixed-mode to plain
					-- WPA2 -- the reason this WLAN got no PMF at all before.
					-- pmf.cipher (AES-128-CMAC) is not carried through:
					-- hostapd's default BIP group-mgmt cipher already is
					-- AES-128-CMAC, so there is nothing to translate.
					pmf_status            = a["pmf.status"],
					pmf_mode              = tonumber(a["pmf.mode"]),
					-- wireless.<n>.mcast.enhance: "Multicast Enhancement" /
					-- "Multicast to Unicast" -- CONFIRMED live 2026-07-18
					-- (Humans+IoT validation): the controller sends =1 on the
					-- toggled WLAN's wireless.<n> entries and =0 elsewhere;
					-- openUF read wireless.<n> but never this key, so no
					-- multicast_to_unicast reached hostapd. (It rides the same
					-- wireless.<n> block as dtim_period/no2ghz_oui -- an earlier
					-- draft misread the "\nwireless.<n>." dump text as a
					-- separate "nwireless" section; the leading n is just the
					-- escaped newline before the wireless key.) 0|1 on the
					-- wire, so _wire_bool handles it directly.
					mcast_enhance         = _wire_bool(w["mcast.enhance"]),
				-- wireless.<n>.dtim_period: CONFIRMED live 2026-07-15 --
				-- always present as a plain integer regardless of the
				-- WLAN's Auto/Custom DTIM toggle (toggling "Auto 802.11
				-- DTIM Period" off and setting a custom 2.4/5GHz value only
				-- changed this same field's value; there is no separate
				-- dtim_mode/dtim_ng/dtim_na key on the wire at all -- an
				-- earlier version of this parser guessed such a scheme and
				-- was wrong). Maps 1:1 onto hostapd/UCI's own
				-- wifi-iface.dtim_period option.
				dtim_period           = tonumber(w.dtim_period),
				-- wireless.<n>.iot / wireless.<n>.qbssload: "Force WiFi 4
				-- Mode" (Settings -> WiFi -> [WLAN] -> IoT Optimization,
				-- REST field enhanced_iot). CONFIRMED live 2026-07-18 by
				-- diffing system_cfg across the toggle: both keys are
				-- absent entirely when it is off, and appear together as
				-- iot=enabled + qbssload=disabled on the WLAN's 2.4GHz
				-- wireless.<n> entry when it is on.
				--
				-- Most of what this feature *does* is encoded by the
				-- controller in keys openUF already applies -- the same
				-- diff showed the WLAN's 5GHz vap removed outright
				-- (wlan_bands forced to 2.4GHz-only), security pinned to
				-- WPA2, and bss_transition/proxy_arp/no2ghz_oui/PMF/
				-- advertise_ap_name all forced off. Notably the parent
				-- radio is NOT touched: radio.<n>.ieee_mode stayed at the
				-- site's configured width (verified by turning this on
				-- with the 2.4GHz radio at HT40 -- it stayed 11nght40), so
				-- this is a per-BSS flag only and must not be reflected
				-- back onto the shared radio.
				--
				-- That leaves qbssload as its one distinct on-air effect:
				-- suppress the QBSS Load information element in this
				-- BSS's beacons, which some legacy clients mis-parse.
				iot                   = _wire_bool(w.iot),
				qbssload              = _wire_bool(w.qbssload),
				-- wireless.<n>.uapsd: WMM power save (U-APSD), from the
				-- WLAN's uapsd_enabled, default false (10.x generator). Always
				-- on the wire. UniFi firmware passes it straight to the driver
				-- (`iwpriv <ath> uapsd 0|1`, firmware-confirmed for 4.0.15), so
				-- "disabled" turns U-APSD off; OpenWrt's own default is on.
				uapsd                 = _wire_bool(w.uapsd),
				-- wireless.<n>.no2ghz_oui: CONFIRMED live 2026-07-15 --
				-- this, not a per-device mgmt_cfg key, is Band Steering's
				-- real wire representation (toggled "Band Steering" in the
				-- Behavior Controls panel with nothing else changed; only
				-- this field flipped, and only on the WLAN's 2.4GHz/radio0
				-- wireless.<n> entry -- a madwifi/QCA driver convention:
				-- omitting the AP's OUI from 2.4GHz beacons/probe responses
				-- nudges dual-band-capable clients toward 5GHz). An
				-- earlier version of this parser guessed a per-device
				-- Device.BandsteeringMode-style mgmt_cfg field (per
				-- paultyng/go-unifi's REST model) that does not exist on
				-- this wire protocol at all -- see PROTOCOL-VALIDATION.md.
				no2ghz_oui            = _wire_bool(w.no2ghz_oui),
				-- wireless.<n>.advertise_ap_name: "Show Access Point Name
				-- in Beacon". CONFIRMED via decompiling the controller's
				-- WLAN-config-generator method directly (not a live diff
				-- -- a live capture showed zero effect from this toggle
				-- until the wifi_caps2 capability bit above was added,
				-- since the controller only emits this key at all when
				-- Device.supportAdvertisingDeviceNameInBeacon() is true;
				-- see that field's comment in build_json for the full
				-- derivation). "enabled"/"disabled" string, same
				-- convention as bss_transition/no2ghz_oui.
				advertise_ap_name     = _wire_bool(w.advertise_ap_name),
				-- wireless.<n>.btm_disassoc.status/.threshold: the WLAN's
				-- "Roaming Assistant". Decompiled from controller 10.6.101
				-- (com.ubnt.service.config.ubntconf, the class holding the
				-- -75/-88 constants): emitted only for 5GHz/6GHz vaps, only
				-- when wifi_caps2 bit 0x20 (supportsAssistedRoaming) is
				-- claimed, and only while the per-band toggle is on --
				-- status=enabled plus threshold=<dBm>, default -75 (na) /
				-- -88 (6e). Absent means off; there is no status=disabled.
				-- Enforced by openuf/roamassist.lua, not by UCI.
				roam_assist_enabled   = _wire_bool(w["btm_disassoc.status"]) or false,
				roam_assist_rssi      = tonumber(w["btm_disassoc.threshold"]),
				-- aaa.<n>.sae.anti_clogging / aaa.<n>.sae.sync: "SAE
				-- Anti-clogging"/"SAE Sync Time" (WPA3-SAE tuning).
				-- CONFIRMED via decompiling the controller's WLAN-config-
				-- generator (a small SAE-specific helper class): both are
				-- plain integers, only emitted when > 0 (the controller's
				-- own admin-side default is 5 for each), and -- unlike
				-- every other field on this vap -- gated on the WLAN
				-- actually being in real WPA3/SAE mode (Wlan.isWpa3() --
				-- an admin-facing "wpa3_support" flag, NOT the same thing
				-- as the "WPA2/WPA3" mixed Security Protocol dropdown
				-- option -- or a 6GHz radio, not a device capability like
				-- advertise_ap_name above). Live-tested: a WPA2/WPA3
				-- mixed-mode WLAN never emits either key even with a
				-- non-default admin value saved server-side, confirming
				-- the gate. Could not live-confirm the emitting (pure
				-- WPA3) case end-to-end -- switching this validation
				-- environment's test WLAN to pure WPA3 tripped an
				-- unrelated, already-documented config-sync flakiness
				-- (see PROTOCOL-VALIDATION.md) where the controller
				-- stopped pushing the WLAN's aaa./wireless. blocks
				-- entirely, even across an inform.lua restart. High
				-- confidence from the decompiled method body alone
				-- (a simple getInt(key, -1) > 0 check, no ambiguity).
					-- aaa.<n>.proxy_arp: "Proxy ARP". CONFIRMED live
					-- 2026-07-18 by REST-toggling wlanconf.proxy_arp and
					-- diffing system_cfg -- exactly aaa.<n>.proxy_arp flipped
					-- disabled->enabled, on both the 2.4GHz and 5GHz entries
					-- of the WLAN and nothing else. Always present on every
					-- aaa.<n> block (like bss_transition), never absent, so
					-- the "disabled" case is explicit rather than implied.
					-- Maps 1:1 onto hostapd/OpenWrt's own proxy_arp option.
					proxy_arp             = _wire_bool(a.proxy_arp),
					-- wireless.<n>.l2_isolation: "Client Isolation" (blocks
					-- station-to-station traffic within the BSS). CONFIRMED
					-- live 2026-07-18 in the same diff as proxy_arp above --
					-- flipped disabled->enabled on both band entries, nothing
					-- else moved. Always present. Maps onto OpenWrt's
					-- "isolate" (hostapd ap_isolate).
					l2_isolation          = _wire_bool(w.l2_isolation),
					-- wireless.<n>.hide_ssid: "Hide WiFi Name" -- suppress the
					-- SSID from beacons. CONFIRMED live 2026-07-18 by toggling
					-- the control in the UI and diffing system_cfg: exactly
					-- aaa.<n>.hide_ssid and wireless.<n>.hide_ssid flipped
					-- false->true, on both band entries of the WLAN, nothing
					-- else moved. The two keys are redundant duplicates; the
					-- wireless.<n> one is read here to keep this next to the
					-- other wireless.<n> booleans.
					--
					-- Note the value vocabulary is "true"/"false" here, not the
					-- "enabled"/"disabled" most of these keys use -- _wire_bool
					-- accepts both. Always present, so "off" is explicit and
					-- must be written back out as such. Maps onto OpenWrt's
					-- wifi-iface "hidden" (hostapd ignore_broadcast_ssid).
					hide_ssid             = _wire_bool(w.hide_ssid),
					-- "MAC Address Filter", joined from the top-level macacl
					-- section on wireless.<n>.devname (see mac_filter_by_dev
					-- above for the wire shape and why the join is needed).
					-- Both are nil when the control is off for this vap, which
					-- the consumer turns into macfilter=disable.
					mac_filter_policy     = (mac_filter_by_dev[w.devname] or {}).policy,
					mac_filter_list       = (mac_filter_by_dev[w.devname] or {}).macs,
					-- "WiFi Speed Limit", in kbps, nil when unlimited.
					ratelimit_down_kbps   = (ratelimit_by_dev[w.devname] or {}).down,
					ratelimit_up_kbps     = (ratelimit_by_dev[w.devname] or {}).up,
					-- "Minimum Data Rate Control" (Settings -> WiFi -> [WLAN]).
					-- CONFIRMED live 2026-07-18 by REST-setting
					-- minrate_setting_preference=manual + minrate_ng_enabled +
					-- minrate_ng_data_rate_kbps=12000 and diffing system_cfg:
					--   minrate_data     1000 -> 12000   (kbps -- 12 Mbps)
					--   beacon_rate      1000 -> 12000
					--   mgmt_rate        1000 -> 12000
					--   minrate_cck_rates.status  true -> false
					--   pureg            0    -> 1
					-- i.e. beacon_rate/mgmt_rate simply mirror minrate_data, and
					-- the CCK/pureg pair are derived consequences (12 Mbps is an
					-- OFDM rate, so every CCK rate falls below the floor and
					-- 802.11b clients are excluded outright).
					--
					-- Per-band, and NOT band-gated: the 5 GHz entries carried
					-- none of these keys at first only because that band's
					-- minrate was disabled. Enabling minrate_na (24 Mbps) made
					-- minrate_data/beacon_rate/mgmt_rate appear on the radio1
					-- entries too, with no cck/pureg keys (2.4 GHz-only
					-- concepts). So the controller has already done the band
					-- math and this side needs no band awareness.
					--
					-- Nothing is emitted at all when that band's Minimum Data
					-- Rate is off, so absent -> nil -> leave the radio alone.
					minrate_data          = tonumber(w.minrate_data),
					minrate_cck           = _wire_bool(w["minrate_cck_rates.status"]),
					beacon_rate           = tonumber(w.beacon_rate),
					-- wireless.<n>.minrate_below_disable: the "advertising
					-- rates" sub-toggle (REST minrate_<band>_advertising_rates).
					-- CONFIRMED live in its own diff -- turning it on added
					-- exactly this key (=true) to both band entries and changed
					-- nothing else. Distinguishes "make the floor a basic rate"
					-- (association still requires it) from "also stop
					-- advertising every rate below the floor".
					minrate_below_disable = _wire_bool(w.minrate_below_disable),
					-- See the bcfilt derivation above the vap literal.
					bcfilt_enabled        = _wire_bool(w["bcfilt.status"]),
					bcfilt_macs           = bcfilt_macs,
					bcfilt_bypass         = bcfilt_bypass,
					-- wireless.<n>.multicast.suppressor: "Multicast Suppression"
					-- (Settings -> WiFi -> [WLAN] -> Advanced). CONFIRMED live
					-- 2026-10-27 in the lab, on both band entries of the WLAN, once
					-- wifi_caps2 0x400000 is claimed.
					--
					-- The control has three positions and the wire carries no mode
					-- string, so the mode is read off the PAIR of keys. 10.6.106's
					-- own writer settles it: bcfilt.status (plus bypass_types) is
					-- emitted when the mode is Aggressive, and this key is emitted
					-- for Aggressive and Conservative alike, so
					--   suppressor + bcfilt  -> Aggressive: block all group frames
					--                           except the four bypass types and the
					--                           allow-listed senders (bcfilter.lua)
					--   suppressor, no bcfilt -> Conservative: "prevents storms"
					--   bcfilt, no suppressor -> an older controller, or the blocker
					--                           turned on with the mode left Off:
					--                           today's behaviour, unchanged
					-- The controller's own description of the two modes is "Limits
					-- multicast and broadcast traffic to reduce WiFi airtime usage.
					-- Conservative prevents storms; Aggressive blocks all except DHCP
					-- and ARP" (10.6.106 en locale,
					-- SETTINGS_WIFI_FORM_ADVANCED_MULTICAST_SUPPRESSION_DESC).
					mcast_suppressor      = _wire_bool(w["multicast.suppressor"]),
					-- Per-VAP disable. Moves with the parent radio's
					-- radio.<n>.status (disabling a radio disables every VAP
					-- on it), but is an independent key -- confirmed live
					-- 2026-07-19. The VAP is still provisioned when disabled,
					-- just with disabled=1, so its config survives a re-enable.
					disabled              = _wire_status_disabled(w.status),
					-- wireless.<n>.schedule_enabled + schedule_<day>[.<i>]:
					-- the "WiFi Blackout Schedule", as the firmware's
					-- schedule lines (wlansched.lua). false: no schedule.
					schedule_lines        = wlansched.lines(w) or false,
			}
		end
	end

	return radio_table, vap_table
end

-- Parse the device-level `bandsteering.*` block: the AP's own Band Steering
-- setting (Devices -> [AP] -> Band Steering: Off / Prefer 5G / Balance),
-- REST field device.bandsteering_mode. The controller emits it only for a
-- device claiming wifi_caps 0x4 (see build_json). Captured live 2026-09-27:
--
--   bandsteering.status=enabled
--   bandsteering.mode=prefer_5g          -- or "equal" (Balance)
--   bandsteering.1.status=enabled        -- one pair per WLAN whose 2.4 and
--   bandsteering.1.vap.1.devname=ath1    -- 5 GHz vaps share name, security
--   bandsteering.1.vap.2.devname=ath3    -- and passphrase (needs 0x8)
--
-- Off is bandsteering.status=disabled with no mode. So is "no WLAN can be
-- paired", and so is the site's advanced features switch being off, so
-- "disabled" means only "no device-level steering", never "turn the per-WLAN
-- toggle (no2ghz_oui) off". The pairs are not read: usteer steers a client
-- only toward a same-SSID 5 GHz interface, which is the pairing already.
--
-- Returns nil when the blob has no bandsteering.status line, else
-- {enabled = bool, mode = string|nil}.
function M._parse_bandsteering_system_cfg(sys_raw)
	local status = sys_raw:match("\nbandsteering%.status=([%w_]+)")
		or sys_raw:match("^bandsteering%.status=([%w_]+)")
	if not status then return nil end
	return {
		enabled = status == "enabled",
		mode    = sys_raw:match("\nbandsteering%.mode=([%w_]+)")
			or sys_raw:match("^bandsteering%.mode=([%w_]+)"),
	}
end

-- Whether usteer should band-steer and whether Roaming Assistant needs it,
-- from the parsed vaps and the raw system_cfg (for the device-level block).
function M._steering_flags(vap_table, sys_raw)
	-- Band Steering (wireless.<n>.no2ghz_oui) is confirmed
	-- live to be a per-WLAN wire field, not a per-device
	-- one -- but usteer (the daemon that actually
	-- implements steering on OpenWrt) is a single
	-- device-wide config, so band steering is treated as
	-- active for the whole device whenever ANY WLAN has it
	-- enabled.
	--
	-- Roaming Assistant (wireless.<n>.btm_disassoc) is
	-- decided per WLAN by openuf/roamassist.lua, but it reads
	-- usteer's cross-AP view and sends 802.11v requests, so
	-- it needs the daemon and 802.11k/v the same way.
	local steering_active, roam_assist_active = false, false
	for _, vap in ipairs(vap_table) do
		if vap.no2ghz_oui then steering_active = true end
		if vap.roam_assist_enabled then roam_assist_active = true end
	end
	-- The device-level setting adds to the per-WLAN one.
	-- "equal" (Balance) has no usteer equivalent: usteer
	-- balances client counts only by rejecting association
	-- requests (assoc_steering), which would also move
	-- clients between APs; probe_steering is compiled in
	-- but not configurable. It is reported, not faked.
	local bs = M._parse_bandsteering_system_cfg(sys_raw)
	if bs and bs.enabled then
		if bs.mode == "prefer_5g" then
			steering_active = true
		elseif not M._warned_bandsteering_mode then
			M._warned_bandsteering_mode = true
			io.stderr:write(("inform: device Band Steering mode %q "
				.. "is not supported, only prefer_5g; per-WLAN "
				.. "Band Steering still applies\n"):format(tostring(bs.mode)))
		end
	end
	return steering_active, roam_assist_active
end

-- Parse the `switch.*` block: per-port VLAN assignment.
--
-- Wire shape, fully mapped live 2026-07-19 by diffing system_cfg across five
-- states (see PROTOCOL-VALIDATION.md's `switch.*` section):
--
--   switch.status=enabled              -- gate, "disabled" until the DEVICE-level
--   switch.vlan.status=enabled         -- "Port VLAN" checkbox is ticked
--   switch.vlan.1.id=1                 -- <m> is a slot number, .id is the VLAN
--   switch.vlan.1.mode=untagged        -- the VLAN's device-wide default
--   switch.vlan.1.status=enabled
--   switch.vlan.2.id=20
--   switch.vlan.2.mode=tagged
--   switch.port.2.pvid=20              -- the port's untagged/native VLAN
--   switch.vlan.1.port.2.mode=tagged   -- the authoritative membership matrix:
--   switch.vlan.2.port.2.mode=untagged -- untagged | tagged | exclude
--
-- Both gates sit at "disabled" in the baseline, so -- unlike
-- wireless.<n>.mac_acl.* or radio.<n>.bcmc_l2_filter.status -- they are real
-- discriminators rather than decoys. Presence of the block is NOT the signal:
-- switch.port.<n>.name/.opmode are always emitted, one per the controller's
-- model-registry port count, and are inventory rather than control.
--
-- switch.port.<n> joins directly to port_table[].port_idx -- no devname
-- indirection, unlike macacl.*/qos.vap.*.
--
-- Returns nil when the blob carries no switch.* line at all (distinct from a
-- block that is present but gated off).
function M._parse_switch_system_cfg(sys_raw)
	local seen = false
	local gate_switch, gate_vlan
	local slots, ports = {}, {}   -- slots keyed by wire slot <m>, ports by port_idx

	local function port(n)
		n = tonumber(n)
		ports[n] = ports[n] or {vlans = {}}
		return ports[n]
	end
	local function slot(m)
		m = tonumber(m)
		slots[m] = slots[m] or {members = {}}
		return slots[m]
	end

	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		if line:match("^switch%.") then
			seen = true
			-- The membership matrix must be tried BEFORE the generic
			-- switch.vlan.<m>.<key> pattern, which would otherwise swallow it
			-- with key="port.2.mode" -- the same ordering care qos.vap.<m>
			-- needs against qos.if/qos.ebt.
			local m, n, mode = line:match("^switch%.vlan%.(%d+)%.port%.(%d+)%.mode=(.*)$")
			if m then
				slot(m).members[tonumber(n)] = mode
			else
				local sm, skey, sval = line:match("^switch%.vlan%.(%d+)%.([^=]+)=(.*)$")
				if sm then
					slot(sm)[skey] = sval
				else
					local pn, pkey, pval = line:match("^switch%.port%.(%d+)%.([^=]+)=(.*)$")
					if pn then
						port(pn)[pkey] = pval
					elseif line:match("^switch%.vlan%.status=") then
						gate_vlan = line:match("=(.*)$")
					elseif line:match("^switch%.status=") then
						gate_switch = line:match("=(.*)$")
					end
				end
			end
		end
	end

	if not seen then return nil end

	-- Resolve slot numbers to real VLAN ids, and fold the membership matrix
	-- onto the ports it belongs to.
	local vlans = {}
	for _, s in pairs(slots) do
		local id = tonumber(s.id)
		if id then
			vlans[id] = {mode = s.mode, enabled = s.status == "enabled"}
			for pidx, mode in pairs(s.members) do
				port(pidx).vlans[id] = mode
			end
		end
	end

	local out = {
		enabled = (gate_switch == "enabled") and (gate_vlan == "enabled"),
		vlans   = vlans,
		ports   = {},
	}
	-- Keep only ports carrying an actual override. The name/opmode-only
	-- entries are inventory for every registry port and mean nothing.
	for idx, p in pairs(ports) do
		if p.pvid or next(p.vlans) then
			out.ports[idx] = {pvid = tonumber(p.pvid), vlans = p.vlans}
		end
	end
	return out
end

-- The IP Settings / DNS / hostname half of a system_cfg: the keys
-- handle_response acts on outside the wifi, switch and sysconf passes.
--
-- Pure on purpose. It was inline in handle_response until 2026-10-26, which
-- left the device-level keys as the one part of a push with no replayable
-- parser -- neither a unit test nor tools/cfg-coverage.lua could reach them
-- without running the whole response handler and its side effects.
-- The malformed-address refusal stays in handle_response: it writes to stderr
-- and feature-detects netconfig, neither of which belongs in a parser.
--
-- Returns a table, always: {ip, netmask, gateway, dhcp, device_name, dns}.
function M._parse_net_system_cfg(sys_raw)
	if type(sys_raw) ~= "string" then return {dhcp = false, dns = {}} end
	local ip, netmask, gateway, device_name
	local dhcp = false
	-- DNS servers, keyed by their wire index so the controller's ordering
	-- (primary/secondary) survives -- resolv.conf's order is the resolver's
	-- preference order, so it is load-bearing. Same index-keyed-then-sorted
	-- treatment as macacl's acl.<k> list.
	local dns_by_idx = {}
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		local k, v = line:match("^([^=]+)=(.*)$")
		if k and v then
			local dns_idx = k:match("^resolv%.nameserver%.(%d+)%.ip$")
			if dns_idx then
				if v ~= "" then dns_by_idx[tonumber(dns_idx)] = v end
			elseif k == "netconf.1.ip" then ip = v
			elseif k == "netconf.1.netmask" then netmask = v
			elseif k == "route.1.gateway" then gateway = v
			elseif k == "dhcpc.1.status" then
				-- Only an enabled-ish value means DHCP. The key's presence
				-- alone used to set dhcp=true, so a hypothetical
				-- dhcpc.1.status=disabled alongside a netconf.1.ip would have
				-- misread a static push as DHCP and flushed the working static
				-- address. Every capture so far carries =enabled; this is
				-- defensive for the static-mode shape that hasn't been
				-- captured yet.
				dhcp = _wire_bool(v) == true
			elseif k == "resolv.host.1.name" then
				-- The controller's own idea of this device's name (its local
				-- network hostname) -- already present in every capture (e.g.
				-- "U6IW" when never renamed). Reused as the WPS Device Name
				-- value when advertise_ap_name is on, since it's the only
				-- controller-assigned "AP name" string available on this wire
				-- protocol.
				if v ~= "" then device_name = v end
			end
		end
	end
	-- Flatten the index-keyed DNS table into controller order.
	local dns, idxs = {}, {}
	for i in pairs(dns_by_idx) do idxs[#idxs + 1] = i end
	table.sort(idxs)
	for _, i in ipairs(idxs) do dns[#dns + 1] = dns_by_idx[i] end
	return {ip = ip, netmask = netmask, gateway = gateway,
		dhcp = dhcp, device_name = device_name, dns = dns}
end

-- ─── Dropped-key visibility ──────────────────────────────────────────────────

-- Key shapes some pass in openUF actually reads. Everything else in a config
-- blob is dropped on the floor.
--
-- Until 2026-07-18 that included macacl.* and qos.vap.* -- two whole features
-- sitting in every capture, unnoticed for months, because no tokenizer here
-- has an `else` branch and nothing ever counted what fell through. This list
-- plus _report_dropped_keys() is the missing feedback loop.
--
-- The keys openUF drops ON PURPOSE (switch.*, qos.if.*, qos.ebt.*, vlan.*,
-- bridge.*, mcastrate, cwm.mode, pmf.cipher, mac_acl.* and the other decoys)
-- are deliberately NOT listed here: they show up in the report, which is the
-- honest picture of what is ignored. Each one's reasoning is in
-- PROTOCOL-VALIDATION.md's `system_cfg` section.
local RECOGNIZED_SYSTEM_CFG = {
	"^aaa%.%d+%.",       -- per-SSID security
	"^wireless%.%d+%.",  -- per-SSID radio binding and behavior
	"^radio%.%d+%.",     -- per-radio config
	"^stamgr%.%d+%.",    -- Minimum RSSI
	"^macacl%.%d+%.",    -- MAC Address Filter
	-- Device-level Band Steering. The per-WLAN pairs (bandsteering.<n>.*)
	-- are not read, so they stay in the report.
	"^bandsteering%.status$",
	"^bandsteering%.mode$",
	"^qos%.vap%.%d+%.",  -- WiFi Speed Limit
	"^netconf%.1%.",     -- IP Settings
	"^route%.1%.gateway$",
	"^dhcpc%.1%.",
	"^resolv%.nameserver%.%d+%.ip$",
	"^resolv%.host%.1%.name$",
	-- Per-port VLAN. Deliberately narrow: switch.dot1x.status and
	-- switch.jumboframes are in every capture and openUF implements neither,
	-- so they stay in the dropped-key report rather than being whitelisted
	-- along with the block they share a prefix with.
	"^switch%.status$",
	"^switch%.vlan%.status$",
	"^switch%.vlan%.%d+%.",
	"^switch%.port%.%d+%.",
	-- Controller-managed system settings (sysconf.lua). cron.<n>.user is
	-- deliberately NOT here: the pushed account does not exist and the jobs
	-- run as root, so the key stays in the report as ignored.
	"^system%.timezone$",
	"^locale%.timezone$",
	"^ntpclient%.status$",
	"^ntpclient%.%d+%.",
	"^cron%.status$",
	"^cron%.%d+%.status$",
	"^cron%.%d+%.job%.%d+%.",
	-- The ebtables hardening block (l2guard.lua). ebtables.add_vlan.status
	-- is not read and stays in the report.
	"^ebtables%.status$",
	"^ebtables%.%d+%.cmd$",
	-- Guest portal on/off (M._guest_wlans) and where it is (guestportal.lua).
	"^redirector%.status$",
	"^redirector%.url$",
	-- The walled garden's domain half (guestportal.parse). dnsmasq.status and
	-- dnsmasq.<n>.* are not here: those ask for a local DNS answerer openUF
	-- does not run, so they stay in the report.
	"^dnsmasq%.walled_garden%.%d+%.status$",
	"^dnsmasq%.walled_garden%.%d+%.site%.%d+%.",
}

local RECOGNIZED_MGMT_CFG = {
	"^inform_url$", "^use_aes_gcm$", "^cfgversion$", "^led_enabled$", "^authkey$",
	"^capability$", "^selfrun_guest_mode$", "^stun_url$",
}

-- Exported for tools/cfg-coverage.lua, which cross-checks these CLAIMS against
-- what a replay proves the parsers actually use. The lists are prefix-coarse by
-- design (`^aaa%.%d+%.` covers keys openUF drops, such as auth_cache), so a key
-- being "recognized" here is not evidence that anything reads it.
M.RECOGNIZED_SYSTEM_CFG = RECOGNIZED_SYSTEM_CFG
M.RECOGNIZED_MGMT_CFG   = RECOGNIZED_MGMT_CFG

-- Set from handle_response when cfg.config.debug_dump_file is on -- the
-- dropped-key report is a diagnostic for exactly the same workflow (diffing
-- full captures against what openUF acts on), so it shares that gate rather
-- than adding a second knob.
M._debug_dropped_keys = false

-- Ceiling for that dump. It is append-only and the inform loop writes to it
-- every few seconds, so left on it grows without bound -- and its usual home
-- is /tmp, which on these boards is a RAM disk. Measured on an Archer C5 after
-- five weeks: 31.7 MB, 55% of a 59 MB tmpfs, on course to starve state.json
-- writes and apk alike. Past the cap the file RESTARTS rather than rotating:
-- keeping a second generation would double the peak footprint on exactly the
-- boards least able to afford it, and a capture is read from its tail anyway.
-- Override per device with config.debug_dump_max_bytes; 0 disables the cap.
M.DEBUG_DUMP_MAX_BYTES = 4 * 1024 * 1024

-- Summarize the keys in a config blob that no pass recognized.
--
-- Emits key PREFIXES and counts only, never values: these blobs carry
-- aaa.<n>.wpa.psk and mgmt_cfg's authkey, and this goes to the log.
-- Numeric indices are collapsed to <n> so a four-VAP blob reports one line
-- per key shape rather than one per instance.
function M._report_dropped_keys(label, raw, recognized)
	if not M._debug_dropped_keys or type(raw) ~= "string" then return end
	local counts, order, total = {}, {}, 0
	for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
		-- Skip blanks and the literal comment a radio-less blob carries
		-- ("# no wlan provisioned as no radio found").
		if line ~= "" and not line:match("^%s*#") then
			local k = line:match("^([^=]+)=")
			if k then
				local known = false
				for _, pat in ipairs(recognized) do
					if k:match(pat) then known = true break end
				end
				if not known then
					local prefix = k:gsub("%.%d+%.", ".<n>."):gsub("%.%d+$", ".<n>")
					if not counts[prefix] then
						counts[prefix] = 0
						order[#order + 1] = prefix
					end
					counts[prefix] = counts[prefix] + 1
					total = total + 1
				end
			end
		end
	end
	if total == 0 then return end
	table.sort(order)
	local parts = {}
	for _, p in ipairs(order) do parts[#parts + 1] = p .. " x" .. counts[p] end
	io.stderr:write(("inform: %s: %d dropped key(s): %s\n")
		:format(label, total, table.concat(parts, ", ")))
end

-- The Airtime Scan sweep (see the spectrum-scan cmd): per radio, sweep every
-- channel, then read back per-channel survey data into a spectrum_table,
-- cached for build_json. Run by _tick after the inform that reported
-- spectrum_scanning = true.
M._spectrum_pending = false
function M._run_spectrum_scan()
	local ufuci = M._ucihelper
	if ufuci and ufuci.get_radio_table then
		local ok_r, radios = pcall(ufuci.get_radio_table)
		if ok_r then
			local now = os.time()
			for _, radio in ipairs(radios) do
				local ok_if, ifname = pcall(ufuci.get_ifname_for_radio, radio.name)
				if ok_if and ifname then
					-- Survey counters are cumulative and exist
					-- independently of the sweep, so sample them BEFORE
					-- it as well: immediately after a scan the radio has
					-- just come back from off-channel and the OPERATING
					-- channel's noise reads as 0 -- confirmed on real
					-- hardware, where the same channel reports 0 right
					-- after the sweep and -106 dBm moments later. 0 dBm
					-- is not a plausible noise floor, and this value is
					-- reported to the controller as `interference`.
					local pre_noise = {}
					local ok_pre, pre_stats = pcall(M._sysinfo.radio_stats, ifname)
					if ok_pre then
						for _, s in ipairs(pre_stats) do
							if s.freq and s.noise and s.noise ~= 0 then
								pre_noise[s.freq] = s.noise
							end
						end
					end
					-- One scan per channel, back home in between (see
					-- SPECTRUM_DWELL_TU). The operating channel is not
					-- scanned: its survey covers all the time the radio
					-- spends there. Without a survey to list the
					-- channels, one default sweep. A refused scan still
					-- leaves the operating channel's survey, so the
					-- table is built either way.
					local freqs = {}
					for _, s in ipairs(ok_pre and pre_stats or {}) do
						if s.freq and not s.in_use then freqs[#freqs + 1] = s.freq end
					end
					if #freqs == 0 then
						M._force_scan(ufuci, ifname, "spectrum-scan")
					else
						local scanned = 0
						for i, f in ipairs(freqs) do
							if M._force_scan(ufuci, ifname, "spectrum-scan",
									{ freqs = { f }, duration = M.SPECTRUM_DWELL_TU, quiet = true }) then
								scanned = scanned + 1
							end
							if i < #freqs then M._sleep(M.SPECTRUM_HOME_S) end
						end
						if scanned == 0 then
							io.stderr:write("inform: spectrum-scan: iw refused to scan " .. ifname .. "\n")
						end
					end
					local ok_rs, stats = pcall(M._sysinfo.radio_stats, ifname)
					if ok_rs then
						local widths = M._spectrum_widths(radio)
						local table_entries = {}
						for _, s in ipairs(stats) do
							local total = s.channel_time or 0
							local busy  = s.channel_time_busy or 0
							for _, width in ipairs(widths) do
								table_entries[#table_entries + 1] = {
									channel     = M._sysinfo.channel_from_freq(s.freq),
									center_freq = s.freq,
									width       = width,
									utilization = total > 0 and math.floor(busy * 100 / total) or 0,
									-- Post-sweep 0 falls back to the
									-- pre-sweep reading for that frequency.
									interference = (s.noise ~= 0 and s.noise)
										or pre_noise[s.freq] or 0,
								}
							end
						end
						M._spectrum_cache[radio.name] = {
							table      = table_entries,
							table_time = now,
						}
					end
				end
			end
		end
	end
end

-- Requests the dispatcher has no handler for, counted per name since the
-- daemon started. The controller's request set grows with each release, and
-- before this an unknown cmd left only the generic "cmd: X" line, the same as
-- a handled one, so the last gap (kick-sta) took a decompile to find. Memory
-- only, no state.json field: flash on the small boards is too scarce for a
-- ledger that grows with whatever the controller sends.
M._unhandled_counts = {}

-- A controller-supplied name as one short log token: no newline can forge a
-- second log line, and a huge string can't flood the log.
local function log_token(name)
	return (tostring(name):sub(1, 48):gsub("[^%w%-_.]", "?"))
end

function M._note_unhandled(kind, name)
	name = log_token(name)
	local key = kind .. " " .. name
	local n = (M._unhandled_counts[key] or 0) + 1
	M._unhandled_counts[key] = n
	io.stderr:write(("inform: unhandled %s '%s' (%d since start) -- ignored\n")
		:format(kind, name, n))
end

-- ─── Response dispatcher ─────────────────────────────────────────────────────

-- Handle a parsed controller response JSON string.
-- st:  current state table
-- cfg: device configuration (from conf.lua; optional -- nil in tests, LED
--      control becomes a no-op without cfg.led)
-- Returns true if config was applied (caller should send follow-up inform).
function M.handle_response(json_str, st, cfg)
	-- Tracks the config rather than latching on: a caller that stops passing
	-- debug_dump_file stops getting dropped-key reports too.
	M._debug_dropped_keys = not not (cfg and cfg.config and cfg.config.debug_dump_file)

	if cfg and cfg.config and cfg.config.debug_dump_file then
		local path = cfg.config.debug_dump_file
		local cap = cfg.config.debug_dump_max_bytes
		if cap == nil then cap = M.DEBUG_DUMP_MAX_BYTES end
		local f = io.open(path, "a")
		if f then
			-- Append mode already positions at the end, so seek reports the
			-- current size -- no stat binding needed, and busybox's stat
			-- applet is missing on some builds anyway.
			local size = f:seek("end") or 0
			if cap and cap > 0 and size >= cap then
				f:close()
				f = io.open(path, "w")
				if f then
					f:write(("%s # openuf: dump passed %d bytes, restarted\n")
						:format(os.date("!%Y-%m-%dT%H:%M:%SZ"), cap))
				end
			end
			if f then
				f:write(os.date("!%Y-%m-%dT%H:%M:%SZ") .. " " .. json_str .. "\n")
				f:close()
			end
		end
	end

	local ok, resp = pcall(cjson.decode, json_str)
	if not ok or type(resp) ~= "table" then
		return false
	end
	-- Every answer carries the controller's clock (WiFi Blackout Schedule).
	pcall(M._note_server_time, resp)

	local _type = resp._type

	if _type == "noop" then
		M._controller_interval = M._sane_interval(resp.interval)
		return false
	end

	if _type == "setparam" then
		-- mgmt_cfg is a newline-delimited key=value string (real controller format,
		-- confirmed by amd989/unifi-gateway _parse_mgmt_cfg).
		local mgmt_raw = resp.mgmt_cfg
		local newly_adopted = false
		if type(mgmt_raw) == "string" then
			-- The controller builds mgmt_cfg whole and always appends
			-- stun_url, so one without it means no STUN (stun.lua).
			local stun_url
			for line in (mgmt_raw .. "\n"):gmatch("([^\n]*)\n") do
				local k, v = line:match("^([^=]+)=(.*)$")
				if k and v then
					if k == "inform_url" then
						-- NOT "mgmt_url" -- confirmed live against a real controller
						-- (2026-07-14) that mgmt_url is the web UI deep link
						-- (https://host:8443/manage/site/default), a completely
						-- different endpoint from the actual inform target.
						-- Aliasing the two here previously made the device
						-- overwrite its own working inform_url with the UI link on
						-- the very next routine setparam cycle after adoption,
						-- breaking the inform loop for good (http-only builds have
						-- no luasec, so switching to that https URL is fatal).
						if v ~= "" then st.inform_url = v end
					elseif k == "capability" then
						-- "notif,notif-assoc-stat" from every 10.x controller:
						-- the request for per-connection STA_ASSOC_TRACKER
						-- notifs (assoctrack.lua). Only sent when asked.
						local asked = ("," .. v .. ","):find(",notif-assoc-stat,", 1, true) ~= nil
						-- A change re-arms the collector check now rather than
						-- up to a minute later: a setparam is not an "applied"
						-- push, so nothing else would.
						if asked ~= (st.notif_assoc_stat == true) then M._rrm_collector_next = 0 end
						st.notif_assoc_stat = asked
					elseif k == "use_aes_gcm" then
						st.use_gcm = (v == "true")
					elseif k == "selfrun_guest_mode" then
						-- The controller sends "pass" or "off"; like the
						-- firmware, only "off" is off.
						st.guest_selfrun = (v == "off") and "off" or "pass"
					elseif k == "stun_url" then
						if v ~= "" then stun_url = v end
					elseif k == "cfgversion" then
						if v ~= "" then st.cfgversion = v end
					elseif k == "led_enabled" then
						local enabled = (v == "true")
						st.led_enabled = enabled
						M._led.set_enabled(cfg and cfg.led, enabled)
					elseif k == "authkey" then
						-- Only trusted pre-adoption. Real L3 adoption has no SSH
						-- step at all (controller logs "skip SSH adoption" for
						-- L3-discovered devices) and delivers the new key this
						-- way instead -- confirmed against amd989/unifi-gateway's
						-- _parse_mgmt_cfg (which does exactly this, no SSH
						-- anywhere in that codebase) and live testing against a
						-- real controller. See PROTOCOL-VALIDATION.md. Restricted
						-- to the unadopted case: while unadopted the device is
						-- still using the well-known DEFAULT_KEY, so this
						-- exchange carries no less confidentiality than the rest
						-- of L3 provisioning already assumes. Once adopted, only
						-- SSH set-adopt may rotate the key (matches real L2
						-- hardware behavior).
						if not st.adopted and is_hex32(v) then
							st.authkey = v
							st.adopted = true
							newly_adopted = true
						end
					end
				end
			end
			st.stun_url = stun_url
		end

		-- IP Settings (DHCP vs Static, in the real controller UI) arrive via
		-- system_cfg, not mgmt_cfg -- a separate flat OpenWrt-UCI-style
		-- key=value blob, confirmed live against a real controller (see
		-- PROTOCOL-VALIDATION.md). Only present when the controller is
		-- actually pushing a network-config change, not on every inform.
		M._report_dropped_keys("mgmt_cfg", mgmt_raw, RECOGNIZED_MGMT_CFG)

		local sys_raw = resp.system_cfg
		if type(sys_raw) == "string" then
			M._report_dropped_keys("system_cfg", sys_raw, RECOGNIZED_SYSTEM_CFG)

			local net = M._parse_net_system_cfg(sys_raw)
			local ip, netmask, gateway = net.ip, net.netmask, net.gateway
			local dhcp, device_name, dns = net.dhcp, net.device_name, net.dns

			-- Shape check BEFORE anything is recorded or run. These three
			-- values are interpolated into `ip addr` / `ip route` command
			-- lines by netconfig.lua (which refuses them again itself), and
			-- this is what keeps a malformed push out of state.json as well:
			-- with the record written first, a refused apply would still leave
			-- ip_mode=static and a bogus static_ip behind for the DHCP-revert
			-- logic to act on. Feature-detected, so a test double standing in
			-- for netconfig need not carry the validator.
			local ipv4 = M._netconfig.is_ipv4
			if ip and ipv4 and not (ipv4(ip)
					and (netmask == nil or netmask == "" or ipv4(netmask))
					and (gateway == nil or gateway == "" or ipv4(gateway))) then
				io.stderr:write(("inform: ignoring IP Settings push with a malformed "
					.. "address (ip=%q netmask=%q gateway=%q)\n"):format(
					tostring(ip), tostring(netmask), tostring(gateway)))
				ip = nil
			end

			if ip then
				local iface = cfg and cfg.net and cfg.net.lan_cpueth
				if dhcp then
					-- Only genuinely ACT when reverting our own prior static
					-- config -- a fresh device's first-ever system_cfg (and
					-- every steady-state reaffirmation) also carries
					-- dhcpc.1.status=enabled, but real hardware already runs
					-- its own DHCP client continuously; flushing+re-leasing
					-- on every "still DHCP" push is needless and, worse,
					-- destructive wherever no DHCP server actually exists to
					-- grant a new lease (confirmed live: this validation
					-- container's Docker bridge has none -- udhcpc timed out
					-- and left the interface with no address at all).
					if st.ip_mode == "static" then
						M._netconfig.apply_dhcp(iface)
						M._populate_net_info(st, cfg)  -- re-read the freshly-leased address
					end
					st.ip_mode = "dhcp"
					st.static_ip, st.static_netmask, st.static_gateway = nil, nil, nil
					-- DNS is deliberately NOT touched here: the lease supplies
					-- it, and rewriting resolv.conf on every steady-state "still
					-- DHCP" push would fight the DHCP client for ownership --
					-- the same hazard as the flush+re-lease guarded above.
					st.static_dns = nil
				else
					st.ip_mode = "static"
					st.static_ip, st.static_netmask, st.static_gateway = ip, netmask, gateway
					st.static_dns = (#dns > 0) and dns or nil
					if M._netconfig.apply_static(iface, ip, netmask, gateway, dns) then
						st.ip = ip  -- known directly, no need to re-read the interface
					end
				end
				-- Persisted HERE, not at the end of handle_response.
				--
				-- The interface has already been reconfigured by this point,
				-- and state.json is the only record that it was: M.run's
				-- startup reapply is what puts a static address back after a
				-- reboot, and it reads exactly these fields. Everything
				-- between here and the save at the end of this function --
				-- the WiFi pass, switchvlan, usteer, bcfilter, shaper -- shells
				-- out or reaches into UCI and can raise, and _tick pcalls this
				-- whole function by design, so an error there costs one log
				-- line and nothing else. Leaving the write until the end meant
				-- any such error left the kernel reconfigured and the record
				-- lost, which is precisely the state the reapply cannot
				-- recover from.
				--
				-- Observed exactly that in the validation lab on 2026-09-10:
				-- usteer raised midway, the AP moved to its pushed static
				-- address, and state.json never learned about it.
				M._state.save(st)
			end

			-- Parsed once, out here: the switch pass below needs the vap_table
			-- too (for the VLANs tagged SSIDs sit on), and scoping it inside
			-- the wifi branch left that consumer reading a nil table -- an
			-- empty trunk list that fails silently.
			local radio_table, vap_table = M._parse_wifi_system_cfg(sys_raw)
			-- Which WLANs a station must pass the guest portal on. Every
			-- system_cfg lists every WLAN and redirector.status, so this
			-- replaces the record outright.
			st.guest_wlans = M._guest_wlans(vap_table, sys_raw)

			-- The switch.* block and, on DSA, the socket the uplink cable is
			-- in: both the port-VLAN set below and the switch pass after the
			-- WiFi pass need them. Each is worked out once per push (the
			-- uplink is a `bridge fdb` dump), not once per consumer.
			local sw = M._parse_switch_system_cfg(sys_raw)
			local dsa_uplink, dsa_uplink_known = nil, false
			local function dsa_uplink_port()
				if not dsa_uplink_known then
					local br = M._sysinfo.bridge_of(cfg and cfg.net and cfg.net.lan_cpueth)
					dsa_uplink = br and M._sysinfo.uplink_bridge_port(br) or nil
					dsa_uplink_known = true
				end
				return dsa_uplink
			end

			-- VLANs that a WIRED port is assigned to. Computed before the
			-- WiFi pass because their L2 is the same bridge a tagged SSID
			-- uses, and apply_config prunes any bridge no WLAN wants --
			-- which would delete the one a per-port assignment is about to
			-- need, on every push, then have switchvlan rebuild it. DSA
			-- only: on swconfig a port VLAN is a switch table entry, not a
			-- bridge. Safe when nothing is pushed (an empty set).
			local port_vlans = {}
			if M._switchvlan and M._switchvlan.dsa_members
				and not (cfg and cfg.vlan and cfg.vlan.ports) then
				local ok_pv, m = pcall(M._switchvlan.dsa_members, sw, cfg, dsa_uplink_port())
				if ok_pv then
					for vid in pairs(m or {}) do port_vlans[vid] = true end
				end
			end

			local ufuci = M._ucihelper
			if ufuci and ufuci.apply_config then
				if #radio_table > 0 or #vap_table > 0 then
					local steering_active, roam_assist_active =
						M._steering_flags(vap_table, sys_raw)
					M._usteer.set_enabled(steering_active, cfg, roam_assist_active)
					M._usteer_filter_next = 0   -- re-check the sync filter next tick
					pcall(ufuci.apply_config,
						{radio_table = radio_table, vap_table = vap_table, network_table = {}},
						cfg, {band_steering_active = steering_active,
							roam_assist_active = roam_assist_active,
							device_name = device_name, keep_vlans = port_vlans,
							peer_ie = M._sysinfo.peer_ie_hex(st and st.mac)})
					M._deny_reloaded()   -- apply_config ran `wifi reload`
				end
			end

			-- Per-port VLAN, after the WiFi pass so that any VLAN interface
			-- ensure_vlan_network() creates for a tagged SSID already exists
			-- before a switch port is put on the same VLAN.
			if M._switchvlan then
				pcall(function()
					-- Every VLAN a tagged SSID lands on. The switch drops
					-- frames for a VID it has no entry for, so these need
					-- trunking whether or not per-port VLAN is in use.
					-- A private pre-shared key's VLAN counts the same.
					local wireless_vlans, seen = {}, {}
					for _, vap in ipairs(vap_table or {}) do
						local vids = (ufuci and ufuci.vap_vlan_ids) and ufuci.vap_vlan_ids(vap)
							or ((vap.vlan_enabled and vap.vlan) and {vap.vlan} or {})
						for _, vid in ipairs(vids) do
							if not seen[vid] then
								seen[vid] = true
								wireless_vlans[#wireless_vlans + 1] = vid
							end
						end
					end
					-- Which socket the uplink cable is in, so a pushed port
					-- VLAN can never be applied to it (see physical_port).
					-- Asked of whichever source this board has: the switch's
					-- ARL table on swconfig, the bridge FDB on DSA.
					local uplink_phys, uplink_ifname = nil, nil
					if cfg and cfg.vlan and cfg.vlan.ports then
						local swst = M._sysinfo.switch_status(cfg.vlan.device)
						uplink_phys = M._sysinfo.uplink_phys_port(swst.arl)
					else
						uplink_ifname = dsa_uplink_port()
					end
					-- Turning Port VLAN off does not always announce itself.
					-- The gates were once observed staying on the wire at
					-- =disabled, but a device that has HAD the feature on and
					-- then has it unticked gets a full system_cfg with no
					-- switch.* keys at all -- confirmed live on the AX3000T,
					-- where the teardown therefore never ran and br-lan kept
					-- openUF's port list forever.
					--
					-- So absence counts as off too, but only when openUF holds
					-- a reversibility ledger: that is proof it applied
					-- something, which in turn is proof the controller was
					-- sending switch.* until now. With no ledger there is
					-- nothing to undo and this is a no-op anyway. Safe on a
					-- partial push -- the worst case is a restore to stock
					-- that the next full push re-applies -- and it cannot
					-- flap, since restore() spends the ledger. Reachable only
					-- inside `type(sys_raw) == "string"`, never on a noop.
					local had_applied = st.swvlan_backup ~= nil
						or st.dsa_brlan_ports ~= nil
					if (sw and not sw.enabled) or (sw == nil and had_applied) then
						-- Explicit disable: unticking the device-level "Port
						-- VLAN" box keeps the switch.* block on the wire with
						-- both gates at =disabled (confirmed live -- the
						-- baseline capture carries them that way). Tear our
						-- sections down and put the stock port strings back,
						-- or the switch stays segmented forever after the
						-- user turns the feature off. A blob with no switch.*
						-- lines at all (sw == nil: older controller, partial
						-- push) still leaves everything alone -- restore only
						-- ever runs on an affirmative off signal, and its own
						-- empty-ledger no-op keeps steady-state disabled
						-- pushes free of switch reloads.
						-- ...unless a tagged SSID still needs its VLAN
						-- trunked. restore() puts the stock port strings
						-- back and drops every openuf section, which would
						-- take the wireless trunk with it and silently kill
						-- the IoT WLAN's uplink. apply() reconciles both
						-- concerns in one pass.
						--
						-- That hazard is SWCONFIG-ONLY, and gating on the
						-- wireless VLANs alone got it wrong on DSA: there the
						-- tagged SSID needs no trunk at all and its bridge
						-- belongs to ucihelper, so restore() cannot harm it --
						-- it only hands br-lan its original port list back.
						-- Skipping restore there meant the reversibility
						-- ledger was never spent and br-lan kept the port
						-- ORDER openUF had left it in, so unticking Port VLAN
						-- looked like it had done nothing.
						if (cfg and cfg.vlan and cfg.vlan.ports)
							and #wireless_vlans > 0 then
							M._switchvlan.apply(sw, cfg, st, wireless_vlans,
								uplink_phys, uplink_ifname)
						else
							M._switchvlan.restore(st, cfg)
						end
					else
						M._switchvlan.apply(sw, cfg, st, wireless_vlans,
							uplink_phys, uplink_ifname)
					end
				end)
			end

			-- Controller-managed system settings: timezone, NTP servers and
			-- the nightly `syswrapper.sh 11k-scan` cron job (sysconf.lua).
			-- Each part is pcall'd inside apply(); this pcall covers parse.
			if M._sysconf then
				local ok_sc, err_sc = pcall(function()
					local sc = M._sysconf.parse(sys_raw)
					if sc then M._sysconf.apply(sc) end
				end)
				if not ok_sc then
					io.stderr:write("inform: sysconf: " .. tostring(err_sc) .. "\n")
				end
			end

			-- Airtime Fairness (airtime.lua). Kept in state.json because the
			-- debugfs switch resets on reboot and the controller does not
			-- push again; M.run reapplies it. No block, no change.
			if M._airtime then
				local atf = M._airtime.parse(sys_raw)
				if atf ~= nil then
					st.atf_enabled = atf
					local ok_atf, err_atf = pcall(M._airtime.set_enabled, atf)
					if not ok_atf then
						io.stderr:write("inform: airtime: " .. tostring(err_atf) .. "\n")
					end
				end
			end

			-- The ebtables.* hardening block (l2guard.lua): BPDU and
			-- VLAN-tag drop on every AP VAP. After the WiFi pass on purpose,
			-- so a VAP this push added has its netdev by now if netifd was
			-- quick; _l2guard_resync picks it up if not.
			if M._l2guard then
				local ok_l2, err_l2 = pcall(M._l2guard_apply_push, sys_raw, st)
				if not ok_l2 then
					io.stderr:write("inform: l2guard: " .. tostring(err_l2) .. "\n")
				end
			end
			-- The guest portal's own ebtables rules (guestportal.lua), after
			-- the WiFi pass for the same reason; _guest_resync covers a
			-- guest VAP whose netdev is not up yet.
			if M._guestportal then
				local ok_gp, err_gp = pcall(M._guest_apply_push, sys_raw, st)
				if not ok_gp then
					io.stderr:write("inform: guestportal: " .. tostring(err_gp) .. "\n")
				end
			end
		end

		-- blocked_sta: the site's whole block list, newline-separated, on
		-- every config push and again when the controller sees the device
		-- come back (PROTOCOL-VALIDATION.md, "blocked_sta"). Present-but-empty
		-- is a real "nothing blocked"; absent means not sent, so the ledger
		-- stands.
		if type(resp.blocked_sta) == "string" then
			M._sync_blocked_stas(st, resp.blocked_sta)
		end

		M._state.save(st)
		return newly_adopted  -- re-inform immediately with the new key if adopted
	end

	if _type == "setdefault" then
		-- Controller requested factory reset.  Reset state on disk and in-memory.
		io.stderr:write("inform: controller requested factory reset\n")
		-- mac/ip/hostname are populated once at M.run() startup by
		-- _populate_net_info and never persisted to state.json -- preserve them
		-- across the reset rather than losing the device's identity mid-run.
		local mac, ip, hostname = st.mac, st.ip, st.hostname
		local prev = {}
		for k, v in pairs(st) do prev[k] = v end
		local fresh = M._state.reset()
		for k in pairs(st) do st[k] = nil end
		for k, v in pairs(fresh) do st[k] = v end
		st.mac, st.ip, st.hostname = mac, ip, hostname
		-- The URL that just reached this controller stays, so the device shows
		-- up there as pending and can be adopted again. The default it would
		-- fall back to (conf.lua's, `http://unifi:8080/inform` out of the box)
		-- names the controller by host name, and an L3 adoption over it fails:
		-- the controller answers HTTP 400 ("invalid inform_ip unifi"), seen on
		-- a UCG Ultra and in the lab, 2026-10-11. A reset-inform still starts
		-- over from the default; it is the explicit way to point elsewhere.
		if prev.inform_url and prev.inform_url ~= "" then
			st.inform_url = prev.inform_url
			M._state.save(st)
		end
		M._sync_bootstrap_account(false, cfg and cfg.config and cfg.config.bootstrap_adopt_user)
		M._firewall.reconcile(st.blocked_stas)
		M._deny_pending = true
		M._forget_controller(prev, cfg)
		return false
	end

	if _type == "reboot" then
		io.stderr:write("inform: controller requested reboot\n")
		os.execute("reboot")
		os.exit(0)
	end

	if _type == "upgrade" then
		-- Store only -- never download/verify/flash/reboot. A real controller's
		-- upgrade URL targets genuine Ubiquiti firmware; applying it to this
		-- (non-Ubiquiti) hardware would brick it. See amd989/unifi-gateway,
		-- which handles this identically (log + store, no real upgrade path).
		st.upgrade_requested_version = tostring(resp.version or "")
		st.upgrade_requested_url     = tostring(resp.url or "")
		io.stderr:write("inform: upgrade requested (version=" .. st.upgrade_requested_version
			.. ") -- stored only, not applying\n")
		M._state.save(st)
		return false
	end

	if _type == "cmd" then
		local cmd = resp.cmd or ""
		io.stderr:write("inform: cmd: " .. log_token(cmd) .. "\n")

		if cmd == "set-locate" or cmd == "unset-locate" then
			local led_path = cfg and cfg.led
			if cmd == "set-locate" then
				-- The trigger the LED was on is persisted, not just held in
				-- memory: the controller sends set-locate and unset-locate as
				-- two independent commands with nothing bounding the gap, so
				-- a restart can easily land between them, and only this copy
				-- then knows what to put back. See M.run's startup handling.
				local _, prev = M._led.locate_start(led_path)
				st.locate_prev_trigger = prev
			else
				M._led.locate_stop(led_path, st.locate_prev_trigger)
				st.locate_prev_trigger = nil
				-- Restoring the TRIGGER is not the whole idle state. An LED
				-- whose normal look is "trigger none, brightness on" -- which
				-- is exactly what set_enabled leaves behind, and what a
				-- dedicated status LED like blue:status or green:system sits
				-- at -- comes back from a Locate on trigger none and
				-- brightness 0, i.e. dark. So re-assert the steady state the
				-- operator actually chose, the same way M.run does at
				-- startup. nil means never pushed: leave the board alone.
				if st.led_enabled ~= nil then
					M._led.set_enabled(led_path, st.led_enabled)
				end
			end
			st.locating = (cmd == "set-locate")
			M._state.save(st)
		elseif cmd == "block-sta" or cmd == "unblock-sta" then
			-- The immediate path. `include_blocks` stays empty even while a
			-- client is blocked; the persistent copy is setparam's
			-- blocked_sta (M._sync_blocked_stas), which only arrives on the
			-- next config push. Persisted in state.blocked_stas and re-applied
			-- at M.run() startup (M._firewall.reconcile), so it survives a
			-- restart.
			local mac = resp.mac
			if type(mac) == "string" then
				st.blocked_stas = st.blocked_stas or {}
				if cmd == "block-sta" then
					local already = false
					for _, m in ipairs(st.blocked_stas) do
						if m == mac then already = true break end
					end
					if not already then
						st.blocked_stas[#st.blocked_stas + 1] = mac
					end
				else
					local kept = {}
					for _, m in ipairs(st.blocked_stas) do
						if m ~= mac then kept[#kept + 1] = m end
					end
					st.blocked_stas = kept
				end
				M._state.save(st)
				M._firewall.reconcile(st.blocked_stas)
				M._deny_pending = true
				pcall(M._block_resync, st)
				if cmd == "block-sta" then
					-- Kick it immediately if it's currently associated --
					-- hostapd drops it on the deny ACL entry, but only where
					-- that took; the nft drop alone stops future traffic and
					-- doesn't tear down an existing association.
					M._firewall.deauth(mac, M._bss_ifnames())
				end
			end
		elseif cmd == "kick-sta" then
			-- Client -> Reconnect: {"cmd":"kick-sta","mac":...}, queued to
			-- the AP the client is on (PROTOCOL-VALIDATION.md, "Response
			-- _types"). A one-shot deauth and nothing more: the client may
			-- reassociate at once, so no ledger and no nft (unlike block-sta).
			if type(resp.mac) == "string" then
				M._firewall.deauth(resp.mac, M._bss_ifnames())
			end
		elseif cmd == "authorize-guest" or cmd == "unauthorize-guest" then
			-- Guest portal: {"cmd":"(un)authorize-guest","mac":...}
			-- (PROTOCOL-VALIDATION.md, "Guest portal (Hotspot)"). The
			-- ledger build_json reports `authorized` from, and the nft set
			-- that lets the guest past the portal.
			M._guest_authorize(st, resp.mac, cmd == "authorize-guest")
			M._state.save(st)
			if M._guest_built then
				pcall(M._guestportal.set_authorized, M._guest_macs(st))
			end
			if cmd == "unauthorize-guest" then M._guest_kick(resp.mac) end
		elseif cmd == "rate-update" then
			-- {"cmd":"rate-update","mac":...,"ul_max":kbps,"dl_max":kbps,
			-- ...}: one client's WiFi Speed Limit, its own profile or a
			-- guest's portal limit, sent each time it connects, roams or
			-- reconnects and whenever the profile changes
			-- (PROTOCOL-VALIDATION.md, "qos.* -- WiFi Speed Limit").
			if M._sta_rate(st, resp) then
				M._state.save(st)
				pcall(M._shaper_resync, st)
			end
		elseif cmd == "scan" or cmd == "scan_band" then
			M._handle_scan_cmd(resp, cfg)
		elseif cmd == "spectrum-scan" then
			-- Airtime Scan ("Scan Now"). Sent only to a device claiming
			-- wifi_caps 0x10. Only marked pending here: the follow-up inform
			-- reports spectrum_scanning = true, and _tick runs the sweep
			-- (M._run_spectrum_scan) once that inform is out, then informs
			-- again with the results and false. The inform that brought this
			-- cmd already reset the controller's flag to false, so sweeping
			-- here would never show the scan as running; UniFi firmware
			-- reports true for the whole scan.
			--
			-- The payload's "spectrum-cfg" is ignored on purpose. It is a
			-- whole replacement system_cfg (every WLAN replaced by one hidden
			-- "vport-<serial>" SSID, every radio rfscan=enabled): UniFi
			-- firmware restarts onto it for the scan, taking clients off
			-- the AP, and restores afterwards (firmware-confirmed for
			-- 3.9.27 to 4.0.15, platdep_funcs.sh spectrum_scan). The
			-- controller marks every radio rfscan=enabled, so it carries no
			-- scan parameter either. openUF sweeps off-channel and keeps
			-- the WLANs up.
			--
			-- Entries follow real UAPs: one per (channel, width), utilization
			-- in percent, interference as noise-floor dBm. The UI averages
			-- the entries whose width equals the chart's width over each
			-- bonded block's 20 MHz channels, so each 20 MHz measurement is
			-- listed once per width the band offers (_spectrum_widths).
			M._spectrum_pending = true
		else
			-- Anything else (other device classes' cmds, the WebRTC console,
			-- crash-log requests; PROTOCOL-VALIDATION.md lists them) is a
			-- no-op, but a named one, so a new request shows up in the log.
			M._note_unhandled("cmd", cmd)
		end
		-- Every cmd, handled or not, gets the immediate follow-up inform.
		-- Per fxkr/unifi-protocol-reverse-engineering's documented inform
		-- semantics: "Upon receiving a command message, an AP will execute a
		-- command and then send another inform immediately" -- regardless of
		-- which cmd it was, including ones we treat as a no-op. Matches the
		-- cfgversion branch below, which already does this correctly.
		return true
	end

	-- Every _type openUF knows has returned by now.
	if _type ~= nil then M._note_unhandled("_type", _type) end

	-- Config update: check cfgversion. WiFi config itself is applied from
	-- system_cfg above, not here -- a real controller never sends the
	-- resp.vap_table/radio_table/network_table JSON this branch used to gate
	-- on, so all that is left to do is record the version we have caught up to.
	if type(resp.cfgversion) == "string" and resp.cfgversion ~= st.cfgversion then
		st.cfgversion = resp.cfgversion
		M._state.save(st)
		return true  -- signal: send follow-up inform immediately
	end

	return false
end

-- The WLAN options the controller last pushed were built with the plugins
-- then enabled. When that set (or a plugin's source) has changed since, forget
-- cfgversion so the controller pushes again, instead of waiting for a Force
-- Provision. A device that has never been pushed to has nothing stale.
function M._reconcile_plugins(st, cfg)
	local plugins = M._plugins
	if not plugins then return end
	local ok, fp = pcall(plugins.fingerprint, cfg)
	if not ok then return end
	if fp ~= (st.plugins_fp or "") then
		if st.adopted and st.cfgversion ~= "" then st.cfgversion = "" end
		st.plugins_fp = fp
		M._state.save(st)
	end
end

-- Every hostapd BSS on the device, for a deauth that must find a station on
-- whichever SSID it is on. One interface per radio missed every SSID after the
-- first on that radio. A VLAN netdev folds into its BSS (hostapd has no
-- control socket on it).
-- Guest portal (PROTOCOL-VALIDATION.md, "Guest portal (Hotspot)").
--
-- On a guest WLAN with the portal on, the controller compares each station's
-- reported `authorized` with its own guest records on every inform: a
-- station it has no record for but that reports authorized gets
-- unauthorize-guest, and a station it has a record for that reports
-- unauthorized gets authorize-guest. An absent `authorized` counts as true,
-- so before this every station on such a WLAN drew an unauthorize-guest per
-- inform and authorize-guest was never sent at all.

-- Cap on st.guest_authorized. Past it the oldest authorization goes first;
-- the controller re-sends authorize-guest for any guest it still has a
-- record for, so a dropped entry costs one inform, not access.
M.GUEST_LEDGER_MAX = 512

-- Set of wlanconf ids (vap.wlanconf_id) on which stations must pass the
-- portal: guest WLANs while redirector.status=enabled. Without the portal a
-- guest WLAN is only isolated, and the controller does not check
-- `authorized` there.
function M._guest_wlans(vap_table, sys_raw)
	local out = {}
	if type(sys_raw) ~= "string"
			or not ("\n" .. sys_raw .. "\n"):find("\nredirector%.status=enabled\n") then
		return out
	end
	for _, vap in ipairs(vap_table or {}) do
		if vap.is_guest and vap.wlanconf_id then out[vap.wlanconf_id] = true end
	end
	return out
end

-- Record or drop one guest authorization. A malformed MAC is ignored.
function M._guest_authorize(st, mac, authorized)
	mac = type(mac) == "string" and mac:lower():match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*$")
	if not mac then return end
	st.guest_authorized = st.guest_authorized or {}
	if not authorized then
		st.guest_authorized[mac] = nil
		return
	end
	st.guest_authorized[mac] = os.time()
	local n, oldest, oldest_t = 0, nil, nil
	for m, t in pairs(st.guest_authorized) do
		n = n + 1
		if not oldest_t or t < oldest_t then oldest, oldest_t = m, t end
	end
	if n > M.GUEST_LEDGER_MAX then
		st.guest_authorized[oldest] = nil
	end
end

-- Disconnect a guest whose authorization ended, as UniFi firmware does
-- (syswrapper.sh unauthorize-guest: drop the MAC, then kick_sta on every
-- user and guest VAP; firmware-confirmed for 3.9.27 to 4.0.15). Associated
-- and unauthorized, the guest's OS never re-runs its captive-portal check,
-- so it sits behind the portal with no page to log in on. On reconnecting
-- it reports authorized false, which the controller leaves alone.
--
-- The firmware reports `authorized` from the very list it just changed, so
-- one unauthorize-guest is all it ever gets. openUF reports it only on the
-- WLANs st.guest_wlans names, and true elsewhere; if that ever disagreed with
-- the controller, unauthorize-guest would come on every inform. One kick per
-- MAC per GUEST_KICK_HOLD seconds keeps that from becoming a deauth storm.
M.GUEST_KICK_HOLD = 60
M._guest_kicked = {}

function M._guest_kick(mac)
	mac = type(mac) == "string" and mac:lower():match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*$")
	if not mac then return false end
	local now = M._time()
	for m, t in pairs(M._guest_kicked) do
		if now - t >= M.GUEST_KICK_HOLD or now < t then M._guest_kicked[m] = nil end
	end
	if M._guest_kicked[mac] then return false end
	M._guest_kicked[mac] = now
	M._firewall.deauth(mac, M._bss_ifnames())
	return true
end

-- A rate-update into st.sta_rates ({mac = {up = kbps, down = kbps}}), for
-- any client, as the firmware's update_sta_qosrate takes it: a limit of 0
-- or less, or none, is -1, which lifts that client's cap that way even on a
-- limited WLAN. Ignored for a MAC no netdev listed at the last heartbeat,
-- as the firmware ignores one with no association. Returns true when the
-- ledger changed.
function M._sta_rate(st, resp)
	local mac = type(resp.mac) == "string"
		and resp.mac:lower():match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*$")
	if not mac then return false end
	local obs = M._shape_obs
	if obs and obs.complete and not obs.where[mac] then return false end
	local function kbps(v)
		v = tonumber(v)
		return v and v > 0 and math.floor(v) or -1
	end
	local up, down = kbps(resp.ul_max), kbps(resp.dl_max)
	st.sta_rates = st.sta_rates or {}
	local cur = st.sta_rates[mac]
	if cur and cur.up == up and cur.down == down then return false end
	st.sta_rates[mac] = {up = up, down = down}
	return true
end

-- WiFi Speed Limit, from what the last build_json saw (M._shape_obs): each
-- netdev's stations and its WLAN's limits, with st.sta_rates on top. A
-- rate-update lasts one association, as the firmware's per-station class
-- does: it goes when the client leaves, or when its connected time drops
-- (it reconnected between two heartbeats; the controller sends a fresh
-- one if the client still has a profile of its own).
M._sta_conn = {}
function M._shaper_resync(st)
	local obs = M._shape_obs
	if not obs then return false end
	local shaper = M._shaper
	if not shaper then return false end
	local rates = st.sta_rates or {}
	local changed = false
	if obs.complete then
		for mac in pairs(rates) do
			local now_c, was_c = obs.conn[mac], M._sta_conn[mac]
			if not obs.where[mac] or (now_c and was_c and now_c < was_c) then
				rates[mac] = nil
				changed = true
			end
		end
		M._sta_conn = obs.conn
	end
	local desired = {}
	for ifname, o in pairs(obs.by_ifname) do
		local down = {default = o.down, stas = {}}
		local up = {default = o.up, stas = {}}
		for _, mac in ipairs(o.macs) do
			local r = rates[mac]
			local d, u = o.down, o.up
			-- An own limit replaces the WLAN's; -1 lifts it (0: uncapped).
			if r then
				d = r.down and r.down > 0 and r.down or 0
				u = r.up and r.up > 0 and r.up or 0
			end
			down.stas[mac], up.stas[mac] = d, u
		end
		local any = down.default or up.default
		for _, k in pairs(down.stas) do any = any or (k and k > 0) end
		for _, k in pairs(up.stas) do any = any or (k and k > 0) end
		if any then
			desired[ifname] = {down = down, up = up}
		end
	end
	if changed then
		st.sta_rates = next(rates) and rates or nil
		M._state.save(st)
	end
	shaper.sync(desired)
	return true
end

-- The `authorized` a station on this vap reports: the ledger's word on a
-- portal WLAN, true everywhere else (what the controller assumes anyway).
function M._guest_sta_authorized(st, vap, mac)
	local wlans = st and st.guest_wlans
	if not (wlans and vap and vap.id and wlans[vap.id]) then return true end
	return (st.guest_authorized or {})[mac] ~= nil
end

-- ─── Guest portal enforcement (guestportal.lua) ─────────────────────────────

-- The ledger as a sorted list, for the nft set.
function M._guest_macs(st)
	local out = {}
	for mac in pairs(st.guest_authorized or {}) do out[#out + 1] = mac end
	table.sort(out)
	return out
end

-- The portal WLANs' live netdevs, each with its SSID and bridge MAC.
function M._guest_vaps(st)
	local ufuci = M._ucihelper
	if not (ufuci and ufuci.wlanconf_ifnames) then return {} end
	local ok, vaps = pcall(ufuci.wlanconf_ifnames, st.guest_wlans)
	if not ok or type(vaps) ~= "table" then return {} end
	for _, v in ipairs(vaps) do v.bridge_mac = M._guestportal.bridge_mac(v.ifname) end
	return vaps
end

local function guest_vaps_key(vaps)
	local parts = {}
	for _, v in ipairs(vaps) do parts[#parts + 1] = v.ifname .. "=" .. tostring(v.bridge_mac) end
	return table.concat(parts, " ")
end

-- While the portal is on: the listening socket (served from M._idle), what
-- the answer needs, and the VAP list the tables were built for.
M._guest_server = nil
M._guest_ctx    = nil
M._guest_built  = nil

-- The walled garden's resolved domain half as reconcile wants it. Empty when
-- the push carries no garden domains, so the rules simply are not there.
function M._guest_garden(st)
	local store = type(st.guest_wg_ips) == "table" and st.guest_wg_ips or {}
	return {
		allowed    = M._guestportal.garden_ips(store.allowed),
		restricted = M._guestportal.garden_ips(store.restricted),
	}
end

-- Resolve the garden's domains and keep the answers in state. Driven on every
-- push and then on the controller's own cadence for the job it asks the device
-- to run (`*/10 * * * *  syswrapper.sh refresh-walled-garden 1`, which
-- sysconf.lua therefore installs no crontab line for). Returns true when the
-- address set changed, i.e. when the chains have to be rebuilt.
--
-- Each name costs two blocking nslookups and a blackholed resolver takes 5 s
-- per lookup, so this is the one path on which the controller can stall the
-- daemon: it runs inline in handle_response, and three missed informs is what
-- puts a genuine AP into selfrun. Two bounds, since neither is enough alone:
--
--  * the NAME LIST's signature, against the refresh window the last pass
--    opened. A push repeats the whole garden whether or not it changed (a
--    Force Provision loop repeats it every few seconds), and re-asking DNS
--    for an unchanged list inside that window buys nothing: the ten-minute
--    refresh is what catches an address that moved. The signature is held in
--    memory, not state.json, because the window is: a restart re-resolves
--    once, which is also when the chains are rebuilt from scratch anyway.
--  * a wall-clock budget per pass. Past it no further name is asked and the
--    rest keep their last answer, which is what a name that stops resolving
--    already does. One name can overrun by a single lookup, so the worst case
--    is BUDGET + 5 s.
M.GUEST_WG_INTERVAL = 600
-- After a pass that ran out of time, rather than ten minutes.
M.GUEST_WG_RETRY = 120
M.GUEST_WG_BUDGET = 5
M._guest_wg_next = 0
M._guest_wg_sig = nil

-- The signature of one push's garden names: the two lists in push order, which
-- is the order they are resolved in, so a reordering is a different list.
local function guest_wg_sig(names)
	local parts = {}
	for _, which in ipairs({"allowed", "restricted"}) do
		parts[#parts + 1] = which .. "=" .. table.concat(names[which], ",")
	end
	return table.concat(parts, " ")
end

function M._guest_wg_resolve(st)
	local gp, spec = M._guestportal, st.guest_portal
	local names = {
		allowed    = (type(spec) == "table" and spec.wg_allowed) or {},
		restricted = (type(spec) == "table" and spec.wg_restricted) or {},
	}
	local now = M._time()
	if #names.allowed == 0 and #names.restricted == 0 then
		M._guest_wg_next = now + M.GUEST_WG_INTERVAL
		M._guest_wg_sig = guest_wg_sig(names)
		if st.guest_wg_ips == nil then return false end
		st.guest_wg_ips = nil
		M._state.save(st)
		return true
	end
	local sig = guest_wg_sig(names)
	if sig == M._guest_wg_sig and now < M._guest_wg_next then return false end
	local store = type(st.guest_wg_ips) == "table" and st.guest_wg_ips or {}
	local changed, partial = false, false
	local out = {}
	for _, which in ipairs({"allowed", "restricted"}) do
		-- One budget for the pass, not one per list: what is left of it after
		-- the allowed names is what the restricted ones get.
		local left = M.GUEST_WG_BUDGET - (M._time() - now)
		local map, _, diff, cut = gp.resolve_garden(names[which], store[which],
			left > 0 and left or 0)
		out[which] = map
		changed = changed or diff
		partial = partial or cut
	end
	M._guest_wg_sig = sig
	-- A pass that ran out of time opens a shorter window, so the names it
	-- never asked are picked up by the heartbeat in two minutes rather than
	-- ten -- without letting every push in between re-ask.
	M._guest_wg_next = M._time()
		+ (partial and M.GUEST_WG_RETRY or M.GUEST_WG_INTERVAL)
	if changed then
		st.guest_wg_ips = out
		M._state.save(st)
	end
	return changed
end

-- The ten-minute refresh itself, from the heartbeat.
function M._guest_wg_resync(st)
	local spec = st and st.guest_portal
	if not (M._guestportal and type(spec) == "table" and spec.enabled) then return false end
	-- Length without the `or {}` fallbacks: a portal with no garden is the
	-- common case, and that is exactly when both fields are nil, so the guard
	-- that exists to do nothing allocated two tables per heartbeat.
	if (spec.wg_allowed and #spec.wg_allowed or 0) == 0
		and (spec.wg_restricted and #spec.wg_restricted or 0) == 0 then return false end
	if M._time() < M._guest_wg_next then return false end
	if not M._guest_wg_resolve(st) then return false end
	io.stderr:write("guestportal: walled-garden addresses changed -- rebuilding\n")
	M._guest_enforce(st)
	return true
end

-- Make the kernel and the listener match st.guest_portal.
function M._guest_enforce(st, vaps)
	local gp = M._guestportal
	local spec = st.guest_portal
	if not (type(spec) == "table" and spec.enabled) then
		gp.reconcile(nil)
		M._guest_built, M._guest_ctx = nil, nil
		if M._guest_server then M._guest_server:close() end
		M._guest_server = nil
		return 0
	end
	-- The portal's guest_token (build_json). Its value would key the
	-- controller's encrypted-cookie redirect, which openUF does not claim;
	-- the plain id=/ap= redirect only needs one to exist.
	if type(st.guest_token) ~= "string" then
		local bytes = M._crypto.random_iv(16)
		st.guest_token = (bytes:gsub(".", function(c) return string.format("%02x", c:byte()) end))
		M._state.save(st)
	end
	vaps = vaps or M._guest_vaps(st)
	local n = gp.reconcile(spec, vaps, M._guest_macs(st), M._guest_selfrun_on,
		M._guest_garden(st))
	M._guest_built = guest_vaps_key(vaps)
	M._guest_ctx = {url = spec.url, ap = st.mac, vaps = vaps}
	if not M._guest_server then
		local ok, server, err = pcall(gp.listen, M._socket())
		if ok and server then
			M._guest_server = server
		else
			io.stderr:write("guestportal: cannot listen on port " .. gp.PORT .. ": "
				.. tostring(ok and err or server) .. "\n")
		end
	end
	return n
end

M._socket = function() return require("socket") end

-- A push's portal facts -> st.guest_portal, and the kernel made to match.
-- A push without redirector.status (a partial one) leaves it alone.
function M._guest_apply_push(sys_raw, st)
	local spec = M._guestportal.parse(sys_raw)
	if not spec then return false end
	for _, u in ipairs(spec.unknown) do
		io.stderr:write("guestportal: unrecognised guest rule shape, not applied: "
			.. ("%q"):format(u) .. "\n")
	end
	spec.unknown = nil
	st.guest_portal = spec.enabled and spec or nil
	-- Before the rebuild, so this push's garden is enforced by it rather than
	-- ten minutes later.
	pcall(M._guest_wg_resolve, st)
	M._guest_enforce(st)
	return true
end

-- Once a minute while the portal is on: rebuild when the guest VAPs' netdevs
-- changed (a push's `wifi reload` finishing, wireless coming up after the
-- daemon). An empty list is "not answering yet" and changes nothing.
M.GUEST_RESYNC_INTERVAL = 60
M._guest_next = 0
function M._guest_resync(st)
	local spec = st and st.guest_portal
	if not (M._guestportal and type(spec) == "table" and spec.enabled) then return false end
	local now = M._time()
	if now < M._guest_next then return false end
	M._guest_next = now + M.GUEST_RESYNC_INTERVAL
	local vaps = M._guest_vaps(st)
	if #vaps == 0 or guest_vaps_key(vaps) == M._guest_built then return false end
	io.stderr:write("guestportal: guest interfaces changed (" .. guest_vaps_key(vaps)
		.. ") -- rebuilding\n")
	M._guest_enforce(st, vaps)
	return true
end

-- selfrun_guest_mode (mgmt_cfg, every push): what guests get while the AP
-- runs without its controller, as the UniFi firmware does it (mcad +
-- syswrapper.sh, BZ2 3.9.27-4.0.15). Selfrun starts after
-- GUEST_SELFRUN_FAILS informs in a row went unanswered and ends with the
-- first answer; it only matters while the portal is on. "pass" (or never
-- told -- only "off" is off) lets every guest through
-- (guestportal.set_selfrun), since nobody could log in meanwhile. "off"
-- takes the guest WLANs down until the controller is back; the ifnames are
-- kept in st.guest_vaps_down, so a restart in between still brings them up.
-- Unlike the firmware, the authorized ledger is kept on return: the
-- controller re-authorizes the same guests anyway.
M.GUEST_SELFRUN_FAILS = 3
M._inform_fails = 0
M._guest_selfrun_on = false
M._guest_up_failed = ""
function M._guest_selfrun(st, contacted)
	M._inform_fails = contacted and 0 or M._inform_fails + 1
	local spec = st and st.guest_portal
	-- WLANs left down before a restart stay down until an answer, rather
	-- than flapping up for the first failures of the new count.
	local selfrun = M._inform_fails >= M.GUEST_SELFRUN_FAILS
		or (st.guest_vaps_down ~= nil and not contacted)
	local mode
	if type(spec) == "table" and spec.enabled == true and selfrun then
		mode = (st.guest_selfrun == "off") and "off" or "pass"
	end
	local changed = false
	if mode == "off" and not st.guest_vaps_down then
		local names = {}
		for _, v in ipairs(M._guest_vaps(st)) do names[#names + 1] = v.ifname end
		for _, n in ipairs(names) do pcall(M._wlansched.set_bss, n, false) end
		st.guest_vaps_down = names
		M._state.save(st)
		io.stderr:write("guestportal: " .. M._inform_fails .. " informs unanswered, "
			.. "selfrun_guest_mode=off -- guest WLANs down (" .. table.concat(names, " ") .. ")\n")
		changed = true
	elseif mode ~= "off" and st.guest_vaps_down then
		-- A WLAN its blackout schedule holds down stays down
		-- (_sched_resync brings it up when the schedule ends). One whose
		-- beacon did not restart (wlansched.set_bss) stays in the ledger,
		-- down, and the next answered inform tries again.
		local held, up, failed = {}, {}, {}
		for _, n in ipairs(st.sched_vaps_down or {}) do held[n] = true end
		for _, n in ipairs(st.guest_vaps_down) do
			-- Already up (a wifi reload recreated it) or gone: nothing to do.
			if not held[n] and M._wlansched.is_up(n) == false then
				local ok, res = pcall(M._wlansched.set_bss, n, true)
				if ok and res then up[#up + 1] = n else failed[#failed + 1] = n end
			end
		end
		if #up > 0 then
			io.stderr:write("guestportal: guest WLANs back up (" .. table.concat(up, " ") .. ")\n")
		end
		-- Said once per set of failures, not on every retry.
		local said = table.concat(failed, " ")
		if #failed > 0 and said ~= M._guest_up_failed then
			io.stderr:write("guestportal: could not put guest WLANs back on the air ("
				.. said .. ") -- retrying at every answer\n")
		end
		M._guest_up_failed = said
		st.guest_vaps_down = (#failed > 0) and failed or nil
		M._state.save(st)
		changed = true
	end
	local pass = mode == "pass"
	if pass ~= M._guest_selfrun_on then
		M._guest_selfrun_on = pass
		io.stderr:write(pass
			and ("guestportal: " .. M._inform_fails .. " informs unanswered, "
				.. "selfrun_guest_mode=pass -- letting guests through\n")
			or "guestportal: controller answered -- guest portal enforced again\n")
		if M._guest_built then pcall(M._guestportal.set_selfrun, pass) end
		changed = true
	end
	return changed
end

-- WiFi Blackout Schedule (wlansched.lua): each heartbeat, every scheduled
-- WLAN outside its schedule's on-times is taken down, as the firmware's
-- configure_vap does with ifconfig, and brought back up when they start
-- again. hostapd stops and restarts that BSS alone when its netdev goes
-- down and up. The ifnames taken down are kept in st.sched_vaps_down, so
-- a restart in between still brings them up. Nothing is done before the
-- clock is known to be right (_clock_trusted): the firmware keeps every
-- VAP up until NTP has set the time, and after a boot every VAP starts up.
-- Once a minute: is hostapd's 802.11r key-exchange socket still bound? See
-- rrbguard.lua. The night repair window needs a trusted clock; without one
-- only the no-clients path can repair.
function M._rrbguard_tick()
	local g = M._rrbguard
	if not (g and g.tick) then return nil end
	local now = M._time()
	local hour = M._clock_trusted() and os.date("*t", now).hour or nil
	return g.tick(now, hour)
end

function M._sched_resync(st)
	local ufuci = M._ucihelper
	if not (ufuci and ufuci.schedule_vaps) then return false end
	if not M._clock_trusted() then return false end
	local ok, vaps = pcall(ufuci.schedule_vaps)
	if not ok or type(vaps) ~= "table" then return false end
	if #vaps == 0 and not st.sched_vaps_down then return false end
	local t = os.date("*t", M._time())
	local down = M._wlansched.down_set(vaps, t.wday - 1, t.hour * 60 + t.min)
	local keep = {}
	for _, n in ipairs(st.guest_vaps_down or {}) do keep[n] = true end
	local held, changed = M._wlansched.reconcile(down, st.sched_vaps_down, keep)
	if #changed.down > 0 then
		io.stderr:write("wlansched: outside the WLAN schedule -- down: "
			.. table.concat(changed.down, " ") .. "\n")
	end
	if #changed.up > 0 then
		io.stderr:write("wlansched: inside the WLAN schedule again -- up: "
			.. table.concat(changed.up, " ") .. "\n")
	end
	if #held == 0 then held = nil end
	local before = table.concat(st.sched_vaps_down or {}, " ")
	if before ~= table.concat(held or {}, " ") then
		st.sched_vaps_down = held
		M._state.save(st)
	end
	return #changed.down > 0 or #changed.up > 0
end

-- The firmware's /var/run/ntp.ready, which its ntpclient writes once it has
-- set the clock. OpenWrt's ntpd leaves no such mark, so openUF writes its
-- own once a controller answer's server_time_in_utc agrees with the local
-- clock. Under /var/run like the firmware's: it outlives a restart of
-- openUF, not a reboot.
M.CLOCK_OK_FILE = "/var/run/openuf.clock-ok"
M.CLOCK_MAX_SKEW = 60
M._clock_ok = false
function M._clock_trusted()
	if M._clock_ok then return true end
	M._clock_ok = M._read_file(M.CLOCK_OK_FILE) ~= nil
	return M._clock_ok
end
function M._note_server_time(resp)
	if M._clock_ok or type(resp) ~= "table" then return end
	local ms = tonumber(resp.server_time_in_utc)
	if not ms then return end
	if math.abs(M._time() - ms / 1000) <= M.CLOCK_MAX_SKEW then
		M._clock_ok = true
		M._touch(M.CLOCK_OK_FILE)
	end
end
M._touch = function(path)
	local f = io.open(path, "w")
	if f then f:close() end
end

-- The guest's SSID for the portal's ssid=: the only one, or the VAP that
-- has the station.
M._station_on = function(ifname, mac)
	local p = io.popen("iw dev " .. ifname .. " station get " .. mac .. " 2>/dev/null")
	if not p then return false end
	local out = p:read("*a") or ""
	p:close()
	return out:find("Station", 1, true) ~= nil
end

function M._guest_ssid_for(vaps, mac)
	local first, single = nil, true
	for _, v in ipairs(vaps or {}) do
		if first == nil then first = v.ssid elseif v.ssid ~= first then single = false end
	end
	if single then return first end
	for _, v in ipairs(vaps) do
		if v.ifname:match("^[%w%-%._]+$") and M._station_on(v.ifname, mac) then return v.ssid end
	end
	return first
end

M._read_arp = function()
	local f = io.open("/proc/net/arp", "r")
	if not f then return "" end
	local s = f:read("*a")
	f:close()
	return s or ""
end

-- The STUN client (stun.lua): opened while the AP is managed and the
-- controller named a STUN server, closed otherwise. Once per tick, before
-- the inform, so a Binding Request goes out every stun.INTERVAL seconds.
M._stun_c = nil
function M._stun_tick(st)
	local c = M._stun_c
	if not c then
		c = M._stun.new(M._socket())
		M._stun_c = c
	end
	-- The firmware runs STUN only while managed: not unadopted, and not in
	-- selfrun (GUEST_SELFRUN_FAILS informs unanswered).
	local active = st.adopted == true and M._inform_fails < M.GUEST_SELFRUN_FAILS
	local ok, err = M._stun.sync(c, st.stun_url, active)
	if ok then
		local _, err2 = M._stun.send_due(c, M._time())
		err = err2
	end
	-- Said once per distinct failure, not every retry.
	if err and err ~= c.last_err then
		io.stderr:write("inform: stun: " .. tostring(err) .. "\n")
	end
	c.last_err = err
end

-- Read the STUN socket. True when the controller asked for an inform, or
-- the mapped address it should send that request to changed.
function M._stun_wake()
	local c = M._stun_c
	if not c then return false end
	local ok, wake = pcall(M._stun.receive, c)
	return ok and wake == true
end

-- Sleep for wait seconds. Meanwhile answer guests while the portal listens,
-- and end early when the STUN socket says to inform now.
function M._idle(socket, wait)
	local deadline = socket.gettime() + wait
	local server_ok = true
	-- Roam reports: wake every ROAM_POLL_S to look at the collector.
	local fast = M._roam_fast
	while true do
		local left = deadline - socket.gettime()
		if left <= 0 then return end
		local step = fast and math.min(left, M.ROAM_POLL_S) or left
		local server = server_ok and M._guest_server or nil
		local stun_sock = M._stun_c and M._stun_c.sock
		if not server and not stun_sock then
			socket.select(nil, nil, step)
			if not fast then return end
		else
			local list = {}
			if server then list[#list + 1] = server end
			if stun_sock then list[#list + 1] = stun_sock end
			local r = socket.select(list, nil, step)
			local server_r, stun_r = false, false
			for _, s in ipairs(r or {}) do
				if s == stun_sock then stun_r = true
				elseif s == server then server_r = true end
			end
			if stun_r and M._stun_wake() then return end
			if server_r then
				local ctx = M._guest_ctx or {}
				local ok, served = pcall(M._guestportal.serve_one, server, {
					url = ctx.url, ap = ctx.ap,
					ssid_for = function(mac) return M._guest_ssid_for(ctx.vaps, mac) end,
					arp = M._read_arp, now = M._time,
				})
				-- Readable but nothing to accept: do not spin on it.
				if not (ok and served) then server_ok = false end
			end
		end
		if fast then pcall(M._roam_poll) end
	end
end

-- Replace the block ledger with the controller's list (setparam blocked_sta)
-- and rebuild the nft set, but only when the set of MACs changed: reconcile
-- drops and recreates the table, so redoing it on every push would open a
-- gap for nothing. A MAC new to the ledger is deauthed as block-sta does.
-- Returns true when the ledger changed.
function M._sync_blocked_stas(st, raw)
	local list, want = {}, {}
	for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
		local mac = line:lower():match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s*$")
		if mac then
			if not want[mac] then want[mac] = true; list[#list + 1] = mac end
		elseif line:match("%S") then
			io.stderr:write(("inform: blocked_sta: ignoring %q\n"):format(line))
		end
	end
	local have, n_have = {}, 0
	for _, m in ipairs(st.blocked_stas or {}) do
		m = tostring(m):lower()
		if not have[m] then have[m] = true; n_have = n_have + 1 end
	end
	local changed = (n_have ~= #list)
	for _, m in ipairs(list) do
		if not have[m] then changed = true break end
	end
	if not changed then return false end
	st.blocked_stas = list
	M._firewall.reconcile(list)
	M._deny_pending = true
	pcall(M._block_resync, st)
	local ifnames
	for _, m in ipairs(list) do
		if not have[m] then
			ifnames = ifnames or M._bss_ifnames()
			M._firewall.deauth(m, ifnames)
		end
	end
	return true
end

-- A block's refusal in hostapd (firewall.deny_sync) is lost whenever hostapd
-- restarts or reloads a BSS. A sync forks a shell, one hostapd_cli per BSS
-- and a grep, so while anything is blocked it runs:
--   - every tick while _deny_pending: set at startup (entries from before a
--     restart get looked at), by a block change and a state reload, and kept
--     by a sync that did not settle (a BSS that did not answer, a change still
--     to read back), until a pass finds nothing left to clean;
--   - on any tick that finds a hostapd control socket replaced (a restart, a
--     BSS rebuilt: firewall.hostapd_sockets, a file read);
--   - every tick for DENY_SETTLE seconds after openUF's own `wifi reload`
--     (_deny_reloaded), which lands asynchronously and can reload a BSS in
--     place, keeping its socket;
--   - and otherwise every DENY_INTERVAL seconds, the bound on a reload in
--     place that openUF did not run (LuCI, a `wifi reload` by hand). Until
--     then the client can associate, and the nft drop still stops its traffic.
M.DENY_INTERVAL = 60
M.DENY_SETTLE   = 60
M._deny_pending = true
M._deny_at, M._deny_socks, M._deny_settle = nil, nil, nil
function M._deny_reloaded()
	M._deny_settle = M._time() + M.DENY_SETTLE
end
function M._block_resync(st)
	local list = st and st.blocked_stas or {}
	if #list == 0 and not M._deny_pending then return false end
	local now = M._time()
	local socks = M._firewall.hostapd_sockets()
	local since = M._deny_at and now - M._deny_at
	local settle = M._deny_settle and M._deny_settle - now
	local due = M._deny_pending or socks ~= M._deny_socks
		or not since or since < 0 or since >= M.DENY_INTERVAL
		-- A clock stepped back must not stretch the window.
		or (settle and settle > 0 and settle <= M.DENY_SETTLE)
	if not due then return false end
	M._deny_at, M._deny_socks = now, socks
	M._deny_pending = M._firewall.deny_sync(list, M._bss_ifnames())
	return true
end

function M._bss_ifnames()
	local ufuci = M._ucihelper
	if not (ufuci and ufuci.ap_ifnames) then return {} end
	local ok, names = pcall(ufuci.ap_ifnames)
	if not ok or type(names) ~= "table" then return {} end
	local out, seen = {}, {}
	for _, name in ipairs(names) do
		local bss = ufuci.bss_ifname and ufuci.bss_ifname(name) or name
		if not seen[bss] then
			seen[bss] = true
			out[#out + 1] = bss
		end
	end
	return out
end

-- ─── HTTP POST ───────────────────────────────────────────────────────────────

-- POST a binary payload to the inform URL.
-- Returns the raw response body or nil, error_msg.
function M.http_post(url, body)
	if M._http_post then
		return M._http_post(url, body)
	end

	-- Parse URL
	local scheme, host, port, path = url:match("^(https?)://([^:/]+):?(%d*)(.*)")
	if not host then return nil, "invalid URL: " .. tostring(url) end
	local is_tls = (scheme == "https")
	port = tonumber(port) or (is_tls and 8443 or 8080)
	if path == "" then path = "/inform" end

	local socket = require("socket")
	local tcp = socket.tcp()
	tcp:settimeout(10)
	local ok, err = tcp:connect(host, port)
	if not ok then
		tcp:close()
		return nil, "connect failed: " .. tostring(err)
	end

	-- For https, wrap the socket in TLS. Previously the scheme was accepted but
	-- ignored, so an https:// URL sent the inform in cleartext to a TLS port and
	-- failed opaquely. Controllers use self-signed certs, so verification is off.
	if is_tls then
		local ok_ssl, ssl = pcall(require, "ssl")
		if not ok_ssl then
			tcp:close()
			return nil, "https inform URL requires luasec (apk add luasec); " ..
				"install it or use an http:// URL"
		end
		local wrapped, werr = ssl.wrap(tcp, {
			mode = "client", protocol = "any", verify = "none", options = "all",
		})
		if not wrapped then
			tcp:close()
			return nil, "TLS wrap failed: " .. tostring(werr)
		end
		tcp = wrapped
		tcp:settimeout(10)
		local ok_h, herr = tcp:dohandshake()
		if not ok_h then
			tcp:close()
			return nil, "TLS handshake failed: " .. tostring(herr)
		end
	end

	local req = table.concat({
		"POST " .. path .. " HTTP/1.0\r\n",
		"Host: " .. host .. ":" .. tostring(port) .. "\r\n",
		"Content-Type: application/x-binary\r\n",
		"Content-Length: " .. #body .. "\r\n",
		"\r\n",
		body
	})

	tcp:send(req)

	-- Read response (HTTP/1.0 — server closes after response). With a numeric
	-- pattern LuaSocket reads *exactly* N bytes and, when the peer closes before
	-- N arrive, returns (nil, "closed", partial). The inform response is almost
	-- always smaller than one read, so the body lives entirely in that `partial`
	-- third value — it must be captured or every response is silently lost
	-- ("HTTP nil") and adoption never completes.
	local response = {}
	while true do
		local chunk, recv_err, partial = tcp:receive(4096)
		if chunk then
			response[#response + 1] = chunk
		else
			if partial and #partial > 0 then
				response[#response + 1] = partial
			end
			if recv_err ~= "closed" then
				tcp:close()
				return nil, "recv error: " .. tostring(recv_err)
			end
			break
		end
	end
	tcp:close()

	local full = table.concat(response)
	-- Extract HTTP status
	local status = tonumber(full:match("HTTP/%S+ (%d+)"))
	if status ~= 200 then
		return nil, "HTTP " .. tostring(status)
	end

	-- Return body (after blank line separating headers)
	local body_start = full:find("\r\n\r\n")
	if body_start then
		return full:sub(body_start + 4)
	end
	return full
end

-- ─── Main loop ───────────────────────────────────────────────────────────────

-- Populate st.mac / st.ip using announce.lua's get_mac/get_ip helpers.
--
-- _require_sibling dofile()s announce.lua fresh every call (dofile, unlike
-- require, never caches), which re-runs its self-executing "script entry
-- point" block at the bottom -- that block is guarded by
-- `if not OPENUF_TEST_MODE`, so outside of tests (where it's already true)
-- this would spawn announce.lua's own *infinite* L2 broadcast loop nested
-- inside inform.lua's own M.run, or -- if the broadcast send errors, as it
-- does e.g. on a docker bridge network that disallows UDP broadcast -- call
-- os.exit(1) and kill the whole inform process before the actual inform loop
-- ever runs. Suppress it for the duration of just this reuse-only dofile.
function M._populate_net_info(st, cfg)
	local prev_test_mode = OPENUF_TEST_MODE
	OPENUF_TEST_MODE = true
	local ok_ann, announce = pcall(_require_sibling, "announce")
	OPENUF_TEST_MODE = prev_test_mode
	if not ok_ann then return end

	local iface = cfg and cfg.net and cfg.net.lan_cpueth or "eth1"
	local mac_tbl = announce.get_mac(iface)
	if mac_tbl then
		-- Format as "xx:xx:xx:xx:xx:xx"
		st.mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
			mac_tbl[1], mac_tbl[2], mac_tbl[3],
			mac_tbl[4], mac_tbl[5], mac_tbl[6])
	end
	local ip_tbl = announce.get_ip(iface)
	if ip_tbl then
		st.ip = string.format("%d.%d.%d.%d",
			ip_tbl[1], ip_tbl[2], ip_tbl[3], ip_tbl[4])
	end
	-- Without this the payload's top-level hostname fell back to "openUF"
	-- for every device (the doc comments always claimed hostname was
	-- populated here, but only mac/ip ever were). Feature-detected so an
	-- older announce module without get_hostname degrades to the fallback.
	local hostname = announce.get_hostname and announce.get_hostname()
	if hostname then st.hostname = hostname end
end

-- Airtime Fairness is debugfs state, back at the kernel's default (on) after
-- every reboot, and the controller does not push it again (cfgversion
-- matches). Reapplied at startup from state.json; nil means never pushed, and
-- the board's default stays. Returns whether it wrote.
function M._reapply_airtime(st)
	if not (st and st.atf_enabled ~= nil and M._airtime) then return false end
	pcall(M._airtime.set_enabled, st.atf_enabled)
	return true
end

-- What a controller left behind outside state.json, torn down when the
-- device stops being adopted -- a `setdefault` (controller "Forget") or an
-- out-of-process `syswrapper.sh reset-inform`. UniFi firmware answers
-- setdefault with a factory reset and reboot (`syswrapper.sh
-- restore-default`, firmware-confirmed for 4.0.15), so a forgotten UAP comes
-- back with no SSID and no VLAN. This reaches the same end state without the
-- reboot: the WLANs, VLAN bridges and radio extras (ucihelper.forget), the
-- per-port VLANs, band steering, the l2guard and guest portal rules, the
-- nightly 11k-scan cron job, Airtime Fairness and a switched-off LED. A long
-- noop interval would also slow re-adoption to one attempt per interval.
--
-- prev is the state from BEFORE the reset: the per-port VLAN ledger
-- (swvlan_backup, dsa_brlan_ports) and led_enabled live only there, and the
-- reset has already cleared them from st by the time this runs.
--
-- Kept: the pushed timezone and NTP servers (sane for the board either way,
-- originals stamped in UCI, USAGE § 6), the radios' channel, width, power and
-- country (see ucihelper.forget), and the management address, which a
-- reset to DHCP could take off the network.
function M._forget_controller(prev, cfg)
	prev = prev or {}
	M._controller_interval = nil
	if M._switchvlan then pcall(M._switchvlan.restore, prev, cfg) end
	if M._usteer then pcall(M._usteer.set_enabled, false, cfg, false) end
	if M._ucihelper and M._ucihelper.forget then
		pcall(M._ucihelper.forget)
		M._deny_reloaded()   -- forget ran `wifi reload`
	end
	if M._l2guard then pcall(M._l2guard.reconcile, nil, {}) end
	if M._guestportal then pcall(M._guest_enforce, {}) end
	if M._sysconf then pcall(M._sysconf.apply_cron, {enabled = false, jobs = {}}) end
	-- A controller that switched Airtime Fairness off no longer does.
	if M._airtime then pcall(M._airtime.set_enabled, true) end
	if prev.led_enabled == false and M._led then
		pcall(M._led.set_enabled, cfg and cfg.led, true)
	end
end

-- Detects an out-of-process change to the on-disk state file -- written by
-- syswrapper.lua's set-adopt/reset-inform, invoked over SSH as a separate,
-- short-lived process -- and reloads it into the in-memory st table this
-- loop uses. Without this, a long-running inform.lua would never notice a
-- fresh SSH-driven adoption (or a manual reset-inform) and would keep
-- informing with stale credentials until restarted. Also keeps the SSH
-- bootstrap account (if enabled) locked/unlocked to match the reloaded
-- adopted state. Returns the current mtime (unchanged from last_mtime if
-- the file didn't change).

function M._reload_if_changed(st, cfg, last_mtime)
	local mtime = M._state_mtime(M._state._state_file)
	if mtime == nil or mtime == last_mtime then
		return last_mtime
	end
	-- This process's own state.save: st already holds it. Reloading would
	-- only rebuild the blocklist table (a drop gap) and re-run the deny sync.
	if mtime == M._state.last_written then
		return mtime
	end
	local was_adopted = st.adopted
	local prev = {}
	for k, v in pairs(st) do prev[k] = v end
	-- mac/ip/hostname are populated once at M.run() startup and never
	-- persisted to state.json -- preserve them across the reload.
	local mac, ip, hostname = st.mac, st.ip, st.hostname
	local fresh = M._state.load()
	for k in pairs(st) do st[k] = nil end
	for k, v in pairs(fresh) do st[k] = v end
	st.mac, st.ip, st.hostname = mac, ip, hostname
	M._sync_bootstrap_account(st.adopted, cfg and cfg.config and cfg.config.bootstrap_adopt_user)
	M._firewall.reconcile(st.blocked_stas)
	M._deny_pending = true
	if was_adopted and not st.adopted then M._forget_controller(prev, cfg) end
	return mtime
end

-- dev.conf.net.lan_cpueth decides the device's IDENTITY, not just which port
-- carries VLANs: its MAC is what the controller keys the adopted device on.
-- Change it on an already-adopted device -- switching modelmaps, say -- and
-- every inform afterwards arrives under a MAC the controller has no adoption
-- for, so it rejects them (HTTP 400) while the old record sits there going
-- Offline. That is invisible from the device: the daemon is healthy, the
-- config is right, the radios are up, and the log just fills with anonymous
-- 400s. Observed for real when a board-specific modelmap moved lan_cpueth
-- from the (unused) WAN socket to the LAN trunk, which have different MACs.
-- Returns true when it warned, so this is testable without running the loop.
-- require("uci") comes from libuci-lua, which `lua` does not pull in and which
-- nothing installed until recently. Every ucihelper call is pcall-wrapped --
-- correctly, since a UCI error off-target must not take the inform loop down
-- -- so without the binding the daemon starts, adopts, reports its ethernet
-- ports and its statistics and looks completely healthy, while
-- get_radio_table() returns nothing and radio_table goes out EMPTY. The
-- controller then has no radio to provision a WLAN onto: the push arrives, is
-- accepted, and not one SSID is ever created. Nothing logs, nothing errors,
-- and the controller UI shows the device Connected.
--
-- Startup-only, and deliberately not fatal: a device with no UCI binding still
-- reports statistics usefully, and killing the daemon would lose that too.
-- Returns true when it warned, so this is testable without running the loop.
-- The symptom _warn_identity_change predicts, caught where it actually shows.
-- When dev.conf.net.lan_cpueth changes under an adopted device, every inform
-- afterwards arrives under a MAC the controller has no adoption for, so it
-- rejects them with HTTP 400 while the old record sits there going Offline.
-- That is invisible from the device -- the daemon is healthy, the config is
-- right, the radios are up -- and the log just fills with anonymous 400s.
-- _warn_identity_change needs the PREVIOUS MAC to compare against and fires at
-- startup; this one fires on the symptom itself, once per streak, so the log
-- names the likely cause. Returns true when it warned.
M._warned_400 = false
function M._warn_http_400(err, st, cfg)
	if M._warned_400 or not (st and st.adopted) then return false end
	if not (type(err) == "string" and err:match("^HTTP 400")) then return false end
	M._warned_400 = true
	io.stderr:write(string.format(
		"openuf: the controller rejects every inform with HTTP 400 although this\n" ..
		"openuf: device is adopted. That is what happens when the identity MAC\n" ..
		"openuf: changed underneath an adoption: this run informs as %s off\n" ..
		"openuf: dev.conf.net.lan_cpueth = %s. If the controller adopted a\n" ..
		"openuf: different MAC, Forget the device there and re-adopt, or point\n" ..
		"openuf: lan_cpueth back at the interface it was adopted under.\n",
		tostring(st.mac), tostring(cfg and cfg.net and cfg.net.lan_cpueth)))
	return true
end

function M._warn_missing_uci()
	if package.loaded["uci"] then return false end
	if pcall(require, "uci") then return false end
	io.stderr:write(
		"openuf: the Lua UCI binding is MISSING (require(\"uci\") failed).\n" ..
		"openuf: WiFi provisioning cannot work at all: every radio and WLAN\n" ..
		"openuf: read/write fails silently, the inform payload reports ZERO\n" ..
		"openuf: radios, and the controller has nothing to push a WLAN onto --\n" ..
		"openuf: adoption and statistics still work, so nothing else looks wrong.\n" ..
		"openuf: Fix it with:  apk add libuci-lua      (25.12+)\n" ..
		"openuf:               opkg install libuci-lua (24.10 and earlier)\n")
	return true
end

function M._warn_identity_change(prev_mac, st, cfg)
	if not (st and st.adopted and prev_mac and st.mac) then return false end
	if prev_mac == st.mac then return false end
	io.stderr:write(string.format(
		"openuf: IDENTITY MAC CHANGED %s -> %s (dev.conf.net.lan_cpueth = %s).\n" ..
		"openuf: this device was adopted as %s, so the controller will reject\n" ..
		"openuf: informs from %s with HTTP 400 and show the old record Offline.\n" ..
		"openuf: Forget the device in the controller and re-adopt it, or point\n" ..
		"openuf: lan_cpueth back at the interface whose MAC is %s.\n",
		prev_mac, st.mac, tostring(cfg and cfg.net and cfg.net.lan_cpueth),
		prev_mac, st.mac, prev_mac))
	return true
end

-- Reapply a controller-pushed static IP at startup.
--
-- A static IP is live kernel state, not UCI: netconfig.apply_static() is
-- `ip addr`/`ip route` only, so the address is gone after a reboot and netifd
-- brings the interface back up on whatever the board's own config says. The
-- controller does not re-push it either -- cfgversion is persisted, so it
-- matches on the first inform and the reply is a noop carrying no system_cfg
-- at all. Without this the device silently returns to DHCP (or to no address)
-- while the controller's IP Settings page goes on showing the static one it
-- assigned. Mirrors the blocked-client and LED reconciliation in M.run.
--
-- Only ip_mode == "static" acts. On "dhcp", and when IP Settings was never
-- pushed at all, the board's own boot config is already right, and flushing
-- the interface to re-lease would be exactly the destructive no-op that the
-- steady-state DHCP push is guarded against (see handle_response).
function M._reapply_static_ip(st, cfg)
	if not st or st.ip_mode ~= "static" or not st.static_ip then return false end
	local iface = cfg and cfg.net and cfg.net.lan_cpueth
	return M._netconfig.apply_static(iface, st.static_ip, st.static_netmask,
		st.static_gateway, st.static_dns) and true or false
end

-- Start the inform heartbeat loop (blocks forever).
-- cfg, ufhw: passed through to build_json()
-- One cycle of the client-assisted enrichment: keep the notification
-- collector alive, fold in whatever clients have reported since last time,
-- expire what the controller would discard anyway, and -- at most every
-- RRM_REQUEST_INTERVAL -- ask one more station to go and look.
--
-- Everything here is pcall-wrapped and best-effort: no hostapd, no ubus, no
-- capable client and no answer are all ordinary outcomes, and none of them may
-- interrupt an inform.
-- Connection tracking runs only when the controller asked for it (mgmt_cfg
-- capability notif-assoc-stat) and conf.lua has not switched it off.
function M._assoc_enabled(st, cfg)
	if not M._assoctrack or type(st) ~= "table" or st.notif_assoc_stat ~= true then
		return false
	end
	return not (cfg and cfg.config and cfg.config.assoc_tracker == false)
end

-- Fold the drained collector lines into connection attempts and decide the
-- ones that are complete. The nft listing is skipped while nobody is
-- mid-connection, which is nearly every heartbeat.
--
-- Returns the parsed event list, which is the only walk of these lines: the
-- radar records in it are _dfs_poll's.
function M._assoc_poll(blob)
	local at = M._assoctrack
	local evs = at.parse_events(blob)
	at.ingest(evs)
	at.roam_ingest(evs, M._vap_by_ifname)
	if next(at._stas) == nil then return evs end
	local up = tonumber(((M._read_file("/proc/uptime") or ""):match("^(%S+)")))
	if not up then return evs end
	at.poll({
		now = up, epoch = M._time(), sets = at.read_sets(up),
		vap_by_ifname = M._vap_by_ifname,
	})
	return evs
end

-- Kill a collector nobody wants any more, and stop asking once it is gone.
--
-- The question costs a `pgrep` and the answer cannot change behind our back:
-- nothing starts a collector except collector_ensure, which clears the latch.
-- Without it a DFS-only site -- or one that never had enrichment on at all --
-- pays that pgrep every RRM_COLLECTOR_CHECK_INTERVAL for as long as the daemon
-- runs, to be told the same thing every time.
function M._reap_collector(rrm)
	if M._collector_reaped or not (rrm and rrm.collector_running) then return end
	local ok, running = pcall(rrm.collector_running)
	if not ok then return end
	if running then
		-- Not latched on a stop: collector_stop is a `kill` whose success is
		-- not read back, and a child that survived it is exactly the unbounded
		-- append this check exists to stop. The next interval asks again.
		pcall(rrm.collector_stop)
		return
	end
	M._collector_reaped = true
end

-- Is there anything in the collector's event file? An open and a seek, against
-- drain()'s read of the whole file plus the truncating rewrite that follows it
-- -- and on a site where the collector is not running (DFS only) the file does
-- not exist at all, so the answer is one failed open per heartbeat.
function M._events_pending(rrm)
	-- No file to look at (a test's stub, a future collector that keeps its
	-- lines elsewhere): drain and let it answer, as before.
	if not rrm.EVENT_FILE then return true end
	local f = io.open(rrm.EVENT_FILE, "r")
	if not f then return false end
	local size = f:seek("end")
	f:close()
	return (tonumber(size) or 0) > 0
end

-- The hostapd event collector serves two consumers: 802.11k enrichment
-- (rrm_enrichment) and connection tracking. It runs while either wants it,
-- and the file it fills is drained once per heartbeat for both.
function M._rrm_tick(cfg, st)
	local rrm = M._rrmscan
	if not rrm then return false end
	local rrm_on   = cfg and cfg.config and cfg.config.rrm_enrichment
	local assoc_on = M._assoc_enabled(st, cfg)
	M._roam_fast, M._roam_st = assoc_on and rrm.drain ~= nil, st
	M._roam_keep = rrm_on and true or false
	if not (assoc_on and rrm_on) then M._pre_blob = nil end
	-- A radio that can see radar is a third consumer of the control-socket
	-- monitors, alongside 802.11k enrichment and connection tracking. Without
	-- it in this condition the whole path below is skipped -- and the branch
	-- stops the collector and deletes the event file -- so on a site with
	-- neither of the other two the radar event would never be sent.
	local dfs_on = M._dfs_radio and true or false
	if not rrm_on and not assoc_on and not dfs_on then
		-- Enrichment is off, but a collector from an earlier run with it ON may
		-- still be alive: it is a detached `ubus subscribe` child reparented to
		-- init, so it outlives both the config change and the daemon. Nothing
		-- below this line runs any more, and harvest() is the ONLY thing that
		-- truncates the notification file -- so left alone the child appends to
		-- /tmp/openuf-rrm.jsonl forever with no reader and no cap. /tmp is a
		-- RAM disk on these boards; the debug-dump cap above exists because
		-- 31.7 MB there was measured starving state.json writes and apk.
		--
		-- Rate-limited on the collector's own liveness clock rather than run
		-- every tick: this is a pgrep, and there is nothing to catch between
		-- checks once the child is gone. Latched on top of that (see
		-- M._collector_reaped): a site that never had enrichment on, or had it
		-- on and has since been cleaned up, would otherwise pgrep every 60 s
		-- for the lifetime of the daemon to learn the same thing every time.
		local now = M._time()
		if now >= M._rrm_collector_next then
			M._rrm_collector_next = now + M.RRM_COLLECTOR_CHECK_INTERVAL
			M._reap_collector(rrm)
			if M._assoc_installed then
				pcall(M._assoctrack.teardown)
				M._assoc_installed = false
			end
		end
		return false
	end

	-- On M._time(), the seam the rest of the timed paths use, so the gate below
	-- is testable. Note this is also the clock the age-out compares against,
	-- and n.seen_at comes from rrmscan's own M._now -- a test that stubs one
	-- must stub the other, or "freshness" is measured between two clocks.
	local now = M._time()
	if now >= M._rrm_collector_next then
		M._rrm_collector_next = now + M.RRM_COLLECTOR_CHECK_INTERVAL
		-- The table first: the collector's on_auth hook writes into it.
		if assoc_on then
			local ok_t, inst = pcall(M._assoctrack.ensure_table)
			M._assoc_installed = (ok_t and inst) or M._assoc_installed
		elseif M._assoc_installed then
			pcall(M._assoctrack.teardown)
			M._assoc_installed = false
		end
		-- The `ubus subscribe` half serves enrichment and connection tracking
		-- only: the radar event comes off the control socket, so a DFS-only
		-- site pays for the monitors and not for the subscriber.
		if rrm_on or assoc_on then
			pcall(rrm.collector_ensure,
				assoc_on and {on_auth = M._assoctrack.forget_shell("m"), fdb = true} or nil)
			-- A collector is wanted again, so whatever the latch below learned
			-- about there not being one no longer holds.
			M._collector_reaped = false
		else
			-- DFS only: no subscriber is wanted, and one left over from a run
			-- with enrichment on is a detached child that would append to the
			-- event file forever. collector_stop also takes the monitors and
			-- the file with it, so it runs before monitors_ensure below.
			M._reap_collector(rrm)
		end
		-- The control-socket monitors serve the 802.11k enrichment and the
		-- DFS radar event: connection tracking reads the ubus lines alone.
		-- M._dfs_radio is what build_json saw on the last cycle -- one cycle
		-- stale, which costs nothing on a check that runs every
		-- RRM_COLLECTOR_CHECK_INTERVAL.
		if rrm_on or dfs_on then
			if rrm.monitors_ensure then pcall(rrm.monitors_ensure) end
		elseif rrm.monitors_stop then
			pcall(rrm.monitors_stop)
		end
	end

	-- A quiet event file is the common case -- on a DFS-only site it is every
	-- heartbeat, since nothing is subscribing -- so the size is checked before
	-- draining, the way _roam_poll already does between heartbeats.
	local blob
	if rrm.drain and M._events_pending(rrm) then
		local ok_d, b = pcall(rrm.drain)
		if ok_d then blob = b end
	end
	local evs
	if assoc_on then
		local ok_a, res = pcall(M._assoc_poll, blob)
		if ok_a then evs = res
		else io.stderr:write("inform: assoctrack: " .. tostring(res) .. "\n") end
	end
	-- Before the rrm_on return: a radar hit is reported whether or not 802.11k
	-- enrichment is on, and the monitors that produce it run on the DFS gate.
	-- `evs` is the walk _assoc_poll already did over these same lines: with
	-- connection tracking on, the radar records come out of it instead of a
	-- second gmatch pass over the blob. Nothing drained, nothing to look at.
	if blob and blob ~= "" then pcall(M._dfs_poll, blob, evs) end
	if not rrm_on then return true end
	-- Lines _idle drained since the last heartbeat were ingested there; the
	-- beacon reports among them are still the harvest's.
	if M._pre_blob then
		local chunks = M._pre_blob
		chunks[#chunks + 1] = blob or ""
		blob, M._pre_blob = table.concat(chunks), nil
	end

	-- `blob or ""`, never a bare nil: harvest drains the file itself when it is
	-- handed nothing, which would undo the size gate above (and re-read a file
	-- a failed drain has already emptied).
	local ok, fresh, reporters = pcall(rrm.harvest, blob or "")
	if ok then
		-- A station that answered is off the bench, whatever it reported.
		for mac in pairs(reporters or {}) do M._rrm_asked[mac] = nil end
		for _, n in ipairs(fresh or {}) do
			-- Keyed by BSSID so a neighbour two clients both saw is carried
			-- once, at whichever sighting is freshest.
			local prev = M._rrm_cache[n.bssid]
			if not prev or n.seen_at >= prev.seen_at then
				-- hostapd emits each report twice: on the control socket with
				-- the neighbour's beacon body, then over ubus without. The two
				-- reach the event file through different processes and land in
				-- different drains often enough (live, 2026-10-13: every row of
				-- one office report went out unnamed, on the 80 MHz centre
				-- channel 42 at 20 MHz). A bodiless copy keeps what the body
				-- proved about the same BSS instead of erasing it.
				if prev and prev.body and not n.body and prev.band == n.band then
					n.essid, n.security, n.bw = prev.essid, prev.security, prev.bw
					n.channel, n.body = prev.channel, true
				end
				M._rrm_cache[n.bssid] = n
			end
		end
	end

	local live = {}
	for bssid, n in pairs(M._rrm_cache) do
		if now - n.seen_at < RRM_MAX_AGE then
			live[#live + 1] = n
		else
			M._rrm_cache[bssid] = nil
		end
	end
	table.sort(live, function(a, b) return a.bssid < b.bssid end)
	M._rrm_neighbours = live

	if now < M._rrm_next_request then return true end
	M._rrm_next_request = now +
		(tonumber(cfg.config.rrm_request_interval) or M.RRM_REQUEST_INTERVAL)

	-- Round-robin across every capable station on every BSS, one per
	-- interval. Asking them all at once would take every 802.11k-capable
	-- client in the house off-channel simultaneously.
	local cands = {}
	local ok_o, objs = pcall(rrm.hostapd_objects)
	for _, obj in ipairs(ok_o and objs or {}) do
		local ifname = obj:match("^hostapd%.(.+)$")
		local ok_s, stas = pcall(rrm.capable_stations, ifname)
		for _, sta in ipairs(ok_s and stas or {}) do
			local key   = tostring(sta):lower()
			local asked = M._rrm_asked[key]
			local spent = asked and asked.n >= M.RRM_MAX_UNANSWERED
			if spent and (now - asked.at) >= M.RRM_BENCH_SECONDS then
				M._rrm_asked[key] = nil   -- bench over: one more try, clean count
				spent = false
			end
			if not spent then
				cands[#cands + 1] = {ifname = ifname, sta = sta}
			end
		end
	end
	if #cands == 0 then return true end
	M._rrm_rr = (M._rrm_rr % #cands) + 1
	local c = cands[M._rrm_rr]
	local key = tostring(c.sta):lower()
	local asked = M._rrm_asked[key] or {n = 0}
	asked.n, asked.at = asked.n + 1, now
	M._rrm_asked[key] = asked
	if asked.n == M.RRM_MAX_UNANSWERED then
		io.stderr:write(string.format(
			"openuf: rrm: %s on %s advertises beacon measurement but has answered none "
			.. "of %d requests -- not asking again for %d h\n",
			c.sta, c.ifname, asked.n - 1, math.floor(M.RRM_BENCH_SECONDS / 3600)))
	end
	-- The operating class has to be one the CLIENT can measure. Asking every
	-- station for class 115 (5 GHz U-NII-1) works for a dual-band client --
	-- they ignore the band restriction and answer for 2.4 GHz too -- but a
	-- 2.4 GHz-only station answers it with report mode 0x02, "incapable", and
	-- an all-zero BSSID, which is nothing at all. So a station on a 2.4 GHz
	-- BSS is asked for class 81 (2.4 GHz, channels 1-13) instead; the band
	-- comes from that BSS's live channel.
	local op_class = 115
	local ok_c, caps = pcall(M._sysinfo.radio_caps, c.ifname)
	if ok_c and type(caps) == "table" and caps.channel and caps.channel <= 14 then
		op_class = 81
	end
	pcall(rrm.request, c.ifname, c.sta, {op_class = op_class})
	return true
end

-- ─── The controller's ebtables hardening (l2guard.lua) ──────────────────────

function M._l2guard_live_ifnames()
	local ufuci = M._ucihelper
	if not (ufuci and ufuci.ap_ifnames) then return {} end
	local ok, names = pcall(ufuci.ap_ifnames)
	return (ok and type(names) == "table") and names or {}
end

local function same_names(a, b)
	if type(a) ~= "table" or type(b) ~= "table" or #a ~= #b then return false end
	for i = 1, #a do if a[i] ~= b[i] then return false end end
	return true
end

-- A push's ebtables.* block -> st.l2guard, and the table rebuilt. A push
-- without the block (a partial one) leaves the current state alone.
function M._l2guard_apply_push(sys_raw, st)
	local eb = M._l2guard.parse(sys_raw)
	if not eb then return false end
	for _, u in ipairs(eb.unknown or {}) do
		-- The guest portal's rules are guestportal.lua's to read.
		if not (M._guestportal and M._guestportal.is_guest_rule(u)) then
			io.stderr:write("l2guard: unrecognised ebtables rule shape, not applied: "
				.. ("%q"):format(u) .. "\n")
		end
	end
	local spec = M._l2guard.spec_from(eb)
	local names = M._l2guard_live_ifnames()
	if #names == 0 and type(st.l2guard) == "table" and type(st.l2guard.ifnames) == "table" then
		names = st.l2guard.ifnames   -- wireless not answering yet: last known
	end
	spec.ifnames = names
	st.l2guard = spec
	M._l2guard.reconcile(spec, names)
	return true
end

-- Once a minute: if the live VAP list no longer matches the one the table was
-- built for (an SSID added by a push whose `wifi reload` had not finished, or
-- wireless coming up after the daemon at boot), rebuild. An empty live list
-- is "not answering", never "no VAPs": it leaves the table alone. Returns true
-- when it rebuilt.
M.L2GUARD_RESYNC_INTERVAL = 60
M._l2guard_next = 0
function M._l2guard_resync(st)
	local g = st and st.l2guard
	if not (M._l2guard and type(g) == "table" and (g.bpdu or g.tagdrop)) then return false end
	local now = M._time()
	if now < M._l2guard_next then return false end
	M._l2guard_next = now + M.L2GUARD_RESYNC_INTERVAL
	local names = M._l2guard_live_ifnames()
	if #names == 0 or same_names(names, g.ifnames) then return false end
	io.stderr:write("l2guard: AP interfaces changed (" .. table.concat(names, " ")
		.. ") -- rebuilding\n")
	g.ifnames = names
	M._state.save(st)
	M._l2guard.reconcile(g, names)
	return true
end

-- Once a minute, independent of the ebtables block: a force-isolated BSS
-- whose bridge port lost its hairpin flag (l2guard.reconcile_hairpin) cuts
-- its clients off from each other, and the reconfigure that causes it can
-- land at any time, not just after a push. Returns the number of flags fixed.
M.HAIRPIN_CHECK_INTERVAL = 60
M._hairpin_next = 0
function M._hairpin_resync()
	if not (M._l2guard and M._l2guard.reconcile_hairpin) then return 0 end
	local now = M._time()
	if now < M._hairpin_next then return 0 end
	M._hairpin_next = now + M.HAIRPIN_CHECK_INTERVAL
	return M._l2guard.reconcile_hairpin()
end

-- Once a minute: keep usteer's AP-to-AP broadcasts off the VAPs
-- (usteer.reconcile_filter) while openUF runs the daemon, rebuilding only when
-- that or the VAP list changed. An empty live list while wanted is "wireless
-- not answering yet" and leaves the table alone. Returns true when it rebuilt.
M.USTEER_FILTER_INTERVAL = 60
M._usteer_filter_next = 0
M._usteer_filter_built = nil
function M._usteer_filter_resync()
	local u = M._usteer
	if not (u and u.reconcile_filter and u.filter_wanted) then return false end
	local now = M._time()
	if now < M._usteer_filter_next then return false end
	M._usteer_filter_next = now + M.USTEER_FILTER_INTERVAL
	local names = {}
	if u.filter_wanted() then
		names = M._l2guard_live_ifnames()
		if #names == 0 then return false end
	end
	local key = table.concat(names, " ")
	if key == M._usteer_filter_built then return false end
	u.reconcile_filter(names)
	M._usteer_filter_built = key
	return true
end

-- ─── The controller's scheduled neighbour scan ──────────────────────────────

-- Where `syswrapper.sh 11k-scan` -- the controller's nightly cron job, see
-- sysconf.lua -- leaves its request: one epoch per line, each a time a scan
-- falls due (two of them, randomised inside SCAN_REQUEST_WINDOW, as UniFi
-- firmware spreads the job). Each heartbeat fires the scan once when any
-- time has come and keeps the rest; the file goes when none is left. A due
-- time more than SCAN_REQUEST_MAX_AGE in the past is dropped unscanned, so a
-- request a stopped daemon never saw does not fire at the next boot in the
-- middle of hostapd's ACS sweep; one further ahead than the window (the
-- clock stepped back) is dropped too.
M.SCAN_REQUEST_FILE    = "/tmp/openuf-scan-request"
M.SCAN_REQUEST_MAX_AGE = 600
M.SCAN_REQUEST_WINDOW  = 3600

-- One blocking off-channel sweep on an AP netdev: `iw dev <if> scan
-- ap-force`. On both our boards (OpenWrt 25.12, mac80211 6.18 backports:
-- ath9k/ath10k on the Archer C5, mt76 on the AX3000T) a plain `scan` sweeps
-- exactly the same channels as `ap-force` -- compared on the live APs,
-- 2026-09-25. `ap-force` (NL80211_SCAN_FLAG_AP) is kept as a free guard for
-- a driver/kernel that does refuse a scan on a beaconing AP. What matters
-- more is the exit status: _popen drops stderr, so a refused scan used to be
-- indistinguishable from a successful one. The scan output itself is
-- discarded (callers read the kernel's caches: `scan dump`, `survey dump`).
-- Returns true when the sweep ran; logs and returns false when iw refused.
-- opts (optional): freqs = {MHz...} narrows the sweep, passive = true listens
-- only, duration = TU per channel, quiet = true leaves the refusal to the
-- caller. iw's grammar puts freq, then duration, before the flags and passive
-- last.
function M._force_scan(ufuci, ifname, who, opts)
	local args = ""
	if opts and opts.freqs and #opts.freqs > 0 then
		args = " freq " .. table.concat(opts.freqs, " ")
	end
	if opts and opts.duration then args = args .. " duration " .. opts.duration end
	args = args .. " ap-force"
	if opts and opts.passive then args = args .. " passive" end
	local out = ufuci._popen("iw dev " .. ifname
		.. " scan" .. args .. " >/dev/null 2>&1 && echo scan-ok")
	if out:find("scan-ok", 1, true) then return true end
	if not (opts and opts.quiet) then
		io.stderr:write("inform: " .. who .. ": iw refused to scan " .. ifname .. "\n")
	end
	return false
end

-- Airtime Scan dwell: per channel, SPECTRUM_DWELL_TU (1 TU = 1.024 ms) off
-- the AP's own channel, then SPECTRUM_HOME_S back on it before the next.
-- A default sweep listens 46-146 ms per channel, too short for a steady
-- utilization figure, and one sweep never returns to the operating channel:
-- measured on both boards (2026-10-10), a 13-channel sweep takes 13 dwells
-- end to end, so a long dwell in one sweep would leave clients without
-- their AP for 7-16 s. ath9k, ath10k and mt76 all honour `duration` (dwell
-- measured as the survey's active time: 213-259 ms for 200 TU), whether or
-- not the phy lists SET_SCAN_DWELL. 200 TU is about two beacon intervals:
-- clients see a hiccup, not a beacon loss.
M.SPECTRUM_DWELL_TU = 200
M.SPECTRUM_HOME_S   = 0.3
M._sleep = function(seconds) require("socket").select(nil, nil, seconds) end

-- A forced sweep on every reported radio (the modelmap's hwassign, as
-- build_json uses). Blocking, a few seconds per radio -- which is the point:
-- build_json runs next and its `scan dump` then carries the fresh results.
-- Returns how many sweeps actually ran, not how many were asked for.
function M._scan_all_radios(cfg)
	return M._scan_radios(cfg, "11k-scan")
end

-- The same, limited to the radios pick(radio) accepts (all when nil), with
-- _force_scan's opts. Returns sweeps run, then radios picked.
function M._scan_radios(cfg, who, pick, opts)
	local ufuci = M._ucihelper
	if not (ufuci and ufuci.get_radio_table and ufuci.get_ifname_for_radio) then return 0, 0 end
	local ok_r, radios = pcall(ufuci.get_radio_table, cfg and cfg.uap and cfg.uap.hwassign)
	if not ok_r or type(radios) ~= "table" then return 0, 0 end
	local issued, picked = 0, 0
	for _, radio in ipairs(radios) do
		if not pick or pick(radio) then
			picked = picked + 1
			local ok_if, ifname = pcall(ufuci.get_ifname_for_radio, radio.name)
			if ok_if and ifname and M._force_scan(ufuci, ifname, who, opts) then
				issued = issued + 1
			end
		end
	end
	return issued, picked
end

-- UniFi band of a frequency in MHz, as radio_table's `radio` names it (the
-- controller's own band table: 6 GHz starts at 5925).
local function band_of_freq(mhz)
	if mhz < 3000 then return "ng" end
	if mhz < 5925 then return "na" end
	return "6e"
end

-- The controller's scan requests (PROTOCOL-VALIDATION.md, "scan and
-- scan_band"): `scan` from the device's own Scan button,
-- {type "active"|"passive", mode "sync", freq?, radio_name?}; `scan_band`
-- {band} from Radio AI's full-scan pass, once per band. Both only set the
-- device's `scanning` flag; the next stats inform clears it and stamps
-- last_scan, and the controller reads the neighbours out of that inform's
-- scan_radio_table. So: sweep now, blocking, and let the immediate re-inform
-- after a cmd carry the fresh `scan dump`. Returns sweeps run.
function M._handle_scan_cmd(resp, cfg)
	local cmd, pick, opts = resp.cmd, nil, nil
	if cmd == "scan_band" then
		local band = resp.band
		pick = function(r) return r.radio == band end
	else
		local freqs = {}
		for f in tostring(resp.freq or ""):gmatch("%d+") do
			freqs[#freqs + 1] = f
		end
		local rn = resp.radio_name
		local fband = freqs[1] and band_of_freq(tonumber(freqs[1]))
		if type(rn) == "string" and rn ~= "" then
			pick = function(r) return r.name == rn end
		elseif fband then
			-- A frequency without a radio: only the radio that can tune it.
			pick = function(r) return r.radio == fband end
		end
		opts = {freqs = freqs, passive = (resp.type == "passive")}
	end
	local issued, picked = M._scan_radios(cfg, cmd, pick, opts)
	io.stderr:write(("inform: %s: scanned %d of %d radio(s)\n"):format(cmd, issued, picked))
	return issued
end

-- True when one of the pending 11k-scan due times has come. The times that
-- fired or went stale are taken out of the file, so each is served at most
-- once; the file is removed when nothing is left in it.
function M._scan_requested()
	local raw = M._read_file(M.SCAN_REQUEST_FILE)
	if not raw then return false end
	local now = M._time()
	local due, stale, keep = false, false, {}
	for s in raw:gmatch("%d+") do
		local late = now - tonumber(s)
		if late > M.SCAN_REQUEST_MAX_AGE or late < -(M.SCAN_REQUEST_WINDOW + 60) then
			stale = true
		elseif late >= 0 then
			due = true
		else
			keep[#keep + 1] = s
		end
	end
	if stale or not (due or #keep > 0) then
		io.stderr:write("inform: ignoring a stale 11k-scan request\n")
	end
	if #keep == 0 then
		os.remove(M.SCAN_REQUEST_FILE)
	elseif due or stale then
		local f = io.open(M.SCAN_REQUEST_FILE, "w")
		if f then f:write(table.concat(keep, "\n"), "\n"); f:close() end
	end
	return due
end

-- Serve a pending 11k-scan request. Returns true when radios were scanned.
function M._maybe_service_scan_request(cfg)
	if not M._scan_requested() then return false end
	local n = M._scan_all_radios(cfg)
	io.stderr:write(("inform: 11k-scan requested -- scanned %d radio(s)\n"):format(n))
	return n > 0
end

-- ─── dfs-reset ───────────────────────────────────────────────────────────────
-- The controller's 02:00 cron job, pushed whenever the site has a 5 GHz radio
-- pinned to a fixed DFS channel (the gate is decompiled in
-- PROTOCOL-VALIDATION.md, "Axis 4"). What it is for: a radar hit takes the
-- radio off that channel and nothing brings it back, so the carefully planned
-- cell quietly stays on whatever channel the driver picked -- until the next
-- Force Provision, which may be months away.
--
-- U7LR 6.8.2's own dfs_reset is the model, verb for verb (bin/syswrapper.sh):
-- for each 5 GHz radio's first VAP in Master mode, compare the live channel
-- against the one the controller configured, skip `auto` and `0`, skip when
-- they already agree, skip while the configured channel is still on the
-- non-occupancy list ("still in nol_channel, wait next time"), and otherwise
-- put the radio back. The firmware uses `radartool chknol` and `iwconfig
-- channel`; the equivalents here are mac80211's per-channel DFS state and a
-- CSA through hostapd's control socket.
--
-- Deliberately a channel switch announcement rather than a `wifi reload`: the
-- BSS is never torn down, associated clients are told where it is going, and
-- UCI is not touched (it already holds the configured channel -- that is what
-- makes this a *reset*). The radio still goes quiet for the CAC on arrival,
-- which is the price of a DFS channel and the reason this runs at 02:00.
M.DFS_RESET_REQUEST_FILE = "/tmp/openuf-dfs-reset-request"
-- A request the daemon never saw (it was down, or the whole AP was) is not
-- carried out hours later, when the clock has moved on and the controller
-- would schedule a fresh one the next night anyway.
M.DFS_RESET_MAX_AGE = 1800

-- True when the hook left a request that is still fresh. The file is removed
-- either way, so one request is served at most once.
function M._dfs_reset_requested()
	local raw = M._read_file(M.DFS_RESET_REQUEST_FILE)
	if not raw then return false end
	os.remove(M.DFS_RESET_REQUEST_FILE)
	local at = tonumber(raw:match("%d+"))
	if not at then return false end
	local late = M._time() - at
	if late > M.DFS_RESET_MAX_AGE or late < -60 then
		io.stderr:write("inform: ignoring a stale dfs-reset request\n")
		return false
	end
	return true
end

-- One radio: put it back on `want` if it is somewhere else and allowed to be
-- there. Returns "moved", or nil plus the reason it was left alone.
function M._dfs_reset_radio(radio, ifname)
	local rrm, si = M._rrmscan, M._sysinfo
	local want = tonumber(radio.channel)
	if not want then return nil, "channel is not pinned" end

	local caps = si.radio_caps(ifname) or {}
	local live = tonumber(caps.channel)
	if not live then return nil, "no live channel" end
	if live == want then return nil, nil end

	if rrm.is_dfs_channel(want) then
		local states = rrm.parse_dfs_states(si.phy_channels(ifname))
		if rrm.channel_in_nol(states, want) then
			local s = states[want] or {}
			io.stderr:write(("inform: dfs-reset: %s is on channel %d, wants %d,"
				.. " but %d is still on the non-occupancy list%s -- waiting for"
				.. " the next run\n"):format(ifname, live, want, want,
				s.secs and (" for another " .. s.secs .. " s") or ""))
			return nil, "in the non-occupancy list"
		end
	end

	local args = rrm.chan_switch_args(want, caps.width)
	if not args then
		io.stderr:write(("inform: dfs-reset: %s: cannot express channel %d at %s"
			.. " MHz as a channel switch -- leaving it on %d\n")
			:format(ifname, want, tostring(caps.width), live))
		return nil, "not expressible as a channel switch"
	end
	local cmd = "hostapd_cli -i " .. ifname .. " chan_switch "
		.. rrm.CS_COUNT .. " " .. args
	local out = M._run_cmd(cmd .. " 2>&1") or ""
	if not out:find("OK", 1, true) then
		io.stderr:write(("inform: dfs-reset: %s: hostapd refused the switch to"
			.. " channel %d (%s): %s\n"):format(ifname, want, args,
			(out:gsub("%s+$", ""))))
		return nil, "hostapd refused the switch"
	end
	io.stderr:write(("inform: dfs-reset: %s switching back from channel %d to"
		.. " the configured %d (%s)\n"):format(ifname, live, want, args))
	return "moved"
end

-- Serve a pending dfs-reset request. Returns how many radios were moved.
function M._maybe_service_dfs_reset(cfg)
	if not M._dfs_reset_requested() then return 0 end
	local ufuci, rrm, si = M._ucihelper, M._rrmscan, M._sysinfo
	if not (ufuci and rrm and si and si.phy_channels) then return 0 end
	local ok_r, radios = pcall(ufuci.get_radio_table, cfg and cfg.uap and cfg.uap.hwassign)
	if not ok_r or type(radios) ~= "table" then return 0 end
	local moved = 0
	for _, radio in ipairs(radios) do
		-- 5 GHz only, as the firmware's own list_first_vaps_ifs 5 does: no
		-- other band has DFS, so no other band can have been pushed off a
		-- channel by radar.
		if radio.radio == "na" and not radio.disabled then
			local ok_if, ifname = pcall(ufuci.get_ifname_for_radio, radio.name)
			if ok_if and ifname then
				local ok_m, what = pcall(M._dfs_reset_radio, radio, ifname)
				if ok_m and what == "moved" then moved = moved + 1 end
			end
		end
	end
	return moved
end

-- One heartbeat: build, send, dispatch. Returns the number of seconds the
-- caller should wait before the next one -- 0 means "again, now", the
-- config-applied case, where a real AP re-informs immediately. ctx carries the
-- loop's own state (interval, backoff, last_mtime) so run() is nothing but
-- `while true do wait(_tick()) end`, and the error boundaries and the backoff
-- can be exercised without a socket.
--
-- Every stage is pcall-wrapped, and that is the point of the split. build_json
-- shells out to a dozen tools and does arithmetic on their output; one nil in
-- one field takes the whole daemon down, and procd's respawn turns that into a
-- crash loop every five seconds that reports no statistics and logs nothing
-- beyond a traceback. A bad cycle now costs one heartbeat and one log line,
-- and the next cycle gets another go.
-- Send queued STA_ASSOC_TRACKER notifs, each as its own inform POST:
-- inform_as_notif/notif_reason/notif_payload next to the device identity.
-- The controller answers a bare noop (no interval) from its notif branch,
-- before any stats or config handling -- so the reply is deliberately not
-- fed to handle_response, which would read the missing interval as "back to
-- the default cadence". A failed POST puts the rest back for next cycle.
local function post_notifs(st, batch, requeue)
	for i, p in ipairs(batch) do
		local body = {}
		for k, v in pairs(M._notif_identity) do body[k] = v end
		body.time            = M._time()
		body.inform_as_notif = true
		body.notif_reason    = "event"
		body.notif_payload   = p
		local ok_p, pkt = pcall(M.build_packet, cjson.encode(body), st)
		local resp = ok_p and M.http_post(st.inform_url, pkt) or nil
		if not resp then
			local rest = {}
			for j = i, #batch do rest[#rest + 1] = batch[j] end
			requeue(rest)
			return i - 1, false
		end
	end
	return #batch, true
end

-- Device events, as opposed to the per-station notifs above: same envelope
-- (notif_reason "event"), but the payload is an `event_string` the
-- controller's own event registry dispatches on, and the device identity is
-- all the rest it needs. The controller logs the event under its site and
-- raises the matching alert.
--
-- Of the eleven EVT_AP_* strings 10.6.106 has a handler for, exactly one is
-- sent by the AP: EVT_AP_RadarDetected. The other ten (ChannelChanged,
-- DetectRogueAP, Isolated, PossibleInterference, AcsTriggerComplete,
-- QuickScanEvent, LocationEvent, AfcEvent, RestartProc, RestartedUnknown)
-- appear nowhere in U7LR 6.8.2's binaries: the controller raises them itself
-- from what it already knows, so there is nothing for a device to send.
-- Conversely EVT_AP_WirelessEvent and EVT_AP_Notification, which 6.8.2 does
-- emit, have no handler in 10.6.106 at all.
M.MAX_EVENTS = 16
M._event_queue = {}

-- Two BSSes on the same radio both see the same radar hit, and hostapd prints
-- the event on each BSS's control socket -- so the same detection arrives
-- once per BSS. Collapsed on (channel, second): the controller would
-- otherwise log one alert per VAP for one radar.
M.EVENT_DEDUP_S = 5
M._event_seen = {}

function M.queue_event(p)
	if type(p) ~= "table" or not p.event_string then return false end
	if p.dedup_key then
		local now, key = M._time(), p.dedup_key
		local last = M._event_seen[key]
		if last and now - last < M.EVENT_DEDUP_S then return false end
		M._event_seen[key] = now
		for k, v in pairs(M._event_seen) do
			if now - v > M.EVENT_DEDUP_S * 4 then M._event_seen[k] = nil end
		end
		p.dedup_key = nil
	end
	if #M._event_queue >= M.MAX_EVENTS then return false end
	M._event_queue[#M._event_queue + 1] = p
	return true
end

-- The radar detections in one drained collector blob, queued as the
-- controller's own event. `vap` is the interface hostapd reported it on,
-- which is what 6.8.2 sends beside channel and freq; the handler reads
-- channel (as a string) and freq (as a number) and ignores the event if
-- either is missing.
--
-- `evs` is assoctrack.parse_events' output over the same blob, when connection
-- tracking has already walked it: its radar records are turned into the same
-- {t, ifname, freq, channel} rows by rrmscan.radar_of, so the blob is walked
-- once per drain rather than once per consumer. Without it (DFS only, nothing
-- else reading the file) parse_dfs does the walk itself.
function M._dfs_poll(blob, evs)
	local rrm = M._rrmscan
	if not (rrm and rrm.parse_dfs) then return 0 end
	local hits
	if evs then
		hits = {}
		for _, e in ipairs(evs) do
			if e.ev == "radar" then
				local d = rrm.radar_of(e.t, e.ifname, e.freq)
				if d then hits[#hits + 1] = d end
			end
		end
	else
		hits = rrm.parse_dfs(blob)
	end
	local n = 0
	for _, d in ipairs(hits) do
		if M.queue_event{
			event_string = "EVT_AP_RadarDetected",
			channel      = tostring(d.channel),
			freq         = d.freq,
			vap          = d.ifname,
			dedup_key    = "radar/" .. tostring(d.channel),
		} then
			n = n + 1
			-- Worth a line of its own: a radar hit takes the radio off that
			-- channel for 30 minutes, and this is the only record openUF
			-- leaves of why.
			io.stderr:write(string.format(
				"inform: DFS radar detected on channel %d (%d MHz) on %s"
				.. " -- reported to the controller\n",
				d.channel, d.freq, tostring(d.ifname)))
		end
	end
	return n
end

local function take_events(n)
	local out = {}
	for i = 1, math.min(n, #M._event_queue) do out[i] = M._event_queue[i] end
	for _ = 1, #out do table.remove(M._event_queue, 1) end
	return out
end

local function requeue_events(list)
	for i = #list, 1, -1 do table.insert(M._event_queue, 1, list[i]) end
end

-- Device events ride no capability: unlike the station notifs they are not
-- gated on notif-assoc-stat, since the controller asked for nothing and the
-- event is the AP telling it something it has no other way to learn.
function M._send_events(st)
	if not (st and st.adopted) or not M._notif_identity then return 0 end
	if #M._event_queue == 0 then return 0 end
	local n = post_notifs(st, take_events(M.MAX_EVENTS), requeue_events)
	return n
end

-- Roam reports first: they are the ones a delay spoils.
function M._send_notifs(st)
	local at = M._assoctrack
	if not at or not (st and st.adopted) or not M._notif_identity then return 0 end
	local n_r, ok = post_notifs(st, at.take_roams(at.MAX_ROAMS), at.requeue_roams)
	if not ok then return n_r end
	return n_r + post_notifs(st, at.take(M.NOTIFS_PER_CYCLE), at.requeue)
end

-- _idle's look at the collector between heartbeats: anything new is ingested
-- now and a roam report it produced is sent now. The size check keeps a
-- quiet file from costing more than an open.
function M._roam_poll()
	local rrm, at, st = M._rrmscan, M._assoctrack, M._roam_st
	if not (rrm and at and rrm.drain) then return end
	if not M._events_pending(rrm) then return end
	local blob = rrm.drain()
	if not blob or blob == "" then return end
	if M._roam_keep then
		local chunks = M._pre_blob or {}
		chunks[#chunks + 1] = blob
		M._pre_blob = chunks
	end
	local evs = at.parse_events(blob)
	at.ingest(evs)
	at.roam_ingest(evs, M._vap_by_ifname)
	-- This drain is the only one these lines get, so the radar events in it
	-- are queued here too; they go out with the next heartbeat. Off the walk
	-- parse_events just did, not a second one over the same blob.
	pcall(M._dfs_poll, blob, evs)
	-- Only the roam reports: the funnel's keep the heartbeat's cadence.
	if #at._roam_queue > 0 and st and st.adopted and M._notif_identity then
		post_notifs(st, at.take_roams(at.MAX_ROAMS), at.requeue_roams)
	end
end

function M._tick(st, cfg, ufhw, ctx)
	-- base_interval is the device's own cadence; interval is what the loop
	-- actually waits, which the controller's noop may have moved.
	ctx.base_interval = ctx.base_interval or ctx.interval or 10
	ctx.interval = ctx.interval or ctx.base_interval
	ctx.backoff  = ctx.backoff  or ctx.interval

	-- One ucihelper lookup pass from here to the payload: the resyncs below
	-- (three of them each asked netifd for the VAP list on the same tick
	-- once a minute), the WLAN schedule check and build_json share one
	-- `ubus call network.wireless status` and one read of the wireless
	-- config. Ended and reopened, never joined: a pass a throw left open
	-- holds the last cycle's answers. A `wifi reload` inside it (a Forget)
	-- drops what it held. Closed after build_json, below, before
	-- handle_response can change the config.
	local ufuci = M._ucihelper
	if ufuci and ufuci.begin_pass and ufuci.end_pass then
		ufuci.end_pass()
		ufuci.begin_pass()
	end
	ctx.last_mtime = M._reload_if_changed(st, cfg, ctx.last_mtime)
	pcall(M._stun_tick, st)
	-- Before build_json, so anything a client reported since the last cycle
	-- rides out on THIS inform rather than waiting for the next.
	pcall(M._rrm_tick, cfg, st)
	-- The controller's nightly scan (syswrapper.sh 11k-scan), also before
	-- build_json so the fresh scan dump is what this inform reports.
	pcall(M._maybe_service_scan_request, cfg)
	pcall(M._maybe_service_dfs_reset, cfg)
	pcall(M._l2guard_resync, st)
	pcall(M._guest_resync, st)
	pcall(M._guest_wg_resync, st)
	pcall(M._hairpin_resync)
	pcall(M._usteer_filter_resync)
	pcall(M._block_resync, st)
	pcall(M._sched_resync, st)
	pcall(M._rrbguard_tick)

	-- Reported as spectrum_scanning = true by this inform; swept below.
	local spectrum_due = M._spectrum_pending
	local ok_b, json_str = pcall(M.build_json, st, cfg, ufhw)
	-- The cycle's ucihelper pass, opened above, ends here whether or not
	-- build_json returned: a pass left open would feed handle_response's own
	-- lookups pre-reload interface names. build_json closes its sysinfo pass
	-- on return; an error skips that, so it is closed here too.
	if ufuci and ufuci.end_pass then pcall(ufuci.end_pass) end
	if M._sysinfo and M._sysinfo.end_pass then pcall(M._sysinfo.end_pass) end
	if not ok_b then
		io.stderr:write("inform: build_json failed: " .. tostring(json_str) .. "\n")
		return ctx.interval
	end
	-- On the stations build_json just listed.
	local ok_sh, err_sh = pcall(M._shaper_resync, st)
	if not ok_sh then io.stderr:write("inform: shaper: " .. tostring(err_sh) .. "\n") end

	local ok_p, pkt = pcall(M.build_packet, json_str, st)  -- use_gcm read from st.use_gcm
	if not ok_p then
		io.stderr:write("inform: build_packet failed: " .. tostring(pkt) .. "\n")
		return ctx.interval
	end

	local body, err = M.http_post(st.inform_url, pkt)
	if not body then
		io.stderr:write("inform: POST failed: " .. tostring(err) .. "\n")
		M._warn_http_400(err, st, cfg)
		if M._guestportal then pcall(M._guest_selfrun, st, false) end
		-- Doubles from the CURRENT cadence, capped at 60 s -- or at the
		-- controller's own interval when that is longer, since a failure
		-- must never make the device poll faster than it was asked to.
		ctx.backoff = math.min(math.max(ctx.backoff, ctx.interval) * 2,
			math.max(60, ctx.interval))
		return ctx.backoff
	end
	ctx.backoff = ctx.interval
	M._warned_400 = false
	if M._guestportal then pcall(M._guest_selfrun, st, true) end

	local parse_ok, json_body = pcall(M.parse_packet, body, st)
	if not parse_ok then
		io.stderr:write("inform: parse error: " .. tostring(json_body) .. "\n")
		return ctx.interval
	end

	local ok_h, applied = pcall(M.handle_response, json_body, st, cfg)
	if not ok_h then
		io.stderr:write("inform: handle_response failed: " .. tostring(applied) .. "\n")
		return ctx.interval
	end
	-- After the state inform, never instead of it: the controller has just
	-- heard from this AP, and a notif from a device it considers lost is
	-- discarded anyway.
	if M._assoc_enabled(st, cfg) then pcall(M._send_notifs, st) end
	pcall(M._send_events, st)
	-- The controller has now seen spectrum_scanning = true: sweep, and
	-- inform again at once with the results and false.
	if spectrum_due then
		local ok_s, err_s = pcall(M._run_spectrum_scan)
		if not ok_s then
			io.stderr:write("inform: spectrum-scan failed: " .. tostring(err_s) .. "\n")
		end
		M._spectrum_pending = false
		ctx.interval = M._controller_interval or ctx.base_interval
		ctx.backoff  = ctx.interval
		return 0
	end
	-- The controller's requested cadence, or the device's own when the last
	-- noop named none. The backoff was reset to the old cadence above, before
	-- this response could move it; follow it here too, or the first failure
	-- after a drop would double from the stale, longer value.
	ctx.interval = M._controller_interval or ctx.base_interval
	ctx.backoff  = ctx.interval
	if applied then
		-- A config push runs `wifi reload`, which takes every hostapd object
		-- the RRM collector subscribed to away with it and kills the
		-- subscription. That is the one moment the liveness check must not
		-- wait out its interval.
		M._rrm_collector_next = 0
		return 0
	end
	return ctx.interval
end

function M.run(cfg, ufhw)
	local st = state.load()
	M._reapply_static_ip(st, cfg)
	-- The MAC persisted by the previous run, before _populate_net_info
	-- overwrites it with the live one read off dev.conf.net.lan_cpueth.
	local prev_mac = st.mac
	M._populate_net_info(st, cfg)
	M._warn_identity_change(prev_mac, st, cfg)
	M._warn_missing_uci()
	-- Identity and reported address must come off the same netdev. openUF takes
	-- the MAC from lan_cpueth and the IP from the bridge that port is enslaved
	-- to, which only agree when the two share a MAC -- true on every swconfig
	-- board, false on DSA, where the gateway then flags an IP conflict between
	-- the AP and itself. Reconciled once, here, before the first inform carries
	-- the mismatch. pcall'd for the same reason reapply_runtime_rules is: this
	-- reaches UCI and sysfs, and a board where either is missing must still
	-- start and report statistics.
	if M._ucihelper and M._ucihelper.ensure_bridge_identity then
		local ok_id, err_id = pcall(M._ucihelper.ensure_bridge_identity, cfg)
		if not ok_id then
			io.stderr:write("inform: could not reconcile bridge identity: "
				.. tostring(err_id) .. "\n")
		elseif err_id then
			-- It changed UCI; netifd has to be told, and nothing else at
			-- startup consumes _network_dirty (apply_config's reload only runs
			-- on a setparam, which may be many minutes away or never).
			M._ucihelper._network_dirty = false
			M._sysinfo._run_cmd("/etc/init.d/network reload 2>/dev/null")
			M._populate_net_info(st, cfg)  -- the address may have moved with it
		end
	end
	M._sync_bootstrap_account(st.adopted, cfg and cfg.config and cfg.config.bootstrap_adopt_user)
	M._reconcile_plugins(st, cfg)
	-- Blocked-client nft rules are live kernel state, not persisted UCI --
	-- reapply from state.json on every fresh start (mirrors the bootstrap
	-- account reconciliation just above).
	M._firewall.reconcile(st.blocked_stas)
	-- Same category, one level out: the "Multicast and Broadcast Blocker" is an
	-- nftables ruleset, so it dies with the reboot, and has no UCI option
	-- OpenWrt itself applies. It is only ever built inside apply_config, which
	-- runs on a setparam -- and after a reboot there is no setparam: cfgversion
	-- matches on the first inform and the controller replies noop, carrying no
	-- system_cfg at all. It therefore stayed off indefinitely while the UI
	-- showed it on. Rebuilt here from the openuf_bcfilt options wlan_add stamps
	-- onto each managed section. (The WiFi Speed Limit is rebuilt by every
	-- heartbeat's _shaper_resync from openuf_ratelimit_*.)
	--
	-- pcall'd because it reaches ubus for each VAP's live netdev name: no
	-- radios, no wifi up yet, no ubus at all are ordinary outcomes on a board
	-- openUF has never provisioned, and none of them may stop the daemon.
	if M._ucihelper and M._ucihelper.reapply_runtime_rules then
		local ok_rt, err_rt = pcall(M._ucihelper.reapply_runtime_rules)
		if not ok_rt then
			io.stderr:write("inform: could not reapply the blocker rules: "
				.. tostring(err_rt) .. "\n")
		end
	end
	-- A Locate does NOT survive a restart, and must not: it is a transient
	-- "which box is it" blink, nobody is still standing in front of the AP,
	-- and unset-locate only ever arrives while someone is watching the
	-- controller. Left alone the device comes back still blinking with no
	-- snapshot of what the LED was on, and the next unset-locate -- if one
	-- ever comes -- restores nothing. Worse, a second set-locate would
	-- snapshot the blink itself as the thing to restore. Observed exactly
	-- that on an AX3000T, whose radio LED stayed on the identify blink
	-- across three Locate cycles.
	if st.locating then
		-- Only when the LED is really still blinking: a device that REBOOTED
		-- mid-Locate comes back with the kernel's own default trigger already
		-- restored, and "stopping" that would write none over it.
		if M._led.locate_active(cfg and cfg.led) then
			M._led.locate_stop(cfg and cfg.led, st.locate_prev_trigger)
		end
		st.locating = false
		st.locate_prev_trigger = nil
		M._state.save(st)
	end
	-- LED brightness is live kernel state too, not UCI -- the same reason the
	-- blocked-client rules are reapplied above. The controller pushes
	-- led_enabled once, in mgmt_cfg, and never again, so without this the
	-- Manage > LED toggle silently forgets itself on every reboot while the
	-- controller goes on believing it took. Applied AFTER the locate teardown:
	-- if both have something to say, the steady state the operator chose wins
	-- over whatever trigger the blink displaced. nil means it was never
	-- pushed, which must leave the board's own default alone rather than
	-- deciding for it.
	if st.led_enabled ~= nil then
		M._led.set_enabled(cfg and cfg.led, st.led_enabled)
	end
	M._reapply_airtime(st)
	-- Per-port byte counters are a switch-driver setting that some boards ship
	-- switched off; without it every socket reports 0 B in the Ports view.
	if M._switchvlan then pcall(M._switchvlan.enable_mib_polling, cfg) end
	-- nftables state does not survive a reboot, so the per-socket MAC tap is
	-- reinstalled here from the UCI sections that record which sockets have
	-- learning off -- the same discipline _firewall.reconcile uses for the
	-- blocklist. A tap that is not reinstalled fails silently, as an empty
	-- mac_table, which is the bug it exists to fix.
	if M._switchvlan then pcall(M._switchvlan.reconcile_mac_taps) end
	-- The controller's ebtables hardening is nft state too. Rebuilt from
	-- state.json's record with the live VAP list, or the names recorded at
	-- the last push while wireless is not answering yet; _l2guard_resync
	-- corrects the list once it is.
	if M._l2guard and type(st.l2guard) == "table" then
		pcall(function()
			local names = M._l2guard_live_ifnames()
			if #names == 0 and type(st.l2guard.ifnames) == "table" then names = st.l2guard.ifnames end
			M._l2guard.reconcile(st.l2guard, names)
		end)
	end
	-- The guest portal's tables, likewise (lab-validated only).
	if M._guestportal and type(st.guest_portal) == "table" then
		pcall(M._guest_enforce, st)
	end

	local socket = require("socket")
	local ctx = {
		interval   = 10,
		backoff    = 10,
		last_mtime = M._state_mtime(M._state._state_file),
	}
	while true do M._cycle(st, cfg, ufhw, ctx, socket) end
end

-- Injectable for tests.
M._collectgarbage = collectgarbage

-- One heartbeat, then a full collection, then the wait. Each tick builds a
-- payload, parses the controller's answer and reads most of /proc and the
-- driver's tables, then drops all of it. Left to the default pause the heap
-- doubles before a cycle runs, and the process keeps the pages it grew into.
-- Collecting here, once the garbage is all garbage, measured on both
-- reference boards over 30 min each (2026-10-17): inform's RssAnon 3068 ->
-- 2378 kB on the Archer C5, 3882 -> 3030 kB on the AX3000T, the peak about
-- 1 MB lower on both, and total CPU unchanged (1.71 -> 1.72 % on the C5; the
-- 20 ms collection replaces the incremental steps the tick paid for). A
-- shorter pause (setpause 100) kept less than half that saving.
function M._cycle(st, cfg, ufhw, ctx, socket)
	local wait = M._tick(st, cfg, ufhw, ctx)
	M._collectgarbage("collect")
	if wait > 0 then M._idle(socket, wait) end
end

-- ─── Script entry point ───────────────────────────────────────────────────────

if not OPENUF_TEST_MODE then
	local ok, err = pcall(function()
		if not ufpkt then
			local ok2 = pcall(dofile, "lib/lib.lua")
			if not ok2 then dofile("openuf/lib/lib.lua") end
		end
		dofile("conf.lua")
		-- conf.lua's state_file was documented as THE state path and read by
		-- nothing: every entry point used state.lua's hardcoded default, so
		-- setting it moved no file and only made the three processes that
		-- touch state.json disagree about where it is. announce.lua and
		-- hook/syswrapper.lua honour it the same way.
		if config and type(config.state_file) == "string" and config.state_file ~= "" then
			M._state._state_file = config.state_file
		end
		-- Same story, same table, missed the first time round: conf.lua's
		-- inform_url was documented as the first-boot URL and read by nothing.
		-- state.lua's defaults() carried its own hardcoded copy, so editing
		-- conf.lua moved nothing -- while install.sh parsed that very key to
		-- decide whether an https:// controller needed luasec, and reported
		-- success for a URL the daemon would never post to. Applied as the
		-- DEFAULT, so it only takes effect when state.json has no URL of its
		-- own: an adopted device keeps whatever the controller assigned it.
		if config and type(config.inform_url) == "string" and config.inform_url ~= "" then
			M._state.DEFAULT_INFORM_URL = config.inform_url
		end
		local ufhw = {uap = dofile("ufmodel/" .. dev.openuf.uap.ufmodel .. ".lua")}
		-- config (debug_dump_file, state_file, ...) is a separate global set by
		-- conf.lua, not a field of dev.conf -- merge it in under .config so
		-- handle_response's cfg.config.debug_dump_file check can see it.
		dev.conf.config = config
		-- Same treatment for the modelmap's UniFi block (dev.openuf.uap): only
		-- dev.conf is passed down, so hwassign is otherwise unreachable from
		-- build_json.
		dev.conf.uap = dev.openuf and dev.openuf.uap
		M.run(dev.conf, ufhw)
	end)
	if not ok then
		io.stderr:write("inform: " .. tostring(err) .. "\n")
		os.exit(1)
	end
end

return M
