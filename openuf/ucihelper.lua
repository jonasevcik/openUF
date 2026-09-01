--[[
	UCI helper for WiFi provisioning.

	Manages SSID sections named with the "openuf_" prefix so that user-created
	SSIDs are never touched.  The controller pushes config via the inform
	response dispatcher (inform.handle_response → apply_config).

	Requires: uci (Lua UCI bindings, standard on OpenWrt)
]]--

local M = {}

-- Injectable seams for tests
M._uci        = nil  -- override with a mock UCI table; nil = require("uci")
-- "Multicast and Broadcast Blocker" enforcement (nftables). Injectable so
-- tests can capture the reconciled rules without shelling out to real nft.
M._bcfilter   = nil  -- nil = load openuf/bcfilter.lua on first use
-- "WiFi Speed Limit" enforcement (tc). Injectable for the same reason.
M._shaper     = nil  -- nil = load openuf/shaper.lua on first use
M._run_cmd    = function(cmd) return os.execute(cmd) end

-- Injectable: command execution that captures stdout (for read-only introspection,
-- as opposed to M._run_cmd which only reports success/failure for mutating commands).
M._popen = function(cmd)
	local h = io.popen(cmd .. " 2>/dev/null")
	if not h then return "" end
	local s = h:read("*a")
	h:close()
	return s or ""
end

-- Injectable: file reader, for sysfs lookups (e.g. interface MAC address).
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- Static radio capability defaults, used when UCI/driver introspection can't
-- supply a real value. Tune per target hardware (see u6iw.lua's fw.ver note
-- for the same caveat pattern).
M.RADIO_DEFAULTS = {
	builtin_antenna  = true,
	builtin_ant_gain = 3,   -- dBi
	max_txpower      = 20,  -- dBm
}

local function get_uci()
	if M._uci then return M._uci end
	return require("uci")
end

-- Load an enforcement sibling by path, mirroring inform.lua's _require_sibling:
-- openUF's modules are not on package.path, and the working directory differs
-- between running from openuf/ and from an install root. Returns nil rather
-- than erroring if it cannot be found, so a missing module degrades to "not
-- enforced" instead of taking the whole config apply down with it.
local function get_sibling(name, override)
	if override then return override end
	for _, p in ipairs({name .. ".lua", "openuf/" .. name .. ".lua"}) do
		local f = io.open(p, "r")
		if f then
			f:close()
			local ok, mod = pcall(dofile, p)
			if ok and type(mod) == "table" then return mod end
		end
	end
	return nil
end

local function get_bcfilter() return get_sibling("bcfilter", M._bcfilter) end
local function get_shaper()   return get_sibling("shaper",   M._shaper)   end

-- Map a UCI wifi-device's channel number to the controller's band identifier.
-- The real controller's radio_table schema requires this "radio" field
-- ("ng"/"na"/"ad"/"6e") on every entry -- confirmed via decompiling the
-- controller's own radio-band enum (com.ubnt.g.f.e.rYtJfMBbtgWvku), whose
-- string-to-enum parser unconditionally calls .toLowerCase() with no null
-- guard. Omitting "radio" (as this function previously did) means that
-- parser gets a null and throws, which corrupts the controller's adopt/UI
-- state on every single inform -- invisible until now because radio_table
-- was always empty (no target hardware to source it from) prior to the UCI
-- mock. Only "ng"/"na" are handled -- openUF only targets dual-band 2.4/5GHz
-- hardware (see modelmap/generic-dualband-ap.lua's hwassign); 60GHz/6GHz
-- would need channel ranges that overlap 5GHz's numbering and can't be
-- disambiguated by channel number alone.
local function band_for_channel(channel)
	local ch = tonumber(channel)
	if ch and ch >= 1 and ch <= 14 then return "ng" end
	return "na"
end
-- Exported for inform.lua's build_json, which re-derives the band from the
-- LIVE negotiated channel (iw) after the radio-caps merge -- authoritative
-- once ACS has picked a channel, when UCI itself may only say "auto".
M.band_for_channel = band_for_channel

-- Band for a UCI wifi-device SECTION: config-first, channel-number fallback.
-- The channel value alone is not enough -- with channel=auto (ACS)
-- tonumber() is nil and the pure channel mapping above misreports a 2.4GHz
-- radio as "na" (5GHz). The section's own band declaration is authoritative:
-- `band` ("2g"/"5g"/"6g") on modern OpenWrt, `hwmode` ("11g"/"11a"/...) on
-- older releases. 6GHz maps to "na" only because openUF targets dual-band
-- 2.4/5GHz hardware (see band_for_channel's comment); a 6E target would need
-- the "6e" identifier and its own model capabilities.
local function band_for_device(s)
	if s.band == "2g" then return "ng" end
	if s.band == "5g" or s.band == "6g" then return "na" end
	if s.hwmode == "11b" or s.hwmode == "11g" or s.hwmode == "11ng" then return "ng" end
	if s.hwmode == "11a" or s.hwmode == "11na" or s.hwmode == "11ac" then return "na" end
	return band_for_channel(s.channel)
end

-- ─── Radio hardware capabilities ─────────────────────────────────────────────
--
-- openUF presents itself as a U6-InWall (802.11ax) no matter what the host
-- radios actually are, so a controller is entitled to push
-- radio.<n>.ieee_mode=11nahe80 at hardware that has never heard of HE -- as it
-- will at every one of this project's documented targets, which are 802.11n/ac.
-- Writing that htmode into UCI verbatim yields a config file that looks
-- perfectly correct and a hostapd that refuses to start: no SSID on the air at
-- all, and nothing in UCI to explain why. So probe what the hardware can
-- really do and clamp DOWNWARD only -- a controller asking for less than the
-- radio supports is a legitimate request, never something to "correct".
local PHY_RANK = {HT = 1, VHT = 2, HE = 3, EHT = 4}
local RANK_PHY = {"HT", "VHT", "HE", "EHT"}

-- Cached because it describes hardware, which does not change while openUF
-- runs. Reset it (M._phy_caps_cache = nil) after anything that changes what
-- the driver reports -- notably a regdomain change, which moves the per-channel
-- TX power limits below.
M._phy_caps_cache = nil

-- Parse `iw phy` output into per-band capabilities, keyed by band_for_device's
-- own vocabulary ("ng"/"na"). Each band is identified by the frequencies it
-- actually lists, NOT by its "Band N:" index -- that index is assigned per
-- driver (this project's ath9k radio reports 2.4GHz as Band 1, its ath10k
-- radio reports 5GHz as Band 2) and means nothing on its own.
local function parse_phy_caps(out)
	local bands, cur, phy = {}, nil, nil
	for line in (tostring(out) .. "\n"):gmatch("([^\n]*)\n") do
		-- Phy-level lines carry exactly one leading tab; a Band block's
		-- contents are indented deeper. That is what marks the end of a band
		-- block -- without it, phy-level sections listed after the bands (the
		-- extended-feature list below) would be attributed to whichever band
		-- happened to be last.
		if line:match("^%s*Wiphy%s") then
			phy = {beacon_rate = false, bands = {}}
			cur = nil
		elseif line:match("^\tBand %d+:") then
			cur = {ht40 = false, vht = false, he = false, eht = false,
				w160 = false, w320 = false, freq = nil, txpower = nil,
				phy = phy}
			bands[#bands + 1] = cur
			if phy then phy.bands[#phy.bands + 1] = cur end
		elseif line:match("^\t[^\t]") then
			cur = nil
		end
		-- Driver support for setting the beacon frame rate, reported per phy.
		-- hostapd treats a beacon_rate it cannot program as FATAL ("Failed to
		-- set beacon parameters" -> "Interface initialization failed"), so the
		-- radio never starts -- see rf_config.
		if phy and line:match("BEACON_RATE_LEGACY") then phy.beacon_rate = true end
		if cur then
			if line:match("HT20/HT40") then cur.ht40 = true end
			if line:match("^%s*VHT Capabilities") then cur.vht = true end
			if line:match("^%s*HE Iftypes") or line:match("^%s*HE PHY Capabilities") then
				cur.he = true
			end
			if line:match("^%s*EHT Iftypes") or line:match("^%s*EHT PHY Capabilities") then
				cur.eht = true
			end
			-- "Supported Channel Width: neither 160 nor 80+80" must NOT count
			-- as 160 support, hence the explicit negative check.
			if line:match("Supported Channel Width:") and line:match("160")
				and not line:match("neither 160") then
				cur.w160 = true
			end
			if line:match("320 MHz") then cur.w320 = true end
			-- "\t\t\t* 5180.0 MHz [36] (23.0 dBm)"; disabled channels carry no
			-- usable power and are skipped.
			local mhz, dbm = line:match("^%s*%*%s+([%d%.]+) MHz.*%(([%d%.]+) dBm%)")
			if mhz and not line:match("disabled") then
				cur.freq = cur.freq or tonumber(mhz)
				-- `iw` prints one decimal ("23.0 dBm"); floored to an integer
				-- so the payload carries 23 rather than 23.0 -- max_txpower is
				-- a whole-dBm field, and flooring never claims more than the
				-- driver allows.
				local p = tonumber(dbm)
				p = p and math.floor(p) or nil
				if p and (not cur.txpower or p > cur.txpower) then cur.txpower = p end
			end
		end
	end

	local caps = {}
	for _, b in ipairs(bands) do
		local key = b.freq and ((b.freq < 3000) and "ng" or "na") or nil
		if key then
			local width = 20
			if b.ht40 then width = 40 end
			if b.vht or b.he then width = math.max(width, 80) end
			if b.w160 then width = math.max(width, 160) end
			if b.eht and b.w320 then width = math.max(width, 320) end
			-- 2.4GHz stops at 40MHz -- there is no 80MHz channel in the band
			-- to be had, whatever the PHY generation. The widths above are
			-- derived from the PHY (a VHT or HE radio can do 80), which was
			-- accurate while every 2.4GHz radio here was HT-only and wrong
			-- the moment one was not: an HE 2.4GHz radio reported max_width
			-- 80, clamp_htmode passed a pushed HE80 straight through (it
			-- narrows to 40 only for kind "HT"), and hostapd treats a channel
			-- width it cannot program as fatal -- the radio never starts.
			if key == "ng" then width = math.min(width, 40) end
			local prev = caps[key]
			-- Two radios can serve the same band (rare, but a 2.4GHz-only and a
			-- dual-band phy in one device do it); keep the more capable view.
			caps[key] = {
				max_kind = (b.eht and 4) or (b.he and 3) or (b.vht and 2) or 1,
				max_width = width,
				max_txpower = b.txpower,
				beacon_rate = (b.phy and b.phy.beacon_rate) or false,
			}
			if prev then
				caps[key].max_kind  = math.max(prev.max_kind, caps[key].max_kind)
				caps[key].max_width = math.max(prev.max_width, caps[key].max_width)
				caps[key].max_txpower = math.max(prev.max_txpower or 0,
					caps[key].max_txpower or 0)
				if caps[key].max_txpower == 0 then caps[key].max_txpower = nil end
				caps[key].beacon_rate = prev.beacon_rate or caps[key].beacon_rate
			end
		end
	end
	return caps
end

-- Per-band hardware capabilities: {ng = {max_kind, max_width, max_txpower}, ...}
-- An empty table (no `iw`, unparseable output) means "unknown", which every
-- caller must treat as "leave the controller's request alone".
function M.phy_caps()
	if not M._phy_caps_cache then
		M._phy_caps_cache = parse_phy_caps(M._popen("iw phy") or "")
	end
	return M._phy_caps_cache
end

-- The best PHY generation the given band's hardware can run ("HT"/"VHT"/
-- "HE"/"EHT"), or nil when the capabilities are unknown -- which callers must
-- treat as "do not upgrade anything".
--
-- The counterpart to clamp_htmode: that one refuses to give a radio a PHY it
-- cannot do, this one says what it CAN do, for a caller whose only other
-- source is a wire format that does not carry the answer.
function M.best_phy(band)
	local caps = M.phy_caps()[band]
	return caps and RANK_PHY[caps.max_kind] or nil
end

-- Clamp an OpenWrt htmode ("HE80", "VHT40", "HT20", ...) to what the given
-- band's hardware can actually do. Returns the (possibly adjusted) htmode and,
-- when it was adjusted, the original -- callers log the pair, because a
-- silently rewritten channel width is exactly the kind of change that turns
-- into an unexplainable bug report months later.
function M.clamp_htmode(band, htmode)
	if type(htmode) ~= "string" then return htmode, nil end
	local caps = M.phy_caps()[band]
	if not caps then return htmode, nil end
	-- Anything that isn't <PHY><width> (e.g. "NOHT") passes through untouched.
	local kind, width = htmode:match("^(%u+)(%d+)$")
	local rank = kind and PHY_RANK[kind]
	if not rank then return htmode, nil end

	local out_kind = RANK_PHY[math.min(rank, caps.max_kind)]
	local out_width = math.min(tonumber(width), caps.max_width)
	-- HT tops out at 40MHz: there is no such thing as HT80.
	if out_kind == "HT" then out_width = math.min(out_width, 40) end
	local out = out_kind .. tostring(out_width)
	if out == htmode then return htmode, nil end
	return out, htmode
end

-- The UCI prefix applied to all openuf-managed wireless sections
local OPENUF_PREFIX = "openuf_"

-- Sentinel for an `extra` value meaning "delete this option", as distinct from
-- both "set it to something" and "leave it alone". Needed because several
-- OpenWrt wifi controls are expressed as the option's absence rather than an
-- off value -- see wlan_add()'s macfilter handling.
M.DELETE = setmetatable({}, {__tostring = function() return "<delete>" end})

-- Map from UniFi security type strings to UCI encryption values.
--
-- There is deliberately no "wpa-enterprise" entry. One existed, mapping to
-- "wpa2+ccmp", but no producer ever emitted that string -- and it could not
-- have worked anyway, since wlan_add() writes no auth_server/auth_secret and
-- the wire protocol carries no RADIUS configuration to write. Enterprise
-- WLANs are now rejected at parse time in inform.lua's
-- _parse_wifi_system_cfg() instead of being silently mis-provisioned.
local SECURITY_MAP = {
	["open"]       = "none",
	["wpa2"]       = "psk2",
	["wpa3"]       = "sae",
	["wpa2/wpa3"]  = "sae-mixed",
}

-- Deterministic 16-bit id from a string, formatted as 4 hex chars (802.11r
-- mobility domain is a 2-octet field). Used as a stopgap mobility_domain
-- when the controller only sends the high-level fast_roaming_enabled toggle
-- and no raw mobility_domain/r0kh/r1kh (UniFi's admin API has no such fields
-- -- it computes and syncs them internally across all APs on a site). Same
-- seed always yields the same domain, so every openUF-emulated AP on the
-- same network computes it identically without needing to coordinate.
function M.derive_mobility_domain(seed)
	local hash = 0
	for i = 1, #seed do
		hash = (hash * 31 + seed:byte(i)) % 65536
	end
	return string.format("%04x", hash)
end

-- ─── VAP management ──────────────────────────────────────────────────────────

-- Delete all openuf_* wifi-iface sections on the given radio (or all radios).
-- radio: optional UCI radio name (e.g. "radio0"); nil removes from all radios.
function M.wlan_clear(radio)
	local uci = get_uci()
	local cursor = uci.cursor()
	local to_delete = {}
	cursor:foreach("wireless", "wifi-iface", function(s)
		local name = s[".name"]
		if name and name:sub(1, #OPENUF_PREFIX) == OPENUF_PREFIX then
			if radio == nil or s.device == radio then
				to_delete[#to_delete + 1] = name
			end
		end
	end)
	for _, name in ipairs(to_delete) do
		cursor:delete("wireless", name)
	end
	cursor:commit("wireless")
end

-- UCI option marking a wifi-iface that openUF disabled on the user's behalf,
-- so use_only_unifi_wlan can be switched back off without stranding the SSID.
local AUTODISABLED = OPENUF_PREFIX .. "autodisabled"

-- Apply conf.lua's use_only_unifi_wlan to every wifi-iface openUF does not
-- manage (i.e. not "openuf_"-prefixed).
--
-- enabled=true  -> disable those SSIDs, stamping each one openUF turns off.
-- enabled=false -> re-enable only the ones carrying that stamp.
--
-- An SSID the *user* had already disabled is never stamped, so switching the
-- option off later does not silently switch their SSID back on. The option is
-- documented (README/USAGE) and shipped as true in conf.lua, but a missing
-- config is treated as false: openUF should not start disabling a stranger's
-- SSIDs just because a caller failed to thread cfg through.
function M.set_wlan_exclusive(enabled)
	local uci = get_uci()
	local cursor = uci.cursor()
	local targets = {}
	cursor:foreach("wireless", "wifi-iface", function(s)
		local name = s[".name"]
		if name and name:sub(1, #OPENUF_PREFIX) ~= OPENUF_PREFIX then
			targets[#targets + 1] = {name = name, disabled = s.disabled,
				stamped = (s[AUTODISABLED] == "1")}
		end
	end)
	for _, t in ipairs(targets) do
		if enabled then
			if t.disabled ~= "1" then
				cursor:set("wireless", t.name, "disabled", "1")
				cursor:set("wireless", t.name, AUTODISABLED, "1")
			end
		elseif t.stamped then
			cursor:set("wireless", t.name, "disabled", "0")
			cursor:set("wireless", t.name, AUTODISABLED, "0")
		end
	end
	cursor:commit("wireless")
end

-- ─── Minimum Data Rate ───────────────────────────────────────────────────────

-- The 802.11 legacy rate ladder, in kb/s -- the unit both the controller's
-- wireless.<n>.minrate_data and OpenWrt's basic_rate/supported_rates use.
-- CCK (802.11b) rates first, then the OFDM (802.11g/a) set.
local CCK_RATES  = {1000, 2000, 5500, 11000}
local OFDM_RATES = {6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000}

-- Derive a radio's UCI rate options from a Minimum Data Rate floor.
--
-- floor_kbps:    the minimum data rate, in kb/s (wireless.<n>.minrate_data)
-- allow_cck:     whether 802.11b/CCK rates stay on the ladder at all
--                (wireless.<n>.minrate_cck_rates.status)
-- drop_below:    whether rates under the floor are also removed from the
--                advertised set, not merely made non-basic
--                (wireless.<n>.minrate_below_disable)
--
-- basic_rate is what actually enforces a *minimum*: a station must support
-- every basic rate to associate at all, so making the floor basic excludes
-- anything slower. supported_rates additionally stops the lower rates being
-- advertised, which is the separate "advertising rates" sub-toggle.
--
-- Returns nil when the floor excludes every rate in the band, rather than
-- emitting an empty list that would leave hostapd unable to bring the BSS up.
function M.derive_rates(floor_kbps, allow_cck, drop_below)
	if not floor_kbps then return nil end
	local ladder = {}
	if allow_cck ~= false then
		for _, r in ipairs(CCK_RATES) do ladder[#ladder + 1] = r end
	end
	for _, r in ipairs(OFDM_RATES) do ladder[#ladder + 1] = r end

	local at_or_above = {}
	for _, r in ipairs(ladder) do
		if r >= floor_kbps then at_or_above[#at_or_above + 1] = r end
	end
	if #at_or_above == 0 then return nil end

	local rates = {
		-- The floor itself is the mandatory rate. Kept as a one-element list
		-- rather than "every rate at or above the floor": each additional basic
		-- rate is another rate a station must implement to associate, which
		-- would exclude clients the controller never intended to exclude.
		basic_rate   = {at_or_above[1]},
		-- OpenWrt's legacy_rates is the 802.11b on/off switch; 0 is also what
		-- the controller signals via pureg=1 on 2.4 GHz.
		legacy_rates = (allow_cck == false) and "0" or "1",
	}
	if drop_below then rates.supported_rates = at_or_above end
	return rates
end

-- Create a new wifi-iface section named openuf_<ssid> on the given radio.
-- radio:    UCI radio name, e.g. "radio0" or "radio1"
-- ssid:     SSID string
-- security: "open" | "wpa2" | "wpa3" | "wpa2/wpa3"
-- password: WPA pre-shared key (ignored when security == "open")
-- extra:    optional table of additional UCI key/value pairs (802.11r/k/v etc.)
-- network:  UCI network/interface name to bridge this SSID onto (defaults to
--           "lan"); pass a VLAN-tagged interface from ensure_vlan_network() to
--           put the SSID on that VLAN.
-- wlanconf_id: optional controller-side wlanconf object id (system_cfg's
--           aaa.<n>.id), stashed the same way so get_vap_table() can echo it
--           back as the vap's "id" -- required for the controller to accept
--           the vap (and its sta_table) at all.
function M.wlan_add(radio, ssid, security, password, extra, network, wlanconf_id)
	local uci = get_uci()
	local cursor = uci.cursor()
	-- Section name includes the radio, not just the SSID: broadcasting the
	-- same SSID on both radios simultaneously is the default, common case
	-- (the controller UI's "Radio Band: 2.4 GHz + 5 GHz" checkboxes) and
	-- produces one wlan_add() call per radio with an identical ssid. Keying
	-- purely by SSID collapsed both calls into the same UCI section, so the
	-- second call's "device" silently overwrote the first -- confirmed live
	-- against a real controller: only the last-processed radio's VAP
	-- survived. name:gsub("[^%w_-]", "_") sanitizes radio the same way ssid
	-- already was, though UCI radio names ("radio0"/"radio1") never need it.
	local section_name = OPENUF_PREFIX .. tostring(radio):gsub("[^%w_-]", "_")
		.. "_" .. ssid:gsub("[^%w_-]", "_")
	local enc = SECURITY_MAP[security] or "psk2"
	cursor:set("wireless", section_name, "wifi-iface")
	cursor:set("wireless", section_name, "device", radio)
	cursor:set("wireless", section_name, "mode", "ap")
	cursor:set("wireless", section_name, "ssid", ssid)
	cursor:set("wireless", section_name, "encryption", enc)
	cursor:set("wireless", section_name, "network", network or "lan")
	if wlanconf_id then
		cursor:set("wireless", section_name, "openuf_wlanconf_id", wlanconf_id)
	end
	if password and enc ~= "none" then
		cursor:set("wireless", section_name, "key", password)
	end
	-- 802.11r/k/v
	if extra then
		for k, v in pairs(extra) do
			-- M.DELETE means "this option must not be present", which is not
			-- the same as "don't touch it": OpenWrt expresses several controls
			-- (macfilter above all) as the option's ABSENCE, and an
			-- out-of-enum stand-in value like "disable" is rejected by the
			-- 25.12 config validator hard enough to abort the radio.
			-- Deleting is also what lifts a previously pushed value.
			if v == M.DELETE then
				cursor:delete("wireless", section_name, k)
			-- A table value is a UCI *list* option (e.g. maclist) and must be
			-- handed to the binding as-is -- tostring() would write the
			-- literal "table: 0x...". Same convention rf_config already uses
			-- for basic_rate/supported_rates.
			elseif type(v) == "table" then
				cursor:set("wireless", section_name, k, v)
			else
				cursor:set("wireless", section_name, k, tostring(v))
			end
		end
	end
	cursor:commit("wireless")
end

-- True when this OpenWrt is 21.02+, i.e. netifd expects `config device`
-- sections and `option device` on an interface. Probed from the running
-- config rather than assumed: any interface carrying `device`, or the
-- presence of a `device` section, settles it. Pre-21.02 builds have neither
-- and want `option ifname` (which 25.12 still accepts as a legacy alias --
-- confirmed live -- so the probe is about which BRIDGE syntax to use, not
-- about the sub-device name).
local function netifd_uses_device_sections(cursor)
	local modern = false
	cursor:foreach("network", "device", function() modern = true end)
	if modern then return true end
	cursor:foreach("network", "interface", function(s)
		if s.device then modern = true end
	end)
	return modern
end

-- Idempotently create (or reuse) the L2 a VLAN-tagged SSID lives on: a bridge
-- holding the tagged uplink sub-device (e.g. "eth1.20" for VLAN 20 on cpueth
-- "eth1"). The VAP joins by naming the returned interface section, and netifd
-- enslaves it to the same bridge.
--
-- The bridge is the whole point. An interface whose device is the bare
-- sub-device does come up (confirmed live on 25.12: `eth1.20@eth1` UP,
-- netifd logging "Interface 'openuf_vlan20' is now up") -- but the VAP is
-- then a second, SEPARATE netdev with no master, so nothing joins the two.
-- A client associates and gets no DHCP, no gateway, nothing, while every
-- layer looks healthy. The controller's own push says as much: alongside the
-- WLAN it sends a bridge block naming exactly this topology --
--   bridge.2.devname=br0.20
--   bridge.2.port.1.devname=ath2      (the vap)
--   bridge.2.port.2.devname=eth0.20   (the tagged uplink)
-- which is a specification, not decoration.
--
-- OWNERSHIP, since two modules write this bridge. This function guarantees
-- one thing: the tagged uplink sub-device is a member. Any OTHER member it
-- finds is left alone, because on a DSA board switchvlan puts the physical
-- sockets assigned to this VLAN into the same bridge -- per-port VLAN and a
-- tagged SSID on the same VID are the same L2 there, and must be. An earlier
-- version set `ports` outright, which meant each push handed the bridge back
-- and forth: apply_config resetting it to the uplink alone, switchvlan adding
-- the sockets again, and a network reload on every inform.
--
-- Returns the UCI network/interface section name.
function M.ensure_vlan_network(cpueth, vlan_id)
	local uci = get_uci()
	local cursor = uci.cursor()
	local section_name = OPENUF_PREFIX .. "vlan" .. tostring(vlan_id)
	local ifname = cpueth .. "." .. tostring(vlan_id)
	local br_section = OPENUF_PREFIX .. "brdev" .. tostring(vlan_id)
	local br_name = "br-" .. OPENUF_PREFIX:gsub("_$", "") .. tostring(vlan_id)

	local changed = false
	if netifd_uses_device_sections(cursor) then
		-- 21.02+: a named `config device` bridge, and the interface points at
		-- it by name.
		if cursor:get("network", br_section, "name") ~= br_name then
			cursor:set("network", br_section, "device")
			cursor:set("network", br_section, "type", "bridge")
			cursor:set("network", br_section, "name", br_name)
			cursor:set("network", br_section, "ports", {ifname})
			changed = true
		else
			-- Section already there: add the uplink if it is missing and
			-- leave every other member in place (see OWNERSHIP above).
			local ports = cursor:get("network", br_section, "ports")
			if type(ports) == "string" then ports = {ports} end
			ports = ports or {}
			local have = false
			for _, p in ipairs(ports) do if p == ifname then have = true end end
			if not have then
				ports[#ports + 1] = ifname
				cursor:set("network", br_section, "ports", ports)
				changed = true
			end
		end
		if cursor:get("network", section_name, "device") ~= br_name then
			cursor:set("network", section_name, "interface")
			cursor:set("network", section_name, "device", br_name)
			cursor:set("network", section_name, "proto", "none")
			-- Leaving a stale ifname behind would have netifd bridge the raw
			-- sub-device instead of the bridge on some builds.
			cursor:delete("network", section_name, "ifname")
			changed = true
		end
	else
		-- Pre-21.02: the interface IS the bridge, with the sub-device as its
		-- only member port.
		if cursor:get("network", section_name, "ifname") ~= ifname
			or cursor:get("network", section_name, "type") ~= "bridge" then
			cursor:set("network", section_name, "interface")
			cursor:set("network", section_name, "type", "bridge")
			cursor:set("network", section_name, "ifname", ifname)
			cursor:set("network", section_name, "proto", "none")
			changed = true
		end
	end

	if changed then cursor:commit("network") end
	-- Reported to the caller so one network reload covers every VLAN in a
	-- push, and a steady-state push that changed nothing issues none.
	M._network_dirty = M._network_dirty or changed

	return section_name
end

-- Delete the interface and bridge sections of every VLAN not in `wanted`
-- (a set keyed by VLAN id). Only openUF's own sections are ever touched --
-- same discipline as wlan_clear()'s openuf_ prefix rule.
--
-- Called on every push, including one that carries no VLAN at all: deleting
-- the last tagged WLAN has to tear its L2 down too, and an empty `wanted` is
-- exactly how that arrives.
function M.prune_vlan_networks(wanted)
	local uci = get_uci()
	local cursor = uci.cursor()
	wanted = wanted or {}

	local doomed = {}
	local function sweep(stype, pattern)
		cursor:foreach("network", stype, function(s)
			local id = s[".name"] and s[".name"]:match(pattern)
			if id and not wanted[tonumber(id)] then
				doomed[#doomed + 1] = s[".name"]
			end
		end)
	end
	sweep("interface", "^" .. OPENUF_PREFIX .. "vlan(%d+)$")
	sweep("device",    "^" .. OPENUF_PREFIX .. "brdev(%d+)$")

	if #doomed == 0 then return false end
	for _, name in ipairs(doomed) do
		cursor:delete("network", name)
	end
	cursor:commit("network")
	M._network_dirty = true
	return true
end

-- ─── Radio configuration ─────────────────────────────────────────────────────

-- Configure a radio's channel, mode, and TX power.
-- radio:  UCI radio name, e.g. "radio0"
-- htmode: UCI/OpenWrt htmode string ("HT20", "HT40", "VHT80", "HE80", ...), or
-- nil to leave the radio's current width/PHY unchanged. Derived from the
-- controller's radio.<n>.ieee_mode by inform.lua's _htmode_from_ieee_mode --
-- that key is the wire's only channel-width signal (CONFIRMED live
-- 2026-07-18). Until then this argument was a "11n"/"11ac"/"11ax" token that
-- nothing on the parse side ever produced, so htmode was never written at all
-- and the controller's channel-width setting silently did nothing.
-- chan:   channel number, or the string "auto" (written verbatim -- UCI
-- channel=auto makes OpenWrt engage hostapd ACS at radio bring-up)
-- txpwr: TX power in dBm, the string "auto" (deletes the UCI option --
-- absent txpower = driver default/max, the closest UCI has to Auto), or
-- nil to leave unchanged
-- minrssi_enabled/minrssi_raw: "Minimum RSSI" (Devices -> [AP] -> Radios),
-- a per-radio (not per-SSID) setting -- confirmed live 2026-07-14 via the
-- controller's stamgr.<n>.minrssi.* wire keys, a section separate from and
-- indexed the same as radio.<n>. minrssi_raw is stored as-received (raw wire
-- units, an offset from the driver's noise floor, NOT plain dBm -- see
-- inform.lua's M._parse_wifi_system_cfg for the conversion math), since the
-- dBm conversion needs a live noise-floor reading only available later, at
-- enforcement/readback time. On disable only the flag is written to 0;
-- minrssi_rssi stays parked in UCI (harmless -- every consumer gates on the
-- flag first) so a later re-enable without a threshold change reuses it.
-- rates: optional table from M.derive_rates() plus an optional beacon_rate,
-- i.e. the "Minimum Data Rate" settings. These are wifi-DEVICE options in
-- OpenWrt, not wifi-iface ones (confirmed in OpenWrt's hostapd.sh: basic_rate,
-- supported_rates, legacy_rates and beacon_rate are all read by
-- hostapd_common_add_device_config and appended to the radio's base_cfg), even
-- though the controller sends Minimum Data Rate per WLAN. apply_config()
-- therefore aggregates the radio's VAPs down to one setting -- see there.
-- Writes are stamped with an openuf_rates marker; rates == nil on a marked
-- section tears all four options down (the wire signals "control off" by
-- omitting every minrate_* key), while unmarked sections are left alone.
-- disabled: tri-state per-radio enable, from the controller's
-- radio.<n>.status (Radios -> Transmit Power -> Disabled). nil leaves UCI
-- alone -- a blob that never carries the key must not re-enable a radio the
-- user disabled by hand; only an explicit enabled/disabled writes.
-- country: ISO 3166-1 alpha-2 regulatory domain from the controller's site
-- setting (system_cfg's radio.<n>.countrycode, numeric on the wire and mapped
-- to alpha-2 by inform.lua). nil leaves UCI alone.
function M.rf_config(radio, htmode, chan, txpwr, minrssi_enabled, minrssi_raw, rates,
		disabled, country)
	local uci = get_uci()
	local cursor = uci.cursor()
	-- Every write below is cursor:set on a named section, which in UCI CREATES
	-- that section when it does not exist. A controller naming a phy this
	-- device does not have (a stale device record, a config cloned from
	-- another AP, an emulated model whose radio count differs from the real
	-- hardware's) would therefore materialize a phantom `wifi-device` that no
	-- driver backs -- carried into every later get_radio_table() and reported
	-- to the controller as a real radio. Refuse instead.
	local exists = false
	cursor:foreach("wireless", "wifi-device", function(s)
		if s[".name"] == radio then exists = true end
	end)
	if not exists then
		io.stderr:write(string.format(
			"openuf: rf_config: no wifi-device section %q on this device -- ignoring\n",
			tostring(radio)))
		return false
	end
	if disabled ~= nil then
		cursor:set("wireless", radio, "disabled", disabled and "1" or "0")
	end
	if country and country ~= cursor:get("wireless", radio, "country") then
		-- The regdomain decides which channels are legal and how much power
		-- each may use, so it has to be written BEFORE the channel and txpower
		-- below -- and it invalidates the cached driver capabilities, whose
		-- per-channel dBm limits are regdomain-derived.
		cursor:set("wireless", radio, "country", country)
		M._phy_caps_cache = nil
	end
	if chan then
		cursor:set("wireless", radio, "channel", tostring(chan))
	end
	if htmode then
		-- The radio's band comes from its own UCI declaration, not from the
		-- channel being pushed alongside: a radio's band is fixed by hardware,
		-- and `chan` can be the literal "auto".
		local band = band_for_device({
			band    = cursor:get("wireless", radio, "band"),
			hwmode  = cursor:get("wireless", radio, "hwmode"),
			channel = cursor:get("wireless", radio, "channel") or chan,
		})
		local clamped, requested = M.clamp_htmode(band, htmode)
		if requested then
			io.stderr:write(string.format(
				"openuf: %s: controller asked for htmode %s, hardware supports %s -- clamped\n",
				radio, requested, clamped))
		end
		cursor:set("wireless", radio, "htmode", clamped)
	end
	if txpwr == "auto" then
		-- UCI has no auto txpower value: absent option = driver default/max.
		-- Deleting is what makes "Transmit Power: Auto" actually revert a
		-- previously pushed fixed dBm instead of stranding it.
		cursor:delete("wireless", radio, "txpower")
	elseif txpwr then
		cursor:set("wireless", radio, "txpower", tostring(txpwr))
	end
	if minrssi_enabled ~= nil then
		cursor:set("wireless", radio, "minrssi_enabled", minrssi_enabled and "1" or "0")
	end
	if minrssi_raw then
		cursor:set("wireless", radio, "minrssi_rssi", tostring(minrssi_raw))
	end
	if rates then
		-- Stamp the sections we rate-manage: "Minimum Data Rate off" arrives
		-- as the minrate_* keys simply vanishing from the wire, which is
		-- indistinguishable from "never managed / user hand-tuned basic_rate"
		-- without a ledger. The marker (same template as set_wlan_exclusive's
		-- openuf_autodisabled stamp) confines the teardown below to options
		-- openUF itself wrote.
		cursor:set("wireless", radio, "openuf_rates", "1")
		-- basic_rate/supported_rates are UCI *list* options carrying kb/s
		-- values; OpenWrt divides each by 100 itself (hostapd_add_rate) to
		-- reach hostapd's 100-kbps units, so they are set in kb/s as received.
		-- Each absent field is DELETED, not skipped: supported_rates and
		-- beacon_rate can legitimately drop out while the feature stays on
		-- (the drop-below/beacon sub-toggles), and a skip would strand the
		-- previous stricter push.
		if rates.basic_rate then
			cursor:set("wireless", radio, "basic_rate", rates.basic_rate)
		else
			cursor:delete("wireless", radio, "basic_rate")
		end
		if rates.supported_rates then
			cursor:set("wireless", radio, "supported_rates", rates.supported_rates)
		else
			cursor:delete("wireless", radio, "supported_rates")
		end
		if rates.legacy_rates then
			cursor:set("wireless", radio, "legacy_rates", rates.legacy_rates)
		else
			cursor:delete("wireless", radio, "legacy_rates")
		end
		-- beacon_rate is only written where the driver can actually program it.
		-- hostapd does not degrade gracefully here: on a driver without
		-- NL80211_EXT_FEATURE_BEACON_RATE_LEGACY it logs
		--   nl80211: Driver does not support setting Beacon frame rate (legacy)
		--   Failed to set beacon parameters / Interface initialization failed
		-- and the radio never comes up at all -- one unsupported option takes
		-- the whole band off the air. Confirmed on a real Archer C5 v1: its
		-- ath9k 2.4GHz radio died on exactly this while the ath10k 5GHz radio
		-- (which the controller sent no beacon_rate for) came up fine.
		local band_caps = M.phy_caps()[band_for_device({
			band    = cursor:get("wireless", radio, "band"),
			hwmode  = cursor:get("wireless", radio, "hwmode"),
			channel = cursor:get("wireless", radio, "channel"),
		})]
		-- Unknown capability (no iw, unparseable output) writes the option:
		-- the honest default is to do what the controller asked, as before.
		local beacon_ok = (band_caps == nil) or band_caps.beacon_rate
		if rates.beacon_rate and beacon_ok then
			-- beacon_rate is the exception among these options: OpenWrt appends
			-- it to the hostapd config verbatim, with NO /100 conversion, and
			-- hostapd documents its beacon_rate as a legacy rate in 100-kbps
			-- units. So this one -- unlike basic_rate/supported_rates above --
			-- has to be converted here, or a 12000 kb/s floor would ask for
			-- 1.2 Gbps.
			cursor:set("wireless", radio, "beacon_rate",
				tostring(math.floor(rates.beacon_rate / 100)))
		else
			if rates.beacon_rate then
				io.stderr:write(string.format(
					"openuf: %s: driver cannot set a beacon rate -- skipping " ..
					"beacon_rate=%s (hostapd would refuse to start the radio)\n",
					radio, tostring(rates.beacon_rate)))
			end
			cursor:delete("wireless", radio, "beacon_rate")
		end
	elseif cursor:get("wireless", radio, "openuf_rates") == "1" then
		-- Minimum Data Rate reverted to off: no VAP on this radio carries a
		-- floor anymore, so tear down exactly the options the marker says we
		-- wrote. Without this, the old basic_rate/supported_rates kept
		-- excluding slow clients forever after the control was turned off.
		-- Hand-tuned rate options on unmarked sections are never touched.
		for _, opt in ipairs({"basic_rate", "supported_rates", "legacy_rates",
				"beacon_rate", "openuf_rates"}) do
			cursor:delete("wireless", radio, opt)
		end
	end
	cursor:commit("wireless")
	return true
end

-- ─── Config apply ────────────────────────────────────────────────────────────

-- Apply a full config payload from the controller.
-- resp: decoded JSON table from the controller's inform response.
-- cfg:  device configuration (from conf.lua); used for dev.conf.net.lan_cpueth
--       when a VAP requires a VLAN-tagged network. VLAN tagging is skipped
--       (falls back to "lan") if cfg is nil.
-- opts: optional table; opts.keep_vlans is a set of VLAN ids that must keep
--       their L2 even when no WLAN sits on them -- a wired port assigned to
--       that VLAN on a DSA board lives in the same bridge. opts.band_steering_active (boolean) forces 802.11k +
--       BSS Transition on for every managed iface regardless of each WLAN's
--       own bss_transition setting, since usteer (Band Steering) needs it
--       network-wide to function at all -- see openuf/usteer.lua. nil/false
--       leaves each vap's own setting in effect. opts.device_name is the
--       controller-assigned device name, used as the WPS Device Name value
--       when a vap has advertise_ap_name enabled ("Show Access Point Name in
--       Beacon"); defaults to "openUF" if nil.
-- Handles vap_table and radio_table from the setparam/config response.
function M.apply_config(resp, cfg, opts)
	local radio_table   = resp.radio_table   or {}
	local vap_table     = resp.vap_table     or {}
	local cpueth = cfg and cfg.net and cfg.net.lan_cpueth

	-- "Minimum Data Rate" arrives per WLAN but OpenWrt's rate options are
	-- per radio, so every VAP sharing a radio has to collapse to one setting.
	-- The aggregate is deliberately the most PERMISSIVE of them: the lowest
	-- floor, CCK still allowed if any WLAN allows it, and lower rates only
	-- dropped from the advertised set if every WLAN asked for that. Erring
	-- the other way would apply one WLAN's stricter floor to a co-hosted WLAN
	-- and lock out clients the controller fully intended to admit -- a
	-- silent, on-air-only failure. VAPs with no floor (the key is absent
	-- whenever that band's control is off) contribute nothing.
	local rates_by_radio = {}
	for _, vap in ipairs(vap_table) do
		if vap.radio and vap.minrate_data then
			local agg = rates_by_radio[vap.radio]
			if not agg then
				-- drop_below is `== true`, not `~= false`: an absent
				-- minrate_below_disable key must count as permissive (don't
				-- trim the advertised set), matching both the most-permissive
				-- contract above and the `if not ...` fold below -- the old
				-- `~= false` made a single VAP with the key absent STRICT,
				-- and flipped to permissive when a second identical VAP
				-- appeared.
				agg = {floor = vap.minrate_data, allow_cck = vap.minrate_cck,
					drop_below = vap.minrate_below_disable == true,
					beacon_rate = vap.beacon_rate}
				rates_by_radio[vap.radio] = agg
			else
				if vap.minrate_data < agg.floor then
					agg.floor = vap.minrate_data
					agg.beacon_rate = vap.beacon_rate
				end
				if vap.minrate_cck ~= false then agg.allow_cck = true end
				if not vap.minrate_below_disable then agg.drop_below = false end
			end
		end
	end

	-- Apply radio parameters
	for _, radio in ipairs(radio_table) do
		if radio.name then
			local rates
			local agg = rates_by_radio[radio.name]
			if agg then
				rates = M.derive_rates(agg.floor, agg.allow_cck, agg.drop_below)
				if rates then rates.beacon_rate = agg.beacon_rate end
			end
			M.rf_config(radio.name, radio.htmode, radio.channel, radio.tx_power,
				radio.min_rssi_enabled, radio.min_rssi, rates, radio.disabled,
				radio.country)
		end
	end

	-- Clear existing openuf_ VAPs and re-add from vap_table
	M.wlan_clear()
	-- Every VLAN this push still wants an L2 for; anything else gets pruned
	-- after the loop.
	local wanted_vlans = {}
	for _, vap in ipairs(vap_table) do
		if vap.ssid and vap.radio then
			local extra = {}
			-- Per-VAP enable, from the controller's wireless.<n>.status. A
			-- disabled WLAN is still provisioned, just with disabled=1, so its
			-- whole config survives a re-enable. These sections are openUF's
			-- own and are rebuilt by wlan_clear() on every push, so there is no
			-- stale state to strand and no need for the autodisabled stamp
			-- set_wlan_exclusive() uses for the user's sections.
			if vap.disabled ~= nil then
				extra.disabled = vap.disabled and "1" or "0"
			end
			-- The controller carries two independent FT toggles: ft.status
			-- for the WLAN and wpa3.ft.status for the SAE akm alone (the
			-- latter only on SAE pushes, so nil elsewhere). OpenWrt cannot
			-- express the split -- one ieee80211r switch feeds hostapd's
			-- key_mgmt, and on sae-mixed it yields FT-PSK *and* FT-SAE
			-- together. So enable FT if either toggle asks for it: that
			-- honours every explicit "enabled" and never silently drops a
			-- capability the controller requested. Warn when they disagree,
			-- because the extra akm is ours, not the controller's.
			local ft_enabled = vap.fast_roaming_enabled
			if vap.wpa3_fast_roaming_enabled ~= nil
				and vap.wpa3_fast_roaming_enabled ~= (vap.fast_roaming_enabled or false) then
				ft_enabled = true
				io.stderr:write(string.format(
					"openuf: %s: ft.status=%s but wpa3.ft.status=%s -- OpenWrt cannot "
						.. "enable 802.11r for one akm only, enabling it for both\n",
					tostring(vap.ssid),
					vap.fast_roaming_enabled and "enabled" or "disabled",
					vap.wpa3_fast_roaming_enabled and "enabled" or "disabled"))
			end
			if ft_enabled then
				extra.ieee80211r = "1"
				extra.mobility_domain = M.derive_mobility_domain(vap.ssid)
				extra.ft_over_ds = "0"
				-- ft_psk_generate_local is deliberately NOT set. It used to be
				-- forced to "1", which silently disabled fast roaming for every
				-- WPA3 client: local key generation is FT-PSK only (each AP
				-- derives PMK-R0/R1 from the PSK it already has), while FT-SAE
				-- derives PMK-R0 from the per-session SAE PMK, which no
				-- passphrase can reproduce. Its PMK-R1 has to be pulled from
				-- the originating AP over the r0kh/r1kh key-holder
				-- relationship -- and forcing local generation is exactly what
				-- stops OpenWrt configuring one.
				--
				-- Observed live on a sae-mixed WLAN: both APs advertised
				-- FT-SAE and the mobility domain correctly, and a station that
				-- had negotiated FT-SAE still reassociated with auth_alg=sae
				-- plus a full EAPOL 4-way -- a fast transition shows
				-- auth_alg=ft and no 4-way at all. It failed even roaming
				-- between two BSSes on the SAME radio, so this was never about
				-- the APs failing to reach each other.
				--
				-- OpenWrt's own default is already right, and better than
				-- anything worth restating here: hostapd.sh keys it on
				-- auth_type (psk -> 1, anything else -> 0) and, when it is 0,
				-- auto-derives wildcard key holders from
				-- md5(mobility_domain .. "/" .. psk) -- deterministic, so every
				-- AP sharing an SSID and passphrase computes the same key with
				-- no coordination, which is the same reasoning behind
				-- derive_mobility_domain above. Leaving the option unset lets
				-- that run: FT-PSK keeps local derivation and needs no
				-- inter-AP traffic, FT-SAE gets the key holders it cannot work
				-- without.
			end
			if opts and opts.band_steering_active then
				-- usteer requires 802.11k (neighbor reports) + BSS
				-- Transition on every managed iface network-wide to
				-- function at all -- confirmed via the OpenWrt wiki's
				-- usteer setup guide. This overrides each WLAN's own
				-- bss_transition/ieee80211k value while device-wide Band
				-- Steering is on, since usteer can't be scoped to a
				-- single SSID.
				extra.ieee80211k          = "1"
				extra.bss_transition      = "1"
				extra.rrm_neighbor_report = "1"
				extra.rrm_beacon_report   = "1"
				extra.wnm_sleep_mode      = "1"
			else
				if vap.bss_transition ~= nil then
					extra.bss_transition = vap.bss_transition and "1" or "0"
				end
			end
			if vap.dtim_period then extra.dtim_period = vap.dtim_period end
			if vap.qbssload ~= nil then
				-- "Force WiFi 4 Mode" (IoT Optimization) sends
				-- wireless.<n>.qbssload=disabled alongside iot=enabled. The
				-- QBSS Load element is emitted by hostapd whenever
				-- bss_load_update_period is non-zero (it is the element's
				-- refresh interval, in beacon intervals); 0 suppresses the
				-- element entirely, which is what the controller is asking
				-- for. 60 is hostapd's own conventional enabled value.
				extra.bss_load_update_period = vap.qbssload and "60" or "0"
			end
			if vap.iot then
				-- Recorded so the applied WiFi-4-compat state is visible in
				-- UCI (and in tests) rather than being invisible. There is
				-- deliberately no radio-level action here: the controller
				-- keeps the shared radio at its configured width, and the
				-- rest of the mode's behavior arrives as the ordinary keys
				-- handled above and below (2.4GHz-only vap placement, WPA2,
				-- PMF/BSS-transition/proxy-ARP/band-steering off). See
				-- inform.lua's parse-side comment for the live evidence.
				extra.openuf_iot = "1"
			end
			if vap.pmf_status ~= nil then
				-- 802.11w PMF. ieee80211w: 0=disabled, 1=optional, 2=required
				-- (hostapd's own option, madwifi/mac80211 alike). The
				-- controller signals this via aaa.<n>.pmf.status+pmf.mode; a
				-- disabled block is mode 0. Written explicitly for both
				-- enabled and disabled so the applied value always reflects
				-- the controller's intent (a WPA2-only WLAN gets an explicit
				-- ieee80211w=0, a WPA2/WPA3 mixed WLAN gets 1/2).
				local w = 0
				if vap.pmf_status == "enabled" then w = vap.pmf_mode or 1 end
				extra.ieee80211w = tostring(w)
			end
			if vap.mcast_enhance ~= nil then
				-- Multicast Enhancement: multicast_to_unicast is the
				-- OpenWrt/mac80211 wifi-iface option that proxies multicast
				-- frames as unicast at the AP (the mechanism UniFi's
				-- "Multicast Enhancement" / "Multicast to Unicast" provides).
				-- Written explicitly on/off, mirroring bss_transition.
				extra.multicast_to_unicast = vap.mcast_enhance and "1" or "0"
			end
			if vap.proxy_arp ~= nil then
				-- "Proxy ARP": the AP answers ARP (and IPv6 ND) on behalf of
				-- associated stations instead of flooding the request over the
				-- air, so sleeping clients aren't woken by every broadcast ARP.
				-- proxy_arp is hostapd's own option name and OpenWrt exposes it
				-- verbatim as a wifi-iface boolean (confirmed in OpenWrt's
				-- hostapd.sh: declared in hostapd_common_add_bss_config and
				-- emitted as "proxy_arp=1" into the per-BSS config). Like
				-- bss_transition it needs a full wpad build -- hostapd only
				-- compiles proxy_arp support in with CONFIG_PROXYARP, which the
				-- -mini/-basic wpad variants leave out. Written explicitly on
				-- and off, mirroring bss_transition/mcast_enhance.
				extra.proxy_arp = vap.proxy_arp and "1" or "0"
			end
			if vap.bcfilt_enabled ~= nil then
				-- "Multicast and Broadcast Blocker". Recorded on the section so
				-- the configured state is visible in `uci show` and survives to
				-- be re-derived later; the actual enforcement is nftables, done
				-- after the wifi reload below (see bcfilter.lua for why hostapd
				-- cannot express it).
				extra.openuf_bcfilt = vap.bcfilt_enabled and "1" or "0"
				if vap.bcfilt_macs and #vap.bcfilt_macs > 0 then
					extra.openuf_bcfilt_macs = table.concat(vap.bcfilt_macs, " ")
				end
			end
			if vap.l2_isolation ~= nil then
				-- "Client Isolation": drop station-to-station frames inside the
				-- BSS. OpenWrt's wifi-iface option is spelled "isolate" (it maps
				-- to hostapd's ap_isolate) -- confirmed in hostapd.sh's
				-- hostapd_common_add_bss_config declaration list.
				extra.isolate = vap.l2_isolation and "1" or "0"
			end
			if vap.hide_ssid ~= nil then
				-- "Hide WiFi Name": leave the SSID out of beacons (clients must
				-- know the name to associate). OpenWrt's wifi-iface option is
				-- spelled "hidden" and maps to hostapd's
				-- ignore_broadcast_ssid -- confirmed in hostapd.sh's
				-- hostapd_common_add_bss_config declaration list. Written
				-- explicitly on and off, since the controller always sends the
				-- key and un-hiding has to actually take effect.
				extra.hidden = vap.hide_ssid and "1" or "0"
			end
			-- "MAC Address Filter". OpenWrt's wifi-iface option is macfilter
			-- plus a maclist list, and the policy vocabulary lines up 1:1 with
			-- the controller's: allow = maclist is a whitelist, deny =
			-- blacklist.
			--
			-- "Off" is the ABSENCE of the option, not macfilter="disable".
			-- OpenWrt's own schema (/usr/share/schema/wireless.wifi-iface.json)
			-- declares macfilter as enum ["allow","deny"], and 25.12's ucode
			-- validator does not merely ignore an out-of-enum value -- it
			-- aborts the whole radio setup with die(), so BOTH radios come up
			-- with no interfaces at all and not one SSID reaches the air:
			--   wifi-scripts: macfilter: disable has to be one of [ "allow", "deny" ]
			--   netifd: radio0 (4179): Died
			-- Confirmed on a real Archer C5 v1 running OpenWrt 25.12.5, where
			-- this alone sank an otherwise perfect config push. Deleting is
			-- also what actually lifts a previously pushed filter: ap.uc's
			-- iface_macfilter() emits accept_mac_file/deny_mac_file only for
			-- the two enum values and returns for anything else.
			if vap.mac_filter_policy then
				extra.macfilter = vap.mac_filter_policy
				extra.maclist   = vap.mac_filter_list or {}
			else
				extra.macfilter = M.DELETE
				extra.maclist   = M.DELETE
			end
			-- "WiFi Speed Limit". Recorded on the section so the configured
			-- state shows up in `uci show`; the actual enforcement is tc, done
			-- after the wifi reload below (see shaper.lua for why no hostapd or
			-- OpenWrt option can express it). Values are kbps, as pushed.
			if vap.ratelimit_down_kbps then
				extra.openuf_ratelimit_down = vap.ratelimit_down_kbps
			end
			if vap.ratelimit_up_kbps then
				extra.openuf_ratelimit_up = vap.ratelimit_up_kbps
			end
			if vap.advertise_ap_name then
				-- "Show Access Point Name in Beacon" -- CONFIRMED (via
				-- decompiling the controller) to require a device-reported
				-- wifi_caps2 capability bit before the controller even
				-- pushes this field at all; see inform.lua's build_json
				-- for that side. There's no standalone "put this string in
				-- a beacon IE" hostapd option, but there IS a real,
				-- standard mechanism for broadcasting a human-readable
				-- device name in every beacon: the Wi-Fi Alliance WPS/WSC
				-- information element's Device Name attribute, which
				-- hostapd includes automatically once WPS is active
				-- (confirmed via hostapd's own README-WPS and OpenWrt's
				-- documented wifi-iface options: wps_device_name maps
				-- directly to hostapd's device_name). ap_setup_locked=1 is
				-- a standard hostapd/WPS hardening flag that disables
				-- PIN-based external registrar enrollment -- set
				-- unconditionally here to minimize the WPS surface this
				-- opens to only what's needed for the name broadcast,
				-- since no push-button/PIN config method is ever enabled.
				-- NOT independently confirmed against genuine Ubiquiti
				-- hardware (no real device available to capture from) --
				-- this is the standards-based mechanism for the stated
				-- goal, not a verified replica of Ubiquiti's own
				-- implementation.
				extra.wps_device_name = (opts and opts.device_name) or "openUF"
				extra.ap_setup_locked = "1"
			end
			if vap.sae_anti_clogging then
				-- hostapd's own option name for this exact WPA3-SAE tuning
				-- value (default 5, confirmed via hostapd upstream docs).
				-- Renamed to "anti_clogging_threshold" in newer hostapd
				-- (to also cover PASN, not just SAE) -- using the older
				-- name here since it's the one broadly supported across
				-- the OpenWrt/wpad versions this project targets; revisit
				-- if a target build's hostapd has dropped the old alias.
				extra.sae_anti_clogging_threshold = vap.sae_anti_clogging
			end
			if vap.sae_sync then
				-- hostapd's own option name, unchanged/stable across
				-- versions (confirmed via hostapd upstream docs) -- max
				-- SAE sync errors (dot11RSNASAESync) before disconnecting
				-- the offending peer.
				extra.sae_sync = vap.sae_sync
			end
			-- VLAN comes off the vap itself: the controller derives it from
			-- aaa.<n>.br.devname ("br0.20"), not from a linked network object.
			local vlan_enabled = vap.vlan_enabled
			local vlan_id      = vap.vlan

			local network = "lan"
			if vlan_enabled and vlan_id and cpueth then
				network = M.ensure_vlan_network(cpueth, vlan_id)
				wanted_vlans[tonumber(vlan_id) or vlan_id] = true
			end

			M.wlan_add(vap.radio, vap.ssid, vap.security, vap.x_passphrase, extra,
				network, vap.wlanconf_id)
		end
	end

	-- A VLAN no WLAN uses may still be wanted by a wired port assigned to it
	-- (DSA per-port VLAN puts the socket in this same bridge -- see
	-- ensure_vlan_network's OWNERSHIP note). Its bridge must survive the
	-- prune below, and be built even when no WLAN mentions the VID at all.
	for vid in pairs((opts and opts.keep_vlans) or {}) do
		local n = tonumber(vid) or vid
		if not wanted_vlans[n] and cpueth then
			M.ensure_vlan_network(cpueth, n)
			wanted_vlans[n] = true
		end
	end

	-- Drop the L2 of any VLAN no longer carried by a WLAN. Changing a
	-- network's VLAN id in the controller (20 -> 10) or deleting the WLAN
	-- outright leaves the old bridge and its tagged sub-device behind
	-- otherwise -- confirmed live on both APs, which kept a br-openuf20 with
	-- eth1.20 in it long after the WLAN had moved to VLAN 10. Harmless-looking
	-- but it accumulates, keeps a sub-device on the trunk forever, and makes
	-- the running config stop matching what the controller asked for.
	-- switchvlan.lua already reconciles its own switch_vlan sections this way.
	M.prune_vlan_networks(wanted_vlans)

	-- Hand-configured (non-openuf_) SSIDs: disable or restore them per
	-- conf.lua's use_only_unifi_wlan. Runs after the vap loop so it sees the
	-- final section set, and before the reload so both land in one restart.
	M.set_wlan_exclusive(cfg and cfg.config and cfg.config.use_only_unifi_wlan == true)

	-- A VLAN bridge that only exists in UCI carries no traffic: netifd has to
	-- be told, and `wifi reload` alone does not create a bridge device. Runs
	-- BEFORE the wireless reload so the bridge exists by the time hostapd's
	-- interfaces come up and netifd looks for something to enslave them to.
	--
	-- Gated on an actual change (ensure_vlan_network sets the flag) for the
	-- same reason switchvlan guards its own reload: every steady-state
	-- setparam re-carries the whole config, and reloading the network on each
	-- one would bounce the uplink -- and with it the inform connection --
	-- every few seconds.
	if M._network_dirty then
		M._run_cmd("/etc/init.d/network reload 2>/dev/null")
		M._network_dirty = false
	end

	-- Reload wireless
	M._run_cmd("wifi reload")

	-- "Multicast and Broadcast Blocker" enforcement. Deliberately after the
	-- reload: the rules key off each VAP's live netdev name, which only exists
	-- (and can change) once netifd has brought the interfaces back up. Always
	-- reconciled, even with no filtered VAPs, so turning the control off in the
	-- controller tears the previous ruleset down rather than leaving it in
	-- place -- the same reason firewall.lua rebuilds from scratch every time.
	local bcfilter = get_bcfilter()
	if bcfilter then
		local rules = {}
		for _, vap in ipairs(vap_table) do
			if vap.bcfilt_enabled and vap.ssid and vap.radio then
				local ifname = M.get_ifname_for_vap(vap.radio, vap.ssid)
				if ifname then
					rules[#rules + 1] = {ifname = ifname, macs = vap.bcfilt_macs or {}}
				end
			end
		end
		bcfilter.reconcile(rules)
	end

	-- "WiFi Speed Limit" enforcement, after the reload for the same reason.
	-- EVERY managed VAP is passed, not just the capped ones: shaper.reconcile
	-- clears each interface it is handed before reshaping it, so a VAP whose
	-- limit was just removed has to appear here (with both rates nil) to get
	-- its old qdisc torn down.
	local shaper = get_shaper()
	if shaper then
		local rules = {}
		for _, vap in ipairs(vap_table) do
			if vap.ssid and vap.radio then
				local ifname = M.get_ifname_for_vap(vap.radio, vap.ssid)
				if ifname then
					rules[#rules + 1] = {
						ifname    = ifname,
						down_kbps = vap.ratelimit_down_kbps,
						up_kbps   = vap.ratelimit_up_kbps,
					}
				end
			end
		end
		shaper.reconcile(rules)
	end
end

-- ─── Read helpers (for inform payload builder) ───────────────────────────────

-- Return a table of radio info for the inform payload.
-- hwassign: the modelmap's dev.openuf.uap.hwassign -- the radio names to
-- report. Documented since the first release as controlling exactly this, but
-- read by nothing until now, so every wifi-device in UCI was reported no matter
-- what the modelmap said. That matters on a board with a radio openUF should
-- not present as part of the emulated model (a third radio, a mesh-only or
-- monitor phy): the controller would show and try to configure a radio the
-- emulated model does not have. nil/empty keeps the report-everything
-- behavior, which is what a modelmap without hwassign means.
function M.get_radio_table(hwassign)
	local uci = get_uci()
	local cursor = uci.cursor()
	local allowed = nil
	if type(hwassign) == "table" and #hwassign > 0 then
		allowed = {}
		for _, name in ipairs(hwassign) do allowed[name] = true end
	end
	local radios = {}
	cursor:foreach("wireless", "wifi-device", function(s)
		if allowed and not allowed[s[".name"]] then return end
		radios[#radios + 1] = {
			name             = s[".name"],
			radio            = band_for_device(s),
			-- Numbers as numbers; the literal "auto" passes through as the
			-- honest config intent until build_json overrides it with the
			-- live negotiated channel.
			channel          = tonumber(s.channel) or s.channel,
			ht               = s.htmode,
			tx_power         = s.txpower,
			-- UCI regdomain (e.g. "CZ"); build_json maps it to the numeric
			-- ISO 3166 country_code. Internal -- stripped before serializing.
			country          = s.country,
			disabled         = (s.disabled == "1"),
			builtin_antenna  = M.RADIO_DEFAULTS.builtin_antenna,
			builtin_ant_gain = M.RADIO_DEFAULTS.builtin_ant_gain,
			-- Real per-band driver limit where `iw` can supply one: this is
			-- what bounds the controller's TX Power slider, so the static
			-- default made every radio claim 20 dBm regardless of hardware
			-- and regdomain. Falls back to the default when unknown.
			max_txpower      = (M.phy_caps()[band_for_device(s)] or {}).max_txpower
				or M.RADIO_DEFAULTS.max_txpower,
			-- min_rssi_enabled/min_rssi_raw: raw UCI echo of rf_config()'s
			-- minrssi_enabled/minrssi_rssi options. min_rssi_raw is still
			-- wire-encoded units at this point (not dBm) -- inform.lua's
			-- build_json converts it to the real outbound "min_rssi" dBm
			-- field once a live noise-floor reading is available, then
			-- discards this raw field.
			min_rssi_enabled = (s.minrssi_enabled == "1"),
			min_rssi_raw     = tonumber(s.minrssi_rssi),
		}
	end)
	return radios
end

-- The cjson binding used to parse `ubus call network.wireless status` for
-- the live ifname lookups below. Injectable (M._load_cjson) and cached; a
-- missing binding warns ONCE, loudly: without it every ifname resolution
-- returns nil and the Multicast/Broadcast Blocker AND the WiFi Speed Limit
-- silently become no-ops while apply_config still reports success -- the
-- kind of quiet degradation nothing would ever surface otherwise.
M._load_cjson = function()
	local ok, mod = pcall(require, "cjson")
	return ok and mod or nil
end
local cjson_checked, cjson_mod = false, nil
local function get_cjson()
	if not cjson_checked then
		cjson_checked = true
		cjson_mod = M._load_cjson()
		if not cjson_mod then
			io.stderr:write("ucihelper: lua-cjson unavailable -- live ifname "
				.. "resolution disabled; Multicast/Broadcast Blocker and WiFi "
				.. "Speed Limit will NOT be enforced\n")
		end
	end
	return cjson_mod
end

-- Resolve a UCI radio name (e.g. "radio0") to its live wireless netdev name
-- (e.g. "wlan0"), as assigned at runtime by netifd. Needed because sta_table()/
-- radio_stats() operate on the live `iw`-visible interface, not the UCI config
-- name. Returns nil if unresolvable (e.g. off-target, radio disabled).
function M.get_ifname_for_radio(radio)
	if not radio then return nil end
	local output = M._popen("ubus call network.wireless status")
	if output == "" then return nil end
	local cjson = get_cjson()
	if not cjson then return nil end
	local ok_d, status = pcall(cjson.decode, output)
	if not ok_d or type(status) ~= "table" then return nil end
	local dev = status[radio]
	if type(dev) == "table" and type(dev.interfaces) == "table" then
		for _, iface in ipairs(dev.interfaces) do
			if type(iface) == "table" and iface.ifname then
				return iface.ifname
			end
		end
	end
	return nil
end

-- Resolve a specific VAP to its live wireless netdev name, by matching the
-- SSID within the radio's interface list. get_ifname_for_radio() above returns
-- the radio's FIRST interface, which is the same thing only when the radio
-- hosts a single SSID -- not good enough for per-WLAN features like the
-- Multicast and Broadcast Blocker, where picking the wrong VAP's netdev would
-- silently apply one SSID's filter to another. Returns nil if unresolvable.
function M.get_ifname_for_vap(radio, ssid)
	if not radio or not ssid then return nil end
	local output = M._popen("ubus call network.wireless status")
	if output == "" then return nil end
	local cjson = get_cjson()
	if not cjson then return nil end
	local ok_d, status = pcall(cjson.decode, output)
	if not ok_d or type(status) ~= "table" then return nil end
	local dev = status[radio]
	if type(dev) ~= "table" or type(dev.interfaces) ~= "table" then return nil end
	for _, iface in ipairs(dev.interfaces) do
		if type(iface) == "table" and iface.ifname
			and type(iface.config) == "table" and iface.config.ssid == ssid then
			return iface.ifname
		end
	end
	-- Fall back to the radio's only interface when the SSID could not be
	-- matched but there is exactly one candidate: netifd does report
	-- config.ssid per interface, but nothing guarantees every build/version
	-- does, and with a single VAP on the radio there is no other interface it
	-- could be. Deliberately not extended to the multi-interface case -- there
	-- a wrong guess would apply one SSID's filter to another, which is worse
	-- than not applying it at all.
	if #dev.interfaces == 1 and type(dev.interfaces[1]) == "table" then
		return dev.interfaces[1].ifname
	end
	return nil
end

-- "Minimum RSSI" enforcement: send a single 802.11 deauthentication frame to
-- mac on ifname. Deliberately standalone from firewall.lua's block-sta
-- feature -- confirmed via web research that Minimum RSSI is a roaming aid,
-- not a block: it's a one-shot deauth with no persistent drop rule, and the
-- client is free to reassociate immediately (even back to the same radio).
-- No state.json persistence either, unlike blocked_stas -- there's nothing
-- to reconcile on restart since this is fully re-derived every inform cycle
-- from live UCI config + sta_table.
function M.kick_station(ifname, mac)
	M._run_cmd("hostapd_cli -i " .. ifname .. " deauthenticate " .. mac .. " 2>/dev/null")
	return true
end

-- Return a table of VAP (virtual AP) info for the inform payload.
function M.get_vap_table()
	local uci = get_uci()
	local cursor = uci.cursor()

	local radio_by_name = {}
	for _, r in ipairs(M.get_radio_table()) do radio_by_name[r.name] = r end

	local vaps = {}
	cursor:foreach("wireless", "wifi-iface", function(s)
		-- Skip foreign SSIDs that are switched off: a disabled section with no
		-- wlanconf id is not openUF's and is not on the air (typically
		-- OpenWrt's stock "OpenWrt" default_radioN sections, which
		-- use_only_unifi_wlan disables during provisioning). Reporting them
		-- claimed a VAP per radio that has no BSS, and -- because the nested
		-- sta_table is built per radio, not per BSS -- attributed every one of
		-- that radio's real stations to the phantom VAP as well, duplicating
		-- their traffic and retry counters across two vap_table entries.
		-- Confirmed on real hardware: a device with one live SSID reported
		-- four VAPs, the two "OpenWrt" ones carrying identical station counts
		-- and counters to the live ones.
		--
		-- A disabled vap that IS openUF-managed stays in the report: that is
		-- how a WLAN the controller itself disabled keeps showing up as
		-- disabled rather than vanishing.
		if s.disabled == "1" and not s.openuf_wlanconf_id then return end
		local radio = radio_by_name[s.device]
		local bssid = ""
		local ok_if, ifname = pcall(M.get_ifname_for_radio, s.device)
		if ok_if and ifname then
			local mac_raw = M._read_file("/sys/class/net/" .. ifname .. "/address")
			if mac_raw then bssid = mac_raw:match("^([%x:]+)") or "" end
		end
		vaps[#vaps + 1] = {
			name          = s[".name"],
			essid         = s.ssid,
			-- "radio" must be the band identifier ("ng"/"na"), not the UCI
			-- device name -- confirmed via the controller's own stats
			-- pipeline (com.ubnt.service.system.QDcGUYAmLvJwylXw), which
			-- feeds vap_table's "radio" field through the same band-parsing
			-- enum (com.ubnt.g.f.e.rYtJfMBbtgWvku) already fixed for
			-- radio_table -- sending "radio0" here instead of "ng" logs
			-- "unexpected radio[radio0] while processing stats" on every
			-- inform and silently drops that vap's per-station stats
			-- aggregation. "radio_name" (the UCI device name) is a
			-- separate, real field on the same DTO -- kept here unchanged.
			radio         = radio and radio.radio,
			radio_name    = s.device,
			encryption    = s.encryption,
			disabled      = (s.disabled == "1"),
			bssid         = bssid,
			channel       = radio and radio.channel,
			tx_power      = radio and radio.tx_power,
			usage         = "user",
			-- "id" must echo the controller's wlanconf ObjectId (delivered in
			-- system_cfg as aaa.<n>.id, stashed by wlan_add): the controller's
			-- vapInformProcessor silently drops any usage=user vap whose "id"
			-- is missing -- discarding the nested sta_table with it, which
			-- kept every wireless client out of the Clients list. The
			-- controller derives wlanconf_id itself from "id", but the real
			-- DTO carries both, so send both. (Previously this sent the
			-- *networkconf* id as wlanconf_id -- a different object; that id
			-- stays in its own UCI option for the VLAN/mobility-domain logic.)
			id            = s.openuf_wlanconf_id,
			wlanconf_id   = s.openuf_wlanconf_id,
		}
	end)
	return vaps
end

return M
