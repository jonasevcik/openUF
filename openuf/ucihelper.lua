--[[
	UCI helper for WiFi provisioning.

	Manages SSID sections named with the "openuf_" prefix so that user-created
	SSIDs are never touched.  The controller pushes config via the inform
	response dispatcher (inform.handle_response → apply_config).

	Requires: uci (Lua UCI bindings, standard on OpenWrt)
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable seams for tests
M._uci        = nil  -- override with a mock UCI table; nil = require("uci")
-- "Multicast and Broadcast Blocker" enforcement (nftables). Injectable so
-- tests can capture the reconciled rules without shelling out to real nft.
M._bcfilter   = nil  -- nil = load openuf/bcfilter.lua on first use
-- "WiFi Speed Limit" enforcement (tc). Injectable for the same reason.
-- Minimum RSSI's constants (wire offset, refusal margin).
M._minrssi    = nil  -- nil = load openuf/minrssi.lua on first use
M._run_cmd    = os.execute

-- Injectable: command execution that captures stdout (for read-only introspection,
-- as opposed to M._run_cmd which only reports success/failure for mutating commands).
M._popen = util.capture

-- Injectable: file reader, for sysfs lookups (e.g. interface MAC address).
M._read_file = util.read_file

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

-- One cursor for a whole config push, instead of one per VAP.
--
-- Every writer below used to open its own cursor and commit it, so a push
-- rewrote /etc/config/wireless once per WLAN -- three times over for a WLAN
-- carrying private pre-shared keys and MAC-based VLANs. That is a flash write
-- each time on boards with ~5 MB of free overlay, for a file whose final
-- contents are the same either way. `apply_config` now opens one cursor, hands
-- it to each writer, and commits once when the VAP loop is done.
--
-- Called with a cursor, borrow it and leave the committing to its owner;
-- called with nil, open one and commit it, which is what every other caller
-- (and every direct caller in the tests) still relies on.
local function borrow_cursor(cursor)
	if cursor then return cursor, false end
	return get_uci().cursor(), true
end

local function release_cursor(cursor, owned, config)
	if owned then cursor:commit(config) end
end

-- General memo for the lookup pass M.begin_pass/end_pass open (see the
-- wireless_status cache further down, which was the first thing to need one).
-- Anything in here answers the SAME question for the length of one inform
-- payload; outside a pass every call recomputes, which is what keeps the test
-- suite's per-test stubs independent of one another.
M._pass_cache = nil
local function pass_memo(key, fn)
	local cache = M._ws_pass and M._pass_cache
	if cache then
		local hit = cache[key]
		if hit ~= nil then return hit[1] end
	end
	local value = fn()
	if cache then cache[key] = {value} end
	return value
end

-- One cursor per pass: libuci keeps a package a cursor has loaded, so
-- /etc/config/wireless is parsed once per tick however many readers ask.
local function pass_cursor()
	return pass_memo("cursor", function() return get_uci().cursor() end)
end

-- Call fn on every wifi-iface section, in file order, as cursor:foreach
-- would. Inside a pass the sections are collected once: schedule_vaps runs
-- every tick and get_vap_table every heartbeat, and each walked the package
-- for the same answer. The section tables are shared between callers, which
-- only read them.
local function each_iface(fn)
	local rows = pass_memo("iface_sections", function()
		local out = {}
		pass_cursor():foreach("wireless", "wifi-iface", function(s) out[#out + 1] = s end)
		return out
	end)
	for _, s in ipairs(rows) do fn(s) end
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
local function get_minrssi()  return get_sibling("minrssi",  M._minrssi)  end
local _plugins_mod
local function get_plugins()
	if M._plugins then return M._plugins end
	_plugins_mod = _plugins_mod or get_sibling("plugins", nil)
	return _plugins_mod
end

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
-- runs -- with one exception. A regdomain change moves the per-channel TX
-- power limits and the DFS flags, so rf_config drops the cache when it writes
-- a new country. But the DRIVER only picks the new domain up when `wifi
-- reload` restarts the radios, which happens later in the same apply_config
-- pass and asynchronously at that -- while rf_config itself re-reads the caps
-- moments after dropping them (clamp_htmode, the beacon_rate check). So the
-- cache came straight back holding the OLD domain's figures and kept them
-- until the daemon restarted, and the max_txpower reported to the controller
-- -- the bound on its TX Power slider -- was the wrong regdomain's.
--
-- Hence the settle window: for PHY_CAPS_SETTLE seconds after a regdomain
-- write, cached caps are trusted for at most PHY_CAPS_REREAD seconds at a
-- time. After that it is back to cache-forever.
M._phy_caps_cache = nil
M._phy_caps_read_at = nil
M._phy_caps_unstable_until = nil
local PHY_CAPS_SETTLE = 60   -- the reload is long done inside this
local PHY_CAPS_REREAD = 10   -- one heartbeat

-- Injectable clock, for the settle window above.
M._time = os.time

local function regdomain_changed()
	M._phy_caps_cache = nil
	M._phy_caps_unstable_until = M._time() + PHY_CAPS_SETTLE
end

-- Parse `iw phy` output into per-band capabilities, keyed by band_for_device's
-- own vocabulary ("ng"/"na"). Each band is identified by the frequencies it
-- actually lists, NOT by its "Band N:" index -- that index is assigned per
-- driver (this project's ath9k radio reports 2.4GHz as Band 1, its ath10k
-- radio reports 5GHz as Band 2) and means nothing on its own.
-- The pairwise cipher suite selectors nl80211 reports per wiphy
-- (IEEE 802.11 Table 12-4: 0x000FAC<n>), keyed by the token OpenWrt's
-- `encryption` string names them with -- iface.uc's second `+` token. Only the
-- ciphers the controller can actually ask for are listed; TKIP and the WEP
-- selectors are deliberately absent (see _wire_pairwise in inform.lua).
local CIPHER_SELECTOR = {
	ccmp    = 1027076,   -- 0x000FAC04
	gcmp    = 1027080,   -- 0x000FAC08
	gcmp256 = 1027081,   -- 0x000FAC09
	ccmp256 = 1027082,   -- 0x000FAC0A
}

-- `iw phy` does NOT list cipher suites on this target (iw 6.17 on 25.12 prints
-- no Supported Ciphers block at all, verified on both boards 2026-10-26), so
-- the one reliable local source is nl80211 itself. ucode and its nl80211
-- binding ship with the wifi stack on 25.12 and are present on both boards.
-- Output is one line per phy: "<phyname> <selector> <selector> ...".
local CIPHER_PROBE = "ucode -l nl80211 -e '"
	.. "let r = nl80211.request(nl80211.const.NL80211_CMD_GET_WIPHY, "
	.. "nl80211.const.NLM_F_DUMP, {}); "
	.. "for (let w in r) print(w.wiphy_name + \" \" "
	.. "+ join(\" \", w.cipher_suites || []) + \"\\n\");' 2>/dev/null"

-- "phy0 1027076 1027080 ..." -> {phy0 = {ccmp = true, gcmp = true, ...}}.
-- A phy that reports no suites at all is left OUT of the result rather than
-- recorded as an empty set: "the probe told us nothing" must not read as "this
-- radio supports no cipher", which would veto every override.
local function parse_cipher_suites(out)
	local by_phy = {}
	for line in (tostring(out) .. "\n"):gmatch("([^\n]*)\n") do
		local name, rest = line:match("^(phy%w+)%s+(.*)$")
		if name and rest ~= "" then
			local set = {}
			for sel in rest:gmatch("%d+") do
				local n = tonumber(sel)
				for token, want in pairs(CIPHER_SELECTOR) do
					if n == want then set[token] = true end
				end
			end
			if next(set) then by_phy[name] = set end
		end
	end
	return by_phy
end

local function parse_phy_caps(out, ciphers_by_phy)
	local bands, cur, phy = {}, nil, nil
	for line in (tostring(out) .. "\n"):gmatch("([^\n]*)\n") do
		-- Phy-level lines carry exactly one leading tab; a Band block's
		-- contents are indented deeper. That is what marks the end of a band
		-- block -- without it, phy-level sections listed after the bands (the
		-- extended-feature list below) would be attributed to whichever band
		-- happened to be last.
		if line:match("^%s*Wiphy%s") then
			-- The name is kept so the cipher probe, which is keyed by phy and
			-- not by band, can be attributed to the right radio.
			phy = {beacon_rate = false, bands = {},
				name = line:match("^%s*Wiphy%s+(%S+)")}
			cur = nil
		elseif line:match("^\tBand %d+:") then
			cur = {ht40 = false, vht = false, he = false, eht = false,
				w160 = false, w320 = false, freq = nil, txpower = nil,
				channels = {}, phy = phy}
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
				-- The channel number in brackets, for the ACS candidate list
				-- (rf_config's chanlist). The regdomain decides which channels
				-- `iw phy` prints at all and which it marks disabled, so this
				-- list is already the legal set -- which is what makes
				-- inverting the controller's blacklist possible. "no IR" is
				-- excluded on top: the radio may not initiate radiation there,
				-- so it is legal to hear but never a channel an AP can beacon
				-- on. (It still counts toward max_txpower above, which is a
				-- reported capability and not a channel choice.)
				local ch = tonumber(line:match("%[(%d+)%]") or "")
				if ch and not line:match("no IR") then
					cur.channels[#cur.channels + 1] = ch
				end
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
				-- nil, not {}, when the probe said nothing about this phy --
				-- cipher_ok() treats nil as "unknown, don't veto".
				ciphers = (b.phy and b.phy.name and ciphers_by_phy
					and ciphers_by_phy[b.phy.name]) or nil,
				-- Channels this band can legally use, ascending. nil (not an
				-- empty table) when `iw` said nothing, so rf_config can tell
				-- "no channels" from "unknown" and skip narrowing ACS rather
				-- than narrowing it to nothing.
				channels = (b.channels and #b.channels > 0) and b.channels or nil,
			}
			if prev then
				caps[key].max_kind  = math.max(prev.max_kind, caps[key].max_kind)
				caps[key].max_width = math.max(prev.max_width, caps[key].max_width)
				caps[key].max_txpower = math.max(prev.max_txpower or 0,
					caps[key].max_txpower or 0)
				if caps[key].max_txpower == 0 then caps[key].max_txpower = nil end
				caps[key].beacon_rate = prev.beacon_rate or caps[key].beacon_rate
				-- Channels fold as a UNION: either phy could end up hosting
				-- the band, and a channel the one that does cannot use is
				-- dropped by ACS itself, while a channel missing from the
				-- candidate list is one ACS can never pick.
				if prev.channels or caps[key].channels then
					local seen, merged = {}, {}
					for _, src in ipairs({prev.channels or {}, caps[key].channels or {}}) do
						for _, ch in ipairs(src) do
							if not seen[ch] then
								seen[ch] = true
								merged[#merged + 1] = ch
							end
						end
					end
					table.sort(merged)
					caps[key].channels = merged
				end
				-- Ciphers fold the other way from every capability above:
				-- the INTERSECTION, because a WLAN on this band may land on
				-- either radio and a cipher one of them cannot program is a
				-- hostapd that refuses to start. Unknown on either side
				-- (nil) means unknown for the band.
				if prev.ciphers and caps[key].ciphers then
					local both = {}
					for token in pairs(prev.ciphers) do
						if caps[key].ciphers[token] then both[token] = true end
					end
					caps[key].ciphers = next(both) and both or nil
				else
					caps[key].ciphers = nil
				end
			end
		end
	end
	return caps
end

-- Per-band hardware capabilities: {ng = {max_kind, max_width, max_txpower}, ...}
-- An empty table (no `iw`, unparseable output) means "unknown", which every
-- caller must treat as "leave the controller's request alone".
function M.phy_caps()
	local now = M._time()
	local stale = false
	if M._phy_caps_cache and M._phy_caps_unstable_until then
		if now < M._phy_caps_unstable_until then
			stale = (now - (M._phy_caps_read_at or 0)) >= PHY_CAPS_REREAD
		else
			M._phy_caps_unstable_until = nil   -- settled: back to cache-forever
		end
	end
	if not M._phy_caps_cache or stale then
		M._phy_caps_cache = parse_phy_caps(M._popen("iw phy") or "",
			parse_cipher_suites(M._popen(CIPHER_PROBE) or ""))
		M._phy_caps_read_at = now
	end
	return M._phy_caps_cache
end

-- Whether the given band's hardware can program the pairwise cipher the
-- controller asked for (a token from _wire_pairwise / CIPHER_SELECTOR).
--
-- Unknown capabilities return true, like every other clamp here: openUF must
-- not refuse a controller's request because a probe failed. But a KNOWN set
-- that lacks the cipher returns false, and the caller keeps the default --
-- hostapd treats a pairwise cipher the driver cannot program as fatal
-- ("Failed to set beacon parameters"), so the BSS never comes up at all, which
-- is strictly worse than running the default CCMP. This is not theoretical on
-- the documented targets: the Archer C5's 5GHz ath10k phy reports neither GCMP
-- nor CCMP-256 while its 2.4GHz ath9k phy reports both, and the AX3000T's
-- mt76 phys report both on both bands (verified on hardware 2026-10-26).
function M.cipher_ok(band, token)
	if not token then return true end
	local caps = M.phy_caps()[band]
	if not caps or not caps.ciphers then return true end
	return caps.ciphers[token] == true
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
-- The four enterprise values were added 2026-10-26, when UAP firmware 6.8.2's
-- hostapd generator and the controller's own AP config builder showed that the
-- wire DOES carry the RADIUS servers (see inform.lua's _wire_radius). Until
-- then there was deliberately no entry, on the belief that it could not work.
--
-- The encryption strings are verified against the LIVE generator on 25.12
-- (/usr/share/ucode/wifi/, which is what runs -- /lib/netifd/wireless/mac80211.sh
-- is itself a ucode script and /lib/netifd/hostapd.sh is dead weight).
-- iface.uc takes auth_type from the first `+` token of `encryption`:
--   wpa2+ccmp -> eap      (wpa=2, CCMP)        -> WPA-EAP
--   wpa3      -> eap2                          -> WPA-EAP-SHA256
--   wpa3-mixed-> eap-eap2                      -> WPA-EAP + WPA-EAP-SHA256
--   wpa3-192  -> eap192   (GCMP-256)           -> WPA-EAP-SUITE-B-192
-- `encryption=eap` would be wrong: auth_type would come out right, but no
-- config.wpa wildcard matches it, so the BSS would get wpa=0.
--
-- ap.uc's EAP branch sets vlan_possible and calls its own
-- iface_authentication_server()/iface_accounting_server(), so the server
-- blocks need nothing beyond the options apply_config writes. It also leaves
-- ft_psk_generate_local off for a non-psk auth_type, which is what FT-EAP
-- needs, and hostapd adds FT-EAP/FT-EAP-SHA384 itself when ieee80211r=1 --
-- so Enterprise fast roaming comes free from the existing 802.11r block.
local SECURITY_MAP = {
	["open"]                 = "none",
	["wpa2"]                 = "psk2",
	["wpa3"]                 = "sae",
	["wpa2/wpa3"]            = "sae-mixed",
	["owe"]                  = "owe",
	["wpa2-enterprise"]      = "wpa2+ccmp",
	["wpa3-enterprise"]      = "wpa3",
	["wpa2/wpa3-enterprise"] = "wpa3-mixed",
	["wpa3-enterprise-192"]  = "wpa3-192",
}

-- Append one raw per-BSS hostapd line to an `extra` table, creating the list
-- on first use. Appending rather than assigning on purpose: hostapd_bss_options
-- has more than one producer, and a bare `extra.hostapd_bss_options = {...}`
-- from a second one would silently drop the first one's lines.
local function add_bss_option(extra, line)
	local t = extra.hostapd_bss_options
	if type(t) ~= "table" then
		t = {}
		extra.hostapd_bss_options = t
	end
	t[#t + 1] = line
end

-- The encryption values whose auth_type lands in ap.uc's EAP branch, which is
-- the only place (besides ppsk) that calls iface_authentication_server(). On
-- any other BSS the auth_server_* wifi-iface options are stored and never
-- reach hostapd, so a RADIUS MAC ACL there has to go in as raw lines. An
-- allow-set, so a future encryption value fails to the route that always works.
local EAP_ENC = {
	["wpa2+ccmp"]  = true,
	["wpa3"]       = true,
	["wpa3-mixed"] = true,
	["wpa3-192"]   = true,
}

-- The encryption values that take a `key` (a passphrase or a 64-hex PMK). An
-- allow-set rather than a "not none, not owe" test: an EAP BSS must never
-- carry a passphrase, and a future encryption value must fail closed.
local PASSPHRASE_ENC = {
	["psk2"]       = true,
	["sae"]        = true,
	["sae-mixed"]  = true,
}

-- Deterministic 16-bit id from a string, formatted as 4 hex chars (802.11r
-- mobility domain is a 2-octet field). The controller never sends a mobility
-- domain: UniFi firmware derives one from the SSID on the AP itself
-- (SHA1("salt" .. ssid)), so openUF does the same with its own hash. Same
-- seed always yields the same domain, so every openUF-emulated AP on the
-- same network computes it identically without needing to coordinate.
-- Deliberately NOT UniFi's formula: real UAPs only exchange FT keys with
-- peers running their patched hostapd, so a matching domain would make
-- clients attempt a fast transition to them that can only fail.
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
	-- The private pre-shared keys and their VLANs (M.ppsk_add) go with their
	-- VAP. netifd applies a wifi-station or wifi-vlan section without an iface
	-- to EVERY VAP, so one left behind would not stay harmless.
	local cleared = {}
	for _, name in ipairs(to_delete) do cleared[name] = true end
	for _, stype in ipairs({"wifi-station", "wifi-vlan"}) do
		cursor:foreach("wireless", stype, function(s)
			local name = s[".name"]
			if name and name:sub(1, #OPENUF_PREFIX) == OPENUF_PREFIX then
				local ifaces = s.iface
				if type(ifaces) ~= "table" then ifaces = {ifaces} end
				local ours = radio == nil
				for _, i in ipairs(ifaces) do
					if cleared[i] then ours = true end
				end
				if ours then to_delete[#to_delete + 1] = name end
			end
		end)
	end
	for _, name in ipairs(to_delete) do
		cursor:delete("wireless", name)
	end
	cursor:commit("wireless")
end

-- Every VLAN id one vap_table entry needs an L2 for: the WLAN's own, plus the
-- VLAN of each private pre-shared key. Sorted, no duplicates.
function M.vap_vlan_ids(vap)
	local seen, out = {}, {}
	local function add(v)
		v = tonumber(v)
		if v and not seen[v] then seen[v] = true; out[#out + 1] = v end
	end
	if vap.vlan_enabled then add(vap.vlan) end
	for _, k in ipairs(vap.ppsk or {}) do add(k.vid) end
	-- MAC-based VLANs: each overridden client needs its VLAN's L2 here too,
	-- or hostapd refuses the station rather than falling back to the VAP's
	-- own network (ieee802_11_set_radius_info -> hostapd_vlan_valid).
	for _, e in ipairs(vap.mac_vlans or {}) do add(e.vid) end
	table.sort(out)
	return out
end

-- One wifi-vlan section for `vid` on the VAP in wifi-iface section `iface`,
-- bound to UCI network `net`. Shared by the private-pre-shared-key and
-- MAC-based-VLAN paths, which can both want the same VLAN on one VAP: the
-- section name is derived from the VID alone, so the second writer reuses the
-- first one's section instead of adding a duplicate vlan_file line.
--
-- ap.uc's iface_vlan() turns each one into a `<vid> <ifname>-<name>` line of
-- hostapd's vlan_file and has netifd put that netdev in the named network's
-- bridge.
local function vlan_section(cursor, iface, vid, net)
	local vs = iface .. "_vlan" .. vid
	cursor:set("wireless", vs, "wifi-vlan")
	cursor:set("wireless", vs, "iface", {iface})
	-- The netdev is <vap ifname>-<name>: "phy0-ap0-20" stays
	-- inside the 15-character limit, where "v20" might not.
	cursor:set("wireless", vs, "name", tostring(vid))
	cursor:set("wireless", vs, "vid", tostring(vid))
	cursor:set("wireless", vs, "network", {net})
	return vs
end

-- Private Pre-Shared Keys for the VAP in wifi-iface section `iface`.
--
-- OpenWrt has the whole feature already: each wifi-station section becomes
-- one line of hostapd's wpa_psk_file (and sae_password_file for SAE),
--   vlanid=20 00:00:00:00:00:00 <passphrase>
-- and each wifi-vlan section one line of its vlan_file, for which netifd
-- creates a netdev named <vap ifname>-<name> and puts it in the bridge of the
-- network it names. A key without a VLAN puts its client on the VAP's own
-- network.
--
-- keys:     vap.ppsk, {key=, vid=, mac=} each (mac nil = any station)
-- networks: vid -> UCI network section for that VLAN (ensure_vlan_network)
-- A key whose VLAN has no network is left out rather than provisioned
-- without one: that client would land on the VAP's own network, past the
-- segmentation the key exists for.
-- cursor:   optional caller's cursor to write into (see borrow_cursor); the
--           caller then commits. Without one this opens and commits its own.
function M.ppsk_add(iface, keys, networks, cursor)
	local owned
	cursor, owned = borrow_cursor(cursor)
	for i, k in ipairs(keys or {}) do
		local net = k.vid and networks[k.vid]
		if k.vid and not net then
			io.stderr:write(("ucihelper: %s: private pre-shared key %d left out, "
				.. "no network for VLAN %d\n"):format(iface, i, k.vid))
		else
			-- Two keys on one VLAN share its section.
			if k.vid then
				vlan_section(cursor, iface, k.vid, net)
			end
			local ss = iface .. "_psk" .. i
			cursor:set("wireless", ss, "wifi-station")
			cursor:set("wireless", ss, "iface", {iface})
			cursor:set("wireless", ss, "mac", {k.mac or "00:00:00:00:00:00"})
			cursor:set("wireless", ss, "key", k.key)
			if k.vid then
				cursor:set("wireless", ss, "vid", tostring(k.vid))
			end
		end
	end
	release_cursor(cursor, owned, "wireless")
end

-- MAC-based VLANs ("Virtual Network Override"): put a named client on a named
-- VLAN whatever SSID it joins. The controller sends one list per WLAN
-- (aaa.<n>.accept_mac.*, see inform.lua's _wire_mac_vlans).
--
-- THE CONSUMER is hostapd's accept-MAC list, whose lines take an optional VLAN
-- id after the address ("<mac> <vid>"). hostapd_check_acl() is consulted on
-- every authentication BEFORE macaddr_acl is even looked at, and a match
-- returns ACCEPT carrying that VLAN; a station that is NOT listed falls
-- through to the macaddr_acl default. So an accept file on its own assigns
-- VLANs without restricting access -- which is the whole feature. Read out of
-- hostapd v2.12-devel (src/ap/ieee802_11_auth.c, hostapd/config_file.c), the
-- build both APs run.
--
-- The VLAN must also be in hostapd's vlan_file or the station is REFUSED, not
-- put on the VAP's own network ("Invalid VLAN %d received from RADIUS server",
-- ieee802_11_set_radius_info -> hostapd_vlan_valid). Hence a wifi-vlan section
-- per VLAN, exactly as the private-pre-shared-key path builds them.
--
-- THREE WAYS IN, because OpenWrt owns the same file for "MAC Address Filter":
--  * No filter: openUF's own file via a raw accept_mac_file= line. ap.uc emits
--    no macaddr_acl, and hostapd's default (0, accept-unless-denied) is what
--    lets unlisted clients keep joining.
--  * macfilter=allow: ap.uc writes accept_mac_file ITSELF from `maclist`, plus
--    macaddr_acl=1. openUF hands its entries to the schema's `macfile` option,
--    which ap.uc appends to that same file -- and drops those MACs from the
--    maclist it writes, so each address appears exactly once (two lines for one
--    station, one with a VLAN and one without, would leave hostapd's bsearch to
--    pick either). An address NOT already allowed is skipped: adding it would
--    silently widen the admin's whitelist.
--  * macfilter=deny: the deny list is a separate file, but the accept list is
--    checked first -- so a mapped MAC that is also denied would be let in.
--    Those entries are dropped and the rest go in via the raw line.
--
-- REFUSED outright when the WLAN has RADIUS MAC authentication: there
-- macaddr_acl=2 asks the RADIUS server about every client, and an accept-list
-- entry returns ACCEPT before the question is asked. A VLAN override is not
-- worth bypassing an access control.
local MACVLAN_DIR = "/etc/openuf"

-- Injectable for tests: write `contents` to `path`, true on success.
M._write_file = function(path, contents)
	local f = io.open(path, "w")
	if not f then return false end
	f:write(contents)
	f:close()
	return true
end

-- Injectable for tests: remove `path`, ignoring an absent file.
M._remove_file = function(path) os.remove(path) end

-- Where this VAP's accept file lives. Named after the wifi-iface section, which
-- is derived from radio + SSID and so is stable across pushes.
function M.mac_vlan_path(section)
	return MACVLAN_DIR .. "/macvlan-" .. section
end

-- Decide what (if anything) this VAP's accept file will hold, before the
-- wifi-iface section exists. Returns nil when there is nothing to write, or
--   {path =, entries = {{mac=, vid=}, ...}, mode = "raw" | "macfile"}
-- `maclist` is the MAC Address Filter list openUF is about to write, and is
-- MUTATED in the macfilter=allow case (see above).
function M.mac_vlan_plan(vap, networks, section, maclist)
	local entries = vap.mac_vlans
	if not entries or #entries == 0 then return nil end
	local policy = vap.mac_filter_policy
	if vap.mac_auth then
		io.stderr:write(("ucihelper: %s: %d MAC-based VLAN entries ignored -- the "
			.. "WLAN uses RADIUS MAC authentication, and an accept-list entry "
			.. "would skip it\n"):format(tostring(vap.ssid), #entries))
		return nil
	end
	-- M.DELETE when the WLAN has no MAC Address Filter, so not a list to read.
	if type(maclist) ~= "table" then maclist = {} end
	local filter = {}
	for _, m in ipairs(maclist) do filter[tostring(m):lower()] = true end
	local keep = {}
	for _, e in ipairs(entries) do
		local why
		if not networks[e.vid] then
			-- Same rule as a private pre-shared key with no network: better no
			-- override than a client silently left on the VAP's own VLAN, which
			-- is the segmentation the override exists to cross.
			why = ("no network for VLAN %d"):format(e.vid)
		elseif policy == "allow" and not filter[e.mac] then
			why = "the MAC Address Filter does not allow it"
		elseif policy == "deny" and filter[e.mac] then
			why = "the MAC Address Filter denies it"
		end
		if why then
			io.stderr:write(("ucihelper: %s: MAC-based VLAN for %s left out -- %s\n")
				:format(tostring(vap.ssid), e.mac, why))
		else
			keep[#keep + 1] = e
		end
	end
	if #keep == 0 then return nil end
	-- The FILE IS WRITTEN HERE, before anything points hostapd at it. An
	-- accept_mac_file= line naming a file that does not exist is not a degraded
	-- feature: hostapd_config_read_maclist() returns -1 and hostapd refuses the
	-- whole BSS, so the WLAN would vanish. On a write failure the plan is
	-- abandoned instead, and the WLAN goes up without the overrides.
	--
	-- A LEADING newline, not a trailing one: ap.uc writes the maclist with
	-- `join('\n', ...)` and no terminator, so in macfile mode openUF's first
	-- byte lands on the end of the last allow-list address. That does NOT fail
	-- -- which is why the newline matters. hwaddr_aton() reads exactly six
	-- octets and ignores whatever follows (src/utils/common.c), so the joined
	-- line is read as that LAST address, and the VLAN id is then taken from
	-- after its first space -- the mapped client's. The allow-listed station
	-- would silently get the override, and the intended one no entry at all.
	-- Verified against hostapd v2.12-devel: the joined line draws no complaint.
	-- Harmless in raw mode, where openUF owns the file outright.
	local lines = {"", "# openUF: MAC-based VLANs. Rebuilt on every config push."}
	for _, e in ipairs(keep) do lines[#lines + 1] = e.mac .. " " .. e.vid end
	local path = M.mac_vlan_path(section)
	local body = table.concat(lines, "\n") .. "\n"
	-- The entries change only when the admin edits the client list, while this
	-- runs on every push. Read the file back first and skip a write whose bytes
	-- are already on the flash. Only the WRITE is skipped: the maclist edit
	-- below is part of what this push hands ap.uc, not part of the file.
	if M._read_file(path) ~= body and not M._write_file(path, body) then
		io.stderr:write(("ucihelper: %s: cannot write %s -- MAC-based VLANs left "
			.. "unapplied\n"):format(tostring(vap.ssid), path))
		return nil
	end
	if policy == "allow" then
		-- One line per address in the file ap.uc builds: ours carry the VLAN.
		local mapped = {}
		for _, e in ipairs(keep) do mapped[e.mac] = true end
		local i = 1
		while maclist[i] do
			if mapped[tostring(maclist[i]):lower()] then
				table.remove(maclist, i)
			else
				i = i + 1
			end
		end
	end
	return {
		path    = path,
		entries = keep,
		mode    = (policy == "allow") and "macfile" or "raw",
	}
end

-- One wifi-vlan section per VLAN the plan names. Called after wlan_add, like
-- ppsk_add, since the sections hang off the VAP's.
-- One section per DISTINCT VLAN, not per entry: vlan_section derives the
-- section name from the VID alone, so N clients on one VLAN wrote the same five
-- options N times over. The controller's lists are per client, and a site that
-- overrides 50 of them across 3 VLANs did 250 cursor:set calls for 15 options'
-- worth of config.
--
-- cursor: optional caller's cursor (see borrow_cursor).
function M.mac_vlans_add(iface, plan, networks, cursor)
	if not plan then return end
	local owned
	cursor, owned = borrow_cursor(cursor)
	local done = {}
	for _, e in ipairs(plan.entries) do
		if not done[e.vid] then
			done[e.vid] = true
			vlan_section(cursor, iface, e.vid, networks[e.vid])
		end
	end
	release_cursor(cursor, owned, "wireless")
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
--
-- A wifi-iface whose mode is not "ap" is EXEMPT, in both directions. This
-- option is about SSIDs competing with the controller's on the air; a mesh
-- point or a station interface is a LINK, not a competing SSID -- and it may
-- well be this AP's own uplink, in which case disabling it takes the device
-- off the network with no way back short of a serial console. An absent mode
-- is OpenWrt's own default of "ap". An exempt section openUF had already
-- switched off on an earlier pass (it carries the stamp) is switched back on
-- once, so the exemption repairs the damage rather than freezing it.
function M.set_wlan_exclusive(enabled)
	local uci = get_uci()
	local cursor = uci.cursor()
	local targets = {}
	cursor:foreach("wireless", "wifi-iface", function(s)
		local name = s[".name"]
		if name and name:sub(1, #OPENUF_PREFIX) ~= OPENUF_PREFIX then
			local stamped = (s[AUTODISABLED] == "1")
			if s.mode ~= nil and s.mode ~= "ap" then
				if stamped then
					targets[#targets + 1] = {name = name, release = true}
				end
			else
				targets[#targets + 1] = {name = name, disabled = s.disabled,
					stamped = stamped}
			end
		end
	end)
	local changed = false
	for _, t in ipairs(targets) do
		if t.release then
			cursor:set("wireless", t.name, "disabled", "0")
			cursor:set("wireless", t.name, AUTODISABLED, "0")
			changed = true
		elseif enabled then
			if t.disabled ~= "1" then
				cursor:set("wireless", t.name, "disabled", "1")
				cursor:set("wireless", t.name, AUTODISABLED, "1")
				changed = true
			end
		elseif t.stamped then
			cursor:set("wireless", t.name, "disabled", "0")
			cursor:set("wireless", t.name, AUTODISABLED, "0")
			changed = true
		end
	end
	-- Each branch above is already a no-op once it has run, so in the steady
	-- state -- which is every push after the first -- there is nothing to
	-- commit, and committing anyway rewrote /etc/config/wireless for it.
	if changed then cursor:commit("wireless") end
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

-- The UCI wifi-iface section name for one WLAN on one radio. Deterministic,
-- and exposed so a caller that needs the name BEFORE the section exists (the
-- MAC-based-VLAN accept file is named after it) derives the same one.
--
-- The name includes the radio, not just the SSID: broadcasting the
-- same SSID on both radios simultaneously is the default, common case
-- (the controller UI's "Radio Band: 2.4 GHz + 5 GHz" checkboxes) and
-- produces one wlan_add() call per radio with an identical ssid. Keying
-- purely by SSID collapsed both calls into the same UCI section, so the
-- second call's "device" silently overwrote the first -- confirmed live
-- against a real controller: only the last-processed radio's VAP
-- survived. The radio is sanitized the same way the ssid is, though UCI
-- radio names ("radio0"/"radio1") never need it.
--
-- The character class must NOT keep "-". A UCI section name may contain
-- only [A-Za-z0-9_], and libuci enforces that in the most unhelpful way
-- available: cursor:set() returns true, cursor:commit() returns true, and
-- the section is silently discarded -- it never reaches /etc/config and
-- never appears in `uci show`. So an SSID with a hyphen produced a
-- wlan_add that reported success at every step and left no WLAN behind,
-- with nothing in any log to say so. Confirmed live: creating
-- "openuf-verify" in the controller pushed correctly, parsed correctly
-- into vap_table, and simply never provisioned. Hyphens are common in
-- SSIDs, so this was a wide hole.
--
-- Sanitizing is lossy, and that loss used to collapse WLANs: "Guest WiFi",
-- "Guest-WiFi" and "Guest_WiFi" all became openuf_radio0_Guest_WiFi, so
-- two of them on one radio shared a section and the second silently
-- overwrote the first -- the same failure the per-radio keying above
-- exists to prevent, one level down. When the name had to be ALTERED at
-- all, a short hash of the original keeps them apart; a name that needed
-- no alteration keeps the section name it has always had, so nothing
-- already deployed is renamed. (apply_config wlan_clear()s every openuf_
-- section before rebuilding them, so a name that does change leaves
-- nothing stale behind either.)
function M.vap_section_name(radio, ssid)
	local safe_ssid = ssid:gsub("[^%w_]", "_")
	if safe_ssid ~= ssid then
		safe_ssid = safe_ssid .. "_" .. M.derive_mobility_domain(ssid)
	end
	return OPENUF_PREFIX .. tostring(radio):gsub("[^%w_]", "_") .. "_" .. safe_ssid
end

-- Create a new wifi-iface section named openuf_<ssid> on the given radio.
-- radio:    UCI radio name, e.g. "radio0" or "radio1"
-- ssid:     SSID string
-- security: "open" | "owe" | "wpa2" | "wpa3" | "wpa2/wpa3"
-- password: WPA pre-shared key (ignored when security is "open" or "owe")
-- extra:    optional table of additional UCI key/value pairs (802.11r/k/v etc.)
-- network:  UCI network/interface name to bridge this SSID onto (defaults to
--           "lan"); pass a VLAN-tagged interface from ensure_vlan_network() to
--           put the SSID on that VLAN.
-- wlanconf_id: optional controller-side wlanconf object id (system_cfg's
--           aaa.<n>.id), stashed the same way so get_vap_table() can echo it
--           back as the vap's "id" -- required for the controller to accept
--           the vap (and its sta_table) at all.
-- pairwise: optional pairwise-cipher token ("gcmp", "ccmp256", ...) from
--           inform.lua's _wire_pairwise, appended to the encryption string
--           when this radio's hardware can program it. nil keeps the default.
-- cursor:   optional caller's cursor to write into (see borrow_cursor), so a
--           push with several WLANs rewrites /etc/config/wireless once rather
--           than once per WLAN. The caller commits.
function M.wlan_add(radio, ssid, security, password, extra, network, wlanconf_id,
		pairwise, cursor)
	local owned
	cursor, owned = borrow_cursor(cursor)
	local section_name = M.vap_section_name(radio, ssid)
	local enc = SECURITY_MAP[security] or "psk2"
	-- The controller's own pairwise cipher (aaa.<n>.wpa.1.pairwise), as the
	-- second `+` token of `encryption` -- which is where iface.uc reads a
	-- cipher from. The base is taken first because SECURITY_MAP already
	-- carries a suffix for the EAP values ("wpa2+ccmp"), and a second one
	-- appended after it would be ignored outright.
	--
	-- "wpa3-192" is left alone on purpose: iface.uc pins that auth_type to
	-- GCMP-256 itself, which is what the 192-bit suite requires, so a cipher
	-- from the wire can only contradict it.
	local enc_base = enc:match("^([^+]+)") or enc
	if pairwise and enc_base ~= "none" and enc_base ~= "owe"
			and enc_base ~= "wpa3-192" then
		-- The radio's band comes from its own UCI declaration, as in
		-- apply_config's htmode clamp: the band is fixed by hardware.
		local band = band_for_device({
			band    = cursor:get("wireless", radio, "band"),
			hwmode  = cursor:get("wireless", radio, "hwmode"),
			channel = cursor:get("wireless", radio, "channel"),
		})
		if M.cipher_ok(band, pairwise) then
			enc = enc_base .. "+" .. pairwise
		else
			io.stderr:write(string.format(
				"openuf: %s: controller asked for pairwise cipher %s, %s hardware "
				.. "does not support it -- keeping %s\n",
				tostring(ssid), pairwise, tostring(band), enc))
		end
	end
	cursor:set("wireless", section_name, "wifi-iface")
	cursor:set("wireless", section_name, "device", radio)
	cursor:set("wireless", section_name, "mode", "ap")
	cursor:set("wireless", section_name, "ssid", ssid)
	cursor:set("wireless", section_name, "encryption", enc)
	cursor:set("wireless", section_name, "network", network or "lan")
	if wlanconf_id then
		cursor:set("wireless", section_name, "openuf_wlanconf_id", wlanconf_id)
	end
	-- Keyed on the BASE value: PASSPHRASE_ENC is an allow-set of security
	-- values, and a cipher suffix must not turn a WLAN that takes a
	-- passphrase into one that silently drops it.
	if password and PASSPHRASE_ENC[enc_base] then
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
	release_cursor(cursor, owned, "wireless")
	return section_name
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
	local port_section = OPENUF_PREFIX .. "brport" .. tostring(vlan_id)

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
		-- Turn MAC learning OFF on the tagged uplink port. On a DSA board
		-- `wan` (untagged, in br-lan) and `wan.10` are the SAME physical
		-- port on the SAME hardware switch, and that switch has ONE FDB.
		-- With learning on, it learns the upstream router's MAC against
		-- wan.10 and files it in the VLAN bridge's domain:
		--     5a:d6:..:f6 dev wan.10 offload master br-openuf10
		-- Wired clients sit in that hardware FDB too (`dev lan4 self`), so
		-- their frames to the router get hardware-forwarded into the VLAN
		-- domain and blackholed -- LAN peers reachable, gateway and internet
		-- dead. WiFi clients ride the CPU/software path, hit the correct
		-- `dev wan master br-lan` entry, and work: the giveaway signature is
		-- WiFi fine, wired broken, on the same AP. Confirmed live on an
		-- AX3000T (2026-09-03) and fixed by exactly this, after which the
		-- hardware entry binds correctly as `dev wan self`.
		--
		-- Cost is nil in practice: the VLAN bridge is the uplink plus the
		-- VAP(s), so unlearned unicast floods to the one other port it would
		-- have been forwarded to anyway. Only the uplink port is set -- every
		-- other member still learns normally.
		if cursor:get("network", port_section, "name") ~= ifname
			or tostring(cursor:get("network", port_section, "learning") or "") ~= "0" then
			cursor:set("network", port_section, "device")
			cursor:set("network", port_section, "name", ifname)
			cursor:set("network", port_section, "learning", "0")
			changed = true
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

-- ─── Bridge identity ─────────────────────────────────────────────────────────

-- One netdev's MAC from sysfs, lowercased, or nil.
local function mac_of(ifname)
	local raw = ifname and M._read_file("/sys/class/net/" .. ifname .. "/address")
	local mac = type(raw) == "string" and raw:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
	return mac and mac:lower() or nil
end

-- The BSSID a VAP has right now: its live netdev's address, resolved the same
-- way the per-VAP features resolve it (find_vap_iface). Asked during
-- apply_config, before the reload, so a VAP being rebuilt still answers with
-- the netdev it is about to get back. nil when the radio has no live
-- interface for it. Handed to plugins as ctx.bssid.
function M.vap_bssid(radio, ssid)
	return mac_of(M.get_ifname_for_vap(radio, ssid))
end

-- The bridge a netdev is enslaved to, or nil when it carries its own address.
local function master_of(ifname)
	return util.master_of(ifname, M._read_file)
end

-- Give the management bridge the MAC openUF identifies as.
--
-- openUF takes its IDENTITY from `dev.conf.net.lan_cpueth` -- that netdev's MAC
-- is what the controller keys the adopted device on, what lldpd advertises as
-- the chassis id, and what every inform arrives under. It takes its reported
-- IP from the same name, but `announce.get_ip` deliberately hops to the BRIDGE
-- that port is enslaved to, because a bridge member carries no address.
--
-- MAC from the port, address from the bridge: fine as long as the two share a
-- MAC, which on every swconfig board here they do (`eth1` and `br-lan` both
-- read the same address, so the divergence never existed to be noticed). It is
-- NOT true on DSA. There `lan_cpueth` names a socket -- `wan` on the AX3000T,
-- whose MAC is board.json's `label_macaddr` -- while `br-lan` inherits the DSA
-- conduit's (`eth0`). openUF then announces itself as 00:00:5e:00:53:01 while
-- every frame it sources, and the ARP entry for the address it reports, is
-- 00:00:5e:00:53:02. The gateway sees one device claiming the IP and a
-- different one using it, and raises an IP conflict against a network that is
-- in fact correctly configured. Confirmed on the wire 2026-09-12: a capture on
-- `wan` shows 192.0.2.4 sending exclusively from the eth0 MAC, while
-- `lldpd.config.cid_interface='wan'` advertises the other one.
--
-- Pinning the bridge's `macaddr` closes it, and is what a real UniFi AP looks
-- like: one MAC for identity, LLDP and management traffic. Adoption is keyed
-- on `lan_cpueth`'s MAC, which this does not touch, so the device record
-- survives -- see _warn_identity_change for what changing THAT would cost.
--
-- Only ever acts when the two genuinely differ, so a board where they already
-- agree (every swconfig one) is untouched and no reload is issued. Note that
-- on a DHCP-addressed board the new L2 identity means a new lease and possibly
-- a new address; openUF reports the change on the next inform and the adoption
-- is unaffected, but that is why this is loud rather than silent.
function M.ensure_bridge_identity(cfg)
	local cpueth = cfg and cfg.net and cfg.net.lan_cpueth
	local want = mac_of(cpueth)
	if not want then return false end

	local br = master_of(cpueth)
	-- No bridge means the port holds the address itself: nothing diverges.
	if not br then return false end
	local have = mac_of(br)
	if not have or have == want then return false end

	local cursor = get_uci().cursor()
	-- Found by the bridge's NAME, not a section name: it is the board's own
	-- anonymous `network.@device[0]`, and openUF must not assume where it sits.
	local sec
	cursor:foreach("network", "device", function(s)
		if s.name == br and s.type == "bridge" then sec = s[".name"] end
	end)
	if not sec then
		io.stderr:write(("ucihelper: %s has MAC %s but openUF identifies as %s, and "
			.. "there is no `config device` section for %s to pin it on -- the "
			.. "controller will see an IP conflict against itself\n")
			:format(br, have, want, br))
		return false
	end

	if tostring(cursor:get("network", sec, "macaddr") or ""):lower() == want then
		return false
	end
	cursor:set("network", sec, "macaddr", want)
	cursor:commit("network")
	io.stderr:write(("ucihelper: pinning %s to the identity MAC %s (was %s, from %s) "
		.. "-- MAC and reported IP must belong to the same netdev or the gateway "
		.. "reports an IP conflict\n"):format(br, want, have, cpueth))
	M._network_dirty = true
	return true
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
	-- The uplink port's learning override goes with the bridge it qualified;
	-- left behind it would keep learning off on a port no openUF bridge owns.
	sweep("device",    "^" .. OPENUF_PREFIX .. "brport(%d+)$")
	-- ...and switchvlan's per-SOCKET overrides on the same bridge
	-- (`openuf_brport<vid>_<socket>`), which the anchored pattern above
	-- deliberately does not match. A VLAN going away takes its moved sockets
	-- back to br-lan, and an override left behind would keep learning off on a
	-- port no openUF bridge owns -- silently costing that port its host list.
	sweep("device",    "^" .. OPENUF_PREFIX .. "brport(%d+)_")

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
-- units, dBm + 95; openuf/minrssi.lua). On disable only the flag is written
-- to 0; minrssi_rssi stays parked in UCI (harmless -- every consumer gates on
-- the flag first) so a later re-enable without a threshold change reuses it.
-- The refusal half is hostapd's: rssi_reject_assoc_rssi and
-- rssi_ignore_probe_request, stamped openuf_minrssi and torn down on disable.
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
-- maxsta: Load balance's per-radio client cap (openuf/loadbalance.lua), kept
-- in the openUF-only option loadbalance_maxsta; false deletes it (off), nil
-- leaves UCI alone.
-- country_beacon: advertise the 802.11d Country IE in this radio's beacons,
-- collapsed from the per-WLAN aaa.<n>.country_beacon by apply_config. nil
-- leaves UCI alone (no WLAN on this radio carried the key).
function M.rf_config(radio, htmode, chan, txpwr, minrssi_enabled, minrssi_raw, rates,
		disabled, country, maxsta, country_beacon, acs_exclude_dfs, acs_blacklist)
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
		regdomain_changed()
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
	-- Minimum RSSI's refusal (openuf/minrssi.lua): the firmware's driver
	-- answers no probe and no authentication below the threshold + 3 dB;
	-- hostapd's equivalents are wifi-device options. Computed from the same
	-- stored threshold the kick reads back, so the two halves never disagree.
	local mr = get_minrssi()
	local raw = tonumber(minrssi_raw or cursor:get("wireless", radio, "minrssi_rssi"))
	if minrssi_enabled and raw and mr then
		local refuse = tostring(mr.dbm(raw) + mr.REFUSE_MARGIN)
		cursor:set("wireless", radio, "rssi_reject_assoc_rssi", refuse)
		cursor:set("wireless", radio, "rssi_ignore_probe_request", refuse)
		cursor:set("wireless", radio, "openuf_minrssi", "1")
	elseif minrssi_enabled ~= nil and cursor:get("wireless", radio, "openuf_minrssi") == "1" then
		-- Off: remove exactly what the stamp says openUF wrote. Hand-set
		-- values on an unstamped radio are never touched.
		for _, opt in ipairs({"rssi_reject_assoc_rssi", "rssi_ignore_probe_request",
				"openuf_minrssi"}) do
			cursor:delete("wireless", radio, opt)
		end
	end
	if maxsta then
		cursor:set("wireless", radio, "loadbalance_maxsta", tostring(maxsta))
	elseif maxsta == false then
		cursor:delete("wireless", radio, "loadbalance_maxsta")
	end
	-- 802.11d Country IE. Written as an explicit 0 rather than deleted when
	-- off: hostapd.uc gates `ieee80211d` on its own truthiness, so 0 and
	-- absent behave identically to hostapd, and writing it keeps the applied
	-- state visible in UCI -- the same reason the iot flag is recorded.
	--
	-- No guard on a country being configured is needed: hostapd itself treats
	-- ieee80211d=1 without country_code as fatal, but hostapd.uc's
	-- device_country_append() returns before emitting ieee80211d at all when
	-- no radio declares a country (read from 25.12's live generator), so the
	-- option cannot reach hostapd unaccompanied.
	--
	-- **Never 0 on a 5 GHz radio.** hostapd refuses the whole interface with
	-- "Cannot enable IEEE 802.11h without IEEE 802.11d enabled", and
	-- `ieee80211h` is exactly what hostapd.uc emits for every radio with
	-- hw_mode 'a' and a country (it defaults to 1 in the schema, and is
	-- deleted only for hw_mode != 'a'). The result is not a dropped option but
	-- `hostapd.add_iface failed`: the 5 GHz phy stays down with no SSID on the
	-- air and nothing in UCI to explain it. Seen in production on both boards
	-- (ath79/ath10k and filogic/mt76) at the first `wifi reload` after this
	-- option was first written -- not at the push that wrote it, which is why
	-- reading UCI and hostapd.conf straight after the provision looked clean.
	-- 802.11h carries DFS and TPC, so suppressing the country IE there is not
	-- something to trade for it; the radio keeps 802.11d and the controller's
	-- setting is honoured on 2.4 GHz only.
	if country_beacon ~= nil then
		local five = band_for_device({
			band    = cursor:get("wireless", radio, "band"),
			hwmode  = cursor:get("wireless", radio, "hwmode"),
			channel = cursor:get("wireless", radio, "channel"),
		}) == "na"
		-- An explicit 1, not a delete: this also repairs a radio an earlier
		-- openUF left at 0.
		cursor:set("wireless", radio, "ieee80211d",
			(country_beacon or five) and "1" or "0")
		if five and not country_beacon and not M._warned_11d then
			M._warned_11d = true
			io.stderr:write("openuf: " .. tostring(radio) .. ": Country IE off is"
				.. " not applicable on 5 GHz -- 802.11h (DFS) requires 802.11d,"
				.. " and hostapd refuses the interface without it\n")
		end
	end
	-- Auto-channel narrowing (the site's Radio settings, see
	-- _parse_wifi_system_cfg). Both land on wifi-device options that only
	-- hostapd's ACS reads, so writing them on a radio pinned to a fixed
	-- channel is inert -- and keeps UCI showing what the controller asked for
	-- the day the user switches that radio back to Auto.
	if acs_exclude_dfs ~= nil then
		cursor:set("wireless", radio, "acs_exclude_dfs", acs_exclude_dfs and "1" or "0")
	end
	-- The controller sends a BLACKLIST (radio.<n>.blklst, what ACS may not
	-- pick); hostapd has no blacklist, only `chanlist`, the candidate list. So
	-- the blacklist is inverted against the channels this band may legally
	-- use, which is exactly what phy_caps reads out of `iw phy` -- the
	-- regdomain has already removed everything else, and disabled channels are
	-- skipped there.
	local chanlist = nil
	if acs_blacklist then
		local section = {
			band    = cursor:get("wireless", radio, "band"),
			hwmode  = cursor:get("wireless", radio, "hwmode"),
			channel = cursor:get("wireless", radio, "channel") or chan,
		}
		-- band_for_device falls back to the channel number, and its documented
		-- trap is that "auto" is not one: it answers "na" for a 2.4 GHz radio
		-- on ACS. Everywhere else that costs a mis-clamped width; here it
		-- would hand a 2.4 GHz radio a candidate list of 5 GHz channels --
		-- i.e. an ACS with nothing it can tune. So a guess is not good enough:
		-- the band has to come from the section's own band/hwmode, or from a
		-- channel that is actually a number.
		local band = (section.band or section.hwmode or tonumber(section.channel))
			and band_for_device(section) or nil
		local caps = band and M.phy_caps()[band]
		local legal = caps and caps.channels
		if not legal then
			-- Unknown channel set (no `iw`, unparseable output): leave ACS
			-- alone. A guessed candidate list can contain nothing the radio
			-- can actually use, and an ACS with no usable candidate is a radio
			-- that does not come up -- strictly worse than ignoring the
			-- blacklist.
			io.stderr:write(string.format(
				"openuf: %s: cannot read the %s channel list -- ignoring the"
				.. " controller's channel blacklist\n", tostring(radio),
				band or "radio's own"))
		else
			local blocked = {}
			for _, ch in ipairs(acs_blacklist) do blocked[ch] = true end
			local keep, dropped = {}, 0
			for _, ch in ipairs(legal) do
				if blocked[ch] then
					dropped = dropped + 1
				else
					keep[#keep + 1] = tostring(ch)
				end
			end
			if dropped == 0 then
				-- The blacklist names nothing this radio could have used anyway,
				-- because the regdomain already excludes it. Writing the band's
				-- entire channel list as a "candidate list" is a no-op that would be
				-- churned into UCI on every push, so this counts as no narrowing at
				-- all -- and tears down a narrowing openUF wrote earlier.
			elseif #keep == 0 then
				io.stderr:write(string.format(
					"openuf: %s: the controller blacklists every %s channel this"
					.. " radio has -- leaving auto-channel unrestricted\n",
					tostring(radio), tostring(band)))
			else
				chanlist = keep
			end
		end
	end
	if chanlist then
		cursor:set("wireless", radio, "chanlist", chanlist)
		-- Same ledger shape as openuf_rates below: the blacklist going empty
		-- is the key simply vanishing from the wire, which is otherwise
		-- indistinguishable from a chanlist the user set by hand.
		cursor:set("wireless", radio, "openuf_chanlist", "1")
	elseif cursor:get("wireless", radio, "openuf_chanlist") == "1" then
		cursor:delete("wireless", radio, "chanlist")
		cursor:delete("wireless", radio, "openuf_chanlist")
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
--       leaves each vap's own setting in effect. opts.roam_assist_active
--       (boolean) forces the same, for Roaming Assistant. opts.device_name is the
--       controller-assigned device name, used as the WPS Device Name value
--       when a vap has advertise_ap_name enabled ("Show Access Point Name in
--       Beacon"); defaults to "openUF" if nil. opts.peer_ie is the
--       vendor_elements hex every VAP beacons so sibling openUF APs can tell
--       it is not a rogue (sysinfo.peer_ie_hex); nil removes it.
-- Drive the Multicast and Broadcast Blocker from one normalized list of
-- {ifname, bcfilt_enabled, bcfilt_macs} entries, so the setparam path and the
-- startup reapply below cannot drift apart.
--
-- Reconciled unconditionally, even with an empty list: it rebuilds from
-- scratch rather than diffing, so turning the control off in the controller
-- tears the previous ruleset down instead of leaving it in place -- the same
-- contract firewall.lua keeps. (WiFi Speed Limit is per client, so it needs
-- the stations: inform's _shaper_resync applies it every heartbeat from the
-- openuf_ratelimit_* stamps, see shaper.lua.)
local function reconcile_runtime(entries)
	local bcfilter = get_bcfilter()
	if bcfilter then
		local rules = {}
		for _, e in ipairs(entries) do
			-- "Multicast Suppression" has three positions and the wire names
			-- none of them, so the mode is the pair of keys (see inform's vap
			-- build): the blocker's own key means Aggressive -- block, with the
			-- bypass types and the allow-list -- and the suppressor key on its
			-- own means Conservative, which only limits the rate. Aggressive
			-- wins when both arrive, since a rate limit under a block is dead
			-- weight.
			if e.bcfilt_enabled then
				rules[#rules + 1] = {
					ifname = e.ifname,
					macs   = e.bcfilt_macs or {},
					bypass = e.bcfilt_bypass,
				}
			elseif e.mcast_suppressor then
				rules[#rules + 1] = {ifname = e.ifname, limit = true}
			end
		end
		bcfilter.reconcile(rules)
	end
end

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
	-- aaa.<n>.country_beacon arrives per WLAN, but OpenWrt's ieee80211d is a
	-- wifi-device option and hostapd's Country IE is a per-radio property
	-- (it rides the radio's beacons, which every BSS on it shares), so the
	-- per-BSS wire key has to collapse to one setting per radio.
	--
	-- The aggregate is "any WLAN on this radio asked for it", i.e. the most
	-- PERMISSIVE reading, matching rates_by_radio below: the element is an
	-- advertisement, not a restriction -- clients that ignore it are
	-- unaffected -- so honouring the one WLAN that wants it costs the others
	-- nothing, while the opposite fold would silently drop a setting the
	-- controller was explicitly asked for. nil for a radio no WLAN mentions,
	-- which leaves UCI alone.
	local country_beacon_by_radio = {}
	for _, vap in ipairs(vap_table) do
		if vap.radio and vap.country_beacon ~= nil then
			country_beacon_by_radio[vap.radio] =
				country_beacon_by_radio[vap.radio] or vap.country_beacon
		end
	end

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
				radio.country, radio.loadbalance_maxsta,
				country_beacon_by_radio[radio.name],
				radio.acs_exclude_dfs, radio.acs_blacklist)
		end
	end

	-- Clear existing openuf_ VAPs and re-add from vap_table
	M.wlan_clear()
	-- Every VLAN this push still wants an L2 for; anything else gets pruned
	-- after the loop.
	local wanted_vlans = {}
	-- ONE cursor for the whole loop, committed once below: the three writers
	-- (wlan_add, ppsk_add, mac_vlans_add) each used to open and commit their
	-- own, so a four-WLAN push rewrote /etc/config/wireless four to twelve
	-- times. Nothing between here and the commit reads the wireless config
	-- through a second cursor, so there is no half-written state to observe.
	local wcursor = get_uci().cursor()
	-- One read of the plugin list for the whole loop instead of one per VAP
	-- (plugins.lua's begin_pass note). Closed after the commit below.
	do
		local plugins = get_plugins()
		if plugins and plugins.begin_pass then plugins.begin_pass() end
	end
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
				-- UniFi firmware's hostapd template also sets these two
				-- (firmware-confirmed for 4.0.15). The push hands a
				-- client's PMK-R1 to each peer key holder right after it
				-- connects, so its first roam there needs no pull.
				-- hostapd skips the wildcard r1kh entry when pushing, so
				-- the push reaches a peer only once it has been learned
				-- from a pull (kept for rkh_pos_timeout, a day). It is
				-- written on the key-holder path only (SAE, EAP). The
				-- deadline is in TU: 3000 instead of OpenWrt's 20000.
				extra.pmk_r1_push            = "1"
				extra.reassociation_deadline = "3000"
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
				-- OpenWrt's own default is already right: hostapd.sh / ap.uc
				-- key it on auth_type (psk -> 1, anything else -> 0), and
				-- only when it is 0 do they write r0kh/r1kh at all. FT-PSK
				-- keeps local derivation and needs no inter-AP traffic, while
				-- FT-SAE and FT-EAP get the key holders they cannot work
				-- without.
				--
				-- The key-holder secret is the controller's: aaa.<n>.iapp_key,
				-- 128 random bits per WLAN, the same key UniFi firmware wraps
				-- its own inter-AP FT frames with. The wildcard forms are the
				-- ones OpenWrt itself generates, so any openUF AP on the WLAN
				-- is accepted as a peer. Without the key (an older controller,
				-- or iapp_enabled off) OpenWrt derives one from
				-- md5(mobility_domain .. "/" .. psk), which also works, but
				-- anyone who knows the passphrase can compute that one.
				if vap.iapp_key then
					extra.r0kh = { "ff:ff:ff:ff:ff:ff,*," .. vap.iapp_key }
					extra.r1kh = { "00:00:00:00:00:00,00:00:00:00:00:00,"
						.. vap.iapp_key }
				end
			end
			if opts and (opts.band_steering_active or opts.roam_assist_active) then
				-- usteer requires 802.11k (neighbor reports) + BSS
				-- Transition on every managed iface network-wide to
				-- function at all -- confirmed via the OpenWrt wiki's
				-- usteer setup guide. This overrides each WLAN's own
				-- bss_transition/ieee80211k value while device-wide Band
				-- Steering is on, since usteer can't be scoped to a
				-- single SSID. Roaming Assistant needs the same: usteer
				-- running on every iface for its cross-AP view, and
				-- bss_transition for hostapd's bss_transition_request.
				extra.ieee80211k          = "1"
				extra.bss_transition      = "1"
				extra.rrm_neighbor_report = "1"
				extra.rrm_beacon_report   = "1"
				extra.wnm_sleep_mode      = "1"
			else
				if vap.bss_transition ~= nil then
					extra.bss_transition = vap.bss_transition and "1" or "0"
				end
				-- The WLAN's own 802.11k toggle (aaa.<n>.11k.status). Off
				-- needs nothing: the section is rebuilt, and OpenWrt's
				-- ieee80211k defaults to 0. Without usteer nothing fills
				-- hostapd's neighbor list, so a neighbor report names no
				-- other AP; beacon reports (rrmscan) work regardless.
				if vap.rrm then
					extra.ieee80211k          = "1"
					extra.rrm_neighbor_report = "1"
					extra.rrm_beacon_report   = "1"
				end
			end
			if vap.dtim_period then extra.dtim_period = vap.dtim_period end
			-- U-APSD. `uapsd` is hostapd.sh's option and, on 25.12, a schema
			-- alias of uapsd_advertisement_enabled, so one name covers both.
			if vap.uapsd ~= nil then extra.uapsd = vap.uapsd and "1" or "0" end
			-- Opportunistic key caching (aaa.<n>.auth_cache). Sent only on a
			-- WPA-Enterprise WLAN, so nil everywhere else and OpenWrt's own
			-- default stands. ap.uc also writes disable_pmksa_caching from
			-- the inverse, but only `okc` is in the 25.12 schema, so an
			-- explicit 0 is the whole of "off" that is available.
			if vap.okc ~= nil then extra.okc = vap.okc and "1" or "0" end
			-- Forbid direct station-to-station links (aaa.<n>.tdls_prohibit).
			-- On the wire for every WLAN, so this always writes.
			if vap.tdls_prohibit ~= nil then
				extra.tdls_prohibit = vap.tdls_prohibit and "1" or "0"
			end
			-- GTK rekey interval (s, 0 = off); hostapd's own default is 86400.
			if vap.group_rekey then extra.wpa_group_rekey = vap.group_rekey end
			-- SAE tuning, as the firmware writes it (6.8.2 ubntbox). Only on a WLAN
			-- that really offers SAE. sae_groups is a wifi-iface option;
			-- hostapd's anti-clogging threshold and sync time are not, so they
			-- go in as raw lines (hostapd_bss_options: per-BSS raw lines, ucode generator).
			if vap.security == "wpa3" or vap.security == "wpa2/wpa3" then
				if vap.sae_groups then extra.sae_groups = vap.sae_groups end
				if vap.sae_anti_clogging then
					add_bss_option(extra,
						"sae_anti_clogging_threshold=" .. vap.sae_anti_clogging)
				end
				if vap.sae_sync then
					add_bss_option(extra, "sae_sync=" .. vap.sae_sync)
				end
			end
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
			-- 802.1X / WPA-Enterprise. The CANONICAL option names, not the
			-- aliases: /usr/share/schema/wireless.wifi-iface.json declares
			-- auth_server/auth_port/auth_secret/acct_server/acct_port/
			-- acct_secret/acct_interval/nasid as "type": "alias" for these, and
			-- the ucode generator (ap.uc) names the canonical ones literally.
			--
			-- One port and one secret cover the WHOLE server list: ap.uc's
			-- iface_authentication_server() re-appends the same
			-- auth_server_port/auth_server_shared_secret after every
			-- auth_server_addr, so a server with its own port or secret cannot
			-- be expressed and is dropped with a named log line rather than
			-- silently authenticated against the wrong secret.
			--
			-- Nothing here is invented: no ownip/dynamic_own_ip_addr,
			-- eap_reauth_period, radius_request_cui, eap_server, ieee8021x or
			-- wpa_key_mgmt. The wire carries none of them, and a consumer keyed
			-- on a producer that does not exist is this codebase's recurring
			-- defect. (radius_das_* IS on the wire -- see below.)
			--
			-- The AUTHENTICATION servers reach hostapd one of two ways. ap.uc
			-- calls iface_authentication_server() only from its EAP branch (and
			-- from iface_ppsk), so on a PSK, SAE or open BSS the wifi-iface
			-- options are stored and silently dropped -- exactly the trap
			-- CLAUDE.md names -- and raw per-BSS lines are the only route.
			-- iface_accounting_server() IS called unconditionally, so the
			-- accounting servers always go through UCI.
			local eap_bss = EAP_ENC[SECURITY_MAP[vap.security] or ""] or false
			if vap.radius then
				local function servers(list, kind, addr_opt, port_opt, secret_opt, raw)
					local first = list and list[1]
					if not first then return end
					local addrs = {first.ip}
					for i = 2, #list do
						local s = list[i]
						if s.port == first.port and s.secret == first.secret then
							addrs[#addrs + 1] = s.ip
						else
							io.stderr:write(("openuf: %s: RADIUS %s server %s has its "
								.. "own port/secret, which OpenWrt's %s list cannot "
								.. "express -- dropped\n")
								:format(tostring(vap.ssid), kind, s.ip, addr_opt))
						end
					end
					if not raw then
						extra[addr_opt]   = addrs
						extra[port_opt]   = first.port
						extra[secret_opt] = first.secret
						return
					end
					-- hostapd reads the port and the secret that FOLLOW each
					-- server address, so the triplet repeats per address -- the
					-- same shape iface_authentication_server() emits.
					for _, ip in ipairs(addrs) do
						add_bss_option(extra, addr_opt .. "=" .. ip)
						add_bss_option(extra, port_opt .. "=" .. first.port)
						add_bss_option(extra, secret_opt .. "=" .. first.secret)
					end
				end
				servers(vap.radius.auth, "authentication", "auth_server_addr",
					"auth_server_port", "auth_server_shared_secret", not eap_bss)
				servers(vap.radius.acct, "accounting", "acct_server_addr",
					"acct_server_port", "acct_server_shared_secret")
				if vap.radius.interim_interval then
					extra.radius_acct_interim_interval = vap.radius.interim_interval
				end
				if vap.radius.nas_id then extra.nas_identifier = vap.radius.nas_id end
				-- RADIUS Dynamic Authorization (CoA / Disconnect-Request). Both
				-- options are real wifi-iface options, appended by ap.uc for
				-- EVERY auth type -- but the one place it joins the secret onto
				-- the client address sits inside the EAP branch, so
				-- radius_das_secret (and its dae_secret alias) is stored and
				-- dropped on a PSK or open BSS. openUF therefore joins the two
				-- itself, which is also exactly what hostapd parses (first token
				-- the address, the REST of the line the shared secret) and what
				-- UAP firmware 6.8.2 writes. radius_das_port is defaulted only
				-- inside that same branch and hostapd's own default is 0 (= no
				-- listener), so it is always written explicitly.
				if vap.radius.das then
					extra.radius_das_client =
						vap.radius.das.client .. " " .. vap.radius.das.secret
					extra.radius_das_port = vap.radius.das.port
				end
			end
			-- RADIUS MAC authentication. macaddr_acl=2 is hostapd's "ask the
			-- RADIUS server whether this MAC may associate"; it has no UCI
			-- option of its own on 25.12 (the schema declares none, and the only
			-- producers are macfilter -> 1/0 and ppsk -> 2), so it goes in raw.
			-- ppsk would set it too, but on a PSK BSS it ALSO sets
			-- wpa_psk_radius=2 and leaves the passphrase out (ap.uc's
			-- `case psk`), turning the WLAN into a per-user-PSK one nobody
			-- could join with the configured key -- a different UniFi feature.
			if vap.mac_auth then add_bss_option(extra, "macaddr_acl=2") end
			-- Hotspot 2.0 / Passpoint. Two gates in the ucode generator:
			-- iw_enabled turns on iface_interworking (the Interworking element
			-- and the ANQP answers), hs20 turns on iface_hs20 (the HS 2.0
			-- indication element and the hs20_* options). Both are needed, and
			-- both are real schema options rather than aliases.
			--
			-- The SCALARS go in as wifi-iface options, the LISTS as raw
			-- hostapd lines, for a specific reason: wifi.common's append()
			-- joins an array value with SPACES into a single key=a b c line,
			-- which is not a format hostapd accepts for any of the cumulative
			-- interworking options (venue_name, nai_realm, roaming_consortium,
			-- hs20_conn_capab each need one line per entry). On top of that,
			-- ap.uc's iface_interworking() overwrites config.domain_name with
			-- the joined anqp_3gpp_cell_net whenever the latter is set, so
			-- routing the domain list through UCI would lose it on any WLAN
			-- that also advertises a cellular network. Raw lines are appended
			-- after every append_vars (ap.uc, "/* raw options */"), so they are
			-- also what hostapd reads last.
			--
			-- Every line below was validated by feeding the generated config to
			-- a real hostapd v2.12-devel (the APs' own build, from
			-- openwrt/rootfs:x86-64-25.12.0 + wpad-mbedtls): zero parse errors.
			if vap.hs20 then
				local hs = vap.hs20
				extra.iw_enabled = "1"
				extra.hs20       = "1"
				local function bit(v) return v and "1" or "0" end
				if hs.access_network_type then
					extra.access_network_type = hs.access_network_type
				end
				if hs.internet ~= nil then extra.internet = bit(hs.internet) end
				if hs.asra ~= nil then extra.asra = bit(hs.asra) end
				if hs.uesa ~= nil then extra.uesa = bit(hs.uesa) end
				if hs.venue_group then extra.venue_group = hs.venue_group end
				if hs.venue_type then extra.venue_type = hs.venue_type end
				if hs.disable_dgaf ~= nil then
					extra.disable_dgaf = bit(hs.disable_dgaf)
				end
				if hs.deauth_req_timeout then
					extra.hs20_deauth_req_timeout = hs.deauth_req_timeout
				end
				if hs.ipaddr_type_avail then
					-- hostapd's own option name. The schema's
					-- iw_ipaddr_type_availability is NOT an alias and ap.uc
					-- never appends it, so through UCI it would be stored and
					-- dropped.
					add_bss_option(extra,
						"ipaddr_type_availability=" .. hs.ipaddr_type_avail)
				end
				if hs.domain_name then
					add_bss_option(extra, "domain_name=" .. hs.domain_name)
				end
				for i, v in ipairs(hs.venue_name or {}) do
					add_bss_option(extra, "venue_name=" .. v.lang .. ":" .. v.name)
					-- venue_url's index refers to the venue_name entry it
					-- belongs to, 1-based in the order written above.
					if v.url then
						add_bss_option(extra, "venue_url=" .. i .. ":" .. v.url)
					end
				end
				for _, r in ipairs(hs.nai_realm or {}) do
					-- <encoding>,<realm>,<eap method>[<auth id>:<auth value>]...
					local line = r.encoding .. "," .. r.name .. "," .. r.eap_method
					for _, au in ipairs(r.auth or {}) do
						line = line .. "[" .. au.id .. ":" .. au.val .. "]"
					end
					add_bss_option(extra, "nai_realm=" .. line)
				end
				for _, oi in ipairs(hs.roaming_consortium or {}) do
					add_bss_option(extra, "roaming_consortium=" .. oi)
				end
				if hs.cell_net then
					-- One option, all pairs: hostapd's anqp_3gpp_cell_net is a
					-- single semicolon-separated list, and a second line would
					-- replace the first rather than add to it.
					local pairs_out = {}
					for _, c in ipairs(hs.cell_net) do
						pairs_out[#pairs_out + 1] = c.mcc .. "," .. c.mnc
					end
					add_bss_option(extra,
						"anqp_3gpp_cell_net=" .. table.concat(pairs_out, ";"))
				end
				for _, f in ipairs(hs.friendly_name or {}) do
					add_bss_option(extra,
						"hs20_oper_friendly_name=" .. f.lang .. ":" .. f.text)
				end
				for _, c in ipairs(hs.conn_capab or {}) do
					add_bss_option(extra, "hs20_conn_capab="
						.. c.protocol .. ":" .. c.port .. ":" .. c.status)
				end
				if hs.wan_metrics then
					local m = hs.wan_metrics
					-- <WAN info>:<downlink speed>:<uplink speed>:<downlink
					-- load>:<uplink load>:<load measurement duration>
					-- WAN info is one OCTET IN HEX, not a decimal: hostapd
					-- parses it with hexstr2bin() over exactly two chars, so
					-- the controller's decimal "1" is rejected with "Invalid
					-- hs20_wan_metrics" -- and a rejected line is a config
					-- parse error, which makes hostapd refuse the whole BSS.
					-- Caught by feeding openUF's own generated config to a
					-- real hostapd v2.12-devel. Every other field is decimal.
					extra.hs20_wan_metrics = table.concat({
						string.format("%02x", tonumber(m.info)),
						m.downlink_speed, m.uplink_speed, m.downlink_load,
						m.uplink_load, m.measurement}, ":")
				end
			end
			if vap.owe_transition then
				-- Enhanced Open transition mode: the ucode generator (24.10+,
				-- hostapd.uc/mac80211.sh) turns this one section into the
				-- hidden OWE BSS plus an open BSS under the section's SSID,
				-- each pointing at the other. The controller sends the same
				-- pair as two VAPs; inform.lua keeps the open one only.
				-- Absent otherwise: wlan_clear drops the section on every
				-- rebuild.
				extra.owe_transition = "1"
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
			if vap.roam_assist_enabled then
				-- "Roaming Assistant" threshold in dBm, read back by
				-- get_vap_table for openuf/roamassist.lua. Absent means off:
				-- wlan_clear drops the whole section before every rebuild,
				-- so switching it off in the controller leaves nothing behind.
				extra.openuf_roam_assist = tostring(vap.roam_assist_rssi or -75)
			end
			if vap.schedule_lines then
				-- "WiFi Blackout Schedule": the firmware's schedule lines,
				-- read back by schedule_vaps for inform's heartbeat check
				-- (wlansched.lua). Absent means no schedule, as above.
				extra.openuf_schedule = table.concat(vap.schedule_lines, " ")
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
				-- The frame types the blocker must pass (bcfilt.bypass_types), in
				-- the wire's own spelling so the stamp stays readable and the
				-- startup reapply rebuilds an identical ruleset. Sorted, since the
				-- parser hands over a set.
				--
				-- Neither stamp needs an M.DELETE for the shrinking case: every
				-- openuf_ wifi-iface section is wlan_clear()ed and rebuilt on each
				-- push, so an emptied allow-list or a withdrawn bypass list cannot
				-- survive into the next one.
				if vap.bcfilt_bypass then
					local toks = {}
					for tok in pairs(vap.bcfilt_bypass) do toks[#toks + 1] = tok end
					table.sort(toks)
					extra.openuf_bcfilt_bypass = table.concat(toks, " ")
				end
			end
			if vap.mcast_suppressor ~= nil then
				-- "Multicast Suppression". Recorded for the same reason as the
				-- blocker above: the enforcement is nftables, applied after the wifi
				-- reload, and this stamp is what the startup reapply re-derives from.
				extra.openuf_mcast_suppress = vap.mcast_suppressor and "1" or "0"
			end
			if vap.l2_isolation ~= nil then
				-- "Client Isolation": drop station-to-station frames inside the
				-- BSS. OpenWrt's wifi-iface option is spelled "isolate" (it maps
				-- to hostapd's ap_isolate) -- confirmed in hostapd.sh's
				-- hostapd_common_add_bss_config declaration list.
				extra.isolate = vap.l2_isolation and "1" or "0"
			end
			-- Sibling-AP recognition: the vendor element that tells the other
			-- openUF APs' scans this BSS is ours (see sysinfo.peer_ie_hex --
			-- without it the controller lists it as a rogue impersonating the
			-- network). Removed when the identity MAC is unknown rather than
			-- left announcing a stale one.
			extra.vendor_elements = (opts and opts.peer_ie) or M.DELETE
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
				-- A COPY: the MAC-based-VLAN plan below takes addresses out of
				-- the allow list it writes (they go in carrying a VLAN instead),
				-- and the vap's own list is read again by get_vap_table.
				local list = {}
				for i, m in ipairs(vap.mac_filter_list or {}) do list[i] = m end
				extra.maclist = list
			else
				extra.macfilter = M.DELETE
				extra.maclist   = M.DELETE
			end
			-- "WiFi Speed Limit", kbps as pushed. Read back by get_vap_table
			-- for inform's _shaper_resync, which enforces it per client with
			-- tc (shaper.lua: no hostapd or OpenWrt option expresses it).
			-- Absent means no limit: wlan_clear drops the section first.
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
			-- NOT written: SAE anti-clogging / sync time. Both are real
			-- hostapd config keys, but OpenWrt exposes neither as a
			-- wifi-iface UCI option -- verified 2026-09-10 on an Archer C5
			-- (ath79) and an AX3000T (filogic), both OpenWrt 25.12.5, against
			-- all three places an option can be declared: the wifi-iface
			-- schema, /usr/share/ucode/wifi/ and hostapd.sh's config_add_*
			-- lists. Neither name appears in any of them, on either board, so
			-- a write here was stored in UCI and dropped in silence.
			-- The wire keys are still parsed and reported; see inform.lua.
			-- VLAN comes off the vap itself: the controller derives it from
			-- aaa.<n>.br.devname ("br0.20"), not from a linked network object.
			local vlan_enabled = vap.vlan_enabled
			local vlan_id      = vap.vlan

			-- One L2 per VLAN the VAP needs: its own and each private
			-- pre-shared key's.
			local vlan_networks = {}
			if cpueth then
				for _, vid in ipairs(M.vap_vlan_ids(vap)) do
					vlan_networks[vid] = M.ensure_vlan_network(cpueth, vid)
					wanted_vlans[vid] = true
				end
			end

			local network = "lan"
			if vlan_enabled and vlan_id and cpueth then
				network = vlan_networks[tonumber(vlan_id)]
			end

			-- The wire sends dynamic_vlan=1 with every key list, and
			-- OpenWrt's ap.uc writes hostapd's VLAN options (vlan_no_bridge
			-- above all: netifd, not hostapd, bridges the VLAN netdev) only
			-- when it is set.
			--
			-- An 802.1X WLAN carries its own value (0/1/2, from the RADIUS
			-- profile's "RADIUS assigned VLAN" mode). PPSK wins if the two ever
			-- met -- they cannot, since EAP and PSK live on disjoint encryption
			-- values, but "2" (required) alongside PPSK would reject every local
			-- key that has no VLAN, so the harmless branch is the safe one.
			--
			-- The same RADIUS profile reaches a MAC-authenticated PSK or open
			-- WLAN since 2026-10-27, and there the value is deliberately NOT
			-- written: hostapd needs a vlan_file (ap.uc builds one from wifi-vlan
			-- sections, which openUF creates none of) before it can put a station
			-- on a RADIUS-assigned VLAN, so "2" (required) would reject every
			-- client on a WLAN that worked a moment earlier. Honouring it needs
			-- the dynamic-VLAN plumbing, which is its own piece of work.
			if vap.ppsk then
				extra.dynamic_vlan = "1"
			elseif eap_bss and vap.radius and vap.radius.dynamic_vlan then
				extra.dynamic_vlan = vap.radius.dynamic_vlan
			end

			-- MAC-based VLANs ("Virtual Network Override"). The plan writes the
			-- accept file; see M.mac_vlan_plan for the three ways it reaches
			-- hostapd and the cases it refuses.
			local mac_vlan = M.mac_vlan_plan(vap, vlan_networks,
				M.vap_section_name(vap.radio, vap.ssid), extra.maclist)
			if mac_vlan then
				if mac_vlan.mode == "macfile" then
					extra.macfile = mac_vlan.path
				else
					add_bss_option(extra, "accept_mac_file=" .. mac_vlan.path)
				end
				-- The wifi-vlan sections below become hostapd's vlan_file either
				-- way (ap.uc's iface_vlan writes it before any gate), but
				-- vlan_no_bridge -- which keeps hostapd's hands off the bridge
				-- netifd already built -- sits behind `vlan_possible &&
				-- dynamic_vlan`. ap.uc sets vlan_possible itself for every
				-- psk/sae/eap auth type, so dynamic_vlan=1 is enough there and
				-- is also what the PPSK path has always written. On an OPEN or
				-- OWE WLAN neither flag is ever set, so the option goes in raw:
				-- without it hostapd creates its own brvlan<id> and moves the
				-- VLAN netdev out of br-openuf<id>.
				if not extra.dynamic_vlan then
					if vap.security == "open" or vap.security == "owe" then
						add_bss_option(extra, "vlan_no_bridge=1")
					else
						extra.dynamic_vlan = "1"
					end
				end
			else
				-- No overrides on this WLAN any more: take the client addresses
				-- off the flash rather than leaving a list nothing reads.
				M._remove_file(M.mac_vlan_path(M.vap_section_name(vap.radio, vap.ssid)))
			end

			-- conf.lua config.plugins: third-party edits to this VAP's
			-- options, after everything built in (plugins.lua). Never
			-- raises, and does nothing unless a plugin is listed.
			do
				local plugins = get_plugins()
				if plugins then
					plugins.vap_options(extra, vap, cfg, {
						DELETE = M.DELETE,
						bssid  = M.vap_bssid,
						cursor = function() return get_uci().cursor() end,
					})
				end
			end

			local section = M.wlan_add(vap.radio, vap.ssid, vap.security,
				vap.x_passphrase, extra, network, vap.wlanconf_id, vap.pairwise,
				wcursor)
			if vap.ppsk and section then
				M.ppsk_add(section, vap.ppsk, vlan_networks, wcursor)
			end
			if mac_vlan and section then
				M.mac_vlans_add(section, mac_vlan, vlan_networks, wcursor)
			end
		end
	end
	-- Everything the loop staged, in one rewrite of /etc/config/wireless.
	wcursor:commit("wireless")
	do
		local plugins = get_plugins()
		if plugins and plugins.end_pass then plugins.end_pass() end
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
	-- netifd may hand the interfaces new netdev names on the way back up, and
	-- the wireless config this reload just wrote is the very thing the radio
	-- rows were read from, so the lookups below must not reuse anything read
	-- before it.
	M._ws_cache   = nil
	M._pass_cache = nil

	-- "Multicast and Broadcast Blocker" (nftables) enforcement. Deliberately
	-- after the reload: the rules key off each VAP's live netdev name, which
	-- only exists (and can change) once netifd has brought the interfaces
	-- back up.
	local entries = {}
	for _, vap in ipairs(vap_table) do
		if vap.ssid and vap.radio then
			-- An OWE transition VAP has two netdevs, and both get the rules.
			for _, ifname in ipairs(M.get_ifnames_for_vap(vap.radio, vap.ssid)) do
				entries[#entries + 1] = {
					ifname           = ifname,
					bcfilt_enabled   = vap.bcfilt_enabled,
					bcfilt_macs      = vap.bcfilt_macs,
					bcfilt_bypass    = vap.bcfilt_bypass,
					mcast_suppressor = vap.mcast_suppressor,
				}
			end
		end
	end
	reconcile_runtime(entries)
end

-- Radio options only openUF writes, deleted outright on Forget, and the
-- stamped ones rf_config writes only under its openuf_minrssi/openuf_rates
-- markers, deleted only where the marker is.
local FORGET_RADIO_OPTS  = {"minrssi_enabled", "minrssi_rssi", "loadbalance_maxsta"}
local FORGET_RADIO_STAMP = {
	openuf_minrssi = {"rssi_reject_assoc_rssi", "rssi_ignore_probe_request"},
	openuf_rates   = {"basic_rate", "supported_rates", "legacy_rates", "beacon_rate"},
}

-- Undo what apply_config wrote, for a controller "Forget" (setdefault) or a
-- reset-inform. UniFi firmware answers setdefault with `syswrapper.sh
-- restore-default`, a factory reset and reboot that leaves no SSID on the air
-- (firmware-confirmed for 4.0.15); this is the same end state without the
-- reboot, limited to what openUF itself put there:
--   * every openuf_ wifi-iface, with its private-key sections (wlan_clear)
--   * every openuf_ VLAN network and bridge (prune_vlan_networks)
--   * the radio options above
--   * the user's own SSIDs that use_only_unifi_wlan switched off come back
--     on, since no controller SSID is left to stand in for them
--   * the Multicast and Broadcast Blocker's ruleset
-- A radio's channel, width, transmit power, country and enable stay as the
-- controller last set them: rf_config overwrites those without keeping the
-- original, and they are valid settings for the board either way.
function M.forget()
	local uci = get_uci()
	local cursor = uci.cursor()
	local radios = {}
	cursor:foreach("wireless", "wifi-device", function(s)
		radios[#radios + 1] = s
	end)
	for _, s in ipairs(radios) do
		local name = s[".name"]
		for _, opt in ipairs(FORGET_RADIO_OPTS) do
			if s[opt] ~= nil then cursor:delete("wireless", name, opt) end
		end
		for stamp, opts in pairs(FORGET_RADIO_STAMP) do
			if s[stamp] == "1" then
				for _, opt in ipairs(opts) do cursor:delete("wireless", name, opt) end
				cursor:delete("wireless", name, stamp)
			end
		end
	end
	cursor:commit("wireless")
	M.wlan_clear()
	M.prune_vlan_networks({})
	M.set_wlan_exclusive(false)
	if M._network_dirty then
		M._run_cmd("/etc/init.d/network reload 2>/dev/null")
		M._network_dirty = false
	end
	M._run_cmd("wifi reload")
	M._ws_cache   = nil
	M._pass_cache = nil
	reconcile_runtime({})
end

-- Reapply the Multicast and Broadcast Blocker from UCI.
--
-- It is an nftables ruleset: LIVE KERNEL STATE that a reboot discards, with no
-- UCI option OpenWrt itself understands. apply_config() only ever runs on a
-- setparam, and after a reboot there is no setparam to run it -- cfgversion is
-- persisted, so it matches on the first inform and the controller replies noop
-- with no system_cfg at all. The blocker therefore stayed switched off
-- indefinitely while the controller UI went on showing it as on.
--
-- The openuf_bcfilt* options wlan_add stamps onto each managed section are
-- the record this reads back.
--
-- Called at startup by inform.M.run, alongside the blocked-client and LED
-- reconciliation, and for the same reason. Returns the number of managed VAPs
-- it found, for the caller's log line.
function M.reapply_runtime_rules()
	local uci = get_uci()
	local cursor = uci.cursor()
	local entries = {}
	cursor:foreach("wireless", "wifi-iface", function(s)
		local name = s[".name"]
		if not name or name:sub(1, #OPENUF_PREFIX) ~= OPENUF_PREFIX then return end
		-- A disabled VAP has no netdev to attach a rule to. It also needs no
		-- teardown: the reload that disabled it took its interface, and with it
		-- every qdisc and every nft rule that named it.
		if s.disabled == "1" then return end
		local ok_if, ifnames = pcall(M.get_ifnames_for_vap, s.device, s.ssid)
		if not ok_if then return end
		local macs = {}
		for mac in (s.openuf_bcfilt_macs or ""):gmatch("%S+") do
			macs[#macs + 1] = mac
		end
		-- Rebuilt as a set, the shape the parser produces, so the reapply and
		-- the setparam path hand bcfilter.lua identical rules.
		local bypass
		for tok in (s.openuf_bcfilt_bypass or ""):gmatch("%S+") do
			bypass = bypass or {}
			bypass[tok] = true
		end
		for _, ifname in ipairs(ifnames) do
			entries[#entries + 1] = {
				ifname           = ifname,
				bcfilt_enabled   = (s.openuf_bcfilt == "1"),
				bcfilt_macs      = macs,
				bcfilt_bypass    = bypass,
				mcast_suppressor = (s.openuf_mcast_suppress == "1"),
			}
		end
	end)
	reconcile_runtime(entries)
	return #entries
end

-- ─── Read helpers (for inform payload builder) ───────────────────────────────

-- Every wifi-device in UCI, unfiltered, read once per pass.
--
-- get_radio_table was called TWICE per heartbeat -- once by build_json with
-- the modelmap's hwassign, and once by get_vap_table with none, to build its
-- band lookup -- so /etc/config/wireless was loaded through a fresh
-- uci.cursor() twice for one answer, on config that changes only when the
-- controller pushes one.
--
-- The rows are held UNFILTERED and hwassign is applied per call: the two
-- callers want different filtering of the same rows, and a memo that held the
-- filtered result would change which radios vap_table can resolve
-- radio/channel/tx_power against.
local function radio_rows()
	return pass_memo("radio_rows", function()
	local cursor = pass_cursor()
	local radios = {}
	cursor:foreach("wireless", "wifi-device", function(s)
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
			-- Load balance's cap, nil when off. Internal: build_json
			-- consumes it and strips it before serializing.
			loadbalance_maxsta = tonumber(s.loadbalance_maxsta),
		}
	end)
	return radios
	end)
end

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
	local allowed = nil
	if type(hwassign) == "table" and #hwassign > 0 then
		allowed = {}
		for _, name in ipairs(hwassign) do allowed[name] = true end
	end
	local radios = {}
	for _, row in ipairs(radio_rows()) do
		if not allowed or allowed[row.name] then
			-- A COPY per call. build_json writes the hardware caps, the
			-- re-derived band and the payload's own fields onto the rows it
			-- gets back and strips the internal ones; sharing the memoized
			-- tables would let that reach the copy get_vap_table is reading
			-- from -- and the next heartbeat's.
			local copy = {}
			for k, v in pairs(row) do copy[k] = v end
			radios[#radios + 1] = copy
		end
	end
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
-- The decoded `ubus call network.wireless status`, shared by the two lookups
-- below. Cached only INSIDE a pass opened by begin_pass() -- inform.lua's
-- _tick opens one per cycle and closes it after the payload -- and dropped by
-- end_pass() and after every `wifi reload`, so a netdev name read before
-- netifd rebuilt the interfaces is never reused after. Outside a pass every
-- call forks ubus exactly as before, which is also what keeps the test suite's
-- per-test _popen stubs independent of one another. Inside one, what used to
-- be ten identical forks per heartbeat on a two-radio, four-SSID box is one.
M._ws_cache = nil      -- {status = <decoded table> | false} while a pass is open
M._ws_pass  = false
-- Nest-safe: returns true only when it opened the pass, and only that caller
-- closes it. inform._tick opens one for the whole cycle, so the once-a-minute
-- resyncs and the payload share one ubus answer and one config read; a
-- build_json called on its own still opens (and closes) its own.
function M.begin_pass()
	if M._ws_pass then return false end
	M._ws_pass = true; M._ws_cache = nil; M._pass_cache = {}
	return true
end
function M.end_pass()   M._ws_pass = false; M._ws_cache = nil; M._pass_cache = nil end

local function wireless_status()
	if M._ws_pass and M._ws_cache then
		return M._ws_cache.status or nil
	end
	local status = nil
	local output = M._popen("ubus call network.wireless status")
	if output ~= "" then
		local cjson = get_cjson()
		if cjson then
			local ok_d, decoded = pcall(cjson.decode, output)
			if ok_d and type(decoded) == "table" then status = decoded end
		end
	end
	if M._ws_pass then M._ws_cache = {status = status or false} end
	return status
end

-- The second netdev of an Enhanced Open transition section, or nil.
--
-- owe_transition=1 makes the generator bring up TWO BSSes from one section:
-- the section's own netdev is the hidden OWE BSS, and the open BSS gets a
-- netdev netifd's status never lists (mac80211.sh assigns it as
-- owe_transition_ifname and hands it only to hostapd). hostapd reports it in
-- its bss_info, which is where OpenWrt's own iwinfo.uc reads it too. Asked
-- only for sections that have the option, so no other VAP pays for a ubus
-- call.
local function owe_transition_ifname(iface)
	local on = type(iface.config) == "table" and iface.config.owe_transition
	if not (on == true or on == 1 or on == "1") then return nil end
	-- Interpolated into a shell command line.
	if type(iface.ifname) ~= "string" or not iface.ifname:match("^[%w%-%._]+$") then
		return nil
	end
	local cjson = get_cjson()
	if not cjson then return nil end
	local out = M._popen("ubus call hostapd bss_info '{\"iface\":\"" .. iface.ifname .. "\"}'")
	local ok, info = pcall(cjson.decode, out or "")
	local peer = ok and type(info) == "table" and info.owe_transition_ifname
	if type(peer) == "string" and peer:match("^[%w%-%._]+$") and peer ~= iface.ifname then
		return peer
	end
	return nil
end

-- The VLAN netdevs of one VAP (private pre-shared keys: a client whose key
-- carries a VLAN is associated on <vap ifname>-<vid>, not on the VAP's own
-- netdev, and `iw dev <vap> station dump` does not list it). netifd reports
-- them under the interface's vlans[].
-- Each one is remembered against its VAP for M.bss_ifname.
M._vlan_parent = {}
local function vlan_ifnames(iface, out)
	for _, v in ipairs(type(iface.vlans) == "table" and iface.vlans or {}) do
		if type(v) == "table" and type(v.ifname) == "string" and v.ifname ~= "" then
			out[#out + 1] = v.ifname
			M._vlan_parent[v.ifname] = iface.ifname
		end
	end
	return out
end

-- The netdev whose hostapd serves a station seen on `ifname`: the VAP itself
-- for a VLAN netdev from get_ifnames_for_vap, else ifname unchanged. hostapd
-- has a control socket and a ubus object per BSS only, so a kick or a BSS
-- transition request aimed at the VLAN netdev would reach nothing.
function M.bss_ifname(ifname)
	return M._vlan_parent[ifname] or ifname
end

-- The live netdev of every AP-mode VAP on the device, from netifd's status
-- (radio order, then interface order). A station or mesh interface -- a
-- wireless backhaul -- is not a VAP and is left out: l2guard's tag drop on an
-- uplink would cut the AP off. Empty when wireless is not up or ubus cannot
-- be asked; callers treat that as "nothing to protect yet".
function M.ap_ifnames()
	local status = wireless_status()
	local out = {}
	if type(status) ~= "table" then return out end
	local radios = {}
	for r in pairs(status) do radios[#radios + 1] = r end
	table.sort(radios)
	for _, r in ipairs(radios) do
		local entry = status[r]
		local ifaces = type(entry) == "table" and entry.interfaces or nil
		for _, i in ipairs(type(ifaces) == "table" and ifaces or {}) do
			local mode = type(i) == "table" and type(i.config) == "table" and i.config.mode or nil
			if type(i) == "table" and type(i.ifname) == "string" and i.ifname ~= ""
					and (mode == nil or mode == "ap") then
				out[#out + 1] = i.ifname
				out[#out + 1] = owe_transition_ifname(i)
				vlan_ifnames(i, out)
			end
		end
	end
	return out
end

function M.get_ifname_for_radio(radio)
	if not radio then return nil end
	local status = wireless_status()
	if not status then return nil end
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
local function find_vap_iface(radio, ssid)
	if not radio or not ssid then return nil end
	local status = wireless_status()
	if not status then return nil end
	local dev = status[radio]
	if type(dev) ~= "table" or type(dev.interfaces) ~= "table" then return nil end
	for _, iface in ipairs(dev.interfaces) do
		if type(iface) == "table" and iface.ifname
			and type(iface.config) == "table" and iface.config.ssid == ssid then
			return iface
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
		return dev.interfaces[1]
	end
	return nil
end

function M.get_ifname_for_vap(radio, ssid)
	local iface = find_vap_iface(radio, ssid)
	return iface and iface.ifname
end

-- Every live netdev of one VAP: its own, the open BSS of an OWE transition
-- section, and the VLAN netdev of each private pre-shared key's VLAN.
-- Per-VAP features (station reporting, the blocker, the speed limit) have to
-- cover them all, or those clients would fall outside them. Empty when the
-- VAP cannot be resolved.
function M.get_ifnames_for_vap(radio, ssid)
	local iface = find_vap_iface(radio, ssid)
	if not iface then return {} end
	local out = {iface.ifname}
	local peer = owe_transition_ifname(iface)
	if peer then out[#out + 1] = peer end
	return vlan_ifnames(iface, out)
end

-- Every live netdev of the enabled openUF VAPs whose wlanconf id is in ids
-- (a set), as {ifname=, ssid=}: the guest portal's interfaces.
function M.wlanconf_ifnames(ids)
	local out = {}
	if type(ids) ~= "table" or next(ids) == nil then return out end
	each_iface(function(s)
		if s.disabled == "1" or not (s.openuf_wlanconf_id and ids[s.openuf_wlanconf_id]) then return end
		local ok_if, ifnames = pcall(M.get_ifnames_for_vap, s.device, s.ssid)
		if not ok_if then return end
		for _, ifname in ipairs(ifnames) do
			out[#out + 1] = {ifname = ifname, ssid = s.ssid}
		end
	end)
	return out
end

-- Every enabled openUF VAP with a WiFi Blackout Schedule, as {ifnames =,
-- lines =}: its BSS netdevs (its own and an OWE transition's open BSS; a
-- private pre-shared key's VLAN netdev goes with its BSS) and the schedule
-- lines apply_config stored.
function M.schedule_vaps()
	local out = {}
	each_iface(function(s)
		if s.disabled == "1" or not s.openuf_wlanconf_id or not s.openuf_schedule then return end
		local ok_if, ifnames = pcall(M.get_ifnames_for_vap, s.device, s.ssid)
		if not ok_if or #ifnames == 0 then return end
		local bss = {}
		for _, n in ipairs(ifnames) do
			if not M._vlan_parent[n] then bss[#bss + 1] = n end
		end
		local lines = {}
		for l in s.openuf_schedule:gmatch("%S+") do lines[#lines + 1] = l end
		out[#out + 1] = {ifnames = bss, lines = lines}
	end)
	return out
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
	local radio_by_name = {}
	for _, r in ipairs(M.get_radio_table()) do radio_by_name[r.name] = r end

	local vaps = {}
	each_iface(function(s)
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
		-- Only access points are VAPs. A mesh point or a station interface has
		-- no SSID to report and is not a BSS the controller can provision; it
		-- went out as a nameless phantom VAP with no clients. An absent mode
		-- is OpenWrt's default of "ap".
		if s.mode ~= nil and s.mode ~= "ap" then return end
		local radio = radio_by_name[s.device]
		-- THIS VAP's netdev, not the radio's first one. Two SSIDs on a radio
		-- have two BSSIDs -- netifd derives the second from the first with the
		-- locally-administered bit set -- so resolving the radio here reported
		-- both VAPs on one BSSID, and the controller saw two BSSes claiming the
		-- same address. The per-VAP lookup already existed for sta_table; this
		-- field was left on the per-radio one. Unresolvable stays "", never a
		-- neighbour's address.
		local bssid = ""
		local ok_if, ifname = pcall(M.get_ifname_for_vap, s.device, s.ssid)
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
			-- Internal, never serialized: build_json consumes it for
			-- Roaming Assistant and removes it.
			roam_assist_rssi = tonumber(s.openuf_roam_assist),
			-- Internal, never serialized: WiFi Speed Limit (kbps), for
			-- inform's _shaper_resync.
			ratelimit_down = tonumber(s.openuf_ratelimit_down),
			ratelimit_up   = tonumber(s.openuf_ratelimit_up),
		}
	end)
	return vaps
end

return M
