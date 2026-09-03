-- Tests for openuf/ucihelper.lua (UCI-backed WiFi provisioning, VLAN tagging).
-- Run from project root: lua tests/run_tests.lua
--
-- Uses an in-memory mock UCI cursor (mirrors the subset of the real `uci`
-- Lua binding's API that ucihelper.lua relies on: cursor:foreach/set/get/delete/commit,
-- including option-level delete(config, section, option)).

local ucihelper = dofile("openuf/ucihelper.lua")

local function new_mock_uci()
	local db           = {}  -- db[config][section] = { [".name"]=.., [".type"]=.., key=val, ... }
	local section_order = {} -- section_order[config] = {name, ...} (foreach iteration order)

	local cursor = {}

	function cursor:set(config, section, a, b)
		-- libuci accepts only [A-Za-z0-9_] in a section name, and enforces it
		-- SILENTLY: set() returns true, commit() returns true, and the section
		-- is discarded before it ever reaches /etc/config. A permissive mock
		-- therefore hides the one bug this can cause -- and did: wlan_add's
		-- sanitizer kept "-", so every SSID with a hyphen provisioned nothing
		-- while every test passed. Fail loudly here instead.
		if not tostring(section):match("^[%w_]+$") then
			error("mock uci: invalid section name '" .. tostring(section)
				.. "' -- libuci would silently discard this", 2)
		end
		db[config] = db[config] or {}
		if not db[config][section] then
			db[config][section] = {[".name"] = section}
			section_order[config] = section_order[config] or {}
			section_order[config][#section_order[config] + 1] = section
		end
		if b == nil then
			db[config][section][".type"] = a
		elseif type(b) == "table" then
			-- Real libuci stringifies list elements on the way through UCI;
			-- mirror that, so no test can pin a native-number representation
			-- the production binding never returns.
			local list = {}
			for i, v in ipairs(b) do list[i] = tostring(v) end
			db[config][section][a] = list
		else
			db[config][section][a] = b
		end
	end

	function cursor:foreach(config, stype, fn)
		for _, name in ipairs(section_order[config] or {}) do
			local s = db[config][name]
			if s and s[".type"] == stype then fn(s) end
		end
	end

	function cursor:delete(config, section, option)
		if option ~= nil then
			if db[config] and db[config][section] then
				db[config][section][option] = nil
			end
			return
		end
		if db[config] then db[config][section] = nil end
		if section_order[config] then
			for i, name in ipairs(section_order[config]) do
				if name == section then table.remove(section_order[config], i); break end
			end
		end
	end

	function cursor:get(config, section, option)
		local s = db[config] and db[config][section]
		local v = s and s[option]
		-- Real libuci returns (nil, "Entry not found") for a miss, and that
		-- second value is a live hazard: tonumber(cursor:get(...)) without
		-- parens takes it as the base argument and throws on the first run,
		-- when the section does not exist yet. A single-value mock hides it
		-- until real hardware finds it.
		if v == nil then return nil, "Entry not found" end
		return v
	end

	-- Commits are recorded, not applied (the mock db is always-live): the
	-- counter is the only way any test can notice a DROPPED commit, which
	-- on a real device strands staged config in the cursor.
	local commits = {}
	function cursor:commit(config)
		commits[config] = (commits[config] or 0) + 1
	end

	return {mock = {cursor = function() return cursor end}, db = db, commits = commits}
end

-- Fresh mock UCI + neutral injectable seams for each test.
-- fn receives (db, cmds): db is the mock UCI backing store, cmds the list of
-- shell commands ucihelper._run_cmd was asked to execute (e.g. "wifi reload")
-- -- capture, don't discard: the reload and its ordering are load-bearing.
-- _bcfilter/_shaper are stubbed to no-ops BY DEFAULT: without stubs
-- apply_config get_sibling()-loads the real openuf/bcfilter.lua + shaper.lua
-- from disk, whose default _exec is os.execute -- i.e. this suite used to
-- run real `nft`/`tc` commands on any Linux host. Tests that need to capture
-- the enforcement calls override the stubs inside fn; every seam (including
-- those and get_ifname_for_vap) is restored here even when fn raises, so a
-- failing test cannot leak its stubs into later ones.
local function with_ucihelper(fn)
	local m = new_mock_uci()
	local cmds = {}
	local orig_uci, orig_popen, orig_read, orig_run =
		ucihelper._uci, ucihelper._popen, ucihelper._read_file, ucihelper._run_cmd
	local orig_bcf, orig_shaper, orig_ifname_vap =
		ucihelper._bcfilter, ucihelper._shaper, ucihelper.get_ifname_for_vap
	ucihelper._uci = m.mock
	ucihelper._popen = function() return "" end       -- no live ifname resolution in tests
	-- Hardware capability probing is cached (it describes hardware); clear it
	-- so a test that feeds a canned `iw phy` dump can't leak those caps into
	-- every later test's clamping decisions.
	ucihelper._phy_caps_cache = nil
	ucihelper._read_file = function() return nil end
	ucihelper._run_cmd = function(cmd) cmds[#cmds + 1] = cmd; return true end
	ucihelper._bcfilter = {reconcile = function() end}
	ucihelper._shaper   = {reconcile = function() end}
	local ok, err = pcall(fn, m.db, cmds, m.commits)
	ucihelper._uci, ucihelper._popen, ucihelper._read_file, ucihelper._run_cmd =
		orig_uci, orig_popen, orig_read, orig_run
	ucihelper._bcfilter, ucihelper._shaper, ucihelper.get_ifname_for_vap =
		orig_bcf, orig_shaper, orig_ifname_vap
	ucihelper._phy_caps_cache = nil
	if not ok then error(err, 2) end
end

-- Seed the `wifi-device` sections every real device already has in
-- /etc/config/wireless. rf_config refuses to touch a radio with no section
-- (writing one would CREATE a phantom radio no driver backs), so any test
-- driving radio config has to start from radios that exist -- which is also
-- the only state apply_config ever sees on hardware: the controller's radio
-- names are echoes of the phynames openUF itself reported from UCI.
local function seed_radios(names)
	local cursor = ucihelper._uci.cursor()
	for _, r in ipairs(names or {"radio0", "radio1"}) do
		cursor:set("wireless", r, "wifi-device")
	end
end

-- Real `iw phy` output from the project's target hardware (TP-Link Archer C5
-- v1, OpenWrt 25.12.5): an ath9k 2.4GHz radio (HT40, no VHT/HE) reporting as
-- "Band 1", and an ath10k 5GHz radio (VHT80, explicitly NOT 160, no HE)
-- reporting as "Band 2". Trimmed to the lines the parser reads -- the band
-- indexes are deliberately kept in their real, inverted-looking order.
local ARCHER_C5_IW_PHY = [[
Wiphy phy1
	Band 1:
		Capabilities: 0x11ef
			RX LDPC
			HT20/HT40
		HT TX/RX MCS rate indexes supported: 0-15
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2437.0 MHz [6] (20.0 dBm)
			* 2472.0 MHz [13] (20.0 dBm)
	Supported extended features:
		* [ RRM ]: RRM
		* [ CAN_REPLACE_PTK0 ]: can replace PTK 0 when rekeying
Wiphy phy0
	Band 2:
		Capabilities: 0x19ef
			RX LDPC
			HT20/HT40
		VHT Capabilities (0x338001b2):
			Max MPDU length: 11454
			Supported Channel Width: neither 160 nor 80+80
		Frequencies:
			* 5180.0 MHz [36] (23.0 dBm)
			* 5260.0 MHz [52] (24.0 dBm) (radar detection)
			* 5745.0 MHz [149] (30.0 dBm)
			* 5845.0 MHz [169] (27.0 dBm) (no IR)
	Supported extended features:
		* [ VHT_IBSS ]: VHT-IBSS
		* [ RRM ]: RRM
		* [ AIRTIME_FAIRNESS ]: airtime fairness
]]

-- Real `iw phy` output from a Xiaomi Mi Router AX3000T (mediatek/filogic,
-- MT7981, OpenWrt 25.12.5): mt76 radios that are HE on BOTH bands -- phy1 is
-- 5GHz with VHT160, phy0 is 2.4GHz with HE but only HT40 channels. Trimmed to
-- the lines the parser reads, band indexes kept in their real order.
--
-- The 2.4GHz half is the point: every earlier board here was HT-only there,
-- so "HE implies 80MHz" was never wrong before this hardware arrived.
local AX3000T_IW_PHY = [[
Wiphy phy1
	Band 2:
		Capabilities: 0x9ff
			HT20/HT40
		VHT Capabilities (0x339a59f6):
			Supported Channel Width: 160 MHz
		HE Iftypes: AP
			HE PHY Capabilities: (0x0c204e926f12afd0000c00):
				20MHz in 160/80+80MHz HE PPDU
		Frequencies:
			* 5180.0 MHz [36] (20.0 dBm)
			* 5745.0 MHz [149] (20.0 dBm) (no IR)
			* 5845.0 MHz [169] (disabled)
	Supported extended features:
		* [ BEACON_RATE_LEGACY ]: legacy beacon rate setting
Wiphy phy0
	Band 1:
		Capabilities: 0x9ff
			HT20/HT40
		HE Iftypes: AP
			HE PHY Capabilities: (0x02204e926f09afc8000c00):
				HE40/2.4GHz
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2437.0 MHz [6] (20.0 dBm)
			* 2472.0 MHz [13] (20.0 dBm) (no IR)
	Supported extended features:
		* [ BEACON_RATE_LEGACY ]: legacy beacon rate setting
]]

-- The same board if its 2.4GHz driver COULD set the beacon frame rate, to pin
-- the capability gate in both directions. Only that phy's extended-feature
-- list differs -- BEACON_RATE_LEGACY is reported per phy, and the gate has to
-- read the flag off the phy serving the band being configured, not off any
-- phy in the device.
local IW_PHY_WITH_BEACON_RATE = (ARCHER_C5_IW_PHY:gsub(
	"%* %[ CAN_REPLACE_PTK0 %]: can replace PTK 0 when rekeying",
	"* [ BEACON_RATE_LEGACY ]: legacy beacon rate"))

return {
	{
		name = "ucihelper: wlan_add defaults network to lan",
		fn = function()
			with_ucihelper(function(db)
				ucihelper.wlan_add("radio0", "myssid", "wpa2", "hunter22")
				assert_eq(db.wireless.openuf_radio0_myssid.network, "lan", "defaults to lan")
			end)
		end
	},
	{
		name = "ucihelper: an SSID with punctuation still lands in a valid UCI section",
		fn = function()
			-- A UCI section name may contain only [A-Za-z0-9_]. libuci enforces
			-- it silently: set() returns true, commit() returns true, and the
			-- section never reaches /etc/config. So an unsanitized character
			-- costs the whole WLAN with nothing reported anywhere -- confirmed
			-- live, where an SSID of "openuf-verify" pushed correctly, parsed
			-- correctly, and simply never provisioned. Hyphens are common in
			-- SSIDs; this was a wide hole.
			for _, ssid in ipairs({"openuf-verify", "Guest WiFi", "caf\195\169!",
					"a.b:c", "5GHz-Fast"}) do
				with_ucihelper(function(db)
					ucihelper.wlan_add("radio0", ssid, "wpa2", "hunter22")
					local found
					for name in pairs(db.wireless or {}) do
						if name:match("^openuf_radio0_") then found = name end
					end
					assert_not_nil(found, ssid .. ": a section was created")
					assert_true(found:match("^[%w_]+$") ~= nil,
						ssid .. ": section name " .. tostring(found)
							.. " is valid for libuci")
					assert_eq(db.wireless[found].ssid, ssid,
						ssid .. ": the SSID itself is stored unmangled")
				end)
			end
		end
	},
	{
		name = "ucihelper: wlan_add sets explicit network and wlanconf_id",
		fn = function()
			with_ucihelper(function(db)
				ucihelper.wlan_add("radio0", "guest", "open", nil, nil,
					"openuf_vlan20", "6a540dd2ffb26b8537ec967d")
				local s = db.wireless.openuf_radio0_guest
				assert_eq(s.network, "openuf_vlan20", "network set")
				assert_eq(s.openuf_wlanconf_id, "6a540dd2ffb26b8537ec967d", "wlanconf_id stashed")
			end)
		end
	},
	{
		name = "ucihelper: wlan_add keeps the same SSID on two radios as separate sections",
		fn = function()
			-- Regression test: broadcasting one SSID on both 2.4GHz and 5GHz
			-- simultaneously (the controller UI's default "Radio Band: 2.4 GHz
			-- + 5 GHz") calls wlan_add() once per radio with an identical
			-- ssid. Section names keyed purely by SSID collapsed both calls
			-- into the same UCI section, so the second call's "device"
			-- silently overwrote the first -- confirmed live against a real
			-- controller: only the last-processed radio's VAP survived.
			with_ucihelper(function(db)
				ucihelper.wlan_add("radio0", "dualband", "wpa2", "hunter22")
				ucihelper.wlan_add("radio1", "dualband", "wpa2", "hunter22")
				local s0 = db.wireless.openuf_radio0_dualband
				local s1 = db.wireless.openuf_radio1_dualband
				assert_true(s0 ~= nil, "radio0 section survives")
				assert_true(s1 ~= nil, "radio1 section survives")
				assert_eq(s0.device, "radio0", "radio0 section bound to radio0")
				assert_eq(s1.device, "radio1", "radio1 section bound to radio1")
			end)
		end
	},
	{
		name = "ucihelper: ensure_vlan_network bridges the tagged uplink (21.02+)",
		fn = function()
			-- The bridge is the entire point. Confirmed live on OpenWrt
			-- 25.12: with only `config interface` + the bare sub-device, both
			-- eth1.20 and the VAP come up as separate masterless netdevs --
			-- netifd even logs "Interface 'openuf_vlan20' is now up" -- and a
			-- client associates to a WLAN with no path to anything. Every
			-- layer looks healthy; only `ip link` shows the missing master.
			with_ucihelper(function(db)
				-- A `config device` section is what marks a 21.02+ netifd.
				-- Seeded through the cursor so the mock's own iteration order
				-- sees it, exactly as libuci's foreach would.
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				c:set("network", "br_lan", "type", "bridge")
				local name = ucihelper.ensure_vlan_network("eth1", 20)
				assert_eq(name, "openuf_vlan20", "section name")

				local br = db.network.openuf_brdev20
				assert_true(br ~= nil, "a bridge device section is created")
				assert_eq(br[".type"], "device", "as a `config device` section")
				assert_eq(br.type, "bridge", "of type bridge")
				assert_eq(br.name, "br-openuf20", "named br-openuf<vid>")
				assert_eq(br.ports[1], "eth1.20", "with the tagged uplink as its port")

				local iface = db.network.openuf_vlan20
				assert_eq(iface.device, "br-openuf20", "the interface points at the bridge")
				assert_eq(iface.proto, "none", "proto none -- the AP needs no address here")
				assert_eq(iface.ifname, nil,
					"no stale ifname: netifd would bridge the raw sub-device instead")
			end)
		end
	},
	{
		name = "ucihelper: ensure_vlan_network turns learning off on the tagged uplink port",
		fn = function()
			-- On a DSA board the untagged uplink and its VLAN sub-device are
			-- ONE physical port on ONE hardware switch with ONE FDB. Left
			-- learning, that switch files the upstream router's MAC under the
			-- VLAN bridge -- `dev wan.10 offload master br-openuf10` -- and
			-- every WIRED client's traffic to the gateway is hardware-
			-- forwarded into the VLAN domain and dropped, while WiFi clients
			-- take the software path and stay fine. Confirmed live on an
			-- AX3000T (2026-09-03): LAN peers reachable, gateway and internet
			-- dead, controller config completely clean.
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				c:set("network", "br_lan", "type", "bridge")
				ucihelper.ensure_vlan_network("wan", 10)

				local port = db.network.openuf_brport10
				assert_true(port ~= nil, "the uplink port gets its own device section")
				assert_eq(port[".type"], "device", "as a `config device` section")
				assert_eq(port.name, "wan.10", "naming the tagged uplink sub-device")
				assert_eq(port.learning, "0", "with MAC learning off")
			end)
		end
	},
	{
		name = "ucihelper: the learning override does not re-dirty a steady-state push",
		fn = function()
			-- A rewrite every inform would reload the network every inform,
			-- bouncing the uplink and the inform connection with it.
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				c:set("network", "br_lan", "type", "bridge")
				ucihelper.ensure_vlan_network("wan", 10)
				ucihelper._network_dirty = false
				ucihelper.ensure_vlan_network("wan", 10)
				assert_eq(ucihelper._network_dirty, false,
					"an unchanged push leaves the learning override alone")
			end)
		end
	},
	{
		name = "ucihelper: prune_vlan_networks takes the uplink port override with it",
		fn = function()
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				c:set("network", "br_lan", "type", "bridge")
				ucihelper.ensure_vlan_network("wan", 10)
				assert_true(db.network.openuf_brport10 ~= nil, "precondition")

				ucihelper.prune_vlan_networks({})
				assert_eq(db.network.openuf_brport10, nil,
					"learning off must not outlive the bridge that needed it")
				assert_eq(db.network.openuf_brdev10, nil, "bridge gone")
				assert_eq(db.network.openuf_vlan10, nil, "interface gone")
			end)
		end
	},
	{
		name = "ucihelper: ensure_vlan_network uses pre-21.02 bridge syntax when that is what the box speaks",
		fn = function()
			-- No `config device` section and no interface carrying `device`
			-- means old netifd, where the interface IS the bridge.
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "lan", "interface")
				c:set("network", "lan", "ifname", "eth0")
				c:set("network", "lan", "proto", "static")
				ucihelper.ensure_vlan_network("eth1", 20)
				local iface = db.network.openuf_vlan20
				assert_eq(iface.type, "bridge", "the interface itself is the bridge")
				assert_eq(iface.ifname, "eth1.20", "with the tagged uplink as its member")
				assert_eq(iface.proto, "none", "proto none")
				assert_eq(db.network.openuf_brdev20, nil,
					"and no `config device` section, which old netifd cannot read")
			end)
		end
	},
	{
		name = "ucihelper: apply_config reloads the network only when a VLAN changed",
		fn = function()
			with_ucihelper(function(db, cmds)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				local resp = {
					radio_table = {},
					vap_table = {{ssid = "iot", radio = "radio0", security = "wpa2",
						x_passphrase = "hunter22", vlan_enabled = true, vlan = 20}},
				}
				local cfg = {net = {lan_cpueth = "eth1"}}
				ucihelper.apply_config(resp, cfg)
				local reloads = 0
				for _, c in ipairs(cmds) do
					if c:find("network reload", 1, true) then reloads = reloads + 1 end
				end
				assert_eq(reloads, 1, "the new bridge is pushed to netifd")

				-- Steady state: the controller re-sends the same config every
				-- inform. Reloading the network each time bounces the uplink
				-- and with it the inform connection.
				local before = #cmds
				ucihelper.apply_config(resp, cfg)
				local again = 0
				for i = before + 1, #cmds do
					if cmds[i]:find("network reload", 1, true) then again = again + 1 end
				end
				assert_eq(again, 0, "an unchanged push issues no network reload")
			end)
		end
	},
	{
		name = "ucihelper: ensure_vlan_network is idempotent",
		fn = function()
			with_ucihelper(function(db)
				local a = ucihelper.ensure_vlan_network("eth1", 20)
				local b = ucihelper.ensure_vlan_network("eth1", 20)
				assert_eq(a, b, "same section name returned")
				local count = 0
				for _ in pairs(db.network) do count = count + 1 end
				assert_eq(count, 1, "only one network section created")
			end)
		end
	},
	{
		name = "ucihelper: apply_config tags a VAP from the vlan set on the vap itself",
		fn = function()
			-- The controller derives the VLAN from aaa.<n>.br.devname
			-- ("br0.20") onto the vap; there is no separate network object on
			-- the wire. (This test used to feed a resp.network_table that a
			-- real controller never sends, so it pinned a join that could
			-- never run in production.)
			with_ucihelper(function(db)
				local resp = {
					cfgversion = "2",
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", vlan = 20, vlan_enabled = true},
					},
				}
				ucihelper.apply_config(resp, {net = {lan_cpueth = "eth1"}})
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.network, "openuf_vlan20", "VAP bound to VLAN network")
				assert_eq(db.network.openuf_vlan20.ifname, "eth1.20", "VLAN interface created")
			end)
		end
	},
	{
		name = "ucihelper: apply_config falls back to lan when vlan_enabled is false",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "open",
						 vlan = 20, vlan_enabled = false},
					},
				}
				ucihelper.apply_config(resp, {net = {lan_cpueth = "eth1"}})
				assert_eq(db.wireless.openuf_radio0_corp.network, "lan", "falls back to lan")
			end)
		end
	},
	{
		name = "ucihelper: apply_config falls back to lan without cfg (no cpueth)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "open",
						 vlan = 20, vlan_enabled = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.network, "lan",
					"no cpueth available -- can't tag, falls back to lan")
			end)
		end
	},
	{
		name = "ucihelper: apply_config derives mobility_domain from fast_roaming_enabled",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", fast_roaming_enabled = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.ieee80211r, "1", "FT enabled")
				assert_eq(s.mobility_domain, ucihelper.derive_mobility_domain("corp"),
					"mobility_domain derived from the ssid")
				assert_eq(#s.mobility_domain, 4, "mobility_domain is 4 hex chars")
				assert_eq(s.ft_over_ds, "0", "over-DS disabled by default")
				-- Deliberately absent. Forcing it to "1" is FT-PSK-only local
				-- key generation, and setting it at all stops OpenWrt
				-- configuring the r0kh/r1kh key holders FT-SAE cannot work
				-- without -- which silently cost every WPA3 client its fast
				-- roaming. OpenWrt's own default already keys on auth_type.
				assert_nil(s.ft_psk_generate_local,
					"left to OpenWrt, which picks per auth_type (psk -> 1, sae -> 0)")
			end)
		end
	},
	{
		name = "ucihelper: a WPA3 WLAN is left able to configure FT key holders",
		fn = function()
			-- The failure this pins is invisible in UCI and on the air: the
			-- WLAN advertises FT-SAE and the right mobility domain, and the
			-- transition still falls back to a full SAE + 4-way. It hinges
			-- entirely on openUF NOT pinning ft_psk_generate_local, because
			-- OpenWrt only derives r0kh/r1kh when that option is 0 -- and it
			-- only defaults it to 0 when nothing overrode it.
			for _, sec in ipairs({"wpa3", "wpa2/wpa3", "wpa2"}) do
				with_ucihelper(function(db)
					ucihelper.apply_config({radio_table = {}, vap_table = {
						{ssid = "corp", radio = "radio0", security = sec,
						 x_passphrase = "hunter22", fast_roaming_enabled = true},
					}}, nil)
					local s = db.wireless.openuf_radio0_corp
					assert_eq(s.ieee80211r, "1", sec .. ": FT enabled")
					assert_nil(s.ft_psk_generate_local,
						sec .. ": openUF does not pin the key-generation mode")
				end)
			end
		end
	},
	{
		name = "ucihelper: wpa3.ft.status alone still enables 802.11r",
		fn = function()
			with_ucihelper(function(db)
				-- The controller asked for FT on the SAE akm while the
				-- WLAN-level toggle is off. OpenWrt has one switch, so the
				-- request is honoured rather than dropped -- ignoring it
				-- would silently deny roaming the controller enabled.
				ucihelper.apply_config({
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2/wpa3",
						 x_passphrase = "hunter22",
						 fast_roaming_enabled = false,
						 wpa3_fast_roaming_enabled = true},
					},
				}, nil)
				assert_eq(db.wireless.openuf_radio0_corp.ieee80211r, "1",
					"FT enabled from the SAE toggle alone")
				assert_eq(db.wireless.openuf_radio0_corp.mobility_domain,
					ucihelper.derive_mobility_domain("corp"),
					"and the mobility domain comes with it")
			end)
		end
	},
	{
		name = "ucihelper: wpa3.ft.status=disabled does not drop FT the WLAN asked for",
		fn = function()
			with_ucihelper(function(db)
				-- The inexpressible case: FT-PSK wanted, FT-SAE not. OpenWrt
				-- cannot split them, so FT stays on -- dropping it would
				-- break roaming for every WPA2 client on the WLAN.
				ucihelper.apply_config({
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2/wpa3",
						 x_passphrase = "hunter22",
						 fast_roaming_enabled = true,
						 wpa3_fast_roaming_enabled = false},
					},
				}, nil)
				assert_eq(db.wireless.openuf_radio0_corp.ieee80211r, "1",
					"FT kept for the akm that did ask for it")
			end)
		end
	},
	{
		name = "ucihelper: both FT toggles off leaves 802.11r off",
		fn = function()
			with_ucihelper(function(db)
				ucihelper.apply_config({
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2/wpa3",
						 x_passphrase = "hunter22",
						 fast_roaming_enabled = false,
						 wpa3_fast_roaming_enabled = false},
					},
				}, nil)
				assert_eq(db.wireless.openuf_radio0_corp.ieee80211r, nil,
					"neither toggle set -- no ieee80211r written")
				assert_eq(db.wireless.openuf_radio0_corp.mobility_domain, nil,
					"and no mobility domain")
			end)
		end
	},
	{
		name = "ucihelper: derive_mobility_domain is stable across independent APs",
		fn = function()
			with_ucihelper(function(db)
				local resp1 = {
					radio_table = {},
					vap_table = {{ssid = "corp", radio = "radio0", security = "wpa2",
						x_passphrase = "hunter22", fast_roaming_enabled = true}},
				}
				ucihelper.apply_config(resp1, nil)
				local first = db.wireless.openuf_radio0_corp.mobility_domain

				local resp2 = {
					radio_table = {},
					vap_table = {{ssid = "corp", radio = "radio1", security = "wpa2",
						x_passphrase = "hunter22", fast_roaming_enabled = true}},
				}
				ucihelper.apply_config(resp2, nil)
				local second = db.wireless.openuf_radio1_corp.mobility_domain

				assert_eq(first, second,
					"same ssid yields same mobility_domain regardless of radio")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes bss_transition from vap.bss_transition",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bss_transition = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, "1", "bss_transition enabled")
				assert_eq(s.ieee80211v, nil, "deprecated ieee80211v option never written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes bss_transition=0 (explicit off), not omitted",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bss_transition = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, "0", "bss_transition explicitly disabled")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits bss_transition when absent from the vap",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, nil, "no bss_transition option written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes dtim_period from vap.dtim_period",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", dtim_period = 3},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.dtim_period, "3", "custom dtim_period written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits dtim_period when absent (Auto DTIM)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.dtim_period, nil, "no dtim_period option written -- leaves hostapd default")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes ieee80211w from vap.pmf (enabled/optional)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", pmf_status = "enabled", pmf_mode = 1},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.ieee80211w, "1", "PMF optional -> ieee80211w=1")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes ieee80211w=2 for PMF required",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa3",
						 x_passphrase = "hunter22", pmf_status = "enabled", pmf_mode = 2},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.ieee80211w, "2", "PMF required -> ieee80211w=2")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes explicit ieee80211w=0 when PMF disabled",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", pmf_status = "disabled", pmf_mode = 0},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.ieee80211w, "0", "PMF disabled -> explicit ieee80211w=0")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits ieee80211w when no pmf block present",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.ieee80211w, nil, "no pmf -> ieee80211w unset")
			end)
		end
	},
	{
		name = "ucihelper: get_ifname_for_vap matches the VAP by SSID, not radio position",
		fn = function()
			local orig = ucihelper._popen
			ucihelper._popen = function()
				return '{"radio0":{"interfaces":['
					.. '{"ifname":"wlan0","config":{"ssid":"corp"}},'
					.. '{"ifname":"wlan0-1","config":{"ssid":"guest"}}]}}'
			end
			local corp  = ucihelper.get_ifname_for_vap("radio0", "corp")
			local guest = ucihelper.get_ifname_for_vap("radio0", "guest")
			local miss  = ucihelper.get_ifname_for_vap("radio0", "nosuch")
			ucihelper._popen = orig
			assert_eq(corp, "wlan0", "first VAP resolved by its SSID")
			assert_eq(guest, "wlan0-1", "second VAP resolved by its SSID")
			-- Ambiguous: two interfaces, neither matching. Guessing would apply
			-- one SSID's filter to another.
			assert_eq(miss, nil, "no guess when the SSID is absent and >1 candidate")
		end
	},
	{
		name = "ucihelper: get_ifname_for_vap falls back to a radio's only interface",
		fn = function()
			local orig = ucihelper._popen
			-- No config.ssid reported at all -- but with a single VAP on the
			-- radio there is no other interface it could be.
			ucihelper._popen = function()
				return '{"radio0":{"interfaces":[{"ifname":"wlan0"}]}}'
			end
			local got = ucihelper.get_ifname_for_vap("radio0", "corp")
			ucihelper._popen = orig
			assert_eq(got, "wlan0", "unambiguous single interface is used")
		end
	},
	{
		name = "ucihelper: apply_config records the blocker on the section and reconciles nft",
		fn = function()
			with_ucihelper(function(db)
				local got
				ucihelper._bcfilter = {reconcile = function(rules) got = rules end}
				-- get_ifname_for_vap goes through _popen, stubbed to "" by the
				-- harness, so resolve it directly here instead.
				local orig = ucihelper.get_ifname_for_vap
				ucihelper.get_ifname_for_vap = function(radio, ssid)
					if radio == "radio0" and ssid == "corp" then return "wlan0" end
				end
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bcfilt_enabled = true,
						 bcfilt_macs = {"01:00:5e:00:00:fb", "aa:bb:cc:dd:ee:ff"}},
					},
				}
				ucihelper.apply_config(resp, nil)
				ucihelper.get_ifname_for_vap = orig
				ucihelper._bcfilter = nil

				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.openuf_bcfilt, "1", "blocker state recorded in UCI")
				assert_eq(s.openuf_bcfilt_macs, "01:00:5e:00:00:fb aa:bb:cc:dd:ee:ff",
					"allow-list recorded in UCI")
				assert_eq(#got, 1, "one nft rule reconciled")
				assert_eq(got[1].ifname, "wlan0", "rule targets the vap's own netdev")
				assert_eq(#got[1].macs, 2, "both allow-listed MACs carried through")
			end)
		end
	},
	{
		name = "ucihelper: apply_config reconciles an empty ruleset when the blocker is off",
		fn = function()
			with_ucihelper(function(db)
				-- Must still reconcile: turning the control off has to tear the
				-- previous ruleset down, not leave it silently in force.
				local got
				ucihelper._bcfilter = {reconcile = function(rules) got = rules end}
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bcfilt_enabled = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				ucihelper._bcfilter = nil
				assert_eq(db.wireless.openuf_radio0_corp.openuf_bcfilt, "0", "recorded off")
				assert_true(got ~= nil, "reconcile still called")
				assert_eq(#got, 0, "no rules")
			end)
		end
	},
	{
		name = "ucihelper: apply_config issues wifi reload BEFORE the bcfilter/shaper reconciles",
		fn = function()
			-- The ordering is load-bearing: both enforcements resolve live
			-- netdev names that only exist after netifd brings the interfaces
			-- back up. Reconciling first would resolve nothing and silently
			-- skip every rule. Record shell commands and reconcile calls into
			-- ONE ordered list to pin the sequence.
			with_ucihelper(function(db, cmds)
				ucihelper._bcfilter = {reconcile = function()
					cmds[#cmds + 1] = "<bcfilter.reconcile>" end}
				ucihelper._shaper = {reconcile = function()
					cmds[#cmds + 1] = "<shaper.reconcile>" end}
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local pos = {}
				for i, c in ipairs(cmds) do
					if c:find("wifi reload", 1, true) then pos.reload = pos.reload or i end
					if c == "<bcfilter.reconcile>" then pos.bcf = i end
					if c == "<shaper.reconcile>" then pos.shaper = i end
				end
				assert_true(pos.reload ~= nil, "wifi reload issued")
				assert_true(pos.bcf ~= nil and pos.reload < pos.bcf,
					"bcfilter reconciled after the reload")
				assert_true(pos.shaper ~= nil and pos.reload < pos.shaper,
					"shaper reconciled after the reload")
			end)
		end
	},
	{
		name = "ucihelper: apply_config hands the shaper every managed VAP, uncapped ones included",
		fn = function()
			-- shaper.reconcile clears each interface it is handed before
			-- reshaping, so a VAP whose limit was just removed must appear
			-- with both rates nil -- omitting it would strand the old qdisc.
			with_ucihelper(function(db)
				local got
				ucihelper._shaper = {reconcile = function(rules) got = rules end}
				ucihelper.get_ifname_for_vap = function(radio, ssid)
					if ssid == "capped" then return "wlan0" end
					if ssid == "uncapped" then return "wlan1" end
				end
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "capped", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22",
						 ratelimit_down_kbps = 33000, ratelimit_up_kbps = 17000},
						{ssid = "uncapped", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(#got, 2, "both VAPs handed to the shaper")
				local by_if = {}
				for _, r in ipairs(got) do by_if[r.ifname] = r end
				assert_eq(by_if.wlan0.down_kbps, 33000, "capped VAP carries its down rate")
				assert_eq(by_if.wlan0.up_kbps, 17000, "capped VAP carries its up rate")
				assert_true(by_if.wlan1 ~= nil, "uncapped VAP still present for teardown")
				assert_nil(by_if.wlan1.down_kbps, "uncapped VAP has no down rate")
				assert_nil(by_if.wlan1.up_kbps, "uncapped VAP has no up rate")
			end)
		end
	},
	{
		name = "ucihelper: rf_config and apply_config commit the wireless config",
		fn = function()
			-- The mock db is always-live, so a dropped cursor:commit is
			-- invisible to every value assertion -- on a real device it
			-- strands the whole push in the uncommitted cursor. The counter
			-- is the only signal.
			with_ucihelper(function(db, cmds, commits)
				seed_radios()
				ucihelper.rf_config("radio0", "HT40", 6, 20)
				assert_eq(commits.wireless, 1, "rf_config commits wireless")
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_true((commits.wireless or 0) >= 2,
					"apply_config commits wireless before the wifi reload")
			end)
		end
	},
	{
		name = "ucihelper: derive_rates makes the floor the sole basic rate",
		fn = function()
			local r = ucihelper.derive_rates(12000, false, false)
			assert_eq(#r.basic_rate, 1, "exactly one basic rate")
			assert_eq(r.basic_rate[1], 12000, "the floor itself is the basic rate")
			assert_eq(r.legacy_rates, "0", "CCK excluded -> legacy_rates off")
			assert_eq(r.supported_rates, nil, "supported_rates untouched without drop_below")
		end
	},
	{
		name = "ucihelper: derive_rates drops rates below the floor when asked",
		fn = function()
			local r = ucihelper.derive_rates(12000, false, true)
			assert_eq(r.supported_rates[1], 12000, "advertised set starts at the floor")
			assert_eq(r.supported_rates[#r.supported_rates], 54000, "and runs to the top")
			for _, rate in ipairs(r.supported_rates) do
				assert_true(rate >= 12000, "no advertised rate below the floor")
			end
		end
	},
	{
		name = "ucihelper: derive_rates keeps CCK rates on the ladder when allowed",
		fn = function()
			local r = ucihelper.derive_rates(1000, true, true)
			assert_eq(r.supported_rates[1], 1000, "1 Mbps CCK retained")
			assert_eq(r.legacy_rates, "1", "legacy rates allowed")
		end
	},
	{
		name = "ucihelper: derive_rates returns nil rather than an empty rate list",
		fn = function()
			-- A floor above every rate on the ladder would otherwise produce an
			-- empty basic_rate and leave hostapd unable to start the BSS.
			assert_eq(ucihelper.derive_rates(99000, true, true), nil, "no rates -> nil")
			assert_eq(ucihelper.derive_rates(nil, true, true), nil, "no floor -> nil")
		end
	},
	{
		name = "ucihelper: apply_config writes radio-level rates from a vap's minrate_data",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false, beacon_rate = 12000,
						 minrate_below_disable = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				local r = db.wireless.radio0
				assert_eq(r.basic_rate[1], "12000", "floor written as the basic rate")
				assert_eq(r.legacy_rates, "0", "CCK off")
				-- beacon_rate is the one option OpenWrt does NOT divide by 100.
				assert_eq(r.beacon_rate, "120", "12000 kb/s -> 120 (100-kbps units)")
			end)
		end
	},
	{
		name = "ucihelper: apply_config takes the lowest floor across VAPs on one radio",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				-- Two WLANs share radio0 with different floors. Applying the
				-- stricter 12 Mbps would lock out clients the 1 Mbps WLAN is
				-- meant to admit, so the permissive floor has to win.
				local resp = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "fast", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false, minrate_below_disable = true},
						{ssid = "iot", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 1000,
						 minrate_cck = true, minrate_below_disable = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				local r = db.wireless.radio0
				assert_eq(r.basic_rate[1], "1000", "lowest floor wins")
				assert_eq(r.legacy_rates, "1", "CCK allowed because one WLAN allows it")
				assert_eq(r.supported_rates, nil, "not all WLANs asked to drop lower rates")
			end)
		end
	},
	{
		name = "ucihelper: apply_config leaves radio rates alone when no VAP has a floor",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local r = db.wireless.radio0 or {}
				assert_eq(r.basic_rate, nil, "no basic_rate written")
				assert_eq(r.legacy_rates, nil, "no legacy_rates written")
				assert_eq(r.beacon_rate, nil, "no beacon_rate written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config tears down rate options when Minimum Data Rate is turned off",
		fn = function()
			-- The wire signals "control off" by omitting every minrate_* key,
			-- so the off-push arrives with no floor on any VAP. Before the
			-- fix that meant rates=nil -> skip -> the old basic_rate kept
			-- excluding slow clients forever.
			with_ucihelper(function(db)
				seed_radios()
				local on = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false, beacon_rate = 12000,
						 minrate_below_disable = true},
					},
				}
				ucihelper.apply_config(on, nil)
				assert_eq(db.wireless.radio0.openuf_rates, "1", "managed section marked")
				assert_eq(db.wireless.radio0.basic_rate[1], "12000", "floor applied")

				local off = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(off, nil)
				local r = db.wireless.radio0
				assert_eq(r.basic_rate, nil, "basic_rate torn down")
				assert_eq(r.supported_rates, nil, "supported_rates torn down")
				assert_eq(r.legacy_rates, nil, "legacy_rates torn down")
				assert_eq(r.beacon_rate, nil, "beacon_rate torn down")
				assert_eq(r.openuf_rates, nil, "marker removed")
			end)
		end
	},
	{
		name = "ucihelper: apply_config never touches hand-tuned rates on an unmarked radio",
		fn = function()
			-- A user's own basic_rate in /etc/config/wireless, never written
			-- by openUF (no openuf_rates marker), must survive a floor-less
			-- push -- absent-when-off is indistinguishable from never-managed
			-- without the marker, so only marked sections are torn down.
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "basic_rate", {6000})
				local resp = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.basic_rate[1], "6000",
					"hand-tuned basic_rate preserved on an unmarked section")
			end)
		end
	},
	{
		name = "ucihelper: apply_config drops supported_rates when only the drop-below sub-toggle reverts",
		fn = function()
			-- The sub-toggle can turn off while the floor stays on: the next
			-- push has minrate_data but no drop-below. supported_rates from
			-- the stricter earlier push must be deleted, not skipped.
			with_ucihelper(function(db)
				seed_radios()
				local strict = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false, minrate_below_disable = true},
					},
				}
				ucihelper.apply_config(strict, nil)
				assert_true(db.wireless.radio0.supported_rates ~= nil, "strict push trims the advertised set")

				local relaxed = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false, minrate_below_disable = false},
					},
				}
				ucihelper.apply_config(relaxed, nil)
				local r = db.wireless.radio0
				assert_eq(r.supported_rates, nil, "supported_rates deleted when drop-below reverts")
				assert_eq(r.basic_rate[1], "12000", "floor still applied")
				assert_eq(r.openuf_rates, "1", "section still marked while the floor is on")
			end)
		end
	},
	{
		name = "ucihelper: a single VAP with minrate_below_disable absent stays permissive",
		fn = function()
			-- The wire can carry minrate_data without minrate_below_disable
			-- (absent -> nil at parse). Absent must mean "don't trim the
			-- advertised set" -- the old init read it as strict for a single
			-- VAP and then flipped to permissive when a second identical VAP
			-- joined the radio, contradicting the most-permissive contract.
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					radio_table = {{name = "radio0"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 12000,
						 minrate_cck = false},  -- no minrate_below_disable
					},
				}
				ucihelper.apply_config(resp, nil)
				local r = db.wireless.radio0
				assert_eq(r.supported_rates, nil,
					"absent drop-below key -> advertised set not trimmed")
				assert_eq(r.basic_rate[1], "12000", "floor still applied")
			end)
		end
	},
	{
		name = "ucihelper: apply_config keeps each radio's floor separate",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					radio_table = {{name = "radio0"}, {name = "radio1"}},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 1000,
						 minrate_cck = true},
						{ssid = "corp", radio = "radio1", security = "wpa2",
						 x_passphrase = "hunter22", minrate_data = 24000,
						 minrate_cck = nil},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.basic_rate[1], "1000", "2.4GHz floor")
				assert_eq(db.wireless.radio1.basic_rate[1], "24000", "5GHz floor")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes proxy_arp from vap.proxy_arp",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", proxy_arp = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.proxy_arp, "1", "proxy ARP enabled")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes proxy_arp=0 (explicit off)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", proxy_arp = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.proxy_arp, "0", "proxy ARP explicitly off")
			end)
		end
	},
	{
		name = "ucihelper: apply_config leaves proxy_arp unset when the vap has none",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.proxy_arp, nil, "no proxy_arp written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes isolate from vap.l2_isolation",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", l2_isolation = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.isolate, "1", "client isolation enabled")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes isolate=0 (explicit off)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", l2_isolation = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.isolate, "0", "client isolation explicitly off")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes hidden from vap.hide_ssid",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", hide_ssid = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.hidden, "1", "SSID hidden")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes hidden=0 (explicit off)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", hide_ssid = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.openuf_radio0_corp.hidden, "0", "SSID explicitly broadcast")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes macfilter/maclist from the MAC filter",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22",
						 mac_filter_policy = "allow",
						 mac_filter_list = {"00:11:22:33:44:55", "66:77:88:99:aa:bb"}},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.macfilter, "allow", "policy written")
				-- Asserted by index: maclist must reach UCI as a real list, not
				-- a stringified table.
				assert_eq(s.maclist[1], "00:11:22:33:44:55", "first MAC in the list")
				assert_eq(s.maclist[2], "66:77:88:99:aa:bb", "second MAC in the list")
			end)
		end
	},
	{
		name = "ucihelper: apply_config OMITS macfilter when the filter is off",
		fn = function()
			with_ucihelper(function(db)
				-- Not macfilter="disable": OpenWrt's own schema declares this
				-- option as enum ["allow","deny"], and 25.12's validator does
				-- not ignore an out-of-enum value -- it aborts the entire radio
				-- setup, so both radios come up with no interfaces and not one
				-- SSID reaches the air. Seen for real on an Archer C5 v1
				-- running 25.12.5:
				--   wifi-scripts: macfilter: disable has to be one of
				--     [ "allow", "deny" ]
				--   netifd: radio0 (4179): Died
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_true(s ~= nil, "vap section still created")
				assert_nil(s.macfilter, "no filter -> option absent, never 'disable'")
				assert_nil(s.maclist, "and no stale maclist left behind")
			end)
		end
	},
	{
		name = "ucihelper: turning the MAC filter off lifts a previously pushed one",
		fn = function()
			with_ucihelper(function(db)
				local function push(vap)
					ucihelper.apply_config({radio_table = {}, vap_table = {vap}}, nil)
				end
				push({ssid = "corp", radio = "radio0", security = "wpa2",
					x_passphrase = "hunter22", mac_filter_policy = "allow",
					mac_filter_list = {"02:11:22:33:44:55"}})
				assert_eq(db.wireless.openuf_radio0_corp.macfilter, "allow",
					"filter applied on the first push")
				push({ssid = "corp", radio = "radio0", security = "wpa2",
					x_passphrase = "hunter22"})
				local s = db.wireless.openuf_radio0_corp
				assert_nil(s.macfilter, "second push lifts the filter")
				assert_nil(s.maclist, "and clears the list it was filtering on")
			end)
		end
	},
	{
		name = "ucihelper: apply_config stamps the speed limit on the section",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22",
						 ratelimit_down_kbps = 33000, ratelimit_up_kbps = 17000},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.openuf_ratelimit_down, "33000", "downlink kbps recorded")
				assert_eq(s.openuf_ratelimit_up, "17000", "uplink kbps recorded")
			end)
		end
	},
	{
		name = "ucihelper: apply_config leaves no speed-limit stamp when uncapped",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.openuf_ratelimit_down, nil, "no downlink stamp")
				assert_eq(s.openuf_ratelimit_up, nil, "no uplink stamp")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes multicast_to_unicast from vap.mcast_enhance",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", mcast_enhance = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.multicast_to_unicast, "1", "mcast enhancement enabled")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes multicast_to_unicast=0 (explicit off)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", mcast_enhance = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.multicast_to_unicast, "0", "mcast enhancement explicitly off")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits multicast_to_unicast when absent",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.multicast_to_unicast, nil, "no mcast field -> option unset")
			end)
		end
	},
	{
		name = "ucihelper: apply_config maps security=wpa2/wpa3 to encryption sae-mixed",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2/wpa3",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.encryption, "sae-mixed", "mixed -> sae-mixed")
				assert_eq(s.key, "hunter22", "passphrase still written for sae-mixed")
			end)
		end
	},
	{
		name = "ucihelper: apply_config maps security=wpa3 to encryption sae",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa3",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.encryption, "sae", "wpa3 -> sae")
			end)
		end
	},
	{
		name = "ucihelper: apply_config forces 802.11k/BSS-Transition on when band steering is active",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bss_transition = false},
					},
				}
				ucihelper.apply_config(resp, nil, {band_steering_active = true})
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, "1", "forced on despite vap.bss_transition=false")
				assert_eq(s.ieee80211k, "1", "802.11k forced on")
				assert_eq(s.rrm_neighbor_report, "1", "rrm_neighbor_report forced on")
				assert_eq(s.rrm_beacon_report, "1", "rrm_beacon_report forced on")
				assert_eq(s.wnm_sleep_mode, "1", "wnm_sleep_mode forced on")
			end)
		end
	},
	{
		name = "ucihelper: apply_config respects per-vap bss_transition when band steering is off",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bss_transition = false},
					},
				}
				ucihelper.apply_config(resp, nil, {band_steering_active = false})
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, "0", "per-vap setting respected, not forced")
				assert_eq(s.ieee80211k, nil, "802.11k not forced on")
			end)
		end
	},
	{
		name = "ucihelper: apply_config respects per-vap bss_transition when opts is nil",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", bss_transition = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_transition, "0", "per-vap setting respected without opts")
			end)
		end
	},
	{
		name = "ucihelper: apply_config sets wps_device_name/ap_setup_locked when advertise_ap_name is on",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", advertise_ap_name = true},
					},
				}
				ucihelper.apply_config(resp, nil, {device_name = "Living-Room-AP"})
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.wps_device_name, "Living-Room-AP", "WPS device name from opts.device_name")
				assert_eq(s.ap_setup_locked, "1", "PIN-based WPS enrollment locked out")
			end)
		end
	},
	{
		name = "ucihelper: apply_config defaults wps_device_name to 'openUF' without opts.device_name",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", advertise_ap_name = true},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.wps_device_name, "openUF", "falls back to 'openUF'")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits wps_device_name/ap_setup_locked when advertise_ap_name is off",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil, {device_name = "Living-Room-AP"})
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.wps_device_name, nil, "no WPS device name written")
				assert_eq(s.ap_setup_locked, nil, "no ap_setup_locked written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes sae_anti_clogging_threshold/sae_sync from vap fields",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa3",
						 x_passphrase = "hunter22", sae_anti_clogging = 12, sae_sync = 20},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.sae_anti_clogging_threshold, "12", "sae_anti_clogging_threshold written")
				assert_eq(s.sae_sync, "20", "sae_sync written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits sae_anti_clogging_threshold/sae_sync when absent",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.sae_anti_clogging_threshold, nil, "no sae_anti_clogging_threshold written")
				assert_eq(s.sae_sync, nil, "no sae_sync written")
			end)
		end
	},
	{
		name = "ucihelper: get_vap_table omits foreign SSIDs that are switched off",
		fn = function()
			-- OpenWrt's stock default_radioN sections, which
			-- use_only_unifi_wlan disables during provisioning. They have no
			-- BSS on the air, and reporting them cost more than a wasted
			-- entry: the nested sta_table is built per RADIO, so every real
			-- station on that radio was attributed to the phantom VAP too,
			-- duplicating its traffic and retry counters. Confirmed on real
			-- hardware -- one live SSID was reported as four VAPs.
			with_ucihelper(function()
				seed_radios({"radio0", "radio1"})
				local cursor = ucihelper._uci.cursor()
				for _, r in ipairs({"radio0", "radio1"}) do
					local name = "default_" .. r
					cursor:set("wireless", name, "wifi-iface")
					cursor:set("wireless", name, "device", r)
					cursor:set("wireless", name, "ssid", "OpenWrt")
					cursor:set("wireless", name, "disabled", "1")
				end
				ucihelper.wlan_add("radio0", "corp", "wpa2", "hunter22", nil, nil, "wlan-1")
				local vaps = ucihelper.get_vap_table()
				assert_eq(#vaps, 1, "only the live, openUF-managed vap is reported")
				assert_eq(vaps[1].essid, "corp", "and it is the right one")
			end)
		end
	},
	{
		name = "ucihelper: get_vap_table still reports an openUF vap the controller disabled",
		fn = function()
			-- The other side of the same rule: a WLAN the controller itself
			-- switched off must keep appearing (as disabled), or the UI would
			-- show it vanishing off the device entirely.
			with_ucihelper(function()
				seed_radios({"radio0"})
				ucihelper.wlan_add("radio0", "corp", "wpa2", "hunter22", nil, nil, "wlan-1")
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "openuf_radio0_corp", "disabled", "1")
				local vaps = ucihelper.get_vap_table()
				assert_eq(#vaps, 1, "still reported")
				assert_eq(vaps[1].disabled, true, "and reported as disabled")
			end)
		end
	},
	{
		name = "ucihelper: get_vap_table echoes the wlanconf id as both id and wlanconf_id",
		fn = function()
			-- Regression test: the controller's vapInformProcessor silently
			-- drops any usage=user vap whose "id" (the wlanconf ObjectId,
			-- pushed in system_cfg as aaa.<n>.id) is missing -- and the
			-- nested sta_table goes with it, so no wireless client ever
			-- reached the Clients list. Note "id" must be the *wlanconf* id,
			-- not the networkconf id this field used to (mis)carry.
			with_ucihelper(function(db)
				ucihelper.wlan_add("radio0", "corp", "wpa2", "hunter22", nil,
					"openuf_vlan20", "wlan-1")
				local vaps = ucihelper.get_vap_table()
				assert_eq(#vaps, 1, "one vap")
				assert_eq(vaps[1].id, "wlan-1", "id echoes the wlanconf id")
				assert_eq(vaps[1].wlanconf_id, "wlan-1", "wlanconf_id matches id")
			end)
		end
	},
	{
		name = "ucihelper: get_vap_table reports radio as the band, not the UCI device name",
		fn = function()
			-- Regression test: the controller's stats pipeline
			-- (com.ubnt.service.system.QDcGUYAmLvJwylXw) parses vap_table's
			-- "radio" field through the same band-parsing enum as
			-- radio_table's "radio" field (com.ubnt.g.f.e.rYtJfMBbtgWvku:
			-- "ng"/"na"/"ad"/"6e") -- sending the raw UCI device name
			-- ("radio0") there instead logs "unexpected radio[radio0]
			-- while processing stats" on every inform. "radio_name" is the
			-- separate field that legitimately holds the UCI device name.
			with_ucihelper(function(db)
				local uci = ucihelper._uci
				local cursor = uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "6")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "channel", "36")
				ucihelper.wlan_add("radio0", "corp24", "wpa2", "hunter22")
				ucihelper.wlan_add("radio1", "corp5", "wpa2", "hunter22")
				local vaps = ucihelper.get_vap_table()
				table.sort(vaps, function(a, b) return a.essid < b.essid end)
				assert_eq(vaps[1].radio, "ng", "2.4GHz vap reports band ng")
				assert_eq(vaps[1].radio_name, "radio0", "2.4GHz vap keeps UCI device name separately")
				assert_eq(vaps[2].radio, "na", "5GHz vap reports band na")
				assert_eq(vaps[2].radio_name, "radio1", "5GHz vap keeps UCI device name separately")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table includes capability defaults",
		fn = function()
			with_ucihelper(function(db)
				local uci = ucihelper._uci
				local cursor = uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "6")
				local radios = ucihelper.get_radio_table()
				assert_eq(#radios, 1, "one radio")
				assert_eq(radios[1].builtin_ant_gain, ucihelper.RADIO_DEFAULTS.builtin_ant_gain,
					"builtin_ant_gain default")
				assert_eq(radios[1].max_txpower, ucihelper.RADIO_DEFAULTS.max_txpower,
					"max_txpower default")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table derives radio band from channel",
		fn = function()
			with_ucihelper(function(db)
				local uci = ucihelper._uci
				local cursor = uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "6")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "channel", "36")
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].radio, "ng", "channel 6 is 2.4GHz")
				assert_eq(radios[2].radio, "na", "channel 36 is 5GHz")
			end)
		end
	},
	{
		-- "Minimum RSSI" (Devices -> [AP] -> Radios) is per-radio, not
		-- per-SSID -- confirmed live 2026-07-14 via the controller's
		-- stamgr.<n>.minrssi.* wire keys, a section indexed the same as
		-- radio.<n> (separate from vap_table/aaa.<n>/wireless.<n>).
		name = "ucihelper: apply_config writes minrssi UCI options from radio_table",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					vap_table = {},
					radio_table = {
						{name = "radio0", min_rssi_enabled = true, min_rssi = 15},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.radio0
				assert_eq(s.minrssi_enabled, "1", "minrssi_enabled written")
				assert_eq(s.minrssi_rssi, "15", "minrssi_rssi written as raw wire units")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits minrssi UCI options when disabled/absent",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", channel = 6}},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.radio0
				assert_eq(s.minrssi_rssi, nil, "no minrssi_rssi written when absent from radio_table")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes htmode from radio.htmode (channel width)",
		fn = function()
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					vap_table = {},
					radio_table = {
						{name = "radio0", htmode = "HT40", channel = 6},
						{name = "radio1", htmode = "VHT80", channel = 36},
					},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.htmode, "HT40", "2.4GHz htmode written")
				assert_eq(db.wireless.radio1.htmode, "VHT80", "5GHz htmode written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config leaves htmode untouched when radio.htmode is absent",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "htmode", "VHT80")
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", channel = 6}},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.htmode, "VHT80",
					"pre-existing htmode preserved when the controller sends no ieee_mode")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes channel 6 from the IoT channel lock",
		fn = function()
			-- "Lock 2.4 GHz to Channel 6 (All APs)" reaches the device as
			-- radio.<n>.channel=6 (CONFIRMED live 2026-07-18) -- no dedicated
			-- key, so this regression-locks the plain channel path it rides.
			with_ucihelper(function(db)
				seed_radios()
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", channel = 6}},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.channel, "6", "channel 6 written")
			end)
		end
	},
	{
		name = "ucihelper: band_for_channel boundaries -- 14 stays ng, 36 is na",
		fn = function()
			-- Only the 2.4GHz side was ever pinned end-to-end; an inverted
			-- mapping on the 5GHz side would have passed the whole suite.
			assert_eq(ucihelper.band_for_channel(1), "ng", "channel 1 (2.4GHz lower edge)")
			assert_eq(ucihelper.band_for_channel(14), "ng", "channel 14 (2.4GHz upper edge, JP)")
			assert_eq(ucihelper.band_for_channel(36), "na", "channel 36 (5GHz lower edge)")
			assert_eq(ucihelper.band_for_channel(165), "na", "channel 165 (5GHz upper)")
			assert_eq(ucihelper.band_for_channel("auto"), "na",
				"non-numeric falls back to na (config-first band_for_device handles it upstream)")
		end
	},
	{
		name = "ucihelper: a missing cjson disables ifname lookups with ONE loud warning",
		fn = function()
			-- Without cjson the ubus JSON can't be parsed: every ifname
			-- lookup returns nil and the Multicast/Broadcast Blocker + WiFi
			-- Speed Limit silently no-op while apply_config reports success.
			-- The degradation must be loud (once), never silent. Fresh module
			-- instance: the cjson probe is cached per instance.
			local fresh = dofile("openuf/ucihelper.lua")
			fresh._load_cjson = function() return nil end
			fresh._popen = function() return '{"radio0":{"interfaces":[{"ifname":"wlan0"}]}}' end
			local buf = {}
			local real = io.stderr
			io.stderr = {write = function(_, s) buf[#buf + 1] = s end}
			local r1 = fresh.get_ifname_for_radio("radio0")
			local r2 = fresh.get_ifname_for_vap("radio0", "corp")
			io.stderr = real
			local out = table.concat(buf)
			assert_nil(r1, "radio lookup degrades to nil")
			assert_nil(r2, "vap lookup degrades to nil")
			assert_contains(out, "lua-cjson unavailable", "warning names the cause")
			assert_contains(out, "NOT be enforced", "warning names the consequence")
			local _, count = out:gsub("lua%-cjson unavailable", "")
			assert_eq(count, 1, "warned exactly once, not per call")
		end
	},
	{
		name = "ucihelper: get_radio_table derives the band config-first when channel is auto",
		fn = function()
			-- With channel=auto (ACS) the channel number can't identify the
			-- band, and the old channel-only mapping reported every ACS radio
			-- as "na" (5GHz). The section's own declaration is authoritative:
			-- `band` on modern OpenWrt, `hwmode` on older releases.
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "auto")
				cursor:set("wireless", "radio0", "band", "2g")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "channel", "auto")
				cursor:set("wireless", "radio1", "hwmode", "11g")
				cursor:set("wireless", "radio2", "wifi-device")
				cursor:set("wireless", "radio2", "channel", "auto")
				cursor:set("wireless", "radio2", "band", "5g")
				cursor:set("wireless", "radio3", "wifi-device")
				cursor:set("wireless", "radio3", "channel", "6")
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].radio, "ng", "band=2g wins over channel=auto (was misreported na)")
				assert_eq(radios[2].radio, "ng", "hwmode=11g wins over channel=auto")
				assert_eq(radios[3].radio, "na", "band=5g respected")
				assert_eq(radios[4].radio, "ng", "numeric channel fallback unchanged")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes the literal channel=auto (ACS) over a stale fixed channel",
		fn = function()
			-- The controller sends radio.<n>.channel=auto for the Auto
			-- setting; the parser passes it through verbatim so this write
			-- replaces any previously pushed fixed channel -- skipping the
			-- write here would leave the old number silently overriding the
			-- user's switch back to Auto.
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "11")
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", channel = "auto"}},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.channel, "auto",
					"stale fixed channel replaced by auto (hostapd ACS)")
			end)
		end
	},
	{
		name = "ucihelper: apply_config deletes a stale fixed txpower when the controller reverts to Auto",
		fn = function()
			-- "Transmit Power: Auto" arrives as the literal radio.<n>.txpower=auto.
			-- UCI has no auto txpower value (absent option = driver default),
			-- so the revert must DELETE the option -- skipping the write left
			-- the old fixed dBm silently overriding the user's Auto choice.
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "txpower", "17")
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", tx_power = "auto"}},
				}
				ucihelper.apply_config(resp, nil)
				assert_eq(db.wireless.radio0.txpower, nil,
					"stale fixed txpower deleted on revert to Auto")
			end)
		end
	},
	{
		name = "ucihelper: apply_config writes bss_load_update_period/openuf_iot (Force WiFi 4)",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", iot = true, qbssload = false},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_load_update_period, "0", "QBSS Load element suppressed")
				assert_eq(s.openuf_iot, "1", "WiFi-4-compat state recorded")
			end)
		end
	},
	{
		name = "ucihelper: apply_config omits the Force WiFi 4 options when the vap has neither",
		fn = function()
			with_ucihelper(function(db)
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, nil)
				local s = db.wireless.openuf_radio0_corp
				assert_eq(s.bss_load_update_period, nil, "no bss_load_update_period written")
				assert_eq(s.openuf_iot, nil, "no openuf_iot marker written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config disables a radio and its VAP, and round-trips it back",
		fn = function()
			with_ucihelper(function(db)
				ucihelper._uci.cursor():set("wireless", "radio0", "wifi-device")
				ucihelper.apply_config({
					radio_table = {{name = "radio0", disabled = true}},
					vap_table   = {{ssid = "net", radio = "radio0",
						security = "wpa2", x_passphrase = "hunter22", disabled = true}},
				}, nil)
				assert_eq(db.wireless.radio0.disabled, "1", "wifi-device disabled")
				assert_eq(db.wireless.openuf_radio0_net.disabled, "1", "wifi-iface disabled")
				-- The outbound radio_table/vap_table already read `disabled`
				-- off UCI, so the controller sees its own push reflected back.
				assert_true(ucihelper.get_radio_table()[1].disabled, "reported back as disabled")
			end)
		end
	},
	{
		name = "ucihelper: apply_config re-enables explicitly, but leaves UCI alone when unset",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "disabled", "1")

				-- nil means "the wire did not say" -- a radio the user disabled
				-- by hand must survive a push that never mentions status.
				ucihelper.apply_config({radio_table = {{name = "radio0", channel = 6}},
					vap_table = {}}, nil)
				assert_eq(db.wireless.radio0.disabled, "1", "untouched when disabled is nil")

				-- An explicit enabled must clear it, or a radio could never be
				-- switched back on from the controller.
				ucihelper.apply_config({radio_table = {{name = "radio0", disabled = false}},
					vap_table = {}}, nil)
				assert_eq(db.wireless.radio0.disabled, "0", "explicit enable clears it")
			end)
		end
	},
	{
		name = "ucihelper: an applied htmode round-trips back out via get_radio_table().ht",
		fn = function()
			-- radio_table[].ht is what build_json turns into the outbound
			-- spectrum_table width. Before ieee_mode was parsed, openUF only
			-- ever echoed a width it had never applied.
			with_ucihelper(function()
				-- The wifi-device section already exists on a real device;
				-- rf_config only mutates it.
				ucihelper._uci.cursor():set("wireless", "radio0", "wifi-device")
				local resp = {
					vap_table = {},
					radio_table = {{name = "radio0", htmode = "HT40", channel = 6}},
				}
				ucihelper.apply_config(resp, nil)
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].ht, "HT40", "applied htmode reported back as ht")
			end)
		end
	},
	{
		name = "ucihelper: use_only_unifi_wlan disables hand-configured SSIDs, not openuf_ ones",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "default_radio0", "wifi-iface")
				cursor:set("wireless", "default_radio0", "ssid", "MyOwnWiFi")
				local resp = {
					radio_table = {},
					vap_table = {
						{ssid = "corp", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22"},
					},
				}
				ucihelper.apply_config(resp, {config = {use_only_unifi_wlan = true}})
				assert_eq(db.wireless.default_radio0.disabled, "1", "user SSID disabled")
				assert_eq(db.wireless.default_radio0.openuf_autodisabled, "1", "and stamped")
				assert_eq(db.wireless.openuf_radio0_corp.disabled, nil,
					"openUF's own vap is never disabled")
			end)
		end
	},
	{
		name = "ucihelper: use_only_unifi_wlan=false leaves hand-configured SSIDs alone",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "default_radio0", "wifi-iface")
				cursor:set("wireless", "default_radio0", "ssid", "MyOwnWiFi")
				ucihelper.apply_config({radio_table = {}, vap_table = {}},
					{config = {use_only_unifi_wlan = false}})
				assert_eq(db.wireless.default_radio0.disabled, nil, "left untouched")
			end)
		end
	},
	{
		name = "ucihelper: turning use_only_unifi_wlan off re-enables only what openUF disabled",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "mine", "wifi-iface")
				cursor:set("wireless", "theirs", "wifi-iface")
				-- An SSID the user disabled themselves: never stamped, so it
				-- must not be switched back on behind their back.
				cursor:set("wireless", "theirs", "disabled", "1")

				ucihelper.set_wlan_exclusive(true)
				assert_eq(db.wireless.mine.disabled, "1", "ours disabled")
				assert_eq(db.wireless.theirs.openuf_autodisabled, nil,
					"already-disabled SSID not stamped")

				ucihelper.set_wlan_exclusive(false)
				assert_eq(db.wireless.mine.disabled, "0", "re-enabled")
				assert_eq(db.wireless.theirs.disabled, "1",
					"user's own disabled SSID stays disabled")
			end)
		end
	},
	{
		name = "ucihelper: a missing cfg is treated as use_only_unifi_wlan=false",
		fn = function()
			with_ucihelper(function(db)
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "default_radio0", "wifi-iface")
				ucihelper.apply_config({radio_table = {}, vap_table = {}}, nil)
				assert_eq(db.wireless.default_radio0.disabled, nil,
					"no cfg threaded through -- must not disable a stranger's SSID")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table echoes minrssi_enabled/minrssi_rssi as raw UCI values",
		fn = function()
			with_ucihelper(function(db)
				local uci = ucihelper._uci
				local cursor = uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "channel", "6")
				cursor:set("wireless", "radio0", "minrssi_enabled", "1")
				cursor:set("wireless", "radio0", "minrssi_rssi", "15")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "channel", "36")
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].min_rssi_enabled, true, "radio0 minrssi enabled")
				assert_eq(radios[1].min_rssi_raw, 15, "radio0 minrssi raw wire value")
				assert_eq(radios[2].min_rssi_enabled, false, "radio1 minrssi not enabled")
				assert_eq(radios[2].min_rssi_raw, nil, "radio1 has no minrssi_rssi set")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table reports only the modelmap's hwassign radios",
		fn = function()
			with_ucihelper(function()
				seed_radios({"radio0", "radio1", "radio2"})
				local all = ucihelper.get_radio_table()
				assert_eq(#all, 3, "no hwassign -> every wifi-device is reported")
				local some = ucihelper.get_radio_table({"radio0", "radio1"})
				assert_eq(#some, 2, "hwassign filters the report")
				assert_eq(some[1].name, "radio0", "kept radio0")
				assert_eq(some[2].name, "radio1", "kept radio1")
				assert_eq(#ucihelper.get_radio_table({}), 3,
					"empty hwassign means unset, not 'report nothing'")
			end)
		end
	},
	{
		name = "ucihelper: rf_config refuses to create a radio this device does not have",
		fn = function()
			with_ucihelper(function(db)
				seed_radios({"radio0"})
				-- Every rf_config write is a cursor:set on a named section,
				-- which in UCI CREATES it. A controller naming a phy we don't
				-- have (stale device record, config cloned off another AP, a
				-- model whose radio count differs from the real hardware)
				-- would otherwise materialize a phantom wifi-device that no
				-- driver backs -- and get_radio_table would then report it
				-- back as a real radio, forever.
				local ok = ucihelper.rf_config("radio7", "HT20", 11, 20)
				assert_eq(ok, false, "reports the refusal to its caller")
				assert_nil(db.wireless.radio7, "no phantom section created")
				assert_true(ucihelper.rf_config("radio0", "HT20", 11, 20) ~= false,
					"a radio that exists is still configured")
				assert_eq(db.wireless.radio0.channel, "11", "real radio written")
			end)
		end
	},
	{
		name = "ucihelper: apply_config skips unknown radios but still applies known ones",
		fn = function()
			with_ucihelper(function(db)
				seed_radios({"radio0"})
				ucihelper.apply_config({
					vap_table = {},
					radio_table = {
						{name = "radio9", htmode = "HT20", channel = 1},
						{name = "radio0", htmode = "HT40", channel = 11},
					},
				}, nil)
				assert_nil(db.wireless.radio9, "unknown radio ignored")
				assert_eq(db.wireless.radio0.htmode, "HT40",
					"one bad entry does not abort the rest of the push")
			end)
		end
	},
	{
		name = "ucihelper: phy_caps parses real iw phy output per band, not per Band index",
		fn = function()
			with_ucihelper(function()
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				local caps = ucihelper.phy_caps()
				assert_not_nil(caps.ng, "2.4GHz band recognized from its frequencies")
				assert_not_nil(caps.na, "5GHz band recognized from its frequencies")
				assert_eq(caps.ng.max_kind, 1, "ath9k 2.4GHz is HT-only")
				assert_eq(caps.ng.max_width, 40, "ath9k 2.4GHz tops out at HT40")
				assert_eq(caps.na.max_kind, 2, "ath10k 5GHz is VHT, not HE")
				assert_eq(caps.na.max_width, 80,
					"'neither 160 nor 80+80' must not be read as 160 support")
				assert_eq(caps.ng.max_txpower, 20, "2.4GHz max dBm")
				assert_eq(caps.na.max_txpower, 30, "5GHz max dBm across usable channels")
				assert_eq(tostring(caps.na.max_txpower), "30",
					"whole dBm, not the 30.0 float `iw` prints")
			end)
		end
	},
	{
		name = "ucihelper: rf_config writes the controller's regdomain to UCI",
		fn = function()
			with_ucihelper(function(db)
				seed_radios({"radio0"})
				ucihelper.rf_config("radio0", nil, 36, nil, nil, nil, nil, nil, "CZ")
				assert_eq(db.wireless.radio0.country, "CZ", "regdomain written")
			end)
		end
	},
	{
		name = "ucihelper: a regdomain change invalidates the cached driver capabilities",
		fn = function()
			with_ucihelper(function()
				-- Per-channel dBm limits are regdomain-derived, so max_txpower
				-- read under the old domain is stale the moment it changes.
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				seed_radios({"radio0"})
				ucihelper.phy_caps()
				assert_true(ucihelper._phy_caps_cache ~= nil, "capabilities cached")
				ucihelper.rf_config("radio0", nil, nil, nil, nil, nil, nil, nil, "CZ")
				assert_nil(ucihelper._phy_caps_cache, "cache dropped on a regdomain change")
			end)
		end
	},
	{
		name = "ucihelper: an unchanged regdomain does not churn the capability cache",
		fn = function()
			with_ucihelper(function()
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				seed_radios({"radio0"})
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "country", "CZ")
				ucihelper.phy_caps()
				ucihelper.rf_config("radio0", nil, 36, nil, nil, nil, nil, nil, "CZ")
				assert_true(ucihelper._phy_caps_cache ~= nil,
					"same country -> cache kept, no re-probe every push")
			end)
		end
	},
	{
		name = "ucihelper: rf_config skips beacon_rate on a driver that cannot set it",
		fn = function()
			with_ucihelper(function(db)
				-- hostapd does not ignore an unsupported beacon rate, it
				-- refuses to start the interface -- one option takes the whole
				-- band off the air. Real Archer C5 v1, 2.4GHz ath9k:
				--   nl80211: Driver does not support setting Beacon frame rate
				--   Failed to set beacon parameters
				--   Interface initialization failed
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				seed_radios({"radio1"})
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio1", "band", "2g")
				ucihelper.rf_config("radio1", nil, nil, nil, nil, nil,
					{basic_rate = {"1000"}, beacon_rate = 1000})
				assert_eq(db.wireless.radio1.basic_rate[1], "1000",
					"the rate floor itself still applies")
				assert_nil(db.wireless.radio1.beacon_rate,
					"beacon_rate withheld from a driver without BEACON_RATE_LEGACY")
			end)
		end
	},
	{
		name = "ucihelper: rf_config writes beacon_rate where the driver supports it",
		fn = function()
			with_ucihelper(function(db)
				ucihelper._popen = function() return IW_PHY_WITH_BEACON_RATE end
				seed_radios({"radio1"})
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio1", "band", "2g")
				ucihelper.rf_config("radio1", nil, nil, nil, nil, nil,
					{basic_rate = {"12000"}, beacon_rate = 12000})
				assert_eq(db.wireless.radio1.beacon_rate, "120",
					"written, and converted to hostapd's 100-kbps units")
			end)
		end
	},
	{
		name = "ucihelper: rf_config writes beacon_rate when capability is unknown",
		fn = function()
			with_ucihelper(function(db)
				-- No iw output: do what the controller asked rather than
				-- withhold config on a guess.
				ucihelper._popen = function() return "" end
				seed_radios({"radio1"})
				ucihelper.rf_config("radio1", nil, nil, nil, nil, nil,
					{basic_rate = {"12000"}, beacon_rate = 12000})
				assert_eq(db.wireless.radio1.beacon_rate, "120",
					"unknown capability -> unchanged behavior")
			end)
		end
	},
	{
		name = "ucihelper: 2.4GHz caps at 40MHz even on an HE radio",
		fn = function()
			-- An HE 2.4GHz radio is HE *and* 40MHz-only; the band has no
			-- 80MHz channel to widen into. Deriving the width from the PHY
			-- alone reported 80 here, and clamp_htmode only narrows to 40 for
			-- kind "HT", so a pushed HE80 reached hostapd unchanged -- which
			-- treats a width it cannot program as fatal and never starts the
			-- radio. Every earlier board was HT-only on 2.4GHz, so nothing
			-- could reach this until real 802.11ax hardware did.
			with_ucihelper(function()
				ucihelper._popen = function() return AX3000T_IW_PHY end
				local caps = ucihelper.phy_caps()
				assert_eq(caps.ng.max_kind, 3, "the 2.4GHz radio really is HE")
				assert_eq(caps.ng.max_width, 40, "and still tops out at 40MHz")
				assert_eq(ucihelper.clamp_htmode("ng", "HE80"), "HE40",
					"a wide 2.4GHz push is narrowed, not passed through")
				local out, requested = ucihelper.clamp_htmode("ng", "HE40")
				assert_eq(out, "HE40", "HE40 fits and is left alone")
				assert_nil(requested, "so nothing is reported as clamped")
			end)
		end
	},
	{
		name = "ucihelper: the 2.4GHz cap does not narrow 5GHz on the same board",
		fn = function()
			-- The cap is keyed on the band, not applied device-wide: this
			-- board's 5GHz radio is VHT160 and must stay that way.
			with_ucihelper(function()
				ucihelper._popen = function() return AX3000T_IW_PHY end
				local caps = ucihelper.phy_caps()
				assert_eq(caps.na.max_width, 160, "5GHz keeps its 160MHz")
				assert_eq(caps.na.max_kind, 3, "and its HE")
				assert_eq(ucihelper.clamp_htmode("na", "HE160"), "HE160",
					"an HE160 push on 5GHz is honoured")
				assert_eq(ucihelper.clamp_htmode("na", "HE80"), "HE80", "as is HE80")
			end)
		end
	},
	{
		name = "ucihelper: clamp_htmode drops HE/VHT the hardware cannot do",
		fn = function()
			with_ucihelper(function()
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				-- The whole point of the fix: openUF claims to be a WiFi-6
				-- U6-InWall, so an HE push at ath9k/ath10k is the expected
				-- case, not an edge case.
				assert_eq(ucihelper.clamp_htmode("na", "HE80"), "VHT80",
					"HE80 -> VHT80 on a VHT-only 5GHz radio")
				assert_eq(ucihelper.clamp_htmode("ng", "HE40"), "HT40",
					"HE40 -> HT40 on an HT-only 2.4GHz radio")
				assert_eq(ucihelper.clamp_htmode("ng", "VHT80"), "HT40",
					"width clamps too: no VHT and no 80MHz on 2.4GHz")
				assert_eq(ucihelper.clamp_htmode("na", "HE160"), "VHT80",
					"160MHz clamps to the radio's real 80MHz ceiling")
			end)
		end
	},
	{
		name = "ucihelper: clamp_htmode never widens or upgrades what was asked for",
		fn = function()
			with_ucihelper(function()
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				local hit, orig = ucihelper.clamp_htmode("na", "HT20")
				assert_eq(hit, "HT20", "a request below the ceiling is left alone")
				assert_nil(orig, "no clamp reported when nothing changed")
				assert_eq(ucihelper.clamp_htmode("na", "VHT40"), "VHT40", "VHT40 fits")
				assert_eq(ucihelper.clamp_htmode("na", "NOHT"), "NOHT",
					"non <PHY><width> values pass through untouched")
			end)
		end
	},
	{
		name = "ucihelper: clamp_htmode leaves the request alone when caps are unknown",
		fn = function()
			with_ucihelper(function()
				-- No `iw`, or output this parser doesn't understand: the
				-- controller's request must survive unmodified rather than be
				-- clamped to a guess.
				ucihelper._popen = function() return "" end
				assert_eq(ucihelper.clamp_htmode("na", "HE80"), "HE80",
					"unknown capability -> unchanged")
			end)
		end
	},
	{
		name = "ucihelper: rf_config writes the clamped htmode to UCI",
		fn = function()
			with_ucihelper(function(db)
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "band", "5g")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "band", "2g")
				ucihelper.rf_config("radio0", "HE80", 36)
				ucihelper.rf_config("radio1", "HE20", 6)
				assert_eq(db.wireless.radio0.htmode, "VHT80",
					"5GHz radio gets the clamped mode, not the pushed HE80")
				assert_eq(db.wireless.radio1.htmode, "HT20", "2.4GHz radio clamped to HT20")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table reports the driver's real max_txpower",
		fn = function()
			with_ucihelper(function()
				ucihelper._popen = function() return ARCHER_C5_IW_PHY end
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "band", "5g")
				cursor:set("wireless", "radio1", "wifi-device")
				cursor:set("wireless", "radio1", "band", "2g")
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].max_txpower, 30, "5GHz radio reports its own ceiling")
				assert_eq(radios[2].max_txpower, 20, "2.4GHz radio reports its own ceiling")
			end)
		end
	},
	{
		name = "ucihelper: get_radio_table falls back to the static max_txpower default",
		fn = function()
			with_ucihelper(function()
				local cursor = ucihelper._uci.cursor()
				cursor:set("wireless", "radio0", "wifi-device")
				cursor:set("wireless", "radio0", "band", "5g")
				local radios = ucihelper.get_radio_table()
				assert_eq(radios[1].max_txpower, ucihelper.RADIO_DEFAULTS.max_txpower,
					"no iw output -> documented default, not nil")
			end)
		end
	},
	{
		name = "ucihelper: kick_station issues a single hostapd_cli deauthenticate",
		fn = function()
			with_ucihelper(function(db)
				local calls = {}
				ucihelper._run_cmd = function(cmd) calls[#calls + 1] = cmd; return true end
				ucihelper.kick_station("wlan0", "aa:bb:cc:dd:ee:ff")
				assert_eq(#calls, 1, "exactly one command run")
				assert_true(calls[1]:find("hostapd_cli", 1, true) ~= nil, "uses hostapd_cli")
				assert_true(calls[1]:find("-i wlan0", 1, true) ~= nil, "targets the given interface")
				assert_true(calls[1]:find("deauthenticate aa:bb:cc:dd:ee:ff", 1, true) ~= nil,
					"deauthenticates the given mac")
			end)
		end
	},
	{
		name = "ucihelper: changing a WLAN's VLAN tears the old L2 down",
		fn = function()
			-- Confirmed live: moving the IoT network from VLAN 20 to 10 in
			-- the controller left br-openuf20 and its eth1.20 member behind
			-- on both APs -- a bridge with a tagged sub-device sitting on the
			-- trunk forever, and a running config that no longer matches what
			-- the controller asked for.
			with_ucihelper(function(db, cmds)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				local cfg = {net = {lan_cpueth = "eth1"}}
				local function push(vlan)
					return {radio_table = {}, vap_table = {
						{ssid = "iot", radio = "radio0", security = "wpa2",
						 x_passphrase = "hunter22", vlan_enabled = true, vlan = vlan}}}
				end

				ucihelper.apply_config(push(20), cfg)
				assert_not_nil(db.network.openuf_vlan20, "VLAN 20 L2 created")
				assert_not_nil(db.network.openuf_brdev20, "with its bridge")

				ucihelper.apply_config(push(10), cfg)
				assert_not_nil(db.network.openuf_vlan10, "VLAN 10 L2 created")
				assert_not_nil(db.network.openuf_brdev10, "with its bridge")
				assert_nil(db.network.openuf_vlan20, "VLAN 20 interface removed")
				assert_nil(db.network.openuf_brdev20, "VLAN 20 bridge removed")
			end)
		end
	},
	{
		name = "ucihelper: removing the last tagged WLAN removes its VLAN L2",
		fn = function()
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "br_lan", "device")
				c:set("network", "br_lan", "name", "br-lan")
				local cfg = {net = {lan_cpueth = "eth1"}}
				ucihelper.apply_config({radio_table = {}, vap_table = {
					{ssid = "iot", radio = "radio0", security = "wpa2",
					 x_passphrase = "hunter22", vlan_enabled = true, vlan = 20}}}, cfg)
				assert_not_nil(db.network.openuf_vlan20, "created")

				-- The WLAN is gone; an untagged one remains.
				ucihelper.apply_config({radio_table = {}, vap_table = {
					{ssid = "home", radio = "radio0", security = "wpa2",
					 x_passphrase = "hunter22"}}}, cfg)
				assert_nil(db.network.openuf_vlan20, "interface torn down")
				assert_nil(db.network.openuf_brdev20, "bridge torn down")
			end)
		end
	},
	{
		name = "ucihelper: the prune never touches a hand-made VLAN interface",
		fn = function()
			with_ucihelper(function(db)
				local c = ucihelper._uci.cursor()
				c:set("network", "iot_vlan99", "interface")
				c:set("network", "iot_vlan99", "device", "br-iot99")
				ucihelper.prune_vlan_networks({})
				assert_not_nil(db.network.iot_vlan99,
					"only openuf_-prefixed sections are ever deleted")
			end)
		end
	},
}
