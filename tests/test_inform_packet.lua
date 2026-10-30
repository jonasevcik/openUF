-- Tests for openuf/inform.lua (TNBU binary packet framing).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
dofile("openuf/lib/lib.lua")	-- needed by announce (loaded by inform)

local crypto = dofile("openuf/crypto.lua")
local state  = dofile("openuf/state.lua")
local inform = dofile("openuf/inform.lua")
local cjson  = require("cjson")

-- Redirect state file to /tmp so handle_response tests don't need /etc/openuf
inform._state._state_file = "/tmp/openuf_test_inform.json"

-- Stub firewall by default so tests don't shell out to real nft/hostapd_cli;
-- individual block-sta/unblock-sta tests below override this to capture calls.
inform._firewall = {
	reconcile = function() end,
	deauth = function() end,
	hostapd_sockets = function() return "" end, deny_sync = function() return false end,
}
-- Same for the controller's L2 hardening (nft) and system settings (UCI
-- system, root's crontab); the tests that exercise them stub their own.
inform._l2guard = {reconcile = function() return 0 end,
	parse = function() return nil end, spec_from = function() return {} end}
inform._sysconf = {parse = function() return nil end, apply = function() return {} end,
	apply_cron = function() return false end}
-- And the guest portal (nft, a listening socket); guest tests stub their own.
inform._guestportal._exec = function() return 0 end
inform._guestportal.listen = function() return {close = function() end} end

-- Deterministic IV for the TEST FILE's own crypto instance -- affects only
-- tests that call crypto.* directly (e.g. the zlib round-trip). inform's
-- packet paths use inform._crypto, a SEPARATE instance: tests that need a
-- pinned IV inside build_packet must stub inform._crypto._random_bytes
-- (see "different authkeys produce different ciphertext").
local FIXED_IV = string.rep("\0", 16)
crypto._random_bytes = function(n) return string.rep("\0", n) end

-- A device with two SSIDs on radio0 (the second one VLAN-tagged, so netifd
-- also lists its VLAN netdev) and one on radio1, as ucihelper.ap_ifnames
-- reports it.
local function bss_mock()
	return {
		ap_ifnames = function()
			return {"phy0-ap0", "phy0-ap1", "phy0-ap1.10", "phy1-ap0"}
		end,
		bss_ifname = function(n) if n == "phy0-ap1.10" then return "phy0-ap1" end return n end,
	}
end

-- Minimal state for packet building
local function sample_state(overrides)
	local st = {
		authkey    = state.DEFAULT_KEY,
		adopted    = false,
		cfgversion = "",
		inform_url = "http://10.0.0.1:8080/inform",
		mac        = "aa:bb:cc:dd:ee:ff",
		ip         = "192.168.1.100",
		hostname   = "testap",
	}
	if overrides then
		for k, v in pairs(overrides) do st[k] = v end
	end
	return st
end

-- Fresh ucihelper instance wired to an in-memory mock UCI cursor, for
-- parse -> apply_config integration tests (same mock shape as
-- test_ucihelper.lua's, including option-level delete and cursor:get).
-- Returns the ucihelper module and the backing db table.
local function new_apply_env()
	local ucihelper = dofile("openuf/ucihelper.lua")
	local db = {}
	local section_order = {}
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
		if b == nil then db[config][section][".type"] = a
		elseif type(b) == "table" then
			-- Real libuci stringifies list elements; mirror it (see
			-- test_ucihelper.lua's mock for the rationale).
			local list = {}
			for i, v in ipairs(b) do list[i] = tostring(v) end
			db[config][section][a] = list
		else db[config][section][a] = b end
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
		return s and s[option]
	end
	function cursor:commit() end

	ucihelper._uci       = {cursor = function() return cursor end}
	ucihelper._popen     = function() return "" end
	ucihelper._read_file = function() return nil end
	ucihelper._run_cmd   = function() return true end
	-- The wifi-device sections a real /etc/config/wireless always has. Radio
	-- config is refused for a radio with no section (writing one would create
	-- a phantom radio no driver backs), and the controller's radio names are
	-- echoes of phynames openUF read out of UCI in the first place -- so an
	-- apply-path environment without radios is a state hardware never reaches.
	cursor:set("wireless", "radio0", "wifi-device")
	cursor:set("wireless", "radio1", "wifi-device")
	return ucihelper, db
end

-- Capture what fn() writes to stderr, restoring the real handle afterwards.
-- Drive _parse_wifi_system_cfg with a known set of per-band PHY capabilities.
-- Without this every ieee_mode test would silently exercise only the
-- hardware-unknown fallback and prove nothing about the upgrade.
-- `caps` is {ng = "HE", na = "EHT", ...}, the string "any" for a stub that
-- answers the same PHY for every band it is asked about (so a test cannot
-- pass merely because the lookup key missed), or nil for "hardware unknown"
-- -- which is what the dev machine really is, there being no `iw` here.
local function with_best_phy(caps, fn)
	-- Swapped wholesale rather than patched: other tests in this file leave
	-- inform._ucihelper nil behind them, which is also the shape the parser
	-- has to survive.
	local orig = inform._ucihelper
	inform._ucihelper = {best_phy = function(band)
		if caps == "any" then return "EHT" end
		return caps and caps[band] or nil
	end}
	local ok, out = pcall(fn)
	inform._ucihelper = orig
	if not ok then error(out, 2) end
	return out
end

local function with_stderr(fn)
	local buf = {}
	local real = io.stderr
	io.stderr = {write = function(_, s) buf[#buf + 1] = s end}
	local ok, err = pcall(fn)
	io.stderr = real
	if not ok then error(err, 0) end
	return table.concat(buf)
end

-- tools/cfg-coverage.lua: the key-coverage sweep over a captured push. Loaded
-- as a module (its script half is gated on arg[0]), so the tests below drive
-- M.analyse/M.format directly with their own parser sets where a synthetic one
-- pins the probe design, and with openUF's real ones where the point is what
-- openUF does.
local cfgcov = dofile("tools/cfg-coverage.lua")

local function real_parsers()
	return cfgcov.parsers(inform, {
		sysconf     = inform._sysconf,
		l2guard     = inform._l2guard,
		guestportal = inform._guestportal,
		airtime     = inform._airtime,
	})
end

local MAGIC = "TNBU"

-- Parse header fields from a raw TNBU packet for assertions
local function parse_header(raw)
	local function u32(s, off)
		local b1,b2,b3,b4 = string.byte(s, off, off+3)
		return ((b1 or 0)*16777216) + ((b2 or 0)*65536) + ((b3 or 0)*256) + (b4 or 0)
	end
	local function u16(s, off)
		local hi, lo = string.byte(s, off, off+1)
		return (hi or 0)*256 + (lo or 0)
	end
	return {
		magic        = raw:sub(1, 4),
		pkt_version  = u32(raw, 5),
		mac          = raw:sub(9, 14),
		flags        = u16(raw, 15),
		iv           = raw:sub(17, 32),
		data_version = u32(raw, 33),
		payload_len  = u32(raw, 37),
		payload      = raw:sub(41),
	}
end

return {
	{
		name = "inform packet: magic is TNBU",
		fn = function()
			local st = sample_state()
			local pkt = inform.build_packet('{"_type":"state"}', st)
			local h = parse_header(pkt)
			assert_eq(h.magic, MAGIC, "magic bytes")
		end
	},
	{
		name = "inform packet: packet version is 1",
		fn = function()
			local pkt = inform.build_packet('{"_type":"state"}', sample_state())
			local h = parse_header(pkt)
			assert_eq(h.pkt_version, 1, "packet version")
		end
	},
	{
		name = "inform packet: data version is 1",
		fn = function()
			local pkt = inform.build_packet('{"_type":"state"}', sample_state())
			local h = parse_header(pkt)
			assert_eq(h.data_version, 1, "data version")
		end
	},
	{
		name = "inform packet: MAC bytes match state.mac",
		fn = function()
			local st = sample_state({mac = "aa:bb:cc:dd:ee:ff"})
			local pkt = inform.build_packet('{"_type":"state"}', st)
			local h = parse_header(pkt)
			assert_eq(string.byte(h.mac, 1), 0xaa, "MAC byte 1")
			assert_eq(string.byte(h.mac, 2), 0xbb, "MAC byte 2")
			assert_eq(string.byte(h.mac, 3), 0xcc, "MAC byte 3")
			assert_eq(string.byte(h.mac, 4), 0xdd, "MAC byte 4")
			assert_eq(string.byte(h.mac, 5), 0xee, "MAC byte 5")
			assert_eq(string.byte(h.mac, 6), 0xff, "MAC byte 6")
		end
	},
	{
		name = "inform packet: CBC flag 0x01 is set",
		fn = function()
			local pkt = inform.build_packet('{"_type":"state"}', sample_state())
			local h = parse_header(pkt)
			assert_true(h.flags % 2 ~= 0, "encrypted flag set")
		end
	},
	{
		name = "inform packet: IV field is 16 bytes in packet",
		fn = function()
			local pkt = inform.build_packet('{"_type":"state"}', sample_state())
			local h = parse_header(pkt)
			assert_eq(#h.iv, 16, "IV length in packet")
		end
	},
	{
		name = "inform packet: payload length field matches actual payload bytes",
		fn = function()
			local pkt = inform.build_packet('{"_type":"state"}', sample_state())
			local h = parse_header(pkt)
			assert_eq(h.payload_len, #h.payload, "payload_len matches actual payload")
		end
	},
	{
		name = "inform packet: total packet length is header (40) + payload",
		fn = function()
			local json = '{"_type":"state"}'
			local pkt = inform.build_packet(json, sample_state())
			local h = parse_header(pkt)
			assert_eq(#pkt, 40 + h.payload_len, "total length = 40 + payload_len")
		end
	},
	{
		name = "inform packet: round-trip build + parse returns original JSON",
		fn = function()
			local json = '{"_type":"state","x":42}'
			local st = sample_state()
			local pkt = inform.build_packet(json, st)
			local recovered, _ = inform.parse_packet(pkt, st)
			-- parse_packet unpads PKCS7 exactly, so the round-trip is
			-- byte-identical -- pin it. (A substring check here would pass
			-- for any implementation returning garbage around the payload.)
			assert_eq(recovered, json, "round-trip is byte-identical")
		end
	},
	{
		name = "inform packet: parse raises error on wrong magic",
		fn = function()
			local st = sample_state()
			local pkt = inform.build_packet('{"_type":"state"}', st)
			-- Corrupt the magic
			local corrupted = "XXXX" .. pkt:sub(5)
			assert_error(function()
				inform.parse_packet(corrupted, st)
			end, "bad magic raises error")
		end
	},
	{
		name = "inform packet: parse raises error on short packet",
		fn = function()
			assert_error(function()
				inform.parse_packet("TNBU\0\0\0", sample_state())
			end, "short packet raises error")
		end
	},
	{
		name = "inform packet: different authkeys produce different ciphertext",
		fn = function()
			-- The IV must be pinned via inform's OWN crypto instance
			-- (inform._crypto): the file-top _random_bytes stub lives on the
			-- test file's separate crypto dofile and never reaches
			-- build_packet. Before this seam existed, the two packets always
			-- differed merely because each got a fresh random IV -- a
			-- hardcoded key inside build_packet passed this test.
			local orig_rand = inform._crypto._random_bytes
			inform._crypto._random_bytes = function(n) return string.rep("\0", n) end
			local json = '{"_type":"state"}'
			local st1 = sample_state({authkey = state.DEFAULT_KEY})
			local st2 = sample_state({authkey = "ffffffffffffffffffffffffffffffff"})
			local ok, err = pcall(function()
				local pkt1 = inform.build_packet(json, st1)
				local pkt2 = inform.build_packet(json, st2)
				assert_eq(pkt1:sub(1, 40), pkt2:sub(1, 40),
					"identical headers (incl. the pinned IV) -- only the key can differ")
				assert_neq(pkt1:sub(41), pkt2:sub(41),
					"ciphertexts differ with different keys under an identical IV")
			end)
			inform._crypto._random_bytes = orig_rand
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: handle_response noop returns false",
		fn = function()
			local st = sample_state()
			local result = inform.handle_response('{"_type":"noop"}', st)
			assert_false(result, "noop returns false")
		end
	},
	{
		name = "inform packet: handle_response setparam updates inform_url from key=value string",
		fn = function()
			local st = sample_state()
			-- Real controller sends mgmt_cfg as newline-delimited key=value string.
			-- Use \\n so the Lua literal contains \n (JSON newline escape).
			local resp = '{"_type":"setparam","mgmt_cfg":"inform_url=http://1.2.3.4:8080/inform\\nuse_aes_gcm=false\\ncfgversion=2\\n"}'
			inform.handle_response(resp, st)
			assert_contains(st.inform_url, "1.2.3.4", "inform_url updated from inform_url")
		end
	},
	{
		name = "inform packet: handle_response setparam does NOT update inform_url from mgmt_url",
		fn = function()
			-- Confirmed live against a real controller (2026-07-14): mgmt_url is
			-- the web UI deep link (https://host:8443/manage/site/default), not
			-- an inform endpoint -- conflating the two broke the device's own
			-- inform loop on the very next routine setparam cycle after adoption.
			local st = sample_state()
			local orig_url = st.inform_url
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=https://1.2.3.4:8443/manage/site/default\\nuse_aes_gcm=false\\n"}'
			inform.handle_response(resp, st)
			assert_eq(st.inform_url, orig_url, "inform_url unchanged by mgmt_url")
		end
	},
	{
		name = "inform packet: handle_response setparam applies authkey and adopts when not yet adopted",
		fn = function()
			-- Real L3 adoption has no SSH step at all -- the controller delivers
			-- the new key via mgmt_cfg.authkey instead (confirmed against
			-- amd989/unifi-gateway and live testing; see PROTOCOL-VALIDATION.md).
			local st = sample_state({adopted = false})
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nauthkey=deadbeefdeadbeefdeadbeefdeadbeef\\n"}'
			local result = inform.handle_response(resp, st)
			assert_eq(st.authkey, "deadbeefdeadbeefdeadbeefdeadbeef", "authkey updated from mgmt_cfg")
			assert_true(st.adopted, "adopted set to true")
			assert_true(result, "re-inform triggered immediately with the new key")
		end
	},
	{
		name = "inform packet: handle_response setparam ignores authkey once already adopted",
		fn = function()
			-- Once adopted, only SSH set-adopt may rotate the key -- matches
			-- real L2 hardware behavior and preserves the original security
			-- invariant for already-adopted devices.
			local st = sample_state({adopted = true})
			local orig_key = st.authkey
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nauthkey=deadbeefdeadbeefdeadbeefdeadbeef\\n"}'
			inform.handle_response(resp, st)
			assert_eq(st.authkey, orig_key, "authkey NOT updated via setparam once adopted")
		end
	},
	{
		name = "inform packet: handle_response setparam ignores malformed authkey",
		fn = function()
			local st = sample_state({adopted = false})
			local orig_key = st.authkey
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nauthkey=not-32-hex-chars\\n"}'
			inform.handle_response(resp, st)
			assert_eq(st.authkey, orig_key, "malformed authkey rejected, key unchanged")
			assert_false(st.adopted, "not marked adopted on malformed authkey")
		end
	},
	{
		name = "inform packet: handle_response setparam sets use_gcm from mgmt_cfg",
		fn = function()
			local st = sample_state()
			assert_false(st.use_gcm or false, "use_gcm starts false")
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nuse_aes_gcm=true\\n"}'
			inform.handle_response(resp, st)
			assert_true(st.use_gcm, "use_gcm set to true from mgmt_cfg")
		end
	},
	{
		name = "inform packet: handle_response setparam sets st.led_enabled from mgmt_cfg",
		fn = function()
			local st = sample_state()
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nled_enabled=false\\n"}'
			inform.handle_response(resp, st)
			assert_false(st.led_enabled, "led_enabled set to false from mgmt_cfg")
		end
	},
	{
		name = "inform packet: handle_response setparam led_enabled drives led.set_enabled",
		fn = function()
			local st = sample_state()
			local writes = {}
			local orig = inform._led._write_file
			inform._led._write_file = function(path, contents)
				writes[#writes + 1] = {path = path, contents = contents}
				return true
			end
			local cfg = {led = "/sys/class/leds/test"}
			local resp = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://x:8080/inform\\nled_enabled=false\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._led._write_file = orig
			assert_eq(#writes, 2, "two sysfs writes")
			assert_eq(writes[2].path, "/sys/class/leds/test/brightness", "brightness path")
			assert_eq(writes[2].contents, "0", "brightness off for led_enabled=false")
		end
	},
	{
		name = "inform packet: handle_response system_cfg atf.mode drives airtime and st.atf_enabled",
		fn = function()
			-- Captured on 10.4.57 2026-09-27 with wifi_caps 0x2C claimed and
			-- the device's atf_enabled switched off over REST.
			local calls = {}
			local orig = inform._airtime.set_enabled
			inform._airtime.set_enabled = function(on) calls[#calls + 1] = on; return 2, 2 end
			local function push(st, sys_cfg)
				local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
				inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			end
			local ok, err = pcall(function()
				local st = sample_state()
				push(st, "mgmt.x=1\n# airtime fairness\natf.status=enabled\natf.mode=disabled\n")
				assert_eq(#calls, 1, "one airtime write")
				assert_false(calls[1], "switched off")
				assert_false(st.atf_enabled, "persisted as false, not nil")
				push(st, "atf.status=enabled\natf.mode=enabled\n")
				assert_true(calls[2], "switched back on")
				assert_true(st.atf_enabled, "persisted as true")
				-- A push without the block leaves the setting alone.
				push(st, "mgmt.x=1\n")
				assert_eq(#calls, 2, "no write without an atf block")
				assert_true(st.atf_enabled, "setting kept")
			end)
			inform._airtime.set_enabled = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: startup reapplies a pushed ATF setting, never an unpushed one",
		fn = function()
			-- debugfs resets to on at reboot, and a matching cfgversion
			-- means the controller does not push again.
			local calls = {}
			local orig = inform._airtime.set_enabled
			inform._airtime.set_enabled = function(on) calls[#calls + 1] = on end
			local r_off = inform._reapply_airtime(sample_state({atf_enabled = false}))
			local r_nil = inform._reapply_airtime(sample_state())
			inform._airtime.set_enabled = orig
			assert_true(r_off, "reapplied")
			assert_eq(#calls, 1, "exactly one write")
			assert_false(calls[1], "the stored off")
			assert_false(r_nil, "never pushed: the board's default stays")
		end
	},
	{
		name = "inform packet: forgetting the controller turns airtime fairness back on",
		fn = function()
			local calls = {}
			local orig = inform._airtime.set_enabled
			inform._airtime.set_enabled = function(on) calls[#calls + 1] = on end
			inform._forget_controller()
			inform._airtime.set_enabled = orig
			assert_eq(#calls, 1, "one write")
			assert_true(calls[1], "back to mac80211's default")
		end
	},
	{
		name = "inform packet: handle_response derives band_steering_active from vap_table.no2ghz_oui and drives usteer",
		fn = function()
			local st = sample_state()
			local captured_enabled, captured_cfg
			local orig = inform._usteer.set_enabled
			inform._usteer.set_enabled = function(enabled, cfg)
				captured_enabled, captured_cfg = enabled, cfg
			end
			local applied_opts
			inform._ucihelper = {
				apply_config = function(_, _, opts) applied_opts = opts end,
			}
			local cfg = {net = {lan_cpueth = "eth0"}}
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.no2ghz_oui=enabled\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, cfg)
			inform._usteer.set_enabled = orig
			inform._ucihelper = nil
			assert_true(captured_enabled, "usteer.set_enabled(true, ...) called -- a vap has no2ghz_oui enabled")
			assert_eq(captured_cfg, cfg, "cfg passed through to usteer.set_enabled")
			assert_true(applied_opts.band_steering_active, "band_steering_active threaded through to apply_config")
		end
	},
	{
		name = "inform packet: handle_response derives band_steering_active=false when no vap has no2ghz_oui",
		fn = function()
			local st = sample_state()
			local captured_enabled
			local orig = inform._usteer.set_enabled
			inform._usteer.set_enabled = function(enabled) captured_enabled = enabled end
			local applied_opts
			inform._ucihelper = {
				apply_config = function(_, _, opts) applied_opts = opts end,
			}
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			inform._usteer.set_enabled = orig
			inform._ucihelper = nil
			assert_false(captured_enabled, "usteer.set_enabled(false, ...) called -- no vap has no2ghz_oui")
			assert_false(applied_opts.band_steering_active, "band_steering_active false")
		end
	},
	{
		name = "inform packet: handle_response setparam applies static IP from system_cfg",
		fn = function()
			local st = sample_state()
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			-- Real captured shape (PROTOCOL-VALIDATION.md): system_cfg is a
			-- flat OpenWrt-UCI-style blob, separate from mgmt_cfg. Static is
			-- signalled by the ABSENCE of dhcpc.1.* keys, not an explicit flag.
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50\\n'
				.. 'netconf.1.netmask=255.255.255.0\\nroute.1.gateway=172.19.0.1\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._netconfig._exec = orig
			assert_eq(st.ip_mode, "static", "ip_mode recorded as static")
			assert_eq(st.static_ip, "172.19.0.50", "static_ip recorded")
			assert_eq(st.static_gateway, "172.19.0.1", "static_gateway recorded")
			assert_eq(st.ip, "172.19.0.50", "st.ip synced to the new static address")
			assert_eq(#cmds, 3, "three shell commands (flush, add, route)")
			assert_contains(cmds[2], "172.19.0.50/24 dev eth0", "correct interface and address")
		end
	},
	{
		-- Found in the validation lab 2026-09-10: usteer raised partway through
		-- handle_response, the AP moved to its pushed static address, and
		-- state.json never learned about it. _tick pcalls handle_response by
		-- design, so the error cost one log line -- but the startup reapply
		-- reads exactly these fields, so the address was unrecoverable after a
		-- reboot. The record has to be written as soon as the interface is
		-- changed, not after another 350 lines of shelling out.
		name = "inform packet: handle_response persists IP settings before the WiFi pass can raise",
		fn = function()
			local st = sample_state()
			local saved = nil
			local orig_save, orig_exec = inform._state.save, inform._netconfig._exec
			local orig_uci = inform._ucihelper
			inform._netconfig._exec = function() return true end
			inform._state.save = function(t)
				-- snapshot, so a later save cannot mask an earlier omission
				saved = {ip_mode = t.ip_mode, static_ip = t.static_ip,
					static_netmask = t.static_netmask, static_gateway = t.static_gateway}
			end
			-- Everything after the IP branch blows up, the way usteer did.
			inform._ucihelper = setmetatable({
				begin_pass = function() end, end_pass = function() end,
				apply_config = function() error("boom: anything downstream can raise") end,
			}, {__index = orig_uci})

			local cfg = {net = {lan_cpueth = "eth0"}, config = {}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50\\n'
				.. 'netconf.1.netmask=255.255.255.0\\nroute.1.gateway=172.19.0.1\\n'
				.. 'aaa.1.ssid=x\\nwireless.1.ssid=x\\nwireless.1.parent=radio0\\n"}'
			local ok = pcall(inform.handle_response, resp, st, cfg)

			inform._state.save, inform._netconfig._exec = orig_save, orig_exec
			inform._ucihelper = orig_uci

			assert_false(ok, "the downstream failure really did raise")
			assert_true(saved ~= nil, "state was saved anyway, before the raise")
			assert_eq(saved.ip_mode, "static", "ip_mode reached disk")
			assert_eq(saved.static_ip, "172.19.0.50", "static_ip reached disk")
			assert_eq(saved.static_gateway, "172.19.0.1", "static_gateway reached disk")
		end
	},
	{
		name = "inform packet: handle_response setparam applies dhcp from system_cfg",
		fn = function()
			local st = sample_state({ip_mode = "static", static_ip = "172.19.0.50"})
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.2\\n'
				.. 'dhcpc.1.status=enabled\\ndhcpc.1.devname=br0\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._netconfig._exec = orig
			assert_eq(st.ip_mode, "dhcp", "ip_mode recorded as dhcp")
			assert_eq(st.static_ip, nil, "static_ip cleared on dhcp")
			assert_contains(cmds[2], "udhcpc -i eth0", "udhcpc invoked on the right interface")
		end
	},
	{
		-- A2: the static address is `ip addr` state only, so it dies with the
		-- reboot, and cfgversion matching means the controller replies noop and
		-- never re-pushes it. Without the startup reapply the device silently
		-- comes back on the board's own boot config.
		name = "inform packet: _reapply_static_ip reapplies a persisted static address at startup",
		fn = function()
			local st = sample_state({
				ip_mode        = "static",
				static_ip      = "172.19.0.50",
				static_netmask = "255.255.255.0",
				static_gateway = "172.19.0.1",
			})
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local ok = inform._reapply_static_ip(st, {net = {lan_cpueth = "eth0"}})
			inform._netconfig._exec = orig
			assert_true(ok, "reapply reports success")
			assert_eq(#cmds, 3, "three shell commands (flush, add, route)")
			assert_contains(cmds[1], "ip addr flush dev eth0", "flushes the right interface")
			assert_contains(cmds[2], "172.19.0.50/24 dev eth0", "restores address and prefix")
			assert_contains(cmds[3], "172.19.0.1", "restores the default route")
		end
	},
	{
		name = "inform packet: _reapply_static_ip restores the pushed DNS servers too",
		fn = function()
			local st = sample_state({
				ip_mode    = "static",
				static_ip  = "172.19.0.50",
				static_dns = {"1.1.1.1", "9.9.9.9"},
			})
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			inform._reapply_static_ip(st, {net = {lan_cpueth = "eth0"}})
			inform._netconfig._exec = orig
			local resolv = cmds[#cmds]
			assert_contains(resolv, "nameserver 1.1.1.1", "primary nameserver restored")
			assert_contains(resolv, "nameserver 9.9.9.9", "secondary nameserver restored")
		end
	},
	{
		-- The board's own boot config already handles DHCP, and flushing to
		-- re-lease is the destructive no-op handle_response guards against.
		name = "inform packet: _reapply_static_ip does nothing on dhcp or when never pushed",
		fn = function()
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			assert_false(inform._reapply_static_ip(sample_state({ip_mode = "dhcp"}), cfg),
				"dhcp mode does not reapply")
			assert_false(inform._reapply_static_ip(sample_state(), cfg),
				"never-pushed IP Settings does not reapply")
			assert_false(inform._reapply_static_ip(
				sample_state({ip_mode = "static"}), cfg),
				"static mode with no recorded address does not reapply")
			inform._netconfig._exec = orig
			assert_eq(#cmds, 0, "no interface was touched in any of the three cases")
		end
	},
	{
		name = "inform packet: handle_response reads dhcpc.1.status=disabled as static, not DHCP",
		fn = function()
			-- The key's mere presence used to set dhcp=true regardless of its
			-- value: a dhcpc.1.status=disabled alongside netconf.1.ip would
			-- have misread a static push as DHCP and flushed the working
			-- static address. Defensive -- every capture so far carries
			-- =enabled, and a static push may simply omit the key (the test
			-- above) -- but the fix is correct under either wire shape.
			local st = sample_state()
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50\\n'
				.. 'netconf.1.netmask=255.255.255.0\\nroute.1.gateway=172.19.0.1\\n'
				.. 'dhcpc.1.status=disabled\\ndhcpc.1.devname=br0\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._netconfig._exec = orig
			assert_eq(st.ip_mode, "static", "explicitly disabled dhcpc -> static path")
			assert_eq(st.static_ip, "172.19.0.50", "static address applied")
		end
	},
	{
		name = "inform packet: handle_response setparam does NOT flush dhcp on first contact",
		fn = function()
			-- A fresh device's very first system_cfg (and every steady-state
			-- reaffirmation) also carries dhcpc.1.status=enabled, but there's
			-- no prior static config to revert -- calling apply_dhcp here
			-- would needlessly (and, without a real DHCP server to grant a
			-- new lease, destructively) flush a working address. Confirmed
			-- live: this exact scenario stranded the validation container.
			local st = sample_state()  -- ip_mode starts nil, never "static"
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.2\\n'
				.. 'dhcpc.1.status=enabled\\ndhcpc.1.devname=br0\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._netconfig._exec = orig
			assert_eq(st.ip_mode, "dhcp", "ip_mode still recorded as dhcp")
			assert_eq(#cmds, 0, "apply_dhcp NOT called -- nothing to revert")
		end
	},
	{
		name = "inform packet: per-BSS okc, tdls_prohibit, country_beacon and the pairwise cipher",
		fn = function()
			-- Verbatim shapes from a 10.6.106 capture (lab, 2026-10-26),
			-- diffed across the wlanconf's auth_cache / tdls_prohibit /
			-- country_beacon / wpa_enc fields -- every one of them changed,
			-- so none is a decoy. auth_cache rides only the WPA-Enterprise
			-- branch of the generator, which is why the PSK vap below has
			-- none: see the vap table's comments.
			local psk = "aaa.1.ssid=net\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.1.wpa.psk=secret\naaa.1.tdls_prohibit=enabled\n"
				.. "aaa.1.country_beacon=enabled\naaa.1.wpa.1.pairwise=GCMP\n"
				.. "wireless.1.ssid=net\nwireless.1.parent=radio0\n"
			local rt, vt = inform._parse_wifi_system_cfg(psk)
			assert_nil(vt[1].okc, "no auth_cache on a PSK WLAN -> nil, not false")
			assert_not_nil(rt, "radio_table comes back too")
			assert_true(vt[1].tdls_prohibit, "tdls_prohibit=enabled")
			assert_true(vt[1].country_beacon, "country_beacon=enabled")
			assert_eq(vt[1].pairwise, "gcmp", "GCMP -> the encryption suffix token")

			local off = psk:gsub("=enabled", "=disabled")
				:gsub("pairwise=GCMP", "pairwise=CCMP")
			rt, vt = inform._parse_wifi_system_cfg(off)
			assert_false(vt[1].tdls_prohibit, "tdls_prohibit=disabled")
			assert_false(vt[1].country_beacon, "country_beacon=disabled")
			assert_nil(vt[1].pairwise,
				"CCMP is OpenWrt's own default -- no suffix is written for it")

			-- The other three values the generator's enum can reach. GCMP-256
			-- is refused by the controller's validator today and mapped only
			-- because the enum carries it; "TKIP CCMP" (a WPA1 WLAN) is
			-- declined outright.
			for wire, token in pairs({["CCMP-256"] = "ccmp256",
					["GCMP-256"] = "gcmp256"}) do
				rt, vt = inform._parse_wifi_system_cfg(
					(psk:gsub("pairwise=GCMP", "pairwise=" .. wire)))
				assert_eq(vt[1].pairwise, token, wire .. " -> " .. token)
			end
			for _, wire in ipairs({"TKIP CCMP", "TKIP", "", "AES"}) do
				rt, vt = inform._parse_wifi_system_cfg(
					(psk:gsub("pairwise=GCMP", "pairwise=" .. wire)))
				assert_nil(vt[1].pairwise, "declined on the wire: " .. wire)
			end
		end
	},
	{
		name = "inform packet: a '=' in a passphrase or SSID stays in the value",
		fn = function()
			-- A line splits at its FIRST '='. A greedy key pattern split at
			-- the last one: the passphrase lost its head (key "wpa.psk=pass"),
			-- and an SSID with '=' left wireless.<n>.ssid unset so no WLAN
			-- was built at all.
			local cfg = "aaa.1.ssid=a=b\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.1.wpa.psk=pass=word==\n"
				.. "wireless.1.ssid=a=b\nwireless.1.parent=radio0\n"
			local _, vt = inform._parse_wifi_system_cfg(cfg)
			assert_not_nil(vt[1], "the WLAN with '=' in its SSID is built")
			assert_eq(vt[1].ssid, "a=b", "SSID keeps its '='")
			assert_eq(vt[1].x_passphrase, "pass=word==", "passphrase keeps every '='")
		end
	},
	{
		name = "inform packet: auth_cache rides the WPA-Enterprise branch and becomes okc",
		fn = function()
			-- The one WLAN kind the controller sends auth_cache on, captured
			-- 2026-10-26: default enabled, and it flips with the field.
			local eap = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.auth_cache=enabled\naaa.1.tdls_prohibit=disabled\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\n"
				.. "aaa.1.radius.auth.1.port=1812\n"
				.. "aaa.1.radius.auth.1.secret=shh\n"
				.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local rt, vt = inform._parse_wifi_system_cfg(eap)
			assert_eq(vt[1].security, "wpa2-enterprise", "the EAP branch")
			assert_true(vt[1].okc, "auth_cache=enabled -> okc on")
			rt, vt = inform._parse_wifi_system_cfg(
				(eap:gsub("auth_cache=enabled", "auth_cache=disabled")))
			assert_false(vt[1].okc, "auth_cache=disabled -> okc off, not nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg reads Roaming Assistant (btm_disassoc) per vap",
		fn = function()
			-- Wire format from the decompiled 10.6.101 generator: status is the
			-- builder's enabled/disabled boolean, threshold a plain dBm string,
			-- only on 5/6 GHz vaps; absent means off.
			local sys_cfg = "aaa.1.ssid=net\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.1.ssid=net\nwireless.1.parent=radio0\n"
				.. "aaa.2.ssid=net\naaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.2.ssid=net\nwireless.2.parent=radio1\n"
				.. "wireless.2.btm_disassoc.status=enabled\nwireless.2.btm_disassoc.threshold=-72\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_false(vap_table[1].roam_assist_enabled, "absent -> off")
			assert_nil(vap_table[1].roam_assist_rssi, "no threshold where off")
			assert_true(vap_table[2].roam_assist_enabled, "enabled")
			assert_eq(vap_table[2].roam_assist_rssi, -72, "threshold in dBm")
		end
	},
	{
		name = "inform packet: handle_response runs usteer and forces 802.11k/v for Roaming Assistant",
		fn = function()
			local st = sample_state()
			local args
			local orig = inform._usteer.set_enabled
			inform._usteer.set_enabled = function(...) args = {...} end
			local applied_opts
			inform._ucihelper = {
				apply_config = function(_, _, opts) applied_opts = opts end,
			}
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio1\n"
				.. "wireless.1.btm_disassoc.status=enabled\nwireless.1.btm_disassoc.threshold=-75\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			inform._usteer.set_enabled = orig
			inform._ucihelper = nil
			assert_false(args[1], "band steering itself stays off")
			assert_true(args[3], "usteer told Roaming Assistant is on")
			assert_true(applied_opts.roam_assist_active, "roam_assist_active threaded to apply_config")
			assert_false(applied_opts.band_steering_active, "band_steering_active untouched")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg reads per-radio and per-VAP disable",
		fn = function()
			-- CONFIRMED live 2026-07-19: Radios -> Transmit Power -> Disabled
			-- moves radio.<n>.status enabled->disabled together with
			-- txpower_mode and every wireless.<n>.status on that radio.
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.status=disabled\n"
				.. "radio.1.txpower_mode=disabled\n"
				.. "radio.2.phyname=radio1\nradio.2.status=enabled\n"
				.. "aaa.1.ssid=net\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.1.ssid=net\nwireless.1.parent=radio0\nwireless.1.status=disabled\n"
				.. "aaa.2.ssid=net\naaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.2.ssid=net\nwireless.2.parent=radio1\nwireless.2.status=enabled\n"
			local radio_table, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_true(radio_table[1].disabled, "2.4 GHz radio disabled")
			assert_false(radio_table[2].disabled, "5 GHz radio explicitly enabled")
			assert_true(vap_table[1].disabled, "the disabled radio's VAP goes down with it")
			assert_false(vap_table[2].disabled, "the other radio's VAP stays up")
		end
	},
	{
		name = "inform packet: the site's regdomain reaches the radio as an alpha-2 country",
		fn = function()
			-- Exact shape from a real controller (UniFi Network 10.4.57, site
			-- set to Czechia): the code is ISO 3166-1 NUMERIC and is sent both
			-- unindexed and per radio, while UCI's `country` wants alpha-2.
			local radio_table = inform._parse_wifi_system_cfg(
				"radio.status=enabled\nradio.countrycode=203\n"
				.. "radio.1.phyname=radio0\nradio.1.countrycode=203\n"
				.. "radio.2.phyname=radio1\nradio.2.countrycode=203\n")
			assert_eq(radio_table[1].country, "CZ", "203 -> CZ on radio0")
			assert_eq(radio_table[2].country, "CZ", "203 -> CZ on radio1")
		end
	},
	{
		name = "inform packet: the site's auto-channel DFS switch and channel blacklist reach the radio",
		fn = function()
			-- Verbatim shape from 10.6.106 once wifi_caps2 0x10 is claimed:
			-- acsdfs only on the 5 GHz radio, blklst only while that radio is
			-- on Auto, and the 2.4 GHz blacklist is the default site's
			-- "conservative" preset (everything but 1/6/11).
			local radio_table = inform._parse_wifi_system_cfg(
				"radio.status=enabled\n"
				.. "radio.1.phyname=radio0\nradio.1.channel=auto\n"
				.. "radio.1.blklst=12,2,13,3,14,4,5,7,8,9,10\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=auto\n"
				.. "radio.2.acsdfs=disabled\n")
			assert_nil(radio_table[1].acs_exclude_dfs,
				"2.4 GHz never carries acsdfs -- nil, not false")
			-- Verbatim wire order: the controller builds the list from a Java
			-- Set, so it arrives unsorted. The channels are kept as sent;
			-- rf_config walks the band's own ascending channel list, so the
			-- chanlist it writes is ordered whatever order this arrives in.
			assert_eq(table.concat(radio_table[1].acs_blacklist, ","),
				"12,2,13,3,14,4,5,7,8,9,10", "every blacklisted channel, as sent")
			assert_eq(radio_table[2].acs_exclude_dfs, true, "DFS excluded from ACS")
			assert_nil(radio_table[2].acs_blacklist, "no blacklist on this band")
			-- enabled is an explicit false, so it can undo an earlier disable.
			local on = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\nradio.1.acsdfs=enabled\n")
			assert_eq(on[1].acs_exclude_dfs, false, "DFS allowed -> explicit false")
			-- Absent keys leave UCI alone; the teardown of a chanlist openUF
			-- wrote earlier happens in rf_config, off its own stamp.
			local none = inform._parse_wifi_system_cfg("radio.1.phyname=radio0\n")
			assert_nil(none[1].acs_exclude_dfs, "no acsdfs -> nil")
			assert_nil(none[1].acs_blacklist, "no blklst -> nil")
			-- A blklst with nothing parseable in it is not an empty blacklist.
			local junk = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\nradio.1.blklst=\n")
			assert_nil(junk[1].acs_blacklist, "empty blklst -> nil")
		end
	},
	{
		name = "inform packet: the unindexed countrycode is used when radios carry none",
		fn = function()
			local radio_table = inform._parse_wifi_system_cfg(
				"radio.countrycode=840\nradio.1.phyname=radio0\n")
			assert_eq(radio_table[1].country, "US", "global regdomain applied")
		end
	},
	{
		name = "inform packet: an unmapped country code leaves the regdomain alone",
		fn = function()
			-- Better an unchanged regdomain than a guessed one: writing the
			-- wrong domain changes which channels and power levels the radio
			-- will legally use.
			local radio_table = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\nradio.1.countrycode=999\n")
			assert_nil(radio_table[1].country, "unknown numeric -> no country written")
			local none = inform._parse_wifi_system_cfg("radio.1.phyname=radio0\n")
			assert_nil(none[1].country, "no countrycode at all -> nil")
		end
	},
	{
		name = "inform packet: radio/VAP disable is nil when the wire omits status",
		fn = function()
			-- Tri-state on purpose: a blob that never carries the key must not
			-- re-enable a radio or SSID the user disabled by hand in
			-- /etc/config/wireless. Only an explicit value writes.
			local radio_table, vap_table = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\n"
				.. "aaa.1.ssid=net\nwireless.1.ssid=net\nwireless.1.parent=radio0\n")
			assert_nil(radio_table[1].disabled, "absent radio status leaves UCI alone")
			assert_nil(vap_table[1].disabled, "absent vap status leaves UCI alone")
		end
	},
	{
		name = "inform packet: the radio-less blob's unindexed radio.status disables nothing",
		fn = function()
			-- The "# no wlan provisioned as no radio found" blob carries a bare
			-- radio.status=disabled with no phyname anywhere. Reading that as a
			-- per-radio signal would take every radio on the device down.
			--
			-- This is a regression pin, not a live guard: the tokenizer's
			-- ^(radio)%.(%d+)%.(.+)= shape cannot match a two-component key at
			-- all, so the protection is structural. Kept so that loosening the
			-- pattern later fails here rather than in the field.
			local radio_table = inform._parse_wifi_system_cfg(
				"# no wlan provisioned as no radio found\nradio.status=disabled\n"
				.. "radio.1.phyname=radio0\nradio.1.channel=6\n")
			assert_eq(#radio_table, 1, "the real radio is still parsed")
			assert_nil(radio_table[1].disabled, "unindexed radio.status is not a per-radio signal")
		end
	},
	{
		name = "inform packet: _parse_switch_system_cfg treats the gated-off baseline as disabled",
		fn = function()
			-- B0, verbatim from the live capture 2026-07-19. The port entries
			-- are ALWAYS present -- one per the controller's model-registry
			-- port count -- so the block's presence must never be read as
			-- "enabled". Same trap as bcfilt/macacl/qos.vap.
			local sw = inform._parse_switch_system_cfg(
				"switch.dot1x.status=disabled\nswitch.jumboframes=disabled\n"
				.. "switch.port.1.name=PoE Out + Data\nswitch.port.1.opmode=switch\n"
				.. "switch.port.2.name=Data\nswitch.port.2.opmode=switch\n"
				.. "switch.status=disabled\nswitch.vlan.status=disabled\n")
			assert_not_nil(sw, "block was present")
			assert_false(sw.enabled, "gated off -- presence is not the discriminator")
			assert_nil(next(sw.ports), "inventory-only ports carry no override")
		end
	},
	{
		name = "inform packet: _parse_switch_system_cfg returns nil when no switch block is sent",
		fn = function()
			assert_nil(inform._parse_switch_system_cfg("radio.1.phyname=radio0\n"),
				"absent block is distinct from a gated-off one")
		end
	},
	{
		name = "inform packet: _parse_switch_system_cfg extracts the per-port VLAN override",
		fn = function()
			-- C2/C3, verbatim from the live capture: port 2 native VLAN 20,
			-- VLAN 1 excluded from it. Slot numbers (vlan.1/vlan.2) are NOT
			-- VLAN ids -- vlan.2 is VLAN 20 -- so the resolution through .id
			-- is load-bearing.
			local sw = inform._parse_switch_system_cfg(
				"switch.status=enabled\nswitch.vlan.status=enabled\n"
				.. "switch.port.1.name=PoE Out + Data\nswitch.port.1.opmode=switch\n"
				.. "switch.port.2.name=Data\nswitch.port.2.opmode=switch\n"
				.. "switch.port.2.pvid=20\n"
				.. "switch.vlan.1.id=1\nswitch.vlan.1.mode=untagged\nswitch.vlan.1.status=enabled\n"
				.. "switch.vlan.1.port.2.mode=exclude\n"
				.. "switch.vlan.2.id=20\nswitch.vlan.2.mode=tagged\nswitch.vlan.2.status=enabled\n"
				.. "switch.vlan.2.port.2.mode=untagged\n")
			assert_true(sw.enabled, "both gates enabled")
			assert_eq(sw.ports[2].pvid, 20, "native VLAN read off the port")
			assert_eq(sw.ports[2].vlans[20], "untagged", "membership keyed by VLAN id, not slot")
			assert_eq(sw.ports[2].vlans[1], "exclude", "Block All maps to exclude")
			assert_nil(sw.ports[1], "untouched port carries no override")
			assert_true(sw.vlans[20].enabled, "VLAN 20 resolved from slot 2")
			assert_eq(sw.vlans[1].mode, "untagged", "VLAN 1 device-wide default")
		end
	},
	{
		name = "inform packet: _parse_switch_system_cfg reads teardown as the absence of port keys",
		fn = function()
			-- C4: reverting a port drops its three keys entirely and the blob
			-- returns byte-identical to the gate-on baseline. Teardown is
			-- therefore expressible -- absence means default.
			local sw = inform._parse_switch_system_cfg(
				"switch.status=enabled\nswitch.vlan.status=enabled\n"
				.. "switch.port.2.name=Data\nswitch.port.2.opmode=switch\n"
				.. "switch.vlan.1.id=1\nswitch.vlan.1.mode=untagged\nswitch.vlan.1.status=enabled\n"
				.. "switch.vlan.2.id=20\nswitch.vlan.2.mode=tagged\nswitch.vlan.2.status=enabled\n")
			assert_true(sw.enabled, "feature still on")
			assert_nil(next(sw.ports), "no port overrides remain")
		end
	},
	{
		name = "inform packet: minrssi survives the triple rename (wire -> UCI -> readback -> dBm)",
		fn = function()
			-- The value crosses three renames no per-side test covers as one
			-- chain: parse emits radio_table[].min_rssi (raw wire units),
			-- apply_config writes UCI minrssi_rssi, get_radio_table reads it
			-- back as min_rssi_raw, and build_json converts it to the
			-- outbound min_rssi dBm. A rename on any hop keeps every per-side
			-- test green while the feature dies silently -- this drives one
			-- value through all four.
			local ucihelper, db = new_apply_env()
			-- The wifi-device section exists on any real device (board
			-- config); rf_config only sets options and the mock's foreach
			-- filters on .type, so pre-create it here.
			ucihelper._uci.cursor():set("wireless", "radio0", "wifi-device")
			local rt, vt = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\nradio.1.channel=6\n"
				.. "stamgr.1.status=true\nstamgr.1.radio=ng\n"
				.. "stamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=15\n")
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(db.wireless.radio0.minrssi_rssi, "15", "wire raw value landed in UCI")

			ucihelper._popen = function(cmd)
				if cmd:find("network.wireless", 1, true) then
					return '{"radio0":{"interfaces":[{"ifname":"wlan0"}]}}'
				end
				return ""
			end
			local orig_uci   = inform._ucihelper
			local orig_stats = inform._sysinfo.radio_stats
			local orig_run   = inform._sysinfo._run_cmd
			local orig_read  = inform._sysinfo._read_file
			inform._ucihelper = ucihelper
			inform._sysinfo._run_cmd = function() return "" end
			inform._sysinfo._read_file = function() return "" end
			local ok, err = pcall(function()
				-- Driven twice with wildly different noise floors, because the
				-- conversion must NOT depend on one. The wire encoding is a
				-- fixed raw = dbm + 95 (the controller never learns a radio's
				-- noise floor, so it has nothing else to encode with), and
				-- adding live noise instead made the same setting mean -75 on
				-- an mt76 radio and -92 on an ath9k one -- it only looked
				-- right on the ath10k radio it was written against, whose
				-- floor happens to be exactly -95.
				for _, noise in ipairs({-90, -107, -95}) do
					inform._sysinfo.radio_stats = function()
						return {{freq = 2437, noise = noise, in_use = true,
							channel_time = 100, channel_time_busy = 10}}
					end
					local d = require("cjson").decode(inform.build_json(sample_state(), nil, nil))
					assert_true(d.radio_table[1].min_rssi_enabled,
						"enabled flag survived the chain")
					assert_eq(d.radio_table[1].min_rssi, -80,
						"15 raw -> -80 dBm, whatever the noise floor reads (" .. noise .. ")")
				end
			end)
			inform._ucihelper = orig_uci
			inform._sysinfo.radio_stats = orig_stats
			inform._sysinfo._run_cmd = orig_run
			inform._sysinfo._read_file = orig_read
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: use_aes_gcm is tri-state -- absent leaves st.use_gcm alone, false clears",
		fn = function()
			-- Every wifi field got tri-state coverage; this mgmt_cfg one
			-- never did. Absent must not clobber a previously negotiated GCM
			-- mode; an explicit false must clear it.
			local st = sample_state({use_gcm = true, adopted = true})
			inform.handle_response(
				'{"_type":"setparam","mgmt_cfg":"cfgversion=9\\n"}', st)
			assert_true(st.use_gcm, "absent key leaves the negotiated mode alone")
			inform.handle_response(
				'{"_type":"setparam","mgmt_cfg":"use_aes_gcm=false\\n"}', st)
			assert_false(st.use_gcm, "explicit false clears it")
		end
	},
	{
		name = "inform packet: handle_response restores stock switch VLANs on an explicit Port VLAN disable",
		fn = function()
			-- Unticking the device-level "Port VLAN" box keeps the switch.*
			-- block on the wire with both gates at =disabled (the live-captured
			-- baseline shape). That must route to switchvlan.restore(st) --
			-- before the fix apply() just early-returned and the openuf_swvlan*
			-- sections plus the mutated stock port strings survived forever.
			local st = sample_state()
			local calls = {}
			local orig = inform._switchvlan
			inform._switchvlan = {
				apply   = function() calls[#calls + 1] = "apply" end,
				restore = function(got_st) calls[#calls + 1] = "restore"
					assert_eq(got_st, st, "restore gets the state ledger") end,
			}
			local sys_cfg = "switch.status=disabled\nswitch.vlan.status=disabled\n"
				.. "switch.port.1.name=Data\nswitch.port.1.opmode=switch\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, nil)
			inform._switchvlan = orig
			assert_eq(table.concat(calls, ","), "restore", "restore called, apply not")
		end
	},
	{
		name = "inform packet: handle_response leaves the switch alone when no switch block is sent",
		fn = function()
			-- Absent block (older controller, partial push) is tri-state
			-- "no opinion": apply(nil, ...) -- itself a no-op -- and never
			-- restore, which would tear down state the push said nothing about.
			local st = sample_state()
			local calls = {}
			local orig = inform._switchvlan
			inform._switchvlan = {
				apply   = function(sw) calls[#calls + 1] = "apply"
					assert_nil(sw, "no switch keys -> parsed nil") end,
				restore = function() calls[#calls + 1] = "restore" end,
			}
			local resp = '{"_type":"setparam","system_cfg":"aaa.1.ssid=x\\nwireless.1.ssid=x\\nwireless.1.parent=radio0\\n"}'
			inform.handle_response(resp, st, nil)
			inform._switchvlan = orig
			assert_eq(table.concat(calls, ","), "apply", "apply called with nil, restore never")
		end
	},
	{
		name = "inform packet: a DSA push works out the switch block and uplink socket once",
		fn = function()
			-- Both the port-VLAN set handed to the WiFi pass and the switch
			-- pass after it need the parsed switch.* block and the socket the
			-- uplink cable is in. Each consumer used to work both out again,
			-- and the uplink is a `bridge fdb` dump.
			local st = sample_state()
			local si, sv = inform._sysinfo, inform._switchvlan
			local orig_parse = inform._parse_switch_system_cfg
			local orig_bo, orig_up = si.bridge_of, si.uplink_bridge_port
			local parses, fdb_dumps, seen = 0, 0, {}
			inform._parse_switch_system_cfg = function(raw)
				parses = parses + 1
				return orig_parse(raw)
			end
			si.bridge_of = function() return "br-lan" end
			si.uplink_bridge_port = function(br)
				fdb_dumps = fdb_dumps + 1
				assert_eq(br, "br-lan", "asked of the LAN bridge")
				return "wan"
			end
			inform._switchvlan = {
				dsa_members = function(sw, _, up) seen.members = {sw = sw, up = up}; return {} end,
				apply = function(sw, _, _, _, phys, ifname)
					seen.apply = {sw = sw, phys = phys, ifname = ifname}
				end,
				restore = function() seen.restore = true end,
			}
			local sys_cfg = "switch.status=enabled\nswitch.vlan.status=enabled\n"
				.. "switch.port.2.name=Data\nswitch.port.2.opmode=switch\n"
				.. "switch.port.2.pvid=20\n"
				.. "switch.vlan.1.id=1\nswitch.vlan.1.mode=untagged\nswitch.vlan.1.status=enabled\n"
				.. "switch.vlan.2.id=20\nswitch.vlan.2.mode=tagged\nswitch.vlan.2.status=enabled\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			local ok, err = pcall(inform.handle_response, resp, st, nil)
			inform._parse_switch_system_cfg = orig_parse
			si.bridge_of, si.uplink_bridge_port = orig_bo, orig_up
			inform._switchvlan = sv
			if not ok then error(err, 0) end
			assert_eq(parses, 1, "switch.* parsed once")
			assert_eq(fdb_dumps, 1, "uplink socket looked up once")
			assert_not_nil(seen.members, "the port-VLAN set was asked for")
			assert_not_nil(seen.apply, "and the switch pass ran")
			assert_eq(seen.members.up, "wan", "port-VLAN set gets the uplink")
			assert_eq(seen.apply.ifname, "wan", "switch pass gets the same uplink")
			assert_nil(seen.apply.phys, "no swconfig ARL lookup on DSA")
			assert_true(seen.apply.sw ~= nil and seen.apply.sw == seen.members.sw,
				"both get the same parsed switch block")
			assert_true(seen.apply.sw.enabled, "and it is the enabled one that was pushed")
		end
	},
	{
		name = "inform packet: a tagged SSID's VLAN reaches switchvlan as a trunk request",
		fn = function()
			-- The switch drops frames for a VID it has no entry for, so a
			-- VLAN-tagged SSID needs a trunk even with the controller's
			-- per-port VLAN feature switched off entirely. Confirmed live:
			-- bridge correct, VAP up, 100% packet loss to the VLAN's gateway
			-- until the trunk existed.
			--
			-- This also pins the scope bug it was written for: vap_table used
			-- to be local to the wifi branch, so the switch pass read nil and
			-- silently trunked nothing while every test still passed.
			local st = sample_state()
			local got
			local orig = inform._switchvlan
			inform._switchvlan = {
				apply   = function(_, _, _, vlans) got = vlans end,
				restore = function() end,
			}
			local sys_cfg = "aaa.1.ssid=Home IoT\naaa.1.wpa=2\n"
				.. "aaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.br.devname=br0.20\n"
				.. "wireless.1.ssid=Home IoT\nwireless.1.parent=radio1\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}')
				:format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, nil)
			inform._switchvlan = orig
			assert_true(got ~= nil, "switchvlan is handed a vlan list")
			assert_eq(#got, 1, "one tagged SSID -> one VLAN to trunk")
			assert_eq(got[1], 20, "the VLAN off aaa.<n>.br.devname=br0.20")
		end
	},
	{
		name = "inform packet: private pre-shared key VLANs reach switchvlan as trunk requests",
		fn = function()
			-- A key's client is tagged onto its VLAN at the AP, so that VLAN
			-- needs the same trunk a tagged SSID does.
			local st = sample_state()
			local got
			local orig, orig_uci = inform._switchvlan, inform._ucihelper
			inform._switchvlan = {
				apply   = function(_, _, _, vlans) got = vlans end,
				restore = function() end,
			}
			inform._ucihelper = {vap_vlan_ids = dofile("openuf/ucihelper.lua").vap_vlan_ids}
			local sys_cfg = "aaa.1.ssid=keys\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.1.br.devname=br0.20\naaa.1.wpa.psk_file.status=enabled\n"
				.. "aaa.1.wpa.psk_file.1.psk=keydefault1\n"
				.. "aaa.1.wpa.psk_file.2.psk=keyvlan30a\naaa.1.wpa.psk_file.2.vlanid=30\n"
				.. "aaa.1.wpa.psk_file.3.psk=keyvlan20a\naaa.1.wpa.psk_file.3.vlanid=20\n"
				.. "wireless.1.ssid=keys\nwireless.1.parent=radio1\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}')
				:format(sys_cfg:gsub("\n", "\\n"))
			local ok, err = pcall(inform.handle_response, resp, st, nil)
			inform._switchvlan, inform._ucihelper = orig, orig_uci
			if not ok then error(err, 0) end
			assert_eq(table.concat(got or {}, ","), "20,30",
				"the WLAN's own VLAN once, plus the other key's")
		end
	},
	{
		name = "inform packet: an untagged-only push asks for no trunk",
		fn = function()
			local st = sample_state()
			local got
			local orig = inform._switchvlan
			inform._switchvlan = {
				apply   = function(_, _, _, vlans) got = vlans end,
				restore = function() end,
			}
			local sys_cfg = "aaa.1.ssid=Home LAN\naaa.1.br.devname=br0\n"
				.. "wireless.1.ssid=Home LAN\nwireless.1.parent=radio1\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}')
				:format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, nil)
			inform._switchvlan = orig
			assert_eq(#(got or {}), 0, "br0 with no suffix -> nothing to trunk")
		end
	},
	{
		name = "inform packet: _report_dropped_keys summarizes unrecognized keys by prefix",
		fn = function()
			-- The feedback loop that macacl.*/qos.vap.* needed: no tokenizer
			-- here has an else branch, so a whole feature can sit in every
			-- capture unnoticed. Indices collapse to <n> so a multi-VAP blob
			-- reports one line per key SHAPE, not one per instance.
			local out = with_stderr(function()
				inform._debug_dropped_keys = true
				inform._report_dropped_keys("system_cfg",
					"aaa.1.ssid=known\nswitch.port.1.name=Port 1\nswitch.port.2.name=Port 2\n"
					.. "switch.status=enabled\n",
					{"^aaa%.%d+%."})
			end)
			assert_contains(out, "3 dropped key(s)", "counts every dropped key")
			assert_contains(out, "switch.port.<n>.name x2", "indices collapsed, instances counted")
			assert_contains(out, "switch.status x1", "non-indexed key reported as-is")
			assert_nil(out:find("aaa", 1, true), "recognized keys are not reported")
		end
	},
	{
		name = "inform packet: _report_dropped_keys never emits values",
		fn = function()
			-- These blobs carry aaa.<n>.wpa.psk and mgmt_cfg's authkey, and
			-- this goes to the log. Prefixes and counts only.
			local out = with_stderr(function()
				inform._debug_dropped_keys = true
				inform._report_dropped_keys("mgmt_cfg",
					"authkey=ccc32a3bbe40157773294de8ed683627\nsecret.thing=hunter2\n",
					{})
			end)
			assert_contains(out, "authkey x1", "key name reported")
			assert_nil(out:find("ccc32a3b", 1, true), "authkey value never logged")
			assert_nil(out:find("hunter2", 1, true), "no value of any key is logged")
		end
	},
	{
		name = "inform packet: _report_dropped_keys is silent when off, clean, or comment-only",
		fn = function()
			local out = with_stderr(function()
				inform._debug_dropped_keys = false
				inform._report_dropped_keys("system_cfg", "switch.status=enabled\n", {})
			end)
			assert_eq(out, "", "silent when the debug gate is off")

			out = with_stderr(function()
				inform._debug_dropped_keys = true
				inform._report_dropped_keys("system_cfg", "aaa.1.ssid=x\n", {"^aaa%.%d+%."})
			end)
			assert_eq(out, "", "silent when every key is recognized")

			out = with_stderr(function()
				inform._debug_dropped_keys = true
				-- A radio-less blob carries this literal comment.
				inform._report_dropped_keys("system_cfg",
					"# no wlan provisioned as no radio found\n\n", {})
			end)
			assert_eq(out, "", "comments and blank lines are not keys")

			inform._debug_dropped_keys = false  -- don't leak the gate into later tests
		end
	},
	{
		name = "inform packet: handle_response reports dropped keys only with the debug gate on",
		fn = function()
			-- End-to-end through the real RECOGNIZED_* lists. qos.if.* is a
			-- genuine never-consumed block (the interface inventory that
			-- accompanies qos.vap.*), so it is the honest probe.
			local sys_cfg = "netconf.1.ip=172.19.0.50\\nqos.if.1.devname=eth0\\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg)

			-- The blob's netconf key reaches the real static-IP apply path
			-- (cfg.net is present), whose default _exec is os.execute -- left
			-- unstubbed this test ran real `ip addr` commands on the host.
			local orig_exec = inform._netconfig._exec
			inform._netconfig._exec = function() return true end

			local out = with_stderr(function()
				inform.handle_response(resp, sample_state(), {net = {lan_cpueth = "eth0"}})
			end)
			assert_eq(out, "", "silent without cfg.config.debug_dump_file")

			out = with_stderr(function()
				inform.handle_response(resp, sample_state(), {
					net = {lan_cpueth = "eth0"},
					config = {debug_dump_file = "/dev/null"},
				})
			end)
			inform._netconfig._exec = orig_exec
			assert_contains(out, "system_cfg:", "reports against the real recognized list")
			assert_contains(out, "qos.if.<n>.devname", "surfaces a block openUF drops")
			assert_nil(out:find("netconf", 1, true), "a consumed key is not reported")

			inform._debug_dropped_keys = false
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg skips a WPA-Enterprise WLAN with no RADIUS server",
		fn = function()
			-- An Enterprise WLAN carries mgmt=WPA-EAP and NO wpa.psk. Without
			-- the aaa.<n>.radius.auth.* block there is nothing to authenticate
			-- against, and falling through would match neither the SAE nor the
			-- PSK branch and land on security="wpa2", producing a psk2 section
			-- with a nil key -- a VAP hostapd refuses to bring up, silently.
			-- The only honest outcome is to drop the WLAN and say so.
			local sys_cfg = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
				.. "aaa.2.ssid=guest\naaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.2.wpa.psk=secret123\n"
				.. "wireless.2.ssid=guest\nwireless.2.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 1, "only the PSK WLAN survives")
			assert_eq(vap_table[1].ssid, "guest", "the Enterprise WLAN was dropped, not mis-provisioned")
			assert_eq(vap_table[1].security, "wpa2", "the PSK WLAN is unaffected")
		end
	},
	{
		name = "inform packet: a WPA-Enterprise WLAN is provisioned with its RADIUS servers",
		fn = function()
			-- The wire DOES carry the RADIUS configuration: 10.6.106's AP config
			-- builder emits aaa.<n>.radius.auth.<k>.{ip,port,secret} and UAP
			-- 6.8.2's ubntbox turns them into auth_server_addr/port/shared_secret.
			-- No device capability gates a WPA2-Enterprise WLAN, so this arrives
			-- whether openUF asks for it or not.
			local sys_cfg = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.port=1812\n"
				.. "aaa.1.radius.auth.1.secret=s3cret\n"
				.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local vap_table
			with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(#vap_table, 1, "the Enterprise WLAN is provisioned")
			local v = vap_table[1]
			assert_eq(v.security, "wpa2-enterprise", "security")
			assert_eq(#v.radius.auth, 1, "one auth server")
			assert_eq(v.radius.auth[1].ip, "192.0.2.10", "ip")
			assert_eq(v.radius.auth[1].port, "1812", "port")
			assert_eq(v.radius.auth[1].secret, "s3cret", "secret")
			assert_eq(#v.radius.acct, 0, "no accounting server was sent")
			assert_nil(v.radius.interim_interval, "no interim updates")
			assert_nil(v.radius.dynamic_vlan, "no dynamic VLAN")
			assert_nil(v.x_passphrase, "an EAP WLAN carries no passphrase")
			assert_nil(v.ppsk, "and no private keys")
		end
	},
	{
		name = "inform packet: the EAP akm and the wpa3 keys pick the enterprise security value",
		fn = function()
			-- The akm alone cannot tell WPA3-Enterprise from transition: the
			-- authoritative keys are wpa3.support/.transition, exactly as on the
			-- PSK side. 192-bit is tested first, since it implies wpa3.support.
			local function sec(extra, mgmt)
				local sys_cfg = "aaa.1.ssid=corp\naaa.1.wpa=2\n"
					.. "aaa.1.wpa.key.1.mgmt=" .. (mgmt or "WPA-EAP") .. "\n"
					.. "aaa.1.radius.auth.1.ip=192.0.2.10\n"
					.. "aaa.1.radius.auth.1.secret=s3cret\n"
					.. extra
					.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
				local vt
				with_stderr(function()
					local _
					_, vt = inform._parse_wifi_system_cfg(sys_cfg)
				end)
				assert_eq(#vt, 1, "provisioned")
				return vt[1]
			end
			assert_eq(sec("").security, "wpa2-enterprise", "plain WPA-EAP")
			assert_eq(sec("aaa.1.wpa3.support=enabled\n").security,
				"wpa3-enterprise", "wpa3.support alone")
			assert_eq(sec("aaa.1.wpa3.support=enabled\naaa.1.wpa3.transition=enabled\n")
				.security, "wpa2/wpa3-enterprise", "transition")
			assert_eq(sec("aaa.1.wpa3.support=enabled\naaa.1.wpa3.enhanced_192=enabled\n")
				.security, "wpa3-enterprise-192", "enhanced_192 wins over wpa3.support")
			assert_eq(sec("", "WPA-EAP-SUITE-B-192").security, "wpa3-enterprise-192",
				"the Suite-B akm alone is enough")
			-- FT-EAP contains "EAP", so it must still be an enterprise WLAN,
			-- and the existing 802.11r field is what carries fast roaming.
			local v = sec("aaa.1.ft.status=enabled\n", "FT-EAP")
			assert_eq(v.security, "wpa2-enterprise", "FT-EAP is still WPA2-Enterprise")
			assert_true(v.fast_roaming_enabled, "and fast roaming is on")
		end
	},
	{
		name = "inform packet: RADIUS servers are read in index order, with defaults and validation",
		fn = function()
			-- The tokenizer keeps the whole dotted path as one flat key, so the
			-- per-server indices have to be re-matched and sorted; the controller
			-- does not emit them in order. A server that cannot be used is
			-- dropped individually, never silently repaired.
			local sys_cfg = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.radius.auth.3.ip=192.0.2.30\naaa.1.radius.auth.3.secret=c\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.secret=a\n"
				.. "aaa.1.radius.auth.4.ip=not-an-ip\naaa.1.radius.auth.4.secret=d\n"
				.. "aaa.1.radius.auth.2.ip=192.0.2.20\naaa.1.radius.auth.2.secret=\n"
				.. "aaa.1.radius.auth.5.ip=192.0.2.50\naaa.1.radius.auth.5.secret=e\n"
				.. "aaa.1.radius.auth.5.ca_cert=ca.pem\n"
				.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_contains(logged, "dropping RADIUS auth server 4",
				"the malformed address is named")
			assert_true(logged:find("s3cret", 1, true) == nil
				and logged:find("secret=", 1, true) == nil,
				"no secret value is ever logged")
			local auth = vap_table[1].radius.auth
			assert_eq(#auth, 2, "the malformed, secretless and RadSec servers are dropped")
			assert_eq(auth[1].ip, "192.0.2.10", "index 1 first")
			assert_eq(auth[2].ip, "192.0.2.30", "then index 3")
			assert_eq(auth[1].port, "1812", "an absent port defaults to 1812")
		end
	},
	{
		name = "inform packet: RADIUS accounting, interim updates, dynamic VLAN and NAS id",
		fn = function()
			local base = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.secret=a\n"
			local tail = "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local function r(extra)
				local vt
				with_stderr(function()
					local _
					_, vt = inform._parse_wifi_system_cfg(base .. extra .. tail)
				end)
				assert_eq(#vt, 1, "provisioned")
				return vt[1].radius
			end
			local rad = r("aaa.1.radius.acct.1.ip=192.0.2.11\n"
				.. "aaa.1.radius.acct.1.secret=b\n"
				.. "aaa.1.interim_update.status=enabled\n"
				.. "aaa.1.interim_update.interval=600\n"
				.. "aaa.1.dynamic_vlan=2\naaa.1.nas_identifier=ap-office\n")
			assert_eq(#rad.acct, 1, "one accounting server")
			assert_eq(rad.acct[1].port, "1813", "accounting defaults to 1813")
			assert_eq(rad.interim_interval, "600", "the pushed interval")
			assert_eq(rad.dynamic_vlan, "2", "required")
			assert_eq(rad.nas_id, "ap-office", "NAS id")
			-- status with no interval is the firmware's 3600 default; status
			-- off means "do not send interim updates", not "use 3600".
			assert_eq(r("aaa.1.interim_update.status=enabled\n").interim_interval, "3600",
				"default interval")
			assert_nil(r("aaa.1.interim_update.status=disabled\n"
				.. "aaa.1.interim_update.interval=600\n").interim_interval,
				"disabled means none")
			assert_nil(r("aaa.1.dynamic_vlan=0\n").dynamic_vlan, "0 is no dynamic VLAN")
			assert_nil(r("").dynamic_vlan, "absent is no dynamic VLAN")
		end
	},
	{
		name = "inform packet: a WPA-Enterprise WLAN whose every RADIUS server is RadSec is skipped",
		fn = function()
			-- RadSec cannot be completed: the controller sends only the cert
			-- FILENAMES, for files it transfers by another channel. Contacting
			-- such a server as plain RADIUS would put the secret on the wire in
			-- the clear, so the server is dropped -- and with no server left the
			-- WLAN is skipped, like any other unprovisionable Enterprise WLAN.
			local sys_cfg = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.secret=a\n"
				.. "aaa.1.radius.auth.1.ca_cert=ca.pem\n"
				.. "aaa.1.radius.auth.1.private_key=key.pem\n"
				.. "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(#vap_table, 0, "no usable server left, so no WLAN")
			assert_contains(logged, "RadSec (TLS) is not supported", "the reason is named")
			assert_contains(logged, "no usable RADIUS authentication server",
				"and the skip says why")
		end
	},
	{
		name = "inform packet: RADIUS MAC authentication comes with its own server block",
		fn = function()
			-- aaa.<n>.radius.macacl.status is on the wire for every WLAN, and the
			-- writer puts no capability gate on it: the VALUE is the whole
			-- discriminator. It is not tied to the security type either -- this
			-- is an OPEN WLAN, and the controller still sends the full
			-- radius.auth.<k>.* block beside it, verbatim as captured from
			-- 10.6.106 on 2026-10-27 (an open guest WLAN with "MAC
			-- Authentication" on and the lab RADIUS profile attached).
			local sys_cfg = "aaa.3.ssid=guest\naaa.3.devname=ath2\n"
				.. "aaa.3.radius.auth.1.ip=192.0.2.10\naaa.3.radius.auth.1.port=1812\n"
				.. "aaa.3.radius.auth.1.secret=a\n"
				.. "aaa.3.radius.auth.2.ip=192.0.2.11\naaa.3.radius.auth.2.port=1812\n"
				.. "aaa.3.radius.auth.2.secret=a\n"
				.. "aaa.3.radius.macacl.status=enabled\n"
				.. "aaa.3.radius.macacl.emptypassword=enabled\n"
				.. "aaa.3.radius.macacl.format=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n"
				.. "wireless.3.ssid=guest\nwireless.3.parent=radio0\n"
			local orig = inform._sysinfo.eap_supported
			inform._sysinfo.eap_supported = function() return true end
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			inform._sysinfo.eap_supported = orig
			assert_eq(#vap_table, 1, "the WLAN is provisioned")
			local v = vap_table[1]
			assert_eq(v.security, "open", "still an open WLAN")
			assert_true(v.mac_auth, "MAC authentication is on")
			assert_eq(#v.radius.auth, 2, "both authentication servers were read")
			assert_eq(v.radius.auth[1].ip, "192.0.2.10", "in index order")
			assert_eq(logged, "", "and nothing is complained about")
			-- The two formatting keys are declines: both are options of UniFi's
			-- patched hostapd (macaddr_format, mac_acl_empty_passwd), neither
			-- string exists in OpenWrt's binary, so nothing may key on them.
			assert_nil(v.radius.macacl, "no macacl field")
			assert_nil(v.mac_auth_format, "the printf format derives nothing")
			assert_nil(v.mac_filter_policy,
				"radius.macacl is not the MAC Address Filter")
			-- A WLAN the controller leaves alone keeps nothing.
			local _, plain = inform._parse_wifi_system_cfg(
				"aaa.1.ssid=open\naaa.1.radius.macacl.status=disabled\n"
				.. "wireless.1.ssid=open\nwireless.1.parent=radio0\n")
			assert_nil(plain[1].mac_auth, "macacl.status=disabled claims nothing")
			assert_nil(plain[1].radius, "and brings no RADIUS block")
		end
	},
	{
		name = "inform packet: MAC-based VLANs are read per client, with the status key ignored",
		fn = function()
			-- VERBATIM from the home controller (UniFi Network on a UCG Ultra),
			-- 2026-10-27, with a Virtual Network Override set on a placeholder
			-- client onto the IoT network (VLAN 10). The same map arrives on
			-- EVERY WLAN -- the emitter takes the site's whole override list and
			-- writes it per WLAN index, so three WLANs got three identical
			-- blocks. (The validation lab cannot produce this: its site has no
			-- gateway, so the controller's second gate refuses to emit the keys
			-- at all. See PROTOCOL-VALIDATION.md.)
			local sys_cfg = "aaa.1.ssid=Home LAN\naaa.1.devname=ath0\n"
				.. "aaa.1.accept_mac.status=enabled\n"
				.. "aaa.1.accept_mac.1.mac=00:00:5e:00:53:01\n"
				.. "aaa.1.accept_mac.1.vlanid=10\n"
				.. "aaa.1.wpa.psk=basepass123\n"
				.. "aaa.2.ssid=Home IoT\naaa.2.devname=ath1\n"
				.. "aaa.2.accept_mac.status=enabled\n"
				.. "aaa.2.accept_mac.1.mac=00:00:5e:00:53:01\n"
				.. "aaa.2.accept_mac.1.vlanid=10\n"
				.. "aaa.2.wpa.psk=basepass123\n"
				.. "wireless.1.ssid=Home LAN\nwireless.1.parent=radio0\n"
				.. "wireless.2.ssid=Home IoT\nwireless.2.parent=radio1\n"
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(#vap_table, 2, "both WLANs are provisioned")
			for i, v in ipairs(vap_table) do
				assert_eq(#v.mac_vlans, 1, "WLAN " .. i .. " carries the override")
				assert_eq(v.mac_vlans[1].mac, "00:00:5e:00:53:01", "the MAC")
				assert_eq(v.mac_vlans[1].vid, 10, "and its VLAN, as a number")
			end
			assert_eq(logged, "", "nothing to complain about")
			-- status is NOT the discriminator: the writer emits it from inside
			-- the loop that writes the first entry, so it is present exactly when
			-- entries are. The entries are the whole signal -- a block's presence
			-- is this protocol's classic decoy.
			local _, bare = inform._parse_wifi_system_cfg(
				"aaa.1.ssid=home\naaa.1.accept_mac.status=enabled\n"
				.. "wireless.1.ssid=home\nwireless.1.parent=radio0\n")
			assert_nil(bare[1].mac_vlans, "status alone claims nothing")
			-- A second entry, which the capture had no occasion to carry: the
			-- controller's map is the site's, so a second overridden client adds
			-- an index rather than a second block.
			local _, two = inform._parse_wifi_system_cfg(
				"aaa.1.ssid=home\naaa.1.accept_mac.status=enabled\n"
				.. "aaa.1.accept_mac.1.mac=00:00:5e:00:53:01\n"
				.. "aaa.1.accept_mac.1.vlanid=10\n"
				.. "aaa.1.accept_mac.2.mac=00:00:5e:00:53:02\n"
				.. "aaa.1.accept_mac.2.vlanid=30\n"
				.. "wireless.1.ssid=home\nwireless.1.parent=radio0\n")
			assert_eq(#two[1].mac_vlans, 2, "both clients")
			assert_eq(two[1].mac_vlans[2].vid, 30, "each on its own VLAN")
		end
	},
	{
		name = "inform packet: a malformed or duplicated MAC-based VLAN entry is named and dropped",
		fn = function()
			-- Every entry is spliced into a hostapd accept-list line, where one
			-- malformed line fails the whole FILE and takes the BSS with it.
			local sys_cfg = "aaa.1.ssid=home\naaa.1.devname=ath0\n"
				.. "aaa.1.accept_mac.1.mac=00:00:5e:00:53:01\n"
				.. "aaa.1.accept_mac.1.vlanid=20\n"
				.. "aaa.1.accept_mac.2.mac=not-a-mac\n"
				.. "aaa.1.accept_mac.2.vlanid=30\n"
				.. "aaa.1.accept_mac.3.mac=00:00:5e:00:53:03\n"
				.. "aaa.1.accept_mac.3.vlanid=4095\n"
				.. "aaa.1.accept_mac.4.mac=00:00:5E:00:53:01\n"
				.. "aaa.1.accept_mac.4.vlanid=40\n"
				.. "aaa.1.wpa.psk=basepass123\n"
				.. "wireless.1.ssid=home\nwireless.1.parent=radio0\n"
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			local v = vap_table[1]
			assert_eq(#v.mac_vlans, 1, "only the sound entry survives")
			assert_eq(v.mac_vlans[1].vid, 20, "the first one")
			assert_contains(logged, "entry 2 -- not a MAC address", "entry 2 by number")
			assert_contains(logged, "entry 3 -- VLAN id out of range", "4095 is not a VLAN")
			assert_contains(logged, "entry 4 -- a duplicate of an earlier entry",
				"two accept lines for one station would leave hostapd's bsearch to pick")
		end
	},
	{
		name = "inform packet: a WLAN needing MAC authentication is dropped, not left open",
		fn = function()
			-- MAC authentication is an access control, so it fails CLOSED: a WLAN
			-- provisioned without it would admit every client the admin meant to
			-- screen, and on an open WLAN that is the only barrier there is.
			local function run(cfg, eap_ok)
				local orig = inform._sysinfo.eap_supported
				inform._sysinfo.eap_supported = function() return eap_ok end
				local vt
				local logged = with_stderr(function()
					local _
					_, vt = inform._parse_wifi_system_cfg(cfg)
				end)
				inform._sysinfo.eap_supported = orig
				return vt, logged
			end
			local tail = "wireless.1.ssid=guest\nwireless.1.parent=radio0\n"
			-- No usable server: the push names none at all.
			local vt, logged = run("aaa.1.ssid=guest\n"
				.. "aaa.1.radius.macacl.status=enabled\n" .. tail, true)
			assert_eq(#vt, 0, "no server, no WLAN")
			assert_contains(logged, "requires RADIUS MAC authentication",
				"the reason is named")
			assert_contains(logged, "no usable RADIUS authentication server",
				"and so is what was missing")
			-- A server, but a hostapd with no RADIUS client: auth_server_addr is
			-- an unknown option to a basic wpad, which refuses the whole config,
			-- so the BSS would not come up anyway.
			vt, logged = run("aaa.1.ssid=guest\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.secret=a\n"
				.. "aaa.1.radius.macacl.status=enabled\n" .. tail, false)
			assert_eq(#vt, 0, "no RADIUS client, no WLAN")
			assert_contains(logged, "no RADIUS client", "and that is said plainly")
			-- The same WLAN without MAC authentication is untouched by any of it.
			vt = run("aaa.1.ssid=guest\naaa.1.radius.macacl.status=disabled\n" .. tail, false)
			assert_eq(#vt, 1, "a plain open WLAN is provisioned either way")
		end
	},
	{
		name = "inform packet: Dynamic Authorization is read in the das shape only",
		fn = function()
			-- The controller sends CoA/Disconnect twice over: the das.* shape names
			-- the client directly, the dad.* shape expects the AP's own daemon to
			-- relay it from 127.0.0.1. openUF has no relay, so only das.* is read.
			local base = "aaa.1.ssid=corp\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\n"
				.. "aaa.1.radius.auth.1.ip=192.0.2.10\naaa.1.radius.auth.1.secret=a\n"
			local tail = "wireless.1.ssid=corp\nwireless.1.parent=radio0\n"
			local function r(extra)
				local vt, logged
				logged = with_stderr(function()
					local _
					_, vt = inform._parse_wifi_system_cfg(base .. extra .. tail)
				end)
				assert_eq(#vt, 1, "provisioned")
				return vt[1].radius, logged
			end
			local rad = r("aaa.1.radius.das.status=enabled\naaa.1.radius.das.port=3801\n"
				.. "aaa.1.radius.das.client=192.0.2.11\naaa.1.radius.das.secret=b\n"
				.. "aaa.1.radius.dad.status=enabled\n"
				.. "aaa.1.radius.dad.client.1.cidr=192.0.2.11/32\n"
				.. "aaa.1.radius.dad.client.1.secret=c\n")
			assert_eq(rad.das.client, "192.0.2.11", "the client the server will call from")
			assert_eq(rad.das.secret, "b", "its shared secret")
			assert_eq(rad.das.port, "3801", "the controller's own port (3800 + index)")
			assert_nil(rad.dad, "the dad shape derives nothing")
			-- RFC 5176's default, and the firmware's fallback.
			assert_eq(r("aaa.1.radius.das.status=enabled\n"
				.. "aaa.1.radius.das.client=192.0.2.11\n"
				.. "aaa.1.radius.das.secret=b\n").das.port, "3799", "default port")
			-- Absence, and an explicit off, are both "no listener".
			assert_nil(r("").das, "absent is off")
			assert_nil(r("aaa.1.radius.das.status=disabled\n"
				.. "aaa.1.radius.das.client=192.0.2.11\n"
				.. "aaa.1.radius.das.secret=b\n").das, "disabled is off")
			-- Each refusal is named, and never with the secret in it.
			local function refused(extra, why)
				local rad2, logged = r("aaa.1.radius.das.status=enabled\n" .. extra)
				assert_nil(rad2.das, "nothing is written for: " .. why)
				assert_contains(logged, why, "the reason is logged")
				assert_true(logged:find("sekrit", 1, true) == nil,
					"and the secret is not")
			end
			refused("aaa.1.radius.das.client=not-an-ip\naaa.1.radius.das.secret=sekrit\n",
				"no usable IPv4 client address")
			refused("aaa.1.radius.das.client=192.0.2.11\naaa.1.radius.das.secret=\n",
				"missing or oversized shared secret")
			-- A newline cannot reach here (the tokenizer splits on it), but a
			-- tab can, and radius_das_client is a single hostapd line.
			refused('aaa.1.radius.das.client=192.0.2.11\n'
				.. "aaa.1.radius.das.secret=sek\trit\n",
				"a control character in the shared secret")
		end
	},
	{
		name = "inform packet: handle_response setparam applies DNS servers in wire order",
		fn = function()
			-- resolv.nameserver.<k>.ip is part of the same "IP Settings" push as
			-- netconf/route (PROTOCOL-VALIDATION.md). <k> is the controller's
			-- primary/secondary ordering and is load-bearing -- resolv.conf's
			-- line order is the resolver's preference order -- so the blob
			-- below deliberately lists index 2 before index 1.
			--
			-- Note this does NOT prove the parser's table.sort: for contiguous
			-- keys 1..n Lua's pairs() walks the array part in order anyway, so
			-- this passes with the sort removed (mutation-tested). The sort is
			-- there for SPARSE indices (1 and 5, say), where the hash part's
			-- iteration order is unspecified and genuinely needs it -- a case
			-- no deterministic test can pin down.
			local st = sample_state()
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local cfg = {net = {lan_cpueth = "eth0"}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50\\n'
				.. 'netconf.1.netmask=255.255.255.0\\nroute.1.gateway=172.19.0.1\\n'
				.. 'resolv.nameserver.2.ip=8.8.8.8\\nresolv.nameserver.1.ip=192.168.1.1\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._netconfig._exec = orig
			assert_eq(#cmds, 4, "flush, add, route, resolv.conf")
			assert_contains(cmds[4], "'nameserver 192.168.1.1' 'nameserver 8.8.8.8'",
				"emitted in wire-index order")
			assert_eq(st.static_dns[1], "192.168.1.1", "primary DNS persisted first")
			assert_eq(st.static_dns[2], "8.8.8.8", "secondary DNS persisted second")
		end
	},
	{
		name = "inform packet: handle_response leaves DNS alone on the dhcp path",
		fn = function()
			-- The lease supplies DNS. Rewriting resolv.conf on every
			-- steady-state "still DHCP" push would fight the DHCP client for
			-- ownership -- same hazard as the flush+re-lease guard above.
			local st = sample_state({ip_mode = "static", static_dns = {"1.1.1.1"}})
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				return true
			end
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.2\\n'
				.. 'dhcpc.1.status=enabled\\nresolv.nameserver.1.ip=192.168.1.1\\n"}'
			inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			inform._netconfig._exec = orig
			assert_eq(st.static_dns, nil, "stale static DNS cleared from state")
			for _, cmd in ipairs(cmds) do
				assert_nil(cmd:find("resolv.conf", 1, true), "resolv.conf never written on dhcp")
			end
		end
	},
	{
		name = "inform packet: handle_response records but does not apply a static IP without cfg.net",
		fn = function()
			-- Same nil-safety convention as cfg.led -- absent per-model
			-- interface config means nothing touches the host. The blob is
			-- NOT fully ignored, though (the old test name overstated): the
			-- static intent is still recorded in state so a later push/reload
			-- knows the controller's assignment. Pin both halves: recorded
			-- yes, applied no.
			local st = sample_state()
			local cmds = {}
			local orig = inform._netconfig._exec
			inform._netconfig._exec = function(cmd) cmds[#cmds + 1] = cmd; return true end
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50\\n"}'
			local ok = pcall(inform.handle_response, resp, st, nil)
			inform._netconfig._exec = orig
			assert_true(ok, "no error without cfg")
			assert_eq(st.ip_mode, "static", "static intent still recorded in state")
			assert_eq(st.static_ip, "172.19.0.50", "static address recorded")
			assert_eq(#cmds, 0, "no interface command issued without cfg.net")
			assert_eq(st.ip, "192.168.1.100", "live st.ip untouched")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg extracts vap_table and radio_table from a real captured blob",
		fn = function()
			-- Real captured shape (PROTOCOL-VALIDATION.md, feature matrix:
			-- SSID push): WiFi config arrives as flat
			-- aaa.<n>.*/wireless.<n>.*/radio.<n>.*
			-- keys, not resp.vap_table/radio_table JSON.
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.channel=auto\nradio.1.txpower=auto\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=36\nradio.2.txpower=17\n"
				.. "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.psk=TestPass123\n"
				.. "aaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.ft.status=disabled\n"
				.. "aaa.1.id=6a540dd2ffb26b8537ec967d\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.security=none\n"
			local radio_table, vap_table = inform._parse_wifi_system_cfg(sys_cfg)

			assert_eq(#radio_table, 2, "two radios parsed")
			assert_eq(radio_table[1].name, "radio0", "radio 1 name from phyname")
			assert_eq(radio_table[1].channel, "auto",
				"channel=auto passes through verbatim (UCI auto -> hostapd ACS; nil would strand a stale fixed channel)")
			assert_eq(radio_table[1].tx_power, "auto",
				"txpower=auto passes through as a sentinel (rf_config deletes the UCI option for it)")
			assert_eq(radio_table[2].name, "radio1", "radio 2 name from phyname")
			assert_eq(radio_table[2].channel, 36, "explicit channel parsed as a number")
			assert_eq(radio_table[2].tx_power, 17, "explicit tx_power parsed as a number")

			assert_eq(#vap_table, 1, "one vap parsed (only wireless.1.* present)")
			assert_eq(vap_table[1].ssid, "openuf-test", "ssid from wireless.1.ssid")
			assert_eq(vap_table[1].radio, "radio0", "radio from wireless.1.parent")
			assert_eq(vap_table[1].security, "wpa2", "security derived from aaa.1.wpa=2")
			assert_eq(vap_table[1].x_passphrase, "TestPass123", "passphrase from aaa.1.wpa.psk")
			assert_eq(vap_table[1].wlanconf_id, "6a540dd2ffb26b8537ec967d",
				"wlanconf id from aaa.1.id (echoed back as vap_table[].id; without it the controller drops the vap)")
			assert_eq(vap_table[1].fast_roaming_enabled, false, "ft.status=disabled -> fast roaming off")
			assert_eq(vap_table[1].vlan_enabled, false, "no br.devname suffix -> vlan not enabled")
			assert_eq(vap_table[1].vlan, nil, "no vlan id without a tagged br.devname")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg extracts VLAN id from a tagged br.devname",
		fn = function()
			-- Real captured shape (PROTOCOL-VALIDATION.md, feature matrix:
			-- VLAN-tagged network): assigning a WiFi network to a
			-- VLAN-tagged network changes aaa.<n>.br.devname
			-- from "br0" to "br0.<vlan>" -- the only field that carries the
			-- VLAN id in this wire format (no separate vap->network join).
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.psk=TestPass123\n"
				.. "aaa.1.br.devname=br0.20\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 1, "one vap parsed")
			assert_eq(vap_table[1].vlan_enabled, true, "tagged br.devname enables vlan")
			assert_eq(vap_table[1].vlan, 20, "vlan id parsed from br0.20")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg extracts minrssi from stamgr.<n> onto radio_table",
		fn = function()
			-- Real captured shape (2026-07-14): "Minimum RSSI" lives under
			-- Devices -> [AP] -> Radios, per-radio (not per-SSID) -- a new
			-- stamgr.<n> section, indexed the same as radio.<n>, entirely
			-- separate from aaa.<n>/wireless.<n>. minrssi.rssi is NOT plain
			-- dBm (UI "-80 dBm" captured as wire value 15) -- parsing keeps
			-- the raw wire units; conversion happens later where a live
			-- noise-floor reading exists.
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.channel=auto\nradio.1.txpower=auto\n"
				.. "stamgr.1.status=true\nstamgr.1.radio=ng\n"
				.. "stamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=15\n"
				.. "stamgr.1.loadbalance.status=false\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=36\nradio.2.txpower=17\n"
			local radio_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#radio_table, 2, "two radios parsed")
			assert_eq(radio_table[1].min_rssi_enabled, true, "radio0 minrssi enabled")
			assert_eq(radio_table[1].min_rssi, 15, "radio0 minrssi raw wire value (not dBm)")
			-- Explicit false, not nil: an absent stamgr block is the wire's
			-- disable signal, and nil would let a stale minrssi_enabled=1
			-- survive in UCI (rf_config skips nil), keeping the deauth
			-- enforcement running after the user turned the feature off.
			assert_eq(radio_table[2].min_rssi_enabled, false, "radio1 has no stamgr block -> explicitly off")
			assert_eq(radio_table[2].min_rssi, nil, "radio1 has no minrssi value")
		end
	},
	{
		name = "inform packet: disabling Minimum RSSI clears the UCI flag (parse -> apply, two pushes)",
		fn = function()
			-- Mutation test for the stale-enforcement bug: push #1 enables
			-- Minimum RSSI, push #2's blob has no stamgr block (the wire's
			-- disable convention). Before the fix, push #2 parsed to nil,
			-- rf_config skipped the write, and UCI kept minrssi_enabled=1 --
			-- so openUF kept one-shot-deauthing weak clients forever.
			local ucihelper, db = new_apply_env()
			local on_blob = "radio.1.phyname=radio0\nradio.1.channel=6\n"
				.. "stamgr.1.status=true\nstamgr.1.radio=ng\n"
				.. "stamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=15\n"
			local off_blob = "radio.1.phyname=radio0\nradio.1.channel=6\n"

			local rt, vt = inform._parse_wifi_system_cfg(on_blob)
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(db.wireless.radio0.minrssi_enabled, "1", "push 1: enforcement enabled")
			assert_eq(db.wireless.radio0.minrssi_rssi, "15", "push 1: raw threshold stored")
			assert_eq(db.wireless.radio0.rssi_reject_assoc_rssi, "-77",
				"push 1: hostapd refuses association below -80 + 3 dBm")
			assert_eq(db.wireless.radio0.rssi_ignore_probe_request, "-77",
				"push 1: and ignores probes there")

			rt, vt = inform._parse_wifi_system_cfg(off_blob)
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(db.wireless.radio0.minrssi_enabled, "0",
				"push 2 (stamgr absent): enforcement flag explicitly cleared")
			assert_nil(db.wireless.radio0.rssi_reject_assoc_rssi, "push 2: refusal removed")
			assert_nil(db.wireless.radio0.rssi_ignore_probe_request, "push 2: probe filter removed")
			assert_nil(db.wireless.radio0.openuf_minrssi, "push 2: stamp removed")
		end
	},
	{
		name = "inform packet: Load balance's cap is parsed from stamgr.<n> and stored, and removed when off",
		fn = function()
			-- Captured from the lab (10.4.57, 2026-10-10): Load balance on for
			-- radio0 with maxsta 3 and Minimum RSSI off. Turning it off made the
			-- whole stamgr.<n> block disappear.
			local ucihelper, db = new_apply_env()
			local on_blob = "radio.1.phyname=radio0\nradio.1.channel=6\n"
				.. "stamgr.1.status=true\nstamgr.1.radio=ng\n"
				.. "stamgr.1.minrssi.status=false\nstamgr.1.minrssi.rssi=15\n"
				.. "stamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=3\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=36\n"
			local off_blob = "radio.1.phyname=radio0\nradio.1.channel=6\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=36\n"

			local rt, vt = inform._parse_wifi_system_cfg(on_blob)
			assert_eq(rt[1].loadbalance_maxsta, 3, "radio0's cap")
			assert_eq(rt[1].min_rssi_enabled, false, "Minimum RSSI stays off beside it")
			assert_eq(rt[2].loadbalance_maxsta, false, "radio1 has no stamgr block: explicitly off")
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(db.wireless.radio0.loadbalance_maxsta, "3", "push 1: cap stored")
			assert_nil(db.wireless.radio1.loadbalance_maxsta, "push 1: radio1 has none")

			rt, vt = inform._parse_wifi_system_cfg(off_blob)
			assert_eq(rt[1].loadbalance_maxsta, false, "push 2: off")
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_nil(db.wireless.radio0.loadbalance_maxsta, "push 2: cap removed")
		end
	},
	{
		name = "inform packet: Load balance is off unless status is true and maxsta is positive",
		fn = function()
			local function cap(lines)
				return inform._parse_wifi_system_cfg("radio.1.phyname=radio0\n"
					.. "stamgr.1.status=true\nstamgr.1.radio=ng\n" .. lines)[1].loadbalance_maxsta
			end
			assert_eq(cap("stamgr.1.loadbalance.status=false\nstamgr.1.loadbalance.maxsta=3\n"), false,
				"status false: off, whatever maxsta says")
			assert_eq(cap("stamgr.1.loadbalance.status=true\n"), false, "no maxsta: off")
			assert_eq(cap("stamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=0\n"), false, "0: off")
			assert_eq(cap("stamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=null\n"), false,
				"not a number: off")
			assert_eq(cap("stamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=1\n"), 1, "1: on")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps radio.<n>.ieee_mode onto htmode",
		fn = function()
			-- CONFIRMED live 2026-07-18: a stock dual-band AP sends
			-- 11nght20 on 2.4GHz and 11naht40 on 5GHz, and flipping the
			-- per-device "2.4 GHz Channel Width" to 40 changes exactly this
			-- key to 11nght40. It is the wire's only channel-width signal.
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.channel=auto\n"
				.. "radio.1.ieee_mode=11nght20\n"
				.. "radio.2.phyname=radio1\nradio.2.channel=36\n"
				.. "radio.2.ieee_mode=11naht40\n"
			-- Hardware capabilities unknown (no `iw`): the token is read
			-- literally, which is the conservative fallback, not the answer.
			local radio_table = with_best_phy(nil, function()
				return inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(radio_table[1].htmode, "HT20", "11nght20 -> HT20")
			assert_eq(radio_table[2].htmode, "HT40", "11naht40 -> HT40")
		end
	},
	{
		name = "inform packet: a plain 'ht' ieee_mode takes the band's real PHY, not 802.11n",
		fn = function()
			-- The wire's vocabulary is Atheros-era -- the same push names the
			-- VAPs ath0/ath1/ath2 -- and "11naht40" is all a real controller
			-- ever sends, to a real U6-InWall as much as to us. It carries the
			-- BAND and the WIDTH; the PHY generation is the device's own
			-- business. Reading the "ht" literally pinned an 802.11ax radio to
			-- 802.11n forever: confirmed live on an AX3000T whose 5GHz radio
			-- came up HT40 on hardware that does HE160 (and runs HE40 fine).
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.ieee_mode=11nght20\n"
				.. "radio.2.phyname=radio1\nradio.2.ieee_mode=11naht40\n"
			local t = with_best_phy({ng = "HE", na = "HE"}, function()
				return inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(t[1].htmode, "HE20", "the 2.4GHz radio runs HE at the pushed width")
			assert_eq(t[2].htmode, "HE40", "and so does the 5GHz one")

			-- The width always comes from the wire, never from the hardware:
			-- this is a PHY upgrade, not a widening.
			local wide = with_best_phy({na = "EHT"}, function()
				return inform._parse_wifi_system_cfg(
					"radio.1.phyname=radio0\nradio.1.ieee_mode=11naht20\n")
			end)
			assert_eq(wide[1].htmode, "EHT20", "40 was not asked for, so 20 it stays")

			-- An HT-only radio is unchanged, which is the whole reason this
			-- was invisible until 802.11ax hardware arrived.
			local legacy = with_best_phy({ng = "HT", na = "HT"}, function()
				return inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(legacy[2].htmode, "HT40", "an n-only radio still gets HT40")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps 11ac/11ax/11be ieee_mode tokens",
		fn = function()
			-- An explicit PHY token is honoured as written, even when the
			-- hardware could do better: only the bare "ht" default is treated
			-- as "the wire is not saying".
			local cases = {
				["11acvht80"] = "VHT80",
				["11axhe80"]  = "HE80",
				["11axhe160"] = "HE160",
				["11beeht320"] = "EHT320",
			}
			for token, expected in pairs(cases) do
				local sys_cfg = "radio.1.phyname=radio0\nradio.1.ieee_mode=" .. token .. "\n"
				-- "any": the stub answers EHT whatever it is asked, so this
				-- cannot pass just because the capability lookup missed.
				local radio_table = with_best_phy("any", function()
					return inform._parse_wifi_system_cfg(sys_cfg)
				end)
				assert_eq(radio_table[1].htmode, expected, token .. " -> " .. expected)
			end
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves htmode nil for absent/garbage ieee_mode",
		fn = function()
			-- nil means "leave the radio's current width alone", the same
			-- convention txpower=auto uses (channel=auto instead passes through
			-- verbatim to engage ACS). Garbage must never reach UCI as an
			-- htmode value.
			local absent = inform._parse_wifi_system_cfg("radio.1.phyname=radio0\n")
			assert_eq(absent[1].htmode, nil, "no ieee_mode key -> nil")
			for _, token in ipairs({ "auto", "11ng", "11nght", "nght20", "11nght33", "" }) do
				local t = inform._parse_wifi_system_cfg(
					"radio.1.phyname=radio0\nradio.1.ieee_mode=" .. token .. "\n")
				assert_eq(t[1].htmode, nil, "unrecognized ieee_mode '" .. token .. "' -> nil")
			end
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.iot/qbssload (Force WiFi 4)",
		fn = function()
			-- CONFIRMED live 2026-07-18: "Force WiFi 4 Mode" (IoT
			-- Optimization) emits both keys together on the WLAN's 2.4GHz
			-- wireless.<n> entry; they are absent entirely when it is off.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.iot=enabled\nwireless.1.qbssload=disabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].iot, true, "iot=enabled -> true")
			assert_eq(vap_table[1].qbssload, false, "qbssload=disabled -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves iot/qbssload nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].iot, nil, "no iot key -> nil")
			assert_eq(vap_table[1].qbssload, nil, "no qbssload key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.uapsd both ways",
		fn = function()
			-- 10.x always emits it, from wlanconf uapsd_enabled (default false).
			local base = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, off = inform._parse_wifi_system_cfg(base .. "wireless.1.uapsd=disabled\n")
			assert_eq(off[1].uapsd, false, "uapsd=disabled -> false")
			local _, on = inform._parse_wifi_system_cfg(base .. "wireless.1.uapsd=enabled\n")
			assert_eq(on[1].uapsd, true, "uapsd=enabled -> true")
			local _, none = inform._parse_wifi_system_cfg(base)
			assert_eq(none[1].uapsd, nil, "no uapsd key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg reads the per-station SAE keys (sae.psk.<n>)",
		fn = function()
			local base = "aaa.1.ssid=sae-keys\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=SAE\n"
				.. "wireless.1.ssid=sae-keys\nwireless.1.parent=radio0\n"
			local _, v = inform._parse_wifi_system_cfg(base
				.. "aaa.1.sae.psk.1.psk=mainpass123\naaa.1.sae.psk.1.mac=ff:ff:ff:ff:ff:ff\n"
				.. "aaa.1.sae.psk.2.psk=stationkey1\naaa.1.sae.psk.2.mac=AA:BB:CC:DD:EE:01\n"
				.. "aaa.1.sae.psk.2.vlan=30\naaa.1.sae.psk.2.id=phone\n"
				.. "aaa.1.sae.psk.3.psk=anystation1\n"
				.. "aaa.1.sae.psk.4.psk=short\n"
				.. "aaa.1.sae.psk.5.psk=badvlankey1\naaa.1.sae.psk.5.vlan=9999\n"
				.. "aaa.1.sae.psk.6.psk=badmackey11\naaa.1.sae.psk.6.mac=zz\n")
			local p = v[1].ppsk
			assert_eq(#p, 2, "main key (ff:..), short key, bad VLAN and bad MAC are left out")
			assert_eq(p[1].key, "stationkey1", "key 2")
			assert_eq(p[1].vid, 30, "its VLAN")
			assert_eq(p[1].mac, "aa:bb:cc:dd:ee:01", "its station, lowercased")
			assert_eq(p[2].key, "anystation1", "key 3")
			assert_nil(p[2].mac, "no mac: any station")
			-- The same key arriving through psk_file too is one key.
			local _, d = inform._parse_wifi_system_cfg(base
				.. "aaa.1.wpa.psk_file.status=enabled\naaa.1.wpa.psk_file.1.psk=anystation1\n"
				.. "aaa.1.sae.psk.2.psk=anystation1\n")
			assert_eq(#d[1].ppsk, 1, "psk_file + sae.psk duplicates collapse")
			local _, none = inform._parse_wifi_system_cfg(base)
			assert_nil(none[1].ppsk, "no keys -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses the SAE tuning keys",
		fn = function()
			local base = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, v = inform._parse_wifi_system_cfg(base
				.. "aaa.1.sae.anti_clogging=5\naaa.1.sae.sync=7\n"
				.. "aaa.1.sae.has_groups=enabled\n"
				.. "aaa.1.sae.groups.2.group=20\naaa.1.sae.groups.1.group=19\n")
			assert_eq(v[1].sae_anti_clogging, "5", "anti_clogging")
			assert_eq(v[1].sae_sync, "7", "sync")
			assert_eq(v[1].sae_groups, "19 20", "groups sorted by index")
			local _, bad = inform._parse_wifi_system_cfg(base
				.. "aaa.1.sae.anti_clogging=0\naaa.1.sae.sync=x\n"
				.. "aaa.1.sae.has_groups=enabled\naaa.1.sae.groups.1.group=19;x\n")
			assert_eq(bad[1].sae_anti_clogging, nil, "0 is off")
			assert_eq(bad[1].sae_sync, nil, "non-numeric")
			assert_eq(bad[1].sae_groups, nil, "non-numeric group")
			local _, none = inform._parse_wifi_system_cfg(base)
			assert_eq(none[1].sae_groups, nil, "no keys -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.wpa.group_rekey",
		fn = function()
			local base = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			for _, c in ipairs({{"3600", "3600"}, {"0", "0"}, {"0600", "600"},
					{"-1", nil}, {"1h", nil}, {"9999999999", nil}}) do
				local _, v = inform._parse_wifi_system_cfg(base .. "aaa.1.wpa.group_rekey=" .. c[1] .. "\n")
				assert_eq(v[1].group_rekey, c[2], "group_rekey=" .. c[1])
			end
			local _, none = inform._parse_wifi_system_cfg(base)
			assert_eq(none[1].group_rekey, nil, "no group_rekey key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.11k.status",
		fn = function()
			local base = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			for _, c in ipairs({{"enabled", true}, {"disabled", false}}) do
				local _, v = inform._parse_wifi_system_cfg(base .. "aaa.1.11k.status=" .. c[1] .. "\n")
				assert_eq(v[1].rrm, c[2], "11k.status=" .. c[1])
			end
			local _, none = inform._parse_wifi_system_cfg(base)
			assert_eq(none[1].rrm, nil, "no 11k.status key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.bss_transition",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.bss_transition=1\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bss_transition, true, "bss_transition=1 -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.bss_transition=0 as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.bss_transition=0\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bss_transition, false, "bss_transition=0 -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves bss_transition nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bss_transition, nil, "no bss_transition key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg reads wireless.<n>.dtim_period regardless of Auto/Custom",
		fn = function()
			-- CONFIRMED live 2026-07-15: wireless.<n>.dtim_period is always a
			-- plain int on the wire, whether the WLAN's DTIM toggle is left
			-- on Auto or set to Custom -- there is no separate dtim_mode/
			-- dtim_ng/dtim_na key at all (an earlier version of this parser
			-- guessed such a scheme and was wrong).
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.dtim_period=1\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].dtim_period, 1, "dtim_period read directly from wireless.1.dtim_period")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg reads a custom wireless.<n>.dtim_period on radio1 (5GHz)",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio1\nwireless.1.dtim_period=9\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].dtim_period, 9, "custom dtim_period read regardless of band")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves dtim_period nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].dtim_period, nil, "no dtim_period key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.pmf.status/mode (802.11w)",
		fn = function()
			-- CONFIRMED live 2026-07-18 (Humans+IoT validation): a WPA2/WPA3
			-- mixed WLAN's PMF-optional intent rides these two fields.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.pmf.status=enabled\naaa.1.pmf.mode=1\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].pmf_status, "enabled", "pmf.status read verbatim")
			assert_eq(vap_table[1].pmf_mode, 1, "pmf.mode parsed as int")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses pmf.status=disabled/mode=0",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.pmf.status=disabled\naaa.1.pmf.mode=0\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].pmf_status, "disabled", "pmf.status=disabled")
			assert_eq(vap_table[1].pmf_mode, 0, "pmf.mode=0")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves pmf fields nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].pmf_status, nil, "no pmf.status -> nil")
			assert_eq(vap_table[1].pmf_mode, nil, "no pmf.mode -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.mcast.enhance=1",
		fn = function()
			-- Real key lives on the wireless.<n> block (like dtim_period);
			-- the "\nwireless." dump text once misread as an "nwireless"
			-- section is just the escaped newline before the wireless key.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.mcast.enhance=1\nwireless.1.mcastrate=auto\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mcast_enhance, true, "mcast.enhance=1 -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.mcast.enhance=0 as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.mcast.enhance=0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mcast_enhance, false, "mcast.enhance=0 -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves mcast_enhance nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mcast_enhance, nil, "no mcast.enhance key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.proxy_arp",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.proxy_arp=enabled\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].proxy_arp, true, "proxy_arp=enabled -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.proxy_arp=disabled as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.proxy_arp=disabled\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].proxy_arp, false, "proxy_arp=disabled -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves proxy_arp nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].proxy_arp, nil, "no proxy_arp key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.l2_isolation",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.l2_isolation=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].l2_isolation, true, "l2_isolation=enabled -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses l2_isolation=disabled as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.l2_isolation=disabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].l2_isolation, false, "l2_isolation=disabled -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves l2_isolation nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].l2_isolation, nil, "no l2_isolation key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.hide_ssid",
		fn = function()
			-- Note the true/false vocabulary here, not enabled/disabled.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.hide_ssid=true\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].hide_ssid, true, "hide_ssid=true -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses hide_ssid=false as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.hide_ssid=false\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].hide_ssid, false, "hide_ssid=false -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves hide_ssid nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].hide_ssid, nil, "no hide_ssid key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses the macacl MAC filter",
		fn = function()
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"macacl.status=enabled",
				"macacl.1.devname=ath0", "macacl.1.status=enabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=allow",
				"macacl.1.acl.1.mac=02:11:22:33:44:55",
				"macacl.1.acl.1.status=enabled", "macacl.1.acl.1.type=user",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mac_filter_policy, "allow", "policy parsed")
			assert_eq(vap_table[1].mac_filter_list[1], "02:11:22:33:44:55", "MAC collected")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg joins macacl on devname, not index",
		fn = function()
			-- The real wire numbers macacl blocks independently of wireless.<n>
			-- -- here the filtered vap is wireless.2/ath1 but its macacl block
			-- is macacl.1. An index-based implementation would misfile this
			-- onto the first vap.
			local sys_cfg = table.concat({
				"aaa.1.ssid=open-a", "aaa.1.wpa=2",
				"wireless.1.ssid=open-a", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"aaa.2.ssid=open-b", "aaa.2.wpa=2",
				"wireless.2.ssid=open-b", "wireless.2.parent=radio0",
				"wireless.2.devname=ath1",
				"macacl.status=enabled",
				"macacl.1.devname=ath1", "macacl.1.status=enabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=deny",
				"macacl.1.acl.1.mac=aa:bb:cc:dd:ee:ff",
				"macacl.1.acl.1.status=enabled", "macacl.1.acl.1.type=user",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mac_filter_policy, nil, "unfiltered vap untouched")
			assert_eq(vap_table[2].mac_filter_policy, "deny", "filter landed on the ath1 vap")
			assert_eq(vap_table[2].mac_filter_list[1], "aa:bb:cc:dd:ee:ff", "its MAC too")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg sorts the MAC filter list",
		fn = function()
			-- <k> ordering is meaningless on the wire (same as bcfilt), so the
			-- list is sorted to stay comparable across pushes.
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"macacl.status=enabled",
				"macacl.1.devname=ath0", "macacl.1.status=enabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=allow",
				"macacl.1.acl.1.mac=ff:ff:00:00:00:01",
				"macacl.1.acl.1.status=enabled", "macacl.1.acl.1.type=user",
				"macacl.1.acl.2.mac=00:00:00:00:00:02",
				"macacl.1.acl.2.status=enabled", "macacl.1.acl.2.type=user",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mac_filter_list[1], "00:00:00:00:00:02", "sorted first")
			assert_eq(vap_table[1].mac_filter_list[2], "ff:ff:00:00:00:01", "sorted second")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg ignores a disabled macacl block",
		fn = function()
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"macacl.status=disabled",
				"macacl.1.devname=ath0", "macacl.1.status=disabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=allow",
				"macacl.1.acl.1.mac=02:11:22:33:44:55",
				"macacl.1.acl.1.status=enabled", "macacl.1.acl.1.type=user",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mac_filter_policy, nil, "disabled block -> no filter")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg ignores wireless.<n>.mac_acl decoys",
		fn = function()
			-- These keys are present on the real wire with the control OFF and
			-- must never be mistaken for the feature.
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"wireless.1.mac_acl.status=enabled",
				"wireless.1.mac_acl.policy=deny",
				"aaa.1.radius.macacl.status=disabled",
				"macacl.status=disabled",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].mac_filter_policy, nil, "decoy keys do not enable the filter")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses the qos speed limit",
		fn = function()
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"qos.status=enabled", "qos.mode=1",
				"qos.vap.1.devname=ath0", "qos.vap.1.id=1",
				"qos.vap.1.dwnlink.maxspeed=33000",
				"qos.vap.1.dwnlink.minspeed=33000",
				"qos.vap.1.uplink.1.devname=eth0",
				"qos.vap.1.uplink.1.maxspeed=17000",
				"qos.vap.1.uplink.1.minspeed=17000",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].ratelimit_down_kbps, 33000, "downlink kbps parsed")
			assert_eq(vap_table[1].ratelimit_up_kbps, 17000, "uplink kbps parsed")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg treats a minspeed-only qos block as unlimited",
		fn = function()
			-- The real wire emits a qos.vap block for EVERY vap. An unlimited
			-- one carries only minspeed, set to that radio's raw devspeed.
			-- Reading the block's existence as "limited" would cap every WLAN
			-- at its own PHY rate.
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"qos.status=enabled",
				"qos.vap.1.devname=ath0", "qos.vap.1.id=1",
				"qos.vap.1.dwnlink.minspeed=570",
				"qos.vap.1.uplink.1.devname=eth0",
				"qos.vap.1.uplink.1.minspeed=570",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].ratelimit_down_kbps, nil, "no maxspeed -> unlimited")
			assert_eq(vap_table[1].ratelimit_up_kbps, nil, "no maxspeed -> unlimited")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg joins qos on devname, not index",
		fn = function()
			-- Same hazard as macacl: qos.vap indices are their own sequence.
			local sys_cfg = table.concat({
				"aaa.1.ssid=open-a", "aaa.1.wpa=2",
				"wireless.1.ssid=open-a", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"aaa.2.ssid=open-b", "aaa.2.wpa=2",
				"wireless.2.ssid=open-b", "wireless.2.parent=radio0",
				"wireless.2.devname=ath1",
				"qos.status=enabled",
				"qos.vap.1.devname=ath1",
				"qos.vap.1.dwnlink.maxspeed=12000",
			}, "\n") .. "\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].ratelimit_down_kbps, nil, "uncapped vap untouched")
			assert_eq(vap_table[2].ratelimit_down_kbps, 12000, "cap landed on the ath1 vap")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg collects the bcfilt allow-list",
		fn = function()
			-- The wire index is 1-based and does not follow the REST list's
			-- order, so the parser sorts -- assert the sorted result.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.bcfilt.status=enabled\n"
				.. "wireless.1.bcfilt.1.mac=bb:bb:bb:bb:bb:bb\n"
				.. "wireless.1.bcfilt.1.status=enabled\n"
				.. "wireless.1.bcfilt.2.mac=aa:aa:aa:aa:aa:aa\n"
				.. "wireless.1.bcfilt.2.status=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			local v = vap_table[1]
			assert_eq(v.bcfilt_enabled, true, "bcfilt.status=enabled -> true")
			assert_eq(#v.bcfilt_macs, 2, "both MACs collected")
			assert_eq(v.bcfilt_macs[1], "aa:aa:aa:aa:aa:aa", "sorted, not wire order")
			assert_eq(v.bcfilt_macs[2], "bb:bb:bb:bb:bb:bb", "sorted, not wire order")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg skips bcfilt entries that are not enabled",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.bcfilt.status=enabled\n"
				.. "wireless.1.bcfilt.1.mac=aa:aa:aa:aa:aa:aa\n"
				.. "wireless.1.bcfilt.1.status=disabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bcfilt_macs, nil, "disabled entry not collected")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg handles the blocker on with an empty list",
		fn = function()
			-- Confirmed live: enabling the control with no excepted devices
			-- emits bcfilt.status and no entry keys at all.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.bcfilt.status=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bcfilt_enabled, true, "still enabled")
			assert_eq(vap_table[1].bcfilt_macs, nil, "no allow-list")
		end
	},
	{
		name = "inform packet: Aggressive multicast suppression carries the bypass types",
		fn = function()
			-- Verbatim from the lab, 2026-10-27: both band entries of one WLAN
			-- after setting multicast_suppressor_mode=aggressive with the
			-- device claiming wifi_caps2 0x400000. bypass_types is ONE key
			-- holding the whole pipe-separated list.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.multicast.suppressor=enabled\n"
				.. "wireless.1.bcfilt.status=enabled\n"
				.. "wireless.1.bcfilt.bypass_types=ARP|NSNA|DHCPV4|DHCPV6\n"
				.. "wireless.1.bcfilt.1.status=enabled\n"
				.. "wireless.1.bcfilt.1.mac=00:00:5e:00:53:01\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			local v = vap_table[1]
			assert_eq(v.mcast_suppressor, true, "the suppressor key is read")
			assert_eq(v.bcfilt_enabled, true, "and it is the Aggressive pair")
			for _, tok in ipairs({"ARP", "NSNA", "DHCPV4", "DHCPV6"}) do
				assert_eq(v.bcfilt_bypass[tok], true, "bypass type " .. tok)
			end
			assert_eq(v.bcfilt_macs[1], "00:00:5e:00:53:01", "allow-list still read")
		end
	},
	{
		name = "inform packet: Conservative multicast suppression arrives without a bcfilt block",
		fn = function()
			-- Verbatim from the lab, 2026-10-27, same WLAN set to
			-- multicast_suppressor_mode=conservative: the suppressor key alone,
			-- with no bcfilt.* of any kind. That absence IS the mode -- the
			-- wire never names it -- so it is asserted, not assumed.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.multicast.inspect=false\n"
				.. "wireless.1.multicast.suppressor=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			local v = vap_table[1]
			assert_eq(v.mcast_suppressor, true, "suppression is on")
			assert_eq(v.bcfilt_enabled, nil, "and nothing is blocked")
			assert_eq(v.bcfilt_bypass, nil, "no bypass types with Conservative")
			-- multicast.inspect sits in the same block and is a decoy: it is
			-- constant across the toggle and openUF reads nothing from it.
			assert_eq(v.mcast_inspect, nil, "multicast.inspect stays unread")
		end
	},
	{
		name = "inform packet: an unknown bypass type is named and dropped, not guessed at",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.bcfilt.status=enabled\n"
				.. "wireless.1.bcfilt.bypass_types=ARP| dhcpv4 ||IGMP\n"
			local logged, vap_table
			local orig, buf = io.stderr, {}
			io.stderr = {write = function(_, ...)
				for _, x in ipairs({...}) do buf[#buf + 1] = tostring(x) end
			end}
			local ok, err = pcall(function()
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			io.stderr = orig
			logged = table.concat(buf)
			if not ok then error(err, 0) end
			local b = vap_table[1].bcfilt_bypass
			assert_eq(b.ARP, true, "the known token is kept")
			assert_eq(b.DHCPV4, true, "case and padding are normalised")
			assert_eq(b.IGMP, nil, "a token with no nft match is not honoured")
			assert_true(logged:find("unknown bypass type", 1, true) ~= nil,
				"and the refusal is logged by name")
			assert_true(logged:find("IGMP", 1, true) ~= nil, "naming the token")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves bcfilt fields nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].bcfilt_enabled, nil, "no bcfilt.status -> nil")
			assert_eq(vap_table[1].bcfilt_macs, nil, "no allow-list -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses the Minimum Data Rate keys",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "wireless.1.minrate_data=12000\nwireless.1.beacon_rate=12000\n"
				.. "wireless.1.minrate_cck_rates.status=false\n"
				.. "wireless.1.minrate_below_disable=true\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			local v = vap_table[1]
			assert_eq(v.minrate_data, 12000, "minrate_data in kb/s")
			assert_eq(v.beacon_rate, 12000, "beacon_rate mirrors the floor")
			assert_eq(v.minrate_cck, false, "12 Mbps floor excludes CCK")
			assert_eq(v.minrate_below_disable, true, "advertising-rates sub-toggle")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves Minimum Data Rate fields nil when absent",
		fn = function()
			-- The controller emits none of these when that band's Minimum Data
			-- Rate is off, which must leave the radio's rates untouched rather
			-- than reset to a default.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			local v = vap_table[1]
			assert_eq(v.minrate_data, nil, "no minrate_data -> nil")
			assert_eq(v.beacon_rate, nil, "no beacon_rate -> nil")
			assert_eq(v.minrate_cck, nil, "no cck status -> nil")
			assert_eq(v.minrate_below_disable, nil, "no below_disable -> nil")
		end
	},
	{
		-- End-to-end producer/consumer link test. Every other WiFi-field test
		-- checks ONE side: the parse tests assert on _parse_wifi_system_cfg's
		-- output, the ucihelper tests hand-build a vap_table and assert on UCI.
		-- Both keep passing if the two sides disagree on a field NAME (parse
		-- emits vap.proxy_arp, apply_config reads vap.proxyarp) -- which is the
		-- exact shape of bug this codebase has hit repeatedly (channel width,
		-- multicast enhancement, minimum RSSI: all parsed by nothing or applied
		-- from nothing, all invisible to per-side tests). This drives a real
		-- system_cfg blob all the way through to UCI so a rename on either side
		-- fails here.
		name = "inform packet: system_cfg -> parse -> apply_config reaches UCI (producer/consumer link)",
		fn = function()
			local ucihelper, db = new_apply_env()

			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-test", "aaa.1.wpa=2",
				"aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk=hunter22",
				"aaa.1.proxy_arp=enabled",
				"wireless.1.ssid=openuf-test", "wireless.1.parent=radio0",
				"wireless.1.l2_isolation=enabled",
				"wireless.1.hide_ssid=true", "wireless.1.devname=ath0",
				"macacl.status=enabled",
				"macacl.1.devname=ath0", "macacl.1.status=enabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=allow",
				"macacl.1.acl.1.mac=02:11:22:33:44:55",
				"macacl.1.acl.1.status=enabled", "macacl.1.acl.1.type=user",
				"qos.status=enabled",
				"qos.vap.1.devname=ath0",
				"qos.vap.1.dwnlink.maxspeed=33000",
				"qos.vap.1.uplink.1.maxspeed=17000",
				"wireless.1.minrate_data=12000", "wireless.1.beacon_rate=12000",
				"wireless.1.minrate_cck_rates.status=false",
				"wireless.1.minrate_below_disable=true",
				"radio.1.phyname=radio0", "radio.1.channel=6",
			}, "\n") .. "\n"

			local radio_table, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			ucihelper.apply_config({radio_table = radio_table, vap_table = vap_table}, nil)

			-- The hyphen is sanitized to "_": a UCI section name may only
			-- contain [A-Za-z0-9_], and libuci discards anything else without
			-- reporting an error. Because the name had to be altered, a short
			-- hash of the ORIGINAL SSID is appended, so two SSIDs differing
			-- only in punctuation cannot collapse onto one section.
			-- Bracket syntax, not a dotted key.
			local section = "openuf_radio0_openuf_test_"
				.. ucihelper.derive_mobility_domain("openuf-test")
			local s = db.wireless and db.wireless[section]
			assert_true(s ~= nil, "vap section created from a real system_cfg blob")
			assert_eq(s.proxy_arp, "1", "aaa.<n>.proxy_arp reached UCI proxy_arp")
			assert_eq(s.isolate, "1", "wireless.<n>.l2_isolation reached UCI isolate")
			assert_eq(s.hidden, "1", "wireless.<n>.hide_ssid reached UCI hidden")
			assert_eq(s.macfilter, "allow", "macacl.<m>.acl.policy reached UCI macfilter")
			assert_eq(s.maclist[1], "02:11:22:33:44:55", "macacl MAC reached UCI maclist")
			assert_eq(s.openuf_ratelimit_down, "33000", "qos.vap maxspeed reached UCI")
			assert_eq(s.openuf_ratelimit_up, "17000", "qos.vap uplink maxspeed reached UCI")

			-- Minimum Data Rate lands on the RADIO section, not the vap.
			local r = db.wireless.radio0
			assert_true(r ~= nil, "radio section created")
			assert_eq(r.basic_rate[1], "12000", "minrate_data reached UCI basic_rate")
			assert_eq(r.legacy_rates, "0", "cck status reached UCI legacy_rates")
			assert_eq(r.beacon_rate, "120", "beacon_rate converted to 100-kbps units")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps WPA-PSK akm to wpa2",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa2", "WPA-PSK only -> wpa2")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps WPA-PSK+SAE akm to wpa2/wpa3 (mixed)",
		fn = function()
			-- transition mode, space-joined on a single key
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK SAE\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa2/wpa3", "WPA-PSK+SAE -> mixed")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps split WPA-PSK/SAE keys to wpa2/wpa3",
		fn = function()
			-- transition mode, listed across separate wpa.key.<k>.mgmt entries
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.key.2.mgmt=SAE\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa2/wpa3", "split PSK/SAE keys -> mixed")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg maps SAE-only akm to wpa3",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=SAE\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa3", "SAE only -> wpa3")
		end
	},
	{
		name = "inform packet: wpa3.transition makes a SAE-only akm mixed, not WPA3-only",
		fn = function()
			-- The exact bytes a real 10.4.57 gateway sends for a WPA2/WPA3
			-- transition WLAN: SAE is the ONLY akm -- no WPA-PSK beside it --
			-- and the transition is marked by its own key. Read the akm alone
			-- and this provisions as pure WPA3, dropping every WPA2-only
			-- client on the network.
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.wpa.key.1.mgmt=SAE\naaa.1.wpa.psk=hunter22\n"
				.. "aaa.1.wpa3.support=enabled\naaa.1.wpa3.transition=enabled\n"
				.. "aaa.1.sae.anti_clogging=5\naaa.1.sae.sync=5\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa2/wpa3",
				"transition -> mixed, so WPA2 clients keep working")
		end
	},
	{
		name = "inform packet: aaa.<n>.wpa3.ft.status is parsed as its own tri-state",
		fn = function()
			-- A separate toggle from ft.status: the SAE emitter
			-- (com.ubnt.service.config.ubntconf.OXMua) writes it on every
			-- SAE push from isWpa3SaeFastRoamingEnabled(). "disabled" must
			-- survive as false, not collapse to nil -- nil means "the
			-- controller said nothing", which is a different instruction.
			local base = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.wpa.key.1.mgmt=SAE\naaa.1.wpa3.support=enabled\n"
				.. "aaa.1.wpa3.transition=enabled\naaa.1.ft.status=enabled\n"
			local tail = "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"

			local _, vt = inform._parse_wifi_system_cfg(
				base .. "aaa.1.wpa3.ft.status=enabled\n" .. tail)
			assert_eq(vt[1].wpa3_fast_roaming_enabled, true, "enabled -> true")

			local _, vt2 = inform._parse_wifi_system_cfg(
				base .. "aaa.1.wpa3.ft.status=disabled\n" .. tail)
			assert_eq(vt2[1].wpa3_fast_roaming_enabled, false,
				"disabled -> false, NOT nil (an and/or idiom would lose this)")

			local _, vt3 = inform._parse_wifi_system_cfg(base .. tail)
			assert_eq(vt3[1].wpa3_fast_roaming_enabled, nil,
				"absent -> nil, so non-SAE pushes are untouched")
			assert_eq(vt3[1].fast_roaming_enabled, true,
				"the WLAN-level ft.status is read independently")
		end
	},
	{
		-- Replay of a real 10.4.57 push (lab, 2026-09-27) for a WPA3-only
		-- WLAN with Fast Roaming on, once radio_caps2 claims bit 0x2. Before
		-- the bit, the same WLAN arrived with ft.status=disabled and
		-- wpa3.ft.status=disabled, so no 802.11r reached hostapd at all.
		name = "inform packet: captured WPA3-only + FT push reaches UCI as sae + ieee80211r",
		fn = function()
			local function run(ft)
				local ucihelper, db = new_apply_env()
				local sys_cfg = table.concat({
					"aaa.1.bss_transition=enabled", "aaa.1.devname=ath0",
					"aaa.1.ft.status=" .. ft, "aaa.1.id=6ab8c7ecc18fc00c5f8f66ed",
					"aaa.1.pmf.cipher=AES-128-CMAC", "aaa.1.pmf.mode=2",
					"aaa.1.pmf.status=enabled",
					"aaa.1.sae.psk.1.mac=ff:ff:ff:ff:ff:ff",
					"aaa.1.sae.psk.1.psk=openufopenuf",
					"aaa.1.ssid=ouf-w3only", "aaa.1.status=enabled",
					"aaa.1.wpa.1.pairwise=CCMP", "aaa.1.wpa.key.1.mgmt=SAE",
					"aaa.1.wpa.psk=openufopenuf",
					"aaa.1.wpa3.ft.status=" .. ft, "aaa.1.wpa3.support=enabled",
					"aaa.1.wpa3.transition=disabled", "aaa.1.wpa=2",
					"wireless.1.devname=ath0", "wireless.1.parent=radio0",
					"wireless.1.ssid=ouf-w3only", "wireless.1.status=enabled",
					"wireless.1.usage=user",
					"radio.1.phyname=radio0",
				}, "\n") .. "\n"
				local rt, vt = inform._parse_wifi_system_cfg(sys_cfg)
				ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
				local section = "openuf_radio0_ouf_w3only_"
					.. ucihelper.derive_mobility_domain("ouf-w3only")
				return db.wireless and db.wireless[section], ucihelper
			end

			local s, ucihelper = run("enabled")
			assert_true(s ~= nil, "vap section created")
			assert_eq(s.encryption, "sae", "WPA3-only -> sae, not sae-mixed")
			assert_eq(s.ieee80211w, "2", "pmf.mode=2 -> ieee80211w required")
			assert_eq(s.ieee80211r, "1", "ft.status/wpa3.ft.status enabled -> 802.11r")
			assert_eq(s.mobility_domain, ucihelper.derive_mobility_domain("ouf-w3only"),
				"mobility domain derived from the SSID")

			local s2 = run("disabled")
			assert_true(s2 ~= nil, "vap section created")
			assert_true(s2.ieee80211r ~= "1",
				"the pre-0x2 push (both FT keys disabled) leaves 802.11r off")
		end
	},
	{
		-- Verbatim lab capture (controller 10.6.106, 2026-10-26): a wlanconf
		-- with security="wpaeap" pointing at a radiusprofile that has two auth
		-- servers, one acct server, interim updates and vlan_wlan_mode
		-- "required". Addresses and the iapp_key are scrubbed to placeholders;
		-- nothing else is edited. Two traps this capture pins down:
		--   * aaa.<n>.wpa.psk is STILL sent on an EAP WLAN ("letmeinnow", a
		--     dummy the controller fills in). Carrying it into UCI would give
		--     the BSS a passphrase it must not have.
		--   * wireless.<n>.security=none on the same push. The discriminator
		--     is aaa.<n>.wpa.key.<k>.mgmt, never that field.
		name = "inform packet: captured WPA-Enterprise push reaches UCI as wpa2+ccmp with RADIUS servers",
		fn = function()
			local ucihelper, db = new_apply_env()
			local sys_cfg = table.concat({
				"aaa.1.pmf.status=disabled", "aaa.1.pmf.mode=0",
				"aaa.1.ft.status=disabled", "aaa.1.country_beacon=disabled",
				"aaa.1.11k.status=disabled", "aaa.1.br.devname=br0",
				"aaa.1.devname=ath0", "aaa.1.driver=madwifi",
				"aaa.1.ssid=openuf-eap", "aaa.1.status=enabled",
				"aaa.1.verbose=2", "aaa.1.wpa=2", "aaa.1.eapol_version=2",
				"aaa.1.wpa.group_rekey=3600", "aaa.1.p2p=disabled",
				"aaa.1.p2p_cross_connect=disabled", "aaa.1.proxy_arp=disabled",
				"aaa.1.is_guest=false", "aaa.1.tdls_prohibit=disabled",
				"aaa.1.bss_transition=enabled", "aaa.1.id=2",
				"aaa.1.wpa.key.1.mgmt=WPA-EAP",
				"aaa.1.wpa.psk=letmeinnow",
				"aaa.1.auth_cache=enabled",
				"aaa.1.radius.auth.1.ip=192.0.2.10",
				"aaa.1.radius.auth.1.port=1812",
				"aaa.1.radius.auth.1.secret=openufradius",
				"aaa.1.radius.auth.2.ip=192.0.2.11",
				"aaa.1.radius.auth.2.port=1812",
				"aaa.1.radius.auth.2.secret=openufradius",
				"aaa.1.radius.acct.1.ip=192.0.2.10",
				"aaa.1.radius.acct.1.port=1813",
				"aaa.1.radius.acct.1.secret=openufradius",
				"aaa.1.interim_update.status=enabled",
				"aaa.1.interim_update.interval=900",
				"aaa.1.dynamic_vlan=2",
				"aaa.1.hs20.status=disabled",
				"aaa.1.wpa.1.pairwise=CCMP",
				"aaa.1.pmf.cipher=AES-128-CMAC",
				"aaa.1.radius.macacl.status=disabled",
				"aaa.1.hide_ssid=false",
				"aaa.1.iapp_key=00112233445566778899aabbccddeeff",
				"wireless.1.mode=master", "wireless.1.devname=ath0",
				"wireless.1.id=2", "wireless.1.status=enabled",
				"wireless.1.authmode=1", "wireless.1.l2_isolation=disabled",
				"wireless.1.is_guest=false", "wireless.1.security=none",
				"wireless.1.ssid=openuf-eap", "wireless.1.hide_ssid=false",
				"wireless.1.wmm=enabled", "wireless.1.uapsd=disabled",
				"wireless.1.parent=radio0", "wireless.1.usage=user",
				"radio.1.phyname=radio0", "radio.1.devname=ath0",
				"radio.1.channel=auto", "radio.1.status=enabled",
			}, "\n") .. "\n"

			local rt, vt = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vt[1].security, "wpa2-enterprise",
				"WPA-EAP without any wpa3 key -> wpa2-enterprise")
			assert_nil(vt[1].x_passphrase,
				"the dummy aaa.1.wpa.psk never becomes a passphrase")
			assert_eq(vt[1].radius.auth[2].ip, "192.0.2.11",
				"both auth servers parsed, in index order")
			assert_eq(vt[1].radius.interim_interval, "900", "interim interval parsed")
			assert_eq(vt[1].radius.dynamic_vlan, "2",
				"vlan_wlan_mode=required reaches the wire as dynamic_vlan=2")

			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			local s = db.wireless["openuf_radio0_openuf_eap_"
				.. ucihelper.derive_mobility_domain("openuf-eap")]
			assert_true(s ~= nil, "vap section created")
			assert_eq(s.encryption, "wpa2+ccmp",
				"wpa2-enterprise -> the encryption ucode maps to auth_type eap")
			assert_nil(s.key, "no passphrase on an EAP BSS")
			assert_eq(table.concat(s.auth_server_addr, " "), "192.0.2.10 192.0.2.11",
				"both auth servers in the list (same port and secret)")
			assert_eq(s.auth_server_port, "1812", "auth port")
			assert_eq(s.auth_server_shared_secret, "openufradius", "auth secret")
			assert_eq(table.concat(s.acct_server_addr, " "), "192.0.2.10", "acct server")
			assert_eq(s.acct_server_port, "1813", "acct port")
			assert_eq(s.radius_acct_interim_interval, "900", "interim interval")
			assert_eq(s.dynamic_vlan, "2", "dynamic VLAN required")
		end
	},
	{
		-- Verbatim lab capture (controller 10.6.106, 2026-10-26): the WLAN's
		-- embedded `hotspot2` object filled with every field
		-- api/fields/WlanConf.json allows, pushed to an openUF AP claiming
		-- fw_caps 0x800000 + fw2_caps 0x80000. The RADIUS and wireless keys of
		-- the same push are exercised by the WPA-Enterprise replay above; this
		-- one keeps the hs20 block whole, including what the controller does
		-- NOT send.
		name = "inform packet: captured Hotspot 2.0 push reaches UCI as interworking and hs20 lines",
		fn = function()
			local ucihelper, db = new_apply_env()
			local sys_cfg = table.concat({
				"aaa.1.ssid=openuf-eap", "aaa.1.status=enabled", "aaa.1.wpa=2",
				"aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.wpa.1.pairwise=CCMP",
				"aaa.1.id=2", "aaa.1.auth_cache=enabled",
				"aaa.1.radius.auth.1.ip=192.0.2.10",
				"aaa.1.radius.auth.1.port=1812",
				"aaa.1.radius.auth.1.secret=openufradius",
				"aaa.1.hs20.status=enabled",
				"aaa.1.hs20.access_network_type=2",
				"aaa.1.hs20.internet=enabled",
				"aaa.1.hs20.asra=disabled",
				"aaa.1.hs20.esr=disabled",
				"aaa.1.hs20.uesa=disabled",
				"aaa.1.hs20.venue_group=2",
				"aaa.1.hs20.venue_type=8",
				"aaa.1.hs20.disable_dgaf=disabled",
				"aaa.1.hs20.deauth_req_timeout=60",
				"aaa.1.hs20.network_availability=13",
				"aaa.1.hs20.venue_name.1.lang=eng",
				"aaa.1.hs20.venue_name.1.name=openUF Lab",
				"aaa.1.hs20.venue_name.1.url=https://example.com/venue",
				"aaa.1.hs20.venue_name.2.lang=fra",
				"aaa.1.hs20.venue_name.2.name=Labo openUF",
				"aaa.1.hs20.hs20_domain_name_list=example.com,example.net",
				"aaa.1.hs20.nai_realm.1.status=enabled",
				"aaa.1.hs20.nai_realm.1.encoding=0",
				"aaa.1.hs20.nai_realm.1.name=example.com",
				"aaa.1.hs20.nai_realm.1.eap_method=13",
				"aaa.1.hs20.nai_realm.1.eap_method.auth.1.id=5",
				"aaa.1.hs20.nai_realm.1.eap_method.auth.1.val=6",
				"aaa.1.hs20.nai_realm.2.status=enabled",
				"aaa.1.hs20.nai_realm.2.encoding=0",
				"aaa.1.hs20.nai_realm.2.name=example.net",
				"aaa.1.hs20.nai_realm.2.eap_method=21",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.1.id=2",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.1.val=4",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.2.id=5",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.2.val=7",
				"aaa.1.hs20.1.roaming_consortium=506f9a",
				"aaa.1.hs20.2.roaming_consortium=001bc504bd",
				"aaa.1.hs20.3gpp.1.mcc=230",
				"aaa.1.hs20.3gpp.1.mnc=01",
				"aaa.1.hs20.3gpp.2.mcc=262",
				"aaa.1.hs20.3gpp.2.mnc=002",
				"aaa.1.hs20.friendly_name.1.language=eng",
				"aaa.1.hs20.friendly_name.1.text=openUF Operator",
				"aaa.1.hs20.capab.1.protocol=6",
				"aaa.1.hs20.capab.1.port=80",
				"aaa.1.hs20.capab.1.status=open",
				"aaa.1.hs20.capab.2.protocol=17",
				"aaa.1.hs20.capab.2.port=5060",
				"aaa.1.hs20.capab.2.status=closed",
				"aaa.1.hs20.capab.3.protocol=1",
				"aaa.1.hs20.capab.3.port=0",
				"aaa.1.hs20.capab.3.status=unknown",
				"aaa.1.hs20.metrics.status=enabled",
				"aaa.1.hs20.metrics.info=1",
				"aaa.1.hs20.metrics.downlink_speed=8000",
				"aaa.1.hs20.metrics.uplink_speed=1000",
				"aaa.1.hs20.metrics.downlink_load=80",
				"aaa.1.hs20.metrics.uplink_load=40",
				"aaa.1.hs20.metrics.measurement=3000",
				"wireless.1.ssid=openuf-eap", "wireless.1.parent=radio0",
				"wireless.1.usage=user", "wireless.1.dgaf_disable=disabled",
				"radio.1.phyname=radio0", "radio.1.devname=ath0",
				"radio.1.channel=auto", "radio.1.status=enabled",
			}, "\n") .. "\n"

			local rt, vt = inform._parse_wifi_system_cfg(sys_cfg)
			local hs = vt[1].hs20
			assert_true(hs ~= nil, "the hs20 block parsed")
			assert_eq(hs.access_network_type, "2", "access network type")
			assert_true(hs.internet, "internet reachable")
			assert_eq(hs.asra, false, "no additional step required")
			assert_eq(hs.uesa, false, "no unauthenticated emergency services")
			assert_eq(hs.venue_group, "2", "venue group")
			assert_eq(hs.venue_type, "8", "venue type")
			assert_eq(hs.disable_dgaf, false, "DGAF left on")
			assert_eq(hs.deauth_req_timeout, "60", "deauth request timeout")
			assert_eq(hs.ipaddr_type_avail, "13",
				"v4=3, v6=1 arrive already combined as (v4 << 2) | v6")
			assert_eq(hs.domain_name, "example.com,example.net",
				"the domain list is comma-separated on the wire already")
			assert_eq(#hs.venue_name, 2, "both venue names")
			assert_eq(hs.venue_name[1].url, "https://example.com/venue",
				"the first venue's URL")
			assert_nil(hs.venue_name[2].url, "the second venue has none")
			assert_eq(#hs.nai_realm, 2, "both realms")
			assert_eq(hs.nai_realm[2].name, "example.net", "second realm")
			assert_eq(hs.nai_realm[2].eap_method, "21", "its EAP method (TTLS)")
			assert_eq(#hs.nai_realm[2].auth, 2, "its two auth parameters")
			assert_eq(hs.nai_realm[2].auth[2].val, "7", "third-level auth value")
			assert_eq(table.concat(hs.roaming_consortium, " "),
				"506f9a 001bc504bd", "both OIs, in index order")
			assert_eq(hs.cell_net[1].mnc, "01",
				"a two-digit MNC stays two digits")
			assert_eq(hs.cell_net[2].mnc, "002", "and a three-digit one does too")
			assert_eq(hs.friendly_name[1].text, "openUF Operator", "operator name")
			assert_eq(#hs.conn_capab, 3, "all three connection capabilities")
			assert_eq(hs.conn_capab[2].status, "0", "closed -> 0")
			assert_eq(hs.conn_capab[3].status, "2", "unknown -> 2")
			assert_eq(hs.wan_metrics.downlink_speed, "8000", "downlink speed")

			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			local s = db.wireless["openuf_radio0_openuf_eap_"
				.. ucihelper.derive_mobility_domain("openuf-eap")]
			assert_true(s ~= nil, "vap section created")
			assert_eq(s.iw_enabled, "1", "iface_interworking's gate")
			assert_eq(s.hs20, "1", "iface_hs20's gate")
			assert_eq(s.access_network_type, "2", "scalar through UCI")
			assert_eq(s.internet, "1", "boolean as 1/0")
			assert_eq(s.asra, "0", "and an off one as 0")
			assert_eq(s.disable_dgaf, "0", "DGAF option written explicitly")
			assert_eq(s.hs20_deauth_req_timeout, "60", "deauth timeout")
			assert_eq(s.hs20_wan_metrics, "01:8000:1000:80:40:3000",
				"WAN metrics as one colon-separated hostapd value, the WAN "
				.. "info octet in hex (hostapd hexstr2bin's it and rejects "
				.. "the whole config if it is not two hex chars)")
			local raw = table.concat(s.hostapd_bss_options or {}, "\n")
			for _, want in ipairs({
				"ipaddr_type_availability=13",
				"domain_name=example.com,example.net",
				"venue_name=eng:openUF Lab",
				"venue_name=fra:Labo openUF",
				"venue_url=1:https://example.com/venue",
				"nai_realm=0,example.com,13[5:6]",
				"nai_realm=0,example.net,21[2:4][5:7]",
				"roaming_consortium=506f9a",
				"roaming_consortium=001bc504bd",
				"anqp_3gpp_cell_net=230,01;262,002",
				"hs20_oper_friendly_name=eng:openUF Operator",
				"hs20_conn_capab=6:80:1",
				"hs20_conn_capab=17:5060:0",
				"hs20_conn_capab=1:0:2",
			}) do
				assert_contains(raw, want, "raw hostapd line: " .. want)
			end
			assert_true(raw:find("venue_url=2:") == nil,
				"no venue_url for the venue that has no URL")
			-- The SAE tuning lines share hostapd_bss_options; nothing here may
			-- have replaced a previous producer's list.
			assert_eq(#s.hostapd_bss_options, 14,
				"one raw line per entry, nothing lost or duplicated")
		end
	},
	{
		name = "inform packet: the Hotspot 2.0 key table is indexed once, not once per collector",
		fn = function()
			-- _wire_hs20 has seven indexed collectors plus one per NAI realm,
			-- and each used to re-walk the WLAN's whole key table. Counted
			-- through string.match, since the hs20 patterns are the only ones
			-- in the parser naming the block: one decomposition attempt per
			-- hs20.* key, and nothing per collector.
			local keys = {
				"aaa.1.hs20.status=enabled",
				"aaa.1.hs20.access_network_type=2",
				"aaa.1.hs20.internet=enabled",
				"aaa.1.hs20.venue_group=2",
				"aaa.1.hs20.venue_type=8",
				"aaa.1.hs20.venue_name.1.lang=eng",
				"aaa.1.hs20.venue_name.1.name=openUF Lab",
				"aaa.1.hs20.venue_name.2.lang=fra",
				"aaa.1.hs20.venue_name.2.name=Labo openUF",
				"aaa.1.hs20.nai_realm.1.name=example.com",
				"aaa.1.hs20.nai_realm.1.eap_method=13",
				"aaa.1.hs20.nai_realm.1.eap_method.auth.1.id=5",
				"aaa.1.hs20.nai_realm.1.eap_method.auth.1.val=6",
				"aaa.1.hs20.nai_realm.2.name=example.net",
				"aaa.1.hs20.nai_realm.2.eap_method=21",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.1.id=2",
				"aaa.1.hs20.nai_realm.2.eap_method.auth.1.val=4",
				"aaa.1.hs20.1.roaming_consortium=506f9a",
				"aaa.1.hs20.2.roaming_consortium=001bc504bd",
				"aaa.1.hs20.3gpp.1.mcc=230",
				"aaa.1.hs20.3gpp.1.mnc=01",
				"aaa.1.hs20.friendly_name.1.language=eng",
				"aaa.1.hs20.friendly_name.1.text=openUF Operator",
				"aaa.1.hs20.capab.1.protocol=6",
				"aaa.1.hs20.capab.1.port=80",
				"aaa.1.hs20.capab.1.status=open",
			}
			local lines = {
				"aaa.1.ssid=openuf-eap", "aaa.1.status=enabled", "aaa.1.wpa=2",
				"aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.wpa.1.pairwise=CCMP",
				"aaa.1.id=2", "aaa.1.auth_cache=enabled",
				"aaa.1.radius.auth.1.ip=192.0.2.10",
				"aaa.1.radius.auth.1.port=1812",
				"aaa.1.radius.auth.1.secret=openufradius",
			}
			for _, l in ipairs(keys) do lines[#lines + 1] = l end
			lines[#lines + 1] = "wireless.1.ssid=openuf-eap"
			lines[#lines + 1] = "wireless.1.parent=radio0"
			lines[#lines + 1] = "radio.1.phyname=radio0"
			lines[#lines + 1] = "radio.1.devname=ath0"
			local sys_cfg = table.concat(lines, "\n") .. "\n"

			local real, calls = string.match, 0
			string.match = function(s, p, ...)
				if type(p) == "string" and p:find("hs20", 1, true) then
					calls = calls + 1
				end
				return real(s, p, ...)
			end
			local ok, rt, vt = pcall(inform._parse_wifi_system_cfg, sys_cfg)
			string.match = real
			if not ok then error(rt, 0) end

			local hs = vt[1].hs20
			assert_true(hs ~= nil, "the hs20 block still parsed")
			assert_eq(#hs.venue_name, 2, "both venue names")
			assert_eq(#hs.nai_realm, 2, "both realms")
			assert_eq(#hs.nai_realm[1].auth, 1, "the first realm's auth pair")
			assert_eq(hs.nai_realm[2].auth[1].id, "2",
				"and the second realm's own, not the first realm's")
			assert_eq(table.concat(hs.roaming_consortium, " "),
				"506f9a 001bc504bd", "both OIs, in index order")
			assert_eq(#hs.cell_net, 1, "the 3GPP cell")
			assert_eq(#hs.friendly_name, 1, "the operator name")
			assert_eq(#hs.conn_capab, 1, "the connection capability")
			-- Two attempts per key at the very most: the indexed shape, then
			-- the roaming_consortium one. Ten scans of the table would be
			-- #keys * 10 or more.
			assert_true(calls <= 2 * #keys, string.format(
				"one index pass, not one per collector (%d matches for %d "
				.. "hs20 keys)", calls, #keys))
		end
	},
	{
		name = "inform packet: a WAN info octet above 9 is hex, not zero-padded decimal",
		fn = function()
			-- "At Capacity" (bit 3) plus "link up" (bits 0-1) is decimal 9 on
			-- the wire; the symmetric-link bit takes it to 10, which hostapd
			-- must see as 0a. Zero-padding the decimal would silently change
			-- the advertised WAN status rather than fail loudly.
			local ucihelper, db = new_apply_env()
			local sys_cfg = table.concat({
				"aaa.1.ssid=corp", "aaa.1.wpa=2",
				"aaa.1.wpa.key.1.mgmt=WPA-EAP",
				"aaa.1.radius.auth.1.ip=192.0.2.10",
				"aaa.1.radius.auth.1.secret=s",
				"aaa.1.hs20.status=enabled",
				"aaa.1.hs20.metrics.status=enabled",
				"aaa.1.hs20.metrics.info=10",
				"aaa.1.hs20.metrics.downlink_speed=0",
				"aaa.1.hs20.metrics.uplink_speed=0",
				"aaa.1.hs20.metrics.downlink_load=0",
				"aaa.1.hs20.metrics.uplink_load=0",
				"aaa.1.hs20.metrics.measurement=0",
				"wireless.1.ssid=corp", "wireless.1.parent=radio0",
				"radio.1.phyname=radio0", "radio.1.devname=ath0",
			}, "\n") .. "\n"
			local rt, vt = inform._parse_wifi_system_cfg(sys_cfg)
			with_stderr(function()
				ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			end)
			local s = db.wireless["openuf_radio0_corp"]
			assert_true(s ~= nil, "vap section created")
			assert_eq(s.hs20_wan_metrics, "0a:0:0:0:0:0", "WAN info in hex")
		end
	},
	{
		name = "inform packet: a Hotspot 2.0 block is dropped on a WLAN that is not WPA-Enterprise",
		fn = function()
			-- hostapd refuses a config with hs20=1 and anything but
			-- WPA2-Enterprise/CCMP, so writing the block out would leave a BSS
			-- that never starts. The controller only offers Passpoint on an
			-- EAP/OSEN WLAN; this pins what happens if that ever changes.
			local sys_cfg = table.concat({
				"aaa.1.ssid=home", "aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK",
				"aaa.1.wpa.psk=hunter22", "aaa.1.hs20.status=enabled",
				"aaa.1.hs20.access_network_type=2",
				"wireless.1.ssid=home", "wireless.1.parent=radio0",
			}, "\n") .. "\n"
			local vap_table
			local logged = with_stderr(function()
				local _
				_, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			end)
			assert_eq(#vap_table, 1, "the WLAN itself is still provisioned")
			assert_nil(vap_table[1].hs20, "but with no hs20 field")
			assert_contains(logged, "not WPA-Enterprise", "and a line says why")
		end
	},
	{
		name = "inform packet: Hotspot 2.0 entries that cannot be expressed are dropped individually",
		fn = function()
			-- Every value here reaches a hostapd config FILE. A control
			-- character would end the line and let the rest be read as further
			-- hostapd options, and a malformed OI or MCC is rejected by hostapd
			-- outright -- so each bad entry is dropped on its own, leaving the
			-- good ones.
			local sys_cfg = table.concat({
				"aaa.1.ssid=corp", "aaa.1.wpa=2",
				"aaa.1.wpa.key.1.mgmt=WPA-EAP",
				"aaa.1.radius.auth.1.ip=192.0.2.10",
				"aaa.1.radius.auth.1.secret=a",
				"aaa.1.hs20.status=enabled",
				"aaa.1.hs20.venue_name.1.lang=eng",
				"aaa.1.hs20.venue_name.1.name=good venue",
				"aaa.1.hs20.venue_name.2.lang=eng",
				"aaa.1.hs20.venue_name.2.name=bad\tvenue",
				"aaa.1.hs20.venue_name.3.lang=english",
				"aaa.1.hs20.venue_name.3.name=bad lang",
				"aaa.1.hs20.1.roaming_consortium=506f9a",
				"aaa.1.hs20.2.roaming_consortium=notahexstring",
				"aaa.1.hs20.3.roaming_consortium=abc",
				"aaa.1.hs20.3gpp.1.mcc=230", "aaa.1.hs20.3gpp.1.mnc=01",
				"aaa.1.hs20.3gpp.2.mcc=23", "aaa.1.hs20.3gpp.2.mnc=01",
				"aaa.1.hs20.nai_realm.1.name=live.example",
				"aaa.1.hs20.nai_realm.1.eap_method=13",
				"aaa.1.hs20.nai_realm.2.status=disabled",
				"aaa.1.hs20.nai_realm.2.name=off.example",
				"aaa.1.hs20.nai_realm.2.eap_method=13",
				"aaa.1.hs20.nai_realm.3.name=norealm.example",
				"aaa.1.hs20.capab.1.protocol=6", "aaa.1.hs20.capab.1.port=80",
				"aaa.1.hs20.capab.1.status=open",
				"aaa.1.hs20.capab.2.protocol=6", "aaa.1.hs20.capab.2.port=81",
				"aaa.1.hs20.capab.2.status=maybe",
				"aaa.1.hs20.metrics.status=enabled",
				"aaa.1.hs20.metrics.info=1",
				"aaa.1.hs20.metrics.downlink_speed=8000",
				"wireless.1.ssid=corp", "wireless.1.parent=radio0",
			}, "\n") .. "\n"
			local _, vt = inform._parse_wifi_system_cfg(sys_cfg)
			local hs = vt[1].hs20
			assert_eq(#hs.venue_name, 1, "only the clean venue name survives")
			assert_eq(hs.venue_name[1].name, "good venue", "and it is the right one")
			assert_eq(table.concat(hs.roaming_consortium, " "), "506f9a",
				"a non-hex and a too-short OI are both dropped")
			assert_eq(#hs.cell_net, 1, "a two-digit MCC is dropped")
			assert_eq(#hs.nai_realm, 1, "a disabled realm and one with no EAP method go")
			assert_eq(hs.nai_realm[1].name, "live.example", "the enabled one stays")
			assert_nil(hs.nai_realm[1].auth, "a realm with no auth parameters has none")
			assert_eq(#hs.conn_capab, 1, "an unknown status word is dropped")
			assert_nil(hs.wan_metrics,
				"WAN metrics are all-or-nothing: one missing field drops the set")
		end
	},
	{
		name = "inform packet: Hotspot 2.0 off leaves no interworking option behind",
		fn = function()
			-- aaa.<n>.hs20.status=disabled is what every non-Passpoint EAP push
			-- carries. The section is rebuilt from scratch on each push, so the
			-- options must simply not be there.
			local ucihelper, db = new_apply_env()
			local function push(on)
				local sys_cfg = table.concat({
					"aaa.1.ssid=corp", "aaa.1.wpa=2",
					"aaa.1.wpa.key.1.mgmt=WPA-EAP",
					"aaa.1.radius.auth.1.ip=192.0.2.10",
					"aaa.1.radius.auth.1.secret=a",
					"aaa.1.hs20.status=" .. (on and "enabled" or "disabled"),
					on and "aaa.1.hs20.access_network_type=2" or "aaa.1.id=2",
					on and "aaa.1.hs20.1.roaming_consortium=506f9a"
						or "aaa.1.hide_ssid=false",
					"wireless.1.ssid=corp", "wireless.1.parent=radio0",
					"radio.1.phyname=radio0", "radio.1.channel=auto",
				}, "\n") .. "\n"
				local rt, vt = inform._parse_wifi_system_cfg(sys_cfg)
				ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
				return db.wireless["openuf_radio0_corp"]
			end
			local s = push(true)
			assert_eq(s.iw_enabled, "1", "on first")
			s = push(false)
			assert_nil(s.iw_enabled, "no iw_enabled left")
			assert_nil(s.hs20, "no hs20 left")
			assert_nil(s.access_network_type, "no access_network_type left")
			assert_nil(s.hostapd_bss_options, "and no raw interworking lines")
		end
	},
	{
		-- aaa.<n>.iapp_key is the wlanconf's x_iapp_key, sent on every
		-- radio's aaa block for the WLAN (seen live from a 10.x UCG Ultra and
		-- the 10.4.57 lab). It is the 802.11r key-holder secret.
		name = "inform packet: aaa.<n>.iapp_key reaches UCI as the r0kh/r1kh key",
		fn = function()
			local key = "00112233445566778899AABBCCDDEEFF"
			local function cfg(k)
				return table.concat({
					"aaa.1.ft.status=enabled", "aaa.1.id=6ab8c7ecc18fc00c5f8f66ed",
					k and ("aaa.1.iapp_key=" .. k) or "aaa.1.status=enabled",
					"aaa.1.ssid=corp", "aaa.1.wpa.1.pairwise=CCMP",
					"aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk=hunter22",
					"aaa.1.wpa3.support=enabled", "aaa.1.wpa3.transition=enabled",
					"aaa.1.wpa=2",
					"wireless.1.parent=radio0", "wireless.1.ssid=corp",
					"wireless.1.usage=user",
				}, "\n") .. "\n"
			end

			local _, vt = inform._parse_wifi_system_cfg(cfg(key))
			assert_eq(vt[1].iapp_key, key:lower(), "key carried, lowercased")
			for _, bad in ipairs({"0011", key .. "00", "zz" .. key:sub(3)}) do
				local _, bvt = inform._parse_wifi_system_cfg(cfg(bad))
				assert_nil(bvt[1].iapp_key, "malformed key dropped: " .. bad)
			end
			_, vt = inform._parse_wifi_system_cfg(cfg(nil))
			assert_nil(vt[1].iapp_key, "absent key -> nil")

			local ucihelper, db = new_apply_env()
			local rt
			rt, vt = inform._parse_wifi_system_cfg(cfg(key))
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			local s = db.wireless.openuf_radio0_corp
			assert_true(s ~= nil, "vap section created")
			assert_eq(s.ieee80211r, "1", "FT on")
			assert_eq(s.r0kh and s.r0kh[1], "ff:ff:ff:ff:ff:ff,*," .. key:lower(),
				"r0kh carries the controller's key")
			assert_eq(s.r1kh and s.r1kh[1],
				"00:00:00:00:00:00,00:00:00:00:00:00," .. key:lower(),
				"r1kh carries the controller's key")
		end
	},
	{
		name = "inform packet: wpa3.support without transition is WPA3-only",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "aaa.1.wpa.key.1.mgmt=SAE\n"
				.. "aaa.1.wpa3.support=enabled\naaa.1.wpa3.transition=disabled\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa3", "support without transition -> WPA3 only")
		end
	},
	{
		name = "inform packet: an Enhanced Open WLAN parses as owe",
		fn = function()
			-- Captured on 10.4.57 with radio_caps2 0xB (2026-09-27), trimmed.
			-- The akm is the only marker: no aaa.<n>.wpa, psk or pmf keys.
			local sys_cfg = "aaa.5.devname=ath4\naaa.5.ssid=ouf-owe\naaa.5.hide_ssid=false\n"
				.. "aaa.5.ft.status=disabled\naaa.5.id=6ab8d43fc18fc00c5f8f6756\n"
				.. "aaa.5.wpa.key.1.mgmt=OWE\n"
				.. "wireless.5.devname=ath4\nwireless.5.ssid=ouf-owe\n"
				.. "wireless.5.parent=radio0\nwireless.5.authmode=0\nwireless.5.hide_ssid=false\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 1, "one vap")
			assert_eq(vap_table[1].security, "owe", "OWE akm -> owe, not open")
			assert_nil(vap_table[1].owe_transition, "no transition without a partner")
		end
	},
	{
		name = "inform packet: an OWE transition pair collapses into one owe_transition vap",
		fn = function()
			-- Captured on 10.4.57 (2026-09-27), trimmed to one radio: the open
			-- half and the hidden OWE half share the SSID and name each other
			-- in owe_devname. OpenWrt builds both BSSes from one section, and
			-- two sections on one radio with one SSID would collapse anyway.
			local sys_cfg = "aaa.5.devname=ath4\naaa.5.ssid=ouf-owe\naaa.5.hide_ssid=false\n"
				.. "aaa.5.id=6ab8d43fc18fc00c5f8f6756\naaa.5.owe_devname=ath6\n"
				.. "wireless.5.devname=ath4\nwireless.5.ssid=ouf-owe\n"
				.. "wireless.5.parent=radio0\nwireless.5.authmode=0\nwireless.5.hide_ssid=false\n"
				.. "aaa.7.devname=ath6\naaa.7.ssid=ouf-owe\naaa.7.hide_ssid=true\n"
				.. "aaa.7.id=6ab8d43fc18fc00c5f8f6756\naaa.7.owe_devname=ath4\n"
				.. "aaa.7.wpa.key.1.mgmt=OWE\n"
				.. "wireless.7.devname=ath6\nwireless.7.ssid=ouf-owe\n"
				.. "wireless.7.parent=radio0\nwireless.7.authmode=0\nwireless.7.hide_ssid=true\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 1, "the hidden OWE half is not a vap of its own")
			local v = vap_table[1]
			assert_eq(v.security, "owe", "the open half carries the WLAN as owe")
			assert_true(v.owe_transition, "marked for owe_transition")
			assert_false(v.hide_ssid, "the visible half's hide_ssid, not the hidden one's")
			assert_eq(v.wlanconf_id, "6ab8d43fc18fc00c5f8f6756", "id kept")
		end
	},
	{
		name = "inform packet: private pre-shared keys parse into vap.ppsk in wire order",
		fn = function()
			-- Captured on 10.4.57 with wifi_caps 0x10002C (2026-09-27),
			-- trimmed: a key on a VLAN-1 network has no vlanid, and the WLAN's
			-- own wpa.psk is a random passphrase the controller generated.
			local sys_cfg = "aaa.1.devname=ath0\naaa.1.ssid=ouf-ppsk\naaa.1.wpa=2\n"
				.. "aaa.1.id=6ab8f2ae1819ec65363e3257\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.1.wpa.psk=A[fGy>a~#h^o2_50ZcGbfGnb2.Y\"*W9Z\naaa.1.dynamic_vlan=1\n"
				.. "aaa.1.wpa.psk_file.status=enabled\n"
				.. "aaa.1.wpa.psk_file.1.psk=keydefault1\n"
				.. "aaa.1.wpa.psk_file.2.psk=keyvlan20a\naaa.1.wpa.psk_file.2.vlanid=20\n"
				.. "aaa.1.wpa.psk_file.3.psk=keyvlan30a\naaa.1.wpa.psk_file.3.vlanid=30\n"
				.. "aaa.1.wpa.1.pairwise=CCMP\naaa.1.br.devname=br0\n"
				.. "wireless.1.devname=ath0\nwireless.1.ssid=ouf-ppsk\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 1, "one vap")
			local v = vap_table[1]
			assert_eq(v.security, "wpa2", "still a WPA2 WLAN")
			assert_eq(v.x_passphrase, 'A[fGy>a~#h^o2_50ZcGbfGnb2.Y"*W9Z', "its own key kept")
			assert_false(v.vlan_enabled, "the WLAN itself is untagged")
			assert_eq(#v.ppsk, 3, "three keys")
			assert_eq(v.ppsk[1].key, "keydefault1", "wire order")
			assert_nil(v.ppsk[1].vid, "no vlanid: the VAP's own network")
			assert_eq(v.ppsk[2].vid, 20, "numeric VLAN")
			assert_eq(v.ppsk[3].key, "keyvlan30a", "third key")
			assert_eq(v.ppsk[3].vid, 30, "third VLAN")
		end
	},
	{
		name = "inform packet: a WLAN whose keys come from RADIUS only is skipped, optional kept",
		fn = function()
			-- UID IoT: aaa.<n>.wpa.psk_radius (0/1/2, hostapd's own values).
			-- The push carries no RADIUS server for it, as for Enterprise.
			local function parse(mode)
				local sys_cfg = "aaa.1.ssid=iot\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
					.. "aaa.1.wpa.psk=basepass123\naaa.1.wpa.psk_radius=" .. mode .. "\n"
					.. "wireless.1.ssid=iot\nwireless.1.parent=radio0\n"
				local _, vt = inform._parse_wifi_system_cfg(sys_cfg)
				return vt
			end
			assert_eq(#parse("2"), 0, "required: nobody could join it")
			assert_eq(#parse("1"), 1, "optional: the local key still works")
			assert_eq(#parse("0"), 1, "disabled: an ordinary WLAN")
		end
	},
	{
		name = "inform packet: invalid private pre-shared keys are dropped, the rest kept",
		fn = function()
			local function parse(extra, head)
				local sys_cfg = (head or "aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n")
					.. "aaa.1.ssid=k\naaa.1.wpa.psk=basepass123\n" .. extra
					.. "wireless.1.ssid=k\nwireless.1.parent=radio0\n"
				local _, vt = inform._parse_wifi_system_cfg(sys_cfg)
				return vt[1]
			end
			local on = "aaa.1.wpa.psk_file.status=enabled\n"
			local v = parse(on .. "aaa.1.wpa.psk_file.1.psk=short\n"
				.. "aaa.1.wpa.psk_file.2.psk=goodkey12\naaa.1.wpa.psk_file.2.vlanid=0\n"
				.. "aaa.1.wpa.psk_file.3.psk=goodkey34\naaa.1.wpa.psk_file.3.vlanid=4095\n"
				.. "aaa.1.wpa.psk_file.4.psk=goodkey56\naaa.1.wpa.psk_file.4.vlanid=abc\n"
				.. "aaa.1.wpa.psk_file.5.psk=" .. string.rep("a", 64) .. "\n"
				.. "aaa.1.wpa.psk_file.6.psk=" .. string.rep("z", 64) .. "\n"
				.. "aaa.1.wpa.psk_file.10.psk=goodkey78\naaa.1.wpa.psk_file.10.vlanid=4094\n")
			assert_eq(#v.ppsk, 2, "only the two valid keys survive")
			assert_eq(v.ppsk[1].key, string.rep("a", 64), "64 hex digits is a raw PSK")
			assert_eq(v.ppsk[2].vid, 4094, "index 10 sorts after 5, numerically")
			assert_nil(parse("aaa.1.wpa.psk_file.status=disabled\n"
				.. "aaa.1.wpa.psk_file.1.psk=goodkey12\n").ppsk, "status off: no keys")
			assert_nil(parse("aaa.1.wpa.psk_file.1.psk=goodkey12\n").ppsk,
				"no status: no keys")
			assert_nil(parse(on .. "aaa.1.wpa.psk_file.1.psk=goodkey12\n", "").ppsk,
				"an open WLAN has no keys to add")
			assert_nil(parse(on .. "aaa.1.wpa.psk_file.1.psk=goodkey12\n",
				"aaa.1.wpa.key.1.mgmt=OWE\n").ppsk, "nor has an Enhanced Open one")
		end
	},
	{
		name = "inform packet: owe_devname pointing at a non-OWE vap is not a transition",
		fn = function()
			-- Only a partner that really is OWE makes a pair. Anything else
			-- stays as the wire says, rather than silently dropping a WLAN.
			local sys_cfg = "aaa.1.devname=ath0\naaa.1.ssid=a\naaa.1.owe_devname=ath1\n"
				.. "wireless.1.ssid=a\nwireless.1.parent=radio0\n"
				.. "aaa.2.devname=ath1\naaa.2.ssid=b\n"
				.. "wireless.2.ssid=b\nwireless.2.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(#vap_table, 2, "both kept")
			assert_eq(vap_table[1].security, "open", "still open")
			assert_nil(vap_table[1].owe_transition, "no transition")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg wpa=2 without any key.mgmt stays wpa2",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].security, "wpa2", "wpa=2, no akm -> wpa2 (unchanged)")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.no2ghz_oui (Band Steering)",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.no2ghz_oui=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].no2ghz_oui, true, "no2ghz_oui=enabled -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.no2ghz_oui=disabled as false",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.no2ghz_oui=disabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].no2ghz_oui, false, "no2ghz_oui=disabled -> false")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves no2ghz_oui nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].no2ghz_oui, nil, "no no2ghz_oui key -> nil")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg parses wireless.<n>.advertise_ap_name (Show AP Name in Beacon)",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\nwireless.1.advertise_ap_name=enabled\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].advertise_ap_name, true, "advertise_ap_name=enabled -> true")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves advertise_ap_name nil when absent",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].advertise_ap_name, nil, "no advertise_ap_name key -> nil")
		end
	},
	{
		name = "inform packet: handle_response parses resolv.host.1.name and threads it as opts.device_name",
		fn = function()
			local st = sample_state()
			local applied_opts
			inform._ucihelper = {
				apply_config = function(_, _, opts) applied_opts = opts end,
			}
			local orig_usteer = inform._usteer.set_enabled
			inform._usteer.set_enabled = function() end
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
				.. "resolv.host.1.name=Living-Room-AP\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			inform._ucihelper = nil
			inform._usteer.set_enabled = orig_usteer
			assert_eq(applied_opts.device_name, "Living-Room-AP", "resolv.host.1.name threaded through as opts.device_name")
		end
	},
	{
		name = "inform packet: handle_response setparam applies WiFi config from system_cfg via ucihelper",
		fn = function()
			local st = sample_state()
			local applied_resp, applied_cfg, applied_opts
			inform._ucihelper = {
				apply_config = function(resp, cfg, opts)
					applied_resp, applied_cfg, applied_opts = resp, cfg, opts
				end,
			}
			local orig_usteer = inform._usteer.set_enabled
			inform._usteer.set_enabled = function() end  -- avoid touching real UCI in this test
			local cfg = {net = {lan_cpueth = "eth0"}}
			local sys_cfg = "radio.1.phyname=radio0\nradio.1.channel=6\nradio.1.txpower=20\n"
				.. "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.wpa.psk=TestPass123\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local resp = ('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg:gsub("\n", "\\n"))
			inform.handle_response(resp, st, cfg)
			inform._ucihelper = nil
			inform._usteer.set_enabled = orig_usteer
			assert_true(applied_resp ~= nil, "ucihelper.apply_config was called")
			assert_eq(#applied_resp.vap_table, 1, "one vap passed through")
			assert_eq(applied_resp.vap_table[1].ssid, "openuf-test", "ssid passed through")
			assert_eq(applied_cfg, cfg, "cfg passed through unchanged")
			assert_false(applied_opts.band_steering_active,
				"band_steering_active false -- no vap has no2ghz_oui enabled")
		end
	},
	{
		name = "inform packet: handle_response setparam skips ucihelper.apply_config when system_cfg has no WiFi keys",
		fn = function()
			local st = sample_state()
			local called = false
			inform._ucihelper = {
				apply_config = function() called = true end,
			}
			local cfg = {net = {lan_cpueth = "eth0"}}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.2\\ndhcpc.1.status=enabled\\n"}'
			inform.handle_response(resp, st, cfg)
			inform._ucihelper = nil
			assert_false(called, "apply_config not called without any aaa./wireless./radio. keys")
		end
	},
	{
		name = "inform packet: handle_response setdefault resets state",
		fn = function()
			local st = sample_state({
				authkey  = "aabbccddeeff00112233445566778899",
				adopted  = true,
				use_gcm  = true,
			})
			inform.handle_response('{"_type":"setdefault"}', st)
			assert_false(st.adopted,  "adopted reset to false")
			assert_false(st.use_gcm, "use_gcm reset to false")
			assert_eq(st.authkey, state.DEFAULT_KEY, "authkey reset to default")
		end
	},
	{
		name = "inform packet: handle_response setdefault preserves mac/ip/hostname",
		fn = function()
			-- mac/ip/hostname are populated once at M.run() startup and never
			-- persisted to state.json -- a factory reset must not wipe the
			-- device's live-detected identity mid-run.
			local st = sample_state({adopted = true})
			inform.handle_response('{"_type":"setdefault"}', st)
			assert_eq(st.mac,      "aa:bb:cc:dd:ee:ff", "mac preserved across reset")
			assert_eq(st.ip,       "192.168.1.100",     "ip preserved across reset")
			assert_eq(st.hostname, "testap",            "hostname preserved across reset")
		end
	},
	{
		name = "inform packet: setdefault keeps the inform URL that reached the controller",
		fn = function()
			-- The default names the controller by host name, and an L3
			-- re-adoption over it fails (HTTP 400, "invalid inform_ip").
			local st = sample_state({adopted = true, inform_url = "http://192.0.2.1:8080/inform"})
			inform.handle_response('{"_type":"setdefault"}', st)
			assert_false(st.adopted, "reset")
			assert_eq(st.inform_url, "http://192.0.2.1:8080/inform", "kept in memory")
			assert_eq(inform._state.load().inform_url, "http://192.0.2.1:8080/inform", "and on disk")
		end
	},
	{
		name = "inform packet: handle_response setdefault unlocks bootstrap account when configured",
		fn = function()
			local st = sample_state({adopted = true})
			local calls = {}
			local orig = inform._run_cmd
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform.handle_response('{"_type":"setdefault"}', st, {config = {bootstrap_adopt_user = "ubnt"}})
			inform._run_cmd = orig
			assert_eq(#calls, 1, "exactly one passwd command issued")
			assert_contains(calls[1], "passwd -u", "unlock command issued")
			assert_contains(calls[1], "ubnt", "unlock command targets ubnt")
		end
	},
	{
		name = "inform packet: handle_response setdefault does nothing when bootstrap account not configured",
		fn = function()
			local st = sample_state({adopted = true})
			local calls = {}
			local orig = inform._run_cmd
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform.handle_response('{"_type":"setdefault"}', st, {config = {}})
			inform._run_cmd = orig
			assert_eq(#calls, 0, "no passwd command issued when bootstrap_adopt_user unset")
		end
	},
	{
		name = "inform packet: handle_response upgrade stores version/url only",
		fn = function()
			local st = sample_state()
			local resp = '{"_type":"upgrade","version":"6.6.99","url":"http://unifi/fw.bin"}'
			local result = inform.handle_response(resp, st)
			assert_eq(st.upgrade_requested_version, "6.6.99", "version stored")
			assert_eq(st.upgrade_requested_url, "http://unifi/fw.bin", "url stored")
			assert_false(result, "upgrade does not trigger a follow-up inform")
		end
	},
	{
		name = "inform packet: handle_response upgrade never flashes/reboots",
		fn = function()
			-- state.save() legitimately calls os.execute("mkdir -p ...") --
			-- what must NEVER happen is a sysupgrade/reboot/download command.
			local st = sample_state()
			local orig_execute = os.execute
			local commands = {}
			os.execute = function(cmd, ...)
				commands[#commands + 1] = cmd
				return orig_execute(cmd, ...)
			end
			local ok = pcall(inform.handle_response,
				'{"_type":"upgrade","version":"6.6.99","url":"http://unifi/fw.bin"}', st)
			os.execute = orig_execute
			assert_true(ok, "handle_response did not error")
			for _, cmd in ipairs(commands) do
				assert_true(type(cmd) == "string", "command is a string")
				assert_false(cmd:find("sysupgrade") ~= nil, "no sysupgrade: " .. cmd)
				assert_false(cmd:find("reboot") ~= nil, "no reboot: " .. cmd)
				assert_false(cmd:find("wget") ~= nil or cmd:find("curl") ~= nil,
					"no download command: " .. cmd)
			end
		end
	},
	{
		name = "inform packet: handle_response cmd set-locate sets st.locating",
		fn = function()
			local st = sample_state()
			local result = inform.handle_response('{"_type":"cmd","cmd":"set-locate"}', st)
			assert_true(st.locating, "locating true after set-locate")
			assert_true(result, "re-inform immediately after executing a command (fxkr protocol notes)")
		end
	},
	{
		name = "inform packet: an unhandled cmd or _type is logged by name and counted",
		fn = function()
			inform._unhandled_counts = {}
			local out = with_stderr(function()
				inform.handle_response('{"_type":"cmd","cmd":"unset-locate"}', sample_state())
			end)
			assert_nil(out:find("unhandled", 1, true), "a handled cmd is not reported")

			local r1, r2
			out = with_stderr(function()
				r1 = inform.handle_response('{"_type":"cmd","cmd":"clear-counters"}', sample_state())
				r2 = inform.handle_response('{"_type":"cmd","cmd":"clear-counters"}', sample_state())
			end)
			assert_contains(out, "unhandled cmd 'clear-counters' (1 since start)", "first sighting")
			assert_contains(out, "unhandled cmd 'clear-counters' (2 since start)", "counted per name")
			assert_true(r1 and r2, "an unhandled cmd still re-informs at once")

			out = with_stderr(function()
				inform.handle_response('{"_type":"cmd","cmd":"x y\\n' .. ("z"):rep(80) .. '"}', sample_state())
			end)
			assert_contains(out, "unhandled cmd 'x?y?", "controller-supplied name is reduced to one token")
			assert_nil(out:find(("z"):rep(48), 1, true), "and capped in length")

			out = with_stderr(function()
				inform.handle_response('{"_type":"setstate"}', sample_state())
				inform.handle_response('{"cfgversion":"abc"}', sample_state())
			end)
			assert_contains(out, "unhandled _type 'setstate' (1 since start)", "an unknown _type is reported")
			local _, n = out:gsub("unhandled", "")
			assert_eq(n, 1, "a response with no _type is not reported")
			inform._unhandled_counts = {}
		end
	},
	{
		name = "inform packet: handle_response cmd unset-locate clears st.locating",
		fn = function()
			local st = sample_state({locating = true})
			local result = inform.handle_response('{"_type":"cmd","cmd":"unset-locate"}', st)
			assert_false(st.locating, "locating false after unset-locate")
			assert_true(result, "re-inform immediately after executing a command")
		end
	},
	{
		name = "inform packet: a Locate persists the trigger it took over",
		fn = function()
			-- set-locate and unset-locate are two independent commands with
			-- nothing bounding the gap between them, so a restart lands there
			-- easily. Holding the snapshot only in memory means the process
			-- that stops the blink is not the one that started it and has
			-- nothing to put back -- on a board whose only LED belongs to a
			-- radio, that costs the activity light until someone notices.
			local st = sample_state()
			local writes = {}
			local orig_w, orig_r = inform._led._write_file, inform._led._read_file
			inform._led._write_file = function(path, contents)
				writes[#writes + 1] = {path = path, contents = contents}
				return true
			end
			inform._led._read_file = function(path)
				if path:find("/trigger", 1, true) then
					return "none timer [phy0tpt] phy1tpt\n"
				end
				return nil
			end
			local cfg = {led = "/sys/class/leds/mt76-phy0"}
			local ok, err = pcall(function()
				inform.handle_response('{"_type":"cmd","cmd":"set-locate"}', st, cfg)
				assert_true(st.locating, "locating set")
				assert_eq(st.locate_prev_trigger, "phy0tpt",
					"and the trigger it took over is in state, not just in memory")

				-- The restart: a fresh module with no in-memory snapshot.
				inform._led._saved_trigger = {}
				inform.handle_response('{"_type":"cmd","cmd":"unset-locate"}', st, cfg)
				assert_eq(writes[#writes].contents, "phy0tpt",
					"the persisted trigger is what gets restored")
				assert_nil(st.locate_prev_trigger, "and is cleared once spent")
			end)
			inform._led._write_file, inform._led._read_file = orig_w, orig_r
			inform._led._saved_trigger = {}
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: stopping a Locate returns the LED to its chosen idle state",
		fn = function()
			-- Restoring the trigger is not the whole idle state. A dedicated
			-- status LED's normal look is "trigger none, brightness on" --
			-- exactly what set_enabled leaves behind -- so restoring only the
			-- trigger brings it back on none/0, i.e. dark. Seen on an
			-- AX3000T: blue:status came out of Locate on trigger none with
			-- brightness 0 and the AP went dark.
			local st = sample_state({led_enabled = true})
			local writes = {}
			local orig_w, orig_r = inform._led._write_file, inform._led._read_file
			inform._led._write_file = function(path, contents)
				writes[#writes + 1] = {path = path, contents = contents}
				return true
			end
			inform._led._read_file = function(path)
				if path:find("/trigger", 1, true) then return "[none] timer\n" end
				return nil
			end
			local cfg = {led = "/sys/class/leds/blue:status"}
			local ok, err = pcall(function()
				inform.handle_response('{"_type":"cmd","cmd":"set-locate"}', st, cfg)
				inform.handle_response('{"_type":"cmd","cmd":"unset-locate"}', st, cfg)
				local last = writes[#writes]
				assert_eq(last.path, "/sys/class/leds/blue:status/brightness",
					"the last write is the brightness, not the trigger")
				assert_eq(last.contents, "1", "and it puts the LED back on")
			end)
			-- Never pushed: the board's own default must be left alone.
			local st2 = sample_state()
			local n_before
			local ok2, err2 = pcall(function()
				inform.handle_response('{"_type":"cmd","cmd":"set-locate"}', st2, cfg)
				n_before = #writes
				inform.handle_response('{"_type":"cmd","cmd":"unset-locate"}', st2, cfg)
				assert_eq(#writes, n_before + 1,
					"one write -- the trigger restore -- and no brightness assertion")
			end)
			inform._led._write_file, inform._led._read_file = orig_w, orig_r
			inform._led._saved_trigger = {}
			if not ok then error(err, 0) end
			if not ok2 then error(err2, 0) end
		end
	},
	{
		name = "inform packet: build_json passes the modelmap's hwassign to get_radio_table",
		fn = function()
			-- The knob is documented in USAGE.md and conf.lua and was read by
			-- nothing at all. Pin the whole path, not just get_radio_table's
			-- filtering: hwassign lives at dev.openuf.uap in the modelmap while
			-- build_json only ever receives dev.conf, so a lookup on the wrong
			-- table would leave it just as dead as before while looking wired.
			local seen = "not called"
			inform._ucihelper = {
				get_vap_table   = function() return {} end,
				get_radio_table = function(hwassign) seen = hwassign; return {} end,
			}
			inform.build_json(sample_state(), {
				net = {lan_cpueth = "eth0"},
				uap = {hwassign = {"radio0", "radio1"}},
			})
			inform._ucihelper = nil
			assert_true(type(seen) == "table", "hwassign reached get_radio_table")
			assert_eq(seen[1], "radio0", "first radio name passed through")
			assert_eq(seen[2], "radio1", "second radio name passed through")
		end
	},
	{
		name = "inform packet: build_json passes no hwassign when the modelmap has none",
		fn = function()
			local seen, called = "sentinel", false
			inform._ucihelper = {
				get_vap_table   = function() return {} end,
				get_radio_table = function(hwassign) called = true; seen = hwassign; return {} end,
			}
			inform.build_json(sample_state(), {net = {lan_cpueth = "eth0"}})
			inform._ucihelper = nil
			assert_true(called, "get_radio_table still called")
			assert_nil(seen, "no hwassign -> nil, i.e. report every radio")
		end
	},
	{
		name = "inform packet: handle_response cmd block-sta adds the MAC, persists, reconciles, and deauths",
		fn = function()
			local st = sample_state()
			local reconciled, deauthed, denied
			local order = {}
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function(mac, ifnames)
					deauthed = {mac = mac, ifnames = ifnames}; order[#order + 1] = "deauth"
				end,
				hostapd_sockets = function() return "" end, deny_sync = function(macs, bsses)
					denied = {macs = macs, bsses = bsses}; order[#order + 1] = "deny"
					return false
				end,
			}
			inform._ucihelper = bss_mock()
			inform._deny_pending = false
			local result = inform.handle_response(
				'{"_type":"cmd","cmd":"block-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_eq(#st.blocked_stas, 1, "one MAC persisted")
			assert_eq(st.blocked_stas[1], "aa:bb:cc:dd:ee:01", "correct MAC persisted")
			assert_eq(#reconciled, 1, "reconcile called with the updated list")
			assert_eq(reconciled[1], "aa:bb:cc:dd:ee:01", "reconcile sees the newly blocked MAC")
			assert_eq(deauthed.mac, "aa:bb:cc:dd:ee:01", "deauth targets the blocked MAC")
			-- Every BSS, not one per radio: the IoT SSID shares radio0 with
			-- the home SSID, and its VLAN netdev folds into its own BSS.
			assert_eq(table.concat(deauthed.ifnames, ","), "phy0-ap0,phy0-ap1,phy1-ap0",
				"deauth issued on every BSS, VLAN netdevs folded into theirs")
			-- The refusal goes into hostapd before the deauth, so the client
			-- has no gap to reassociate in.
			assert_eq(table.concat(denied.macs, ","), "aa:bb:cc:dd:ee:01", "hostapd's deny list gets the MAC")
			assert_eq(table.concat(denied.bsses, ","), "phy0-ap0,phy0-ap1,phy1-ap0", "on every BSS")
			assert_eq(table.concat(order, ","), "deny,deauth", "refused before it is kicked")
			assert_true(result, "re-inform immediately after executing a command")
		end
	},
	{
		name = "inform packet: handle_response cmd block-sta is idempotent for an already-blocked MAC",
		fn = function()
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform.handle_response('{"_type":"cmd","cmd":"block-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_eq(#st.blocked_stas, 1, "MAC not duplicated")
		end
	},
	{
		name = "inform packet: handle_response cmd unblock-sta removes the MAC and reconciles",
		fn = function()
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}})
			local reconciled, denied
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function() end,
				hostapd_sockets = function() return "" end, deny_sync = function(macs) denied = macs; return true end,
			}
			inform._deny_pending = false
			local result = inform.handle_response(
				'{"_type":"cmd","cmd":"unblock-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_eq(table.concat(denied or {}, ","), "aa:bb:cc:dd:ee:02",
				"hostapd's deny list is synced to what is still blocked")
			assert_true(inform._deny_pending, "and looked at again next tick, as deny_sync asked")
			inform._deny_pending = false
			assert_eq(#st.blocked_stas, 1, "one MAC remains")
			assert_eq(st.blocked_stas[1], "aa:bb:cc:dd:ee:02", "the other MAC is untouched")
			assert_eq(#reconciled, 1, "reconcile called with the updated (shorter) list")
			assert_true(result, "re-inform immediately after executing a command")
		end
	},
	{
		name = "inform packet: handle_response cmd kick-sta deauths on every BSS and blocks nothing",
		fn = function()
			-- Client -> Reconnect. A one-shot deauth: the client may come
			-- straight back, so no ledger entry and no nft reconcile.
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:02"}})
			local deauthed, reconciled
			inform._firewall = {
				reconcile = function() reconciled = true end,
				deauth = function(mac, ifnames) deauthed = {mac = mac, ifnames = ifnames} end,
			}
			inform._ucihelper = bss_mock()
			local result = inform.handle_response(
				'{"_type":"cmd","cmd":"kick-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_true(deauthed ~= nil, "kick-sta deauthenticates")
			assert_eq(deauthed.mac, "aa:bb:cc:dd:ee:01", "deauth targets the kicked MAC")
			assert_eq(table.concat(deauthed.ifnames, ","), "phy0-ap0,phy0-ap1,phy1-ap0",
				"deauth issued on every BSS")
			assert_eq(reconciled, nil, "a kick does not touch the block table")
			assert_eq(#st.blocked_stas, 1, "a kick adds nothing to the block ledger")
			assert_true(result, "re-inform immediately after executing a command")
		end
	},
	{
		name = "inform packet: scan and scan_band sweep the requested radios and re-inform",
		fn = function()
			-- Two radios (2.4 + 5 GHz), each sweep recorded. The controller
			-- reads the result from the next inform's scan_radio_table, so the
			-- sweep has to happen here, before the immediate re-inform.
			local orig_uci, orig_stderr = inform._ucihelper, io.stderr
			io.stderr = {write = function() end}
			local popens
			inform._ucihelper = {
				get_radio_table = function()
					return {{name = "radio0", radio = "na"}, {name = "radio1", radio = "ng"}}
				end,
				get_ifname_for_radio = function(r) return r == "radio0" and "phy0-ap0" or "phy1-ap0" end,
				_popen = function(cmd) popens[#popens + 1] = cmd; return "scan-ok\n" end,
			}
			local function run(body)
				popens = {}
				local r = inform.handle_response(body, sample_state(), {})
				return r, popens
			end
			local ok, err = pcall(function()
				-- What the Scan button sends: no radio, no freq -> every radio.
				local r, p = run('{"_type":"cmd","cmd":"scan","type":"active","mode":"sync"}')
				assert_true(r, "re-inform immediately after a scan")
				assert_eq(#p, 2, "scan with no radio_name sweeps every radio")
				assert_contains(p[1], "iw dev phy0-ap0 scan ap-force >", "active, forced, full sweep")
				assert_contains(p[2], "iw dev phy1-ap0 scan ap-force >", "and the other radio")

				_, p = run('{"_type":"cmd","cmd":"scan","radio_name":"radio1"}')
				assert_eq(#p, 1, "radio_name narrows to that radio")
				assert_contains(p[1], "iw dev phy1-ap0 ", "the named radio")

				_, p = run('{"_type":"cmd","cmd":"scan","type":"passive","freq":"5180"}')
				assert_eq(#p, 1, "a freq without a radio picks the radio on that band")
				assert_contains(p[1], "iw dev phy0-ap0 scan freq 5180 ap-force passive >",
					"freq before the flags, passive last")

				_, p = run('{"_type":"cmd","cmd":"scan","radio_name":"radio9"}')
				assert_eq(#p, 0, "an unknown radio_name sweeps nothing")

				r, p = run('{"_type":"cmd","cmd":"scan_band","band":"ng"}')
				assert_true(r, "re-inform immediately after scan_band")
				assert_eq(#p, 1, "scan_band sweeps only that band's radio")
				assert_contains(p[1], "iw dev phy1-ap0 scan ap-force >", "the 2.4 GHz radio")

				_, p = run('{"_type":"cmd","cmd":"scan_band","band":"6e"}')
				assert_eq(#p, 0, "a band this AP has no radio for sweeps nothing")
			end)
			inform._ucihelper, io.stderr = orig_uci, orig_stderr
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: handle_response cmd kick-sta without a mac is a safe no-op",
		fn = function()
			local st = sample_state()
			local deauthed = false
			inform._firewall = { reconcile = function() end, deauth = function() deauthed = true end }
			inform._ucihelper = bss_mock()
			local result = inform.handle_response('{"_type":"cmd","cmd":"kick-sta"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_eq(deauthed, false, "nothing to deauth without a mac")
			assert_true(result, "still re-informs")
		end
	},
	{
		name = "inform packet: handle_response cmd block-sta without a mac field is a safe no-op",
		fn = function()
			local st = sample_state()
			local called = false
			inform._firewall = {
				reconcile = function() called = true end,
				deauth = function() called = true end,
			}
			inform.handle_response('{"_type":"cmd","cmd":"block-sta"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_true(st.blocked_stas == nil, "state untouched without a mac field in the command")
			assert_false(called, "firewall not touched without a mac field")
		end
	},
	{
		name = "inform packet: authorize-guest / unauthorize-guest drive the guest ledger",
		fn = function()
			local st = sample_state()
			local saved = 0
			local save = inform._state.save
			inform._state.save = function() saved = saved + 1 end
			local ok, err = pcall(function()
				local r = inform.handle_response(
					'{"_type":"cmd","cmd":"authorize-guest","mac":"AA:BB:CC:DD:EE:01"}', st)
				assert_true(r, "re-inform so the controller sees authorized at once")
				assert_not_nil(st.guest_authorized["aa:bb:cc:dd:ee:01"], "recorded, lowercased")
				assert_eq(saved, 1, "persisted")
				inform.handle_response('{"_type":"cmd","cmd":"authorize-guest","mac":"x;reboot"}', st)
				inform.handle_response('{"_type":"cmd","cmd":"authorize-guest"}', st)
				local n = 0
				for _ in pairs(st.guest_authorized) do n = n + 1 end
				assert_eq(n, 1, "a malformed or missing mac records nothing")
				inform.handle_response(
					'{"_type":"cmd","cmd":"unauthorize-guest","mac":"aa:bb:cc:dd:ee:01"}', st)
				assert_eq(next(st.guest_authorized), nil, "unauthorize-guest drops it")
			end)
			inform._state.save = save
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: unauthorize-guest disconnects the guest after closing the portal on it",
		fn = function()
			local real_fw, real_gp, real_time = inform._firewall, inform._guestportal, inform._time
			local save = inform._state.save
			local order, kicks = {}, {}
			local now = 1000
			inform._time = function() return now end
			inform._state.save = function() end
			inform._firewall = {reconcile = function() end, hostapd_sockets = function() return "" end, deny_sync = function() return false end,
				deauth = function(mac, ifnames)
					kicks[#kicks + 1] = {mac = mac, ifnames = ifnames}; order[#order + 1] = "deauth"
				end}
			inform._guestportal = {set_authorized = function() order[#order + 1] = "nft" end}
			inform._ucihelper = bss_mock()
			inform._guest_kicked = {}
			local ok, err = pcall(function()
				local st = sample_state({guest_authorized = {["de:ad:be:ef:00:02"] = 1}})
				inform._guest_built = "phy0-ap1=x"
				local function cmd(c, mac)
					return inform.handle_response(cjson.encode({_type = "cmd", cmd = c, mac = mac}), st)
				end
				assert_true(cmd("unauthorize-guest", "DE:AD:BE:EF:00:02"), "re-inform")
				assert_eq(#kicks, 1, "one deauth")
				assert_eq(kicks[1].mac, "de:ad:be:ef:00:02", "of that guest, lowercased")
				assert_eq(table.concat(kicks[1].ifnames, ","), "phy0-ap0,phy0-ap1,phy1-ap0",
					"on every BSS: the firmware kicks on every user and guest VAP")
				assert_eq(table.concat(order, ","), "nft,deauth",
					"out of the authorized set first, so it reconnects to the portal")
				cmd("authorize-guest", "de:ad:be:ef:00:03")
				cmd("unauthorize-guest", "x;reboot")
				cmd("unauthorize-guest", nil)
				assert_eq(#kicks, 1, "authorize-guest and a malformed mac kick nobody")
				-- A MAC openUF had no record of is still kicked: the controller
				-- only asks when the station reports authorized.
				cmd("unauthorize-guest", "de:ad:be:ef:00:09")
				assert_eq(#kicks, 2, "kicked without a ledger entry, as the firmware does")
				now = now + inform.GUEST_KICK_HOLD - 1
				cmd("unauthorize-guest", "de:ad:be:ef:00:02")
				assert_eq(#kicks, 2, "a repeat inside the hold is not kicked again")
				now = now + 1
				cmd("unauthorize-guest", "de:ad:be:ef:00:02")
				assert_eq(#kicks, 3, "after the hold it is")
				now = 10
				cmd("unauthorize-guest", "de:ad:be:ef:00:02")
				assert_eq(#kicks, 4, "a clock step backwards does not hold it forever")
				inform._guest_built = nil
				cmd("unauthorize-guest", "de:ad:be:ef:00:05")
				assert_eq(#kicks, 5, "no portal built: still kicked")
			end)
			inform._firewall, inform._guestportal, inform._time = real_fw, real_gp, real_time
			inform._state.save, inform._ucihelper, inform._guest_built = save, nil, nil
			inform._guest_kicked = {}
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: the guest ledger is capped, oldest authorization first",
		fn = function()
			local st = sample_state({guest_authorized = {}})
			local max = inform.GUEST_LEDGER_MAX
			for i = 1, max do
				st.guest_authorized[("02:00:00:00:%02x:%02x"):format(math.floor(i / 256), i % 256)] = 1000 + i
			end
			inform._guest_authorize(st, "aa:bb:cc:dd:ee:01", true)
			local n = 0
			for _ in pairs(st.guest_authorized) do n = n + 1 end
			assert_eq(n, max, "held at the cap")
			assert_eq(st.guest_authorized["02:00:00:00:00:01"], nil, "the oldest went")
			assert_not_nil(st.guest_authorized["aa:bb:cc:dd:ee:01"], "the new one stays")
		end
	},
	{
		name = "inform packet: system_cfg records the portal WLANs; portal off clears them",
		fn = function()
			-- Shape from the 10.4.57 lab capture (PROTOCOL-VALIDATION.md,
			-- "Guest portal"): wireless.<n>.is_guest per WLAN, one
			-- redirector.status for the site, "disabled" when off.
			local function push(st, portal)
				local sys = "aaa.1.id=w1\nwireless.1.ssid=g\nwireless.1.parent=wifi0\n"
					.. "wireless.1.is_guest=true\naaa.2.id=w2\nwireless.2.ssid=h\n"
					.. "wireless.2.parent=wifi0\nwireless.2.is_guest=false\n"
					.. "redirector.status=" .. portal .. "\n"
				inform.handle_response('{"_type":"setparam","system_cfg":"' .. sys .. '"}',
					st, {net = {lan_cpueth = "eth0"}})
			end
			local st = sample_state()
			push(st, "enabled")
			assert_true(st.guest_wlans.w1, "the guest WLAN needs the portal")
			assert_eq(st.guest_wlans.w2, nil, "the other WLAN does not")
			push(st, "disabled")
			assert_eq(next(st.guest_wlans), nil, "portal off: no WLAN needs it")
		end
	},
	{
		name = "inform packet: setparam blocked_sta replaces the ledger, reconciles, deauths only new MACs",
		fn = function()
			-- The wire form captured from 10.4.57: the site's blocked
			-- clients joined with "\n", beside system_cfg/mgmt_cfg.
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:09"}})
			local reconciled, deauthed, denied = nil, {}, nil
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function(mac, ifnames) deauthed[#deauthed + 1] = mac .. "@" .. table.concat(ifnames, ",") end,
				hostapd_sockets = function() return "" end, deny_sync = function(macs) denied = table.concat(macs, ","); return false end,
			}
			inform._ucihelper = bss_mock()
			inform._deny_pending = false
			local result = inform.handle_response(cjson.encode({_type = "setparam",
				blocked_sta = "aa:bb:cc:dd:ee:01\nAA:BB:CC:DD:EE:02"}), st)
			assert_eq(denied, "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02", "hostapd's deny list follows the new list")
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_eq(table.concat(st.blocked_stas, ","), "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02",
				"ledger is the controller's list, lowercased; a MAC it dropped is gone")
			assert_eq(table.concat(reconciled, ","), "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02",
				"nft rebuilt from the new list")
			assert_eq(table.concat(deauthed, " "), "aa:bb:cc:dd:ee:02@phy0-ap0,phy0-ap1,phy1-ap0",
				"only the newly blocked MAC is deauthed, on every BSS")
			assert_false(result, "a plain setparam does not re-inform")
		end
	},
	{
		name = "inform packet: a fresh start looks at hostapd's deny lists once even with nothing blocked",
		fn = function()
			-- An unblock that happened while openUF was down (state.json
			-- edited, a reset) leaves hostapd refusing the MAC: the first
			-- tick cleans it up.
			local fresh = dofile("openuf/inform.lua")
			assert_true(fresh._deny_pending, "pending from the start")
		end
	},
	{
		name = "inform packet: _block_resync syncs hostapd every tick only while a sync is pending",
		fn = function()
			-- hostapd's deny list is runtime-only. While a sync has not
			-- settled (a BSS that did not answer, a change to read back) it
			-- runs every tick, also once the ledger is empty, until a pass
			-- finds nothing left to clean.
			local calls, answer, now = {}, true, 1000
			local real_time = inform._time
			inform._time = function() return now end
			inform._firewall = {reconcile = function() end, deauth = function() end,
				hostapd_sockets = function() return "s" end,
				deny_sync = function(macs, bsses)
					calls[#calls + 1] = table.concat(macs, ",") .. "@" .. table.concat(bsses, ",")
					return answer
				end}
			inform._ucihelper = bss_mock()
			inform._deny_at, inform._deny_socks, inform._deny_settle = nil, nil, nil
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			inform._deny_pending = false
			assert_true(inform._block_resync(st), "first look: synced")
			assert_eq(calls[1], "aa:bb:cc:dd:ee:01@phy0-ap0,phy0-ap1,phy1-ap0", "on every BSS")
			assert_true(inform._block_resync(st), "that pass asked for another: synced the same second")
			st.blocked_stas = {}
			assert_true(inform._block_resync(st), "empty but pending from the last pass: synced")
			answer = false
			assert_true(inform._block_resync(st), "still pending (that pass changed something): synced")
			assert_false(inform._block_resync(st), "a clean pass: nothing more to do")
			now = now + 3600
			assert_false(inform._block_resync(st), "nothing blocked, nothing pending: never")
			assert_eq(#calls, 4, "no call once clean")
			inform._time = real_time
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
		end
	},
	{
		name = "inform packet: a settled block is re-checked once a minute, or at once when a hostapd socket is replaced",
		fn = function()
			local n, now, socks = 0, 1000, "/var/run/hostapd/phy0-ap0=11"
			local real_time = inform._time
			inform._time = function() return now end
			inform._firewall = {reconcile = function() end, deauth = function() end,
				hostapd_sockets = function() return socks end,
				deny_sync = function() n = n + 1; return false end}
			inform._ucihelper = bss_mock()
			inform._deny_at, inform._deny_socks, inform._deny_settle = nil, nil, nil
			inform._deny_pending = false
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			assert_true(inform._block_resync(st), "first look")
			for _, dt in ipairs({15, 30, 59}) do
				now = 1000 + dt
				assert_false(inform._block_resync(st), "settled: not at +" .. dt .. " s")
			end
			now = 1060
			assert_true(inform._block_resync(st), "DENY_INTERVAL later: again")
			assert_eq(n, 2, "two syncs in a minute of ticks")
			-- A hostapd restart, or a BSS torn down and rebuilt, threw the
			-- runtime list away; its control socket is a new one.
			now = 1075
			socks = "/var/run/hostapd/phy0-ap0=12"
			assert_true(inform._block_resync(st), "a replaced socket: at once")
			now = 1090
			assert_false(inform._block_resync(st), "and settled again after")
			now = 1000
			assert_true(inform._block_resync(st), "a clock stepped back: looked at, not skipped for an hour")
			assert_eq(n, 4, "no other syncs")
			inform._time = real_time
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
		end
	},
	{
		name = "inform packet: after openUF's own wifi reload the deny list is checked every tick for DENY_SETTLE",
		fn = function()
			-- `wifi reload` lands asynchronously and can reload a BSS in
			-- place, keeping its socket: a clean sync the tick after the push
			-- may have read the list before hostapd dropped it.
			local n, now = 0, 2000
			local real_time = inform._time
			inform._time = function() return now end
			inform._firewall = {reconcile = function() end, deauth = function() end,
				hostapd_sockets = function() return "s" end,
				deny_sync = function() n = n + 1; return false end}
			inform._ucihelper = bss_mock()
			inform._deny_at, inform._deny_socks, inform._deny_settle = nil, nil, nil
			inform._deny_pending = false
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			assert_true(inform._block_resync(st), "first look")
			inform._deny_reloaded()
			for _, dt in ipairs({0, 15, 30, 59}) do
				now = 2000 + dt
				assert_true(inform._block_resync(st), "within the settle window: +" .. dt .. " s")
			end
			now = 2060
			assert_false(inform._block_resync(st), "window over, and the last sync was 1 s ago")
			now = 2119
			assert_true(inform._block_resync(st), "back to once a minute")
			inform._deny_reloaded()          -- settle until 2179
			now = 1000                       -- a clock stepped back 1119 s
			assert_true(inform._block_resync(st), "stepped back: one look")
			now = 1010
			assert_false(inform._block_resync(st), "but the window is not stretched over the step")
			inform._time = real_time
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
		end
	},
	{
		name = "inform packet: a WiFi push and a Forget open the deny-sync settle window",
		fn = function()
			local real_time = inform._time
			inform._time = function() return 5000 end
			inform._deny_settle = nil
			local orig = inform._usteer.set_enabled
			inform._usteer.set_enabled = function() end
			inform._ucihelper = {apply_config = function() end}
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			inform.handle_response(('{"_type":"setparam","system_cfg":"%s"}'):format(sys_cfg),
				sample_state(), {net = {lan_cpueth = "eth0"}})
			assert_eq(inform._deny_settle, 5000 + inform.DENY_SETTLE, "the push ran wifi reload")
			inform._deny_settle = nil
			inform._ucihelper = {forget = function() end}
			inform._forget_controller()
			assert_eq(inform._deny_settle, 5000 + inform.DENY_SETTLE, "so did the Forget")
			inform._usteer.set_enabled = orig
			inform._deny_settle = nil
			inform._ucihelper = nil
			inform._time = real_time
		end
	},
	{
		name = "inform packet: setparam blocked_sta \"\" clears every block",
		fn = function()
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			local reconciled, deauthed = nil, false
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function() deauthed = true end,
			}
			inform.handle_response('{"_type":"setparam","blocked_sta":""}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_eq(#st.blocked_stas, 0, "present-but-empty means nothing is blocked")
			assert_eq(#reconciled, 0, "nft set emptied")
			assert_false(deauthed, "unblocking deauths nobody")
		end
	},
	{
		name = "inform packet: setparam without blocked_sta leaves the ledger alone",
		fn = function()
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:01"}})
			local called = false
			inform._firewall = {
				reconcile = function() called = true end,
				deauth = function() called = true end,
			}
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"cfgversion=abc"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_eq(table.concat(st.blocked_stas, ","), "aa:bb:cc:dd:ee:01", "absent is not empty")
			assert_false(called, "firewall untouched")
		end
	},
	{
		name = "inform packet: setparam blocked_sta with the same set does not rebuild nft",
		fn = function()
			-- Every config push carries the list: reconcile drops and
			-- recreates the table, so an unchanged list must not touch it.
			local st = sample_state({blocked_stas = {"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"}})
			local called = false
			inform._firewall = {
				reconcile = function() called = true end,
				deauth = function() called = true end,
			}
			inform.handle_response(cjson.encode({_type = "setparam",
				blocked_sta = "aa:bb:cc:dd:ee:01\naa:bb:cc:dd:ee:02\naa:bb:cc:dd:ee:01"}), st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_false(called, "same set in another order (with a duplicate) is a no-op")
			assert_eq(#st.blocked_stas, 2, "ledger kept")
		end
	},
	{
		name = "inform packet: setparam blocked_sta skips malformed entries",
		fn = function()
			local st = sample_state()
			local reconciled
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function() end,
			}
			inform._ucihelper = bss_mock()
			inform.handle_response(cjson.encode({_type = "setparam",
				blocked_sta = "aa:bb:cc:dd:ee:01\n\nnot-a-mac\naa:bb:cc:dd:ee:0;reboot\n aa:bb:cc:dd:ee:03 \n"}), st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_eq(table.concat(st.blocked_stas, ","), "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:03",
				"only well-formed MACs kept (surrounding whitespace trimmed)")
			assert_eq(table.concat(reconciled, ","), "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:03",
				"nft sees the same list")
		end
	},
	{
		name = "inform packet: handle_response cmd re-informs immediately even for unhandled commands",
		fn = function()
			local st = sample_state()
			local result = inform.handle_response('{"_type":"cmd","cmd":"mfi-output"}', st)
			assert_true(result, "re-inform immediately regardless of which command was received")
		end
	},
	{
		name = "inform packet: handle_response cmd spectrum-scan builds spectrum_table from survey dump",
		fn = function()
			local st = sample_state()
			-- Save/restore everything this test stubs: these are module-level
			-- seams, and leaking them would make any later build_json/
			-- radio_stats test silently run against this test's fixtures.
			local orig_uci, orig_stats = inform._ucihelper, inform._sysinfo.radio_stats
			local orig_cache = inform._spectrum_cache
			inform._spectrum_cache = {}
			local popens = {}
			inform._ucihelper = {
				get_radio_table = function()
					return { { name = "radio0", radio = "ng", channel = "6", ht = "HT40" } }
				end,
				get_ifname_for_radio = function() return "wlan0" end,
				_popen = function(cmd) popens[#popens + 1] = cmd; return "scan-ok\n" end,
			}
			inform._sysinfo.radio_stats = function()
				return {
					{ freq = 2437, noise = -95, channel_time = 5000, channel_time_busy = 1850 },
					{ freq = 2412, noise = -90, channel_time = 100,  channel_time_busy = 12 },
					{ freq = 2462, noise = -96, channel_time = 9000, channel_time_busy = 900, in_use = true },
				}
			end
			local orig_sleep, sleeps = inform._sleep, {}
			inform._sleep = function(sec) sleeps[#sleeps + 1] = sec end

			local ok, err = pcall(function()
				-- The real payload carries a whole scan-mode system_cfg in
				-- spectrum-cfg (captured on 10.4.57); it must not be applied.
				local result = inform.handle_response('{"_type":"cmd","cmd":"spectrum-scan",'
					.. '"spectrum-cfg":"wireless.1.ssid=vport-x\\nradio.1.rfscan=enabled\\n"}', st)
				assert_true(result, "re-inform immediately after executing a command")
				assert_eq(#popens, 0, "the cmd only marks the scan pending")
				assert_true(inform._spectrum_pending, "pending until _tick sweeps")
				inform._spectrum_pending = false
				inform._run_spectrum_scan()

				local cached = inform._spectrum_cache.radio0
				assert_true(cached ~= nil, "spectrum-scan cmd populates _spectrum_cache for the radio")
				-- One entry per (frequency, width): the UI filters on the
				-- chart's width and averages each bonded block's channels.
				assert_eq(#cached.table, 6, "3 frequencies x widths 20/40 on 2.4 GHz")
				assert_eq(cached.table[1].width, 20, "20 MHz entry")
				assert_eq(cached.table[2].width, 40, "40 MHz entry")
				assert_eq(cached.table[2].utilization, cached.table[1].utilization, "same measurement per width")
				assert_true(cached.table[1].channel == 6, "channel derived from 2437MHz")
				assert_true(cached.table[1].center_freq == 2437, "center_freq passed through from survey dump")
				assert_eq(cached.table[3].center_freq, 2412, "next frequency after its widths")
				assert_true(cached.table[1].utilization == 37, "utilization = channel_time_busy/channel_time * 100")
				assert_true(cached.table[1].interference == -95, "interference is best-effort noise-floor passthrough")
				-- One scan per channel with a longer dwell, back on the
				-- operating channel in between (a whole sweep never returns
				-- to it); the operating channel itself is not scanned.
				-- ap-force guards against a driver that refuses to scan on a
				-- beaconing AP (ours do not; see inform._force_scan).
				assert_eq(#popens, 2, "one scan per off-channel frequency")
				assert_contains(popens[1], "iw dev wlan0 scan freq 2437 duration 200 ap-force", "first channel, 200 TU")
				assert_contains(popens[2], "iw dev wlan0 scan freq 2412 duration 200 ap-force", "second channel")
				assert_eq(#sleeps, 1, "home between the two scans, not after the last")
				assert_eq(sleeps[1], 0.3, "0.3 s on the operating channel")
			end)
			inform._sleep = orig_sleep
			inform._ucihelper, inform._sysinfo.radio_stats = orig_uci, orig_stats
			inform._spectrum_cache = orig_cache
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: a refused spectrum sweep is logged and still reports the survey it has",
		fn = function()
			local st = sample_state()
			local orig_uci, orig_stats = inform._ucihelper, inform._sysinfo.radio_stats
			local orig_cache, orig_stderr = inform._spectrum_cache, io.stderr
			inform._spectrum_cache = {}
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			inform._ucihelper = {
				get_radio_table = function() return { { name = "radio0", radio = "ng", channel = "6", ht = "HT20" } } end,
				get_ifname_for_radio = function() return "wlan0" end,
				_popen = function() return "" end,   -- iw failed: no scan-ok
			}
			inform._sysinfo.radio_stats = function()
				return { { freq = 2437, noise = -95, channel_time = 100, channel_time_busy = 10 },
				         { freq = 2412, noise = -95, channel_time = 100, channel_time_busy = 10 } }
			end
			local orig_sleep = inform._sleep
			inform._sleep = function() end
			local ok, err = pcall(inform._run_spectrum_scan)
			inform._sleep = orig_sleep
			local cached = inform._spectrum_cache.radio0
			inform._ucihelper, inform._sysinfo.radio_stats = orig_uci, orig_stats
			inform._spectrum_cache, io.stderr = orig_cache, orig_stderr
			assert_true(ok, tostring(err))
			assert_contains(table.concat(logged), "spectrum-scan: iw refused to scan wlan0",
				"the refusal is visible, not silent")
			local n = select(2, table.concat(logged):gsub("iw refused", ""))
			assert_eq(n, 1, "one refusal line per radio, not one per channel")
			assert_true(cached ~= nil and #cached.table == 4, "the survey is still reported (2 channels x 20/40)")
		end
	},
	{
		name = "inform packet: the spectrum-scan home sleep needs only luasocket",
		fn = function()
			-- Found on the APs: _sleep went through M._socket, a seam only
			-- the guest-portal build defines, and the sweep died after its
			-- first channel ("attempt to call field '_socket'").
			local orig = inform._socket
			inform._socket = nil
			local ok, err = pcall(inform._sleep, 0)
			inform._socket = orig
			assert_true(ok, "sleeps without M._socket: " .. tostring(err))
		end
	},
	{
		name = "inform packet: spectrum_table widths follow the band and the configured width",
		fn = function()
			local w = inform._spectrum_widths
			assert_eq(table.concat(w({ radio = "ng", ht = "HT20" }), ","), "20,40", "2.4 GHz")
			assert_eq(table.concat(w({ radio = "ng", ht = "HE40" }), ","), "20,40", "2.4 GHz at 40")
			assert_eq(table.concat(w({ radio = "na", ht = "VHT40" }), ","), "20,40,80", "5 GHz")
			assert_eq(table.concat(w({ radio = "na", ht = "HE160" }), ","), "20,40,80,160", "5 GHz at 160")
			assert_eq(table.concat(w({ radio = "6e", ht = "EHT320" }), ","), "20,40,80,160,320", "6 GHz at 320")
			assert_eq(table.concat(w({ radio = "na" }), ","), "20,40,80", "no htmode")
		end
	},
	{
		name = "inform packet: spectrum-scan keeps the pre-sweep noise when the post-sweep read is 0",
		fn = function()
			-- On real hardware the OPERATING channel's noise reads back as 0
			-- immediately after an `iw scan` sweep -- the radio has just
			-- returned from off-channel -- while the same channel reports
			-- -106 dBm moments later. 0 dBm is not a plausible noise floor,
			-- and this value goes to the controller as `interference`.
			local st = sample_state()
			local orig_uci, orig_stats = inform._ucihelper, inform._sysinfo.radio_stats
			local orig_cache = inform._spectrum_cache
			inform._spectrum_cache = {}
			local scanned = false
			inform._ucihelper = {
				get_radio_table = function()
					return { { name = "radio0", radio = "na", channel = "36", ht = "HT40" } }
				end,
				get_ifname_for_radio = function() return "wlan0" end,
				_popen = function(cmd)
					if tostring(cmd):match("scan") then scanned = true end
					return "scan-ok\n"
				end,
			}
			inform._sysinfo.radio_stats = function()
				if not scanned then
					-- pre-sweep: the operating channel has a real noise floor
					return {
						{ freq = 5180, noise = -106, channel_time = 1000, channel_time_busy = 10, in_use = true },
						{ freq = 5200, noise = -105, channel_time = 46, channel_time_busy = 0 },
					}
				end
				-- post-sweep: operating channel's noise has gone to 0
				return {
					{ freq = 5180, noise = 0,    channel_time = 5000, channel_time_busy = 500 },
					{ freq = 5200, noise = -104, channel_time = 46, channel_time_busy = 0 },
				}
			end

			local ok, err = pcall(function()
				inform._run_spectrum_scan()
				local t = inform._spectrum_cache.radio0.table
				assert_eq(t[1].interference, -106,
					"operating channel keeps its pre-sweep noise floor, not 0")
				assert_eq(t[1].utilization, 10,
					"utilization still comes from the fresh post-sweep counters")
				-- t[1..3] are the first frequency at 20/40/80 MHz.
				assert_eq(t[4].interference, -104,
					"a valid post-sweep reading always wins over the pre-sweep one")
			end)
			inform._ucihelper, inform._sysinfo.radio_stats = orig_uci, orig_stats
			inform._spectrum_cache = orig_cache
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: _populate_net_info does not trigger announce.lua's self-executing entry point outside test mode",
		fn = function()
			-- Regression test: _populate_net_info dofile()s announce.lua to
			-- reuse get_mac/get_ip. Outside of test mode, announce.lua's own
			-- bottom "script entry point" block would otherwise fire (it's
			-- only guarded by `if not OPENUF_TEST_MODE`), spawning an
			-- infinite broadcast loop nested inside the caller, or calling
			-- os.exit(1) on this test process if the broadcast send errors --
			-- either way this test would visibly hang or the whole suite
			-- would abort if the suppression regresses.
			local prev = OPENUF_TEST_MODE
			OPENUF_TEST_MODE = nil  -- simulate real (non-test) execution
			local st = {}
			local ok = pcall(inform._populate_net_info, st, nil)
			local restored = OPENUF_TEST_MODE
			OPENUF_TEST_MODE = prev
			assert_true(ok, "_populate_net_info did not error/exit with OPENUF_TEST_MODE unset")
			assert_true(restored == nil, "OPENUF_TEST_MODE restored to its prior (unset) value after the call")
		end
	},
	{
		name = "inform: _populate_net_info fills st.hostname from the real system hostname",
		fn = function()
			-- The doc comments always claimed mac/ip/hostname were populated
			-- here, but hostname never was -- so build_json's
			-- `st.hostname or "openUF"` fallback labeled every device
			-- "openUF" in the controller. Runs against the dev machine's real
			-- `hostname` binary (get_mac/get_ip harmlessly find nothing).
			local st = {}
			inform._populate_net_info(st, nil)
			assert_true(type(st.hostname) == "string" and st.hostname ~= "",
				"st.hostname populated with a nonempty string")
		end
	},
	{
		name = "inform packet: handle_response dumps raw JSON when debug_dump_file set",
		fn = function()
			local st = sample_state()
			local path = "/tmp/openuf_test_dump.log"
			os.remove(path)
			local cfg = { config = { debug_dump_file = path } }
			inform.handle_response('{"_type":"noop"}', st, cfg)
			local f = io.open(path, "r")
			assert_true(f ~= nil, "dump file was created")
			local contents = f:read("*a")
			f:close()
			os.remove(path)
			assert_true(contents:find('{"_type":"noop"}', 1, true) ~= nil,
				"dump file contains the raw response JSON")
		end
	},
	{
		name = "inform packet: handle_response does not dump when debug_dump_file unset",
		fn = function()
			local st = sample_state()
			local path = "/tmp/openuf_test_dump_unset.log"
			os.remove(path)
			inform.handle_response('{"_type":"noop"}', st, { config = {} })
			local f = io.open(path, "r")
			assert_true(f == nil, "no dump file created when flag is unset")
		end
	},
	{
		name = "inform packet: handle_response restarts the dump once it passes the cap",
		fn = function()
			local st = sample_state()
			local path = "/tmp/openuf_test_dump_cap.log"
			os.remove(path)
			local pre = io.open(path, "w")
			pre:write(string.rep("x", 5000) .. "\nOLDMARKER\n")
			pre:close()
			inform.handle_response('{"_type":"noop"}', st,
				{ config = { debug_dump_file = path, debug_dump_max_bytes = 1024 } })
			local f = io.open(path, "r")
			local contents = f:read("*a")
			f:close()
			os.remove(path)
			assert_true(contents:find("OLDMARKER", 1, true) == nil,
				"the oversized previous contents are gone")
			assert_true(contents:find("restarted", 1, true) ~= nil,
				"a restart marker records why the history vanished")
			assert_true(contents:find('{"_type":"noop"}', 1, true) ~= nil,
				"the response that triggered the restart is still recorded")
			assert_true(#contents < 1024,
				"the file is back under the cap, not merely appended to")
		end
	},
	{
		name = "inform packet: handle_response appends while the dump is under the cap",
		fn = function()
			local st = sample_state()
			local path = "/tmp/openuf_test_dump_under.log"
			os.remove(path)
			local pre = io.open(path, "w")
			pre:write("OLDMARKER\n")
			pre:close()
			inform.handle_response('{"_type":"noop"}', st,
				{ config = { debug_dump_file = path, debug_dump_max_bytes = 1024 } })
			local f = io.open(path, "r")
			local contents = f:read("*a")
			f:close()
			os.remove(path)
			assert_true(contents:find("OLDMARKER", 1, true) ~= nil,
				"history below the cap is preserved -- the cap is not an unconditional truncate")
			assert_true(contents:find('{"_type":"noop"}', 1, true) ~= nil,
				"the new response was appended after it")
		end
	},
	{
		name = "inform packet: debug_dump_max_bytes = 0 disables the cap",
		fn = function()
			local st = sample_state()
			local path = "/tmp/openuf_test_dump_nocap.log"
			os.remove(path)
			local pre = io.open(path, "w")
			pre:write(string.rep("x", 5000) .. "\nOLDMARKER\n")
			pre:close()
			inform.handle_response('{"_type":"noop"}', st,
				{ config = { debug_dump_file = path, debug_dump_max_bytes = 0 } })
			local f = io.open(path, "r")
			local contents = f:read("*a")
			f:close()
			os.remove(path)
			assert_true(contents:find("OLDMARKER", 1, true) ~= nil,
				"an explicit 0 keeps the unbounded behaviour")
		end
	},
	{
		name = "inform packet: parse_packet inflates a zlib-compressed response",
		fn = function()
			-- OpenWrt 25.12 has no Lua zlib binding, so this exercises the in-tree
			-- pure-Lua inflater on the parse path. The fixture is a real zlib stream
			-- (tests/fixtures/zlib_response.bin) whose plaintext is asserted below.
			-- The mgmt_cfg newlines are JSON-escaped (\n), so the decompressed bytes
			-- contain literal backslash-n, written here as \\n.
			local expected = '{"_type":"setparam","mgmt_cfg":"mgmt_url=http://unifi:8080/inform\\n'
				.. 'use_aes_gcm=false\\ncfgversion=7\\n","note":"padding to ensure zlib actually '
				.. 'shrinks this payload below its original size aaaaaaaaaaaaaaaaaaaa"}'
			local ff = io.open("tests/fixtures/zlib_response.bin", "rb")
			assert_not_nil(ff, "fixture present")
			local compressed = ff:read("*a"); ff:close()

			local st = sample_state()
			-- Encrypt the compressed bytes exactly as a controller would, then frame.
			local iv = FIXED_IV
			local ct = crypto.aes_cbc_encrypt(st.authkey, iv, compressed)
			local FLAG_ENCRYPTED, FLAG_COMPRESSED = 0x01, 0x02
			local flags = FLAG_ENCRYPTED + FLAG_COMPRESSED
			local function u32(n)
				return string.char(math.floor(n/16777216)%256, math.floor(n/65536)%256,
					math.floor(n/256)%256, n%256)
			end
			local pkt = MAGIC .. u32(1) .. "\170\187\204\221\238\255"
				.. string.char(math.floor(flags/256), flags%256)
				.. iv .. u32(1) .. u32(#ct) .. ct
			local recovered = inform.parse_packet(pkt, st)
			assert_eq(recovered, expected, "compressed response inflated to original JSON")
		end
	},
	{
		name = "inform packet: zlib is looked up and the inflater loaded once, not per packet",
		fn = function()
			-- A failed require is not remembered by Lua: asking for zlib per
			-- packet walked every package.path/cpath entry on every inform and
			-- notification, and the inflater was dofile'd per compressed reply.
			-- A fresh inform instance, so an earlier test's lookup doesn't count.
			local zlib_asks, inflate_loads = 0, 0
			local orig_require, orig_dofile = require, dofile
			require = function(name)
				if name == "zlib" then zlib_asks = zlib_asks + 1 end
				return orig_require(name)
			end
			dofile = function(path)
				if tostring(path):find("inflate", 1, true) then inflate_loads = inflate_loads + 1 end
				return orig_dofile(path)
			end
			local ok, err = pcall(function()
				local fresh = dofile("openuf/inform.lua")
				fresh._crypto = inform._crypto
				local st = sample_state()
				local ff = io.open("tests/fixtures/zlib_response.bin", "rb")
				local compressed = ff:read("*a"); ff:close()
				local ct = crypto.aes_cbc_encrypt(st.authkey, FIXED_IV, compressed)
				local function u32(n)
					return string.char(math.floor(n/16777216)%256, math.floor(n/65536)%256,
						math.floor(n/256)%256, n%256)
				end
				local pkt = MAGIC .. u32(1) .. "\170\187\204\221\238\255"
					.. string.char(0, 3) .. FIXED_IV .. u32(1) .. u32(#ct) .. ct
				for _ = 1, 3 do
					fresh.build_packet('{"x":1}', st)
					assert_true(fresh.parse_packet(pkt, st):find("setparam", 1, true) ~= nil,
						"the reply still inflates")
				end
			end)
			require, dofile = orig_require, orig_dofile
			if not ok then error(err, 0) end
			assert_true(zlib_asks <= 1, "zlib asked for at most once, got " .. zlib_asks)
			assert_true(inflate_loads <= 1, "inflater loaded at most once, got " .. inflate_loads)
		end
	},
	{
		name = "inform packet: parse_packet errors on snappy-compressed response",
		fn = function()
			-- Build a raw packet with FLAG_SNAPPY (0x04) set
			local FLAG_SNAPPY = 0x04
			local st = sample_state()
			local pkt = inform.build_packet('{"_type":"state"}', st)
			-- Patch byte 15-16 (flags, big-endian) to set FLAG_SNAPPY
			local flags_byte = string.byte(pkt, 15) * 256 + string.byte(pkt, 16)
			flags_byte = flags_byte + FLAG_SNAPPY
			local patched = pkt:sub(1, 14)
				.. string.char(math.floor(flags_byte / 256))
				.. string.char(flags_byte % 256)
				.. pkt:sub(17)
			assert_error(function()
				inform.parse_packet(patched, st)
			end, "snappy flag raises error")
		end
	},
	{
		name = "inform: _state_mtime forks nothing and returns nil for a missing file",
		fn = function()
			-- This runs on the first line of every heartbeat. It used to fork
			-- `stat -c %Y` and keep the file contents as a fallback; the fork
			-- bought strictly less than the fallback (mtime has one-second
			-- granularity) and on a board with no stat applet it could only
			-- ever fail. Nothing here may spawn a process.
			local orig, orig_read = inform._run_cmd, inform._read_file
			local forks = 0
			inform._run_cmd = function() forks = forks + 1; return "1700000000\n" end
			inform._read_file = function() return nil end
			local mtime = inform._state_mtime("/nonexistent")
			inform._run_cmd, inform._read_file = orig, orig_read
			assert_eq(forks, 0, "no process is spawned to poll the state file")
			assert_true(mtime == nil, "nil when the file cannot be read")
		end
	},
	{
		name = "inform: a changed identity MAC on an adopted device is reported loudly",
		fn = function()
			-- lan_cpueth's MAC is the device's identity. Moving it on an
			-- adopted device (a modelmap switch) makes the controller reject
			-- every inform with HTTP 400 while the old record goes Offline --
			-- with nothing on the device to explain it. Observed for real.
			local out = with_stderr(function()
				local warned = inform._warn_identity_change(
					"00:00:5e:00:53:1a",
					{adopted = true, mac = "00:00:5e:00:53:19"},
					{net = {lan_cpueth = "eth0"}})
				assert_true(warned, "warns")
			end)
			assert_contains(out, "IDENTITY MAC CHANGED", "names the problem")
			assert_contains(out, "00:00:5e:00:53:1a", "the MAC it was adopted as")
			assert_contains(out, "00:00:5e:00:53:19", "the MAC it now reports")
			assert_contains(out, "eth0", "and which setting decides it")
			assert_contains(out, "re-adopt", "says how to fix it")
		end
	},
	{
		name = "inform: no identity warning when unadopted, unchanged, or first run",
		fn = function()
			-- Not adopted yet: a MAC change is harmless, the controller has no
			-- record. Unchanged: nothing to say. First run: nothing persisted
			-- to compare against, which must not read as a change.
			local cfg = {net = {lan_cpueth = "eth0"}}
			local out = with_stderr(function()
				assert_false(inform._warn_identity_change("aa:bb:cc:dd:ee:01",
					{adopted = false, mac = "aa:bb:cc:dd:ee:02"}, cfg), "unadopted")
				assert_false(inform._warn_identity_change("aa:bb:cc:dd:ee:01",
					{adopted = true, mac = "aa:bb:cc:dd:ee:01"}, cfg), "unchanged")
				assert_false(inform._warn_identity_change(nil,
					{adopted = true, mac = "aa:bb:cc:dd:ee:01"}, cfg), "first run")
			end)
			assert_eq(out, "", "and stays silent in all three")
		end
	},
	{
		name = "inform: the state token tracks the file's contents",
		fn = function()
			-- Detecting an SSH set-adopt or a manual reset-inform hangs on
			-- this: a state file written since the last heartbeat must produce
			-- a different token. Contents, not mtime -- two writes inside one
			-- second are indistinguishable by mtime and not by this.
			local orig, orig_read = inform._run_cmd, inform._read_file
			inform._run_cmd = function() return "" end
			inform._read_file = function() return '{"adopted":false}' end
			local a = inform._state_mtime("/etc/openuf/state.json")
			inform._read_file = function() return '{"adopted":true}' end
			local b = inform._state_mtime("/etc/openuf/state.json")
			inform._run_cmd, inform._read_file = orig, orig_read
			assert_not_nil(a, "a token is produced")
			assert_true(a ~= b, "and it changes when the file changes")
		end
	},
	{
		name = "inform: _reload_if_changed reloads on a contents-only change",
		fn = function()
			-- The whole point of the fallback: with no stat, a changed file
			-- must still trigger the reload path.
			local orig, orig_read = inform._run_cmd, inform._read_file
			local orig_state = inform._state
			inform._run_cmd = function() return "" end
			inform._read_file = function() return '{"adopted":true}' end
			inform._state = {
				_state_file = "/etc/openuf/state.json",
				load = function() return {adopted = true, authkey = "new"} end,
			}
			local st = {adopted = false, authkey = "old"}
			local token = inform._reload_if_changed(st, nil, "an-older-token")
			inform._run_cmd, inform._read_file = orig, orig_read
			inform._state = orig_state
			assert_eq(st.adopted, true, "state reloaded from disk")
			assert_eq(st.authkey, "new", "including the rotated key")
			assert_eq(token, '{"adopted":true}', "token advanced to the new contents")
		end
	},
	{
		name = "inform: _sync_bootstrap_account is a no-op without a configured user",
		fn = function()
			local calls = {}
			local orig = inform._run_cmd
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._sync_bootstrap_account(true, nil)
			inform._run_cmd = orig
			assert_eq(#calls, 0, "no shell-out without a configured user")
		end
	},
	{
		name = "inform: _sync_bootstrap_account locks the account when adopted",
		fn = function()
			local calls = {}
			local orig = inform._run_cmd
			local orig_shadow = inform.SHADOW_FILE
			inform.SHADOW_FILE = "/nonexistent/openuf-test-shadow"
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._sync_bootstrap_account(true, "ubnt")
			inform._run_cmd = orig
			inform.SHADOW_FILE = orig_shadow
			assert_eq(#calls, 1, "one command issued when the shadow file cannot be read")
			assert_contains(calls[1], "passwd -l", "lock command issued")
			assert_contains(calls[1], "ubnt", "targets ubnt")
		end
	},
	{
		name = "inform: _sync_bootstrap_account unlocks the account when not adopted",
		fn = function()
			local calls = {}
			local orig = inform._run_cmd
			local orig_shadow = inform.SHADOW_FILE
			inform.SHADOW_FILE = "/nonexistent/openuf-test-shadow"
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._sync_bootstrap_account(false, "ubnt")
			inform._run_cmd = orig
			inform.SHADOW_FILE = orig_shadow
			assert_eq(#calls, 1, "one command issued")
			assert_contains(calls[1], "passwd -u", "unlock command issued")
		end
	},
	{
		name = "inform: _sync_bootstrap_account skips passwd when the account is already in the wanted state",
		fn = function()
			-- BusyBox passwd logs "already locked" to auth.err on a repeat
			-- lock, and this runs on every config push.
			local shadow = "root:$1$abc:19000:0:99999:7:::\n"
				.. "ubnt:!$1$xyz:19000:0:99999:7:::\n"
				.. "guest:$1$def:19000:0:99999:7:::\n"
			local calls = {}
			local orig_run, orig_read = inform._run_cmd, inform._read_file
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._read_file = function(path)
				if path == inform.SHADOW_FILE then return shadow end
				return orig_read(path)
			end
			inform._sync_bootstrap_account(true, "ubnt")    -- locked, wants locked
			local after_locked = #calls
			inform._sync_bootstrap_account(false, "guest")  -- unlocked, wants unlocked
			local after_unlocked = #calls
			inform._sync_bootstrap_account(false, "ubnt")   -- locked, wants unlocked
			inform._sync_bootstrap_account(true, "guest")   -- unlocked, wants locked
			inform._sync_bootstrap_account(true, "nobody")  -- not in the file: act anyway
			inform._run_cmd, inform._read_file = orig_run, orig_read
			assert_eq(after_locked, 0, "no passwd -l on an already-locked account")
			assert_eq(after_unlocked, 0, "no passwd -u on an already-unlocked account")
			assert_eq(#calls, 3, "the three real transitions still run")
			assert_contains(calls[1], "passwd -u 'ubnt'", "unlocks the locked account")
			assert_contains(calls[2], "passwd -l 'guest'", "locks the unlocked account")
			assert_contains(calls[3], "passwd -l 'nobody'", "an unknown user is acted on")
		end
	},
	{
		name = "inform: _reload_if_changed is a no-op when mtime is unchanged",
		fn = function()
			local orig_mtime = inform._state_mtime
			inform._state_mtime = function(path) return 42 end
			local st = sample_state({adopted = false})
			local last = inform._reload_if_changed(st, {config = {}}, 42)
			inform._state_mtime = orig_mtime
			assert_eq(last, 42, "mtime unchanged")
			assert_eq(st.mac, "aa:bb:cc:dd:ee:ff", "st left untouched")
		end
	},
	{
		name = "inform: _reload_if_changed ignores this process's own state.save, not an external write",
		fn = function()
			-- Real file, real token: the token is the file's contents.
			local path = inform._state._state_file
			inform._state.save(sample_state({adopted = true, cfgversion = "v1"}))
			local token = inform._state_mtime(path)
			local reconciles = 0
			local orig_fw = inform._firewall
			inform._firewall = {reconcile = function() reconciles = reconciles + 1 end,
				deauth = function() end, hostapd_sockets = function() return "" end, deny_sync = function() return false end}
			local ok, err = pcall(function()
				-- A save from inside the daemon (a setparam, a guest cmd ...).
				local st = sample_state({adopted = true, cfgversion = "v2"})
				inform._state.save(st)
				token = inform._reload_if_changed(st, {config = {}}, token)
				assert_eq(reconciles, 0, "own save is not reloaded")
				assert_eq(token, inform._state_mtime(path), "token follows the own write")
				assert_eq(st.mac, "aa:bb:cc:dd:ee:ff", "st untouched")
				-- syswrapper writing the file from another process.
				local f = assert(io.open(path, "w"))
				f:write('{"adopted":false,"cfgversion":"v3"}')
				f:close()
				inform._reload_if_changed(st, {config = {}}, token)
				assert_eq(reconciles, 1, "an external write still reloads")
				assert_eq(st.cfgversion, "v3", "external contents loaded")
			end)
			inform._firewall = orig_fw
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: _reload_if_changed reloads state and preserves mac/ip/hostname when mtime changes",
		fn = function()
			-- Write a real fixture to the redirected state file, distinct
			-- from sample_state()'s in-memory values, so a genuine
			-- state.load() picks it up -- exercises the real disk round-trip
			-- rather than mocking state.load itself. Must go through
			-- inform._state (not the test file's own `state` local) --
			-- dofile never caches, so those are separate module instances
			-- and only inform._state._state_file was redirected above.
			inform._state.save({
				authkey    = "11112222333344445555666677778888",
				adopted    = true,
				cfgversion = "abc123",
				inform_url = "http://controller/inform",
				use_gcm    = true,
				upgrade_requested_version = "",
				upgrade_requested_url     = "",
			})

			local orig_mtime = inform._state_mtime
			inform._state_mtime = function(path) return 100 end

			local calls = {}
			local orig_run = inform._run_cmd
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end

			local st = sample_state({adopted = false})
			local last = inform._reload_if_changed(
				st, {config = {bootstrap_adopt_user = "ubnt"}}, 1)

			inform._state_mtime = orig_mtime
			inform._run_cmd = orig_run

			assert_eq(last, 100, "returns new mtime")
			assert_true(st.adopted, "adopted reloaded from disk")
			assert_eq(st.authkey, "11112222333344445555666677778888",
				"authkey reloaded from disk")
			assert_eq(st.cfgversion, "abc123", "cfgversion reloaded from disk")
			assert_eq(st.mac,      "aa:bb:cc:dd:ee:ff", "mac preserved across reload")
			assert_eq(st.ip,       "192.168.1.100",     "ip preserved across reload")
			assert_eq(st.hostname, "testap",            "hostname preserved across reload")
			assert_eq(#calls, 1, "bootstrap account synced")
			assert_contains(calls[1], "passwd -l",
				"locked since reloaded state is adopted")
		end
	},
	{
		name = "inform: spectrum-scan reports scanning, sweeps after that inform, then informs again",
		fn = function()
			-- The inform that brings the cmd resets the controller's flag to
			-- false. Sweeping inside the handler never showed the scan as
			-- running; the real UCG now shows true for the sweep (11 s).
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response, scan = inform._run_spectrum_scan,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
			}
			local events = {}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function()
				events[#events + 1] = "inform scanning=" .. tostring(inform._spectrum_pending and true or false)
				return "{}"
			end
			inform.build_packet = function() return "pkt" end
			inform.http_post = function() return "body" end
			local responses = {
				'{"_type":"cmd","cmd":"spectrum-scan"}',
				'{"_type":"noop"}', '{"_type":"noop"}',
			}
			inform.parse_packet = function() return table.remove(responses, 1) end
			inform._run_spectrum_scan = function() events[#events + 1] = "sweep" end
			inform._spectrum_pending = false
			-- Startup leaves hostapd's deny lists to look at; the tick does it.
			local orig_fw = inform._firewall
			inform._firewall = {reconcile = function() end, deauth = function() end,
				hostapd_sockets = function() return "" end, deny_sync = function() events[#events + 1] = "deny"; return false end}
			inform._deny_pending = true

			local ctx = {interval = 10, backoff = 10}
			local st = {inform_url = "http://unifi:8080/inform"}
			local ok, err = pcall(function()
				assert_eq(inform._tick(st, nil, nil, ctx), 0, "the cmd gets its immediate follow-up")
				assert_eq(inform._tick(st, nil, nil, ctx), 0, "the sweep gets its immediate follow-up")
				assert_eq(inform._tick(st, nil, nil, ctx), 10, "then the normal cadence")
			end)
			inform.build_json, inform.build_packet, inform.http_post, inform.parse_packet,
				inform.handle_response, inform._run_spectrum_scan,
				inform._reload_if_changed, inform._rrm_tick =
				orig.build_json, orig.build_packet, orig.http_post, orig.parse_packet,
				orig.handle_response, orig.scan, orig.reload, orig.rrm
			inform._spectrum_pending = false
			inform._firewall = orig_fw
			if not ok then error(err, 0) end
			assert_eq(events[1], "deny", "the tick syncs hostapd's deny lists before informing")
			table.remove(events, 1)
			assert_eq(table.concat(events, ", "),
				"inform scanning=false, inform scanning=true, sweep, inform scanning=false",
				"true is reported before the sweep, false after it")
		end
	},
	{
		name = "inform: a tick's resyncs and payload share one netifd answer",
		fn = function()
			-- Once a minute the l2guard and usteer resyncs each asked netifd
			-- for the VAP list, and the payload asked again: three
			-- `ubus call network.wireless status` on the same tick.
			local u = dofile("openuf/ucihelper.lua")
			local orig = {
				ucihelper = inform._ucihelper,
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				l2guard = inform._l2guard, usteer = inform._usteer, popen = u._popen,
				l2_next = inform._l2guard_next, us_next = inform._usteer_filter_next,
				us_built = inform._usteer_filter_built,
			}
			local asks = 0
			u._popen = function(cmd)
				if cmd:find("network.wireless status", 1, true) then
					asks = asks + 1
					return '{"radio0":{"interfaces":[{"ifname":"phy0-ap0","config":{"ssid":"a"}}]}}'
				end
				return ""
			end
			inform._ucihelper = u
			local in_payload
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function()
				in_payload = u.get_ifname_for_radio("radio0")
				return "{}"
			end
			inform.build_packet = function() return "pkt" end
			inform.http_post = function() return "body" end
			inform.parse_packet = function() return '{"_type":"noop"}' end
			inform._l2guard = {reconcile = function() end}
			inform._usteer = {reconcile_filter = function() end, filter_wanted = function() return true end}
			local st = {inform_url = "http://unifi:8080/inform",
				l2guard = {bpdu = true, ifnames = {"phy0-ap0"}}}
			local ctx = {interval = 10, backoff = 10}
			local ok, err = pcall(function()
				inform._l2guard_next, inform._usteer_filter_next = 0, 0
				inform._usteer_filter_built = nil
				inform._tick(st, nil, nil, ctx)
				assert_eq(in_payload, "phy0-ap0", "the payload resolved its VAP")
				assert_eq(inform._usteer_filter_built, "phy0-ap0", "the usteer resync ran")
				assert_eq(asks, 1, "one ubus call for the resyncs and the payload")
				assert_false(u._ws_pass, "the pass ends with the payload")

				inform._tick(st, nil, nil, ctx)
				assert_eq(asks, 2, "the next tick asks again")

				-- A pass a throw left open holds the last cycle's answer.
				u.begin_pass()
				u.get_ifname_for_radio("radio0")
				asks = 0
				inform._tick(st, nil, nil, ctx)
				assert_eq(asks, 1, "a tick never joins a pass left open")
			end)
			inform.build_json, inform.build_packet, inform.http_post, inform.parse_packet =
				orig.build_json, orig.build_packet, orig.http_post, orig.parse_packet
			inform._reload_if_changed, inform._rrm_tick = orig.reload, orig.rrm
			inform._l2guard, inform._usteer, u._popen = orig.l2guard, orig.usteer, orig.popen
			inform._l2guard_next, inform._usteer_filter_next = orig.l2_next, orig.us_next
			inform._usteer_filter_built = orig.us_built
			inform._ucihelper = orig.ucihelper
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: a heartbeat that raises costs one cycle, not the daemon",
		fn = function()
			-- Regression test: the loop body called build_json, build_packet
			-- and handle_response unprotected. build_json shells out to a
			-- dozen tools and does arithmetic on their output -- one nil field
			-- once took the whole daemon down (`nil + noise`, from a radio
			-- with the minrssi flag set and no threshold) -- and procd turned
			-- that into a respawn every five seconds, reporting no statistics
			-- and logging nothing but a traceback.
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr,
			}
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_packet = function() return "pkt" end
			inform.http_post = function() return "body" end
			inform.parse_packet = function() return '{"_type":"noop"}' end
			inform.handle_response = function() return false end

			local ctx = {interval = 10, backoff = 10}
			local st = {inform_url = "http://unifi:8080/inform"}

			inform.build_json = function() error("boom: a nil crept into a stat") end
			local wait = inform._tick(st, nil, nil, ctx)
			assert_eq(wait, 10, "a failed build_json waits one interval and comes back")

			inform.build_json = function() return "{}" end
			inform.handle_response = function() error("boom in dispatch") end
			assert_eq(inform._tick(st, nil, nil, ctx), 10,
				"a failed handle_response is survivable too")

			io.stderr = orig.stderr
			inform.build_json, inform.build_packet, inform.http_post,
				inform.parse_packet, inform.handle_response,
				inform._reload_if_changed, inform._rrm_tick =
				orig.build_json, orig.build_packet, orig.http_post,
				orig.parse_packet, orig.handle_response, orig.reload, orig.rrm

			local out = table.concat(logged)
			assert_true(out:find("build_json failed", 1, true) ~= nil,
				"and the log names the stage that failed")
			assert_true(out:find("handle_response failed", 1, true) ~= nil,
				"for each stage")
		end
	},
	{
		name = "inform: each cycle collects the heartbeat's garbage before it waits",
		fn = function()
			local orig = {tick = inform._tick, idle = inform._idle, gc = inform._collectgarbage}
			local seq = {}
			local wait = 10
			inform._tick = function() seq[#seq + 1] = "tick"; return wait end
			inform._collectgarbage = function(opt) seq[#seq + 1] = "gc " .. tostring(opt) end
			inform._idle = function(_, w) seq[#seq + 1] = "idle " .. w end
			inform._cycle({}, nil, nil, {}, {})
			wait = 0
			inform._cycle({}, nil, nil, {}, {})
			inform._tick, inform._idle, inform._collectgarbage = orig.tick, orig.idle, orig.gc
			assert_eq(table.concat(seq, ", "),
				"tick, gc collect, idle 10, tick, gc collect",
				"a full collection after every tick, before the wait; none when there is no wait")
			assert_true(inform._collectgarbage == collectgarbage, "the real collector by default")
		end
	},
	{
		name = "inform: a POST failure backs off, and a config push re-informs at once",
		fn = function()
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr,
			}
			io.stderr = {write = function() end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() return "{}" end
			inform.build_packet = function() return "pkt" end
			inform.parse_packet = function() return '{"_type":"setparam"}' end

			local ctx = {interval = 10, backoff = 10}
			local st = {inform_url = "http://unifi:8080/inform"}

			inform.http_post = function() return nil, "connection refused" end
			assert_eq(inform._tick(st, nil, nil, ctx), 20, "backoff doubles")
			assert_eq(inform._tick(st, nil, nil, ctx), 40, "and doubles again")
			assert_eq(inform._tick(st, nil, nil, ctx), 60, "capped at 60s")
			assert_eq(inform._tick(st, nil, nil, ctx), 60, "and stays there")

			inform.http_post = function() return "body" end
			inform.handle_response = function() return false end
			assert_eq(inform._tick(st, nil, nil, ctx), 10, "a success resets the backoff")

			-- A real AP re-informs immediately after applying a config push,
			-- rather than sitting out the rest of the interval.
			inform.handle_response = function() return true end
			assert_eq(inform._tick(st, nil, nil, ctx), 0, "an applied config informs again at once")

			io.stderr = orig.stderr
			inform.build_json, inform.build_packet, inform.http_post,
				inform.parse_packet, inform.handle_response,
				inform._reload_if_changed, inform._rrm_tick =
				orig.build_json, orig.build_packet, orig.http_post,
				orig.parse_packet, orig.handle_response, orig.reload, orig.rrm
		end
	},
	{
		name = "inform: _sane_interval clamps the controller's interval",
		fn = function()
			assert_eq(inform._sane_interval(10), 10, "a normal value passes through")
			assert_eq(inform._sane_interval("30"), 30, "a numeric string is accepted")
			assert_eq(inform._sane_interval(12.7), 12, "fractions are floored")
			assert_eq(inform._sane_interval(0), inform.INTERVAL_MIN, "too fast is clamped up")
			assert_eq(inform._sane_interval(-4), inform.INTERVAL_MIN, "negative too")
			assert_eq(inform._sane_interval(86400), inform.INTERVAL_MAX, "too slow is clamped down")
			assert_eq(inform._sane_interval(math.huge), inform.INTERVAL_MAX, "infinity too")
			assert_eq(inform._sane_interval(nil), nil, "absent means default")
			assert_eq(inform._sane_interval("soon"), nil, "garbage means default")
			assert_eq(inform._sane_interval(0/0), nil, "NaN means default")
		end
	},
	{
		name = "inform: handle_response records a noop's interval, and a noop without one resets it",
		fn = function()
			inform._controller_interval = nil
			inform.handle_response('{"_type":"noop","interval":30}', sample_state(), {config = {}})
			assert_eq(inform._controller_interval, 30, "interval adopted")
			inform.handle_response('{"_type":"noop","interval":1}', sample_state(), {config = {}})
			assert_eq(inform._controller_interval, inform.INTERVAL_MIN, "and clamped")
			inform.handle_response('{"_type":"noop"}', sample_state(), {config = {}})
			assert_eq(inform._controller_interval, nil, "a noop without one goes back to the default")
		end
	},
	{
		name = "inform: _tick waits the controller's interval, and backoff never polls faster",
		fn = function()
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr,
			}
			io.stderr = {write = function() end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() return "{}" end
			inform.build_packet = function() return "pkt" end
			inform.parse_packet = function() return '{"_type":"noop"}' end
			inform.http_post = function() return "body" end

			local ctx = {interval = 10, backoff = 10}
			local st = {inform_url = "http://unifi:8080/inform"}

			inform.handle_response = function() inform._controller_interval = 90; return false end
			local wait_slow = inform._tick(st, nil, nil, ctx)

			inform.http_post = function() return nil, "connection refused" end
			local fail1 = inform._tick(st, nil, nil, ctx)
			local fail2 = inform._tick(st, nil, nil, ctx)

			inform.http_post = function() return "body" end
			inform.handle_response = function() inform._controller_interval = nil; return false end
			local wait_default = inform._tick(st, nil, nil, ctx)

			inform.http_post = function() return nil, "connection refused" end
			local fail3 = inform._tick(st, nil, nil, ctx)

			io.stderr = orig.stderr
			inform._controller_interval = nil
			inform.build_json, inform.build_packet, inform.http_post,
				inform.parse_packet, inform.handle_response,
				inform._reload_if_changed, inform._rrm_tick =
				orig.build_json, orig.build_packet, orig.http_post,
				orig.parse_packet, orig.handle_response, orig.reload, orig.rrm

			assert_eq(wait_slow, 90, "the controller's interval is what the loop waits")
			assert_eq(fail1, 90, "a failure at a 90 s cadence is capped at 90, not 60")
			assert_eq(fail2, 90, "and stays there")
			assert_eq(wait_default, 10, "a noop without an interval goes back to the device's own")
			assert_eq(fail3, 20, "and backoff doubles from that again")
		end
	},
	{
		name = "inform: an 11k-scan request scans every radio once, a stale or absent one does nothing",
		fn = function()
			local FILE = "/tmp/openuf_test_scan_request"
			local orig = {file = inform.SCAN_REQUEST_FILE, uci = inform._ucihelper,
				time = inform._time, stderr = io.stderr}
			io.stderr = {write = function() end}
			local popens = {}
			inform._ucihelper = {
				get_radio_table = function() return {{name = "radio0"}, {name = "radio1"}} end,
				get_ifname_for_radio = function(r) return (r == "radio0") and "phy0-ap0" or "phy1-ap0" end,
				_popen = function(cmd)
					popens[#popens + 1] = cmd
					return cmd:find("phy0", 1, true) and "scan-ok\n" or ""
				end,
			}
			inform.SCAN_REQUEST_FILE = FILE
			inform._time = function() return 1000000 end
			local function request(at)
				local f = io.open(FILE, "w"); f:write(tostring(at), "\n"); f:close()
			end

			os.remove(FILE)
			local none = inform._maybe_service_scan_request({})
			request(1000000 - 30)
			local fresh = inform._maybe_service_scan_request({})
			local file_gone = io.open(FILE, "r") == nil
			local again = inform._maybe_service_scan_request({})
			local before = #popens
			local scanned_n = inform._scan_all_radios({})
			for _ = before + 1, #popens do table.remove(popens) end
			request(1000000 - 3600)
			local stale = inform._maybe_service_scan_request({})
			local stale_gone = io.open(FILE, "r") == nil

			os.remove(FILE)
			inform.SCAN_REQUEST_FILE, inform._ucihelper, inform._time, io.stderr =
				orig.file, orig.uci, orig.time, orig.stderr

			assert_false(none, "no request, no scan")
			assert_true(fresh, "a fresh request scans")
			assert_eq(#popens, 2, "one scan per radio")
			assert_contains(popens[1], "iw dev phy0-ap0 scan ap-force",
				"on the live netdev, forced")
			assert_contains(popens[2], "iw dev phy1-ap0 scan ap-force", "of each radio")
			assert_eq(scanned_n, 1, "only the scan iw accepted is counted")
			assert_true(file_gone, "the request is consumed")
			assert_false(again, "and served only once")
			assert_false(stale, "an hour-old request is ignored")
			assert_true(stale_gone, "but still removed")
		end
	},
	{
		name = "inform: an 11k-scan request with two due times fires each once when it falls due",
		fn = function()
			local FILE = "/tmp/openuf_test_scan_request2"
			local orig = {file = inform.SCAN_REQUEST_FILE, time = inform._time,
				scan = inform._scan_all_radios, stderr = io.stderr}
			io.stderr = {write = function() end}
			local scans = 0
			inform._scan_all_radios = function() scans = scans + 1; return 2 end
			inform.SCAN_REQUEST_FILE = FILE
			local now = 1000000
			inform._time = function() return now end
			local function request(...)
				local f = io.open(FILE, "w"); f:write(table.concat({...}, "\n"), "\n"); f:close()
			end
			local function left()
				local f = io.open(FILE, "r")
				if not f then return nil end
				local b = f:read("*a"); f:close(); return b
			end

			-- Due at +100 s and +2000 s.
			os.remove(FILE)
			request(now + 100, now + 2000)
			local early = inform._maybe_service_scan_request({})
			local early_left = left()
			now = now + 100
			local first = inform._maybe_service_scan_request({})
			local first_left = left()
			now = now + 10
			local between = inform._maybe_service_scan_request({})
			now = now + 1890 + 5
			local second = inform._maybe_service_scan_request({})
			local second_gone = left() == nil
			local scans_two = scans

			-- Both overdue on one heartbeat (a long blocking cycle): one scan.
			scans = 0
			request(now - 30, now - 5)
			local both = inform._maybe_service_scan_request({})
			local both_gone = left() == nil
			local scans_both = scans

			-- One stale, one pending: the stale one is dropped, the other kept.
			scans = 0
			request(now - 3600, now + 50)
			local mixed = inform._maybe_service_scan_request({})
			local mixed_left = left()

			-- Beyond the window (clock stepped back): dropped, not kept for hours.
			request(now + 7200)
			local ahead = inform._maybe_service_scan_request({})
			local ahead_gone = left() == nil

			os.remove(FILE)
			inform.SCAN_REQUEST_FILE, inform._time, inform._scan_all_radios, io.stderr =
				orig.file, orig.time, orig.scan, orig.stderr

			assert_false(early, "nothing before the first due time")
			assert_eq(early_left, (1000000 + 100) .. "\n" .. (1000000 + 2000) .. "\n",
				"and the file is left untouched")
			assert_true(first, "the first due time scans")
			assert_eq(first_left, (1000000 + 2000) .. "\n", "and only the second is kept")
			assert_false(between, "nothing between the two")
			assert_true(second, "the second due time scans")
			assert_true(second_gone, "then the request is gone")
			assert_eq(scans_two, 2, "two scans in all")
			assert_true(both, "two overdue times scan")
			assert_eq(scans_both, 1, "once")
			assert_true(both_gone, "and both are consumed")
			assert_false(mixed, "a stale time does not scan")
			assert_eq(mixed_left, tostring(now + 50) .. "\n", "the pending one survives")
			assert_false(ahead, "a time beyond the window does not scan")
			assert_true(ahead_gone, "and is dropped")
		end
	},
	{
		name = "inform: a setparam's timezone/NTP/cron blocks reach sysconf, and are not reported as dropped",
		fn = function()
			local orig = {sysconf = inform._sysconf, dbg = inform._debug_dropped_keys,
				stderr = io.stderr, l2 = inform._l2guard}
			inform._l2guard = nil   -- no real nft from a unit test
			local parsed_from, applied
			inform._sysconf = {
				parse = function(raw) parsed_from = raw; return {timezone = "CET-1CEST,M3.5.0,M10.5.0/3"} end,
				apply = function(sc) applied = sc; return {} end,
			}
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			-- The dropped-key report is gated on debug_dump_file, which
			-- handle_response reads off cfg on every call.
			local DUMP = "/tmp/openuf_test_sysconf_dump.txt"
			local sys_raw = "system.timezone=CET-1CEST,M3.5.0,M10.5.0/3\n"
				.. "locale.timezone=CET-1CEST,M3.5.0,M10.5.0/3\n"
				.. "ntpclient.status=enabled\nntpclient.1.server=0.ubnt.pool.ntp.org\n"
				.. "cron.status=enabled\ncron.1.status=enabled\ncron.1.user=pusheduser\n"
				.. "cron.1.job.1.schedule=0 4 * * *\ncron.1.job.1.cmd=syswrapper.sh 11k-scan\n"
				.. "ebtables.status=enabled\n"
				.. "ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP\n"
			local ok, err = pcall(inform.handle_response,
				require("cjson").encode({_type = "setparam", system_cfg = sys_raw}),
				sample_state({adopted = true}), {config = {debug_dump_file = DUMP}})
			os.remove(DUMP)
			inform._sysconf, inform._debug_dropped_keys, io.stderr, inform._l2guard =
				orig.sysconf, orig.dbg, orig.stderr, orig.l2
			assert_true(ok, "handle_response survives: " .. tostring(err))
			assert_eq(parsed_from, sys_raw, "sysconf parses the whole system_cfg")
			assert_eq(applied and applied.timezone, "CET-1CEST,M3.5.0,M10.5.0/3", "and applies what it parsed")
			local out = table.concat(logged)
			assert_true(out:find("cron.<n>.user", 1, true) ~= nil,
				"the ignored cron user is still reported as dropped")
			for _, k in ipairs({"system.timezone", "locale.timezone", "ntpclient.", "cron.status",
					"cron.<n>.job", "ebtables.status", "ebtables.<n>.cmd"}) do
				assert_true(out:find(k, 1, true) == nil, k .. " is recognized, not dropped")
			end
		end
	},
	{
		name = "inform: an ebtables push builds l2guard on the live VAPs and records it; a push without the block changes nothing",
		fn = function()
			local orig = {l2 = inform._l2guard, uci = inform._ucihelper, stderr = io.stderr}
			io.stderr = {write = function() end}
			local reconciled = {}
			inform._l2guard = setmetatable({
				reconcile = function(spec, names) reconciled[#reconciled + 1] = {spec = spec, names = names}; return 3 end,
			}, {__index = dofile("openuf/l2guard.lua")})
			local live = {"phy0-ap0", "phy1-ap0"}
			inform._ucihelper = {ap_ifnames = function() return live end}
			local sys_raw = "ebtables.status=enabled\n"
				.. "ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP\n"
				.. "ebtables.2.cmd=-t broute -A BROUTING --vlan-id 10 -p 802_1Q -j DROP\n"
			local st = {}
			local applied = inform._l2guard_apply_push(sys_raw, st)
			-- wireless not answering: the recorded names are used
			live = {}
			inform._l2guard_apply_push(sys_raw, st)
			local partial = inform._l2guard_apply_push("radio.1.channel=6\n", st)
			inform._l2guard, inform._ucihelper, io.stderr = orig.l2, orig.uci, orig.stderr

			assert_true(applied, "applied")
			assert_true(st.l2guard.bpdu and st.l2guard.tagdrop, "both ideas recorded")
			assert_eq(table.concat(st.l2guard.ifnames, ","), "phy0-ap0,phy1-ap0", "live names recorded")
			assert_eq(table.concat(reconciled[1].names, ","), "phy0-ap0,phy1-ap0", "and enforced")
			assert_eq(table.concat(reconciled[2].names, ","), "phy0-ap0,phy1-ap0",
				"an unanswering wireless falls back to the recorded names")
			assert_false(partial, "a push without the block is a no-op")
			assert_eq(#reconciled, 2, "and does not touch the table")
		end
	},
	{
		name = "inform: _l2guard_resync rebuilds once a minute when the VAP list changed, never on an empty answer",
		fn = function()
			local orig = {l2 = inform._l2guard, uci = inform._ucihelper, time = inform._time,
				save = inform._state.save, stderr = io.stderr}
			io.stderr = {write = function() end}
			local rebuilt, saves = {}, 0
			inform._l2guard = {reconcile = function(_, names) rebuilt[#rebuilt + 1] = table.concat(names, ",") end}
			inform._state.save = function() saves = saves + 1 end
			local live = {"phy0-ap0"}
			inform._ucihelper = {ap_ifnames = function() return live end}
			local now = 5000
			inform._time = function() return now end
			inform._l2guard_next = 0
			local st = {l2guard = {bpdu = true, tagdrop = true, ifnames = {"phy0-ap0"}}}

			local same = inform._l2guard_resync(st)
			live = {"phy0-ap0", "phy0-ap1"}
			now = now + 10
			local too_soon = inform._l2guard_resync(st)
			now = now + 60
			local changed = inform._l2guard_resync(st)
			live = {}
			now = now + 60
			local empty = inform._l2guard_resync(st)
			local off = inform._l2guard_resync({l2guard = {bpdu = false, tagdrop = false, ifnames = {}}})

			inform._l2guard, inform._ucihelper, inform._time, inform._state.save, io.stderr =
				orig.l2, orig.uci, orig.time, orig.save, orig.stderr
			inform._l2guard_next = 0

			assert_false(same, "unchanged list: nothing")
			assert_false(too_soon, "rate-limited")
			assert_true(changed, "a new VAP rebuilds")
			assert_eq(rebuilt[1], "phy0-ap0,phy0-ap1", "on the new list")
			assert_eq(table.concat(st.l2guard.ifnames, ","), "phy0-ap0,phy0-ap1", "which is recorded")
			assert_eq(saves, 1, "and saved")
			assert_false(empty, "an empty answer is 'not up', not 'no VAPs'")
			assert_eq(#rebuilt, 1, "so the table is left alone")
			assert_false(off, "nothing enforced, nothing to resync")
		end
	},
	{
		name = "inform: _hairpin_resync checks once a minute, whether or not the ebtables block was pushed",
		fn = function()
			local orig = {l2 = inform._l2guard, time = inform._time}
			local calls = 0
			inform._l2guard = {reconcile_hairpin = function() calls = calls + 1; return 1 end}
			local now = 5000
			inform._time = function() return now end
			inform._hairpin_next = 0
			local first = inform._hairpin_resync()
			now = now + 10
			local too_soon = inform._hairpin_resync()
			now = now + 60
			inform._hairpin_resync()
			inform._l2guard = {}
			now = now + 60
			local absent = inform._hairpin_resync()
			inform._l2guard, inform._time = orig.l2, orig.time
			inform._hairpin_next = 0
			assert_eq(first, 1, "first tick checks")
			assert_eq(too_soon, 0, "rate-limited")
			assert_eq(calls, 2, "checked again after a minute")
			assert_eq(absent, 0, "a module without it is tolerated")
		end
	},
	{
		name = "inform: _usteer_filter_resync rebuilds once a minute only when wanted-ness or the VAPs change",
		fn = function()
			local orig = {u = inform._usteer, time = inform._time, live = inform._l2guard_live_ifnames}
			local builds, wanted, live = {}, true, {"phy0-ap0"}
			inform._usteer = {
				filter_wanted = function() return wanted end,
				reconcile_filter = function(names) builds[#builds + 1] = table.concat(names, " ") end,
			}
			inform._l2guard_live_ifnames = function() return live end
			local now = 9000
			inform._time = function() return now end
			inform._usteer_filter_next, inform._usteer_filter_built = 0, nil
			local r = {}
			local function step(dt) now = now + dt; r[#r + 1] = inform._usteer_filter_resync() end
			step(0)                        -- 1 builds
			step(10)                       -- 2 rate-limited
			step(60)                       -- 3 unchanged: no rebuild
			live = {"phy0-ap0", "phy1-ap0"}
			step(60)                       -- 4 VAP added: rebuild
			live = {}
			step(60)                       -- 5 wireless not answering: leave it
			live = {"phy0-ap0", "phy1-ap0"}
			wanted = false
			step(60)                       -- 6 usteer stopped: remove
			step(60)                       -- 7 still stopped: nothing
			inform._usteer, inform._time, inform._l2guard_live_ifnames = orig.u, orig.time, orig.live
			inform._usteer_filter_next, inform._usteer_filter_built = 0, nil
			assert_eq(table.concat(builds, "|"), "phy0-ap0|phy0-ap0 phy1-ap0|", "built, extended, removed")
			assert_true(r[1] and not r[2] and not r[3] and r[4] and not r[5] and r[6] and not r[7],
				"returns whether it rebuilt")
		end
	},
	{
		name = "inform: a factory reset, from the controller or reset-inform, forgets the controller's leftovers",
		fn = function()
			local orig = {l2 = inform._l2guard, fw = inform._firewall, sc = inform._sysconf,
				mtime = inform._state_mtime, load = inform._state.load, stderr = io.stderr}
			io.stderr = {write = function() end}
			local l2calls, crons = {}, {}
			inform._l2guard = {reconcile = function(spec, names) l2calls[#l2calls + 1] = {spec = spec, n = #names} end}
			inform._firewall = {reconcile = function() end}
			inform._sysconf = {apply_cron = function(c) crons[#crons + 1] = c end}

			-- 1. The controller's setdefault.
			inform._controller_interval = 300
			inform._deny_pending = false
			local ok, err = pcall(inform.handle_response, '{"_type":"setdefault"}',
				sample_state({adopted = true, l2guard = {bpdu = true, tagdrop = true, ifnames = {"x"}}}),
				{config = {}})
			local interval_after_setdefault = inform._controller_interval
			local deny_after_setdefault = inform._deny_pending
			inform._deny_pending = false

			-- 2. An out-of-process reset-inform, seen through the state-file reload.
			inform._controller_interval = 300
			inform._state_mtime = function() return "reset" end
			inform._state.load = function() return {adopted = false} end
			local st = sample_state({adopted = true, l2guard = {bpdu = true, tagdrop = true, ifnames = {"x"}}})
			inform._reload_if_changed(st, {config = {}}, "before")
			local interval_after_reset = inform._controller_interval
			local deny_after_reset = inform._deny_pending
			inform._deny_pending = false
			-- 3. A reload that stays adopted forgets nothing.
			inform._controller_interval = 300
			inform._state.load = function() return {adopted = true} end
			inform._reload_if_changed(sample_state({adopted = true}), {config = {}}, "before")
			local interval_kept = inform._controller_interval

			inform._l2guard, inform._firewall, inform._sysconf, inform._state_mtime,
				inform._state.load, io.stderr =
				orig.l2, orig.fw, orig.sc, orig.mtime, orig.load, orig.stderr
			inform._controller_interval = nil

			assert_true(ok, tostring(err))
			assert_eq(#l2calls, 2, "the l2guard table is torn down on both paths, and only those")
			assert_nil(l2calls[1].spec, "with nothing to enforce, which only deletes the table")
			assert_nil(l2calls[2].spec, "on the reset-inform path too")
			assert_eq(#crons, 2, "the controller's cron block is removed on both paths")
			assert_false(crons[1].enabled, "by applying an empty, disabled cron block")
			assert_nil(interval_after_setdefault, "the controller's interval is forgotten")
			assert_nil(interval_after_reset, "on both paths")
			assert_eq(interval_kept, 300, "a reload that stays adopted keeps it")
			assert_true(deny_after_setdefault, "the block ledger is gone: hostapd's deny lists get cleaned")
			assert_true(deny_after_reset, "on both paths")
		end
	},
	{
		name = "inform: Forget puts UCI back the way it was before the controller's push",
		fn = function()
			-- UniFi firmware answers setdefault with a factory reset (no SSID,
			-- no VLAN); openUF undoes its own writes instead of rebooting.
			local ucihelper, db = new_apply_env()
			local c = ucihelper._uci.cursor()
			c:set("wireless", "radio0", "channel", "6")
			-- The user's own SSID, which use_only_unifi_wlan switches off.
			c:set("wireless", "default_radio0", "wifi-iface")
			c:set("wireless", "default_radio0", "device", "radio0")
			c:set("wireless", "default_radio0", "ssid", "Mine")
			-- A hand-tuned rate on a radio openUF never rate-managed.
			c:set("wireless", "radio1", "basic_rate", {"6000"})
			c:set("network", "lan", "interface")
			c:set("network", "lan", "device", "br-lan")
			local function dump(t)
				local out = {}
				for cfgname, secs in pairs(t) do
					for name, sec in pairs(secs) do
						for k, v in pairs(sec) do
							if type(v) == "table" then v = table.concat(v, ",") end
							out[#out + 1] = cfgname .. "." .. name .. "." .. k .. "=" .. tostring(v)
						end
					end
				end
				table.sort(out)
				return table.concat(out, "\n")
			end
			local before = dump(db)

			local cmds = {}
			ucihelper._run_cmd = function(cmd) cmds[#cmds + 1] = cmd; return true end
			local rt, vt = inform._parse_wifi_system_cfg(
				"radio.1.phyname=radio0\nradio.1.channel=6\n"
				.. "stamgr.1.status=true\nstamgr.1.radio=ng\n"
				.. "stamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=15\n"
				.. "stamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=3\n"
				.. "aaa.1.ssid=IoT\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "aaa.1.br.devname=br0.20\n"
				.. "wireless.1.ssid=IoT\nwireless.1.parent=radio0\n"
				.. "wireless.1.minrate_data=12000\nwireless.1.minrate_cck_rates.status=false\n")
			ucihelper.apply_config({radio_table = rt, vap_table = vt},
				{net = {lan_cpueth = "eth0"}, config = {use_only_unifi_wlan = true}})
			assert_eq(db.wireless.default_radio0.disabled, "1", "push: the user's SSID is off")
			assert_eq(db.wireless.radio0.openuf_rates, "1", "push: rates managed")
			assert_eq(db.wireless.radio0.loadbalance_maxsta, "3", "push: load balance cap")
			assert_not_nil(db.network.openuf_vlan20, "push: the VLAN 20 network")

			cmds = {}
			ucihelper.forget()
			-- set_wlan_exclusive leaves its stamp at "0", which is how it
			-- marks a section it switched back on.
			assert_eq(db.wireless.default_radio0.disabled, "0", "the user's SSID is back on")
			db.wireless.default_radio0.disabled = nil
			db.wireless.default_radio0.openuf_autodisabled = nil
			assert_eq(dump(db), before, "every other write is undone, hand-made options kept")
			assert_eq(table.concat(cmds, "|"),
				"/etc/init.d/network reload 2>/dev/null|wifi reload", "network, then wireless")
		end
	},
	{
		name = "inform: Forget tears down per-port VLANs, steering and the LED from the pre-reset state",
		fn = function()
			local orig = {sv = inform._switchvlan, us = inform._usteer, uh = inform._ucihelper,
				led = inform._led, fw = inform._firewall, mtime = inform._state_mtime,
				load = inform._state.load, stderr = io.stderr}
			io.stderr = {write = function() end}
			local restored, steer, forgot, leds = {}, {}, 0, {}
			inform._switchvlan = {restore = function(st) restored[#restored + 1] = st.dsa_brlan_ports end}
			inform._usteer = {set_enabled = function(on, _, ra) steer[#steer + 1] = tostring(on) .. tostring(ra) end}
			inform._ucihelper = {forget = function() forgot = forgot + 1 end}
			inform._led = {set_enabled = function(_, on) leds[#leds + 1] = on end}
			inform._firewall = {reconcile = function() end}
			local ledger = {lan = "lan1 lan2"}
			local ok, err = pcall(inform.handle_response, '{"_type":"setdefault"}',
				sample_state({adopted = true, dsa_brlan_ports = ledger, led_enabled = false}),
				{config = {}})
			inform._state_mtime = function() return "reset" end
			inform._state.load = function() return {adopted = false} end
			local ok2, err2 = pcall(inform._reload_if_changed,
				sample_state({adopted = true, dsa_brlan_ports = ledger, led_enabled = true}),
				{config = {}}, "before")
			inform._switchvlan, inform._usteer, inform._ucihelper, inform._led, inform._firewall,
				inform._state_mtime, inform._state.load, io.stderr =
				orig.sv, orig.us, orig.uh, orig.led, orig.fw, orig.mtime, orig.load, orig.stderr
			inform._controller_interval = nil
			assert_true(ok, tostring(err))
			assert_true(ok2, tostring(err2))
			assert_eq(#restored, 2, "per-port VLAN restored on both paths")
			assert_eq(restored[1], ledger, "from the ledger the reset cleared (setdefault)")
			assert_eq(restored[2], ledger, "and on reset-inform")
			assert_eq(table.concat(steer, ","), "falsefalse,falsefalse", "band steering and roaming assistant off")
			assert_eq(forgot, 2, "the WLANs are torn down on both paths")
			assert_eq(#leds, 1, "only the LED the controller switched off comes back on")
			assert_true(leds[1], "on")
		end
	},
	{
		name = "inform: a missing UCI binding is announced, not silently survived",
		fn = function()
			-- libuci-lua is what require("uci") comes from; `lua` does not
			-- pull it in and install.sh did not list it. Every ucihelper call
			-- is pcall-wrapped (correctly), so without it the device adopts,
			-- reports ports and statistics and looks healthy while
			-- radio_table goes out EMPTY and no pushed WLAN is ever created.
			local orig_loaded, orig_require, orig_stderr =
				package.loaded["uci"], require, io.stderr
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}

			package.loaded["uci"] = nil
			require = function(name)
				if name == "uci" then error("module 'uci' not found") end
				return orig_require(name)
			end
			local warned = inform._warn_missing_uci()
			assert_true(warned, "an unresolvable uci binding warns")
			local out = table.concat(logged)
			assert_true(out:find("libuci%-lua") ~= nil, "and names the package to install")
			assert_true(out:find("ZERO") ~= nil, "and says what actually breaks")

			-- Present: silent, whichever way it is present.
			logged = {}
			package.loaded["uci"] = {}
			assert_false(inform._warn_missing_uci(), "an already-loaded binding is fine")
			assert_eq(table.concat(logged), "", "and says nothing")

			require = orig_require
			package.loaded["uci"] = orig_loaded
			io.stderr = orig_stderr
		end
	},
	{
		name = "inform packet: a malformed IP Settings push is refused before it is recorded",
		fn = function()
			-- The order matters as much as the check. With the state record
			-- written first, a refused apply still left ip_mode=static and a
			-- bogus static_ip behind -- which the DHCP-revert logic then acts
			-- on, flushing the interface on the next "still DHCP" push.
			local st = sample_state()
			local cmds = {}
			local orig_exec, orig_stderr = inform._netconfig._exec, io.stderr
			inform._netconfig._exec = function(cmd) cmds[#cmds + 1] = cmd; return true end
			io.stderr = {write = function() end}
			local resp = '{"_type":"setparam","system_cfg":"netconf.1.ip=172.19.0.50; reboot\\n'
				.. 'netconf.1.netmask=255.255.255.0\\nroute.1.gateway=172.19.0.1\\n"}'
			inform.handle_response(resp, st, {net = {lan_cpueth = "eth0"}})
			inform._netconfig._exec, io.stderr = orig_exec, orig_stderr

			assert_eq(#cmds, 0, "nothing is run")
			assert_nil(st.ip_mode, "and nothing is recorded either")
			assert_nil(st.static_ip, "no static address is left behind")
		end
	},
	{
		name = "inform packet: malformed MACs are dropped from the ACL and blocker lists",
		fn = function()
			-- Both lists end up inside a command line or a hostapd-parsed UCI
			-- list. The controller's UI cannot produce a malformed entry, but
			-- before adoption the inform channel is plain HTTP under the
			-- well-known key, so the parser is the boundary that has to hold.
			local orig_stderr = io.stderr
			io.stderr = {write = function() end}
			local _, vap_table = inform._parse_wifi_system_cfg(table.concat({
				"aaa.1.ssid=corp", "aaa.1.wpa=2",
				"wireless.1.ssid=corp", "wireless.1.parent=radio0",
				"wireless.1.devname=ath0",
				"wireless.1.bcfilt.status=enabled",
				"wireless.1.bcfilt.1.mac=02:11:22:33:44:55",
				"wireless.1.bcfilt.1.status=enabled",
				"wireless.1.bcfilt.2.mac=02:11:22:33:44:66 }; touch /tmp/pwned; echo '{ 1",
				"wireless.1.bcfilt.2.status=enabled",
				"macacl.status=enabled",
				"macacl.1.devname=ath0", "macacl.1.status=enabled",
				"macacl.1.acl.status=enabled", "macacl.1.acl.policy=allow",
				"macacl.1.acl.1.mac=02:11:22:33:44:55", "macacl.1.acl.1.status=enabled",
				"macacl.1.acl.2.mac=not-a-mac", "macacl.1.acl.2.status=enabled",
			}, "\n") .. "\n")
			io.stderr = orig_stderr

			local vap = vap_table[1]
			assert_eq(#vap.bcfilt_macs, 1, "only the well-formed blocker MAC survives")
			assert_eq(vap.bcfilt_macs[1], "02:11:22:33:44:55", "and it is the right one")
			assert_eq(vap.mac_filter_policy, "allow", "the ACL is still parsed")
			assert_eq(#vap.mac_filter_list, 1, "with only the well-formed entry")
			assert_eq(vap.mac_filter_list[1], "02:11:22:33:44:55", "and it is the right one")
		end
	},
	{
		-- A3: turning rrm_enrichment off returns before collector_ensure AND
		-- before harvest, so a collector started while it was on kept
		-- appending to /tmp/openuf-rrm.jsonl with nothing left to drain it.
		-- The child is detached and reparented to init, so nothing else was
		-- going to clean it up either.
		name = "inform: _rrm_tick stops an orphaned collector once enrichment is switched off",
		fn = function()
			local orig_rrm, orig_time = inform._rrmscan, inform._time
			local stopped, ensured = 0, 0
			inform._rrmscan = {
				collector_running = function() return true end,
				collector_stop    = function() stopped = stopped + 1 end,
				collector_ensure  = function() ensured = ensured + 1 end,
				harvest           = function() return {}, {} end,
				hostapd_objects   = function() return {} end,
			}
			local clock = 1000
			inform._time = function() return clock end
			inform._rrm_collector_next = 0

			local cfg = {config = {rrm_enrichment = false}}
			assert_false(inform._rrm_tick(cfg), "still reports disabled")
			assert_eq(stopped, 1, "the stale collector is killed")
			assert_eq(ensured, 0, "and nothing is started in its place")

			-- Rate-limited on the collector's own liveness clock: this is a
			-- pgrep, and there is nothing to catch between checks.
			inform._rrm_tick(cfg)
			inform._rrm_tick(cfg)
			assert_eq(stopped, 1, "not re-run on every tick")
			clock = clock + inform.RRM_COLLECTOR_CHECK_INTERVAL
			inform._rrm_tick(cfg)
			assert_eq(stopped, 2, "checked again once the interval has passed")

			-- Nothing running is the steady state once it has been cleaned up,
			-- and must not turn into a pkill every interval forever.
			inform._rrmscan.collector_running = function() return false end
			clock = clock + inform.RRM_COLLECTOR_CHECK_INTERVAL
			inform._rrm_tick(cfg)
			assert_eq(stopped, 2, "no kill when there is no collector to kill")

			inform._rrmscan, inform._time = orig_rrm, orig_time
			inform._rrm_collector_next = 0
		end
	},
	{
		name = "inform: a 2.4 GHz-only station is asked for its own operating class",
		fn = function()
			-- Every station used to be asked for class 115 (5 GHz U-NII-1).
			-- Dual-band clients ignore the band restriction and answer for
			-- 2.4 GHz too, but a 2.4 GHz-only station answers a 5 GHz class
			-- with report mode 0x02, "incapable", and an all-zero BSSID --
			-- nothing usable. Class 81 is 2.4 GHz, channels 1-13.
			local orig_rrm, orig_sysinfo = inform._rrmscan, inform._sysinfo
			local asked = {}
			inform._rrmscan = {
				collector_ensure = function() end,
				harvest          = function() return {}, {} end,
				hostapd_objects  = function() return {"hostapd.wlan0", "hostapd.wlan1"} end,
				capable_stations = function(ifname)
					return {ifname == "wlan0" and "aa:bb:cc:dd:ee:01" or "aa:bb:cc:dd:ee:02"}
				end,
				request = function(ifname, sta, opts)
					asked[#asked + 1] = {ifname = ifname, sta = sta, op = opts and opts.op_class}
				end,
			}
			inform._sysinfo = setmetatable({
				radio_caps = function(ifname)
					return {channel = (ifname == "wlan0") and 6 or 36}
				end,
			}, {__index = orig_sysinfo})

			local cfg = {config = {rrm_enrichment = true, rrm_request_interval = 0}}
			inform._rrm_asked = {}
			inform._rrm_next_request = 0
			inform._rrm_rr = 0
			inform._rrm_tick(cfg)
			inform._rrm_tick(cfg)

			inform._rrmscan, inform._sysinfo = orig_rrm, orig_sysinfo
			inform._rrm_asked = {}

			assert_eq(#asked, 2, "one station asked per tick, round-robin")
			local by_if = {}
			for _, a in ipairs(asked) do by_if[a.ifname] = a.op end
			assert_eq(by_if["wlan0"], 81, "the station on a 2.4 GHz BSS gets class 81")
			assert_eq(by_if["wlan1"], 115, "the one on 5 GHz still gets 115")
		end
	},
	{
		name = "inform: with no rrm_request_interval set, beacon requests go out hourly",
		fn = function()
			-- hostapd logs every report as a long hex line; at the old 600 s
			-- default they filled three quarters of logread.
			local orig_rrm, orig_sysinfo, orig_time =
				inform._rrmscan, inform._sysinfo, inform._time
			local asked, t = 0, 1000
			inform._time = function() return t end
			inform._rrmscan = {
				collector_ensure = function() end,
				harvest          = function() return {}, {aa = true} end,
				hostapd_objects  = function() return {"hostapd.wlan0"} end,
				capable_stations = function() return {"aa:bb:cc:dd:ee:01"} end,
				request          = function() asked = asked + 1 end,
			}
			inform._sysinfo = setmetatable({
				radio_caps = function() return {channel = 36} end,
			}, {__index = orig_sysinfo})

			local cfg = {config = {rrm_enrichment = true}}
			inform._rrm_asked = {}
			inform._rrm_next_request = 0
			inform._rrm_rr = 0

			inform._rrm_tick(cfg)
			t = 1000 + 600;  inform._rrm_tick(cfg)
			t = 1000 + 3599; inform._rrm_tick(cfg)
			local before_hour = asked
			t = 1000 + 3600; inform._rrm_tick(cfg)

			inform._rrmscan, inform._sysinfo, inform._time = orig_rrm, orig_sysinfo, orig_time
			inform._rrm_asked = {}
			inform._rrm_next_request = 0

			assert_eq(before_hour, 1, "one request in the first hour")
			assert_eq(asked, 2, "the next one an hour later")
		end
	},
	{
		name = "inform: a station that never answers is benched, and un-benched by a report",
		fn = function()
			-- Asking a station that only ever acknowledges costs it an ack
			-- every interval, forever, and yields nothing.
			local orig_rrm, orig_sysinfo, orig_stderr =
				inform._rrmscan, inform._sysinfo, io.stderr
			io.stderr = {write = function() end}
			local asked, reporters = 0, {}
			inform._rrmscan = {
				collector_ensure = function() end,
				harvest          = function() return {}, reporters end,
				hostapd_objects  = function() return {"hostapd.wlan0"} end,
				capable_stations = function() return {"aa:bb:cc:dd:ee:01"} end,
				request          = function() asked = asked + 1 end,
			}
			inform._sysinfo = setmetatable({
				radio_caps = function() return {channel = 36} end,
			}, {__index = orig_sysinfo})

			local cfg = {config = {rrm_enrichment = true, rrm_request_interval = 0}}
			inform._rrm_asked = {}
			inform._rrm_next_request = 0
			inform._rrm_rr = 0

			for _ = 1, 5 do inform._rrm_tick(cfg) end
			assert_eq(asked, inform.RRM_MAX_UNANSWERED,
				"asked twice, then left alone however many ticks go by")

			-- An answer -- any answer -- puts it straight back in rotation.
			reporters = {["aa:bb:cc:dd:ee:01"] = true}
			inform._rrm_tick(cfg)
			assert_eq(asked, inform.RRM_MAX_UNANSWERED + 1, "a report clears the count")

			inform._rrmscan, inform._sysinfo, io.stderr = orig_rrm, orig_sysinfo, orig_stderr
			inform._rrm_asked = {}
		end
	},
	{
		name = "inform: a build_json that throws still closes the ucihelper lookup pass",
		fn = function()
			-- build_json opens a pass and closes it on its normal return. An
			-- error skips that close, and a stale pass would then hand
			-- handle_response's own lookups the interface names read before
			-- `wifi reload` rebuilt them.
			local orig = {
				build_json = inform.build_json, uci = inform._ucihelper,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr,
			}
			io.stderr = {write = function() end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			local open_passes = 0
			inform._ucihelper = {
				begin_pass = function() open_passes = open_passes + 1 end,
				end_pass   = function() open_passes = open_passes - 1 end,
			}
			inform.build_json = function()
				inform._ucihelper.begin_pass()
				error("boom halfway through the payload")
			end
			inform._tick({inform_url = "http://unifi:8080/inform"}, nil, nil,
				{interval = 10, backoff = 10})

			inform.build_json, inform._ucihelper, inform._reload_if_changed,
				inform._rrm_tick, io.stderr =
				orig.build_json, orig.uci, orig.reload, orig.rrm, orig.stderr
			assert_eq(open_passes, 0, "the pass is closed even on the error path")
		end
	},
	{
		name = "inform: the RRM collector is checked once a minute, not every heartbeat",
		fn = function()
			-- collector_ensure forks `pgrep -f` to ask whether the background
			-- `ubus subscribe` child is alive. That ran on every 10-second
			-- heartbeat, but the subscription only dies when one of the
			-- hostapd objects it named goes away -- a config push, not a
			-- ten-second event.
			local orig = {rrm = inform._rrmscan, time = inform._time}
			local clock, checks = 4000, 0
			inform._time = function() return clock end
			inform._rrm_collector_next = 0
			inform._rrmscan = {
				collector_ensure = function() checks = checks + 1 end,
				harvest = function() return {}, {} end,
				_now = function() return clock end,
			}
			local cfg = {config = {rrm_enrichment = true}}

			inform._rrm_tick(cfg)
			clock = clock + 10; inform._rrm_tick(cfg)
			clock = clock + 10; inform._rrm_tick(cfg)
			assert_eq(checks, 1, "one liveness check, not one per heartbeat")

			clock = clock + inform.RRM_COLLECTOR_CHECK_INTERVAL
			inform._rrm_tick(cfg)
			assert_eq(checks, 2, "and another once the interval is up")

			inform._rrmscan, inform._time = orig.rrm, orig.time
			inform._rrm_collector_next = 0
		end
	},
	{
		name = "inform: a bodiless 802.11k copy keeps what the beacon body proved",
		fn = function()
			-- hostapd sends each report on its control socket (with the body)
			-- and then over ubus (without). Landing in a later drain, the ubus
			-- copy replaced the named record: live, every row of one office
			-- report reached the controller unnamed, at 20 MHz on channel 42.
			local orig = {rrm = inform._rrmscan, time = inform._time,
				nxt = inform._rrm_next_request, cache = inform._rrm_cache}
			local clock = 5000
			inform._time = function() return clock end
			inform._rrm_collector_next = math.huge
			inform._rrm_next_request = math.huge
			inform._rrm_cache = {}
			local batch
			inform._rrmscan = {harvest = function() return batch, {} end}
			local cfg = {config = {rrm_enrichment = true}}

			batch = {{bssid = "00:00:5e:00:53:01", band = "na", channel = 48, bw = 80,
				essid = "Neighbour", security = "wpa2", signal = -70, seen_at = clock, body = true}}
			inform._rrm_tick(cfg)
			clock = clock + 10
			batch = {{bssid = "00:00:5e:00:53:01", band = "na", channel = 42,
				signal = -71, seen_at = clock}}
			inform._rrm_tick(cfg)
			local n = inform._rrm_neighbours[1]
			assert_eq(n.essid, "Neighbour", "name kept")
			assert_eq(n.security, "wpa2", "security kept")
			assert_eq(n.bw, 80, "width kept")
			assert_eq(n.channel, 48, "primary kept, not the centre channel")
			assert_eq(n.signal, -71, "the fresher level is taken")
			assert_eq(n.seen_at, clock, "and so is the fresher time")

			-- With nothing proven before, a bodiless record stands as it is.
			inform._rrm_cache = {}
			batch = {{bssid = "00:00:5e:00:53:01", band = "na", channel = 42,
				signal = -71, seen_at = clock}}
			inform._rrm_tick(cfg)
			assert_nil(inform._rrm_neighbours[1].essid, "no body, no name")
			assert_eq(inform._rrm_neighbours[1].channel, 42, "fixed-field channel")

			inform._rrmscan, inform._time = orig.rrm, orig.time
			inform._rrm_next_request, inform._rrm_cache = orig.nxt, orig.cache
			inform._rrm_collector_next = 0
		end
	},
	{
		name = "inform: a config push re-arms the RRM collector check immediately",
		fn = function()
			-- `wifi reload` takes every hostapd object the collector subscribed
			-- to away with it and kills the subscription. That is the one
			-- moment the check must not wait out its interval -- otherwise
			-- 802.11k enrichment is dead for up to a minute after every push,
			-- which is exactly when the neighbourhood is worth re-reading.
			local orig = {
				rrm = inform._rrmscan, time = inform._time,
				build = inform.build_json, packet = inform.build_packet,
				post = inform.http_post, parse = inform.parse_packet,
				handle = inform.handle_response, reload = inform._reload_if_changed,
			}
			local clock, checks = 4000, 0
			inform._time = function() return clock end
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrmscan = {
				collector_ensure = function() checks = checks + 1 end,
				harvest = function() return {}, {} end,
				_now = function() return clock end,
			}
			inform.build_json    = function() return "{}" end
			inform.build_packet  = function() return "pkt" end
			inform.http_post     = function() return "body" end
			inform.parse_packet  = function() return "{}" end
			inform.handle_response = function() return true end   -- config applied
			inform._rrm_collector_next = 0
			local cfg = {config = {rrm_enrichment = true}}
			local ctx = {interval = 10, backoff = 10}

			assert_eq(inform._tick({inform_url = "u"}, cfg, nil, ctx), 0,
				"a config was applied, so the AP re-informs at once")
			assert_eq(checks, 1, "the first heartbeat checked")
			-- Well inside the interval, so without the re-arm this would not.
			clock = clock + 10
			inform._tick({inform_url = "u"}, cfg, nil, ctx)
			assert_eq(checks, 2, "and the push re-armed the check straight away")

			inform._rrmscan, inform._time = orig.rrm, orig.time
			inform.build_json, inform.build_packet = orig.build, orig.packet
			inform.http_post, inform.parse_packet = orig.post, orig.parse
			inform.handle_response, inform._reload_if_changed = orig.handle, orig.reload
			inform._rrm_collector_next = 0
		end
	},
	{
		name = "inform: a build_json that throws still closes the sysinfo lookup pass",
		fn = function()
			-- The sysinfo pass memoizes /proc/net/arp, /tmp/dhcp.leases and the
			-- bucketed switch ARL for the length of one payload. Leaving it
			-- open past an error would feed the NEXT heartbeat this one's
			-- wired-host data -- clients that have since moved socket or
			-- changed address, reported where they used to be.
			local orig = {
				build_json = inform.build_json, sysinfo = inform._sysinfo,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr,
			}
			io.stderr = {write = function() end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			local open_passes = 0
			inform._sysinfo = {
				begin_pass = function() open_passes = open_passes + 1 end,
				end_pass   = function() open_passes = open_passes - 1 end,
			}
			inform.build_json = function()
				inform._sysinfo.begin_pass()
				error("boom halfway through the payload")
			end
			inform._tick({inform_url = "http://unifi:8080/inform"}, nil, nil,
				{interval = 10, backoff = 10})

			inform.build_json, inform._sysinfo, inform._reload_if_changed,
				inform._rrm_tick, io.stderr =
				orig.build_json, orig.sysinfo, orig.reload, orig.rrm, orig.stderr
			assert_eq(open_passes, 0, "the pass is closed even on the error path")
		end
	},
	{
		name = "inform: a streak of HTTP 400s names its likely cause once",
		fn = function()
			-- When lan_cpueth changes under an adopted device, every inform
			-- afterwards arrives under a MAC the controller has no adoption
			-- for -- rejected 400 while the old record goes Offline. Nothing
			-- about that is visible from the device: the daemon is healthy,
			-- the radios are up, and the log fills with anonymous 400s.
			local orig_stderr = io.stderr
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			local st = {adopted = true, mac = "aa:bb:cc:dd:ee:ff"}
			local cfg = {net = {lan_cpueth = "wan"}}
			inform._warned_400 = false

			assert_true(inform._warn_http_400("HTTP 400", st, cfg), "the first 400 warns")
			assert_false(inform._warn_http_400("HTTP 400", st, cfg), "the rest of the streak is quiet")
			local out = table.concat(logged)
			assert_true(out:find("lan_cpueth", 1, true) ~= nil, "and it names the likely cause")
			assert_true(out:find("aa:bb:cc:dd:ee:ff", 1, true) ~= nil, "and the MAC it informs as")

			-- Not every failure, and not on an unadopted device: before
			-- adoption a 400 means something else entirely.
			inform._warned_400 = false
			assert_false(inform._warn_http_400("connection refused", st, cfg),
				"a transport failure is not this")
			assert_false(inform._warn_http_400("HTTP 500", st, cfg), "nor is any other status")
			assert_false(inform._warn_http_400("HTTP 400", {adopted = false}, cfg),
				"and an unadopted device has other reasons to be refused")

			io.stderr = orig_stderr
			inform._warned_400 = false
		end
	},
	{
		name = "inform: device-level bandsteering block parses as captured (prefer_5g, equal, off)",
		fn = function()
			-- Captured on 10.4.57 2026-09-27 with wifi_caps 0xC claimed, two
			-- dual-band WLANs, and the device's Band Steering set to each mode.
			local pairs_blk = "bandsteering.1.status=enabled\n"
				.. "bandsteering.1.vap.1.devname=ath1\nbandsteering.1.vap.2.devname=ath3\n"
				.. "bandsteering.2.status=enabled\n"
				.. "bandsteering.2.vap.1.devname=ath0\nbandsteering.2.vap.2.devname=ath2\n"
			local on = inform._parse_bandsteering_system_cfg("# bandsteering\n"
				.. "bandsteering.status=enabled\nbandsteering.mode=prefer_5g\n" .. pairs_blk)
			assert_true(on.enabled, "prefer_5g is enabled")
			assert_eq(on.mode, "prefer_5g", "mode read")
			local eq = inform._parse_bandsteering_system_cfg(
				"bandsteering.status=enabled\nbandsteering.mode=equal\n" .. pairs_blk)
			assert_eq(eq.mode, "equal", "equal read")
			local off = inform._parse_bandsteering_system_cfg(
				"# bandsteering\nbandsteering.status=disabled\n")
			assert_false(off.enabled, "off is disabled")
			assert_nil(off.mode, "and carries no mode")
			assert_nil(inform._parse_bandsteering_system_cfg("wireless.1.devname=ath0\n"),
				"no block (bit not claimed) is nil, not off")
			-- A pair's own status line is not the device's.
			assert_nil(inform._parse_bandsteering_system_cfg(pairs_blk),
				"bandsteering.<n>.status is not bandsteering.status")
		end
	},
	{
		name = "inform: device Band Steering prefer_5g turns steering on; off and equal leave per-WLAN alone",
		fn = function()
			local orig_stderr = io.stderr
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			inform._warned_bandsteering_mode = false
			local none = {{no2ghz_oui = false}}
			local wlan_on = {{no2ghz_oui = true}}
			local pf = "bandsteering.status=enabled\nbandsteering.mode=prefer_5g\n"
			local eq = "bandsteering.status=enabled\nbandsteering.mode=equal\n"
			local off = "bandsteering.status=disabled\n"

			assert_true(inform._steering_flags(none, pf), "device prefer_5g steers")
			assert_false(inform._steering_flags(none, off), "device off, WLANs off: none")
			assert_true(inform._steering_flags(wlan_on, off),
				"device off does not override a WLAN's own Band Steering")
			assert_false(inform._steering_flags(none, ""), "no block: per-WLAN only")
			assert_true(inform._steering_flags(wlan_on, ""), "no block, WLAN on: steers")

			assert_false(inform._steering_flags(none, eq), "equal is not faked as prefer_5g")
			assert_true(inform._steering_flags(wlan_on, eq), "equal leaves per-WLAN steering")
			local out = table.concat(logged)
			assert_true(out:find("equal", 1, true) ~= nil, "equal is reported")
			local n = #logged
			inform._steering_flags(none, eq)
			assert_eq(#logged, n, "once")

			local _, ra = inform._steering_flags({{roam_assist_enabled = true}}, pf)
			assert_true(ra, "Roaming Assistant still reported")

			io.stderr = orig_stderr
			inform._warned_bandsteering_mode = false
		end
	},
	{
		-- Every 10.x controller sends capability=notif,notif-assoc-stat in
		-- mgmt_cfg (captured on 10.4.57, PROTOCOL-VALIDATION.md). It is the
		-- only signal that the controller wants STA_ASSOC_TRACKER notifs.
		name = "inform: mgmt_cfg capability notif-assoc-stat is recorded and persisted",
		fn = function()
			local st = sample_state()
			inform._rrm_collector_next = 999
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat\\ncfgversion=2\\n"}', st)
			assert_eq(st.notif_assoc_stat, true, "asked")
			assert_eq(inform._rrm_collector_next, 0, "the collector check is re-armed at once")
			inform._rrm_collector_next = 999
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat\\ncfgversion=2\\n"}', st)
			assert_eq(inform._rrm_collector_next, 999, "but not by a setparam that changes nothing")
			inform._rrm_collector_next = 0
			assert_eq(state.FIELDS.notif_assoc_stat, "boolean", "survives a restart (setparam is not resent)")
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"capability=notif\\ncfgversion=3\\n"}', st)
			assert_eq(st.notif_assoc_stat, false, "a capability list without it turns it off")
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat-v2\\ncfgversion=4\\n"}', st)
			assert_eq(st.notif_assoc_stat, false, "matched as a whole list item, not a prefix")
		end
	},
	{
		-- The controller builds mgmt_cfg whole and always appends stun_url
		-- (com.ubnt.service.config mgmt builder, 10.6).
		name = "inform: mgmt_cfg stun_url is recorded, persisted, and cleared by its absence",
		fn = function()
			local st = sample_state()
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"cfgversion=2\\nstun_url=stun://192.0.2.4:3478/\\ninform_url=http://192.0.2.4:8080/inform\\n"}', st)
			assert_eq(st.stun_url, "stun://192.0.2.4:3478/", "recorded")
			assert_eq(state.FIELDS.stun_url, "string", "survives a restart (setparam is not resent)")
			inform.handle_response('{"_type":"noop","interval":10}', st)
			assert_eq(st.stun_url, "stun://192.0.2.4:3478/", "a noop leaves it")
			inform.handle_response('{"_type":"setparam","system_cfg":"netconf.1.ip=192.0.2.3\\n"}', st)
			assert_eq(st.stun_url, "stun://192.0.2.4:3478/", "a setparam without mgmt_cfg leaves it")
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"cfgversion=3\\nstun_url=\\n"}', st)
			assert_eq(st.stun_url, nil, "empty: no STUN")
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"cfgversion=4\\nstun_url=stun://192.0.2.4:3478/\\n"}', st)
			inform.handle_response('{"_type":"setparam","mgmt_cfg":"cfgversion=5\\n"}', st)
			assert_eq(st.stun_url, nil, "a mgmt_cfg without it: no STUN")
		end
	},
	{
		name = "inform: the STUN client runs only while managed and a server is named",
		fn = function()
			local sent, opened, closed = {}, 0, 0
			local fake = {dns = {toip = function(h) return h end}}
			fake.udp = function()
				opened = opened + 1
				return {
					setsockname = function() return 1 end,
					settimeout = function() end,
					sendto = function(_, data, ip, port) sent[#sent + 1] = ip .. ":" .. port; return #data end,
					receive = function() return nil, "timeout" end,
					close = function() closed = closed + 1 end,
				}
			end
			local rs, rt, rf = inform._socket, inform._time, inform._inform_fails
			local now = 1000
			inform._socket = function() return fake end
			inform._time = function() return now end
			inform._stun_c, inform._inform_fails = nil, 0
			local ok, err = pcall(function()
				local st = sample_state({adopted = false, stun_url = "stun://192.0.2.4:3478/"})
				inform._stun_tick(st)
				assert_eq(opened, 0, "not adopted: no socket")
				st.adopted = true
				st.stun_url = nil
				inform._stun_tick(st)
				assert_eq(opened, 0, "no stun_url: no socket")
				st.stun_url = "stun://192.0.2.4:3478/"
				inform._stun_tick(st)
				assert_eq(opened, 1, "managed with a server: opened")
				assert_eq(sent[1], "192.0.2.4:3478", "and a Binding Request sent")
				now = now + 10
				inform._stun_tick(st)
				assert_eq(#sent, 1, "not again within 30 s")
				now = now + 20
				inform._stun_tick(st)
				assert_eq(#sent, 2, "again at 30 s")
				-- Selfrun: GUEST_SELFRUN_FAILS informs unanswered.
				inform._inform_fails = inform.GUEST_SELFRUN_FAILS
				inform._stun_tick(st)
				assert_eq(closed, 1, "selfrun: closed")
				inform._inform_fails = inform.GUEST_SELFRUN_FAILS - 1
				inform._stun_tick(st)
				assert_eq(opened, 2, "managed again: reopened")
			end)
			inform._socket, inform._time, inform._inform_fails = rs, rt, rf
			inform._stun_c = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: _idle ends early on a STUN connection request, not on other packets",
		fn = function()
			local t = 0
			local queue = {}
			local stun_sock = {receive = function()
				local p = table.remove(queue, 1)
				if p then return p end
				return nil, "timeout"
			end}
			local selects = {}
			local sock = {
				gettime = function() return t end,
				select = function(r, _, timeout)
					selects[#selects + 1] = #(r or {}) .. "@" .. timeout
					-- A packet arrives 2 s in.
					if #queue > 0 then t = t + 2; return {stun_sock} end
					t = t + timeout
					return {}
				end,
			}
			local wake = string.char(0x88, 0x88) .. string.rep(string.char(0), 18)
			local junk = string.char(0x01, 0x11) .. string.rep(string.char(0), 18)
			inform._guest_server = nil
			inform._stun_c = {sock = stun_sock}
			local ok, err = pcall(function()
				queue = {wake}
				inform._idle(sock, 10)
				assert_eq(t, 2, "woke at the request")
				assert_eq(table.concat(selects, ","), "1@10", "one wait on the STUN socket")
				t, selects, queue = 0, {}, {junk}
				inform._idle(sock, 10)
				assert_eq(t, 10, "an error response does not wake it")
				assert_eq(table.concat(selects, ","), "1@10,1@8", "it keeps waiting for the rest")
			end)
			inform._stun_c = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: connection tracking needs the controller's ask and no conf.lua veto",
		fn = function()
			assert_false(inform._assoc_enabled({}, {config = {}}), "not asked")
			assert_true(inform._assoc_enabled({notif_assoc_stat = true}, {config = {}}), "asked, conf silent")
			assert_true(inform._assoc_enabled({notif_assoc_stat = true}, nil), "no cfg at all")
			assert_false(inform._assoc_enabled({notif_assoc_stat = true}, {config = {assoc_tracker = false}}),
				"conf.lua assoc_tracker = false wins")
		end
	},
	{
		-- The envelope proven in the lab against 10.4.57: inform_as_notif,
		-- notif_reason "event", notif_payload, beside the device identity.
		-- The controller's noop reply carries no interval and must not reach
		-- handle_response.
		name = "inform: queued notifs go out one POST each in the notif envelope",
		fn = function()
			local at = inform._assoctrack
			local o_post, o_build, o_hr = inform.http_post, inform.build_packet, inform.handle_response
			local o_queue, o_ident = at._queue, inform._notif_identity
			local bodies, hr_calls = {}, 0
			inform.build_packet = function(json) return json end
			inform.http_post = function(url, pkt) bodies[#bodies + 1] = cjson.decode(pkt); return "noop" end
			inform.handle_response = function() hr_calls = hr_calls + 1 end
			inform._notif_identity = {mac = "00:00:5e:00:53:20", model = "U6IW", version = "6.8.2.15592"}
			at._queue = {{message_type = "STA_ASSOC_TRACKER", n = 1}, {message_type = "STA_ASSOC_TRACKER", n = 2}}
			local sent = inform._send_notifs({adopted = true, inform_url = "http://x/inform"})
			local q_after = #at._queue
			inform.http_post, inform.build_packet, inform.handle_response = o_post, o_build, o_hr
			at._queue, inform._notif_identity = o_queue, o_ident
			assert_eq(sent, 2, "both sent")
			assert_eq(q_after, 0, "queue drained")
			assert_eq(#bodies, 2, "one POST per notif")
			local b = bodies[1]
			assert_eq(b.inform_as_notif, true, "inform_as_notif")
			assert_eq(b.notif_reason, "event", "notif_reason")
			assert_eq(b.notif_payload.message_type, "STA_ASSOC_TRACKER", "payload")
			assert_eq(b.notif_payload.n, 1, "in queue order")
			assert_eq(b.mac, "00:00:5e:00:53:20", "device identity")
			assert_eq(b.version, "6.8.2.15592", "firmware version")
			assert_eq(type(b.time), "number", "time")
			assert_eq(hr_calls, 0, "the noop reply never reaches handle_response")
		end
	},
	{
		name = "inform: a failed notif POST puts it and the rest back in order",
		fn = function()
			local at = inform._assoctrack
			local o_post, o_build = inform.http_post, inform.build_packet
			local o_queue, o_ident = at._queue, inform._notif_identity
			local posts = 0
			inform.build_packet = function(json) return json end
			inform.http_post = function() posts = posts + 1; if posts == 2 then return nil, "timeout" end return "noop" end
			inform._notif_identity = {mac = "00:00:5e:00:53:20"}
			at._queue = {{n = 1}, {n = 2}, {n = 3}}
			local sent = inform._send_notifs({adopted = true, inform_url = "http://x/inform"})
			local q = at._queue
			inform.http_post, inform.build_packet = o_post, o_build
			at._queue, inform._notif_identity = o_queue, o_ident
			assert_eq(sent, 1, "one got through")
			assert_eq(#q, 2, "two kept")
			assert_eq(q[1].n, 2, "the failed one first")
			assert_eq(q[2].n, 3, "then the one never tried")
		end
	},
	{
		-- The monitors are what produce the radar event, so a DFS radio has to
		-- keep them running on a site with neither 802.11k enrichment nor
		-- connection tracking -- where _rrm_tick used to return early, stop
		-- the collector and delete the event file.
		name = "inform: a DFS radio keeps the control-socket monitors alive on its own",
		fn = function()
			local o_rrm, o_at, o_dfs = inform._rrmscan, inform._assoctrack, inform._dfs_radio
			local o_next, o_time = inform._rrm_collector_next, inform._time
			local calls
			local stub = {
				drain = function() return "" end,
				collector_running = function() return false end,
				collector_stop = function() calls[#calls + 1] = "collector_stop" end,
				collector_ensure = function() calls[#calls + 1] = "collector_ensure" end,
				monitors_ensure = function() calls[#calls + 1] = "monitors_ensure" end,
				monitors_stop = function() calls[#calls + 1] = "monitors_stop" end,
				parse_dfs = function() return {} end,
			}
			inform._rrmscan = stub
			inform._assoctrack = nil	-- so _assoc_enabled is false
			-- Restored through a pcall: this test replaces _assoctrack and the
			-- collector clock, and a bare assert would leave both broken for
			-- every test after it.
			local function run(dfs, rrm_on)
				calls = {}
				inform._dfs_radio = dfs
				inform._rrm_collector_next = 0
				inform._time = function() return 1 end
				inform._rrm_tick({config = {rrm_enrichment = rrm_on or nil}}, {})
				return table.concat(calls, ",")
			end
			local ok, err = pcall(function()
				assert_eq(run(true, false), "monitors_ensure",
					"DFS only: the monitors run, the subscriber does not")
				assert_eq(run(false, false), "",
					"nothing wanted: the early branch, as before")
				assert_eq(run(true, true), "collector_ensure,monitors_ensure",
					"enrichment on: both")
				assert_eq(run(false, true), "collector_ensure,monitors_ensure",
					"enrichment alone still starts both")
				-- A subscriber left over from a run with enrichment on is stopped.
				stub.collector_running = function() return true end
				assert_eq(run(true, false), "collector_stop,monitors_ensure",
					"the stale subscriber goes before the monitors are restarted")
			end)
			inform._rrmscan, inform._assoctrack = o_rrm, o_at
			inform._dfs_radio, inform._time = o_dfs, o_time
			inform._rrm_collector_next = o_next
			if not ok then error(err, 0) end
		end
	},
	{
		-- A DFS-only site has no subscriber, so nothing ever writes the event
		-- file: draining it every heartbeat was a read of the whole file plus
		-- the truncating rewrite that follows, for nothing.
		name = "inform: a quiet collector file is not drained",
		fn = function()
			local o_rrm, o_at, o_dfs = inform._rrmscan, inform._assoctrack, inform._dfs_radio
			local o_next, o_time = inform._rrm_collector_next, inform._time
			local file = os.tmpname()
			os.remove(file)	-- the DFS-only case: no collector, no file at all
			local drains = 0
			inform._rrmscan = {
				EVENT_FILE = file,
				drain = function()
					drains = drains + 1
					local h = io.open(file, "r")
					local b = h and h:read("*a") or ""
					if h then h:close() end
					local w = io.open(file, "w"); if w then w:close() end
					return b
				end,
				collector_running = function() return false end,
				collector_stop = function() end,
				monitors_ensure = function() end,
				parse_dfs = function(blob)
					return blob:find("RADAR", 1, true)
						and {{channel = 100, freq = 5500, ifname = "phy1-ap0"}} or {}
				end,
			}
			inform._assoctrack = nil
			inform._dfs_radio, inform._time = true, function() return 1 end
			inform._event_queue, inform._event_seen = {}, {}
			local o_stderr = io.stderr
			io.stderr = {write = function() end}
			local cfg = {config = {rrm_enrichment = false}}
			local ok, err = pcall(function()
				inform._rrm_collector_next = 0
				inform._rrm_tick(cfg, {})
				assert_eq(drains, 0, "no file: nothing to drain")
				local h = io.open(file, "w"); h:close()
				inform._rrm_tick(cfg, {})
				assert_eq(drains, 0, "an empty file costs an open and a seek, not a drain")
				h = io.open(file, "w")
				h:write("1299.01 phy1-ap0 DFS-RADAR-DETECTED freq=5500\n")
				h:close()
				inform._rrm_tick(cfg, {})
				assert_eq(drains, 1, "lines in it: drained")
				assert_eq(#inform._event_queue, 1, "and the radar event is queued")
				inform._rrm_tick(cfg, {})
				assert_eq(drains, 1, "the drain emptied it, so the next heartbeat is free again")
			end)
			io.stderr = o_stderr
			os.remove(file)
			inform._rrmscan, inform._assoctrack = o_rrm, o_at
			inform._dfs_radio, inform._time = o_dfs, o_time
			inform._rrm_collector_next = o_next
			inform._event_queue, inform._event_seen = {}, {}
			if not ok then error(err, 0) end
		end
	},
	{
		-- `elseif rrm.collector_running then` tested a FUNCTION value, so the
		-- branch was always taken and the pgrep inside it ran every 60 s for
		-- the lifetime of the daemon -- on every DFS-only site, to be told the
		-- same thing every time.
		name = "inform: the collector check stops once it reports there is none",
		fn = function()
			local o_rrm, o_at, o_dfs = inform._rrmscan, inform._assoctrack, inform._dfs_radio
			local o_next, o_time, o_reaped =
				inform._rrm_collector_next, inform._time, inform._collector_reaped
			local checks, stops, alive = 0, 0, true
			inform._rrmscan = {
				drain = function() return "" end,
				collector_running = function() checks = checks + 1; return alive end,
				collector_stop = function() stops = stops + 1 end,
				collector_ensure = function() end,
				harvest = function() return {}, {} end,
				hostapd_objects = function() return {} end,
				monitors_ensure = function() end,
				parse_dfs = function() return {} end,
			}
			inform._assoctrack = nil
			inform._dfs_radio = true
			local clock = 1000
			inform._time = function() return clock end
			local function minute()
				clock = clock + inform.RRM_COLLECTOR_CHECK_INTERVAL
				inform._rrm_tick({config = {rrm_enrichment = false}}, {})
			end
			local ok, err = pcall(function()
				inform._rrm_collector_next, inform._collector_reaped = 0, false
				minute()
				assert_eq(checks, 1, "the leftover subscriber is looked for")
				assert_eq(stops, 1, "and killed")
				-- A kill whose success is never read back: while it still
				-- reports alive the question is asked again.
				minute()
				assert_eq(checks, 2, "a survivor is chased")
				assert_eq(stops, 2, "and killed again")
				alive = false
				minute()
				assert_eq(checks, 3, "one more check reports it gone")
				assert_eq(stops, 2, "nothing left to kill")
				minute(); minute(); minute()
				assert_eq(checks, 3, "and that is the last pgrep this state costs")
				-- Enrichment back on starts a collector, so the answer can
				-- change again: the latch is cleared.
				inform._rrm_collector_next = 0
				inform._rrm_tick({config = {rrm_enrichment = true}}, {})
				assert_eq(checks, 3, "nothing is pgrepped while one is wanted")
				alive = true
				minute()
				assert_eq(checks, 4, "once it is unwanted again it is looked for afresh")
			end)
			inform._rrmscan, inform._assoctrack = o_rrm, o_at
			inform._dfs_radio, inform._time = o_dfs, o_time
			inform._rrm_collector_next, inform._collector_reaped = o_next, o_reaped
			if not ok then error(err, 0) end
		end
	},
	{
		-- parse_dfs walked the whole blob a second time, right after
		-- assoctrack.parse_events had walked it for the funnel -- the
		-- one-pass rule the rest of the tick follows.
		name = "inform: one walk of the collector blob finds the funnel's events and the radar",
		fn = function()
			local at = inform._assoctrack
			local STA = "00:00:5e:00:53:01"
			local blob = table.concat({
				'100.10 { "assoc": {"address":"' .. STA .. '","ifname":"phy1-ap0","signal":-61} }',
				'100.20 { "probe": {"address":"00:00:5e:00:53:09"} }',
				'100.30 phy1-ap0 DFS-RADAR-DETECTED freq=5500 ht_enabled=0 cf1=5530',
				'100.40 phy1-ap0 BEACON-RESP-RX 00:00:5e:00:53:01 1 0 0011',
			}, "\n") .. "\n"
			local evs = at.parse_events(blob)
			local kinds = {}
			for _, e in ipairs(evs) do kinds[e.ev] = (kinds[e.ev] or 0) + 1 end
			assert_eq(kinds.assoc, 1, "the association is still parsed")
			assert_eq(kinds.radar, 1, "and the radar line comes out of the same walk")
			assert_eq(kinds.probe, nil, "probes are still ignored")
			local radar
			for _, e in ipairs(evs) do if e.ev == "radar" then radar = e end end
			assert_eq(radar.ifname, "phy1-ap0", "the BSS hostapd reported it on")
			assert_eq(radar.freq, 5500, "the frequency the radar was seen on")
			assert_eq(radar.t, 100.30, "stamped with the collector's uptime")

			-- Handed those records, _dfs_poll does not walk the blob again.
			local o_rrm, o_time = inform._rrmscan, inform._time
			local walks = 0
			inform._rrmscan = setmetatable({
				parse_dfs = function(b) walks = walks + 1; return o_rrm.parse_dfs(b) end,
			}, {__index = o_rrm})
			inform._time = function() return 7000 end
			inform._event_queue, inform._event_seen = {}, {}
			local o_stderr = io.stderr
			io.stderr = {write = function() end}
			local ok, err = pcall(function()
				assert_eq(inform._dfs_poll(blob, evs), 1, "the detection is still reported")
				assert_eq(walks, 0, "off the walk parse_events already did")
				assert_eq(inform._event_queue[1].channel, "100",
					"and radar_of resolved the channel the same way")
				-- No event list (DFS only, nothing else reading the file):
				-- parse_dfs does the walk itself, as before.
				inform._event_queue, inform._event_seen = {}, {}
				assert_eq(inform._dfs_poll(blob), 1, "the standalone path still works")
				assert_eq(walks, 1, "by walking the blob")
			end)
			io.stderr = o_stderr
			inform._rrmscan, inform._time = o_rrm, o_time
			inform._event_queue, inform._event_seen = {}, {}
			at._stas, at._queue, at._here, at._roamed, at._roam_queue = {}, {}, {}, {}, {}
			if not ok then error(err, 0) end
		end
	},
	{
		-- The contract is 10.6.106's own handler (com.ubnt.service.devmgr.e.c):
		-- it needs BOTH "channel" and "freq" in the notif_payload and drops
		-- the event with "Event without handler" if either is missing, reads
		-- channel as a STRING and freq as an int, and then logs
		-- "{ap} detected radar on channel {radar_channel} ({freq} MHz)".
		-- 6.8.2's ubntbox sends the same three fields plus "vap".
		name = "inform: a DFS radar detection goes out as EVT_AP_RadarDetected",
		fn = function()
			local o_post, o_build, o_ident = inform.http_post, inform.build_packet,
				inform._notif_identity
			local bodies = {}
			inform.build_packet = function(json) return json end
			inform.http_post = function(_, pkt) bodies[#bodies + 1] = cjson.decode(pkt); return "noop" end
			inform._notif_identity = {mac = "00:00:5e:00:53:20", model = "U6IW"}
			inform._event_queue, inform._event_seen = {}, {}
			local queued = inform._dfs_poll(
				"1299.01 phy1-ap0 DFS-RADAR-DETECTED freq=5500 ht_enabled=0 "
				.. "chan_offset=0 chan_width=1 cf1=5530 cf2=0\n")
			local sent = inform._send_events({adopted = true, inform_url = "http://x/inform"})
			local q_after = #inform._event_queue
			inform.http_post, inform.build_packet = o_post, o_build
			inform._notif_identity = o_ident
			inform._event_queue, inform._event_seen = {}, {}
			assert_eq(queued, 1, "one detection queued")
			assert_eq(sent, 1, "and sent")
			assert_eq(q_after, 0, "queue drained")
			local b = bodies[1]
			assert_eq(b.inform_as_notif, true, "the notif envelope, as for a station notif")
			assert_eq(b.notif_reason, "event", "notif_reason")
			assert_eq(b.mac, "00:00:5e:00:53:20", "device identity")
			local p = b.notif_payload
			assert_eq(p.event_string, "EVT_AP_RadarDetected", "the event the controller dispatches on")
			assert_eq(p.channel, "100", "channel as a string, which is how the handler reads it")
			assert_eq(p.freq, 5500, "freq as a number")
			assert_eq(p.vap, "phy1-ap0", "the BSS, as 6.8.2 sends it")
			assert_eq(p.dedup_key, nil, "the dedup key is ours and never goes on the wire")
		end
	},
	{
		name = "inform: one radar hit on two BSSes is one event, and the queue is capped",
		fn = function()
			local o_time = inform._time
			local now = 5000
			inform._time = function() return now end
			inform._event_queue, inform._event_seen = {}, {}
			-- hostapd prints the detection on each BSS of the radio: same
			-- channel, same second, two lines.
			local two = "1299.01 phy1-ap0 DFS-RADAR-DETECTED freq=5500\n"
				.. "1299.01 phy1-ap1 DFS-RADAR-DETECTED freq=5500\n"
			assert_eq(inform._dfs_poll(two), 1, "collapsed to one")
			-- A different channel in the same second is a different radar.
			assert_eq(inform._dfs_poll("1299.02 phy1-ap0 DFS-RADAR-DETECTED freq=5260\n"),
				1, "another channel still reported")
			-- Past the window the same channel is a new detection.
			now = now + inform.EVENT_DEDUP_S + 1
			assert_eq(inform._dfs_poll(two), 1, "a later hit on the same channel is new")
			-- The cap is a queue cap, not a drop-everything: an unreachable
			-- controller must not let /tmp grow an unbounded backlog.
			inform._event_queue, inform._event_seen = {}, {}
			for i = 1, inform.MAX_EVENTS + 4 do
				inform.queue_event{event_string = "EVT_AP_RadarDetected", n = i}
			end
			assert_eq(#inform._event_queue, inform.MAX_EVENTS, "capped")
			assert_eq(inform._event_queue[1].n, 1, "the oldest is kept")
			-- An event with no event_string is not an event.
			assert_eq(inform.queue_event{channel = "100"}, false, "no event_string")
			assert_eq(inform.queue_event("EVT_AP_RadarDetected"), false, "not a table")
			inform._time = o_time
			inform._event_queue, inform._event_seen = {}, {}
		end
	},
	{
		-- Unlike the station notifs, a device event rides no capability: the
		-- controller asked for nothing, and the AP is telling it something it
		-- has no other way to learn. It does still need an adopted device
		-- with an identity to file the event under.
		name = "inform: device events need no notif-assoc-stat, but do need an adopted device",
		fn = function()
			local o_post, o_build, o_ident = inform.http_post, inform.build_packet,
				inform._notif_identity
			local posts = 0
			inform.build_packet = function(json) return json end
			inform.http_post = function() posts = posts + 1; return "noop" end
			local ev = {event_string = "EVT_AP_RadarDetected", channel = "100", freq = 5500}
			inform._notif_identity = nil
			inform._event_queue = {ev}
			assert_eq(inform._send_events({adopted = true, inform_url = "http://x/inform"}), 0,
				"no identity yet: nothing sent")
			inform._notif_identity = {mac = "00:00:5e:00:53:20"}
			assert_eq(inform._send_events({adopted = false, inform_url = "http://x/inform"}), 0,
				"not adopted: nothing sent")
			assert_eq(#inform._event_queue, 1, "and the event is still queued")
			assert_eq(inform._send_events({adopted = true, inform_url = "http://x/inform"}), 1,
				"adopted, with an identity: sent, with no capability asked for")
			-- A failed POST keeps it for the next heartbeat.
			inform.http_post = function() return nil, "timeout" end
			inform._event_queue = {ev}
			assert_eq(inform._send_events({adopted = true, inform_url = "http://x/inform"}), 0,
				"POST failed")
			assert_eq(#inform._event_queue, 1, "kept")
			inform.http_post, inform.build_packet = o_post, o_build
			inform._notif_identity = o_ident
			inform._event_queue, inform._event_seen = {}, {}
			assert_eq(posts, 1, "exactly one POST reached the controller")
		end
	},
	{
		-- A roam report spoils with delay; a funnel event does not. Roams go
		-- first, and a failed roam POST stops the funnel too (the controller
		-- is not answering).
		name = "inform: roam reports are sent before funnel notifs",
		fn = function()
			local at = inform._assoctrack
			local o_post, o_build = inform.http_post, inform.build_packet
			local o_queue, o_roams, o_ident = at._queue, at._roam_queue, inform._notif_identity
			local sent, fail_on = {}, nil
			inform.build_packet = function(json) return json end
			inform.http_post = function(_, pkt)
				local p = cjson.decode(pkt).notif_payload
				if p.n == fail_on then return nil, "timeout" end
				sent[#sent + 1] = p.n
				return "noop"
			end
			inform._notif_identity = {mac = "00:00:5e:00:53:20"}
			local ok, err = pcall(function()
				at._queue = {{n = "f1"}}
				at._roam_queue = {{n = "r1"}, {n = "r2"}}
				assert_eq(inform._send_notifs({adopted = true, inform_url = "u"}), 3, "all three")
				assert_eq(table.concat(sent, ","), "r1,r2,f1", "roams first")
				sent, fail_on = {}, "r2"
				at._queue = {{n = "f1"}}
				at._roam_queue = {{n = "r1"}, {n = "r2"}}
				assert_eq(inform._send_notifs({adopted = true, inform_url = "u"}), 1, "stopped at the failure")
				assert_eq(#at._roam_queue, 1, "the failed roam kept")
				assert_eq(at._roam_queue[1].n, "r2", "the failed roam kept")
				assert_eq(#at._queue, 1, "the funnel event not tried")
			end)
			inform.http_post, inform.build_packet = o_post, o_build
			at._queue, at._roam_queue, inform._notif_identity = o_queue, o_roams, o_ident
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: _idle looks at the collector every ROAM_POLL_S while roam reports are on",
		fn = function()
			local t = 0
			local selects = {}
			local sock = {
				gettime = function() return t end,
				select = function(r, _, timeout)
					selects[#selects + 1] = timeout
					t = t + timeout
					return {}
				end,
			}
			local o_poll, polls = inform._roam_poll, 0
			inform._roam_poll = function() polls = polls + 1 end
			inform._guest_server, inform._stun_c = nil, nil
			inform._roam_fast = true
			local ok, err = pcall(inform._idle, sock, 1)
			inform._roam_fast = false
			inform._roam_poll = o_poll
			if not ok then error(err, 0) end
			assert_eq(#selects, 4, "1 s in 0.25 s steps")
			assert_eq(selects[1], inform.ROAM_POLL_S, "step")
			assert_eq(polls, 4, "a look after each")
			assert_eq(t, 1, "and still returns at the deadline")
		end
	},
	{
		-- Between heartbeats _idle drains the collector's file itself: the
		-- roam report goes out at once, the funnel's notif waits for the
		-- heartbeat, and the drained lines are kept for the beacon-report
		-- harvest the heartbeat still runs.
		name = "inform: _roam_poll sends roam reports at once and keeps the lines for the harvest",
		fn = function()
			local at = inform._assoctrack
			local STA = "00:00:5e:00:53:01"
			local file = os.tmpname()
			local lines = table.concat({
				'100.10 { "assoc": {"address":"' .. STA .. '","ifname":"phy1-ap0","signal":-61} }',
				'100.22 { "sta-authorized": {"address":"' .. STA .. '","ifname":"phy1-ap0","auth-alg":"ft"} }',
				'100.30 { "beacon-report": {"address":"' .. STA .. '"} }',
			}, "\n") .. "\n"
			local f = io.open(file, "w"); f:write(lines); f:close()
			local o = {rrm = inform._rrmscan, post = inform.http_post, build = inform.build_packet,
				ident = inform._notif_identity, map = inform._vap_by_ifname}
			local posts = {}
			inform._rrmscan = {EVENT_FILE = file, drain = function()
				local h = io.open(file, "r"); local b = h:read("*a"); h:close()
				h = io.open(file, "w"); h:close()
				return b
			end}
			inform.build_packet = function(json) return json end
			inform.http_post = function(_, pkt) posts[#posts + 1] = cjson.decode(pkt).notif_payload; return "noop" end
			inform._notif_identity = {mac = "00:00:5e:00:53:20"}
			inform._vap_by_ifname = {["phy1-ap0"] = "openuf_radio1_home"}
			inform._roam_st = {adopted = true, inform_url = "u"}
			at._stas, at._queue, at._here, at._roamed, at._roam_queue = {}, {}, {}, {}, {}
			inform._pre_blob, inform._roam_keep = nil, true
			local ok, err = pcall(function()
				inform._roam_poll()
				assert_eq(#posts, 1, "one POST")
				assert_eq(posts[1].event_type, "association", "the roam report")
				assert_eq(posts[1].auth_algo, "ft", "auth_algo")
				assert_true(at._stas[STA] ~= nil, "the funnel's attempt is open, for the heartbeat")
				assert_eq(table.concat(inform._pre_blob), lines, "lines kept for the harvest")
				inform._roam_poll()
				assert_eq(#posts, 1, "an empty file costs nothing more")
				-- A second drain is appended as its own chunk, not recopied.
				local h = io.open(file, "w"); h:write("101.00 tail0\n"); h:close()
				inform._roam_poll()
				assert_eq(#inform._pre_blob, 2, "one chunk per drain")
			end)
			-- The heartbeat folds those lines into what harvest sees.
			local harvested
			inform._rrmscan = {drain = function() return "200.0 tail\n" end,
				harvest = function(b) harvested = b; return {}, {} end,
				collector_ensure = function() end}
			local o_time = inform._time
			inform._time = function() return 1 end
			inform._rrm_collector_next = 10
			local ok2, err2 = pcall(inform._rrm_tick, {config = {rrm_enrichment = true}}, {notif_assoc_stat = true})
			inform._time = o_time
			inform._rrm_collector_next = 0
			os.remove(file)
			inform._rrmscan, inform.http_post, inform.build_packet = o.rrm, o.post, o.build
			inform._notif_identity, inform._vap_by_ifname = o.ident, o.map
			inform._roam_st, inform._roam_fast, inform._pre_blob, inform._roam_keep = nil, false, nil, false
			at._stas, at._queue, at._here, at._roamed, at._roam_queue = {}, {}, {}, {}, {}
			if not ok then error(err, 0) end
			if not ok2 then error(err2, 0) end
			assert_eq(harvested, lines .. "101.00 tail0\n200.0 tail\n", "pre-drained lines first, then the heartbeat's own")
		end
	},
	{
		-- With enrichment off nothing harvests beacon reports, so _idle's
		-- drains are ingested for the roam reports and then let go.
		name = "inform: _roam_poll keeps nothing for a harvest that will not run",
		fn = function()
			local at = inform._assoctrack
			local file = os.tmpname()
			local f = io.open(file, "w")
			f:write('100.10 { "disassoc": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0"} }\n')
			f:close()
			local o_rrm = inform._rrmscan
			inform._rrmscan = {EVENT_FILE = file, drain = function()
				local h = io.open(file, "r"); local b = h:read("*a"); h:close()
				h = io.open(file, "w"); h:close()
				return b
			end, collector_ensure = function() end}
			at._stas, at._queue, at._here, at._roamed, at._roam_queue = {}, {}, {}, {}, {}
			local o_time = inform._time
			inform._time = function() return 1 end
			inform._rrm_collector_next = 10
			local ok, err = pcall(function()
				inform._pre_blob = {"stale"}
				inform._rrm_tick({config = {rrm_enrichment = false}}, {notif_assoc_stat = true})
				assert_true(inform._roam_fast, "connection tracking still polls")
				assert_eq(inform._pre_blob, nil, "a kept chunk list is dropped once enrichment is off")
				f = io.open(file, "w"); f:write("101.00 x\n"); f:close()
				inform._roam_poll()
				assert_eq(inform._pre_blob, nil, "and nothing new is kept")
			end)
			inform._time = o_time
			inform._rrm_collector_next = 0
			os.remove(file)
			inform._rrmscan = o_rrm
			inform._roam_st, inform._roam_fast, inform._pre_blob, inform._roam_keep = nil, false, nil, false
			at._stas, at._queue, at._here, at._roamed, at._roam_queue = {}, {}, {}, {}, {}
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: nothing is sent before adoption",
		fn = function()
			local at = inform._assoctrack
			local o_post, o_queue, o_ident = inform.http_post, at._queue, inform._notif_identity
			local posts = 0
			inform.http_post = function() posts = posts + 1; return "noop" end
			inform._notif_identity = {mac = "00:00:5e:00:53:20"}
			at._queue = {{n = 1}}
			inform._send_notifs({adopted = false, inform_url = "http://x/inform"})
			local left = #at._queue
			inform.http_post, at._queue, inform._notif_identity = o_post, o_queue, o_ident
			assert_eq(posts, 0, "no POST")
			assert_eq(left, 1, "kept for later")
		end
	},
	{
		-- With rrm_enrichment off, the collector used to be stopped. It is
		-- now also connection tracking's source, so it must keep running --
		-- with the table installed BEFORE the collector whose auth hook
		-- writes into it -- while beacon-report harvesting stays off.
		name = "inform: connection tracking keeps the collector alive with rrm_enrichment off",
		fn = function()
			local o_rrm, o_at, o_time = inform._rrmscan, inform._assoctrack, inform._time
			local calls, ensure_opts = {}, nil
			local at = setmetatable({
				ensure_table = function() calls[#calls + 1] = "table"; return true end,
				teardown = function() calls[#calls + 1] = "teardown" end,
			}, {__index = o_at})
			inform._assoctrack = at
			inform._rrmscan = {
				collector_running = function() return true end,
				collector_stop    = function() calls[#calls + 1] = "stop" end,
				collector_ensure  = function(opts) calls[#calls + 1] = "collector"; ensure_opts = opts end,
				drain             = function() return "" end,
				harvest           = function() calls[#calls + 1] = "harvest"; return {}, {} end,
			}
			inform._time = function() return 5000 end
			inform._rrm_collector_next = 0
			inform._assoc_installed = false
			local st = {notif_assoc_stat = true}
			inform._rrm_tick({config = {rrm_enrichment = false}}, st)
			local seq = table.concat(calls, ",")

			-- Then the controller stops asking: table and hook go away.
			calls = {}
			inform._rrm_collector_next = 0
			inform._rrm_tick({config = {rrm_enrichment = false}}, {})
			local seq2 = table.concat(calls, ",")

			inform._rrmscan, inform._assoctrack, inform._time = o_rrm, o_at, o_time
			inform._rrm_collector_next = 0
			inform._assoc_installed = false
			assert_eq(seq, "table,collector", "table first, then the collector; no stop, no harvest")
			assert_true(ensure_opts and type(ensure_opts.on_auth) == "string"
				and ensure_opts.on_auth:find("destroy element", 1, true) ~= nil,
				"the collector carries the auth hook")
			assert_eq(seq2, "stop,teardown", "neither consumer wants it: collector stopped, table removed")
		end
	},
	{
		-- Notifs ride on the heartbeat: after a state inform succeeded, and
		-- only when the controller asked for them.
		name = "inform: a heartbeat sends queued notifs after the state inform, when asked",
		fn = function()
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response, send = inform._send_notifs,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
			}
			local order = {}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() return "{}" end
			inform.build_packet = function() return "pkt" end
			inform.http_post = function() order[#order + 1] = "state"; return "body" end
			inform.parse_packet = function() return '{"_type":"noop"}' end
			inform.handle_response = function() return false end
			inform._send_notifs = function() order[#order + 1] = "notifs"; return 0 end

			local ctx = {interval = 10, backoff = 10}
			inform._tick({inform_url = "u", notif_assoc_stat = true}, {config = {}}, nil, ctx)
			local asked = table.concat(order, ",")
			order = {}
			inform._tick({inform_url = "u"}, {config = {}}, nil, ctx)
			local not_asked = table.concat(order, ",")

			inform.build_json, inform.build_packet, inform.http_post,
				inform.parse_packet, inform.handle_response, inform._send_notifs,
				inform._reload_if_changed, inform._rrm_tick =
				orig.build_json, orig.build_packet, orig.http_post, orig.parse_packet,
				orig.handle_response, orig.send, orig.reload, orig.rrm
			assert_eq(asked, "state,notifs", "state inform first, then the notifs")
			assert_eq(not_asked, "state", "nothing when the controller did not ask")
		end
	},
	{
		name = "inform packet: a portal push enforces it; portal off tears it down",
		fn = function()
			local real = inform._guestportal
			local calls = {reconcile = {}, listen = 0, closed = 0}
			inform._guestportal = {
				parse = real.parse, is_guest_rule = real.is_guest_rule, PORT = real.PORT,
				garden_ips = real.garden_ips, resolve_garden = real.resolve_garden,
				bridge_mac = function(ifname) return ifname == "phy0-ap1" and "02:00:00:00:00:aa" or nil end,
				reconcile = function(spec, vaps, macs, selfrun)
					calls.reconcile[#calls.reconcile + 1] = {spec = spec, vaps = vaps, macs = macs,
						selfrun = selfrun}
					return 1
				end,
				listen = function()
					calls.listen = calls.listen + 1
					return {close = function() calls.closed = calls.closed + 1 end}
				end,
			}
			local asked_ids
			inform._ucihelper = {wlanconf_ifnames = function(ids)
				asked_ids = ids
				return {{ifname = "phy0-ap1", ssid = "g"}, {ifname = "phy1-ap1", ssid = "g"}}
			end}
			local save = inform._state.save
			inform._state.save = function() end
			local function push(st, portal)
				local sys = "aaa.1.id=w1\nwireless.1.ssid=g\nwireless.1.parent=wifi0\n"
					.. "wireless.1.is_guest=true\nredirector.status=" .. portal .. "\n"
					.. "redirector.url=http://192.0.2.2:8880/guest/s/default/\n"
					.. "ebtables.7.cmd=-t nat -A PREROUTING --in-interface ath0 -j GUESTIN\n"
				inform.handle_response(cjson.encode({_type = "setparam", system_cfg = sys}),
					st, {net = {lan_cpueth = "eth0"}})
			end
			local ok, err = pcall(function()
				local st = sample_state({guest_authorized = {["de:ad:be:ef:00:02"] = 1}})
				push(st, "enabled")
				assert_true(st.guest_portal and st.guest_portal.enabled, "the portal's facts kept")
				assert_eq(st.guest_portal.unknown, nil, "the report is not persisted")
				assert_true(type(st.guest_token) == "string" and st.guest_token:match("^%x+$") ~= nil
					and #st.guest_token == 32, "a guest_token to report")
				assert_true(asked_ids.w1, "the guest WLAN's netdevs were asked for")
				local r = calls.reconcile[1]
				assert_eq(#r.vaps, 2, "both guest netdevs")
				assert_eq(r.vaps[1].bridge_mac, "02:00:00:00:00:aa", "with their bridge MAC")
				assert_eq(table.concat(r.macs, ","), "de:ad:be:ef:00:02", "and the ledger")
				assert_false(r.selfrun, "the controller is there: no selfrun")
				inform._guest_selfrun_on = true
				inform._guest_enforce(st)
				inform._guest_selfrun_on = false
				assert_true(calls.reconcile[2].selfrun, "a rebuild while in selfrun keeps guests let through")
				table.remove(calls.reconcile, 2)
				assert_eq(calls.listen, 1, "listening")
				assert_eq(inform._guest_ctx.url, "http://192.0.2.2:8880/guest/s/default/", "the answer's target")
				local token = st.guest_token
				push(st, "enabled")
				assert_eq(calls.listen, 1, "a second push does not listen again")
				assert_eq(st.guest_token, token, "nor change the token")
				push(st, "disabled")
				assert_eq(st.guest_portal, nil, "off")
				assert_eq(calls.reconcile[3].spec, nil, "tables torn down")
				assert_eq(calls.closed, 1, "listener closed")
				assert_eq(inform._guest_server, nil, "and forgotten")
				assert_eq(inform._guest_built, nil, "nothing built")
			end)
			inform._guestportal, inform._ucihelper, inform._state.save = real, nil, save
			inform._guest_server, inform._guest_built, inform._guest_ctx = nil, nil, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: authorize-guest refills the nft set only while the portal is built",
		fn = function()
			local real = inform._guestportal
			local filled
			inform._guestportal = {set_authorized = function(macs) filled = macs end}
			local save = inform._state.save
			inform._state.save = function() end
			local ok, err = pcall(function()
				local st = sample_state({guest_authorized = {["de:ad:be:ef:00:02"] = 1}})
				inform._guest_built = nil
				inform.handle_response('{"_type":"cmd","cmd":"authorize-guest","mac":"de:ad:be:ef:00:03"}', st)
				assert_eq(filled, nil, "no portal: the ledger only")
				inform._guest_built = "phy0-ap1=x"
				inform.handle_response('{"_type":"cmd","cmd":"authorize-guest","mac":"de:ad:be:ef:00:04"}', st)
				assert_eq(table.concat(filled, ","), "de:ad:be:ef:00:02,de:ad:be:ef:00:03,de:ad:be:ef:00:04",
					"the whole ledger, sorted")
				inform.handle_response('{"_type":"cmd","cmd":"unauthorize-guest","mac":"de:ad:be:ef:00:02"}', st)
				assert_eq(table.concat(filled, ","), "de:ad:be:ef:00:03,de:ad:be:ef:00:04", "and on unauthorize")
			end)
			inform._guestportal, inform._state.save, inform._guest_built = real, save, nil
			if not ok then error(err, 0) end
		end
	},
	{
		-- The controller sends rate-update for any client with a WiFi Speed
		-- Limit profile of its own, not only portal guests: each time it
		-- connects, roams or reconnects (the qos_policy_applied latch) and
		-- when the profile changes. update_sta_qosrate takes it for any
		-- associated station, and -1 lifts that station's cap.
		name = "inform packet: rate-update keeps a per-client limit for any associated client",
		fn = function()
			local save, saves = inform._state.save, 0
			inform._state.save = function() saves = saves + 1 end
			local real_sh, synced = inform._shaper, {}
			inform._shaper = {sync = function(d) synced[#synced + 1] = d end}
			local ok, err = pcall(function()
				local st = sample_state({})
				inform._shape_obs = {complete = true,
					by_ifname = {wlan0 = {down = 5000, macs = {"de:ad:be:ef:00:02"}}},
					where = {["de:ad:be:ef:00:02"] = "wlan0"}, conn = {["de:ad:be:ef:00:02"] = 30}}
				local function upd(mac, ul, dl)
					inform.handle_response(cjson.encode({_type = "cmd", cmd = "rate-update", mac = mac,
						ul_max = ul, ul_min = 64, dl_max = dl, dl_min = 64}), st)
				end
				upd("DE:AD:BE:EF:00:02", 2048, 4096)
				assert_eq(st.sta_rates["de:ad:be:ef:00:02"].up, 2048, "upload kbps")
				assert_eq(st.sta_rates["de:ad:be:ef:00:02"].down, 4096, "download kbps")
				assert_eq(saves, 1, "persisted")
				assert_eq(#synced, 1, "applied at once")
				assert_eq(synced[1].wlan0.down.stas["de:ad:be:ef:00:02"], 4096, "replacing the WLAN's 5000")
				upd("de:ad:be:ef:00:02", 2048, 4096)
				assert_eq(saves, 1, "a repeat changes nothing")
				assert_eq(#synced, 1, "and applies nothing")
				upd("de:ad:be:ef:00:02", -1, 4096)
				assert_eq(st.sta_rates["de:ad:be:ef:00:02"].up, -1, "-1 is kept: it lifts the cap")
				upd("de:ad:be:ef:00:02", nil, 0)
				assert_eq(st.sta_rates["de:ad:be:ef:00:02"].down, -1, "missing or 0 is -1 too")
				assert_eq(synced[#synced].wlan0.down.stas["de:ad:be:ef:00:02"], 0, "uncapped under the WLAN limit")
				local before = saves
				upd("de:ad:be:ef:00:03", 2048, 4096)
				assert_nil(st.sta_rates["de:ad:be:ef:00:03"], "not associated here: ignored, as the firmware does")
				assert_eq(saves, before, "not even stored")
				upd("x;reboot", 1, 1)
				assert_nil(st.sta_rates["x;reboot"])
				inform._shape_obs = nil
				upd("de:ad:be:ef:00:04", 512, 512)
				assert_eq(st.sta_rates["de:ad:be:ef:00:04"].down, 512, "before the first heartbeat: kept")
			end)
			inform._state.save, inform._shaper, inform._shape_obs = save, real_sh, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: _shaper_resync shapes each listed client at its WLAN's limit or its own",
		fn = function()
			local save = inform._state.save
			inform._state.save = function() end
			local real_sh, got = inform._shaper, nil
			inform._shaper = {sync = function(d) got = d end}
			local ok, err = pcall(function()
				local A, B, C = "de:ad:be:ef:00:0a", "de:ad:be:ef:00:0b", "de:ad:be:ef:00:0c"
				local st = sample_state({sta_rates = {[B] = {up = 300, down = -1}, [C] = {up = -1, down = 200}}})
				inform._sta_conn = {}
				inform._shape_obs = {complete = true,
					by_ifname = {
						wlan0 = {down = 5000, up = 1000, macs = {A, B}},
						wlan1 = {macs = {C}},
						wlan2 = {macs = {"de:ad:be:ef:00:0d"}},
					},
					where = {[A] = "wlan0", [B] = "wlan0", [C] = "wlan1", ["de:ad:be:ef:00:0d"] = "wlan2"},
					conn = {[A] = 10, [B] = 10, [C] = 10}}
				assert_true(inform._shaper_resync(st))
				assert_eq(got.wlan0.down.default, 5000, "the WLAN's limit for new clients")
				assert_eq(got.wlan0.down.stas[A], 5000, "A at the WLAN's limit, in its own class")
				assert_eq(got.wlan0.up.stas[A], 1000)
				assert_eq(got.wlan0.down.stas[B], 0, "B's own -1: uncapped")
				assert_eq(got.wlan0.up.stas[B], 300, "B's own upload limit")
				assert_eq(got.wlan1.down.stas[C], 200, "a client's download limit alone, on an unlimited WLAN")
				assert_nil(got.wlan1.down.default)
				assert_nil(got.wlan2, "no limit anywhere: not shaped")
			end)
			inform._state.save, inform._shaper, inform._shape_obs = save, real_sh, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: a client's own limit lasts one association",
		fn = function()
			local save, saves = inform._state.save, 0
			inform._state.save = function() saves = saves + 1 end
			local real_sh = inform._shaper
			inform._shaper = {sync = function() end}
			local ok, err = pcall(function()
				local A, B = "de:ad:be:ef:00:0a", "de:ad:be:ef:00:0b"
				local st = sample_state({sta_rates = {[A] = {up = 300, down = 300}, [B] = {up = 1, down = 1}}})
				inform._sta_conn = {}
				local function obs(complete, conn)
					local where, macs = {}, {}
					for m in pairs(conn) do where[m] = "wlan0"; macs[#macs + 1] = m end
					inform._shape_obs = {complete = complete, by_ifname = {wlan0 = {macs = macs}},
						where = where, conn = conn}
				end
				obs(true, {[A] = 100, [B] = 100})
				inform._shaper_resync(st)
				assert_true(st.sta_rates[A] and st.sta_rates[B], "both still connected")
				assert_eq(saves, 0, "nothing changed")
				obs(true, {[A] = 110})
				inform._shaper_resync(st)
				assert_nil(st.sta_rates[B], "B left: its limit goes")
				assert_eq(saves, 1, "persisted")
				obs(false, {})
				inform._shaper_resync(st)
				assert_true(st.sta_rates[A] ~= nil, "a listing that failed proves nothing: A's kept")
				obs(true, {[A] = 5})
				inform._shaper_resync(st)
				assert_nil(st.sta_rates, "A's connected time dropped: a new association, the limit goes")
			end)
			inform._state.save, inform._shaper, inform._shape_obs = save, real_sh, nil
			inform._sta_conn = {}
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: build_json hands each netdev's stations and limits to the shaper",
		fn = function()
			local orig_si, orig_uci = inform._sysinfo, inform._ucihelper
			local ok, err = pcall(function()
				inform._sysinfo = setmetatable({sta_table = function(ifname)
					if ifname == "wlan0" then return {{mac = "DE:AD:BE:EF:00:0A", connected_sec = 42}} end
					if ifname == "wlan0.10" then return {{mac = "de:ad:be:ef:00:0b", connected_sec = 7}} end
					error("iw failed")
				end}, {__index = orig_si})
				inform._ucihelper = setmetatable({
					get_vap_table = function()
						return {
							{name = "a", essid = "corp", radio_name = "radio0", radio = "ng", usage = "user",
							 ratelimit_down = 5000, ratelimit_up = 1000},
							{name = "b", essid = "iot", radio_name = "radio0", radio = "ng", usage = "user"},
						}
					end,
					get_ifnames_for_vap = function(_, essid)
						if essid == "corp" then return {"wlan0", "wlan0.10"} end
						return {"wlan1"}
					end,
				}, {__index = orig_uci})
				local out = cjson.decode(inform.build_json(sample_state({adopted = true}), {}, nil))
				local o = inform._shape_obs
				assert_eq(o.by_ifname.wlan0.down, 5000, "the WLAN's limits on each of its netdevs")
				assert_eq(o.by_ifname["wlan0.10"].up, 1000, "a VLAN netdev's too")
				assert_eq(o.by_ifname.wlan0.macs[1], "de:ad:be:ef:00:0a", "lower-cased")
				assert_eq(o.where["de:ad:be:ef:00:0b"], "wlan0.10", "shaped where it is listed")
				assert_eq(o.conn["de:ad:be:ef:00:0a"], 42)
				assert_false(o.complete, "wlan1's listing failed")
				for _, v in ipairs(out.vap_table or {}) do
					assert_nil(v.ratelimit_down, "internal: never sent")
					assert_nil(v.ratelimit_up)
				end
			end)
			inform._sysinfo, inform._ucihelper, inform._shape_obs = orig_si, orig_uci, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: selfrun_guest_mode is kept from mgmt_cfg",
		fn = function()
			local save = inform._state.save
			inform._state.save = function() end
			local ok, err = pcall(function()
				local st = sample_state()
				inform.handle_response(cjson.encode({_type = "setparam",
					mgmt_cfg = "capability=notif\nselfrun_guest_mode=pass\ncfgversion=abc\n"}), st)
				assert_eq(st.guest_selfrun, "pass", "pass")
				inform.handle_response(cjson.encode({_type = "setparam",
					mgmt_cfg = "selfrun_guest_mode=off\n"}), st)
				assert_eq(st.guest_selfrun, "off", "off")
				inform.handle_response(cjson.encode({_type = "setparam",
					mgmt_cfg = "selfrun_guest_mode=weird\n"}), st)
				assert_eq(st.guest_selfrun, "pass", "like the firmware, only off is off")
				inform.handle_response(cjson.encode({_type = "setparam",
					mgmt_cfg = "selfrun_guest_mode=off\n"}), st)
				inform.handle_response(cjson.encode({_type = "setparam", mgmt_cfg = "cfgversion=x\n"}), st)
				assert_eq(st.guest_selfrun, "off", "absent: unchanged")
			end)
			inform._state.save = save
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform: selfrun starts after 3 unanswered informs; pass opens the portal, off takes the guest WLANs down",
		fn = function()
			local orig = {
				build_json = inform.build_json, build_packet = inform.build_packet,
				http_post = inform.http_post, parse_packet = inform.parse_packet,
				handle_response = inform.handle_response,
				reload = inform._reload_if_changed, rrm = inform._rrm_tick,
				stderr = io.stderr, gp = inform._guestportal, vaps = inform._guest_vaps,
				save = inform._state.save, ws = inform._wlansched,
			}
			local logged = {}
			io.stderr = {write = function(_, s) logged[#logged + 1] = s end}
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() return "{}" end
			inform.build_packet = function() return "pkt" end
			inform.parse_packet = function() return '{"_type":"noop"}' end
			inform.handle_response = function() return false end
			local saves = 0
			inform._state.save = function() saves = saves + 1 end
			local calls, links = {}, {}
			inform._guestportal = {set_selfrun = function(pass) calls[#calls + 1] = pass end}
			local link = {["phy0-ap1"] = true, ["phy1-ap1"] = true}
			inform._wlansched = setmetatable({
				set_bss = function(n, up)
					links[#links + 1] = (up and "up " or "down ") .. n
					link[n] = up
					return true
				end,
				is_up = function(n) return link[n] end,
			}, {__index = orig.ws})
			inform._guest_vaps = function() return {{ifname = "phy0-ap1"}, {ifname = "phy1-ap1"}} end
			inform._inform_fails, inform._guest_selfrun_on, inform._guest_built = 0, false, "phy0-ap1=x"
			local ok, err = pcall(function()
				local ctx = {interval = 10, backoff = 10}
				local st = {inform_url = "http://unifi:8080/inform", guest_portal = {enabled = true}}
				local function tick(up)
					inform.http_post = up and function() return "body" end
						or function() return nil, "connection refused" end
					inform._tick(st, nil, nil, ctx)
				end
				-- never told: pass
				tick(true); tick(false); tick(false)
				assert_eq(#calls, 0, "two failures: the portal holds")
				tick(false)
				assert_eq(calls[1], true, "the third: guests let through")
				tick(false)
				assert_eq(#calls, 1, "once")
				assert_eq(#links, 0, "pass leaves the WLANs up")
				tick(true)
				assert_eq(calls[2], false, "the first answer closes it again")
				tick(false); tick(false); tick(true); tick(false); tick(false)
				assert_eq(#calls, 2, "the count restarts at each answer")
				tick(true)

				st.guest_selfrun = "off"
				tick(false); tick(false)
				assert_eq(#links, 0, "off: nothing before the third failure")
				tick(false)
				assert_eq(table.concat(links, ", "), "down phy0-ap1, down phy1-ap1", "off: the guest WLANs go down")
				assert_eq(#calls, 2, "off never opens the portal")
				assert_eq(table.concat(st.guest_vaps_down, " "), "phy0-ap1 phy1-ap1", "kept for a restart")
				local saved = saves
				assert_true(saved > 0, "the ledger is saved")
				tick(false); tick(false)
				assert_eq(#links, 2, "once")
				-- a daemon restart while down: module state is fresh, the ledger is not
				inform._inform_fails, inform._guest_selfrun_on = 0, false
				tick(false)
				assert_eq(#links, 2, "still no controller after the restart: they stay down")
				tick(true)
				assert_eq(links[3] .. ", " .. links[4], "up phy0-ap1, up phy1-ap1", "the answer brings them back up")
				assert_nil(st.guest_vaps_down, "ledger cleared")
				assert_eq(#calls, 2, "and the portal was never opened")

				st.guest_selfrun = "pass"
				st.guest_portal = nil
				tick(false); tick(false); tick(false)
				assert_eq(#calls, 2, "no portal: nothing to open")
				st.guest_portal = {enabled = true}
				inform._guest_built = nil
				tick(false)
				assert_eq(#calls, 2, "no tables yet: remembered, not applied")
				assert_true(inform._guest_selfrun_on, "for the next reconcile")
				local all = table.concat(logged)
				assert_true(all:find("letting guests through", 1, true) ~= nil, "said: pass")
				assert_true(all:find("guest WLANs down (phy0-ap1 phy1-ap1)", 1, true) ~= nil, "said: off")
				assert_true(all:find("guest WLANs back up", 1, true) ~= nil, "said: back up")
			end)
			io.stderr = orig.stderr
			inform.build_json, inform.build_packet, inform.http_post,
				inform.parse_packet, inform.handle_response,
				inform._reload_if_changed, inform._rrm_tick, inform._guestportal =
				orig.build_json, orig.build_packet, orig.http_post,
				orig.parse_packet, orig.handle_response, orig.reload, orig.rrm, orig.gp
			inform._guest_vaps, inform._state.save, inform._wlansched = orig.vaps, orig.save, orig.ws
			inform._inform_fails, inform._guest_selfrun_on, inform._guest_built = 0, false, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: l2guard leaves the guest rules to guestportal",
		fn = function()
			local real = inform._l2guard
			inform._l2guard = {
				parse = function() return {unknown = {
					"-t nat -A PREROUTING --in-interface ath0 -j GUESTIN", "-t nat -A X -j NEWTHING"}} end,
				spec_from = function() return {} end, reconcile = function() return 0 end,
			}
			local log
			local ok, err = pcall(function()
				log = with_stderr(function() inform._l2guard_apply_push("x", sample_state()) end)
			end)
			inform._l2guard = real
			if not ok then error(err, 0) end
			assert_eq(log:find("GUESTIN", 1, true), nil, "the guest hook is not reported")
			assert_true(log:find("NEWTHING", 1, true) ~= nil, "a real unknown still is")
		end
	},
	{
		name = "inform packet: _guest_resync rebuilds only when the guest netdevs changed",
		fn = function()
			local real, rt = inform._guestportal, inform._time
			local built = 0
			inform._guestportal = {
				bridge_mac = function() return "02:00:00:00:00:aa" end,
				garden_ips = real.garden_ips,
				reconcile = function() built = built + 1; return 1 end,
				listen = function() return {close = function() end} end, PORT = 1,
			}
			local live = {}
			inform._ucihelper = {wlanconf_ifnames = function() return live end}
			local now = 1000
			inform._time = function() return now end
			local ok, err = pcall(function()
				local st = sample_state({guest_portal = {enabled = true, url = "http://192.0.2.2/"},
					guest_token = "00"})
				inform._guest_enforce(st)          -- startup: wireless not up yet
				assert_eq(built, 1, "built once (with nothing to hook)")
				inform._guest_next = 0
				assert_false(inform._guest_resync(st), "still nothing live: no rebuild")
				live = {{ifname = "phy0-ap1", ssid = "g"}}
				assert_false(inform._guest_resync(st), "not before the interval")
				now = now + inform.GUEST_RESYNC_INTERVAL
				with_stderr(function() assert_true(inform._guest_resync(st), "the VAP came up: rebuilt") end)
				assert_eq(built, 2, "rebuilt once")
				now = now + inform.GUEST_RESYNC_INTERVAL
				assert_false(inform._guest_resync(st), "unchanged: left alone")
				assert_false(inform._guest_resync(sample_state()), "portal off: nothing to do")
			end)
			inform._guestportal, inform._time, inform._ucihelper = real, rt, nil
			inform._guest_server, inform._guest_built, inform._guest_ctx, inform._guest_next = nil, nil, nil, 0
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: the walled garden is resolved on the push and every ten minutes after",
		fn = function()
			local real, rt, save = inform._guestportal, inform._time, inform._state.save
			local orig_resolve = real._resolve
			local built, saved, passed = 0, 0, nil
			local answers = {["a.example"] = {"198.51.100.20"}}
			-- resolve_garden is the real one, so the resolver seam is replaced on
			-- the real module: that is what its closure reaches.
			real._resolve = function(n) return answers[n] or {} end
			inform._guestportal = {
				bridge_mac = function() return "02:00:00:00:00:aa" end,
				garden_ips = real.garden_ips, resolve_garden = real.resolve_garden,
				reconcile = function(_, _, _, _, garden)
					built = built + 1
					passed = garden
					return 1
				end,
				listen = function() return {close = function() end} end, PORT = 1,
			}
			inform._state.save = function() saved = saved + 1 end
			inform._ucihelper = {wlanconf_ifnames = function() return {} end}
			local now = 1000
			inform._time = function() return now end
			local ok, err = pcall(function()
				local st = sample_state({guest_token = "00", guest_portal = {enabled = true,
					url = "http://192.0.2.2/", wg_allowed = {"a.example"}, wg_restricted = {}}})
				inform._guest_wg_next = 0
				assert_true(inform._guest_wg_resolve(st), "first resolve: an address appeared")
				assert_eq(table.concat(st.guest_wg_ips.allowed["a.example"], ","), "198.51.100.20",
					"kept in state, so a reboot rebuilds without waiting on DNS")
				assert_eq(saved, 1, "written once")
				inform._guest_enforce(st)
				assert_eq(table.concat(passed.allowed, ","), "198.51.100.20",
					"and handed to reconcile as addresses")
				built, saved = 0, 0
				assert_false(inform._guest_wg_resync(st), "not before the interval")
				assert_eq(built, 0, "no rebuild")
				answers["a.example"] = {"198.51.100.22"}
				now = now + inform.GUEST_WG_INTERVAL
				with_stderr(function()
					assert_true(inform._guest_wg_resync(st), "the record moved: re-resolved and rebuilt")
				end)
				assert_eq(built, 1, "rebuilt once")
				assert_eq(table.concat(passed.allowed, ","), "198.51.100.22", "with the new address")
				now = now + inform.GUEST_WG_INTERVAL
				assert_false(inform._guest_wg_resync(st), "an unchanged answer rebuilds nothing")
				assert_eq(built, 1, "still one rebuild")
				-- A garden that empties takes its addresses with it.
				st.guest_portal.wg_allowed = {}
				inform._guest_wg_next = 0
				assert_true(inform._guest_wg_resolve(st), "the garden emptied")
				assert_nil(st.guest_wg_ips, "and state no longer carries addresses")
				assert_false(inform._guest_wg_resync(st), "nothing to refresh")
				assert_false(inform._guest_wg_resync(sample_state()), "portal off: nothing to do")
				-- A portal with no garden at all: the fields are absent, not
				-- empty, which is the case the guard is measured in (it used
				-- to allocate an empty table per field per heartbeat to take
				-- a length of). Still nothing resolved and nothing rebuilt.
				built = 0
				inform._guest_wg_next = 0
				assert_false(inform._guest_wg_resync(sample_state({guest_token = "00",
					guest_portal = {enabled = true, url = "http://192.0.2.2/"}})),
					"no garden: no refresh")
				assert_eq(built, 0, "and no rebuild")
			end)
			inform._guestportal, inform._time, inform._state.save = real, rt, save
			real._resolve = orig_resolve
			inform._ucihelper = nil
			inform._guest_server, inform._guest_built, inform._guest_ctx = nil, nil, nil
			inform._guest_wg_next, inform._guest_wg_sig = 0, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: a push does not re-ask DNS for a garden whose names did not move",
		fn = function()
			local real, rt, save = inform._guestportal, inform._time, inform._state.save
			local orig_resolve = real._resolve
			local asked = 0
			real._resolve = function() asked = asked + 1; return {"198.51.100.20"} end
			inform._guestportal = {
				garden_ips = real.garden_ips, resolve_garden = real.resolve_garden,
			}
			inform._state.save = function() end
			local now = 1000
			inform._time = function() return now end
			local ok, err = pcall(function()
				local spec = {enabled = true, url = "http://192.0.2.2/",
					wg_allowed = {"a.example"}, wg_restricted = {}}
				local st = sample_state({guest_token = "00", guest_portal = spec})
				inform._guest_wg_next, inform._guest_wg_sig = 0, nil
				inform._guest_wg_resolve(st)
				assert_eq(asked, 2, "the first push resolves: one name, asked twice")
				-- The controller repeats the whole garden on every push, and
				-- each name costs two blocking nslookups.
				inform._guest_wg_resolve(st)
				inform._guest_wg_resolve(st)
				assert_eq(asked, 2, "two more pushes with the same names ask nothing")
				spec.wg_allowed = {"a.example", "b.example"}
				inform._guest_wg_resolve(st)
				assert_eq(asked, 6, "a changed name list resolves both names")
				spec.wg_allowed = {"b.example", "a.example"}
				inform._guest_wg_resolve(st)
				assert_eq(asked, 10, "so does a reordering: that is the order they are asked in")
				now = now + inform.GUEST_WG_INTERVAL
				inform._guest_wg_resolve(st)
				assert_eq(asked, 14, "and the ten-minute window reopens it")
			end)
			inform._guestportal, inform._time, inform._state.save = real, rt, save
			real._resolve = orig_resolve
			inform._guest_wg_next, inform._guest_wg_sig = 0, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: a garden pass that runs out of time is retried in two minutes",
		fn = function()
			local real, rt, save = inform._guestportal, inform._time, inform._state.save
			local orig_resolve, orig_now = real._resolve, real._now
			local clock, asked = 0, 0
			real._now = function() return clock end
			real._resolve = function()
				asked = asked + 1
				clock = clock + 5
				return {"198.51.100.20"}
			end
			inform._guestportal = {
				garden_ips = real.garden_ips, resolve_garden = real.resolve_garden,
			}
			inform._state.save = function() end
			local now = 1000
			inform._time = function() return now end
			local ok, err = pcall(function()
				local st = sample_state({guest_token = "00", guest_portal = {enabled = true,
					url = "http://192.0.2.2/", wg_allowed = {"a.example", "b.example"},
					wg_restricted = {}}})
				inform._guest_wg_next, inform._guest_wg_sig = 0, nil
				with_stderr(function() inform._guest_wg_resolve(st) end)
				assert_eq(asked, 1, "the budget is spent inside the first name")
				assert_eq(inform._guest_wg_next, now + inform.GUEST_WG_RETRY,
					"so the heartbeat comes back in two minutes, not ten")
				asked, clock = 0, 0
				inform._guest_wg_resolve(st)
				assert_eq(asked, 0, "a push inside the retry window asks nothing")
				now = now + inform.GUEST_WG_RETRY
				with_stderr(function() inform._guest_wg_resolve(st) end)
				assert_true(asked > 0, "the retry window reopens it")
			end)
			inform._guestportal, inform._time, inform._state.save = real, rt, save
			real._resolve, real._now = orig_resolve, orig_now
			inform._guest_wg_next, inform._guest_wg_sig = 0, nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: _idle sleeps plainly, or answers guests until the deadline",
		fn = function()
			local t = 0
			local selects = {}
			local sock = {
				gettime = function() return t end,
				select = function(r, _, timeout)
					selects[#selects + 1] = (r and "R" or "-") .. timeout
					-- Two guests arrive a second apart, then nobody.
					if r and #selects <= 2 then t = t + 1; return {r[1]} end
					t = t + timeout
					return {}
				end,
			}
			inform._guest_server = nil
			inform._idle(sock, 10)
			assert_eq(table.concat(selects, ","), "-10", "no portal: one plain sleep")
			local real = inform._guestportal
			local served = 0
			inform._guestportal = {serve_one = function(server, ctx)
				assert_eq(type(ctx.arp), "function", "the answer can look the guest up")
				served = served + 1
				return true
			end}
			inform._guest_server = {}
			inform._guest_ctx = {url = "http://192.0.2.2/", ap = "00:00:5e:00:53:02", vaps = {}}
			selects, t = {}, 0
			local ok, err = pcall(inform._idle, sock, 10)
			inform._guestportal = real
			if not ok then
				inform._guest_server, inform._guest_ctx = nil, nil
				error(err, 0)
			end
			assert_eq(served, 2, "two guests answered")
			assert_eq(table.concat(selects, ","), "R10,R9,R8", "waits only for what is left")
			-- Readable with nothing to accept: rest out the wait, do not spin.
			inform._guestportal = {serve_one = function() return false end}
			selects, t = {}, 0
			ok, err = pcall(inform._idle, sock, 10)
			inform._guestportal = real
			inform._guest_server, inform._guest_ctx = nil, nil
			if not ok then error(err, 0) end
			assert_eq(table.concat(selects, ","), "R10,-9", "one try, then a plain sleep")
		end
	},
	{
		name = "inform packet: forgetting the controller tears the guest portal down",
		fn = function()
			local real = inform._guestportal
			local torn, closed = false, false
			inform._guestportal = {reconcile = function(spec) torn = (spec == nil) end}
			inform._guest_server = {close = function() closed = true end}
			inform._guest_built = "x"
			local ok, err = pcall(inform._forget_controller)
			inform._guestportal = real
			local left = inform._guest_server
			inform._guest_server, inform._guest_built = nil, nil
			if not ok then error(err, 0) end
			assert_true(torn, "tables deleted")
			assert_true(closed and left == nil, "listener closed")
		end
	},
	{
		name = "inform packet: a WiFi Blackout Schedule is parsed, stored on the wifi-iface and removed when off",
		fn = function()
			-- The lab push (10.4.57, fw_caps 0x1110, 2026-10-10): blackout 22:00
			-- for 540 min Mon-Fri, 13:00 for 60 and 15:30 for 30 on Saturday.
			-- Clearing schedule_with_duration left schedule_enabled=disabled
			-- and no schedule_* key.
			local ucihelper, db = new_apply_env()
			local base = "aaa.1.ssid=net\naaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\n"
				.. "wireless.1.ssid=net\nwireless.1.parent=radio0\n"
			local on_blob = base .. "wireless.1.schedule_enabled=enabled\n"
				.. "wireless.1.schedule_sun.0=0000-2359\n"
				.. "wireless.1.schedule_mon.0=0000-2200\nwireless.1.schedule_mon.1=0000-2200\n"
				.. "wireless.1.schedule_tue.0=0700-2200\nwireless.1.schedule_tue.1=0700-2200\n"
				.. "wireless.1.schedule_wed.0=0700-2200\nwireless.1.schedule_wed.1=0700-2200\n"
				.. "wireless.1.schedule_thu.0=0700-2200\nwireless.1.schedule_thu.1=0700-2200\n"
				.. "wireless.1.schedule_fri.0=0700-2200\nwireless.1.schedule_fri.1=0700-2200\n"
				.. "wireless.1.schedule_sat.0=0700-1300\nwireless.1.schedule_sat.1=1400-1530\n"
				.. "wireless.1.schedule_sat.2=1600-2359\n"
			local off_blob = base .. "wireless.1.schedule_enabled=disabled\n"
			local function iface()
				for _, sec in pairs(db.wireless or {}) do
					if sec[".type"] == "wifi-iface" and sec.ssid == "net" then return sec end
				end
			end

			local rt, vt = inform._parse_wifi_system_cfg(on_blob)
			assert_eq(#vt[1].schedule_lines, 14, "seven days, fourteen lines")
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(iface().openuf_schedule, "0=00:00-23:59 1=00:00-22:00 1=00:00-22:00 "
				.. "2=07:00-22:00 2=07:00-22:00 3=07:00-22:00 3=07:00-22:00 4=07:00-22:00 "
				.. "4=07:00-22:00 5=07:00-22:00 5=07:00-22:00 6=07:00-13:00 6=14:00-15:30 "
				.. "6=16:00-23:59", "push 1: stored")

			rt, vt = inform._parse_wifi_system_cfg(off_blob)
			assert_eq(vt[1].schedule_lines, false, "push 2: no schedule")
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_nil(iface().openuf_schedule, "push 2: removed")
		end
	},
	{
		name = "inform packet: _sched_resync follows the schedule once the clock is trusted, with a ledger",
		fn = function()
			local ws = inform._wlansched
			local orig = {uci = inform._ucihelper, time = inform._time, save = inform._state.save,
				ct = inform._clock_trusted, exec = ws._exec, read = ws._read_file, popen = ws._popen}
			ws._popen = function() return "OK\n" end
			local links = {["phy0-ap1"] = true}
			ws._read_file = function(p)
				local n = p:match("^/sys/class/net/(.-)/flags$")
				if links[n] == nil then return nil end
				return links[n] and "0x1003\n" or "0x1002\n"
			end
			ws._exec = function(c)
				local n, how = c:match("^ip link set dev (%S+) (%a+)")
				links[n] = (how == "up")
				return 0
			end
			local lines = {"0=00:00-23:59", "1=00:00-22:00", "2=07:00-22:00", "3=07:00-22:00",
				"4=07:00-22:00", "5=07:00-22:00", "6=07:00-23:59"}
			local vaps = {{ifnames = {"phy0-ap1"}, lines = lines}}
			inform._ucihelper = {schedule_vaps = function() return vaps end}
			local trusted = false
			inform._clock_trusted = function() return trusted end
			local saves = 0
			inform._state.save = function() saves = saves + 1 end
			-- 2026-10-12 is a Monday; os.time and os.date both use local time.
			local now
			inform._time = function() return now end
			local mon_2300 = os.time({year = 2026, month = 10, day = 12, hour = 23, min = 0})
			local tue_0700 = os.time({year = 2026, month = 10, day = 13, hour = 7, min = 0})
			local ok, err = pcall(function()
				local st = {}
				now = mon_2300
				local log = with_stderr(function() assert_false(inform._sched_resync(st), "clock unknown") end)
				assert_true(links["phy0-ap1"], "unknown clock: left up")
				assert_eq(log, "", "quiet")
				trusted = true
				-- Monday 06:00 is inside Monday's 00:00-22:00 but outside
				-- Tuesday's 07:00-22:00: pins the weekday (os.date's wday is 1-based).
				now = os.time({year = 2026, month = 10, day = 12, hour = 6, min = 0})
				assert_false(inform._sched_resync(st), "Monday 06:00: on-time, nothing to do")
				assert_true(links["phy0-ap1"], "still up")
				now = mon_2300
				log = with_stderr(function() assert_true(inform._sched_resync(st), "changed") end)
				assert_false(links["phy0-ap1"], "Monday 23:00: down")
				assert_eq(table.concat(st.sched_vaps_down, " "), "phy0-ap1", "ledger")
				assert_eq(saves, 1, "saved")
				assert_true(log:find("down: phy0-ap1", 1, true) ~= nil, "said so")
				assert_false(inform._sched_resync(st), "again: nothing")
				assert_eq(saves, 1, "nothing saved")
				now = tue_0700
				log = with_stderr(function() assert_true(inform._sched_resync(st), "changed") end)
				assert_true(links["phy0-ap1"], "Tuesday 07:00: up")
				assert_nil(st.sched_vaps_down, "ledger cleared")
				assert_eq(saves, 2, "saved")
				assert_true(log:find("up: phy0-ap1", 1, true) ~= nil, "said so")

				-- selfrun_guest_mode=off holds it too: the schedule's end leaves it down.
				now = mon_2300
				with_stderr(function() inform._sched_resync(st) end)
				st.guest_vaps_down = {"phy0-ap1"}
				now = tue_0700
				with_stderr(function() inform._sched_resync(st) end)
				assert_false(links["phy0-ap1"], "selfrun still holds it")
				assert_nil(st.sched_vaps_down, "but the schedule no longer does")
				st.guest_vaps_down = nil

				-- The schedule removed while it held a WLAN down: brought back up.
				now = mon_2300
				links["phy0-ap1"] = true
				with_stderr(function() inform._sched_resync(st) end)
				assert_false(links["phy0-ap1"], "down")
				vaps = {}
				with_stderr(function() inform._sched_resync(st) end)
				assert_true(links["phy0-ap1"], "no schedule any more: up")
				assert_nil(st.sched_vaps_down, "ledger cleared")
				local n = saves
				assert_false(inform._sched_resync(st), "no schedule, no ledger: nothing")
				assert_eq(saves, n, "nothing saved")
			end)
			inform._ucihelper, inform._time, inform._state.save, inform._clock_trusted =
				orig.uci, orig.time, orig.save, orig.ct
			ws._exec, ws._read_file, ws._popen = orig.exec, orig.read, orig.popen
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: the clock is trusted once the controller's time agrees, via a /var/run mark",
		fn = function()
			local orig = {time = inform._time, read = inform._read_file, touch = inform._touch}
			local files = {}
			inform._read_file = function(p) return files[p] end
			inform._touch = function(p) files[p] = "" end
			inform._time = function() return 1791664111 end
			inform._clock_ok = false
			local ok, err = pcall(function()
				assert_false(inform._clock_trusted(), "no mark yet")
				inform._note_server_time({server_time_in_utc = "1791660000000"})
				assert_false(inform._clock_trusted(), "68 minutes apart: not trusted")
				inform._note_server_time({})
				assert_false(inform._clock_trusted(), "no server time: not trusted")
				inform._note_server_time({server_time_in_utc = "1791664106669"})
				assert_true(inform._clock_trusted(), "5 s apart: trusted")
				assert_eq(files[inform.CLOCK_OK_FILE], "", "marked")
				-- A restart of openUF (not a reboot) finds the mark.
				inform._clock_ok = false
				assert_true(inform._clock_trusted(), "after a restart")
				files = {}
				inform._clock_ok = false
				assert_false(inform._clock_trusted(), "after a reboot: unknown again")
			end)
			inform._time, inform._read_file, inform._touch = orig.time, orig.read, orig.touch
			inform._clock_ok = false
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: handle_response notes the controller's clock",
		fn = function()
			local orig = inform._note_server_time
			local seen
			inform._note_server_time = function(resp) seen = resp.server_time_in_utc end
			local ok, err = pcall(function()
				inform.handle_response('{"_type":"noop","interval":10,"server_time_in_utc":"1791664106669"}',
					sample_state(), nil)
			end)
			inform._note_server_time = orig
			if not ok then error(err, 0) end
			assert_eq(seen, "1791664106669", "passed on")
		end
	},
	{
		name = "inform packet: selfrun's return leaves a WLAN its blackout schedule holds down",
		fn = function()
			local orig = {ws = inform._wlansched, save = inform._state.save}
			local ups = {}
			inform._wlansched = setmetatable({
				set_bss = function(n, up) if up then ups[#ups + 1] = n end return true end,
				is_up = function() return false end,
			}, {__index = orig.ws})
			inform._state.save = function() end
			inform._inform_fails, inform._guest_selfrun_on = 0, false
			local ok, err = pcall(function()
				local st = {guest_portal = {enabled = true}, guest_selfrun = "off",
					guest_vaps_down = {"phy0-ap1", "phy1-ap1"}, sched_vaps_down = {"phy1-ap1"}}
				with_stderr(function() inform._guest_selfrun(st, true) end)
				assert_eq(table.concat(ups, " "), "phy0-ap1", "only the one the schedule does not hold")
				assert_nil(st.guest_vaps_down, "selfrun's ledger cleared")
				assert_eq(table.concat(st.sched_vaps_down, " "), "phy1-ap1", "the schedule's kept")
			end)
			inform._wlansched, inform._state.save = orig.ws, orig.save
			inform._inform_fails, inform._guest_selfrun_on = 0, false
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: selfrun's return retries a guest WLAN whose beacon did not restart",
		fn = function()
			local orig = {ws = inform._wlansched, save = inform._state.save}
			local link = {["phy0-ap1"] = false, ["phy1-ap1"] = false, ["phy0-ap2"] = true}
			local beacon_ok, tried = {["phy0-ap1"] = true, ["phy1-ap1"] = false}, {}
			inform._wlansched = setmetatable({
				set_bss = function(n, up)
					tried[#tried + 1] = n
					if up and beacon_ok[n] then link[n] = true return true end
					return false
				end,
				is_up = function(n) return link[n] end,
			}, {__index = orig.ws})
			local saves = 0
			inform._state.save = function() saves = saves + 1 end
			inform._inform_fails, inform._guest_selfrun_on = 0, false
			local ok, err = pcall(function()
				local st = {guest_portal = {enabled = true}, guest_selfrun = "off",
					guest_vaps_down = {"phy0-ap1", "phy1-ap1", "phy0-ap2", "gone0"}}
				local log = with_stderr(function() assert_true(inform._guest_selfrun(st, true), "changed") end)
				assert_eq(table.concat(tried, " "), "phy0-ap1 phy1-ap1", "only the ones still down")
				assert_eq(table.concat(st.guest_vaps_down, " "), "phy1-ap1", "the failure stays in the ledger")
				assert_eq(saves, 1, "saved")
				assert_true(log:find("back up (phy0-ap1)", 1, true) ~= nil, "said what came up")
				assert_true(log:find("on the air (phy1-ap1)", 1, true) ~= nil, "said what did not")
				tried = {}
				log = with_stderr(function() inform._guest_selfrun(st, true) end)
				assert_eq(table.concat(tried, " "), "phy1-ap1", "retried")
				assert_nil(log:find("on the air", 1, true), "said once, not on every retry")
				tried, beacon_ok["phy1-ap1"] = {}, true
				with_stderr(function() inform._guest_selfrun(st, true) end)
				assert_eq(table.concat(tried, " "), "phy1-ap1", "the next answer retries it")
				assert_nil(st.guest_vaps_down, "then the ledger is gone")
				tried = {}
				with_stderr(function() inform._guest_selfrun(st, true) end)
				assert_eq(#tried, 0, "and nothing more is done")
			end)
			inform._wlansched, inform._state.save = orig.ws, orig.save
			inform._inform_fails, inform._guest_selfrun_on = 0, false
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform packet: every heartbeat runs the schedule check",
		fn = function()
			local orig = {sr = inform._sched_resync, rl = inform._reload_if_changed, rrm = inform._rrm_tick,
				bj = inform.build_json}
			local ran = 0
			inform._sched_resync = function() ran = ran + 1 end
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() error("stop here") end
			local ok, err = pcall(function()
				with_stderr(function() inform._tick({}, nil, nil, {interval = 10}) end)
			end)
			inform._sched_resync, inform._reload_if_changed, inform._rrm_tick, inform.build_json =
				orig.sr, orig.rl, orig.rrm, orig.bj
			if not ok then error(err, 0) end
			assert_eq(ran, 1, "before build_json")
		end
	},
	{
		name = "inform packet: every heartbeat applies the speed limits after build_json, not without it",
		fn = function()
			local orig = {sh = inform._shaper_resync, rl = inform._reload_if_changed, rrm = inform._rrm_tick,
				bj = inform.build_json, bp = inform.build_packet}
			local order = {}
			inform._shaper_resync = function() order[#order + 1] = "shaper" end
			inform._reload_if_changed = function(_, _, last) return last end
			inform._rrm_tick = function() return false end
			inform.build_json = function() order[#order + 1] = "build_json"; return "{}" end
			inform.build_packet = function() error("stop here") end
			local ok, err = pcall(function()
				with_stderr(function() inform._tick({}, nil, nil, {interval = 10}) end)
				assert_eq(table.concat(order, ","), "build_json,shaper", "on the stations it just listed")
				order = {}
				inform.build_json = function() error("no payload") end
				with_stderr(function() inform._tick({}, nil, nil, {interval = 10}) end)
				assert_eq(#order, 0, "no fresh listing: nothing applied")
			end)
			inform._shaper_resync, inform._reload_if_changed, inform._rrm_tick, inform.build_json,
				inform.build_packet = orig.sh, orig.rl, orig.rrm, orig.bj, orig.bp
			if not ok then error(err, 0) end
		end
	},
	{
		name = "net push: IP Settings, DNS order and the controller's hostname out of one blob",
		fn = function()
			local net = inform._parse_net_system_cfg(table.concat({
				"netconf.1.ip=192.0.2.7",
				"netconf.1.netmask=255.255.255.0",
				"route.1.gateway=192.0.2.1",
				"dhcpc.1.status=disabled",
				-- Deliberately out of wire order: resolv.conf's order is the
				-- resolver's preference order, so the index decides, not the
				-- line position.
				"resolv.nameserver.2.ip=192.0.2.3",
				"resolv.nameserver.1.ip=192.0.2.2",
				"resolv.nameserver.3.ip=",
				"resolv.host.1.name=U6IW",
			}, "\n"))
			assert_eq(net.ip, "192.0.2.7", "static address")
			assert_eq(net.netmask, "255.255.255.0", "netmask")
			assert_eq(net.gateway, "192.0.2.1", "gateway")
			assert_false(net.dhcp, "dhcpc.1.status=disabled is NOT DHCP")
			assert_eq(net.device_name, "U6IW", "controller-assigned hostname")
			assert_eq(table.concat(net.dns, ","), "192.0.2.2,192.0.2.3",
				"sorted by wire index, the empty one dropped")
		end
	},
	{
		name = "net push: a DHCP push and a blob with none of these keys",
		fn = function()
			local dh = inform._parse_net_system_cfg("dhcpc.1.status=enabled\nnetconf.1.ip=192.0.2.7")
			assert_true(dh.dhcp, "enabled means DHCP")
			local empty = inform._parse_net_system_cfg("wireless.1.ssid=x")
			assert_nil(empty.ip, "no address pushed")
			assert_false(empty.dhcp, "absent dhcpc.1.status is not DHCP")
			assert_eq(#empty.dns, 0, "no nameservers")
			-- Called on every system_cfg, including the degenerate ones.
			assert_eq(#inform._parse_net_system_cfg(nil).dns, 0, "nil blob is a table, not an error")
		end
	},
	{
		name = "cfg-coverage: a replay sorts a push into consumed / inert / ignored",
		fn = function()
			local report = cfgcov.analyse(table.concat({
				"# no wlan provisioned as no radio found",
				"radio.1.phyname=wifi0",
				"radio.1.channel=36",
				"",
				"wireless.1.devname=ath0",
				"wireless.1.parent=wifi0",
				"wireless.1.ssid=openuf-test",
				"wireless.1.status=enabled",
				-- Claimed by `^wireless%.%d+%.` yet read by nothing: the
				-- MAC-filter decoy from PROTOCOL-VALIDATION.md.
				"wireless.1.mac_acl.policy=deny",
				"unifi.version=10.6.106",
				"",
			}, "\n"), real_parsers(), inform.RECOGNIZED_SYSTEM_CFG)

			local function bucket(key)
				for _, name in ipairs({"consumed", "inert", "ignored"}) do
					for _, row in ipairs(report[name]) do
						if row.key == key then return name end
					end
				end
				return "(absent)"
			end
			assert_eq(bucket("wireless.1.ssid"), "consumed", "the SSID reaches a VAP")
			assert_eq(bucket("radio.1.channel"), "consumed", "the channel reaches a radio")
			assert_eq(bucket("wireless.1.mac_acl.policy"), "inert",
				"recognized by prefix, read by nothing")
			assert_eq(bucket("unifi.version"), "ignored", "neither claimed nor read")
			assert_eq(report.lines, 8, "key=value lines")
			-- The comment and the interior blank. The trailing newline's empty
			-- element is dropped rather than counted.
			assert_eq(report.blanks, 2, "the comment and the blank line")
		end
	},
	{
		name = "cfg-coverage: mutating the value catches a key a fallback hides from deletion",
		fn = function()
			-- radio.<n>.countrycode falls back to the unindexed
			-- radio.countrycode, so DELETING either leaves the regdomain
			-- unchanged and a deletion-only sweep reports both as unread.
			-- Modelled here as a parser with exactly that fallback, so the
			-- probe design is pinned rather than one controller's capture.
			local parsers = {{"fallback", function(blob)
				return blob:match("\na%.1%.k=([%w_]+)") or blob:match("\na%.k=([%w_]+)")
			end}}
			local blob = "\na.1.k=203\na.k=203"
			local report = cfgcov.analyse(blob, parsers, {})
			local verdict = {}
			for _, name in ipairs({"consumed", "inert", "ignored"}) do
				for _, row in ipairs(report[name]) do verdict[row.key] = name end
			end
			assert_eq(verdict["a.1.k"], "consumed", "the indexed key is read, fallback or not")
			-- The unindexed one genuinely cannot be observed while the indexed
			-- one shadows it -- the honest verdict, and why the sweep needs two
			-- captures across a toggle rather than one.
			assert_eq(verdict["a.k"], "ignored", "shadowed: no probe can move the output")
		end
	},
	{
		name = "cfg-coverage: a report never prints a pushed secret",
		fn = function()
			local parsers = {{"none", function() return nil end}}
			local report = cfgcov.analyse(table.concat({
				"aaa.1.wpa.psk=letmeinnow",
				"aaa.1.radius.auth.1.secret=letmeinnow",
				"aaa.1.iapp_key=letmeinnow",
				"authkey=letmeinnow",
				"aaa.1.ssid=openuf-test",
			}, "\n"), parsers, {})
			local out = cfgcov.format(report, {values = true})
			assert_nil(out:find("letmeinnow", 1, true), "no secret in the report")
			assert_true(out:find("openuf%-test") ~= nil, "a non-secret value still prints")
			assert_true(out:find("<redacted>") ~= nil, "and says it was redacted")
		end
	},
	{
		name = "inform packet: dfs-reset only moves a 5 GHz radio that is off its pinned channel",
		fn = function()
			local orig = {
				uci = inform._ucihelper, si = inform._sysinfo,
				run = inform._run_cmd, read = inform._read_file,
				time = inform._time, stderr = io.stderr,
			}
			local said, cmds, request = "", {}, nil
			io.stderr = {write = function(_, s) said = said .. s end}
			-- The AX3000T's own layout: 2.4 on radio0, the DFS 5 GHz on radio1.
			local live, width, nol = 36, 80, nil
			inform._ucihelper = {
				get_radio_table = function()
					return {
						{name = "radio0", radio = "ng", channel = 11},
						{name = "radio1", radio = "na", channel = 100},
					}
				end,
				get_ifname_for_radio = function(r)
					return r == "radio0" and "phy0-ap0" or "phy1-ap0"
				end,
			}
			inform._sysinfo = {
				radio_caps = function(ifname)
					if ifname == "phy1-ap0" then return {channel = live, width = width} end
					-- The 2.4 radio is deliberately off ITS pinned channel
					-- too (1, configured 11): the only thing keeping it out
					-- of this job is the band gate.
					return {channel = 1, width = 20}
				end,
				phy_channels = function()
					return "\t* 5500 MHz [100] \n\t  Radar detection\n\t  DFS state: "
						.. (nol and "unavailable (for 1766 sec)" or "available (for 86400 sec)")
						.. "\n"
				end,
			}
			inform._run_cmd = function(c) cmds[#cmds + 1] = c; return "OK\n" end
			inform._read_file = function(p)
				if p == inform.DFS_RESET_REQUEST_FILE then return request end
				return nil
			end
			inform._time = function() return 1000000 end

			local ok, err = pcall(function()
				-- No request: nothing is read, nothing runs.
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "no request, no work")
				assert_eq(#cmds, 0, "and no command")

				-- Off its channel, the channel is free: one CSA, on the 5 GHz
				-- radio only. The 2.4 radio is never even looked at -- no band
				-- but 5 GHz has DFS.
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 1, "one radio moved")
				assert_eq(#cmds, 1, "one command")
				assert_contains(cmds[1], "hostapd_cli -i phy1-ap0 chan_switch 5 "
					.. "5500 sec_channel_offset=1 center_freq1=5530 bandwidth=80 vht",
					"a CSA back to the configured channel, at the live width")
				assert_contains(said, "switching back from channel 36 to the configured 100",
					"and says what it did")
				assert_eq(said:find("phy0%-ap0"), nil,
					"the 2.4 radio is off its channel too and is still not touched")

				-- Already there: the firmware's own first check, and the state
				-- openUF is in on every night but the one after a radar hit.
				cmds, live = {}, 100
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "nothing to do")
				assert_eq(#cmds, 0, "no switch when the channel already agrees")

				-- Still on the non-occupancy list: wait, do not ask hostapd.
				-- This is the case that makes the NOL read worth doing --
				-- the kernel would refuse and the AP would have announced a
				-- switch it cannot complete.
				cmds, live, nol, said = {}, 36, true, ""
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "left alone")
				assert_eq(#cmds, 0, "no switch attempted")
				assert_contains(said, "still on the non-occupancy list",
					"and the reason is named")
				assert_contains(said, "another 1766 s", "with the time left")

				-- hostapd refusing is reported, not swallowed.
				cmds, nol, said = {}, nil, ""
				inform._run_cmd = function(c) cmds[#cmds + 1] = c; return "FAIL\n" end
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "not counted as moved")
				assert_contains(said, "hostapd refused the switch", "and is logged")
				inform._run_cmd = function(c) cmds[#cmds + 1] = c; return "OK\n" end

				-- A stale request (the daemon was down when crond fired) is
				-- dropped rather than acted on hours later.
				cmds, said = {}, ""
				request = tostring(1000000 - inform.DFS_RESET_MAX_AGE - 1) .. "\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "stale, ignored")
				assert_eq(#cmds, 0, "no switch")
				assert_contains(said, "stale dfs-reset request", "and says so")

				-- An unpinned radio is left to the driver: "auto" is the
				-- controller's intent, not a channel to return to. Silently:
				-- every site that lets the controller pick a channel is in
				-- this case, and it is not a problem to report.
				cmds, said = {}, ""
				inform._ucihelper.get_radio_table = function()
					return {{name = "radio1", radio = "na", channel = "auto"}}
				end
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "auto is not pinned")
				assert_eq(#cmds, 0, "no switch")
				assert_eq(said, "", "and nothing logged")
				-- Asserted on the reason, not just the silence: "auto" has to
				-- be refused before anything reads the radio, or the live
				-- channel gets compared against nothing.
				local _, why = inform._dfs_reset_radio({channel = "auto"}, "phy1-ap0")
				assert_eq(why, "channel is not pinned", "and refused up front")

				-- A radio the controller turned off is not woken up.
				cmds, said = {}, ""
				inform._ucihelper.get_radio_table = function()
					return {{name = "radio1", radio = "na", channel = 100, disabled = true}}
				end
				request = "1000000\n"
				assert_eq(inform._maybe_service_dfs_reset({}), 0, "a disabled radio is skipped")
				assert_eq(#cmds, 0, "no switch")
			end)
			inform._ucihelper, inform._sysinfo = orig.uci, orig.si
			inform._run_cmd, inform._read_file = orig.run, orig.read
			inform._time, io.stderr = orig.time, orig.stderr
			if not ok then error(err, 0) end
		end
	},
}
