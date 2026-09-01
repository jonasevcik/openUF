-- Tests for openuf/inform.lua (TNBU binary packet framing).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
dofile("openuf/lib/lib.lua")	-- needed by announce (loaded by inform)

local crypto = dofile("openuf/crypto.lua")
local state  = dofile("openuf/state.lua")
local inform = dofile("openuf/inform.lua")

-- Redirect state file to /tmp so handle_response tests don't need /etc/openuf
inform._state._state_file = "/tmp/openuf_test_inform.json"

-- Stub firewall by default so tests don't shell out to real nft/hostapd_cli;
-- individual block-sta/unblock-sta tests below override this to capture calls.
inform._firewall = {
	reconcile = function() end,
	deauth = function() end,
}

-- Deterministic IV for the TEST FILE's own crypto instance -- affects only
-- tests that call crypto.* directly (e.g. the zlib round-trip). inform's
-- packet paths use inform._crypto, a SEPARATE instance: tests that need a
-- pinned IV inside build_packet must stub inform._crypto._random_bytes
-- (see "different authkeys produce different ciphertext").
local FIXED_IV = string.rep("\0", 16)
crypto._random_bytes = function(n) return string.rep("\0", n) end

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
		name = "inform packet: _parse_wifi_system_cfg skips WPA-Enterprise WLANs",
		fn = function()
			-- An Enterprise WLAN carries mgmt=WPA-EAP and NO wpa.psk. Before
			-- this guard it matched neither the SAE nor the PSK branch and fell
			-- through to security="wpa2", producing a psk2 section with a nil
			-- key -- a VAP hostapd refuses to bring up, silently. openUF has no
			-- RADIUS configuration on this wire protocol, so the only honest
			-- outcome is to drop the WLAN and say so.
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

			rt, vt = inform._parse_wifi_system_cfg(off_blob)
			ucihelper.apply_config({radio_table = rt, vap_table = vt}, nil)
			assert_eq(db.wireless.radio0.minrssi_enabled, "0",
				"push 2 (stamgr absent): enforcement flag explicitly cleared")
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
			-- reporting an error. Bracket syntax, not a dotted key.
			local s = db.wireless and db.wireless["openuf_radio0_openuf_test"]
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
		name = "inform packet: _parse_wifi_system_cfg parses aaa.<n>.sae.anti_clogging/sae.sync (WPA3-SAE tuning)",
		fn = function()
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\naaa.1.sae.anti_clogging=12\naaa.1.sae.sync=20\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].sae_anti_clogging, 12, "sae.anti_clogging parsed as a number")
			assert_eq(vap_table[1].sae_sync, 20, "sae.sync parsed as a number")
		end
	},
	{
		name = "inform packet: _parse_wifi_system_cfg leaves sae_anti_clogging/sae_sync nil when absent",
		fn = function()
			-- Real controller behavior: these keys are only ever emitted
			-- when the WLAN is actually in WPA3/SAE mode (or 6GHz) --
			-- absent for a plain WPA2 or WPA2/WPA3-mixed WLAN even with a
			-- non-default admin value saved server-side (confirmed live).
			local sys_cfg = "aaa.1.ssid=openuf-test\naaa.1.wpa=2\n"
				.. "wireless.1.ssid=openuf-test\nwireless.1.parent=radio0\n"
			local _, vap_table = inform._parse_wifi_system_cfg(sys_cfg)
			assert_eq(vap_table[1].sae_anti_clogging, nil, "no sae.anti_clogging key -> nil")
			assert_eq(vap_table[1].sae_sync, nil, "no sae.sync key -> nil")
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
			local reconciled, deauthed
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function(mac, ifnames) deauthed = {mac = mac, ifnames = ifnames} end,
			}
			inform._ucihelper = {
				get_radio_table = function() return {{name = "radio0"}, {name = "radio1"}} end,
				get_ifname_for_radio = function(name)
					if name == "radio0" then return "wlan0" end
					if name == "radio1" then return "wlan1" end
					return nil
				end,
			}
			local result = inform.handle_response(
				'{"_type":"cmd","cmd":"block-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			inform._ucihelper = nil
			assert_eq(#st.blocked_stas, 1, "one MAC persisted")
			assert_eq(st.blocked_stas[1], "aa:bb:cc:dd:ee:01", "correct MAC persisted")
			assert_eq(#reconciled, 1, "reconcile called with the updated list")
			assert_eq(reconciled[1], "aa:bb:cc:dd:ee:01", "reconcile sees the newly blocked MAC")
			assert_eq(deauthed.mac, "aa:bb:cc:dd:ee:01", "deauth targets the blocked MAC")
			assert_eq(#deauthed.ifnames, 2, "deauth issued across every configured radio")
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
			local reconciled
			inform._firewall = {
				reconcile = function(macs) reconciled = macs end,
				deauth = function() end,
			}
			local result = inform.handle_response(
				'{"_type":"cmd","cmd":"unblock-sta","mac":"aa:bb:cc:dd:ee:01"}', st)
			inform._firewall = { reconcile = function() end, deauth = function() end }
			assert_eq(#st.blocked_stas, 1, "one MAC remains")
			assert_eq(st.blocked_stas[1], "aa:bb:cc:dd:ee:02", "the other MAC is untouched")
			assert_eq(#reconciled, 1, "reconcile called with the updated (shorter) list")
			assert_true(result, "re-inform immediately after executing a command")
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
			inform._ucihelper = {
				get_radio_table = function()
					return { { name = "radio0", channel = "6", ht = "HT40" } }
				end,
				get_ifname_for_radio = function() return "wlan0" end,
				_popen = function() return "" end,
			}
			inform._sysinfo.radio_stats = function()
				return {
					{ freq = 2437, noise = -95, channel_time = 5000, channel_time_busy = 1850 },
					{ freq = 2412, noise = -90, channel_time = 100,  channel_time_busy = 12 },
				}
			end

			local ok, err = pcall(function()
				local result = inform.handle_response('{"_type":"cmd","cmd":"spectrum-scan"}', st)
				assert_true(result, "re-inform immediately after executing a command")

				local cached = inform._spectrum_cache.radio0
				assert_true(cached ~= nil, "spectrum-scan cmd populates _spectrum_cache for the radio")
				assert_true(#cached.table == 2, "one spectrum_table entry per survey-dump frequency")
				assert_true(cached.table[1].channel == 6, "channel derived from 2437MHz")
				assert_true(cached.table[1].center_freq == 2437, "center_freq passed through from survey dump")
				assert_true(cached.table[1].width == 40, "width derived from radio's HT40 htmode")
				assert_true(cached.table[1].utilization == 37, "utilization = channel_time_busy/channel_time * 100")
				assert_true(cached.table[1].interference == -95, "interference is best-effort noise-floor passthrough")
			end)
			inform._ucihelper, inform._sysinfo.radio_stats = orig_uci, orig_stats
			inform._spectrum_cache = orig_cache
			if not ok then error(err, 0) end
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
					return { { name = "radio0", channel = "36", ht = "HT40" } }
				end,
				get_ifname_for_radio = function() return "wlan0" end,
				_popen = function(cmd)
					if tostring(cmd):match("scan") then scanned = true end
					return ""
				end,
			}
			inform._sysinfo.radio_stats = function()
				if not scanned then
					-- pre-sweep: the operating channel has a real noise floor
					return {
						{ freq = 5180, noise = -106, channel_time = 1000, channel_time_busy = 10 },
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
				inform.handle_response('{"_type":"cmd","cmd":"spectrum-scan"}', st)
				local t = inform._spectrum_cache.radio0.table
				assert_eq(t[1].interference, -106,
					"operating channel keeps its pre-sweep noise floor, not 0")
				assert_eq(t[1].utilization, 10,
					"utilization still comes from the fresh post-sweep counters")
				assert_eq(t[2].interference, -104,
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
		name = "inform: _state_mtime parses stat output as a number",
		fn = function()
			local orig = inform._run_cmd
			inform._run_cmd = function(cmd) return "1700000000\n" end
			local mtime = inform._state_mtime("/tmp/whatever")
			inform._run_cmd = orig
			assert_eq(mtime, 1700000000, "mtime parsed as number")
		end
	},
	{
		name = "inform: _state_mtime returns nil when stat yields no output",
		fn = function()
			local orig, orig_read = inform._run_cmd, inform._read_file
			inform._run_cmd = function(cmd) return "" end
			inform._read_file = function() return nil end
			local mtime = inform._state_mtime("/nonexistent")
			inform._run_cmd, inform._read_file = orig, orig_read
			assert_true(mtime == nil, "nil when file missing")
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
					"e8:de:27:5f:62:7a",
					{adopted = true, mac = "e8:de:27:5f:62:77"},
					{net = {lan_cpueth = "eth0"}})
				assert_true(warned, "warns")
			end)
			assert_contains(out, "IDENTITY MAC CHANGED", "names the problem")
			assert_contains(out, "e8:de:27:5f:62:7a", "the MAC it was adopted as")
			assert_contains(out, "e8:de:27:5f:62:77", "the MAC it now reports")
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
		name = "inform: _state_mtime falls back to file contents without stat",
		fn = function()
			-- BusyBox gates `stat -c` behind FEATURE_STAT_FORMAT and some
			-- builds ship no stat applet at all -- confirmed on a real
			-- TL-WDR3500 -- which silently disabled detection of an SSH
			-- set-adopt or a manual reset-inform until openUF restarted.
			local orig, orig_read = inform._run_cmd, inform._read_file
			inform._run_cmd = function() return "" end        -- no stat anywhere
			inform._read_file = function() return '{"adopted":false}' end
			local a = inform._state_mtime("/etc/openuf/state.json")
			inform._read_file = function() return '{"adopted":true}' end
			local b = inform._state_mtime("/etc/openuf/state.json")
			inform._run_cmd, inform._read_file = orig, orig_read
			assert_not_nil(a, "a token is produced without stat")
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
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._sync_bootstrap_account(true, "ubnt")
			inform._run_cmd = orig
			assert_eq(#calls, 1, "one command issued")
			assert_contains(calls[1], "passwd -l", "lock command issued")
			assert_contains(calls[1], "ubnt", "targets ubnt")
		end
	},
	{
		name = "inform: _sync_bootstrap_account unlocks the account when not adopted",
		fn = function()
			local calls = {}
			local orig = inform._run_cmd
			inform._run_cmd = function(cmd) calls[#calls + 1] = cmd; return "" end
			inform._sync_bootstrap_account(false, "ubnt")
			inform._run_cmd = orig
			assert_eq(#calls, 1, "one command issued")
			assert_contains(calls[1], "passwd -u", "unlock command issued")
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
}
