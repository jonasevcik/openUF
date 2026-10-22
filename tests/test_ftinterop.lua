-- Tests for openuf/ftinterop.lua (802.11r interop with genuine UniFi APs) and
-- its use in ucihelper.apply_config.
-- Run from project root: lua tests/run_tests.lua

local ftinterop = dofile("openuf/ftinterop.lua")
local ucihelper = dofile("openuf/ucihelper.lua")

local KEY   = "00112233445566778899aabbccddeeff"
local PEER1 = "00:00:5e:00:53:21"
local PEER2 = "00:00:5e:00:53:22"
local OWN   = "00:00:5e:00:53:2b"

-- Minimal read-only cursor over {config = {section = {option = value}}}.
local function ro_cursor(db)
	return {get = function(_, config, section, option)
		local s = db[config] and db[config][section]
		local v = s and s[option]
		if v == nil then return nil, "Entry not found" end
		return v
	end}
end

local function rrb_cfg(peers, ft_iface)
	return {["rrb-unifi"] = {main = {ft_peer = peers, ft_iface = ft_iface}}}
end

-- Run fn with ftinterop's seams stubbed: sysfs answers for the netdevs in
-- `present`, and log lines are collected instead of printed.
local function with_ftinterop(present, fn)
	local orig_read, orig_log = ftinterop._read_file, ftinterop._log
	local logged = {}
	ftinterop._read_file = function(path)
		local ifn = path:match("^/sys/class/net/([^/]+)/ifindex$")
		return (ifn and present[ifn]) and "9\n" or nil
	end
	ftinterop._log = function(msg) logged[#logged + 1] = msg end
	local ok, err = pcall(fn, logged)
	ftinterop._read_file, ftinterop._log = orig_read, orig_log
	if not ok then error(err, 0) end
end

local DELETE = setmetatable({}, {__tostring = function() return "<delete>" end})

local function has_log(logged, text)
	for _, l in ipairs(logged) do
		if l:find(text, 1, true) then return true end
	end
	return false
end

return {
	{
		name = "ftinterop: sha1 matches the FIPS 180 test vectors",
		fn = function()
			assert_eq(ftinterop.sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "empty")
			assert_eq(ftinterop.sha1("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d", "abc")
			-- 56 bytes: the padding spills into a second block.
			assert_eq(ftinterop.sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
				"84983e441c3bd26ebaae4aa1f95129e5e54670f1", "two-block message")
			assert_eq(ftinterop.sha1(string.rep("a", 1000)),
				"291e9a6c66994949b57ba5e650361e98fc36b1ba", "1000 x a")
		end
	},
	{
		name = "ftinterop: the mobility domain is UniFi firmware's, not openUF's",
		fn = function()
			-- The derivation was checked against a live U7 Lite's (UniFi
			-- 8.7.11) hostapd config; "corp" -> 5de5 is the same formula.
			assert_eq(ftinterop.mobility_domain("corp"), "5de5", "UniFi's derivation")
			assert_neq(ftinterop.mobility_domain("corp"),
				ucihelper.derive_mobility_domain("corp"), "and differs from openUF's own")
			-- 32 bytes is the pad width; a 32-byte SSID gets no padding.
			assert_eq(#ftinterop.mobility_domain(string.rep("x", 32)), 4, "four hex chars")
		end
	},
	{
		name = "ftinterop: peers come from rrb-unifi's ft_peer list, malformed ones dropped",
		fn = function()
			with_ftinterop({}, function(logged)
				local p = ftinterop.peers(ro_cursor(rrb_cfg({
					PEER1:upper() .. ",00005e005321",
					"not-a-mac,00005e005399",
					PEER2 .. ", 00005e005322",
					PEER2 .. ",bad id;rm",
				})))
				assert_eq(#p, 2, "two valid peers")
				assert_eq(p[1].bssid, PEER1, "lowercased BSSID")
				assert_eq(p[1].r0kh_id, "00005e005321", "R0KH-ID")
				assert_eq(p[2].r0kh_id, "00005e005322", "spaces around the comma are fine")
				assert_true(has_log(logged, "not-a-mac"), "a malformed entry is logged")
			end)
			-- A single entry comes back from UCI as a string, not a list.
			local p = ftinterop.peers(ro_cursor(rrb_cfg(PEER1 .. ",00005e005321")))
			assert_eq(#p, 1, "single string entry")
			assert_eq(#ftinterop.peers(ro_cursor({})), 0, "no rrb-unifi config -> no peers")
			assert_eq(#ftinterop.peers(nil), 0, "no cursor -> no peers")
		end
	},
	{
		name = "ftinterop: ft_iface only when the translator's veth exists",
		fn = function()
			with_ftinterop({vft0 = true}, function()
				assert_eq(ftinterop.ft_iface(ro_cursor({})), "vft0", "default name, present")
				assert_nil(ftinterop.ft_iface(ro_cursor(rrb_cfg(nil, "vft7"))), "configured name, absent")
				assert_nil(ftinterop.ft_iface(ro_cursor(rrb_cfg(nil, "x;reboot"))), "unsafe name refused")
			end)
			with_ftinterop({}, function()
				assert_nil(ftinterop.ft_iface(ro_cursor({})), "no veth -> nil")
			end)
		end
	},
	{
		name = "ftinterop: apply reproduces the working U7 interop config",
		fn = function()
			with_ftinterop({vft0 = true}, function()
				local extra = {ieee80211r = "1", reassociation_deadline = "3000",
					pmk_r1_push = "1", ft_over_ds = "0"}
				ftinterop.apply(extra, {ssid = "corp", radio = "radio0", iapp_key = KEY},
					OWN:upper(), ro_cursor(rrb_cfg({
						PEER2 .. ",00005e005322", PEER1 .. ",00005e005321"})), DELETE)
				assert_eq(extra.mobility_domain, "5de5", "UniFi mobility domain")
				assert_eq(extra.ft_psk_generate_local, "0", "key holders, not local derivation")
				assert_eq(extra.reassociation_deadline, DELETE, "OpenWrt's default deadline")
				assert_eq(extra.nasid, "00005e00532b", "R0KH-ID = own BSSID")
				assert_eq(extra.pmk_r1_push, "1", "push untouched")
				assert_eq(#extra.r0kh, 3, "two peers + wildcard")
				assert_eq(extra.r0kh[1], PEER2 .. ",00005e005322," .. KEY, "peer order kept")
				assert_eq(extra.r0kh[2], PEER1 .. ",00005e005321," .. KEY, "second peer")
				assert_eq(extra.r0kh[3], "ff:ff:ff:ff:ff:ff,*," .. KEY, "wildcard last")
				assert_eq(extra.r1kh[1], PEER2 .. "," .. PEER2 .. "," .. KEY, "r1kh peer")
				assert_eq(extra.r1kh[3], "00:00:00:00:00:00,00:00:00:00:00:00," .. KEY,
					"r1kh wildcard")
				assert_eq(type(extra.hostapd_bss_options), "table", "list option")
				assert_eq(extra.hostapd_bss_options[1], "ft_iface=vft0", "hostapd on the veth")
			end)
		end
	},
	{
		name = "ftinterop: apply degrades without key, peers, BSSID or veth",
		fn = function()
			with_ftinterop({}, function(logged)
				local extra = {}
				ftinterop.apply(extra, {ssid = "corp", radio = "radio0"}, nil,
					ro_cursor({}), DELETE)
				assert_eq(extra.mobility_domain, "5de5", "mobility domain still set")
				assert_nil(extra.nasid, "no BSSID -> no nasid")
				assert_nil(extra.r0kh, "no key -> no key holders")
				assert_eq(extra.hostapd_bss_options, DELETE, "no veth -> option removed")
				assert_true(has_log(logged, "iapp_key"), "missing key logged")
				assert_true(has_log(logged, "BSSID not known"), "missing BSSID logged")
				assert_true(has_log(logged, "ft_iface not present"), "missing veth logged")
			end)
			with_ftinterop({vft0 = true}, function(logged)
				local extra = {}
				ftinterop.apply(extra, {ssid = "corp", radio = "radio0", iapp_key = KEY},
					OWN, ro_cursor({}), DELETE)
				assert_eq(#extra.r0kh, 1, "wildcard only")
				assert_true(has_log(logged, "no ft_peer"), "missing peers logged")
			end)
		end
	},
	{
		name = "ftinterop: apply_config uses it only when unifi_ft_interop is on",
		fn = function()
			-- Recording cursor shared by ucihelper (wireless) and ftinterop
			-- (rrb-unifi), as the real binding is.
			local db = {["rrb-unifi"] = {main = {[".type"] = "rrb",
				ft_peer = {PEER1 .. ",00005e005321"}}}}
			local cursor = {}
			function cursor:set(config, section, a, b)
				db[config] = db[config] or {}
				db[config][section] = db[config][section] or {[".name"] = section}
				if b == nil then db[config][section][".type"] = a
				else db[config][section][a] = b end
			end
			function cursor:get(config, section, option)
				local s = db[config] and db[config][section]
				local v = s and s[option]
				if v == nil then return nil, "Entry not found" end
				return v
			end
			function cursor:delete(config, section, option)
				if option then
					if db[config] and db[config][section] then db[config][section][option] = nil end
				elseif db[config] then db[config][section] = nil end
			end
			function cursor:foreach(config, stype, fn)
				for _, s in pairs(db[config] or {}) do
					if s[".type"] == stype then fn(s) end
				end
			end
			function cursor:commit() end

			local orig = {uci = ucihelper._uci, popen = ucihelper._popen,
				read = ucihelper._read_file, run = ucihelper._run_cmd,
				bcf = ucihelper._bcfilter, shaper = ucihelper._shaper,
				fti = ucihelper._ftinterop, vap = ucihelper.get_ifname_for_vap}
			local function restore()
				ucihelper._uci, ucihelper._popen = orig.uci, orig.popen
				ucihelper._read_file, ucihelper._run_cmd = orig.read, orig.run
				ucihelper._bcfilter, ucihelper._shaper = orig.bcf, orig.shaper
				ucihelper._ftinterop, ucihelper.get_ifname_for_vap = orig.fti, orig.vap
			end
			ucihelper._uci = {cursor = function() return cursor end}
			ucihelper._popen = function() return "" end
			ucihelper._read_file = function(path)
				if path == "/sys/class/net/phy0-ap0/address" then return OWN .. "\n" end
				return nil
			end
			ucihelper._run_cmd = function() return true end
			ucihelper._bcfilter = {reconcile = function() end}
			ucihelper._shaper = {reconcile = function() end}
			ucihelper._ftinterop = ftinterop
			ucihelper.get_ifname_for_vap = function(radio)
				return radio == "radio0" and "phy0-ap0" or nil
			end
			local resp = {radio_table = {}, vap_table = {
				{ssid = "corp", radio = "radio0", security = "wpa2",
				 x_passphrase = "hunter22", fast_roaming_enabled = true, iapp_key = KEY},
			}}
			local ok, err = pcall(function()
				with_ftinterop({vft0 = true}, function()
					ucihelper.apply_config(resp, {config = {unifi_ft_interop = true}})
					local s = db.wireless.openuf_radio0_corp
					assert_eq(s.ieee80211r, "1", "FT on")
					assert_eq(s.mobility_domain, "5de5", "UniFi mobility domain")
					assert_eq(s.ft_psk_generate_local, "0", "key holders")
					assert_eq(s.nasid, "00005e00532b", "nasid from the live netdev")
					assert_nil(s.reassociation_deadline, "OpenWrt's default deadline")
					assert_eq(s.r0kh[1], PEER1 .. ",00005e005321," .. KEY, "the peer")
					assert_eq(s.hostapd_bss_options[1], "ft_iface=vft0", "veth")

					db.wireless = nil
					ucihelper.apply_config(resp, {config = {}})
					s = db.wireless.openuf_radio0_corp
					assert_eq(s.mobility_domain, ucihelper.derive_mobility_domain("corp"),
						"off: openUF's own mobility domain")
					assert_eq(s.reassociation_deadline, "3000", "off: upstream deadline")
					assert_nil(s.ft_psk_generate_local, "off: left to OpenWrt")
					assert_nil(s.nasid, "off: no nasid")
					assert_nil(s.hostapd_bss_options, "off: no ft_iface")
					assert_eq(#s.r0kh, 1, "off: wildcard only")
				end)
			end)
			restore()
			if not ok then error(err, 0) end
		end
	},
}
