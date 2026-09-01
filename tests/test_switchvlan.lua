-- Tests for openuf/switchvlan.lua (per-port VLAN assignment, swconfig boards).
-- Run from project root: lua tests/run_tests.lua
--
-- In-memory mock UCI cursor, same shape as test_ucihelper.lua's plus the
-- cursor:get() switchvlan.lua needs for its no-op check.

local switchvlan = dofile("openuf/switchvlan.lua")

local function new_mock_uci()
	local db, order = {}, {}
	local cursor = {}

	function cursor:set(config, section, a, b)
		db[config] = db[config] or {}
		if not db[config][section] then
			db[config][section] = {[".name"] = section}
			order[config] = order[config] or {}
			order[config][#order[config] + 1] = section
		end
		if b == nil then db[config][section][".type"] = a
		else db[config][section][a] = b end
	end

	function cursor:get(config, section, key)
		local s = db[config] and db[config][section]
		local v = s and s[key]
		-- Real libuci returns (nil, "Entry not found") for a miss. Mirroring
		-- that matters: a caller writing tonumber(cursor:get(...)) without
		-- parens passes the message string as tonumber's base and throws on
		-- the very first run. A single-value mock made that unreachable in
		-- tests and it only surfaced on real hardware.
		if v == nil then return nil, "Entry not found" end
		return v
	end

	function cursor:foreach(config, stype, fn)
		for _, name in ipairs(order[config] or {}) do
			local s = db[config][name]
			if s and s[".type"] == stype then fn(s) end
		end
	end

	function cursor:delete(config, section)
		if db[config] then db[config][section] = nil end
		for i, name in ipairs(order[config] or {}) do
			if name == section then table.remove(order[config], i) break end
		end
	end

	-- Recorded, not applied -- the counter lets tests catch a dropped commit.
	local commits = {}
	function cursor:commit(config)
		commits[config] = (commits[config] or 0) + 1
	end

	return {mock = {cursor = function() return cursor end}, db = db, cursor = cursor,
		commits = commits}
end

-- A board with a real swconfig switch and a stock VLAN 1 section.
local function swconfig_board()
	local u = new_mock_uci()
	u.cursor:set("network", "sw0", "switch")
	u.cursor:set("network", "sw0", "name", "switch0")
	u.cursor:set("network", "stock_vlan1", "switch_vlan")
	u.cursor:set("network", "stock_vlan1", "vlan", "1")
	u.cursor:set("network", "stock_vlan1", "ports", "0t 1 2 3 4")
	return u
end

local CFG = {
	net  = {lan_vlanid = 1, ports = {
		{idx = 1, ifname = "eth0", uplink = true},
		{idx = 2, ifname = "eth1", swport = "lan1"},
	}},
	vlan = {cpu_lan = 0, cpu_wan = 6, ports = {lan1 = 1, lan2 = 2, lan3 = 3, lan4 = 4, wan = 5}},
}

-- Port 2 native VLAN 20, VLAN 1 excluded -- the live-captured C3 shape.
local function override()
	return {
		enabled = true,
		vlans   = {[1] = {mode = "untagged", enabled = true},
		           [20] = {mode = "tagged", enabled = true}},
		ports   = {[2] = {pvid = 20, vlans = {[1] = "exclude", [20] = "untagged"}}},
	}
end

-- A DSA board: no `config switch`, no `config bridge-vlan`, a br-lan device
-- section holding the four sockets, and the bridge a tagged SSID already
-- built for VLAN 10. Modelled on the Xiaomi AX3000T.
local function dsa_board()
	local u = new_mock_uci()
	u.cursor:set("network", "brlan", "device")
	u.cursor:set("network", "brlan", "type", "bridge")
	u.cursor:set("network", "brlan", "name", "br-lan")
	u.cursor:set("network", "brlan", "ports", {"lan2", "lan3", "lan4", "wan"})
	u.cursor:set("network", "openuf_brdev10", "device")
	u.cursor:set("network", "openuf_brdev10", "type", "bridge")
	u.cursor:set("network", "openuf_brdev10", "name", "br-openuf10")
	u.cursor:set("network", "openuf_brdev10", "ports", {"wan.10"})
	return u
end

local DSA_CFG = {
	net = {lan_name = "lan", lan_cpueth = "wan", lan_vlanid = 1, ports = {
		{idx = 1, ifname = "wan"},
		{idx = 2, ifname = "lan2"},
		{idx = 3, ifname = "lan3"},
		{idx = 4, ifname = "lan4"},
	}},
}

-- Port 3 (lan3) assigned native VLAN 10.
local function dsa_push(port_idx, vid)
	return {
		enabled = true,
		vlans   = {[vid] = {mode = "tagged", enabled = true}},
		ports   = {[port_idx] = {pvid = vid,
			vlans = {[1] = "exclude", [vid] = "untagged"}}},
	}
end

local function ports_of(u, section)
	local v = u.db.network[section].ports
	if type(v) == "string" then return {v} end
	return v or {}
end

local function joined(u, section)
	return table.concat(ports_of(u, section), ",")
end

local function with_capture(fn)
	local cmds = {}
	local orig = switchvlan._exec
	switchvlan._exec = function(c) cmds[#cmds + 1] = c return true end
	local ok, err = pcall(fn, cmds)
	switchvlan._exec = orig
	switchvlan._uci = nil
	if not ok then error(err, 0) end
end

local function silently(fn)
	local real = io.stderr
	io.stderr = {write = function() end}
	local ok, err = pcall(fn)
	io.stderr = real
	if not ok then error(err, 0) end
end

return {
	{
		name = "switchvlan: physical_port walks port_idx -> swport -> physical",
		fn = function()
			assert_eq(switchvlan.physical_port(CFG, 2), 1, "port_idx 2 is lan1, physical 1")
			assert_nil(switchvlan.physical_port(CFG, 1), "uplink port is never mappable")
			assert_nil(switchvlan.physical_port(CFG, 9), "unknown port_idx")
			assert_nil(switchvlan.physical_port({}, 2), "no dev.conf.vlan at all")
		end
	},
	{
		name = "switchvlan: build_ports renders swconfig membership syntax",
		fn = function()
			-- untagged -> bare number, tagged -> Nt, exclude -> omitted.
			-- The CPU port is always tagged in.
			assert_eq(switchvlan.build_ports(CFG, 20, {[2] = "untagged"}), "0t 1",
				"untagged member")
			assert_eq(switchvlan.build_ports(CFG, 20, {[2] = "tagged"}), "0t 1t",
				"tagged member")
			assert_nil(switchvlan.build_ports(CFG, 1, {[2] = "exclude"}),
				"a VLAN with only exclusions is not written at all")
		end
	},
	{
		name = "switchvlan: apply writes an openuf-prefixed section and reloads",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				assert_true(switchvlan.apply(override(), CFG, st), "apply reports a change")
				local sec = u.db.network.openuf_swvlan20
				assert_not_nil(sec, "openuf_swvlan20 section created")
				-- netifd on these builds has no `vid` option (confirmed with
				-- `strings /sbin/netifd`), so this value is both the table
				-- slot and the VLAN ID -- see vlan_table_size.
				assert_eq(sec.vlan, "20", "VLAN id written")
				assert_eq(sec.ports, "0t 1", "port 2 (physical 1) untagged, CPU tagged")
				assert_eq(sec.device, "switch0", "bound to the switch device")
				assert_eq(#cmds, 1, "one reload")
				assert_contains(cmds[1], "/etc/init.d/network reload", "reload, not restart")
			end)
		end
	},
	{
		name = "switchvlan: apply is idempotent -- no second commit or reload",
		fn = function()
			-- Every steady-state setparam re-carries this block. Reloading the
			-- network on each one would bounce the uplink every inform.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(override(), CFG, st)
				assert_eq(#cmds, 1, "first apply reloads")
				assert_eq(u.commits.network, 1, "first apply commits network")
				assert_false(switchvlan.apply(override(), CFG, st), "second apply is a no-op")
				assert_eq(#cmds, 1, "no second reload")
				assert_eq(u.commits.network, 1, "no second commit either")
			end)
		end
	},
	{
		name = "switchvlan: apply strips the moved port from the stock VLAN; restore puts it back",
		fn = function()
			-- The C3 override moves physical port 1 to native VLAN 20 and
			-- excludes it from VLAN 1. swconfig allows ONE untagged VLAN per
			-- port, so the port must leave stock VLAN 1's list -- before the
			-- fix it stayed untagged in both sections (invalid config, the
			-- port move could not work) and restore()'s stock-rewrite branch
			-- was dead code, with this very test pinning the broken state.
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(override(), CFG, st)
				assert_eq(st.swvlan_backup["1"], "0t 1 2 3 4",
					"stock VLAN 1 snapshotted BEFORE the strip")
				assert_eq(u.db.network.stock_vlan1.ports, "0t 2 3 4",
					"moved port removed from the stock VLAN's list")
				assert_eq(u.db.network.openuf_swvlan20.ports, "0t 1",
					"port untagged in its new VLAN")

				assert_true(switchvlan.restore(st), "restore reports a change")
				assert_nil(u.db.network.openuf_swvlan20, "openUF's section removed")
				assert_eq(u.db.network.stock_vlan1.ports, "0t 1 2 3 4",
					"stock ports restored from the ledger (branch finally live)")
				assert_nil(st.swvlan_backup, "ledger cleared")
			end)
		end
	},
	{
		name = "switchvlan: exclude drops a tagged stock membership even without a new untagged home",
		fn = function()
			-- "Block All" on a tagged VLAN: the port keeps its untagged home
			-- in VLAN 1, so dropping the tagged membership strands nothing.
			with_capture(function(cmds)
				local u = swconfig_board()
				u.cursor:set("network", "stock_vlan30", "switch_vlan")
				u.cursor:set("network", "stock_vlan30", "vlan", "30")
				u.cursor:set("network", "stock_vlan30", "ports", "0t 1t 2t")
				switchvlan._uci = u.mock
				local sw = {enabled = true,
					vlans = {[30] = {mode = "tagged", enabled = true}},
					ports = {[2] = {vlans = {[30] = "exclude"}}}}
				assert_true(switchvlan.apply(sw, CFG, {}), "strip reports a change")
				assert_eq(u.db.network.stock_vlan30.ports, "0t 2t",
					"tagged membership dropped on exclude")
				assert_eq(u.db.network.stock_vlan1.ports, "0t 1 2 3 4",
					"untagged home untouched")
				assert_eq(#cmds, 1, "one reload")
			end)
		end
	},
	{
		name = "switchvlan: an untagged membership is never stripped without a new untagged home",
		fn = function()
			-- exclude from the port's ONLY untagged VLAN, with no new home in
			-- the push: honoring it would leave the port untagged nowhere.
			-- Refuse rather than strand.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local sw = {enabled = true,
					vlans = {[1] = {mode = "untagged", enabled = true}},
					ports = {[2] = {vlans = {[1] = "exclude"}}}}
				assert_false(switchvlan.apply(sw, CFG, {}), "nothing to change")
				assert_eq(u.db.network.stock_vlan1.ports, "0t 1 2 3 4",
					"homeless exclude leaves the untagged membership alone")
				assert_eq(#cmds, 0, "no reload")
			end)
		end
	},
	{
		name = "switchvlan: the management VLAN keeps its last downstream port",
		fn = function()
			-- A one-port board: stripping the sole downstream port off the
			-- management VLAN would cut the switch off the network even
			-- though the port has a new untagged home.
			with_capture(function()
				local u = new_mock_uci()
				u.cursor:set("network", "sw0", "switch")
				u.cursor:set("network", "sw0", "name", "switch0")
				u.cursor:set("network", "stock_vlan1", "switch_vlan")
				u.cursor:set("network", "stock_vlan1", "vlan", "1")
				u.cursor:set("network", "stock_vlan1", "ports", "0t 1")
				switchvlan._uci = u.mock
				silently(function()
					switchvlan.apply(override(), CFG, {})
				end)
				assert_eq(u.db.network.stock_vlan1.ports, "0t 1",
					"management VLAN strip refused, not applied")
				assert_eq(u.db.network.openuf_swvlan20.ports, "0t 1",
					"the new VLAN section is still written")
			end)
		end
	},
	{
		name = "switchvlan: apply deletes an orphaned openuf_swvlan section when its VLAN leaves the wire",
		fn = function()
			-- Removing a per-port override in the controller drops the port's
			-- keys from the wire (the C4 capture shape) while the feature
			-- stays enabled. Before the fix the push early-returned on "no
			-- overrides" and the orphan section kept programming VLAN 20.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(override(), CFG, st)
				assert_not_nil(u.db.network.openuf_swvlan20, "section exists after the first push")
				assert_eq(#cmds, 1, "first apply reloads")

				local shrunk = {enabled = true,
					vlans = {[1] = {mode = "untagged", enabled = true}},
					ports = {}}
				assert_true(switchvlan.apply(shrunk, CFG, st), "reconcile reports a change")
				assert_nil(u.db.network.openuf_swvlan20, "orphan section deleted")
				assert_eq(#cmds, 2, "reconcile reloads once")

				assert_false(switchvlan.apply(shrunk, CFG, st), "steady-state stays a no-op")
				assert_eq(#cmds, 2, "no third reload")
			end)
		end
	},
	{
		name = "switchvlan: apply deletes a section whose VLAN shrank to exclusions-only",
		fn = function()
			-- A VLAN still on the wire but with every member excluded renders
			-- to no ports string at all -- its section must go the same way
			-- as one whose VLAN left the wire entirely.
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(override(), CFG, st)
				assert_not_nil(u.db.network.openuf_swvlan20, "section exists after the first push")

				local excluded = {enabled = true,
					vlans = {[20] = {mode = "tagged", enabled = true}},
					ports = {[2] = {vlans = {[20] = "exclude"}}}}
				assert_true(switchvlan.apply(excluded, CFG, st), "reconcile reports a change")
				assert_nil(u.db.network.openuf_swvlan20, "exclusions-only VLAN loses its section")
			end)
		end
	},
	{
		name = "switchvlan: restore is a no-op with nothing to undo",
		fn = function()
			-- handle_response now routes every explicit-disable push here, so
			-- a steady-state disabled controller must not bounce the network:
			-- no openuf_ sections, no ledger -> no commit, no reload.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_false(switchvlan.restore({}), "nothing to restore")
				assert_false(switchvlan.restore(nil), "nil state tolerated")
				assert_eq(#cmds, 0, "no reload issued")
				assert_nil(u.commits.network, "no commit issued either")
			end)
		end
	},
	{
		name = "switchvlan: apply refuses on a DSA board",
		fn = function()
			with_capture(function(cmds)
				local u = new_mock_uci()
				u.cursor:set("network", "br0v20", "bridge-vlan")
				switchvlan._uci = u.mock
				assert_eq(switchvlan.detect_backend(u.cursor), "dsa", "DSA detected")
				silently(function()
					assert_false(switchvlan.apply(override(), CFG, {}), "no apply on DSA")
				end)
				assert_eq(#cmds, 0, "no command issued -- bridge-vlan is unverifiable here")
			end)
		end
	},
	{
		name = "switchvlan: apply refuses without dev.conf.vlan",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				silently(function()
					assert_false(switchvlan.apply(override(), {net = CFG.net}, {}),
						"a guessed switch port map would strand the device")
				end)
				assert_eq(#cmds, 0, "no command issued")
			end)
		end
	},
	{
		name = "switchvlan: apply skips ports with no swport rather than defaulting",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local cfg = {net = {lan_vlanid = 1, ports = {
					{idx = 2, ifname = "eth1"},   -- no swport
				}}, vlan = CFG.vlan}
				silently(function()
					assert_false(switchvlan.apply(override(), cfg, {}), "nothing applied")
				end)
				assert_eq(#cmds, 0, "an unmappable port is skipped, never guessed at")
			end)
		end
	},
	{
		name = "switchvlan: apply never touches the uplink port",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local sw = {
					enabled = true,
					vlans   = {[20] = {mode = "tagged", enabled = true}},
					-- port_idx 1 is the uplink -- reassigning its VLAN strands
					-- the device.
					ports   = {[1] = {pvid = 20, vlans = {[20] = "untagged"}}},
				}
				-- The uplink here is given a valid swport ON PURPOSE, so the
				-- ONLY thing that can reject it is the uplink guard. With the
				-- production modelmaps (which give uplinks no swport) this test
				-- would pass even with the guard deleted -- mutation-tested.
				local cfg = {net = {lan_vlanid = 1, ports = {
					{idx = 1, ifname = "eth0", uplink = true, swport = "wan"},
					{idx = 2, ifname = "eth1", swport = "lan1"},
				}}, vlan = CFG.vlan}
				silently(function()
					assert_false(switchvlan.apply(sw, cfg, {}), "uplink override ignored")
				end)
				assert_eq(#cmds, 0, "no command issued")
			end)
		end
	},
	{
		name = "switchvlan: apply never touches the socket the uplink cable is in",
		fn = function()
			-- A socket-shaped modelmap names no uplink: which socket carries
			-- it is detected at runtime (sysinfo.uplink_phys_port) and passed
			-- in. Moving that socket's VLAN strands the device just as surely
			-- as moving a statically declared uplink would.
			local cfg = {net = {lan_vlanid = 1, ports = {
				{idx = 1, swport = "lan1"},   -- physical 1
				{idx = 2, swport = "lan2"},   -- physical 2 -- the cable is here
			}}, vlan = CFG.vlan}
			local sw = {
				enabled = true,
				vlans   = {[20] = {mode = "tagged", enabled = true}},
				ports   = {[2] = {pvid = 20, vlans = {[20] = "untagged"}}},
			}
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				silently(function()
					assert_false(switchvlan.apply(sw, cfg, {}, nil, 2),
						"the override lands on the uplink socket and is refused")
				end)
				assert_eq(#cmds, 0, "no command issued")
			end)
			-- The same push on a board whose cable is elsewhere is applied.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				silently(function()
					assert_true(switchvlan.apply(sw, cfg, {}, nil, 1),
						"a downstream socket is assignable")
				end)
				assert_true(#cmds > 0, "the switch is reloaded")
			end)
		end
	},
	{
		name = "switchvlan: a dynamic-uplink board fails closed when the uplink is unknown",
		fn = function()
			-- No static uplink flag and no detected socket: any port could be
			-- the one carrying the device's own management traffic. Refusing
			-- every port loses a feature; guessing loses the device.
			local cfg = {net = {lan_vlanid = 1, ports = {
				{idx = 1, swport = "lan1"},
				{idx = 2, swport = "lan2"},
			}}, vlan = CFG.vlan}
			assert_nil(switchvlan.physical_port(cfg, 2, nil),
				"no port resolves without a known uplink")
			-- A modelmap that DOES name its uplink statically is unaffected --
			-- it already told openUF which port to protect.
			assert_eq(switchvlan.physical_port(CFG, 2, nil), 1,
				"a static-uplink board still resolves its downstream ports")
		end
	},
	{
		name = "switchvlan: MIB polling is switched on only when the driver has it off",
		fn = function()
			-- Per-port byte counters exist only while the ar8xxx driver polls
			-- the MIB, and an AR8327 ships with the interval at 0 -- so that
			-- board's Ports view read 0 B on every socket while an AR9344's
			-- was populated. Never turned off, and never touched on a board
			-- that has no such knob.
			local cfg = {vlan = {cpu_lan = 0, ports = {lan1 = 1}}}
			local orig = switchvlan._popen
			local ok, err = pcall(function()
				with_capture(function(cmds)
					switchvlan._popen = function() return "0\n" end
					silently(function()
						assert_true(switchvlan.enable_mib_polling(cfg), "polling off -> enabled")
					end)
					assert_eq(#cmds, 1, "one command")
					assert_true(cmds[1]:find("set ar8xxx_mib_poll_interval 500", 1, true) ~= nil,
						"sets the poll interval: " .. cmds[1])
				end)
				with_capture(function(cmds)
					switchvlan._popen = function() return "500\n" end
					assert_false(switchvlan.enable_mib_polling(cfg), "already polling -> untouched")
					assert_eq(#cmds, 0, "no command")
				end)
				with_capture(function(cmds)
					switchvlan._popen = function() return 'Unknown attribute "x"\n' end
					assert_false(switchvlan.enable_mib_polling(cfg), "no such knob -> untouched")
					assert_eq(#cmds, 0, "no command")
				end)
				with_capture(function(cmds)
					switchvlan._popen = function() return "0\n" end
					assert_false(switchvlan.enable_mib_polling({vlan = {mib_poll_ms = false}}),
						"explicit opt-out is honoured")
					assert_false(switchvlan.enable_mib_polling({}), "no switch map -> no switch")
					assert_eq(#cmds, 0, "no command")
				end)
			end)
			switchvlan._popen = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "switchvlan: apply is a no-op when gated off or absent",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_false(switchvlan.apply(nil, CFG, {}), "nil block")
				local off = override()
				off.enabled = false
				assert_false(switchvlan.apply(off, CFG, {}), "gated off")
				local bare = override()
				bare.ports = {}
				assert_false(switchvlan.apply(bare, CFG, {}), "gate on but no override")
				assert_eq(#cmds, 0, "no command in any case")
			end)
		end
	},
	{
		name = "switchvlan: a tagged SSID's VLAN gets trunked even with per-port VLAN off",
		fn = function()
			-- The IoT-network case. Per-port VLAN is untouched in the
			-- controller (sw is nil), but a WLAN sits on VLAN 20, and the
			-- switch drops every VID it has no entry for once enable_vlan is
			-- set -- the stock config on both validated boards. Confirmed
			-- live: 100% loss to the VLAN's gateway without this section, 0%
			-- with it.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_true(switchvlan.apply(nil, CFG, {}, {20}, 4),
					"a wireless VLAN alone is reason enough to program the switch")
				local sec = u.db.network.openuf_swvlan20
				assert_true(sec ~= nil, "a switch_vlan section is written for VLAN 20")
				assert_eq(sec.vlan, "20", "for the right VID")
				-- CPU + the uplink socket, and nothing else: that is the whole
				-- path a tagged SSID's frames take. Tagging the other sockets
				-- is not merely useless -- on an ar8216-family switch the tag
				-- flag is one global per-port bitmask shared by every VLAN, so
				-- it makes untagged wired clients on those sockets deaf.
				assert_eq(sec.ports, "0t 4t", "CPU + uplink tagged, nothing else")
				assert_eq(#cmds, 1, "one network reload")
			end)
		end
	},
	{
		name = "switchvlan: an unknown uplink holds the trunk instead of writing a guess",
		fn = function()
			-- Nothing to trunk through, so no section -- and emphatically not
			-- the old fallback of tagging every socket, which is what broke
			-- wired clients on the AR8229.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				silently(function()
					assert_false(switchvlan.apply(nil, CFG, {}, {20}),
						"no uplink, no trunk, no reload")
				end)
				assert_true(u.db.network.openuf_swvlan20 == nil,
					"no section is invented")
				assert_eq(#cmds, 0, "and the network is not reloaded")
			end)
		end
	},
	{
		name = "switchvlan: a transient unknown uplink does not tear down a working trunk",
		fn = function()
			-- The flap guard. Uplink detection reads the switch ARL and
			-- /proc/net/arp; an empty ARP cache for one inform is enough to
			-- return nil. If that fell through to the reconcile pass it would
			-- delete a good trunk and reload, then rewrite it on the next
			-- inform and reload again -- bouncing the IoT WLAN forever.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_true(switchvlan.apply(nil, CFG, {}, {20}, 4), "trunk written")
				assert_eq(u.db.network.openuf_swvlan20.ports, "0t 4t", "as expected")
				local before = #cmds

				silently(function()
					assert_false(switchvlan.apply(nil, CFG, {}, {20}),
						"the uplink went unknown: nothing changes")
				end)
				assert_true(u.db.network.openuf_swvlan20 ~= nil,
					"the existing trunk survives an unresolvable uplink")
				assert_eq(u.db.network.openuf_swvlan20.ports, "0t 4t", "unmodified")
				assert_eq(#cmds, before, "and no second network reload")
			end)
		end
	},
	{
		name = "switchvlan: a VLAN that really left the wire is still reconciled away",
		fn = function()
			-- The other half of the hold: holding must not become a leak. When
			-- the uplink IS known, a VID the push no longer names still loses
			-- its section -- the hold has to be scoped to the unresolvable
			-- case, not to every absence.
			--
			-- Moving the SSID from VLAN 20 to 30 rather than deleting it
			-- outright, because an empty wireless_vlans with no switch push
			-- returns before the reconcile by design; inform.lua routes that
			-- case to restore() instead.
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_true(switchvlan.apply(nil, CFG, {}, {20}, 4), "trunk written")
				assert_true(switchvlan.apply(nil, CFG, {}, {30}, 4),
					"the SSID moved to another VLAN")
				assert_true(u.db.network.openuf_swvlan20 == nil,
					"VLAN 20's section goes with it")
				assert_eq(u.db.network.openuf_swvlan30.ports, "0t 4t",
					"and VLAN 30 gets the trunk")
			end)
		end
	},
	{
		name = "switchvlan: the reversibility ledger records stock sections only",
		fn = function()
			-- A second push happens with openUF's own sections already in UCI.
			-- Snapshotting those as if they were the board's original state
			-- makes the ledger lie about what to restore to.
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(nil, CFG, st, {20}, 4)
				st.swvlan_backup = nil          -- force a fresh snapshot
				switchvlan.apply(nil, CFG, st, {20, 30}, 4)
				assert_eq(st.swvlan_backup["1"], "0t 1 2 3 4",
					"the stock VLAN 1 section is in the ledger")
				assert_true(st.swvlan_backup["20"] == nil,
					"openUF's own openuf_swvlan20 is not")
			end)
		end
	},
	{
		name = "switchvlan: a per-port assignment wins over the blanket trunk for the same VID",
		fn = function()
			-- Both features can name VLAN 20. Two sections for one VID is a
			-- config the switch cannot honour, so the specific one -- which
			-- may mark a socket untagged -- takes it.
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local sw = override()
				sw.ports = {[2] = {vlans = {[20] = "untagged"}}}
				switchvlan.apply(sw, CFG, {}, {20})
				assert_eq(u.db.network.openuf_swvlan20.ports, "0t 1",
					"the per-port membership, not the trunk")
			end)
		end
	},
	{
		name = "switchvlan: no wireless VLAN and no switch push changes nothing",
		fn = function()
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				assert_false(switchvlan.apply(nil, CFG, {}, {}), "empty vlan list")
				assert_false(switchvlan.apply(nil, CFG, {}, nil), "no vlan list at all")
				assert_eq(#cmds, 0, "no reload, no section")
			end)
		end
	},
	{
		name = "switchvlan: a VLAN beyond the switch's table is refused, loudly",
		fn = function()
			-- The AR8229 on the second validation AP reports "vlans: 16".
			-- netifd has no `vid` option, so the section's `vlan` is both the
			-- table slot and the VLAN ID: asking for 20 on a 16-entry table
			-- writes a section netifd skips in total silence. Better to say
			-- so than to leave a WLAN that associates and passes nothing.
			with_capture(function(cmds)
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local orig = switchvlan._popen
				switchvlan._popen = function()
					return "switch0: mdio.0:1f(Atheros AR8229), ports: 5 (cpu @ 0), vlans: 16\n"
				end
				local msg = {}
				local real = io.stderr
				io.stderr = {write = function(_, s) msg[#msg + 1] = s end}
				local ok = pcall(switchvlan.apply, nil, CFG, {}, {20}, 4)
				io.stderr = real
				switchvlan._popen = orig
				assert_true(ok, "no error thrown")
				assert_nil(u.db.network.openuf_swvlan20,
					"no section written -- netifd would ignore it anyway")
				assert_eq(#cmds, 0, "and no pointless reload")
				assert_contains(table.concat(msg), "exceeds this switch",
					"the reason is logged")
			end)
		end
	},
	{
		name = "switchvlan: a VLAN inside the table is programmed normally",
		fn = function()
			with_capture(function()
				local u = swconfig_board()
				switchvlan._uci = u.mock
				local orig = switchvlan._popen
				switchvlan._popen = function()
					return "switch0: ports: 5 (cpu @ 0), vlans: 16\n"
				end
				switchvlan.apply(nil, CFG, {}, {8}, 4)
				switchvlan._popen = orig
				assert_not_nil(u.db.network.openuf_swvlan8, "VLAN 8 fits in 16 entries")
				assert_eq(u.db.network.openuf_swvlan8.vlan, "8", "written as the id")
			end)
		end
	},
	{
		name = "switchvlan/dsa: an assigned socket moves from br-lan into the VLAN's bridge",
		fn = function()
			-- The whole feature. lan3 leaves br-lan and joins br-openuf10 --
			-- the same bridge the tagged SSID's wan.10 is already in, because
			-- a wired and a wireless client on VLAN 10 are one broadcast
			-- domain and the controller models them as one network.
			local u = dsa_board()
			with_capture(function(cmds)
				switchvlan._uci = u.mock
				local st = {}
				local changed = switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan")
				assert_true(changed, "UCI changed")
				assert_eq(joined(u, "brlan"), "lan2,lan4,wan", "lan3 left br-lan")
				assert_eq(joined(u, "openuf_brdev10"), "wan.10,lan3",
					"and joined the VLAN 10 bridge, behind its tagged uplink")
				assert_eq(cmds[#cmds], "/etc/init.d/network reload 2>/dev/null",
					"network reloaded once")
				assert_eq(table.concat(st.dsa_brlan_ports, ","), "lan2,lan3,lan4,wan",
					"br-lan's original ports are in the ledger, pristine")
			end)
		end
	},
	{
		name = "switchvlan/dsa: the uplink socket is never reassigned",
		fn = function()
			-- The rule that keeps the AP reachable. Moving the socket the
			-- gateway is behind into an isolated bridge strands the device at
			-- the far end of a cable with no way back.
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				silently(function()
					local changed = switchvlan.apply(dsa_push(1, 10), DSA_CFG, {}, {}, nil, "wan")
					assert_false(changed, "nothing applied")
				end)
				assert_eq(joined(u, "brlan"), "lan2,lan3,lan4,wan", "br-lan untouched")
				assert_eq(joined(u, "openuf_brdev10"), "wan.10", "and the uplink stayed put")
			end)
		end
	},
	{
		name = "switchvlan/dsa: an unknown uplink refuses every port, not just the uplink",
		fn = function()
			-- Fail closed. If the bridge FDB cannot say which socket faces the
			-- gateway -- an ARP cache that has not populated yet is enough --
			-- then applying ANY assignment is a coin flip on whether the one
			-- being moved is the uplink.
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				silently(function()
					assert_false(switchvlan.apply(dsa_push(3, 10), DSA_CFG, {}, {}, nil, nil),
						"nothing applied without a known uplink")
				end)
				assert_eq(joined(u, "brlan"), "lan2,lan3,lan4,wan", "br-lan untouched")
			end)
		end
	},
	{
		name = "switchvlan/dsa: un-assigning a socket brings it back to br-lan",
		fn = function()
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan")
				assert_eq(joined(u, "brlan"), "lan2,lan4,wan", "moved out")

				-- Same push with the port assignment removed.
				local off = {enabled = true, vlans = {}, ports = {}}
				local changed = switchvlan.apply(off, DSA_CFG, st, {}, nil, "wan")
				assert_true(changed, "the reconcile changed UCI")
				assert_eq(joined(u, "brlan"), "lan2,lan4,wan,lan3", "lan3 is back in br-lan")
				assert_eq(joined(u, "openuf_brdev10"), "wan.10",
					"and out of the VLAN bridge, which keeps its tagged uplink")
			end)
		end
	},
	{
		name = "switchvlan/dsa: restore puts br-lan back exactly as the board shipped it",
		fn = function()
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan")
				assert_true(switchvlan.restore(st), "restore ran")
				assert_eq(joined(u, "brlan"), "lan2,lan3,lan4,wan", "original port list, in order")
				assert_eq(joined(u, "openuf_brdev10"), "wan.10",
					"the VLAN bridge survives -- a tagged SSID may still need it")
				assert_nil(st.dsa_brlan_ports, "ledger spent")
			end)
		end
	},
	{
		name = "switchvlan/dsa: the ledger records the board's config, never openUF's own",
		fn = function()
			-- The failure this guards is silent and unrecoverable: snapshot
			-- after the first mutation and restore() faithfully puts back a
			-- br-lan that is already missing the moved socket, while
			-- reporting success. Same trap the swconfig ledger hit.
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan")
				local first = table.concat(st.dsa_brlan_ports, ",")
				-- A second push moves another socket; the ledger must not move.
				switchvlan.apply(dsa_push(4, 10), DSA_CFG, st, {}, nil, "wan")
				assert_eq(table.concat(st.dsa_brlan_ports, ","), first,
					"still the pristine list after a second mutation")
				assert_eq(first, "lan2,lan3,lan4,wan", "which is the board's own")
			end)
		end
	},
	{
		name = "switchvlan/dsa: a tagged assignment is refused rather than half-applied",
		fn = function()
			-- A bridge gives a port exactly one untagged home, which is what a
			-- Native VLAN is. Tagged membership would need a <ifname>.<vid>
			-- sub-device; no AP port control emits it, so it is declined out
			-- loud instead of shipped unverified.
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				local push = {enabled = true, vlans = {[10] = {mode = "tagged"}},
					ports = {[3] = {pvid = 1, vlans = {[10] = "tagged"}}}}
				silently(function()
					assert_false(switchvlan.apply(push, DSA_CFG, {}, {}, nil, "wan"),
						"nothing applied")
				end)
				assert_eq(joined(u, "brlan"), "lan2,lan3,lan4,wan", "br-lan untouched")
			end)

			-- ...but a port that DID get a native VLAN is not "refused"
			-- anything just because other VLANs came through tagged. The
			-- controller's default Tagged VLAN Management is "Allow All",
			-- which marks every non-native VLAN tagged -- warning on that
			-- logged a line per VLAN on every inform about a default nobody
			-- chose. Confirmed live: "port lan3 tagged into VLAN 1" fired
			-- twice a push for a port that had been assigned correctly.
			local u2 = dsa_board()
			with_capture(function()
				switchvlan._uci = u2.mock
				local push = {enabled = true, vlans = {[10] = {mode = "tagged"}},
					ports = {[3] = {pvid = 10,
						vlans = {[1] = "tagged", [10] = "untagged"}}}}
				local warned = false
				local real = io.stderr
				io.stderr = {write = function(_, t)
					if tostring(t):find("tagged") then warned = true end
				end}
				local ok = pcall(switchvlan.apply, push, DSA_CFG, {}, {}, nil, "wan")
				io.stderr = real
				assert_true(ok, "applied")
				assert_false(warned, "no tagged warning for a port with a native VLAN")
				assert_eq(joined(u2, "openuf_brdev10"), "wan.10,lan3", "and it moved")
			end)
		end
	},
	{
		name = "switchvlan/dsa: a port left on the management VLAN stays in br-lan",
		fn = function()
			-- Its native VLAN already IS br-lan; moving it into a bridge of
			-- its own would cut it off from the AP's own network for nothing.
			local u = dsa_board()
			with_capture(function()
				switchvlan._uci = u.mock
				local push = {enabled = true, vlans = {[1] = {mode = "untagged"}},
					ports = {[3] = {pvid = 1, vlans = {[1] = "untagged"}}}}
				assert_false(switchvlan.apply(push, DSA_CFG, {}, {}, nil, "wan"),
					"no change")
				assert_eq(joined(u, "brlan"), "lan2,lan3,lan4,wan", "lan3 stayed home")
			end)
		end
	},
	{
		name = "switchvlan/dsa: a steady-state re-push changes nothing and reloads nothing",
		fn = function()
			-- Every inform carries the same switch block. Rewriting the
			-- bridges each time would reload the network every ~10s and bounce
			-- the wired client the feature exists to serve.
			local u = dsa_board()
			with_capture(function(cmds)
				switchvlan._uci = u.mock
				local st = {}
				switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan")
				local n = #cmds
				assert_false(switchvlan.apply(dsa_push(3, 10), DSA_CFG, st, {}, nil, "wan"),
					"second identical push is a no-op")
				assert_eq(#cmds, n, "and issues no reload")
			end)
		end
	},
}
