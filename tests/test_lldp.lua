-- Tests for openuf/lldp.lua (lldpctl JSON parsing).
-- Run from project root: lua tests/run_tests.lua

local lldp = dofile("openuf/lldp.lua")

local function fixture(name)
	local f = io.open("tests/fixtures/" .. name, "r")
	if not f then error("fixture not found: " .. name) end
	local s = f:read("*a"); f:close()
	return s
end

local function with_cmd(output_or_fn, fn)
	local orig = lldp._run_cmd
	lldp._run_cmd = type(output_or_fn) == "function"
		and output_or_fn
		or function() return output_or_fn end
	-- neighbors() is TTL-cached (lldpd advertises on a 30s interval; forking
	-- lldpctl every 10s bought nothing) and _local_port_idx is memoized for
	-- the process. Both must be dropped on the way in AND out, or one test's
	-- fixture answers the next one's question.
	lldp._neighbours_cache = nil
	lldp._port_idx_cache   = {}
	local ok, err = pcall(fn)
	lldp._run_cmd = orig
	lldp._neighbours_cache = nil
	lldp._port_idx_cache   = {}
	if not ok then error(err, 2) end
end

return {
	{
		name = "lldp: neighbors() parses fixture JSON and returns one neighbor",
		fn = function()
			with_cmd(fixture("lldpctl_output.json"), function()
				local nbrs = lldp.neighbors()
				assert_eq(#nbrs, 1, "one neighbor")
				assert_eq(nbrs[1].chassis_id,  "aa:bb:cc:dd:ee:01",             "chassis_id")
				assert_eq(nbrs[1].system_name, "switch01",                       "system_name")
				assert_eq(nbrs[1].port_id,     "GigabitEthernet0/1",             "port_id")
				assert_eq(nbrs[1].port,        "eth0",                           "local port")
				assert_contains(nbrs[1].system_desc, "UniFi Switch",             "system_desc")
				assert_eq(nbrs[1].port_descr,  "Uplink port",                    "port_descr")
			end)
		end
	},
	{
		name = "lldp: neighbors() reads local_port_idx from /sys/class/net/<port>/ifindex",
		fn = function()
			local orig_read = lldp._read_file
			lldp._read_file = function(path)
				if path == "/sys/class/net/eth0/ifindex" then return "3\n" end
				return nil
			end
			with_cmd(fixture("lldpctl_output.json"), function()
				local nbrs = lldp.neighbors()
				assert_eq(nbrs[1].local_port_idx, 3, "local_port_idx from sysfs")
			end)
			lldp._read_file = orig_read
		end
	},
	{
		name = "lldp: neighbors() local_port_idx is nil when sysfs is unavailable",
		fn = function()
			-- Explicitly mock sysfs as absent rather than relying on the
			-- ambient environment actually lacking it: real Linux CI
			-- runners/containers always have a genuine eth0 with a real
			-- /sys/class/net/eth0/ifindex, so this only ever passed by
			-- accident on a /sys-less macOS dev machine.
			local orig_read = lldp._read_file
			lldp._read_file = function() return nil end
			with_cmd(fixture("lldpctl_output.json"), function()
				local nbrs = lldp.neighbors()
				assert_true(nbrs[1].local_port_idx == nil, "nil without /sys access")
			end)
			lldp._read_file = orig_read
		end
	},
	{
		name = "lldp: neighbors() returns {} for empty output",
		fn = function()
			with_cmd("", function()
				assert_eq(#lldp.neighbors(), 0, "empty result")
			end)
		end
	},
	{
		name = "lldp: neighbors() returns {} for malformed JSON",
		fn = function()
			with_cmd("{this is not valid json!!!}", function()
				assert_eq(#lldp.neighbors(), 0, "empty on bad JSON")
			end)
		end
	},
	{
		name = "lldp: neighbors() returns {} when lldp key is absent",
		fn = function()
			with_cmd('{"something_else": {}}', function()
				assert_eq(#lldp.neighbors(), 0, "empty when no lldp key")
			end)
		end
	},
	{
		name = "lldp: neighbor capabilities list is parsed",
		fn = function()
			with_cmd(fixture("lldpctl_output.json"), function()
				local nbrs = lldp.neighbors()
				assert_true(#nbrs[1].capabilities >= 1, "at least one capability")
				-- The fixture has Bridge enabled and Router disabled -- the
				-- `if cap.enabled` filter must include one and EXCLUDE the
				-- other, or a regression emitting disabled caps passes.
				local has_bridge, has_router = false, false
				for _, cap in ipairs(nbrs[1].capabilities) do
					if cap == "Bridge" then has_bridge = true end
					if cap == "Router" then has_router = true end
				end
				assert_true(has_bridge, "enabled Bridge capability present")
				assert_false(has_router, "disabled Router capability excluded")
			end)
		end
	},
	{
		name = "lldp: the neighbour list is reused for a minute, not re-forked every heartbeat",
		fn = function()
			-- lldpd advertises on a 30-second TX interval and the controller
			-- renders this as topology, not as a statistic, so forking lldpctl
			-- and cjson-decoding a full chassis tree every 10-second heartbeat
			-- bought nothing.
			local orig_cmd, orig_time = lldp._run_cmd, lldp._time
			local clock, forks = 9000, 0
			lldp._time = function() return clock end
			lldp._neighbours_cache = nil
			lldp._run_cmd = function()
				forks = forks + 1
				return fixture("lldpctl_output.json")
			end

			assert_eq(#lldp.neighbors(), 1, "the neighbour is found")
			lldp.neighbors(); lldp.neighbors()
			assert_eq(forks, 1, "one lldpctl fork serves a minute of heartbeats")

			clock = clock + lldp.NEIGHBOURS_TTL + 1
			assert_eq(#lldp.neighbors(), 1, "and it is re-read once the TTL is up")
			assert_eq(forks, 2, "with a second fork")

			lldp._run_cmd, lldp._time = orig_cmd, orig_time
			lldp._neighbours_cache = nil
		end
	},
	{
		name = "lldp: an empty answer is not cached",
		fn = function()
			-- No lldpd, a failed fork and a truncated reply all come back
			-- empty. Pinning that for a minute would blank the controller's
			-- topology on a transient the very next heartbeat would have
			-- fixed -- and would keep a device that starts before lldpd
			-- reporting no neighbours long after lldpd is up.
			local orig_cmd, orig_time = lldp._run_cmd, lldp._time
			local clock = 9000
			lldp._time = function() return clock end
			lldp._neighbours_cache = nil
			local up = false
			lldp._run_cmd = function()
				return up and fixture("lldpctl_output.json") or ""
			end

			assert_eq(#lldp.neighbors(), 0, "nothing yet")
			up = true
			assert_eq(#lldp.neighbors(), 1, "and the neighbour lands immediately, not in a minute")

			lldp._run_cmd, lldp._time = orig_cmd, orig_time
			lldp._neighbours_cache = nil
		end
	},
	{
		name = "lldp: a port's ifindex is read once, not once per neighbour on it",
		fn = function()
			-- _local_port_idx is called from the per-NEIGHBOUR record builder,
			-- so a port with two neighbours opened the same sysfs file twice.
			-- An ifindex is fixed for the life of the netdev.
			local orig_rf = lldp._read_file
			local reads = 0
			lldp._port_idx_cache = {}
			lldp._read_file = function(path)
				reads = reads + 1
				return path:find("eth0") and "7\n" or nil
			end
			assert_eq(lldp._local_port_idx("eth0"), 7, "the ifindex")
			lldp._local_port_idx("eth0")
			assert_eq(reads, 1, "read once for the port, not once per neighbour")
			-- A port that does not exist is "asked and absent", not "unasked".
			assert_nil(lldp._local_port_idx("lan9"), "no such netdev")
			lldp._local_port_idx("lan9")
			assert_eq(reads, 2, "and it is not re-opened per neighbour either")

			lldp._read_file = orig_rf
			lldp._port_idx_cache = {}
		end
	},
}
