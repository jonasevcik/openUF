-- Tests for openuf/shaper.lua ("WiFi Speed Limit" tc enforcement).
-- Run from project root: lua tests/run_tests.lua
--
-- Every command shape pinned here was checked against a real tc
-- (iproute2 6.9.0) on a dummy netdev while writing the module -- including
-- the explicit `quantum`, without which HTB warns about r2q. These tests
-- pin the shape so a regression in it is visible.

local shaper = dofile("openuf/shaper.lua")

-- Capture tc invocations instead of running them.
local function with_shaper(fn)
	local orig = shaper._exec
	local cmds = {}
	shaper._exec = function(cmd) cmds[#cmds + 1] = cmd; return true end
	local ok, err = pcall(fn, cmds)
	shaper._exec = orig
	if not ok then error(err, 0) end
end

local function joined(cmds) return table.concat(cmds, "\n") end

local function contains(cmds, needle)
	return joined(cmds):find(needle, 1, true) ~= nil
end

local function assert_true(cond, msg)
	if not cond then error(msg or "assertion failed", 2) end
end

return {
	{
		name = "shaper: reconcile caps the downlink with an HTB class",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0", down_kbps = 33000}})
				assert_true(contains(cmds,
					"tc qdisc add dev wlan0 root handle 1: htb default 10"),
					"HTB root qdisc added")
				assert_true(contains(cmds,
					"tc class add dev wlan0 parent 1: classid 1:10 htb rate 33000kbit ceil 33000kbit quantum 1514"),
					"rate-capped class added with an explicit quantum")
			end)
		end
	},
	{
		name = "shaper: reconcile polices the uplink on ingress",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0", up_kbps = 17000}})
				assert_true(contains(cmds,
					"tc qdisc add dev wlan0 handle ffff: ingress"),
					"ingress qdisc added")
				-- burst is one tenth of a second of the configured rate.
				assert_true(contains(cmds,
					"tc filter add dev wlan0 parent ffff: protocol all prio 1 u32 match u32 0 0 police rate 17000kbit burst 1700k drop flowid :1"),
					"match-everything policing filter added")
			end)
		end
	},
	{
		name = "shaper: reconcile clears before shaping (idempotent across repeat calls)",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0", down_kbps = 1000}})
				assert_true(contains(cmds,
					"tc qdisc del dev wlan0 root 2>/dev/null"),
					"root qdisc torn down first")
				assert_true(contains(cmds,
					"tc qdisc del dev wlan0 ingress 2>/dev/null"),
					"ingress qdisc torn down first")
				-- Teardown must precede the add, or the add hits an existing qdisc.
				local text = joined(cmds)
				assert_true(text:find("del dev wlan0 root", 1, true)
					< text:find("add dev wlan0 root", 1, true),
					"teardown ordered before setup")
			end)
		end
	},
	{
		name = "shaper: an uncapped VAP is cleared but not shaped",
		fn = function()
			-- This is how removing a speed limit in the controller takes
			-- effect: the VAP still arrives, with both rates nil.
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0"}})
				assert_true(contains(cmds, "tc qdisc del dev wlan0 root"),
					"previous shaping torn down")
				assert_true(not contains(cmds, "htb"), "no HTB qdisc installed")
				assert_true(not contains(cmds, "police"), "no policing filter installed")
			end)
		end
	},
	{
		name = "shaper: each direction is independent",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0", down_kbps = 5000}})
				assert_true(contains(cmds, "htb rate 5000kbit"), "downlink capped")
				assert_true(not contains(cmds, "police"), "uplink left uncapped")
			end)
		end
	},
	{
		name = "shaper: reconcile shapes each VAP on its own netdev",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({
					{ifname = "wlan0", down_kbps = 33000},
					{ifname = "wlan1", down_kbps = 44000},
				})
				assert_true(contains(cmds, "dev wlan0 parent 1: classid 1:10 htb rate 33000kbit"),
					"first VAP's rate")
				assert_true(contains(cmds, "dev wlan1 parent 1: classid 1:10 htb rate 44000kbit"),
					"second VAP's rate")
			end)
		end
	},
	{
		name = "shaper: a tiny uplink rate still gets a usable burst floor",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{ifname = "wlan0", up_kbps = 100}})
				assert_true(contains(cmds, "burst 32k"),
					"burst floors at 32k rather than 10k")
			end)
		end
	},
	{
		name = "shaper: reconcile is a safe no-op with nil rules",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile(nil)
				assert_true(#cmds == 0, "no commands emitted")
			end)
		end
	},
	{
		name = "shaper: reconcile skips entries with no resolved ifname",
		fn = function()
			with_shaper(function(cmds)
				shaper.reconcile({{down_kbps = 33000}})
				assert_true(#cmds == 0, "no commands emitted for an unresolved VAP")
			end)
		end
	},
	{
		name = "shaper: a rejected police filter is reported, not counted as success",
		fn = function()
			-- The police ACTION is act_police (kmod-sched-act-police), a
			-- separate module from the ingress qdisc and absent from a stock
			-- filogic image: the download cap applies and this one call fails
			-- with "Failed to load TC action module", so the controller was
			-- told the whole limit took while only half of it did.
			local orig_exec, orig_stderr = shaper._exec, io.stderr
			local logged = {}
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			-- Lua 5.1's os.execute returns the raw exit status, so a FAILED
			-- call returns a non-zero number -- which is truthy. That is why a
			-- bare truth test would have passed here.
			shaper._exec = function(cmd)
				if cmd:find("police", 1, true) then return 2 end
				return 0
			end
			local ok = shaper.reconcile({{ifname = "wlan0", down_kbps = 33000, up_kbps = 17000}})
			shaper._exec, io.stderr = orig_exec, orig_stderr

			assert_false(ok, "reconcile reports the failure")
			local out = table.concat(logged)
			assert_true(out:find("kmod%-sched%-act%-police") ~= nil,
				"and names the package that fixes it")
			assert_true(out:find("wlan0", 1, true) ~= nil, "and the interface it happened on")
		end
	},
	{
		name = "shaper: an all-successful reconcile still reports success",
		fn = function()
			local orig = shaper._exec
			shaper._exec = function() return 0 end     -- Lua 5.1 shape: 0 = success
			assert_true(shaper.reconcile({{ifname = "wlan0", down_kbps = 1000, up_kbps = 500}}),
				"nothing failed, so nothing is reported")
			shaper._exec = function() return true end  -- Lua 5.4 shape
			assert_true(shaper.reconcile({{ifname = "wlan0", up_kbps = 500}}),
				"and the 5.4 return shape is understood too")
			shaper._exec = orig
		end
	},
}
