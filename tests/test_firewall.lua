-- Tests for openuf/firewall.lua (client block/unblock enforcement).
-- Run from project root: lua tests/run_tests.lua

local firewall = dofile("openuf/firewall.lua")

local function with_capture(fn)
	local cmds = {}
	local orig = firewall._exec
	firewall._exec = function(cmd)
		cmds[#cmds + 1] = cmd
		return true
	end
	fn(cmds)
	firewall._exec = orig
end

return {
	{
		name = "firewall: reconcile with an empty list still (re)creates the table/set/chain",
		fn = function()
			with_capture(function(cmds)
				firewall.reconcile({})
				assert_true(#cmds >= 5, "at least delete+table+set+chain+2 rules")
				assert_contains(cmds[1], "nft delete table bridge openuf", "clears any prior table first")
				assert_contains(cmds[2], "nft add table bridge openuf", "recreates the table")
				assert_contains(cmds[3], "nft add set bridge openuf blocked_macs", "recreates the set")
				local joined = table.concat(cmds, "\n")
				assert_contains(joined, "type filter hook forward priority 0", "chain hooked into bridge forward")
				assert_contains(joined, "ether saddr @blocked_macs drop", "drops traffic from a blocked MAC")
				assert_contains(joined, "ether daddr @blocked_macs drop", "drops traffic to a blocked MAC")
			end)
		end
	},
	{
		name = "firewall: reconcile adds an element per blocked MAC",
		fn = function()
			with_capture(function(cmds)
				firewall.reconcile({"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
				local joined = table.concat(cmds, "\n")
				assert_contains(joined, "nft add element bridge openuf blocked_macs '{ aa:bb:cc:dd:ee:01 }'",
					"first MAC added as a set element")
				assert_contains(joined, "nft add element bridge openuf blocked_macs '{ aa:bb:cc:dd:ee:02 }'",
					"second MAC added as a set element")
			end)
		end
	},
	{
		name = "firewall: reconcile rebuilds from scratch rather than diffing (idempotent across repeat calls)",
		fn = function()
			with_capture(function(cmds)
				firewall.reconcile({"aa:bb:cc:dd:ee:01"})
				local first_count = #cmds
				firewall.reconcile({"aa:bb:cc:dd:ee:01"})
				assert_eq(#cmds, first_count * 2, "second call issues the exact same command sequence again")
			end)
		end
	},
	{
		name = "firewall: deauth issues hostapd_cli per interface",
		fn = function()
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", {"wlan0", "wlan1"})
				assert_eq(#cmds, 2, "one hostapd_cli call per interface")
				assert_contains(cmds[1], "hostapd_cli -i wlan0 deauthenticate aa:bb:cc:dd:ee:01",
					"deauth on the first radio")
				assert_contains(cmds[2], "hostapd_cli -i wlan1 deauthenticate aa:bb:cc:dd:ee:01",
					"deauth on the second radio")
			end)
		end
	},
	{
		name = "firewall: deauth is a safe no-op with no interfaces",
		fn = function()
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", {})
				assert_eq(#cmds, 0, "no commands issued")
			end)
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", nil)
				assert_eq(#cmds, 0, "no commands issued for nil ifnames")
			end)
		end
	},
	{
		name = "firewall: a malformed MAC never reaches the nft command line",
		fn = function()
			-- blocked_stas comes from the controller by way of state.json,
			-- which is hand-editable too, and every entry is spliced straight
			-- into a shell command. Before adoption the inform channel is
			-- plain HTTP under the well-known default key, so a forged
			-- block-sta is within reach of anyone on the path.
			local orig_exec, orig_stderr = firewall._exec, io.stderr
			local cmds, logged = {}, {}
			firewall._exec = function(c) cmds[#cmds + 1] = c; return true end
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			firewall.reconcile({
				"aa:bb:cc:dd:ee:ff",
				"aa:bb:cc:dd:ee:ff }; touch /tmp/pwned; nft add element x y '{ 1",
				"not-a-mac",
			})
			local ok_deauth = firewall.deauth("$(id)", {"wlan0"})
			firewall._exec, io.stderr = orig_exec, orig_stderr

			local all = table.concat(cmds, "\n")
			assert_true(all:find("aa:bb:cc:dd:ee:ff", 1, true) ~= nil, "the real MAC is added")
			assert_true(all:find("touch", 1, true) == nil, "the injected command never runs")
			assert_true(all:find("not%-a%-mac") == nil, "and neither does the junk entry")
			assert_true(all:find("hostapd_cli") == nil, "deauth refuses a non-MAC outright")
			assert_false(ok_deauth, "and says so")
			assert_true(table.concat(logged):find("malformed") ~= nil, "each drop is logged")
		end
	},
}
