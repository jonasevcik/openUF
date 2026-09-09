-- Tests for openuf/netconfig.lua (IP Settings: DHCP/Static network config).
-- Run from project root: lua tests/run_tests.lua

local netconfig = dofile("openuf/netconfig.lua")

local function with_capture(fn)
	local cmds = {}
	local orig = netconfig._exec
	netconfig._exec = function(cmd)
		cmds[#cmds + 1] = cmd
		return true
	end
	fn(cmds)
	netconfig._exec = orig
end

return {
	{
		name = "netconfig: netmask_to_prefix converts common netmasks",
		fn = function()
			assert_eq(netconfig.netmask_to_prefix("255.255.255.0"), 24, "/24")
			assert_eq(netconfig.netmask_to_prefix("255.255.255.128"), 25, "/25")
			assert_eq(netconfig.netmask_to_prefix("255.255.0.0"), 16, "/16")
			assert_eq(netconfig.netmask_to_prefix("255.255.255.255"), 32, "/32")
		end
	},
	{
		name = "netconfig: netmask_to_prefix defaults to 24 for nil/malformed input",
		fn = function()
			assert_eq(netconfig.netmask_to_prefix(nil), 24, "nil defaults to /24")
			assert_eq(netconfig.netmask_to_prefix("not-a-netmask"), 24, "malformed defaults to /24")
		end
	},
	{
		name = "netconfig: apply_static returns false without iface or ip",
		fn = function()
			assert_false(netconfig.apply_static(nil, "10.0.0.5", "255.255.255.0"), "no-op without iface")
			assert_false(netconfig.apply_static("eth0", nil, "255.255.255.0"), "no-op without ip")
			assert_false(netconfig.apply_static("eth0", "0.0.0.0", "255.255.255.0"), "no-op for 0.0.0.0")
		end
	},
	{
		name = "netconfig: apply_static flushes and adds the address with correct prefix",
		fn = function()
			with_capture(function(cmds)
				local ok = netconfig.apply_static("eth0", "172.19.0.50", "255.255.255.0", "172.19.0.1")
				assert_true(ok, "apply_static returns true")
				assert_eq(#cmds, 3, "three shell commands")
				assert_contains(cmds[1], "ip addr flush dev eth0", "flush existing address")
				assert_contains(cmds[2], "ip addr add 172.19.0.50/24 dev eth0", "add static address with /24")
				assert_contains(cmds[3], "ip route replace default via 172.19.0.1", "set default route")
			end)
		end
	},
	{
		name = "netconfig: apply_static skips the route command without a gateway",
		fn = function()
			with_capture(function(cmds)
				netconfig.apply_static("eth0", "172.19.0.50", "255.255.255.0", nil)
				assert_eq(#cmds, 2, "no route command without gateway")
			end)
		end
	},
	{
		name = "netconfig: apply_static skips the route command for gateway 0.0.0.0",
		fn = function()
			with_capture(function(cmds)
				netconfig.apply_static("eth0", "172.19.0.50", "255.255.255.0", "0.0.0.0")
				assert_eq(#cmds, 2, "no route command for 0.0.0.0 gateway")
			end)
		end
	},
	{
		name = "netconfig: apply_dns writes nameservers in controller order",
		fn = function()
			with_capture(function(cmds)
				local ok = netconfig.apply_dns({"192.168.1.1", "8.8.8.8"})
				assert_true(ok, "apply_dns returns true")
				assert_eq(#cmds, 1, "one shell command")
				assert_contains(cmds[1], "'nameserver 192.168.1.1' 'nameserver 8.8.8.8'",
					"both servers, primary first")
				assert_contains(cmds[1], "> /etc/resolv.conf", "writes resolv.conf")
			end)
		end
	},
	{
		name = "netconfig: apply_dns is a no-op for nil/empty input",
		fn = function()
			with_capture(function(cmds)
				-- The controller omitting nameservers must never blank out
				-- working resolution.
				assert_false(netconfig.apply_dns(nil), "nil is a no-op")
				assert_false(netconfig.apply_dns({}), "empty list is a no-op")
				assert_eq(#cmds, 0, "no shell command issued")
			end)
		end
	},
	{
		name = "netconfig: apply_dns drops non-IPv4 entries rather than shelling them out",
		fn = function()
			with_capture(function(cmds)
				-- These values come straight off the wire and are interpolated
				-- into a shell command, so they must never reach it.
				assert_false(netconfig.apply_dns({"'; touch /tmp/pwned; '"}),
					"injection attempt rejected")
				assert_false(netconfig.apply_dns({"999.1.1.1"}), "out-of-range octet rejected")
				assert_false(netconfig.apply_dns({"not-an-ip"}), "garbage rejected")
				assert_eq(#cmds, 0, "no shell command issued")

				netconfig.apply_dns({"192.168.1.1", "nope"})
				assert_eq(#cmds, 1, "valid entry still applied")
				assert_contains(cmds[1], "'nameserver 192.168.1.1'", "valid server kept")
				assert_nil(cmds[1]:find("nope", 1, true), "invalid server dropped")
			end)
		end
	},
	{
		name = "netconfig: apply_static applies DNS alongside the address",
		fn = function()
			with_capture(function(cmds)
				netconfig.apply_static("eth0", "172.19.0.50", "255.255.255.0",
					"172.19.0.1", {"172.19.0.1"})
				assert_eq(#cmds, 4, "flush, add, route, resolv.conf")
				assert_contains(cmds[4], "'nameserver 172.19.0.1'", "DNS written last")
			end)
		end
	},
	{
		name = "netconfig: apply_static without DNS leaves resolv.conf alone",
		fn = function()
			with_capture(function(cmds)
				netconfig.apply_static("eth0", "172.19.0.50", "255.255.255.0", "172.19.0.1")
				assert_eq(#cmds, 3, "no resolv.conf write without DNS servers")
			end)
		end
	},
	{
		name = "netconfig: apply_dhcp returns false without iface",
		fn = function()
			assert_false(netconfig.apply_dhcp(nil), "no-op without iface")
		end
	},
	{
		name = "netconfig: apply_dhcp flushes the address and invokes udhcpc",
		fn = function()
			with_capture(function(cmds)
				local ok = netconfig.apply_dhcp("eth0")
				assert_true(ok, "apply_dhcp returns true")
				assert_eq(#cmds, 2, "two shell commands")
				assert_contains(cmds[1], "ip addr flush dev eth0", "flush existing address")
				assert_contains(cmds[2], "udhcpc -i eth0", "invoke udhcpc on the right interface")
			end)
		end
	},
	{
		name = "netconfig: apply_static refuses a malformed address rather than half-applying",
		fn = function()
			-- ip and gateway come off the wire and go into an `ip addr` /
			-- `ip route` command line -- and before adoption that wire is
			-- plain HTTP under the well-known default key. apply_dns already
			-- had this rule; the address half did not. Refused WHOLE: an
			-- address with no route is not what was asked for.
			local orig = netconfig._exec
			local cmds = {}
			netconfig._exec = function(c) cmds[#cmds + 1] = c; return true end

			assert_false(netconfig.apply_static("br-lan", "10.0.0.5; reboot", "255.255.255.0", "10.0.0.1"),
				"an injected command in the address is refused")
			assert_false(netconfig.apply_static("br-lan", "10.0.0.5", "255.255.255.0", "10.0.0.1; reboot"),
				"and so is one in the gateway")
			assert_eq(#cmds, 0, "and neither ran anything at all")

			assert_true(netconfig.apply_static("br-lan", "10.0.0.5", "255.255.255.0", "10.0.0.1"),
				"a well-formed push still applies")
			assert_true(#cmds > 0, "and does run")
			netconfig._exec = orig
		end
	},
}
