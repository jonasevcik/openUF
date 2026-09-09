--[[
	Network interface configuration, driven by the controller's "IP Settings"
	(DHCP vs Static) push. Delivered via the inform response's `system_cfg`
	field -- a flat OpenWrt-UCI-style key=value blob (same format as
	`mgmt_cfg`, different keys), NOT the vap_table/network_table-shaped JSON
	used elsewhere. Confirmed live against a real controller: static IP is
	`netconf.1.ip`/`netconf.1.netmask`, gateway is `route.1.gateway`, DNS is
	`resolv.nameserver.N.ip`, and DHCP-vs-static is signalled by the
	presence/absence of `dhcpc.1.*` sub-keys (not an explicit flag) -- see
	PROTOCOL-VALIDATION.md.

	All operations are safe no-ops without an iface (unconfigured hardware),
	matching led.lua/ucihelper.lua's convention.
]]--

local M = {}

-- Injectable: shell command runner, for real `ip`/`udhcpc` invocations.
M._exec = function(cmd) return os.execute(cmd) end

-- Overridable: where apply_dns() writes. On OpenWrt this is frequently a
-- symlink into /tmp that netifd owns; writing through it is still the right
-- move for a controller-pushed static config, since netifd has no lease to
-- re-assert over it.
M.RESOLV_CONF = "/etc/resolv.conf"

-- Strict IPv4 dotted-quad check. DNS servers arrive straight off the wire and
-- are interpolated into a shell command in apply_dns(), so anything that isn't
-- four 0-255 octets is dropped rather than escaped.
local function is_ipv4(s)
	if type(s) ~= "string" then return false end
	local octets = {s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
	if #octets ~= 4 then return false end
	for _, o in ipairs(octets) do
		if #o > 3 or tonumber(o) > 255 then return false end
	end
	return true
end
-- Exported so inform.lua can refuse a malformed push before RECORDING it in
-- state.json, not only before running it.
M.is_ipv4 = is_ipv4


-- Convert a dotted-quad netmask ("255.255.255.0") to a CIDR prefix length.
-- Returns 24 (a common default) if netmask is nil/unparseable.
function M.netmask_to_prefix(netmask)
	if type(netmask) ~= "string" then return 24 end
	local bits = 0
	local octets = 0
	for octet in netmask:gmatch("%d+") do
		local n = tonumber(octet)
		if n then
			while n > 0 do
				bits = bits + (n % 2)
				n = math.floor(n / 2)
			end
			octets = octets + 1
		end
	end
	return octets == 4 and bits or 24
end

-- Replace /etc/resolv.conf with the controller-pushed nameservers.
-- servers: array of IPv4 strings in controller order (resolv.nameserver.<k>.ip,
-- sorted by <k>).
--
-- A nil/empty list is a no-op: the controller simply not sending nameservers
-- must never blank out working resolution. Same reasoning as apply_dhcp()'s
-- guard below -- absence of a key is not an instruction to tear something down.
function M.apply_dns(servers)
	if type(servers) ~= "table" or #servers == 0 then return false end
	local args = {}
	for _, ip in ipairs(servers) do
		if is_ipv4(ip) then args[#args + 1] = "'nameserver " .. ip .. "'" end
	end
	if #args == 0 then return false end
	M._exec(string.format("printf '%%s\\n' %s > %s 2>/dev/null",
		table.concat(args, " "), M.RESOLV_CONF))
	return true
end

-- Apply a static IPv4 address (+ optional gateway and DNS servers) to iface.
-- Replaces any existing address on iface -- callers are responsible for
-- deciding this is the right moment (e.g. a genuine controller push).
-- dns: optional array of nameserver IPs, applied via apply_dns().
function M.apply_static(iface, ip, netmask, gateway, dns)
	if not iface or not ip or ip == "0.0.0.0" then return false end
	-- Same rule as apply_dns, for the same reason: ip and gateway come off the
	-- wire and go into a command line, and before adoption that wire is plain
	-- HTTP under the well-known key. Refused whole rather than half-applied --
	-- an address with no route is not what was asked for. (The netmask only
	-- ever reaches the command as a digit count.)
	if not is_ipv4(ip) then return false end
	if gateway and gateway ~= "" and gateway ~= "0.0.0.0" and not is_ipv4(gateway) then
		return false
	end
	local prefix = M.netmask_to_prefix(netmask)
	M._exec(string.format("ip addr flush dev %s 2>/dev/null", iface))
	M._exec(string.format("ip addr add %s/%d dev %s 2>/dev/null", ip, prefix, iface))
	if gateway and gateway ~= "0.0.0.0" then
		M._exec(string.format("ip route replace default via %s 2>/dev/null", gateway))
	end
	M.apply_dns(dns)
	return true
end

-- Release any static config and let a DHCP client re-acquire an address.
-- Best-effort: real hardware's netifd handles this natively; here we shell
-- out to udhcpc directly (present on both Alpine and OpenWrt).
function M.apply_dhcp(iface)
	if not iface then return false end
	M._exec(string.format("ip addr flush dev %s 2>/dev/null", iface))
	M._exec(string.format("udhcpc -i %s -n -q 2>/dev/null", iface))
	return true
end

return M
