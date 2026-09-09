--[[
	Client blocking, driven by the controller's "Block"/"Unblock" client
	actions. Delivered as a one-shot inform-response cmd (`{"_type":"cmd",
	"cmd":"block-sta"|"unblock-sta","mac":"<mac>"}`) -- confirmed live against
	a real controller (see PROTOCOL-VALIDATION.md). There is no persistent
	wire-level block list the controller pushes on every inform (a candidate
	top-level `include_blocks` field stays empty even while a client is
	blocked) -- the device is expected to remember the block itself, the same
	way real hardware persists it locally after a one-shot command.

	Enforcement is nftables, in a dedicated `bridge openuf` table so it never
	collides with (or gets wiped by) OpenWrt's own fw4-managed tables. Rules
	are added directly to the live kernel ruleset, not via UCI -- like
	netconfig.lua's `ip addr`/`ip route` calls, this is ephemeral runtime
	state that must be explicitly reconciled again after a restart (see
	M.reconcile, called both on the block/unblock cmd and at inform.lua
	startup with the persisted list from state.json).

	A single dynamic nft set (`blocked_macs`) holds every blocked MAC, with
	two static rules matching against it (source and destination) -- adding/
	removing a MAC is then a single `nft add|delete element` against the set,
	never touching the rules themselves. M.reconcile rebuilds the whole table
	from scratch (delete + recreate) rather than diffing, mirroring
	netconfig.lua's flush-then-reapply pattern -- simpler and self-healing if
	the table was ever left in an unexpected state.
]]--

local M = {}

-- Injectable: shell command runner, for real `nft`/`hostapd_cli` invocations.
M._exec = function(cmd) return os.execute(cmd) end

local NFT_TABLE = "bridge openuf"

-- Exactly "aa:bb:cc:dd:ee:ff". Every MAC below is spliced into a shell command
-- line; the list comes from the controller (block-sta) by way of state.json,
-- which is also hand-editable, so this module refuses anything else itself
-- rather than trusting the caller to have.
local function is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

-- Rebuild the nftables blocklist to exactly match blocked_macs (a list of
-- MAC address strings). Safe to call with an empty list (leaves an empty,
-- harmless table+set+chain in place) and safe to call repeatedly (each call
-- fully replaces the previous state rather than accumulating).
function M.reconcile(blocked_macs)
	M._exec("nft delete table " .. NFT_TABLE .. " 2>/dev/null")
	M._exec("nft add table " .. NFT_TABLE)
	M._exec("nft add set " .. NFT_TABLE .. " blocked_macs '{ type ether_addr; }'")
	for _, mac in ipairs(blocked_macs or {}) do
		if is_mac(mac) then
			M._exec("nft add element " .. NFT_TABLE .. " blocked_macs '{ " .. mac .. " }' 2>/dev/null")
		else
			io.stderr:write(("firewall: ignoring malformed blocked MAC %q\n"):format(tostring(mac)))
		end
	end
	M._exec("nft add chain " .. NFT_TABLE .. " block '{ type filter hook forward priority 0; }'")
	M._exec("nft add rule " .. NFT_TABLE .. " block ether saddr @blocked_macs drop")
	M._exec("nft add rule " .. NFT_TABLE .. " block ether daddr @blocked_macs drop")
	return true
end

-- Immediately kick mac if it's currently associated to any of the given
-- wireless interfaces (ifnames), on top of the nft drop rule from
-- M.reconcile -- the drop rule alone stops future traffic, but a station
-- already associated stays associated (just unable to pass data) until it's
-- actually deauthenticated. Best-effort per interface: a station is only
-- ever associated to one radio at a time, so every other call here is
-- expected to (harmlessly) fail to find it.
function M.deauth(mac, ifnames)
	if not is_mac(mac) then return false end
	for _, ifname in ipairs(ifnames or {}) do
		M._exec("hostapd_cli -i " .. ifname .. " deauthenticate " .. mac .. " 2>/dev/null")
	end
	return true
end

return M
