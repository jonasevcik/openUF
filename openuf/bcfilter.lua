--[[
	"Multicast and Broadcast Blocker" enforcement (Settings -> WiFi -> [WLAN]).

	The controller pushes this per WLAN as wireless.<n>.bcfilt.status plus a
	bcfilt.<k>.mac allow-list -- see inform.lua's parser for the live wire
	evidence. Unlike every other WLAN setting openUF carries, there is no
	hostapd or OpenWrt option for it: hostapd can suppress group-addressed
	frames wholesale (ap_isolate, disable_dgaf) but has no notion of an
	allow-list, so this is enforced with nftables instead.

	WHAT IT DOES, and why that is deliberately destructive:

	Per Ubiquiti's own documentation this blocks LAN->WLAN multicast and
	broadcast traffic except from the listed source MACs. That genuinely breaks
	DHCP for wireless clients unless the DHCP server's MAC is on the list --
	Ubiquiti documents exactly that, and instructs admins to add it. So the
	filter here is faithful to the controller's intent and deliberately does
	NOT carve out DHCP/ARP exemptions of its own: an admin who enabled this
	control and curated an allow-list would find a silent "helpful" exemption
	harder to debug than the documented behavior.

	The match is on SOURCE MAC in the to-wireless direction: a group-addressed
	frame heading out a managed VAP is dropped unless its sender is
	allow-listed. (Group destinations are not per-station addresses, so a
	destination match could not express an allow-list at all.)

	Mechanism mirrors firewall.lua: a dedicated `bridge` table rebuilt from
	scratch on every reconcile rather than diffed, so it is idempotent and
	self-healing. It uses its OWN table, separate from firewall.lua's `bridge
	openuf` -- that module deletes and recreates its whole table on each
	block/unblock, which would otherwise wipe these rules.

	REQUIRES kmod-nft-bridge. The rule below is the only place openUF uses a
	`meta` expression in the bridge family, and that expression lives in
	nft_meta_bridge.ko -- a module OpenWrt ships in kmod-nft-bridge, which is
	not pulled in by nftables and is absent from a default filogic or ath79
	image. Without it the kernel rejects the rule with a bare
	"Error: Could not process rule: No such file or directory", nft's caret
	pointing at `oifname`. Everything either side of it still succeeds: the
	table, the chain and the per-VAP allow set are all created and populated,
	so the control looks enabled in the controller and on the device while
	filtering nothing at all. That is why a failed rule add warns loudly
	below rather than being left to the reader of a syslog. `ether saddr`
	needs no module, which is why firewall.lua's block-sta table works on the
	same image and hid this for so long.

	VERIFIED on real hardware (AX3000T, mediatek/filogic, nftables 1.1.6,
	kernel 6.12): with the sender not allow-listed, 14 of 14 broadcast frames
	entering the VLAN bridge from the uplink and heading out the IoT VAP
	matched and were dropped; with the same sender allow-listed, 0 of 15
	matched. Both halves of the control do what the controller advertises.
]]--

local M = {}

-- Injectable: shell command runner, for real `nft` invocations.
M._exec = function(cmd) return os.execute(cmd) end

-- os.execute's contract differs across the Lua versions this module runs on:
-- 5.1 (the target) returns the raw exit status, so SUCCESS is the number 0 and
-- failure is a non-zero number -- both truthy. 5.4+ returns ok, "exit", code.
-- A bare `if M._exec(...) then` therefore reports success for every failure on
-- the very interpreter the APs use, which is how the missing module above went
-- unnoticed. Normalise before deciding anything.
local function exec_ok(status)
	if status == nil or status == false then return false end
	if type(status) == "number" then return status == 0 end
	return true
end

local NFT_TABLE = "bridge openuf_bcfilt"

-- Exactly "aa:bb:cc:dd:ee:ff": every allow-list entry is spliced into an nft
-- command line, so the shape is enforced here as well as at the parser.
local function is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

-- Rebuild the filter to exactly match rules, a list of
-- {ifname = "wlan0", macs = {"aa:bb:..", ...}} entries -- one per VAP that has
-- the control enabled. A VAP with an empty allow-list still belongs here: that
-- is "block all group-addressed traffic to this SSID", which is a meaningful
-- (if aggressive) setting rather than a no-op.
--
-- Safe with an empty/nil list (leaves an empty table in place, blocking
-- nothing) and safe to call repeatedly.
function M.reconcile(rules)
	local ok = true
	M._exec("nft delete table " .. NFT_TABLE .. " 2>/dev/null")
	M._exec("nft add table " .. NFT_TABLE)
	M._exec("nft add chain " .. NFT_TABLE ..
		" bcfilt '{ type filter hook forward priority 0; }'")

	for _, rule in ipairs(rules or {}) do
		if rule.ifname then
			-- One set per interface, so each SSID keeps its own allow-list.
			local set = "allow_" .. rule.ifname:gsub("[^%w]", "_")
			M._exec("nft add set " .. NFT_TABLE .. " " .. set ..
				" '{ type ether_addr; }'")
			for _, mac in ipairs(rule.macs or {}) do
				if is_mac(mac) then
					M._exec("nft add element " .. NFT_TABLE .. " " .. set ..
						" '{ " .. mac .. " }' 2>/dev/null")
				else
					io.stderr:write(("bcfilter: ignoring malformed MAC %q\n")
						:format(tostring(mac)))
				end
			end
			-- Matches frames leaving via this VAP (the LAN->WLAN direction)
			-- that are group-addressed and not from an allow-listed sender.
			--
			-- oifname, not oif: `oif` resolves the interface to an index when
			-- the rule is added and so fails outright if it does not exist
			-- yet -- fatal here, since these rules are (re)built around a
			-- `wifi reload` that tears the wireless netdevs down and back up.
			-- oifname matches on the name and tolerates its absence. Both were
			-- checked against nftables 1.0.9: `oif wlan0` errors with
			-- "Interface does not exist", `oifname "wlan0"` accepts.
			--
			-- meta pkttype names broadcast and multicast explicitly; an
			-- earlier draft used `ether daddr type multicast`, which is not
			-- valid nft syntax at all (it parses as far as `type` and stops).
			--
			-- This is the one rule in openUF that needs kmod-nft-bridge (see
			-- the header): when that module is missing the add fails while
			-- the set above still exists, leaving a table that looks built
			-- and filters nothing. Say so, with the package name.
			if not exec_ok(M._exec("nft add rule " .. NFT_TABLE ..
				" bcfilt oifname '\"" .. rule.ifname ..
				"\"' meta pkttype '{ broadcast, multicast }'" ..
				" ether saddr != @" .. set .. " drop")) then
				ok = false
				io.stderr:write(string.format(
					"openuf: Multicast/Broadcast Blocker: nft rejected the drop rule " ..
					"for %s -- install kmod-nft-bridge\n" ..
					"openuf: (nft_meta_bridge); without it this WLAN is filtering nothing.\n",
					tostring(rule.ifname)))
			end
		end
	end
	return ok
end

return M
