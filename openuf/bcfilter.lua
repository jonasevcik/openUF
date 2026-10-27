--[[
	"Multicast Suppression" enforcement (Settings -> WiFi -> [WLAN] ->
	Advanced), which the controller used to call "Multicast and Broadcast
	Blocker" and which openUF still reads through the same bcfilt.* keys.

	The controller pushes this per WLAN as wireless.<n>.bcfilt.status plus a
	bcfilt.<k>.mac allow-list -- see inform.lua's parser for the live wire
	evidence. Unlike every other WLAN setting openUF carries, there is no
	hostapd or OpenWrt option for it: hostapd can suppress group-addressed
	frames wholesale (ap_isolate, disable_dgaf) but has no notion of an
	allow-list, so this is enforced with nftables instead.

	THE THREE MODES, and which keys name them:

	The control is Off / Conservative / Aggressive, and no key carries the mode
	name -- it is the PAIR of keys that says which (see inform.lua's vap build).
	The controller describes the two active ones itself: "Limits multicast and
	broadcast traffic to reduce WiFi airtime usage. Conservative prevents
	storms; Aggressive blocks all except DHCP and ARP" (10.6.106 UI).

	- Aggressive: bcfilt.status plus bcfilt.bypass_types=ARP|NSNA|DHCPV4|DHCPV6
	  and the bcfilt.<k>.mac allow-list. Blocks LAN->WLAN group-addressed
	  traffic except those four frame types and the listed senders. The
	  allow-list the controller sends is not only the admin's: it adds every
	  UniFi device MAC in the site and the gateway's LAN peers, which is why its
	  own UI says gateways need not be added by hand.
	- Conservative: the suppressor key alone, with no bcfilt block. A rate
	  ceiling, not a block. The controller sends no number with it, so the rate
	  below is openUF's own choice, documented as such in USAGE.md.
	- Off, or an older controller: nothing arrives and nothing is enforced.

	One case is deliberately left as it was. A controller that sends
	bcfilt.status with NO bypass_types -- the plain old blocker, or the new
	control with its mode left Off while the legacy REST flag is on -- still
	gets a filter that drops ARP and DHCP too. Ubiquiti's older documentation
	described exactly that behaviour and instructed admins to allow-list the
	DHCP server's MAC, so inventing an exemption that controller never asked
	for would change a WLAN that was working as documented.

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
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable: shell command runner, for real `nft` invocations.
M._exec = os.execute

local NFT_TABLE = "bridge openuf_bcfilt"

-- Exactly "aa:bb:cc:dd:ee:ff": every allow-list entry is spliced into an nft
-- command line, so the shape is enforced here as well as at the parser.
local is_mac = util.is_mac
local valid_ifname = util.valid_ifname

-- The nft match for each bcfilt.bypass_types token the controller can send
-- (inform.lua parses the list; see its BCFILT_BYPASS_TYPES for the vocabulary).
-- Order is fixed so the generated ruleset is byte-stable across pushes, which
-- is what makes a rebuilt table comparable to the previous one by eye.
--
-- Every one was accepted by real nft 1.0.9 in the validation container before
-- being written here, the same way the drop rule below was: `ether type ip udp
-- dport ...` parses in the bridge family, and nft itself rewrites the icmpv6
-- form by dropping the redundant `ether type ip6` dependency it infers.
local BYPASS_ORDER = {"ARP", "NSNA", "DHCPV4", "DHCPV6"}
local BYPASS_MATCH = {
	ARP    = "ether type arp",
	NSNA   = "ether type ip6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }",
	DHCPV4 = "ether type ip udp dport { 67, 68 }",
	DHCPV6 = "ether type ip6 udp dport { 546, 547 }",
}

-- Conservative "Multicast Suppression" is a rate ceiling, and the controller
-- sends no number with it -- the key is a bare "enabled" (see inform.lua).
-- These are therefore openUF's own figures, not values read off the wire, and
-- they are stated in USAGE.md as such.
--
-- 100 packets/second with a 50-packet burst. Measured 2026-10-27 over 60 s on
-- both production APs, from each bridge's own
-- /sys/class/net/<br>/statistics/multicast: 3.2 and 3.6 frames/second on the
-- main bridge, 1.4 and 1.5 on the IoT VLAN's. So the ceiling sits roughly 30x
-- above the real idle rate -- ordinary discovery (mDNS, SSDP, IGMP) never
-- reaches it -- while still capping the airtime a storm can take at a 1-6 Mbps
-- basic rate. It is a ceiling, not a target.
local LIMIT_RATE  = "100/second"
local LIMIT_BURST = "50 packets"

-- Rebuild the filter to exactly match rules, a list of
-- {ifname = "wlan0", macs = {"aa:bb:..", ...}} entries -- one per VAP that has
-- the control enabled. A VAP with an empty allow-list still belongs here: that
-- is "block all group-addressed traffic to this SSID", which is a meaningful
-- (if aggressive) setting rather than a no-op.
--
-- Safe with an empty/nil list (leaves an empty table in place, blocking
-- nothing) and safe to call repeatedly.
function M.reconcile(rules)
	local T = NFT_TABLE
	local stmts = {"add chain " .. T .. " bcfilt { type filter hook forward priority 0; }"}
	local drop_of = {}   -- statement index -> the ifname its drop rule is for
	for _, rule in ipairs(rules or {}) do
		if rule.ifname and not valid_ifname(rule.ifname) then
			io.stderr:write(("bcfilter: ignoring odd interface name %q\n"):format(tostring(rule.ifname)))
		elseif rule.ifname then
			-- Conservative "Multicast Suppression" (rule.limit) rate-limits
			-- instead of blocking, so it needs no allow-list and no set: the
			-- ceiling applies to every sender alike.
			local bypass = rule.bypass or {}
			local tail
			if rule.limit then
				tail = "limit rate over " .. LIMIT_RATE .. " burst " .. LIMIT_BURST .. " drop"
			else
				-- One set per interface, so each SSID keeps its own allow-list.
				local set = "allow_" .. rule.ifname:gsub("[^%w]", "_")
				stmts[#stmts + 1] = "add set " .. T .. " " .. set .. " { type ether_addr; }"
				for _, mac in ipairs(rule.macs or {}) do
					if is_mac(mac) then
						stmts[#stmts + 1] = "add element " .. T .. " " .. set .. " { " .. mac .. " }"
					else
						io.stderr:write(("bcfilter: ignoring malformed MAC %q\n")
							:format(tostring(mac)))
					end
				end
				tail = "ether saddr != @" .. set .. " drop"
			end
			-- The bypass types come FIRST: an accept terminates this chain for
			-- the frame, so ARP/ND/DHCP leave before the drop or the limit can
			-- see them. Each accept is pinned to this VAP's own oifname, so one
			-- SSID's exemptions never reach another's.
			--
			-- These arrive only with Aggressive suppression, the only mode the
			-- controller sends bcfilt.bypass_types for. The plain blocker (an
			-- older controller, or the mode left Off) still drops ARP and DHCP,
			-- exactly as it did before -- see the header.
			for _, tok in ipairs(BYPASS_ORDER) do
				if bypass[tok] then
					stmts[#stmts + 1] = "add rule " .. T .. " bcfilt oifname \""
						.. rule.ifname .. "\" " .. BYPASS_MATCH[tok] .. " accept"
				end
			end
			-- Matches group-addressed frames leaving via this VAP (the LAN->WLAN
			-- direction) -- dropped unless the sender is allow-listed, or, under
			-- Conservative suppression, only the excess above the ceiling.
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
			stmts[#stmts + 1] = "add rule " .. T .. " bcfilt oifname \"" .. rule.ifname
				.. "\" meta pkttype { broadcast, multicast } " .. tail
			drop_of[#stmts] = rule.ifname
		end
	end
	local ok, failed = util.nft_apply(T, stmts, M._exec)
	for i = 1, #stmts do
		local ifname = drop_of[i]
		if ifname and failed[i] then
			io.stderr:write(string.format(
				"openuf: Multicast Suppression: nft rejected the pkttype rule " ..
				"for %s -- install kmod-nft-bridge\n" ..
				"openuf: (nft_meta_bridge); without it this WLAN is filtering nothing.\n",
				ifname))
		end
	end
	return ok
end

return M
