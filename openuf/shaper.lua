--[[
	"WiFi Speed Limit" enforcement (Settings -> WiFi -> [WLAN]).

	The controller pushes this per VAP as qos.vap.<m>.dwnlink.maxspeed /
	uplink.1.maxspeed, in kbps, keyed by devname -- see inform.lua's parser for
	the live wire evidence and for why the presence of *maxspeed* (rather than
	of the block, or of the global qos.status) is what marks a VAP as limited.

	Note the control only becomes assignable once a speed-limit *profile*
	exists in the site settings; with no profile the per-WLAN toggle has
	nothing to select and nothing reaches the wire.

	Neither hostapd nor OpenWrt's wifi-iface schema has any notion of a
	throughput cap, so this is enforced with tc, the same way bcfilter.lua
	reaches for nftables.

	WHAT IT DOES:

	The cap is a per-VAP aggregate, not per-client -- it applies to the netdev
	as a whole, so all clients on that SSID share the ceiling. That is what the
	wire describes (one maxspeed per vap devname, no per-station structure) and
	it is why one qdisc per VAP is sufficient.

	  * Downlink (AP -> clients) is egress on the VAP netdev: an HTB root qdisc
	    with a single rate-capped default class.
	  * Uplink (clients -> LAN) is ingress on the VAP netdev: an ingress qdisc
	    with a match-everything u32 filter carrying a police action. Ingress
	    cannot be queued, only policed, so excess traffic is dropped rather
	    than delayed -- TCP backs off, which is the standard mechanism.

	The stock firmware would instead replay the qos.ebt.<n>.cmd ebtables
	fragments that fwmark each VAP; openUF implements the intent directly on
	the netdev, since ebtables is not a given on OpenWrt while tc is part of
	the base iproute2.

	Mechanism mirrors bcfilter.lua/firewall.lua: rebuilt from scratch on every
	reconcile rather than diffed, so it is idempotent and self-healing, and an
	empty rule list tears down any previous shaping.

	Every command emitted here was checked against real tc (iproute2 6.9.0) on
	a dummy netdev before being committed -- including the explicit `quantum`,
	without which HTB warns "quantum of class ... is big. Consider r2q change."
	NOT verified against real hardware or real radios: what is confirmed is the
	wire format and that the generated commands are accepted by tc, not the
	on-air throughput they produce.
]]--

local M = {}

-- Injectable: shell command runner, for real `tc` invocations.
M._exec = function(cmd) return os.execute(cmd) end

-- os.execute returns the raw exit status on Lua 5.1 (0 = success, non-zero =
-- failure, and BOTH are truthy) and ok/"exit"/code on 5.4+. Same normalisation
-- as bcfilter.lua, for the same reason: a bare truth test passes for a failed
-- tc call on the interpreter the APs actually run.
local function exec_ok(status)
	if status == nil or status == false then return false end
	if type(status) == "number" then return status == 0 end
	return true
end
M._exec_ok = exec_ok

-- Deleting a qdisc that is not there exits non-zero and prints to stderr, so
-- teardown is always silenced and its status ignored -- reconcile has to be
-- safe to call on an unshaped interface.
local function clear(ifname)
	M._exec("tc qdisc del dev " .. ifname .. " root 2>/dev/null")
	M._exec("tc qdisc del dev " .. ifname .. " ingress 2>/dev/null")
end

-- Rebuild shaping to exactly match rules, a list of
-- {ifname = "wlan0", down_kbps = 33000, up_kbps = 17000} entries -- one per
-- VAP that has a limit. Either direction may be nil, meaning "uncapped in
-- that direction"; a VAP with neither does not belong in the list at all.
--
-- Callers must pass every managed VAP they want *cleared* as well, or rather:
-- clearing is the caller's business only in the sense that this function
-- clears each interface it is given before reshaping it. Interfaces absent
-- from the list are left alone, so the caller (ucihelper.apply_config) hands
-- over every managed VAP, capped or not.
--
-- Safe with an empty/nil list and safe to call repeatedly.
function M.reconcile(rules)
	local ok = true
	for _, rule in ipairs(rules or {}) do
		if rule.ifname then
			clear(rule.ifname)

			if rule.down_kbps then
				-- Egress: HTB with one class, everything defaulting into it.
				M._exec("tc qdisc add dev " .. rule.ifname ..
					" root handle 1: htb default 10")
				-- quantum is set explicitly rather than derived from r2q:
				-- at these rates the default derivation trips HTB's
				-- "quantum ... is big" warning. 1514 is one full Ethernet
				-- frame, the conventional choice for a single-class setup.
				M._exec("tc class add dev " .. rule.ifname ..
					" parent 1: classid 1:10 htb rate " .. rule.down_kbps ..
					"kbit ceil " .. rule.down_kbps .. "kbit quantum 1514")
			end

			if rule.up_kbps then
				-- Ingress: policing only, no queueing possible.
				M._exec("tc qdisc add dev " .. rule.ifname ..
					" handle ffff: ingress")
				-- `u32 match u32 0 0` is the idiomatic match-everything
				-- filter. burst is sized at one tenth of a second of the
				-- configured rate (kbit/10 -> kbit of burst), the usual
				-- rule of thumb; too small a burst throttles well under
				-- the nominal rate.
				local burst = math.max(math.floor(rule.up_kbps / 10), 32)
				-- The police ACTION is its own kernel module (act_police, in
				-- kmod-sched-act-police), separate from the ingress qdisc and
				-- not in every image: a stock filogic build has sch_htb,
				-- sch_ingress, act_gact and act_mirred but no act_police, so
				-- this one call fails with "Failed to load TC action module"
				-- while the download cap above applies -- half a feature
				-- reporting success. install.sh installs the module; this says
				-- so when it is still missing, the way bcfilter.lua does for
				-- kmod-nft-bridge.
				if not exec_ok(M._exec("tc filter add dev " .. rule.ifname ..
					" parent ffff: protocol all prio 1 u32 match u32 0 0" ..
					" police rate " .. rule.up_kbps .. "kbit burst " ..
					burst .. "k drop flowid :1")) then
					ok = false
					io.stderr:write(string.format(
						"openuf: WiFi Speed Limit: tc rejected the upload police filter " ..
						"for %s -- install kmod-sched-act-police (act_police); the " ..
						"download cap applies, the upload cap does not.\n",
						tostring(rule.ifname)))
				end
			end
		end
	end
	return ok
end

return M
