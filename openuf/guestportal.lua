--[[
	Guest portal (Hotspot) enforcement: the controller's guest ebtables rules,
	re-expressed in nftables, plus the HTTP answer that sends an unauthorized
	guest to the portal. LAB-VALIDATED ONLY (2026-10-10): never run against a
	real guest WLAN on the production APs.

	What the controller pushes (PROTOCOL-VALIDATION.md, "Guest portal
	(Hotspot)"): a GUESTIN chain on every guest VAP's ingress (policy DROP)
	and a GUESTOUT chain on its egress, ~47 ebtables fragments in all, plus
	redirector.url (the portal) and three iptables REDIRECTs for the frames
	the ebtables rules mark. The stock firmware's own parts are the
	AUTHORIZED_GUESTS chain -- pushed empty, the device fills it from
	authorize-guest -- and a local HTTP/DNS answerer for the marked frames.

	Not a verbatim translator. parse() reads the facts the rules carry: the
	(ip, port) pairs a guest may always reach (the portal), the ones to
	answer locally (`-I GUESTIN ... -j REDIRECT_HTTP`), and the subnets
	dropped either way. reconcile() builds openUF's own chains from them, in
	the stock order:

	  in:  EAPOL, portal accepts, intercepts, broadcast DHCP request, ARP,
	       DNS -> accept; IPv6, other broadcast, multicast, restricted
	       subnets -> drop; authorized MAC to another host -> accept;
	       tcp 80 -> local answer; everything else -> drop
	  out: DHCP reply, ARP -> accept; IPv6, other broadcast, multicast -> drop

	After the authorized accept, a `selfrun` chain that lets every guest
	through while the controller is unreachable (set_selfrun); with
	selfrun_guest_mode=off the guest VAPs go down instead (inform._guest_selfrun).

	The walled garden ("Pre-Authorization Access") arrives in two halves, and
	the controller splits them by what the entry looks like
	(`com/ubnt/service/config/hyFnQ`, 10.6.106): every `allowed_subnet_<n>` /
	`restricted_subnet_<n>` that parses as an IP or CIDR becomes an ebtables
	rule, and every one that is a domain name (Guava
	`InternetDomainName.isValid`) becomes a `dnsmasq.walled_garden.1.site.<n>.
	{allowed,restricted}` key. parse() reads both:

	- the IP half as port-less `-I GUESTIN -p 0x800 --ip-dst <net> -j ACCEPT`
	  and its `-I GUESTOUT ... --ip-src <net>` twin (spec.accept with no port,
	  and spec.accept_out). The portal's own accepts carry a port; a garden
	  entry does not, which is why it needed its own shape.
	- the domain half as spec.wg_allowed / spec.wg_restricted, names only.
	  Resolving them is the device's job: the firmware's `/bin/walled_action.sh`
	  (U7LR 6.8.2) runs `nslookup` over each name twice, dedupes the IPv4
	  answers and fills three chains (ALLOWED_DOMAIN_IN by --ip-dst,
	  ALLOWED_DOMAIN_OUT by --ip-src, RESTRICTED_DOMAIN_IN by --ip-dst), and
	  the controller pushes a `*/10 * * * *` cron job
	  (`syswrapper.sh refresh-walled-garden 1`) to redo it. openUF resolves
	  through M._resolve, keeps the last good answer per name
	  (state.json's guest_wg_ips) and re-resolves on the same ten minutes
	  (inform._guest_wg_resync), so a name that stops resolving neither opens
	  nor closes the garden on its own.

	Deliberate narrowings, all of them stated in README/USAGE:
	- The garden is IPv4 only, and resolved on the AP: a name whose answer
	  differs from the client's (a CDN, round-robin DNS) can be reachable by an
	  address openUF never saw. The firmware has the same limit.
	- A domain-only `restricted` list never arrives: the controller emits the
	  whole `dnsmasq.walled_garden` block only when the ALLOWED set is
	  non-empty, so restricted domains are dropped on its side (10.6.106).
	- DNS passes for every guest. The stock firmware answers an unauthorized
	  guest's DNS itself (dnsmasq on br0); openUF runs no resolver, and a
	  captive-portal check needs real answers to reach the HTTP step at all.
	- No HTTPS answer. Marked 443 would need a certificate the client
	  trusts; it is dropped, so the client's HTTP probe is what finds the
	  portal.
	- The local answer needs an IPv4 address on the guest VAP's bridge: the
	  frame is handed to the bridge's own stack (ebtables `redirect`, here
	  `ether daddr set` + `pkttype set host`) and NAT-redirected to M.PORT,
	  and the reply leaves from that bridge. A guest WLAN on a VLAN bridge
	  without an address stays blocked but sees no portal.

	Mechanism as in firewall.lua/l2guard.lua: own tables, rebuilt from
	scratch on every reconcile, kernel state that dies with a reboot and is
	rebuilt at startup from state.json, each rebuild one nft transaction
	(util.nft_apply). The authorized set alone is refreshed in place
	(set_authorized), so an authorize-guest does not open a gap in the rest.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M._exec = os.execute

M.BRIDGE_TABLE = "bridge openuf_guest"
M.NAT_TABLE    = "ip openuf_guest"
-- The stock REDIRECT_HTTP mark; the iptables side matches it under
-- 0xc0000000.
M.MARK_HTTP    = "0x40000000"
-- Where the NAT-redirected HTTP is answered. Not 80: uhttpd/LuCI may hold it.
M.PORT         = 8820

-- Names per list the garden will resolve. Each one costs two blocking
-- nslookups, and a blackholed resolver takes 5 s per lookup (musl's res_msend
-- cap, measured on the Archer C5), so an unbounded list is a stall measured in
-- minutes on a daemon whose heartbeat is 10 s. The controller's own UI offers
-- no such list length; anything past this is dropped with a line in the log.
M.WG_MAX_SITES = 32

-- ─── Parsing ─────────────────────────────────────────────────────────────────

local function is_ipv4(s)
	if type(s) ~= "string" then return false end
	local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return false end
	for _, o in ipairs({a, b, c, d}) do
		if tonumber(o) > 255 then return false end
	end
	return true
end

local function is_cidr(s)
	if type(s) ~= "string" then return false end
	local ip, len = s:match("^([%d%.]+)/(%d+)$")
	if ip then return is_ipv4(ip) and tonumber(len) <= 32 end
	return is_ipv4(s)
end

local function is_port(s)
	local n = tonumber(s)
	return n ~= nil and n >= 1 and n <= 65535 and n == math.floor(n)
end

-- A walled-garden site name, as strictly as the controller validates it before
-- sending it (Guava's InternetDomainName.isValid, read in 10.6.106): up to 253
-- characters of dot-separated labels, each 1-63 of letters, digits, '-' and
-- '_', none starting or ending with '-', and a rightmost label that is not all
-- digits -- which is what keeps an IPv4 literal out of this list, since those
-- entries travel as ebtables rules instead. One trailing dot is a valid
-- absolute name and is kept. Strict because the name reaches a resolver call:
-- no spaces, no shell metacharacters, nothing else.
function M.is_hostname(s)
	if type(s) ~= "string" or #s < 1 or #s > 253 then return false end
	local body = s:gsub("%.$", "")
	if body == "" or body:find("%.%.") then return false end
	local last
	for label in (body .. "."):gmatch("([^%.]*)%.") do
		if #label < 1 or #label > 63 then return false end
		if label:find("[^%w_%-]") then return false end
		if label:sub(1, 1) == "-" or label:sub(-1) == "-" then return false end
		last = label
	end
	return last ~= nil and last:match("^%d+$") == nil
end

-- The fixed skeleton of the guest ruleset: chain declarations and rules the
-- chains above re-create by construction. %S+ stands for a VAP name.
local SKELETON = {
	"^%-t nat %-N GUESTIN %-P DROP$",
	"^%-t nat %-N GUESTOUT %-P ACCEPT$",
	"^%-t nat %-A POSTROUTING %-%-out%-interface %S+ %-j GUESTOUT$",
	"^%-t nat %-A GUESTIN %-%-in%-interface %S+ %-%-proto 0x888e %-j ACCEPT$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-pkttype%-type broadcast %-%-ip%-proto 17 %-%-ip%-sport 68 %-%-ip%-dport 67 %-j ACCEPT$",
	"^%-t nat %-A GUESTIN %-p arp %-j ACCEPT$",
	"^%-t nat %-N GUEST_DNS %-P DROP$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j GUEST_DNS$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j GUEST_DNS$",
	"^%-t nat %-A GUESTIN %-p 0x86dd %-j DROP$",
	"^%-t nat %-A GUESTIN %-%-pkttype%-type broadcast %-j DROP$",
	"^%-t nat %-A GUESTOUT %-p 0x800 %-%-pkttype%-type broadcast %-%-ip%-proto 17 %-%-ip%-sport 67 %-%-ip%-dport 68 %-j ACCEPT$",
	"^%-t nat %-A GUESTOUT %-p arp %-j ACCEPT$",
	"^%-t nat %-A GUESTOUT %-p 0x86dd %-j DROP$",
	"^%-t nat %-A GUESTOUT %-%-pkttype%-type broadcast %-j DROP$",
	"^%-t nat %-N CAPTIVE_PORTAL %-P RETURN$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 443 %-j CAPTIVE_PORTAL$",
	"^%-t nat %-N REDIRECT_HTTP$",
	"^%-t nat %-A REDIRECT_HTTP %-j mark %-%-mark%-or 0x40000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_HTTP %-j redirect$",
	"^%-t nat %-N REDIRECT_HTTPS$",
	"^%-t nat %-A REDIRECT_HTTPS %-j mark %-%-mark%-or 0x80000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_HTTPS %-j redirect$",
	"^%-t nat %-N AUTHORIZED_GUESTS %-P RETURN$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-pkttype%-type otherhost %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 80 %-j REDIRECT_HTTP$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 443 %-j REDIRECT_HTTPS$",
	"^%-t nat %-N REDIRECT_DNS$",
	"^%-t nat %-A REDIRECT_DNS %-j mark %-%-mark%-or 0x40000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_DNS %-j redirect$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j REDIRECT_DNS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j REDIRECT_DNS$",
	-- The domain half of the walled garden: the chains walled_action.sh fills
	-- from the dnsmasq.walled_garden keys, and the jumps into them. openUF
	-- resolves the names itself and emits the rules inline, so the
	-- declarations carry nothing of their own -- but they must be known, or
	-- every push with a garden domain in it is reported as unrecognised.
	"^%-t nat %-N ALLOWED_DOMAIN_IN %-P RETURN$",
	"^%-t nat %-I GUESTIN %-p 0x800 %-j ALLOWED_DOMAIN_IN$",
	"^%-t nat %-N ALLOWED_DOMAIN_OUT %-P RETURN$",
	"^%-t nat %-I GUESTOUT %-p 0x800 %-j ALLOWED_DOMAIN_OUT$",
	"^%-t nat %-N RESTRICTED_DOMAIN_IN %-P RETURN$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-j RESTRICTED_DOMAIN_IN$",
}

-- Chains only the guest ruleset uses: a rule naming one of them is the
-- portal's, whether or not parse() knows its shape.
local GUEST_CHAINS = {"GUESTIN", "GUESTOUT", "GUEST_DNS", "CAPTIVE_PORTAL",
	"REDIRECT_HTTP", "REDIRECT_HTTPS", "REDIRECT_DNS", "AUTHORIZED_GUESTS",
	"ALLOWED_DOMAIN_IN", "ALLOWED_DOMAIN_OUT", "RESTRICTED_DOMAIN_IN"}

-- Whether an ebtables fragment belongs to the guest ruleset (l2guard leaves
-- these to this module rather than reporting them as unrecognised).
function M.is_guest_rule(v)
	if type(v) ~= "string" then return false end
	for _, c in ipairs(GUEST_CHAINS) do
		if (" " .. v .. " "):find(" " .. c .. " ", 1, true) then return true end
	end
	return false
end

-- One guest-ruleset fragment into spec. Returns false when the shape is
-- not known.
local function classify(v, spec)
	local dev = v:match("^%-t nat %-A PREROUTING %-%-in%-interface (%S+) %-j GUESTIN$")
	if dev then
		spec.devs[#spec.devs + 1] = dev
		return true
	end
	for _, p in ipairs(SKELETON) do
		if v:match(p) then return true end
	end
	local port, ip = v:match("^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-%-ip%-dst (%S+) %-j ACCEPT$")
	if not port then
		ip, port = v:match("^%-t nat %-I GUESTIN %-p 0x800 %-%-ip%-dst (%S+) %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-j ACCEPT$")
	end
	if port then
		if not (is_ipv4(ip) and is_port(port)) then return false end
		spec.accept[#spec.accept + 1] = {ip = ip, port = tonumber(port)}
		return true
	end
	ip, port = v:match("^%-t nat %-I GUESTIN %-p 0x800 %-%-ip%-dst (%S+) %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-j REDIRECT_HTTP$")
	if ip then
		if not (is_ipv4(ip) and is_port(port)) then return false end
		spec.intercept[#spec.intercept + 1] = {ip = ip, port = tonumber(port)}
		return true
	end
	-- The IP half of the walled garden: no port, and both directions.
	local net = v:match("^%-t nat %-I GUESTIN %-p 0x800 %-%-ip%-dst (%S+) %-j ACCEPT$")
	if net then
		if not is_cidr(net) then return false end
		spec.accept[#spec.accept + 1] = {ip = net}
		return true
	end
	net = v:match("^%-t nat %-I GUESTOUT %-p 0x800 %-%-ip%-src (%S+) %-j ACCEPT$")
	if net then
		if not is_cidr(net) then return false end
		spec.accept_out[#spec.accept_out + 1] = net
		return true
	end
	local chain
	chain, net = v:match("^%-t nat %-A (GUEST[IO][NU]T?) %-p 0x800 %-%-ip%-dst (%S+) %-j DROP$")
	if chain == "GUESTIN" or chain == "GUESTOUT" then
		if not is_cidr(net) then return false end
		local list = chain == "GUESTIN" and spec.restrict or spec.restrict_out
		list[#list + 1] = net
		return true
	end
	return false
end

-- The portal as pushed, or nil when the blob does not say (no
-- redirector.status: a partial push). enabled is false when the portal is
-- off, or on but without the facts to enforce it (no URL, no GUESTIN hook).
function M.parse(sys_raw)
	if type(sys_raw) ~= "string" then return nil end
	local spec = {enabled = false, devs = {}, accept = {}, accept_out = {},
		intercept = {}, restrict = {}, restrict_out = {},
		wg_allowed = {}, wg_restricted = {}, unknown = {}}
	local status, wg_status
	local wg_rows = {allowed = {}, restricted = {}}
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		local k, v = line:match("^([^=]+)=(.*)$")
		if k == "redirector.status" then
			status = v
		elseif k == "redirector.url" then
			-- Spliced into a Location header: one token, http(s) only.
			if v:match("^https?://[%w%.%-:%[%]]+[%S]*$") and not v:find("[%c\"<>\\]") then
				spec.url = v
			end
		elseif k and k:match("^ebtables%.%d+%.cmd$") and M.is_guest_rule(v) then
			if not classify(v, spec) then spec.unknown[#spec.unknown + 1] = v end
		elseif k and k:match("^dnsmasq%.walled_garden%.%d+%.") then
			local g, n, which = k:match("^dnsmasq%.walled_garden%.(%d+)%.site%.(%d+)%.(%a+)$")
			if g and wg_rows[which] then
				local rows = wg_rows[which]
				rows[#rows + 1] = {g = tonumber(g), n = tonumber(n), name = v}
			elseif k:match("^dnsmasq%.walled_garden%.%d+%.status$") then
				-- Only ever index 1 so far; one status for the whole garden.
				wg_status = v
			end
		end
	end
	-- The garden's domain half, in push order (the controller iterates a Java
	-- Set, so its own order is arbitrary and the index is all there is), with
	-- the two lists indexed independently from 1.
	if wg_status == "enabled" then
		for _, which in ipairs({"allowed", "restricted"}) do
			local rows = wg_rows[which]
			table.sort(rows, function(a, b)
				if a.g ~= b.g then return a.g < b.g end
				return a.n < b.n
			end)
			local out, seen = {}, {}
			for _, r in ipairs(rows) do
				if not M.is_hostname(r.name) then
					io.stderr:write("guestportal: ignoring malformed walled-garden site "
						.. ("%q"):format(tostring(r.name)) .. "\n")
				elseif not seen[r.name] then
					seen[r.name] = true
					if #out >= M.WG_MAX_SITES then
						io.stderr:write(("guestportal: walled garden: more than %d %s "
							.. "sites pushed -- %q and any after it are not enforced\n")
							:format(M.WG_MAX_SITES, which, r.name))
						break
					end
					out[#out + 1] = r.name
				end
			end
			spec[which == "allowed" and "wg_allowed" or "wg_restricted"] = out
		end
	end
	if status == nil then return nil end
	spec.enabled = (status == "enabled" and spec.url ~= nil and #spec.devs > 0)
	return spec
end

-- ─── Apply ───────────────────────────────────────────────────────────────────

local valid_ifname = util.valid_ifname

local is_mac = util.is_mac

M._read = util.read_file

-- ─── The walled garden's domain half ────────────────────────────────────────

-- Every IPv4 a name resolves to, in the resolver's order. The seam the tests
-- replace; the default is the device's own resolver, which is what the UniFi
-- firmware's walled_action.sh uses (U7LR 6.8.2). Addresses are taken only
-- after the first "Name:" line -- the lines before it are the resolver's own
-- address, the same cut walled_action.sh's awk makes. Both output shapes are
-- read: "Address 1: <ip>" (the firmware's busybox) and the repeated
-- "Name:"/"Address: <ip>" pairs of OpenWrt 25.12's nslookup. AAAA answers
-- fall out on is_ipv4, since the chains are IPv4-only on both sides.
M._capture = util.capture
M._resolve = function(name)
	local out = {}
	if not M.is_hostname(name) then return out end
	local named = false
	for line in ((M._capture("nslookup " .. name) or "") .. "\n"):gmatch("([^\n]*)\n") do
		if line:match("^Name:") then
			named = true
		elseif named then
			local a = line:match("^Address%s*%d*:%s*(%S+)")
			if a and is_ipv4(a) then out[#out + 1] = a end
		end
	end
	return out
end

-- Resolve every name in names, keeping prev's answer for one that resolves to
-- nothing: a name that stops resolving must not quietly open the garden (an
-- allowed site) or close it (a restricted one). Names no longer pushed are
-- dropped. Like walled_action.sh, each name is asked twice and the answers
-- merged, so a round-robin record does not shrink the set on alternate runs.
--
-- `budget` is how many seconds of wall clock the whole pass may spend asking:
-- M._resolve blocks, and the daemon that calls this has a heartbeat to keep.
-- Past it no further name is asked; the names already done are kept, the rest
-- fall back on prev exactly as a name that failed to resolve does, and the
-- fourth return value says the pass was cut short so the caller can come back
-- sooner. A budget, not a deadline, so the clock is only ever M._now() --
-- inform.lua's own M._time is a different, test-stubbed one.
--
-- Returns the new {name = {ip, ...}} map, how many names could not be
-- resolved, whether the flattened address set changed, and whether the pass
-- ran out of time.
M._now = os.time
function M.resolve_garden(names, prev, budget)
	prev = type(prev) == "table" and prev or {}
	local map, failed, partial, said = {}, 0, false, false
	local deadline = tonumber(budget) and (M._now() + budget) or nil
	for _, name in ipairs(names or {}) do
		local out_of_time = deadline and M._now() >= deadline
		local ips, seen = {}, {}
		if not out_of_time then
			for n = 1, 2 do
				-- Also between the two asks, so one name can overrun the
				-- deadline by at most a single lookup.
				if n == 2 and deadline and M._now() >= deadline then
					partial = true
					break
				end
				for _, ip in ipairs(M._resolve(name) or {}) do
					if not seen[ip] then
						seen[ip] = true
						ips[#ips + 1] = ip
					end
				end
			end
		end
		if #ips > 0 then
			map[name] = ips
		else
			-- One line for the whole cut-off, not one per name left: the names
			-- after the deadline were never asked, so "did not resolve" would
			-- be wrong about every one of them.
			if out_of_time then
				if not said then
					said = true
					io.stderr:write("guestportal: walled garden: out of time at "
						.. name .. " -- the names from here on keep their last "
						.. "answer until the next refresh\n")
				end
				partial = true
				map[name] = prev[name]
			elseif prev[name] then
				failed = failed + 1
				io.stderr:write("guestportal: walled garden: " .. name
					.. " did not resolve -- keeping the last " .. #prev[name] .. " address(es)\n")
				map[name] = prev[name]
			else
				failed = failed + 1
				io.stderr:write("guestportal: walled garden: " .. name
					.. " did not resolve and has no earlier answer -- not enforced\n")
			end
		end
	end
	local function flat(m)
		local l = {}
		for _, ips in pairs(m) do for _, ip in ipairs(ips) do l[#l + 1] = ip end end
		table.sort(l)
		return table.concat(l, " ")
	end
	return map, failed, flat(map) ~= flat(prev), partial
end

-- A {name = {ip, ...}} map as one sorted, deduplicated address list, which is
-- what the rules are built from: two names behind the same CDN address must
-- not become two identical rules.
function M.garden_ips(map)
	local seen, out = {}, {}
	for _, ips in pairs(type(map) == "table" and map or {}) do
		for _, ip in ipairs(ips) do
			if is_ipv4(ip) and not seen[ip] then
				seen[ip] = true
				out[#out + 1] = ip
			end
		end
	end
	table.sort(out)
	return out
end

-- The MAC of the bridge a VAP is enslaved to, or nil when it is not bridged.
function M.bridge_mac(ifname)
	if not valid_ifname(ifname) then return nil end
	local raw = M._read("/sys/class/net/" .. ifname .. "/master/address")
	local mac = raw and raw:match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
	return mac and mac:lower() or nil
end

-- The statement that puts macs (a list) into the authorized set, or nil when
-- none is valid.
local function authorized_stmt(macs)
	local list = {}
	for _, mac in ipairs(macs or {}) do
		if is_mac(mac) then list[#list + 1] = mac:lower() end
	end
	if #list == 0 then return nil end
	return "add element " .. M.BRIDGE_TABLE .. " authorized { " .. table.concat(list, ", ") .. " }"
end

local SELFRUN_RULE = "add rule %s selfrun meta pkttype other accept"

-- Refill the authorized set from macs (a list), flush and refill in one
-- transaction: an authorized guest is never dropped in between. False when
-- the table is not there.
function M.set_authorized(macs)
	local add = authorized_stmt(macs)
	return util.nft_run("flush set " .. M.BRIDGE_TABLE .. " authorized\n"
		.. (add and add .. "\n" or ""), M._exec, true)
end

-- selfrun_guest_mode=pass while the controller is unreachable (the firmware's
-- AUTHORIZED_GUESTS ACCEPT-all): every guest
-- is let through as an authorized one would be (to other hosts only, and
-- still not into the restricted subnets), since nobody can log in to the
-- portal meanwhile. An empty chain otherwise. Refreshed in place.
function M.set_selfrun(pass)
	return util.nft_run("flush chain " .. M.BRIDGE_TABLE .. " selfrun\n"
		.. (pass and SELFRUN_RULE:format(M.BRIDGE_TABLE) .. "\n" or ""), M._exec, true)
end

-- Rebuild both tables for spec on these VAPs ({ifname=, bridge_mac=}), with
-- macs authorized and selfrun (see set_selfrun) applied, and garden
-- ({allowed = {ip, ...}, restricted = {ip, ...}}, the resolved domain half of
-- the walled garden) enforced. Returns the number of rules installed (0,
-- tables gone, when there is nothing to enforce or nothing to enforce it on).
function M.reconcile(spec, vaps, macs, selfrun, garden)
	local tables = {M.BRIDGE_TABLE, M.NAT_TABLE}
	if type(spec) ~= "table" or not spec.enabled then
		util.nft_apply(tables, nil, M._exec)
		return 0
	end
	local names, redirect = {}, {}
	for _, v in ipairs(vaps or {}) do
		if valid_ifname(v.ifname) then
			names[#names + 1] = '"' .. v.ifname .. '"'
			if is_mac(v.bridge_mac) then redirect[#redirect + 1] = v end
		else
			io.stderr:write("guestportal: ignoring odd interface name "
				.. ("%q"):format(tostring(v.ifname)) .. "\n")
		end
	end
	if #names == 0 then
		util.nft_apply(tables, nil, M._exec)
		io.stderr:write("guestportal: no guest interfaces up yet -- rules deferred\n")
		return 0
	end
	local T = M.BRIDGE_TABLE
	local set = "{ " .. table.concat(names, ", ") .. " }"

	local rules = {
		{"pre",  "iifname " .. set .. " jump guestin"},
		{"post", "oifname " .. set .. " jump guestout"},
		{"guestin", "ether type 0x888e accept"},
	}
	local function add(chain, rule) rules[#rules + 1] = {chain, rule} end
	garden = type(garden) == "table" and garden or {}
	-- The controller inserts these at the top (-I): ahead of every drop.
	for _, a in ipairs(spec.intercept) do
		add("guestin", "ip daddr " .. a.ip .. " tcp dport " .. a.port .. " jump redirect_http")
	end
	-- ALLOWED_DOMAIN_IN, inserted above the garden's IP accepts.
	for _, ip in ipairs(garden.allowed or {}) do
		add("guestin", "ip daddr " .. ip .. " accept")
	end
	-- The portal's own accepts carry a port; a walled-garden IP entry does not.
	for _, a in ipairs(spec.accept) do
		add("guestin", "ip daddr " .. a.ip
			.. (a.port and (" tcp dport " .. a.port) or "") .. " accept")
	end
	add("guestin", "meta pkttype broadcast udp sport 68 udp dport 67 accept")
	add("guestin", "ether type arp accept")
	add("guestin", "ether type ip udp dport 53 accept")
	add("guestin", "ether type ip tcp dport 53 accept")
	add("guestin", "ether type ip6 drop")
	add("guestin", "meta pkttype broadcast drop")
	-- RESTRICTED_DOMAIN_IN: a drop among the restricted-subnet drops, so like
	-- them it holds for an authorized guest too.
	for _, ip in ipairs(garden.restricted or {}) do
		add("guestin", "ip daddr " .. ip .. " drop")
	end
	for _, net in ipairs(spec.restrict) do
		add("guestin", "ip daddr " .. net .. " drop")
	end
	-- AUTHORIZED_GUESTS: --pkttype-type otherhost, i.e. not to the AP itself.
	add("guestin", "ether saddr @authorized meta pkttype other accept")
	add("guestin", "jump selfrun")
	add("guestin", "tcp dport 80 jump redirect_http")
	add("guestin", "drop")
	add("redirect_http", "meta mark set meta mark or " .. M.MARK_HTTP)
	for _, v in ipairs(redirect) do
		add("redirect_http", 'iifname "' .. v.ifname .. '" ether daddr set ' .. v.bridge_mac:lower()
			.. " meta pkttype set host accept")
	end
	add("redirect_http", "drop")
	-- ALLOWED_DOMAIN_OUT and the garden's IP accepts, both by source address
	-- and both inserted at the top of GUESTOUT by the controller.
	for _, ip in ipairs(garden.allowed or {}) do
		add("guestout", "ip saddr " .. ip .. " accept")
	end
	for _, net in ipairs(spec.accept_out or {}) do
		add("guestout", "ip saddr " .. net .. " accept")
	end
	add("guestout", "meta pkttype broadcast udp sport 67 udp dport 68 accept")
	add("guestout", "ether type arp accept")
	add("guestout", "ether type ip6 drop")
	add("guestout", "meta pkttype broadcast drop")
	for _, net in ipairs(spec.restrict_out) do
		add("guestout", "ip daddr " .. net .. " drop")
	end

	local stmts = {
		"add set " .. T .. " authorized { type ether_addr; }",
		"add chain " .. T .. " pre { type filter hook prerouting priority -300; policy accept; }",
		"add chain " .. T .. " post { type filter hook postrouting priority 0; policy accept; }",
		"add chain " .. T .. " guestin",
		"add chain " .. T .. " guestout",
		"add chain " .. T .. " redirect_http",
		"add chain " .. T .. " selfrun",
	}
	local first = #stmts + 1
	for _, r in ipairs(rules) do
		stmts[#stmts + 1] = "add rule " .. T .. " " .. r[1] .. " " .. r[2]
	end
	local last = #stmts
	stmts[#stmts + 1] = authorized_stmt(macs)
	if selfrun then stmts[#stmts + 1] = SELFRUN_RULE:format(T) end
	-- The marked frames reach the bridge's own stack; send them to M.PORT.
	stmts[#stmts + 1] = "add chain " .. M.NAT_TABLE .. " pre { type nat hook prerouting priority -101; }"
	stmts[#stmts + 1] = "add rule " .. M.NAT_TABLE .. " pre meta mark and 0xc0000000 == " .. M.MARK_HTTP
		.. " meta l4proto tcp redirect to :" .. M.PORT
	local _, bad = util.nft_apply(tables, stmts, M._exec)

	local n, failed = 0, 0
	for i = first, last do
		if bad[i] then
			failed = failed + 1
			io.stderr:write("openuf: guestportal: nft rejected " .. ("%q"):format(rules[i - first + 1][2]) .. "\n")
		else
			n = n + 1
		end
	end
	if failed > 0 then
		io.stderr:write("openuf: guestportal: " .. failed .. " rule(s) not installed; iifname/oifname in "
			.. "the bridge family need kmod-nft-bridge. The guest portal is NOT fully enforced.\n")
	end
	if bad[#stmts] then
		io.stderr:write("openuf: guestportal: nft rejected the NAT redirect (kmod-nft-nat?). "
			.. "Guests stay blocked but are not shown the portal.\n")
	else
		n = n + 1
	end
	if #redirect < #names then
		io.stderr:write("openuf: guestportal: " .. (#names - #redirect) .. " guest interface(s) not "
			.. "bridged; their guests are blocked but not shown the portal\n")
	end
	return n
end

-- ─── The HTTP answer ────────────────────────────────────────────────────────

local function urlencode(s)
	return (tostring(s):gsub("[^%w%-%._~]", function(c)
		return string.format("%%%02X", c:byte())
	end))
end

-- The station MAC behind an IPv4 address, from /proc/net/arp's text.
function M.arp_mac(ip, text)
	for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
		local a, flags, mac = line:match("^(%S+)%s+%S+%s+(%S+)%s+(%S+)")
		if a == ip and tonumber(flags) and tonumber(flags) % 4 >= 2 and is_mac(mac)
				and mac ~= "00:00:00:00:00:00" then
			return mac:lower()
		end
	end
	return nil
end

-- Where the portal is: the controller's redirect handler takes the guest
-- from id=, the AP from ap=, and refuses a t= more than 60 s from its own
-- clock (PROTOCOL-VALIDATION.md, "Guest portal (Hotspot)").
function M.location(ctx, mac, orig_url, ssid, now)
	local q = {"id=" .. urlencode(mac), "ap=" .. urlencode(ctx.ap or ""), "t=" .. string.format("%.0f", now)}
	if orig_url then q[#q + 1] = "url=" .. urlencode(orig_url) end
	if ssid then q[#q + 1] = "ssid=" .. urlencode(ssid) end
	return ctx.url .. (ctx.url:find("?", 1, true) and "&" or "?") .. table.concat(q, "&")
end

-- The request line and Host header, read with a bound: a guest is not
-- allowed to hold the inform loop.
local function read_request(client)
	local first, host
	for i = 1, 32 do
		local line = client:receive("*l")
		if not line or line == "" then break end
		if i == 1 then
			first = line
		else
			local h = line:match("^[Hh][Oo][Ss][Tt]:%s*([%w%.%-:%[%]]+)%s*$")
			if h then host = h end
		end
	end
	local path = first and first:match("^%u+ (/%S*) HTTP/%d%.%d$")
	if host and path and #path <= 1024 then return "http://" .. host .. path end
	return nil
end

-- Answer one waiting connection, if any. ctx: {url, ap, ssid_for(mac) or nil,
-- arp() -> /proc/net/arp text, now()}. Returns true when it answered.
function M.serve_one(server, ctx)
	local client = server:accept()
	if not client then return false end
	client:settimeout(1)
	local ok, err = pcall(function()
		local ip = client:getpeername()
		local orig = read_request(client)
		local mac = ip and M.arp_mac(ip, ctx.arp())
		if not mac then
			client:send("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\n"
				.. "Content-Length: 0\r\nConnection: close\r\n\r\n")
			return
		end
		local ssid = ctx.ssid_for and ctx.ssid_for(mac) or nil
		client:send("HTTP/1.1 302 Found\r\nLocation: " .. M.location(ctx, mac, orig, ssid, ctx.now())
			.. "\r\nCache-Control: no-cache, no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	end)
	client:close()
	if not ok then io.stderr:write("guestportal: answer failed: " .. tostring(err) .. "\n") end
	return true
end

-- A listening socket on M.PORT, or nil and the error.
function M.listen(socket)
	local server, err = socket.bind("*", M.PORT)
	if not server then return nil, err end
	server:settimeout(0)
	return server
end

return M
