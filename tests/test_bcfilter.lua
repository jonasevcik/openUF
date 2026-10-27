-- Tests for openuf/bcfilter.lua ("Multicast and Broadcast Blocker" nftables
-- enforcement). Run from project root: lua tests/run_tests.lua
--
-- The generated nft syntax was checked against a real nftables 1.0.9 while
-- writing this (see the module's comments on oifname vs oif, and on meta
-- pkttype vs the invalid `ether daddr type multicast`); these tests pin the
-- command shape so a regression in it is visible.

local bcfilter = dofile("openuf/bcfilter.lua")

-- Capture the nft statements that took effect instead of running them.
-- `fail` (optional) is a function(statement) -> true for one nft rejects, so a
-- test can make one specific statement fail the way a real one does.
local function with_bcfilter(fn, fail)
	local orig = bcfilter._exec
	local exec, r = fake_nft(fail)
	bcfilter._exec = exec
	local ok, err = pcall(fn, r.cmds, r)
	bcfilter._exec = orig
	if not ok then error(err, 0) end
end

-- Capture what the module writes to stderr while fn runs.
local function with_stderr(fn)
	local orig, buf = io.stderr, {}
	io.stderr = {write = function(_, ...)
		for _, v in ipairs({...}) do buf[#buf + 1] = tostring(v) end
	end}
	local ok, err = pcall(fn)
	io.stderr = orig
	if not ok then error(err, 0) end
	return table.concat(buf)
end

-- What an image without kmod-nft-bridge rejects: the drop rule.
local function lua51_fail(stmt)
	return stmt:find("add rule", 1, true) ~= nil
end

local function joined(cmds) return table.concat(cmds, "\n") end

local function contains(cmds, needle)
	return joined(cmds):find(needle, 1, true) ~= nil
end

return {
	{
		name = "bcfilter: reconcile rebuilds its own table from scratch",
		fn = function()
			with_bcfilter(function(cmds, r)
				bcfilter.reconcile({})
				assert_eq(r.runs, 1, "one nft run")
				assert_true(contains(cmds, "nft delete table bridge openuf_bcfilt"),
					"deletes before recreating (idempotent)")
				assert_true(contains(cmds, "nft add table bridge openuf_bcfilt"),
					"recreates the table")
				assert_true(contains(cmds, "nft add chain bridge openuf_bcfilt bcfilt"),
					"creates the filter chain")
				-- The hook spec is what makes the chain filter anything at
				-- all -- a chain with a corrupted hook/priority passes every
				-- other assertion while filtering nothing.
				assert_true(contains(cmds, "bcfilt { type filter hook forward priority 0; }"),
					"chain is hooked into forward at priority 0")
			end)
		end
	},
	{
		name = "bcfilter: reconcile uses a table separate from firewall.lua's",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile({})
				-- firewall.lua deletes and recreates `bridge openuf` wholesale on
				-- every block/unblock; sharing that table would wipe these rules.
				assert_false(joined(cmds):find("bridge openuf ", 1, true) ~= nil,
					"never touches firewall.lua's `bridge openuf` table")
			end)
		end
	},
	{
		name = "bcfilter: reconcile emits a per-interface allow set and drop rule",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile({
					{ifname = "wlan0", macs = {"aa:bb:cc:dd:ee:ff"}},
				})
				assert_true(contains(cmds, "add set bridge openuf_bcfilt allow_wlan0"),
					"per-interface set")
				assert_true(contains(cmds, "allow_wlan0 { aa:bb:cc:dd:ee:ff }"),
					"allow-listed MAC added as an element")
				assert_true(contains(cmds, 'oifname "wlan0"'),
					"matches by interface NAME, so a not-yet-created netdev is fine")
				assert_true(contains(cmds, "meta pkttype { broadcast, multicast }"),
					"matches group-addressed traffic")
				assert_true(contains(cmds, "ether saddr != @allow_wlan0 drop"),
					"drops unless the SENDER is allow-listed")
			end)
		end
	},
	{
		name = "bcfilter: reconcile keeps each VAP's allow-list in its own set",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile({
					{ifname = "wlan0", macs = {"aa:aa:aa:aa:aa:aa"}},
					{ifname = "wlan1", macs = {"bb:bb:bb:bb:bb:bb"}},
				})
				assert_true(contains(cmds, "allow_wlan0 { aa:aa:aa:aa:aa:aa }"),
					"wlan0 keeps its own MAC")
				assert_true(contains(cmds, "allow_wlan1 { bb:bb:bb:bb:bb:bb }"),
					"wlan1 keeps its own MAC")
				assert_false(contains(cmds, "allow_wlan0 { bb:bb:bb:bb:bb:bb }"),
					"lists are not merged across VAPs")
			end)
		end
	},
	{
		name = "bcfilter: an empty allow-list still installs the drop rule",
		fn = function()
			with_bcfilter(function(cmds)
				-- "Blocker on, nothing excepted" is a real (aggressive) setting,
				-- not a no-op -- it must not silently degrade to allowing all.
				bcfilter.reconcile({{ifname = "wlan0", macs = {}}})
				assert_true(contains(cmds, "ether saddr != @allow_wlan0 drop"),
					"drop rule present with an empty set")
			end)
		end
	},
	{
		name = "bcfilter: reconcile is a safe no-op with nil rules",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile(nil)
				assert_false(contains(cmds, "add rule"), "no drop rules emitted")
			end)
		end
	},
	{
		name = "bcfilter: a rejected drop rule is reported, not swallowed",
		fn = function()
			-- Real failure mode on a stock image with no kmod-nft-bridge: the
			-- table, chain and allow set all build, only `meta` in the bridge
			-- family is missing, so ONLY the drop rule is rejected. Everything
			-- looked fine on the device and in the controller while the WLAN
			-- filtered nothing.
			local out = with_stderr(function()
				with_bcfilter(function(cmds)
					local ok = bcfilter.reconcile({{ifname = "wlan0", macs = {"aa:bb:cc:dd:ee:ff"}}})
					assert_false(ok, "reconcile reports failure to its caller")
					assert_true(contains(cmds, "allow_wlan0 { aa:bb:cc:dd:ee:ff }"),
						"the set is still built and filled, as nft without the module leaves it")
				end, lua51_fail)
			end)
			assert_true(out:find("kmod%-nft%-bridge") ~= nil,
				"names the package that fixes it")
			assert_true(out:find("wlan0", 1, true) ~= nil,
				"names the interface that is not being filtered")
		end
	},
	{
		name = "bcfilter: a Lua 5.1 exit status of 0 counts as success",
		fn = function()
			-- The trap this whole path exists for: on 5.1 a FAILED os.execute
			-- returns a non-zero number, which is truthy, so a bare truth test
			-- passes for both outcomes. Guard the success side too, or the fix
			-- degrades into warning on every healthy reconcile.
			local out = with_stderr(function()
				with_bcfilter(function()
					local ok = bcfilter.reconcile({{ifname = "wlan0", macs = {}}})
					assert_true(ok, "exit status 0 is success")
				end)
			end)
			assert_eq(out, "", "no warning on a healthy reconcile")
		end
	},
	{
		name = "bcfilter: reconcile skips entries with no resolved ifname",
		fn = function()
			with_bcfilter(function(cmds)
				-- get_ifname_for_vap returns nil off-target or for a downed
				-- radio; a rule with no interface would apply network-wide.
				bcfilter.reconcile({{ifname = nil, macs = {"aa:bb:cc:dd:ee:ff"}}})
				assert_false(contains(cmds, "add rule"), "no unscoped rule emitted")
			end)
		end
	},
	{
		name = "bcfilter: an odd interface name never reaches the nft script",
		fn = function()
			-- The name is spliced into a script line: a newline in it would be
			-- a statement of its own.
			local logged = with_stderr(function()
				with_bcfilter(function(cmds)
					bcfilter.reconcile({{ifname = "wlan0\nflush ruleset", macs = {}},
						{ifname = "wlan1", macs = {}}})
					assert_false(contains(cmds, "flush"), "the injected statement never runs")
					assert_true(contains(cmds, 'oifname "wlan1"'), "the good VAP is still filtered")
				end)
			end)
			assert_true(logged:find("odd interface name", 1, true) ~= nil, "and the drop is logged")
		end
	},
	{
		name = "bcfilter: a malformed allow-list MAC never reaches the nft command line",
		fn = function()
			local all = ""
			local logged = with_stderr(function()
				with_bcfilter(function(cmds)
					bcfilter.reconcile({{ifname = "wlan0", macs = {
						"aa:bb:cc:dd:ee:ff",
						"aa:bb:cc:dd:ee:ff }; touch /tmp/pwned; nft add element x y '{ 1",
						"",
					}}})
					all = table.concat(cmds, "\n")
				end)
			end)
			assert_true(all:find("aa:bb:cc:dd:ee:ff", 1, true) ~= nil, "the real MAC is added")
			assert_true(all:find("touch", 1, true) == nil, "the injected command never runs")
			assert_true(logged:find("malformed") ~= nil, "and the drop is logged")
		end
	},

	{
		name = "bcfilter: Aggressive exempts the four bypass types, before the drop",
		fn = function()
			with_bcfilter(function(cmds)
				-- The verbatim set the controller sends (one literal string,
				-- "ARP|NSNA|DHCPV4|DHCPV6"), as the lab captured it.
				bcfilter.reconcile({{ifname = "wlan0", macs = {"00:00:5e:00:53:01"},
					bypass = {ARP = true, NSNA = true, DHCPV4 = true, DHCPV6 = true}}})
				assert_true(contains(cmds, 'oifname "wlan0" ether type arp accept'),
					"ARP is let through")
				assert_true(contains(cmds,
					'oifname "wlan0" ether type ip udp dport { 67, 68 } accept'),
					"DHCPv4 is let through")
				assert_true(contains(cmds,
					'oifname "wlan0" ether type ip6 udp dport { 546, 547 } accept'),
					"DHCPv6 is let through")
				assert_true(contains(cmds,
					'oifname "wlan0" ether type ip6 icmpv6 type ' ..
					'{ nd-neighbor-solicit, nd-neighbor-advert } accept'),
					"IPv6 neighbour discovery is let through")
				-- Order is the whole point: an accept after the drop would never
				-- be reached, and the rules go in in list order.
				local all = joined(cmds)
				assert_true(all:find("ether type arp accept", 1, true)
					< all:find("ether saddr != @allow_wlan0 drop", 1, true),
					"every exemption is added before the drop")
				assert_true(contains(cmds, "add element bridge openuf_bcfilt allow_wlan0 " ..
					"{ 00:00:5e:00:53:01 }"), "and the allow-list still applies")
			end)
		end
	},
	{
		name = "bcfilter: the plain blocker still drops ARP and DHCP",
		fn = function()
			-- A controller that sends no bypass_types gets exactly the ruleset it
			-- got before this existed. Ubiquiti's older documentation described
			-- that behaviour and told admins to allow-list the DHCP server, so an
			-- invented exemption would change a working WLAN.
			with_bcfilter(function(cmds)
				bcfilter.reconcile({{ifname = "wlan0", macs = {}}})
				assert_false(contains(cmds, "accept"), "no exemption of any kind")
				assert_true(contains(cmds, 'oifname "wlan0" meta pkttype ' ..
					"{ broadcast, multicast } ether saddr != @allow_wlan0 drop"),
					"and the drop is unchanged")
			end)
		end
	},
	{
		name = "bcfilter: Conservative limits the rate instead of blocking",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile({{ifname = "wlan0", limit = true}})
				assert_true(contains(cmds, 'oifname "wlan0" meta pkttype ' ..
					"{ broadcast, multicast } limit rate over 100/second " ..
					"burst 50 packets drop"),
					"only the excess above the ceiling is dropped")
				-- `limit rate over` is the form that drops the EXCESS; plain
				-- `limit rate` matches while UNDER the rate, which with a drop
				-- verb would discard all the ordinary traffic and pass the storm.
				assert_true(contains(cmds, "limit rate over"),
					"`over`, not a bare `limit rate`")
				assert_false(contains(cmds, "allow_wlan0"),
					"a rate ceiling needs no allow-list, so no set is created")
				assert_false(contains(cmds, "ether saddr !="),
					"and nothing is blocked outright")
			end)
		end
	},
	{
		name = "bcfilter: one VAP's exemptions never reach another's",
		fn = function()
			with_bcfilter(function(cmds)
				bcfilter.reconcile({
					{ifname = "wlan0", macs = {}, bypass = {ARP = true}},
					{ifname = "wlan1", macs = {}},
					{ifname = "wlan2", limit = true},
				})
				assert_true(contains(cmds, 'oifname "wlan0" ether type arp accept'),
					"the exempt VAP has its accept")
				assert_false(contains(cmds, 'oifname "wlan1" ether type arp'),
					"the blocked VAP does not")
				assert_true(contains(cmds, 'oifname "wlan1" meta pkttype ' ..
					"{ broadcast, multicast } ether saddr != @allow_wlan1 drop"),
					"each VAP keeps its own mode")
				assert_true(contains(cmds, 'oifname "wlan2" meta pkttype ' ..
					"{ broadcast, multicast } limit rate over"),
					"including the rate-limited one")
			end)
		end
	},
}
