-- Tests for openuf/l2guard.lua (the controller's ebtables.* rules in nft).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
local l2guard = dofile("openuf/l2guard.lua")

-- The ten rules as the yesrab/openUF fork captured them (2026-09-15).
local CAPTURE = table.concat({
	"ebtables.status=enabled",
	"ebtables.add_vlan.status=disabled",
	"ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP",
	"ebtables.2.cmd=-t nat -A POSTROUTING --out-interface ath0 -d BGA -j DROP",
	"ebtables.3.cmd=-t nat -A PREROUTING --in-interface ath1 -d BGA -j DROP",
	"ebtables.4.cmd=-t nat -A POSTROUTING --out-interface ath1 -d BGA -j DROP",
	"ebtables.5.cmd=-t nat -A PREROUTING --in-interface ath2 -d BGA -j DROP",
	"ebtables.6.cmd=-t nat -A POSTROUTING --out-interface ath2 -d BGA -j DROP",
	"ebtables.7.cmd=-t broute -A BROUTING -i ath1 -p 802_1Q -j DROP",
	"ebtables.8.cmd=-t broute -A BROUTING --vlan-id 10 -p 802_1Q -j DROP",
	"radio.1.channel=6",
}, "\n") .. "\n"

local function with_capture(fn, fail_pattern)
	local cmds, orig = {}, l2guard._exec
	l2guard._exec = function(cmd)
		cmds[#cmds + 1] = cmd
		if fail_pattern and cmd:find(fail_pattern, 1, true) then return 1 end
		return 0
	end
	local ok, err = pcall(fn, cmds)
	l2guard._exec = orig
	if not ok then error(err, 0) end
	return cmds
end

local function with_stderr(fn)
	local buf, real = {}, io.stderr
	io.stderr = {write = function(_, ...) for _, s in ipairs({...}) do buf[#buf + 1] = s end end}
	local ok, err = pcall(fn)
	io.stderr = real
	if not ok then error(err, 0) end
	return table.concat(buf)
end

return {
	{
		name = "l2guard: parse sorts the ten captured rules into their four shapes",
		fn = function()
			local p = l2guard.parse(CAPTURE)
			assert_true(p.enabled, "enabled")
			assert_eq(table.concat(p.bpdu_in, ","), "ath0,ath1,ath2", "BPDU in, per VAP")
			assert_eq(table.concat(p.bpdu_out, ","), "ath0,ath1,ath2", "BPDU out, per VAP")
			assert_eq(table.concat(p.tag_in, ","), "ath1", "tag drop on the tagged SSID's VAP")
			assert_eq(table.concat(p.tag_vids, ","), "10", "bridge-wide VLAN id")
			assert_eq(#p.unknown, 0, "nothing unrecognised")
		end
	},
	{
		name = "l2guard: parse keeps an unknown rule shape verbatim and returns nil without the block",
		fn = function()
			local p = l2guard.parse("ebtables.status=enabled\nebtables.1.cmd=-t filter -A FORWARD -j ACCEPT\n")
			assert_eq(#p.unknown, 1, "one unknown")
			assert_eq(p.unknown[1], "-t filter -A FORWARD -j ACCEPT", "verbatim")
			assert_nil(l2guard.parse("radio.1.channel=6\n"), "no block")
			assert_nil(l2guard.parse(nil), "nil input")
			local off = l2guard.parse("ebtables.status=disabled\nebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP\n")
			assert_false(off.enabled, "disabled gate read")
		end
	},
	{
		name = "l2guard: spec_from reduces the block to the two device-wide booleans, honouring the gate",
		fn = function()
			local s = l2guard.spec_from(l2guard.parse(CAPTURE))
			assert_true(s.bpdu, "bpdu")
			assert_true(s.tagdrop, "tagdrop")
			local off = l2guard.spec_from({enabled = false, bpdu_in = {"ath0"}, bpdu_out = {}, tag_in = {}, tag_vids = {}})
			assert_false(off.bpdu, "gate off -> nothing")
			assert_false(off.tagdrop, "gate off -> nothing")
			local only_bpdu = l2guard.spec_from({enabled = true, bpdu_in = {"ath0"}, bpdu_out = {}, tag_in = {}, tag_vids = {}})
			assert_true(only_bpdu.bpdu, "bpdu alone")
			assert_false(only_bpdu.tagdrop, "no tag rules")
			assert_false(l2guard.spec_from(nil).bpdu, "nil")
		end
	},
	{
		name = "l2guard: reconcile rebuilds the table with BPDU in/out and tag-drop rules on exactly the VAP names",
		fn = function()
			local n
			local cmds = with_capture(function()
				n = l2guard.reconcile({bpdu = true, tagdrop = true}, {"phy0-ap0", "phy1-ap0", "phy1-ap1"})
			end)
			assert_eq(n, 3, "three rules")
			assert_contains(cmds[1], "nft delete table bridge openuf_l2guard", "clears first")
			assert_contains(cmds[2], "nft add table bridge openuf_l2guard", "recreates")
			local joined = table.concat(cmds, "\n")
			assert_contains(joined, "pre '{ type filter hook prerouting priority -300; policy accept; }'", "prerouting chain")
			assert_contains(joined, "post '{ type filter hook postrouting priority 0; policy accept; }'", "postrouting chain")
			local set = '{ "phy0-ap0", "phy1-ap0", "phy1-ap1" }'
			assert_contains(joined, "pre 'iifname " .. set .. " ether daddr 01:80:c2:00:00:00 drop'", "BPDU in")
			assert_contains(joined, "post 'oifname " .. set .. " ether daddr 01:80:c2:00:00:00 drop'", "BPDU out")
			assert_contains(joined, "pre 'iifname " .. set .. " ether type vlan drop'", "tag drop")
			assert_true(joined:find("br%-lan") == nil, "never a wired interface")
		end
	},
	{
		name = "l2guard: reconcile with the spec off, or nothing to protect, only deletes the table",
		fn = function()
			local cmds = with_capture(function()
				assert_eq(l2guard.reconcile({bpdu = false, tagdrop = false}, {"phy0-ap0"}), 0, "off")
			end)
			assert_eq(#cmds, 1, "delete only")
			assert_contains(cmds[1], "nft delete table", "deleted")
			local out = with_stderr(function()
				cmds = with_capture(function()
					assert_eq(l2guard.reconcile({bpdu = true, tagdrop = true}, {}), 0, "no VAPs yet")
				end)
			end)
			assert_eq(#cmds, 1, "delete only")
			assert_contains(out, "no AP interfaces to protect yet", "deferred, and said so")
			cmds = with_capture(function() assert_eq(l2guard.reconcile(nil, {"x"}), 0, "nil spec") end)
			assert_eq(#cmds, 1, "delete only")
		end
	},
	{
		name = "l2guard: reconcile drops odd interface names and only bpdu when tagdrop is off",
		fn = function()
			local out = with_stderr(function()
				local cmds = with_capture(function()
					assert_eq(l2guard.reconcile({bpdu = true, tagdrop = false}, {"phy0-ap0", "bad name; rm", "x'y"}), 2, "two rules")
				end)
				local joined = table.concat(cmds, "\n")
				assert_contains(joined, '{ "phy0-ap0" }', "only the sane name")
				assert_true(joined:find("rm", 1, true) == nil, "injection attempt not spliced")
				assert_true(joined:find("ether type vlan") == nil, "no tag rule")
			end)
			assert_contains(out, "ignoring odd interface name", "logged")
		end
	},
	{
		name = "l2guard: a rejected rule is warned about by name, naming kmod-nft-bridge",
		fn = function()
			local out = with_stderr(function()
				local n
				with_capture(function()
					n = l2guard.reconcile({bpdu = true, tagdrop = true}, {"phy0-ap0"})
				end, "oifname")
				assert_eq(n, 2, "two of three installed")
			end)
			assert_contains(out, "nft rejected the BPDU drop (out) rule", "names the rule")
			assert_contains(out, "kmod-nft-bridge", "names the fix")
		end
	},
}
