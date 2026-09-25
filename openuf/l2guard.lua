--[[
	The controller's `ebtables.*` hardening rules, re-expressed in nftables.

	Every full system_cfg push carries a block of literal ebtables fragments the
	stock firmware replays (captured by the yesrab/openUF fork, 2026-09-15).
	Ten rules, two ideas:

	  -t nat -A PREROUTING  --in-interface  ath<n> -d BGA -j DROP     one per VAP
	  -t nat -A POSTROUTING --out-interface ath<n> -d BGA -j DROP     one per VAP
	  -t broute -A BROUTING -i ath1 -p 802_1Q -j DROP                 the VLAN-tagged SSID's VAP
	  -t broute -A BROUTING --vlan-id 10 -p 802_1Q -j DROP            every bridge port

	BGA is ebtables' name for the Bridge Group Address, 01:80:c2:00:00:00 --
	where STP BPDUs go. With STP off (OpenWrt's default) the kernel bridge
	FORWARDS frames to that address (br_handle_frame: BR_NO_STP -> forward), so
	a wireless client could inject BPDUs into the wired LAN. The 802_1Q rules
	say no client may inject VLAN-tagged frames, i.e. no VLAN hopping from the
	air.

	What is applied, and the one deliberate narrowing: both ideas on every
	AP-mode VAP netdev, in and out -- wireless clients are exactly who the
	controller's rules name. The `--vlan-id <n>` rule with no interface would
	on the stock firmware cover the wired sockets too, because there the tagged
	uplink is an 8021q sub-device (eth0.10) that takes tagged frames BEFORE the
	bridge sees them. On a DSA board openUF's tagged uplink is `br-lan.10`, on
	the bridge itself, so tagged frames DO traverse the bridge from the uplink
	socket -- a bridge-wide "drop VLAN 10" would kill the IoT WLAN's uplink,
	and telling the uplink socket apart from a client socket is a runtime
	detection that is refused when unsure. Refuse rather than guess: the tag
	drop covers the VAPs only, and that is documented as the scope.

	Mechanism as in firewall.lua/bcfilter.lua: its own `bridge` table rebuilt
	from scratch on every reconcile (idempotent, self-healing), kernel state
	that dies with a reboot and is rebuilt at startup from state.json's
	`l2guard` record plus the live VAP list. iifname/oifname in the bridge
	family are meta expressions and need kmod-nft-bridge, like the Blocker's
	rule; a rejected rule is warned about by name for the same reason.

	The VAP list is a snapshot, and VAPs come and go: a push that adds an SSID
	runs `wifi reload` asynchronously, so the netdev may not exist yet when the
	push is handled, and at boot wireless is often not up when the daemon
	starts. inform.lua therefore re-reads the list once a minute
	(_l2guard_resync) and rebuilds the table when it changed, rather than
	leaving a new VAP unguarded until the next push.
]]--

local M = {}

M._exec = function(cmd) return os.execute(cmd) end

-- os.execute on the device's Lua 5.1 returns the raw exit status (0 =
-- success, non-zero = failure, both truthy); newer Lua returns true/nil.
local function exec_ok(status)
	return status == true or status == 0
end
M._exec_ok = exec_ok

M.NFT_TABLE = "bridge openuf_l2guard"
M.BGA       = "01:80:c2:00:00:00"

-- ─── Parsing ─────────────────────────────────────────────────────────────────

-- The ebtables.* block, or nil when the blob carries none. Each recognised
-- shape lands in its list; anything else in `unknown`, verbatim, so a new
-- rule shape is visible rather than silently dropped.
function M.parse(sys_raw)
	if type(sys_raw) ~= "string" then return nil end
	local seen = false
	local out = {enabled = true, bpdu_in = {}, bpdu_out = {}, tag_in = {}, tag_vids = {}, unknown = {}}
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		local k, v = line:match("^([^=]+)=(.*)$")
		if k == "ebtables.status" then
			seen = true
			out.enabled = (v == "enabled")
		elseif k and k:match("^ebtables%.%d+%.cmd$") then
			seen = true
			local dev = v:match("^%-t nat %-A PREROUTING %-%-in%-interface (%S+) %-d BGA %-j DROP$")
			if dev then
				out.bpdu_in[#out.bpdu_in + 1] = dev
			else
				dev = v:match("^%-t nat %-A POSTROUTING %-%-out%-interface (%S+) %-d BGA %-j DROP$")
				if dev then
					out.bpdu_out[#out.bpdu_out + 1] = dev
				else
					dev = v:match("^%-t broute %-A BROUTING %-i (%S+) %-p 802_1Q %-j DROP$")
					if dev then
						out.tag_in[#out.tag_in + 1] = dev
					else
						local vid = v:match("^%-t broute %-A BROUTING %-%-vlan%-id (%d+) %-p 802_1Q %-j DROP$")
						if vid then
							out.tag_vids[#out.tag_vids + 1] = tonumber(vid)
						else
							out.unknown[#out.unknown + 1] = v
						end
					end
				end
			end
		end
	end
	if not seen then return nil end
	return out
end

-- What to enforce, boiled down to the two device-wide booleans state.json
-- keeps: the controller emits the BPDU pair for every VAP and the tag drop
-- for the tagged one plus bridge-wide, so per-VAP bookkeeping adds nothing.
function M.spec_from(parsed)
	if type(parsed) ~= "table" or not parsed.enabled then
		return {bpdu = false, tagdrop = false}
	end
	return {
		bpdu    = (#parsed.bpdu_in > 0 or #parsed.bpdu_out > 0),
		tagdrop = (#parsed.tag_in > 0 or #parsed.tag_vids > 0),
	}
end

-- ─── Apply ───────────────────────────────────────────────────────────────────

local function valid_ifname(s)
	return type(s) == "string" and s:match("^[%w%-%._]+$") ~= nil and #s <= 15
end

-- Rebuild the table to match spec on exactly these VAP netdevs. Returns the
-- number of rules installed (0 when there was nothing to enforce or nothing
-- to enforce it on; the table is deleted either way).
function M.reconcile(spec, ifnames)
	M._exec("nft delete table " .. M.NFT_TABLE .. " 2>/dev/null")
	if type(spec) ~= "table" or not (spec.bpdu or spec.tagdrop) then return 0 end
	local names = {}
	for _, n in ipairs(ifnames or {}) do
		if valid_ifname(n) then
			names[#names + 1] = '"' .. n .. '"'
		else
			io.stderr:write("l2guard: ignoring odd interface name " .. ("%q"):format(tostring(n)) .. "\n")
		end
	end
	if #names == 0 then
		io.stderr:write("l2guard: no AP interfaces to protect yet -- rules deferred\n")
		return 0
	end
	local set = "{ " .. table.concat(names, ", ") .. " }"
	M._exec("nft add table " .. M.NFT_TABLE)
	-- -300 is where ebtables' nat/broute PREROUTING sat; before bridging.
	M._exec("nft add chain " .. M.NFT_TABLE
		.. " pre '{ type filter hook prerouting priority -300; policy accept; }'")
	M._exec("nft add chain " .. M.NFT_TABLE
		.. " post '{ type filter hook postrouting priority 0; policy accept; }'")
	local rules = {}
	if spec.bpdu then
		rules[#rules + 1] = {"pre",  "iifname " .. set .. " ether daddr " .. M.BGA .. " drop", "BPDU drop (in)"}
		rules[#rules + 1] = {"post", "oifname " .. set .. " ether daddr " .. M.BGA .. " drop", "BPDU drop (out)"}
	end
	if spec.tagdrop then
		rules[#rules + 1] = {"pre",  "iifname " .. set .. " ether type vlan drop", "VLAN-tag drop"}
	end
	local n = 0
	for _, r in ipairs(rules) do
		if exec_ok(M._exec("nft add rule " .. M.NFT_TABLE .. " " .. r[1] .. " '" .. r[2] .. "'")) then
			n = n + 1
		else
			io.stderr:write("openuf: l2guard: nft rejected the " .. r[3] .. " rule. iifname/oifname in the "
				.. "bridge family need kmod-nft-bridge (apk add kmod-nft-bridge); without it the "
				.. "controller's ebtables rules are NOT enforced.\n")
		end
	end
	return n
end

return M
