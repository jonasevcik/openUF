--[[
	Per-port VLAN assignment, driven by the controller's `switch.*` push.

	Wire format mapped live 2026-07-19 (see PROTOCOL-VALIDATION.md's `switch.*`
	section) and parsed by inform.lua's M._parse_switch_system_cfg(), which
	hands this module:

	    {enabled = true,
	     vlans = {[1] = {...}, [20] = {...}},
	     ports = {[2] = {pvid = 20, vlans = {[1]="exclude", [20]="untagged"}}}}

	keyed by UniFi port_idx. The controller's untagged|tagged|exclude vocabulary
	maps 1:1 onto swconfig's port membership syntax ("3", "3t", absent).

	=== SCOPE AND LIMITS -- read before extending ===

	**swconfig boards only.** All three boards this project targets (TP-Link
	WDR3500, Archer C5 v1, WR1043ND v2) are ath79/swconfig, and both modelmaps
	already carry the swconfig physical-port map this needs. Modern OpenWrt
	(21.02+) is DSA, where per-port VLAN is `config bridge-vlan` instead --
	detect_backend() recognizes DSA and refuses, rather than emitting
	unverifiable config. There is no DSA board here to verify against.

	**Not verified against real switch hardware.** The validation container has
	no switch, no swconfig binary, and only a mock UCI. What is verified: the
	wire format (live, against a real controller), the parse layer, and the
	UCI state this module produces (unit tests with a mock cursor). What is
	NOT: that the generated `switch_vlan` sections actually program a switch
	ASIC, that traffic lands on the right VLAN, or that the reload command
	behaves on real ath79. Same honesty as bcfilter.lua's nftables caveat.

	**Reversibility.** Assigning a port to a VLAN requires removing it from the
	stock VLAN's port list, so unlike the wireless side this module cannot stay
	entirely inside openuf_-prefixed sections. It therefore snapshots any
	pre-existing section's original `ports` string into openUF's state before
	the first mutation, and restore() puts them back.

	All operations are safe no-ops without dev.conf.vlan (an unknown board's
	switch port map must never be guessed -- that is how you strand a device).
]]--

local M = {}

-- Injectable, matching netconfig.lua/shaper.lua's convention.
M._exec = function(cmd) return os.execute(cmd) end
-- Injectable stdout capture, for read-only switch introspection (the VLAN
-- table size). Same seam name and shape as ucihelper's.
M._popen = function(cmd)
	local h = io.popen(cmd .. " 2>/dev/null")
	if not h then return "" end
	local s = h:read("*a")
	h:close()
	return s or ""
end
M._uci  = nil   -- set by callers/tests; falls back to require("uci")

local OPENUF_VLAN_PREFIX = "openuf_swvlan"

local function get_uci()
	if M._uci then return M._uci end
	return require("uci")
end

-- Which switch backend this board uses. Only "swconfig" is actionable.
-- cursor: an open UCI cursor (so tests can drive this without a real system).
function M.detect_backend(cursor)
	local has_switch, has_bridge_vlan = false, false
	cursor:foreach("network", "switch", function() has_switch = true end)
	cursor:foreach("network", "bridge-vlan", function() has_bridge_vlan = true end)
	if has_switch then return "swconfig" end
	if has_bridge_vlan then return "dsa" end
	return "unknown"
end

-- Resolve a modelmap `swport` to a physical switch port number. It may name a
-- key in dev.conf.vlan.ports ("lan1") or be the physical number outright.
-- Returns nil when the board has no switch map or the name is not in it --
-- never a guess. Also used by inform.lua, which needs the mapping for every
-- socket including the uplink one physical_port() below refuses.
function M.resolve_swport(cfg, swport)
	local vlan = cfg and cfg.vlan
	if not (vlan and vlan.ports and swport) then return nil end
	return vlan.ports[swport] or tonumber(swport)
end

-- Does this board's modelmap name its uplink port statically? Boards whose
-- uplink socket is fixed (a dedicated WAN netdev, say) say so with
-- `uplink = true`; boards where the cable can sit in any LAN socket leave it
-- out and the uplink is detected at runtime instead.
local function has_static_uplink(net)
	for _, p in ipairs((net and net.ports) or {}) do
		if p.uplink then return true end
	end
	return false
end

-- Map a UniFi port_idx to this board's physical switch port number.
-- The chain is deliberately explicit and never guessed:
--   controller port_idx -> dev.conf.net.ports[].swport -> dev.conf.vlan.ports[]
-- Returns nil when any link is missing, which callers treat as "skip this port".
--
-- uplink_phys: the physical port the uplink cable is currently in
-- (sysinfo.uplink_phys_port), for modelmaps that do not name one statically.
-- Reassigning the uplink's VLAN strands the device, so that socket is refused
-- here -- and when a dynamic-uplink board cannot say which socket that is, so
-- is every port: fail closed, since the alternative is a coin flip on which
-- one takes the device off the network.
function M.physical_port(cfg, port_idx, uplink_phys)
	local net  = cfg and cfg.net
	local vlan = cfg and cfg.vlan
	if not (net and net.ports and vlan and vlan.ports) then return nil end
	for _, p in ipairs(net.ports) do
		if p.idx == port_idx then
			if p.uplink then return nil, "uplink" end
			if not p.swport then return nil, "no swport in modelmap" end
			local phys = M.resolve_swport(cfg, p.swport)
			if not phys then return nil, "swport not in dev.conf.vlan.ports" end
			if uplink_phys then
				if phys == uplink_phys then return nil, "uplink" end
			elseif not has_static_uplink(net) then
				return nil, "uplink port unknown"
			end
			return phys
		end
	end
	return nil, "no such port_idx"
end

-- Build the desired swconfig port string for one VLAN.
-- members: {[port_idx] = "untagged"|"tagged"|"exclude"}
-- uplink_phys: as for M.physical_port -- the socket that must never be moved.
-- Returns nil when the VLAN ends up with no member beyond the CPU port, so the
-- caller can skip writing an empty section.
function M.build_ports(cfg, vlan_id, members, uplink_phys)
	local cpu = cfg and cfg.vlan and cfg.vlan.cpu_lan
	if not cpu then return nil end
	local parts, any = {}, false
	-- The CPU port is always tagged: it carries every VLAN up to the SoC.
	parts[#parts + 1] = tostring(cpu) .. "t"
	local idxs = {}
	for idx in pairs(members) do idxs[#idxs + 1] = idx end
	table.sort(idxs)   -- stable, comparable output
	for _, idx in ipairs(idxs) do
		local mode = members[idx]
		local phys = M.physical_port(cfg, idx, uplink_phys)
		if phys and mode ~= "exclude" then
			parts[#parts + 1] = tostring(phys) .. (mode == "tagged" and "t" or "")
			any = true
		end
	end
	if not any then return nil end
	return table.concat(parts, " ")
end

-- Port string trunking one VLAN from the SoC out to the gateway: the CPU port
-- and the uplink socket, both tagged. Nothing else.
--
-- A VLAN-tagged SSID is useless without this. The bridge can be perfect and
-- the VAP up, and the switch still drops every VID it has no entry for once
-- `enable_vlan 1` is set -- which is the stock config on both validated
-- boards. Confirmed live: with the bridge in place and no VLAN 20 entry,
-- pinging the IoT gateway over the tagged interface lost 100% of packets;
-- adding a trunk took it to 0%.
--
-- Those two ports are the whole path: VAP -> br-openuf<id> -> eth0.<id> ->
-- CPU port -> uplink socket -> gateway. A LAN socket is never on it.
--
-- This used to tag EVERY LAN socket, on the reasoning that which one carries
-- the uplink is not knowable and `pvid` is untouched so wired clients see no
-- change. Both halves were wrong, and together they broke every untagged
-- wired host behind an AP running a tagged SSID:
--
--   * The uplink socket IS knowable -- sysinfo.uplink_phys_port() reads it out
--     of the switch's own ARL table, and apply() already has the answer.
--   * On the ar8216/ar8226/ar8229/ar8236 driver family, tagging is NOT per
--     (port, VLAN). ar8xxx_sw_set_ports() folds it into one global per-port
--     bitmask, `priv->vlan_tagged`, and __ar8216_setup_port() picks
--     AR8216_OUT_ADD_VLAN vs AR8216_OUT_STRIP_VLAN from that single bitmask
--     for every VLAN at once. So tagging a socket into VLAN 10 makes it
--     egress-tagged in VLAN 1 too, and the untagged host plugged into it
--     stops receiving. Diagnosed live on a TL-WDR3500 (AR8229): UCI held
--     VLAN 1 as "1 2 3 4 0t" while the switch reported "0t 1t 2t 3t 4t", and
--     a printer on socket 2 was transmitting but deaf.
--
-- The Archer C5's AR8327 has a real per-(port, VLAN) tag table -- ar8327.c
-- overrides the get/set-ports ops -- so it showed none of this, which is
-- exactly why the bug shipped: it is invisible on the board it was written
-- against. Trunking only what the VLAN needs is correct on both, and stops
-- the AR8327 boards making every wired socket a tagged member of the IoT
-- VLAN, which it had no business doing either.
--
-- A consequence worth knowing on the global-bitmask chips: a port cannot be
-- untagged in VLAN 1 and tagged in VLAN 10 at the same time, so running a
-- tagged wireless VLAN necessarily leaves the UPLINK socket egress-tagged for
-- VLAN 1 as well. UniFi gateways accept that (it is the live, working state
-- on the WDR3500), and it is confined to the one port facing the gateway.
--
-- Returns nil plus a reason when the uplink socket is not known; the caller
-- must hold rather than guess, since guessing wrong here strands the device.
function M.trunk_ports(cfg, vlan_id, uplink_phys)
	local cpu = cfg and cfg.vlan and cfg.vlan.cpu_lan
	local ports = cfg and cfg.vlan and cfg.vlan.ports
	if not (cpu and ports) then return nil end
	if not uplink_phys then return nil, "uplink unknown" end
	-- A board whose uplink is a netdev off its own PHY (the WDR3500's WAN
	-- socket, say) has no switch port to trunk through; uplink_phys is nil
	-- there and we never reach this line.
	if tonumber(uplink_phys) == tonumber(cpu) then return tostring(cpu) .. "t" end
	return ("%dt %dt"):format(tonumber(cpu), tonumber(uplink_phys))
end

-- How many VLAN table entries this switch has, or nil when unknown.
-- `swconfig dev <sw> help` opens with e.g.
--   switch0: mdio.0:1f(Atheros AR8229), ports: 5 (cpu @ 0), vlans: 16
-- and that number is a hard limit on the VLAN ID openUF can program, because
-- netifd on these builds has NO `vid` option -- `strings /sbin/netifd` lists
-- `vlan` and `ports` and nothing else -- so the section's `vlan` value is
-- used as BOTH the table slot and the VLAN ID. Asking for VLAN 20 on a
-- 16-entry table therefore cannot work: netifd skips the section without a
-- word, which is exactly how it presented on the second validation AP.
function M.vlan_table_size(cursor, device)
	local out = M._popen(("swconfig dev %s help"):format(device or "switch0"))
	local n = tostring(out or ""):match("vlans:%s*(%d+)")
	return n and tonumber(n) or nil
end

-- Switch on the driver's per-port MIB polling, once, at startup.
--
-- port_table's per-socket byte counters come from the switch's MIB, and the
-- ar8xxx driver only maintains them while `ar8xxx_mib_poll_interval` is
-- non-zero. It ships that way on some boards and not others -- an AR9344
-- (TL-WDR3500) had it at 500 ms and reported counters, while an AR8327
-- (Archer C5) had it at 0 and answered "Operation not supported" for every
-- port, so that AP's Ports view showed 0 B on every socket while the other's
-- was populated. Confirmed live: one `swconfig set` produced counters on the
-- next read.
--
-- Only ever turns it ON, and only when the attribute exists and reads 0 --
-- a board that already polls (or a driver with no such knob) is left alone.
-- `dev.conf.vlan.mib_poll_ms = false` opts out; a number sets the interval.
-- Returns true when it changed something.
function M.enable_mib_polling(cfg)
	local vlan = cfg and cfg.vlan
	if not vlan then return false end          -- no switch map: no switch
	if vlan.mib_poll_ms == false then return false end
	local interval = tonumber(vlan.mib_poll_ms) or 500
	local device = vlan.device or "switch0"
	local attr = "ar8xxx_mib_poll_interval"
	local cur = M._popen(("swconfig dev %s get %s"):format(device, attr))
	local n = tostring(cur or ""):match("^%s*(%d+)")
	if not n then return false end             -- unknown attribute / no swconfig
	if tonumber(n) > 0 then return false end   -- already polling
	M._exec(("swconfig dev %s set %s %d"):format(device, attr, interval))
	io.stderr:write(("switchvlan: enabled %s=%d on %s -- per-port counters were off\n")
		:format(attr, interval, device))
	return true
end

-- Apply a parsed switch table.
-- sw:  output of inform.M._parse_switch_system_cfg (may be nil)
-- cfg: device configuration (dev.conf)
-- st:  openUF state table, used as the reversibility ledger
-- wireless_vlans: array of VLAN ids carried by tagged SSIDs on this device.
--   These need a trunk whether or not the controller's per-port VLAN feature
--   is in use, so their presence alone is enough to run this function. Kept
--   here rather than in a module of its own so that ONE place owns every
--   switch_vlan section -- two writers would race to define the same VID.
-- uplink_phys: the physical port the uplink cable is currently in, from
--   sysinfo.uplink_phys_port -- see M.physical_port for why it is refused.
-- uplink_ifname: the same answer on a DSA board, from
--   sysinfo.uplink_bridge_port -- the socket's netdev name rather than a
--   switch port number. Refused for exactly the same reason.
-- Returns true when UCI was changed and a reload was issued.
function M.apply(sw, cfg, st, wireless_vlans, uplink_phys, uplink_ifname)
	local has_wireless = wireless_vlans and #wireless_vlans > 0
	if (not sw or not sw.enabled) and not has_wireless then return false end
	if not cfg then return false end
	-- dev.conf.vlan is a SWCONFIG requirement -- it is the physical port-number
	-- map. A DSA board correctly has none (each socket is its own netdev), so
	-- that check waits until the backend is known, below. Checking it here
	-- logged a scary line about a missing map on every single inform of a
	-- board that neither has one nor needs one.
	-- No early return on empty sw.ports: an enabled push whose last per-port
	-- override was removed must still reach the reconcile below, or the
	-- now-orphaned openuf_swvlan* sections would keep programming VLANs the
	-- controller no longer defines.

	local uci = get_uci()
	local cursor = uci.cursor()

	local backend = M.detect_backend(cursor)
	if backend ~= "swconfig" then
		-- DSA needs no trunk for a tagged SSID (the switch passes tags with
		-- vlan_filtering off, and the 8021q device on the uplink bridge port
		-- takes the VID before the bridge sees it), so wireless_vlans has
		-- nothing to do here. Per-port VLAN is a bridge membership move --
		-- see the DSA section below.
		return M.dsa_apply(sw, cfg, st, uplink_ifname)
	end
	if not (cfg.vlan and cfg.vlan.ports and cfg.vlan.cpu_lan) then
		io.stderr:write("switchvlan: no dev.conf.vlan for this swconfig board -- "
			.. "per-port VLAN not applied (a guessed switch port map strands the device)\n")
		return false
	end

	-- Invert the per-port matrix into per-VLAN membership.
	local members_by_vlan = {}
	for port_idx, p in pairs((sw and sw.enabled and sw.ports) or {}) do
		local phys, why = M.physical_port(cfg, port_idx, uplink_phys)
		if not phys then
			io.stderr:write(("switchvlan: skipping port_idx %d (%s)\n")
				:format(port_idx, why or "unmappable"))
		else
			for vlan_id, mode in pairs(p.vlans) do
				members_by_vlan[vlan_id] = members_by_vlan[vlan_id] or {}
				members_by_vlan[vlan_id][port_idx] = mode
			end
		end
	end
	-- Refuse to strand management: the CPU port must keep the management VLAN.
	local mgmt_vlan = (cfg.net and cfg.net.lan_vlanid) or 1
	local mgmt = members_by_vlan[mgmt_vlan]
	if mgmt then
		local survives = false
		for _, mode in pairs(mgmt) do
			if mode ~= "exclude" then survives = true end
		end
		-- The CPU port is always tagged into every VLAN we write, so the
		-- management VLAN itself survives; this guards the case where the
		-- controller excludes every port from it, leaving a VLAN with no
		-- downstream member at all.
		if not survives then
			members_by_vlan[mgmt_vlan] = nil
		end
	end

	-- The sections this push wants to exist. Keyed on the rendered result,
	-- not on members_by_vlan: a VLAN that shrank to exclusions-only renders
	-- to nil and must lose its section just like a VLAN that left the wire.
	local desired = {}
	for vlan_id, members in pairs(members_by_vlan) do
		desired[vlan_id] = M.build_ports(cfg, vlan_id, members, uplink_phys)
	end

	-- Tagged SSIDs' VLANs. A per-port assignment for the same VID wins: it
	-- names specific sockets and may mark one untagged, which a blanket trunk
	-- would override. The trunk only fills in VIDs nothing else defines, so
	-- the two features compose instead of fighting over a section.
	--
	-- `held` are VIDs whose trunk we cannot render right now because the
	-- uplink socket is unknown -- a transient empty ARP cache is enough. That
	-- is not the same as "this VLAN is gone": letting it fall through to the
	-- reconcile below would delete a working trunk and reload the network on
	-- one inform, then put it back on the next, bouncing the IoT WLAN in a
	-- loop. Leave whatever is already there alone instead.
	local held = {}
	for _, vlan_id in ipairs(wireless_vlans or {}) do
		local vid = tonumber(vlan_id)
		if vid and not desired[vid] then
			local ports, why = M.trunk_ports(cfg, vid, uplink_phys)
			if ports then
				desired[vid] = ports
			elseif why == "uplink unknown" then
				held[vid] = true
				io.stderr:write(("switchvlan: VLAN %d needs a trunk but the uplink "
					.. "socket is unknown -- leaving the existing section as it is "
					.. "(tagging every socket instead would make wired clients on "
					.. "this board's LAN ports egress-tagged and deaf)\n"):format(vid))
			end
		end
	end

	-- Stock-section strips: moving a port onto an openuf VLAN means it must
	-- LEAVE the stock VLAN's port list too -- swconfig allows one untagged
	-- VLAN per port, and a port left untagged in stock VLAN 1 while also
	-- untagged in openuf_swvlan20 is an invalid config the ASIC cannot
	-- honor. (This forward mutation is what st.swvlan_backup/restore() were
	-- always documented for; until now it was never actually performed, so
	-- the restore machinery was dead code and port moves could not work.)
	--
	-- Rules, per managed physical port P and stock VLAN section V:
	--   * exclude(P, V) on the wire  -> drop P's tokens from V, but drop an
	--     UNTAGGED membership only when P gains an untagged home elsewhere
	--     in this push (never strand a port with no untagged VLAN at all);
	--     a tagged membership is always safe to drop.
	--   * P untagged in some pushed VLAN W -> drop P's untagged token from
	--     every OTHER stock section (the one-untagged-VLAN rule).
	--   * CPU ports are never touched; the uplink cannot appear (its
	--     port_idx is unmappable by design).
	--   * The management VLAN is never stripped of its last downstream
	--     port (same survival principle as the members_by_vlan guard).
	local untagged_home = {}  -- phys -> vlan_id it becomes untagged in
	local excluded      = {}  -- vlan_id -> { [phys] = true }
	for port_idx, p in pairs((sw and sw.enabled and sw.ports) or {}) do
		local phys = M.physical_port(cfg, port_idx)
		if phys then
			for vlan_id, mode in pairs(p.vlans) do
				if mode == "untagged" and desired[vlan_id] then
					untagged_home[phys] = vlan_id
				elseif mode == "exclude" then
					excluded[vlan_id] = excluded[vlan_id] or {}
					excluded[vlan_id][phys] = true
				end
			end
		end
	end

	local cpu_ports = {[tostring(cfg.vlan.cpu_lan)] = true}
	if cfg.vlan.cpu_wan then cpu_ports[tostring(cfg.vlan.cpu_wan)] = true end

	local stock_edits = {}  -- section name -> new ports string
	cursor:foreach("network", "switch_vlan", function(s)
		local name = s[".name"]
		if not name or name:match("^" .. OPENUF_VLAN_PREFIX) then return end
		local vid = tonumber(s.vlan)
		if not vid or not s.ports then return end
		local out, changed_here, non_cpu_left = {}, false, false
		for tok in tostring(s.ports):gmatch("%S+") do
			local num, tag = tok:match("^(%d+)(t?)$")
			local keep = true
			if num and not cpu_ports[num] then
				local phys = tonumber(num)
				local home = untagged_home[phys]
				if excluded[vid] and excluded[vid][phys] then
					if tag == "t" or (home and home ~= vid) then
						keep = false
					end
				elseif tag == "" and home and home ~= vid then
					keep = false
				end
			end
			if keep then
				out[#out + 1] = tok
				if num and not cpu_ports[num] then non_cpu_left = true end
			else
				changed_here = true
			end
		end
		if changed_here then
			if vid == mgmt_vlan and not non_cpu_left then
				io.stderr:write(("switchvlan: not stripping %s (management "
					.. "VLAN %d) -- it would lose its last downstream port\n")
					:format(name, vid))
			else
				stock_edits[name] = table.concat(out, " ")
			end
		end
	end)

	-- Reconcile: drop every openuf_swvlan* section this push no longer
	-- wants. Without this, removing a VLAN in the controller left its
	-- orphan section programming the switch forever.
	local changed = false
	local doomed = {}
	cursor:foreach("network", "switch_vlan", function(s)
		local vid = s[".name"] and s[".name"]:match("^" .. OPENUF_VLAN_PREFIX .. "(%d+)$")
		if vid and desired[tonumber(vid)] == nil and not held[tonumber(vid)] then
			doomed[#doomed + 1] = s[".name"]
		end
	end)
	for _, name in ipairs(doomed) do
		cursor:delete("network", name)
		changed = true
	end

	if next(desired) or next(stock_edits) then
		-- Snapshot the stock sections' port strings once, before the first
		-- mutation, so restore() can put them back. Only taken when we are
		-- about to write or strip sections -- a reconcile-only pass has no
		-- new mutation to ledger.
		-- Stock sections only. An earlier version snapshotted every
		-- switch_vlan section, so a second push -- by which time openUF's own
		-- openuf_swvlan<vid> existed -- filed openUF's output in the ledger as
		-- if it were the board's original. Inert, because restore() deletes
		-- the openuf sections before replaying the backup and nothing is left
		-- to restore that key onto, but it is a false record of what the board
		-- looked like, and the ledger is the only thing standing between a
		-- forward mutation and an unrecoverable switch config.
		st.swvlan_backup = st.swvlan_backup or (function()
			local snap = {}
			cursor:foreach("network", "switch_vlan", function(s)
				local name = s[".name"]
				if name and name:match("^" .. OPENUF_VLAN_PREFIX) then return end
				if s.vlan and s.ports then snap[tostring(s.vlan)] = s.ports end
			end)
			return snap
		end)()

		for name, ports in pairs(stock_edits) do
			cursor:set("network", name, "ports", ports)
			changed = true
		end

		for vlan_id, ports in pairs(desired) do
			local section = OPENUF_VLAN_PREFIX .. tostring(vlan_id)
			local cap = M.vlan_table_size(cursor, cfg.vlan.device)
			if cap and vlan_id >= cap then
				-- Not necessarily fatal: whether it matters depends on the
				-- ASIC. Confirmed live on both validated boards -- the
				-- AR8327 drops tagged frames for a VID it has no entry for
				-- (100% loss until the trunk existed), while the AR8229
				-- forwards them and the tagged SSID works with no entry at
				-- all. So this is reported as a fact, not a failure.
				io.stderr:write(("switchvlan: VLAN %d exceeds this switch's %d-entry "
					.. "VLAN table -- netifd has no `vid` option, so the id doubles "
					.. "as the table slot; leaving this VLAN unprogrammed. If a "
					.. "tagged SSID on it does not pass traffic, this switch filters "
					.. "unknown VIDs and the VLAN id must be below %d\n")
					:format(vlan_id, cap, cap))
			elseif cursor:get("network", section, "ports") ~= ports then
				cursor:set("network", section, "switch_vlan")
				cursor:set("network", section, "device",
					(cfg.vlan.device) or "switch0")
				-- `vlan` is the switch's VLAN TABLE INDEX, not the VLAN ID --
				-- the single most confusing thing about swconfig, and openUF
				-- had it wrong. Small switches have few entries (the WDR3500's
				-- AR8229 reports "vlans: 16"), so writing vlan='20' names a
				-- slot that does not exist: netifd skips the section in
				-- silence, no log line, and the VLAN is simply never
				-- programmed. It only appeared to work on the Archer because
				-- its AR8327 has a table big enough for index 20 to be real.
				cursor:set("network", section, "vlan", tostring(vlan_id))
				cursor:set("network", section, "ports", ports)
				changed = true
			end
		end
	end

	-- No-op discipline: every steady-state setparam re-carries this block, and
	-- reloading the network on each one would bounce the uplink every inform.
	-- Same class of hazard as the DHCP flush guarded in inform.lua.
	if not changed then return false end

	cursor:commit("network")
	M._exec("/etc/init.d/network reload 2>/dev/null")
	return true
end

-- === DSA: per-port VLAN without touching br-lan ============================
--
-- The swconfig path above programs a switch ASIC's VLAN table. DSA has no such
-- table to write and no `swconfig` to write it with, and the obvious
-- translation -- `config bridge-vlan` sections plus vlan_filtering on br-lan --
-- is the wrong answer here twice over:
--
--   1. br-lan carries the AP's own management address and the uplink socket.
--      Turning vlan_filtering on there means every VLAN, the management one
--      included, must be declared exactly right or the device is stranded at
--      the far end of a cable with no way back. That is the single most
--      dangerous thing this module could do.
--   2. It would silently fight the tagged-SSID path. `wan.10` is an 8021q
--      device on the `wan` BRIDGE PORT, and vlan_do_receive() runs ahead of
--      the bridge's rx_handler in __netif_receive_skb_core -- so VLAN 10
--      frames are claimed by wan.10 before br-lan ever sees them. A
--      bridge-vlan declaring VLAN 10 on br-lan would therefore never receive
--      anything, while looking perfectly correct in UCI.
--
-- What DSA wants instead is the L2 openUF already builds for a tagged SSID.
-- Assigning a socket to VLAN 10 means moving it out of br-lan and into
-- br-openuf10 -- the bridge that already holds `wan.10`. Then:
--
--     device on lan3 --untagged--> lan3 -> br-openuf10 -> wan.10 --tagged--> uplink
--
-- and the return path is the same in reverse. br-lan keeps the uplink, the
-- unassigned sockets and the management address, entirely untouched; nothing
-- anywhere runs with vlan_filtering. A wired device and a wireless client on
-- the same VLAN land in the same bridge, which is not a coincidence but the
-- point -- they are one broadcast domain and the controller models them as
-- one network.
--
-- Verified on a Xiaomi AX3000T (mt7530): the driver accepts a user port in a
-- second bridge while br-lan keeps the rest. It drops that bridge to software
-- forwarding (the port enters promiscuous mode), which costs nothing at the
-- rates an AP's downstream socket carries.
--
-- OWNERSHIP of br-openuf<vid>: ucihelper.ensure_vlan_network guarantees the
-- tagged uplink is a member and never removes anyone else; this module owns
-- the socket members. Neither touches the other's.

local OPENUF_BRDEV_PREFIX = "openuf_brdev"

-- Which netdev a UniFi port_idx is on a DSA board, or nil plus a reason.
--
-- Same refusals as M.physical_port and for the same reasons: the uplink
-- socket is never reassignable (moving it strands the device), and a board
-- that cannot say which socket that is refuses every port rather than taking
-- a coin flip on it.
function M.dsa_ifname(cfg, port_idx, uplink_ifname)
	local net = cfg and cfg.net
	if not (net and net.ports) then return nil, "no dev.conf.net.ports" end
	for _, p in ipairs(net.ports) do
		if p.idx == port_idx then
			if not p.ifname then return nil, "no ifname in modelmap" end
			if p.uplink then return nil, "uplink" end
			if not uplink_ifname then return nil, "uplink port unknown" end
			if p.ifname == uplink_ifname then return nil, "uplink" end
			return p.ifname
		end
	end
	return nil, "no such port_idx"
end

-- Invert the controller's per-port matrix into {[vid] = {ifname, ...}}, the
-- sockets that should become untagged members of each VLAN's bridge.
--
-- Only "untagged" is honoured. A bridge gives a port exactly one untagged
-- home, which is precisely what a Native VLAN is, and that is the whole of
-- what an AP's downstream socket needs. "tagged" would mean carrying a VID
-- the attached device itself tags -- expressible as a <ifname>.<vid>
-- sub-device, but no UniFi AP port control emits it and it would ship
-- unverified, so it is refused out loud instead of half-done.
--
-- A port whose native VLAN is the management VLAN is deliberately absent from
-- the result: its home is br-lan, which is where it already is.
function M.dsa_members(sw, cfg, uplink_ifname)
	local out = {}
	if not (sw and sw.enabled and sw.ports) then return out end
	local mgmt = (cfg and cfg.net and cfg.net.lan_vlanid) or 1
	local idxs = {}
	for idx in pairs(sw.ports) do idxs[#idxs + 1] = idx end
	table.sort(idxs)
	for _, port_idx in ipairs(idxs) do
		local p = sw.ports[port_idx]
		local ifname, why = M.dsa_ifname(cfg, port_idx, uplink_ifname)
		if not ifname then
			io.stderr:write(("switchvlan: skipping port_idx %s (%s)\n")
				:format(tostring(port_idx), why or "unmappable"))
		else
			local native, tagged = nil, {}
			for vid, mode in pairs(p.vlans or {}) do
				local n = tonumber(vid)
				if n and mode == "untagged" and n ~= mgmt then
					native = n
				elseif n and mode == "tagged" and n ~= mgmt then
					tagged[#tagged + 1] = n
				end
			end
			if native then
				out[native] = out[native] or {}
				out[native][#out[native] + 1] = ifname
			elseif #tagged > 0 then
				-- Only worth saying when tagged membership is ALL the port was
				-- given. The controller's default Tagged VLAN Management is
				-- "Allow All", which marks every VLAN the port is not native
				-- to as tagged -- so warning per tagged VID logged a line per
				-- VLAN per inform about a default nobody chose. A port with a
				-- native VLAN got what it asked for; only one with nothing but
				-- tagged VLANs is actually being refused something.
				table.sort(tagged)
				io.stderr:write(("switchvlan: port %s is tagged-only (VLAN %s) "
					.. "-- not applied. DSA per-port VLAN implements the "
					.. "native/untagged assignment; set a Native VLAN on the "
					.. "port instead\n"):format(ifname, table.concat(tagged, ", ")))
			end
		end
	end
	for _, list in pairs(out) do table.sort(list) end
	return out
end

-- The bridge device section a VLAN's L2 lives in, matching the names
-- ucihelper.ensure_vlan_network writes.
local function brdev_section(vid) return OPENUF_BRDEV_PREFIX .. tostring(vid) end

-- Read a UCI list option that may come back as a bare string.
local function as_list(v)
	if type(v) == "table" then return v end
	if type(v) == "string" and v ~= "" then return {v} end
	return {}
end

-- The `config device` section that defines br-lan, and its port list. Found by
-- the bridge's NAME rather than by a section name, because it is the board's
-- own anonymous section (network.@device[0]) and openUF must not assume where
-- in the file it sits.
local function find_lan_bridge(cursor, br_name)
	local found
	cursor:foreach("network", "device", function(s)
		if s.name == br_name and s.type == "bridge" then found = s[".name"] end
	end)
	return found
end

-- Apply a parsed switch table on a DSA board.
--
-- Moves each assigned socket out of br-lan and into its VLAN's bridge, and
-- reconciles both directions: a socket the controller no longer assigns comes
-- back to br-lan, and a bridge left with no sockets keeps only its uplink.
--
-- st.dsa_brlan_ports is the reversibility ledger -- br-lan's port list exactly
-- as the board shipped it, snapshotted once before the first mutation. It is
-- the only record of what to put back, so it is written before anything else
-- changes and cleared only by dsa_restore.
--
-- Returns true when UCI changed and a reload was issued.
function M.dsa_apply(sw, cfg, st, uplink_ifname)
	local uci = get_uci()
	local cursor = uci.cursor()

	local lan_name = "br-" .. ((cfg and cfg.net and cfg.net.lan_name) or "lan")
	local lan_sec  = find_lan_bridge(cursor, lan_name)
	if not lan_sec then
		io.stderr:write(("switchvlan: no `config device` for %s -- per-port VLAN "
			.. "not applied (nothing to move sockets out of)\n"):format(lan_name))
		return false
	end

	local members = M.dsa_members(sw, cfg, uplink_ifname)

	-- Every socket openUF is entitled to move: the modelmap's ports, minus the
	-- uplink and anything unmappable. Anything outside this set is the user's
	-- and is never added to or removed from br-lan.
	local managed = {}
	for _, p in ipairs((cfg and cfg.net and cfg.net.ports) or {}) do
		if M.dsa_ifname(cfg, p.idx, uplink_ifname) then managed[p.ifname] = true end
	end

	local assigned = {}   -- ifname -> vid
	for vid, list in pairs(members) do
		for _, ifname in ipairs(list) do assigned[ifname] = vid end
	end

	local changed = false

	-- br-lan: it keeps every port that is not assigned elsewhere. Ports
	-- outside `managed` pass through untouched whatever the push says.
	local lan_ports = as_list(cursor:get("network", lan_sec, "ports"))
	local keep, dropped = {}, false
	for _, ifname in ipairs(lan_ports) do
		if assigned[ifname] and managed[ifname] then
			dropped = true
		else
			keep[#keep + 1] = ifname
		end
	end
	-- ...and takes back any managed socket this push no longer assigns.
	for _, p in ipairs((cfg and cfg.net and cfg.net.ports) or {}) do
		local ifname = p.ifname
		if ifname and managed[ifname] and not assigned[ifname] then
			local present = false
			for _, k in ipairs(keep) do if k == ifname then present = true end end
			if not present then keep[#keep + 1] = ifname; dropped = true end
		end
	end
	if dropped or #keep ~= #lan_ports then
		-- Ledger first, always, and only ever the pristine list: taking the
		-- snapshot after a mutation would file openUF's own output as the
		-- board's original and make restore() a no-op that looks like a
		-- success. Same discipline as swvlan_backup above.
		if st and st.dsa_brlan_ports == nil then st.dsa_brlan_ports = lan_ports end
		cursor:set("network", lan_sec, "ports", keep)
		changed = true
	end

	-- Each VLAN bridge: openUF's socket members, leaving the tagged uplink
	-- sub-device (ucihelper's) and anything else alone.
	local vids = {}
	cursor:foreach("network", "device", function(s)
		local vid = s[".name"] and s[".name"]:match("^" .. OPENUF_BRDEV_PREFIX .. "(%d+)$")
		if vid then vids[tonumber(vid)] = true end
	end)
	for vid in pairs(members) do vids[vid] = true end

	for vid in pairs(vids) do
		local sec = brdev_section(vid)
		if cursor:get("network", sec, "name") then
			local want = {}
			for _, ifname in ipairs(members[vid] or {}) do want[ifname] = true end
			local cur, out, diff = as_list(cursor:get("network", sec, "ports")), {}, false
			for _, ifname in ipairs(cur) do
				-- Drop only sockets openUF manages and this push dropped;
				-- the uplink sub-device and any hand-added member survive.
				if managed[ifname] and not want[ifname] then diff = true
				else out[#out + 1] = ifname; want[ifname] = nil end
			end
			for _, ifname in ipairs(members[vid] or {}) do
				if want[ifname] then out[#out + 1] = ifname; diff = true end
			end
			if diff then
				cursor:set("network", sec, "ports", out)
				changed = true
			end
		end
	end

	if not changed then return false end
	cursor:commit("network")
	M._exec("/etc/init.d/network reload 2>/dev/null")
	return true
end

-- Undo dsa_apply: put br-lan's original port list back and drop openUF's
-- socket members from the VLAN bridges. The bridges themselves belong to
-- ucihelper (a tagged SSID may still need them) and are left standing.
function M.dsa_restore(st, cfg)
	if not (st and st.dsa_brlan_ports) then return false end
	local uci = get_uci()
	local cursor = uci.cursor()
	local orig = as_list(st.dsa_brlan_ports)

	local was = {}
	for _, ifname in ipairs(orig) do was[ifname] = true end

	local changed = false
	cursor:foreach("network", "device", function(s)
		local vid = s[".name"] and s[".name"]:match("^" .. OPENUF_BRDEV_PREFIX .. "(%d+)$")
		if not vid then return end
		local out, diff = {}, false
		for _, ifname in ipairs(as_list(s.ports)) do
			-- A socket that br-lan originally owned goes home; the tagged
			-- uplink sub-device (which br-lan never had) stays.
			if was[ifname] then diff = true else out[#out + 1] = ifname end
		end
		if diff then cursor:set("network", s[".name"], "ports", out); changed = true end
	end)

	-- Derived, not hardcoded: dsa_apply names this bridge from the modelmap,
	-- and a restore that looked for a different one would silently put nothing
	-- back while reporting success. Falls back to "lan" only when cfg is
	-- absent, which is what every board here uses anyway.
	local lan_name = "br-" .. ((cfg and cfg.net and cfg.net.lan_name) or "lan")
	local lan_sec  = find_lan_bridge(cursor, lan_name)
	if lan_sec then
		cursor:set("network", lan_sec, "ports", orig)
		changed = true
	end
	st.dsa_brlan_ports = nil

	if changed then
		cursor:commit("network")
		M._exec("/etc/init.d/network reload 2>/dev/null")
	end
	return changed
end

-- Undo everything apply() wrote: drop openUF's sections and put the stock
-- sections' port strings back. cfg is needed only on the DSA path, which has
-- to name the same bridge dsa_apply moved sockets out of.
function M.restore(st, cfg)
	local uci = get_uci()
	local cursor = uci.cursor()
	-- A DSA board has no switch_vlan sections to drop and a different thing to
	-- put back; the presence of its ledger is what says so.
	if st and st.dsa_brlan_ports then return M.dsa_restore(st, cfg) end
	local removed = false
	local doomed = {}
	cursor:foreach("network", "switch_vlan", function(s)
		if s[".name"] and s[".name"]:match("^" .. OPENUF_VLAN_PREFIX) then
			doomed[#doomed + 1] = s[".name"]
		end
	end)
	for _, name in ipairs(doomed) do
		cursor:delete("network", name)
		removed = true
	end
	if st and st.swvlan_backup then
		cursor:foreach("network", "switch_vlan", function(s)
			local orig = s.vlan and st.swvlan_backup[tostring(s.vlan)]
			if orig and s.ports ~= orig then
				cursor:set("network", s[".name"], "ports", orig)
				removed = true
			end
		end)
		st.swvlan_backup = nil
	end
	if removed then
		cursor:commit("network")
		M._exec("/etc/init.d/network reload 2>/dev/null")
	end
	return removed
end

return M
