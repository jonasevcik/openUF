--[[
	State persistence for openuf.

	Reads and writes /etc/openuf/state.json (configurable via M._state_file).

	Load invariant: EVERY field save() writes must be listed in FIELDS below.
	save() encodes the whole table, load() copies back only what it recognises
	-- so a field added by a caller and not added here is written to disk,
	looks persisted in the file, and comes back nil on the next start. Ten of
	them had accumulated that way, and the failures were all silent:
	  • swvlan_backup, the per-port VLAN reversibility ledger -- so unticking
	    Port VLAN after any restart restored nothing and left the switch on
	    openUF's config for good;
	  • led_enabled, so the controller's Manage > LED toggle forgot itself on
	    every reboot while the controller went on believing it took;
	  • locating, so a Locate could never be cleaned up by a later start;
	  • ip_mode, whose only reader guards "am I reverting my OWN static
	    config", so across a restart a genuine static->DHCP push did nothing;
	  • mac, read by M.run as prev_mac and compared against the live one --
	    the entire IDENTITY MAC CHANGED diagnostic was unreachable, since its
	    only producer returned nil every time.
	The type is checked on the way in: state.json is not a trusted input (an
	operator edits it, syswrapper writes it), and a wrong type reaching, say,
	blocked_stas would crash the daemon at startup rather than at parse.

	Security invariant: if adopted == false, authkey is always reset to the
	default key on load, regardless of what the file contains. This prevents a
	stale key from blocking adoption after a reset.
]]--

local cjson = require("cjson")

local M = {}

-- Default adoption key (pre-shared, well-known across all UniFi firmware)
M.DEFAULT_KEY = "ba86f2bbe107c7c57eb5f2690775c712"

-- Override this in tests to point at a temp file
M._state_file = "/etc/openuf/state.json"

-- Inform URL used when state.json does not carry one -- a first boot, or the
-- state after a factory reset. conf.lua's config.inform_url overrides this at
-- startup (see inform.lua's entry point), which is what makes that documented
-- option real: before, conf.lua's value was read by nothing and this constant
-- was the only URL a fresh device ever used, while install.sh went on parsing
-- conf.lua for "the URL openUF will really use" to decide whether to install
-- luasec for an https:// controller.
M.DEFAULT_INFORM_URL = "http://unifi:8080/inform"

local function defaults()
	return {
		authkey                  = M.DEFAULT_KEY,
		adopted                  = false,
		cfgversion               = "",
		inform_url               = M.DEFAULT_INFORM_URL,
		use_gcm                  = false,
		upgrade_requested_version = "",
		upgrade_requested_url     = "",
		blocked_stas             = {},
	}
end

-- Every persisted field and the type it must have on the way in. Fields with
-- an entry in defaults() above always come back (with the default when the
-- file is missing or the type is wrong); the rest come back only when the file
-- carries them, which is the "never pushed / never set" signal their readers
-- test for -- st.led_enabled ~= nil, st.ip_mode == "static", and so on. Adding
-- a field to state means adding it here; see the header.
M.FIELDS = {
	authkey                   = "string",
	adopted                   = "boolean",
	cfgversion                = "string",
	-- plugins.fingerprint() of the plugins the last push was built with.
	plugins_fp                = "string",
	inform_url                = "string",
	use_gcm                   = "boolean",
	upgrade_requested_version = "string",
	upgrade_requested_url     = "string",
	blocked_stas              = "table",
	-- Identity, re-derived at startup by inform's _populate_net_info. Kept
	-- here so the PREVIOUS run's values are still readable at that moment:
	-- M.run compares the loaded mac against the live one to catch a modelmap
	-- change that silently re-identifies an adopted device.
	mac                       = "string",
	ip                        = "string",
	hostname                  = "string",
	-- Controller-pushed IP settings. ip_mode is the "was I static before?"
	-- guard on the DHCP path, which must not flush a working lease just
	-- because a steady-state push reaffirmed DHCP.
	ip_mode                   = "string",
	static_ip                 = "string",
	static_netmask            = "string",
	static_gateway            = "string",
	static_dns                = "table",
	-- Live kernel state, not UCI, so it is reapplied from here at startup the
	-- way the blocked-client rules are.
	led_enabled               = "boolean",
	-- mgmt_cfg's capability list asked for STA_ASSOC_TRACKER notifs. Only
	-- carried by setparam, so it has to outlive a restart.
	notif_assoc_stat          = "boolean",
	-- mgmt_cfg's stun_url, the controller's STUN server (stun.lua). Only
	-- carried by setparam, likewise.
	stun_url                  = "string",
	locating                  = "boolean",
	locate_prev_trigger       = "string",
	-- The per-port VLAN reversibility ledger: the stock `ports` strings of
	-- every switch_vlan section openUF overwrote. Without it restore() has
	-- nothing to put back and the board keeps openUF's VLAN config forever.
	swvlan_backup             = "table",
	-- The DSA counterpart: br-lan's port list exactly as the board shipped
	-- it, before per-port VLAN moved any socket out of it. Same job, and the
	-- same "only record of what to put back".
	dsa_brlan_ports           = "table",
	-- The controller's ebtables.* intent ({bpdu, tagdrop, ifnames}), so the
	-- nft rules l2guard builds from it come back after a reboot like the
	-- blocklist does.
	l2guard                   = "table",
	-- Airtime Fairness (atf.mode): a debugfs flag, back on after a reboot.
	atf_enabled               = "boolean",
	-- Guest portal: the WLANs that need it ({wlanconf_id = true}, from the
	-- last system_cfg) and the guests the controller authorized
	-- ({mac = epoch s}, from authorize-guest). Only carried by pushes and
	-- one-shot cmds, so both have to outlive a restart.
	guest_wlans               = "table",
	guest_authorized          = "table",
	-- Per-client WiFi Speed Limits from rate-update ({mac = {up=, down=}}
	-- kbps, -1 = none), one association each (inform._shaper_resync).
	sta_rates                 = "table",
	-- The portal's enforcement facts (guestportal.parse) while it is on;
	-- the nft tables are rebuilt from it at startup.
	guest_portal              = "table",
	-- mgmt_cfg selfrun_guest_mode: "pass" lets guests through while the
	-- controller is unreachable, "off" takes the guest WLANs down.
	guest_selfrun             = "string",
	-- The guest VAP ifnames selfrun_guest_mode=off took down, until they
	-- are brought back up (also after a restart in between).
	guest_vaps_down           = "table",
	-- The VAP ifnames a WiFi Blackout Schedule took down (wlansched.lua),
	-- likewise until they are brought back up.
	sched_vaps_down           = "table",
	-- Reported as guest_token while the portal is on (32 hex).
	guest_token               = "string",
	-- The walled garden's domain half, resolved: {allowed = {name = {ip, ...}},
	-- restricted = {...}}. Kept so a reboot rebuilds the chains from the last
	-- good answers instead of waiting on DNS, and so a name that stops
	-- resolving keeps the addresses it had (guestportal.resolve_garden).
	guest_wg_ips              = "table",
}

-- Load state from disk. Missing file returns defaults. Applies security
-- invariant: resets authkey if adopted == false.
function M.load()
	local f = io.open(M._state_file, "r")
	if not f then
		return defaults()
	end
	local raw = f:read("*a")
	f:close()

	local ok, tbl = pcall(cjson.decode, raw)
	if not ok or type(tbl) ~= "table" then
		-- Falling back to defaults means the device comes up UNADOPTED with
		-- the well-known key -- the right call for a garbage file, but it must
		-- not be silent: from the controller's side that is indistinguishable
		-- from a factory reset. An EMPTY file is normal (install.sh
		-- --bootstrap-adopt pre-creates one) and says nothing.
		if raw:match("%S") then
			io.stderr:write("state: " .. M._state_file .. " is not valid JSON -- "
				.. "starting from defaults; the device will appear unadopted\n")
		end
		return defaults()
	end

	local st = defaults()
	for field, want in pairs(M.FIELDS) do
		if type(tbl[field]) == want then st[field] = tbl[field] end
	end

	-- blocked_stas is a list, but a cjson build that tags decoded objects
	-- (the lab image's) saves `{}` plus an append as {"1":mac}, which
	-- reloads with a string key that ipairs never sees -- every block gone
	-- after a restart. Rebuild it as a plain array, in key order.
	local entries = {}
	for k, v in pairs(st.blocked_stas) do
		if type(v) == "string" and tonumber(k) then
			entries[#entries + 1] = {tonumber(k), v}
		end
	end
	table.sort(entries, function(a, b) return a[1] < b[1] end)
	st.blocked_stas = {}
	for i, e in ipairs(entries) do st.blocked_stas[i] = e[2] end

	-- Security invariant: never use a custom key when not adopted
	if not st.adopted then
		st.authkey = M.DEFAULT_KEY
	end

	return st
end

-- Save state to disk. Creates the parent directory only if the first write
-- fails (avoids shelling out to `mkdir -p` on every heartbeat, since the
-- directory almost always already exists).
--
-- Written to a sibling temp file and renamed into place. rename(2) is atomic
-- within a filesystem, so a power cut or a full overlay mid-write leaves
-- either the old file or the new one and never a truncated one. That matters
-- more here than for most files: load() reads unparseable JSON as "start from
-- defaults", which resets the authkey and clears `adopted` -- so an in-place
-- write interrupted at the wrong moment cost the adoption outright.
-- A side effect worth knowing: the bootstrap account now needs write
-- permission on the DIRECTORY, not on the previous file.
--
-- M.last_written keeps the exact bytes, so inform's change detection can tell
-- this process's own write from syswrapper's: without it every save was read
-- back on the next heartbeat as an out-of-process change, and the full reload
-- rebuilt the firewall's nft table each time.
M.last_written = nil
function M.save(st)
	local tmp = M._state_file .. ".tmp"
	local f = io.open(tmp, "w")
	if not f then
		local dir = M._state_file:match("^(.*)/[^/]+$")
		if dir then os.execute("mkdir -p '" .. dir .. "'") end
		f = io.open(tmp, "w")
		if not f then
			error("state.save: cannot write to " .. tmp)
		end
	end
	local body = cjson.encode(st)
	f:write(body)
	f:close()
	local ok, err = os.rename(tmp, M._state_file)
	if not ok then
		os.remove(tmp)
		error("state.save: cannot replace " .. M._state_file .. ": " .. tostring(err))
	end
	M.last_written = body
end

-- Reset state to defaults and persist immediately.
function M.reset()
	local st = defaults()
	M.save(st)
	return st
end

return M
