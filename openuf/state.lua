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

local function defaults()
	return {
		authkey                  = M.DEFAULT_KEY,
		adopted                  = false,
		cfgversion               = "",
		inform_url               = "http://unifi:8080/inform",
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
	locating                  = "boolean",
	locate_prev_trigger       = "string",
	-- The per-port VLAN reversibility ledger: the stock `ports` strings of
	-- every switch_vlan section openUF overwrote. Without it restore() has
	-- nothing to put back and the board keeps openUF's VLAN config forever.
	swvlan_backup             = "table",
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
		return defaults()
	end

	local st = defaults()
	for field, want in pairs(M.FIELDS) do
		if type(tbl[field]) == want then st[field] = tbl[field] end
	end

	-- Security invariant: never use a custom key when not adopted
	if not st.adopted then
		st.authkey = M.DEFAULT_KEY
	end

	return st
end

-- Save state to disk. Creates the parent directory only if the first write
-- fails (avoids shelling out to `mkdir -p` on every heartbeat, since the
-- directory almost always already exists).
function M.save(st)
	local f = io.open(M._state_file, "w")
	if not f then
		local dir = M._state_file:match("^(.*)/[^/]+$")
		if dir then os.execute("mkdir -p '" .. dir .. "'") end
		f = io.open(M._state_file, "w")
		if not f then
			error("state.save: cannot write to " .. M._state_file)
		end
	end
	f:write(cjson.encode(st))
	f:close()
end

-- Reset state to defaults and persist immediately.
function M.reset()
	local st = defaults()
	M.save(st)
	return st
end

return M
