--[[
	plugins.lua -- opt-in third-party extensions to the per-VAP UCI options.

	openUF cannot carry every interoperability recipe, and some depend on
	software that changes the stock OpenWrt install (daemons, extra netdevs).
	A plugin lets such a recipe live in its own project and be switched on per
	device, while openUF itself stays what ships on a clean OpenWrt.

	Off by default. conf.lua's `config.plugins = {"name", ...}` is an explicit
	allowlist: nothing in the plugin directory is loaded unless it is named.
	With the list empty or absent, apply_config's output is unchanged.

	A plugin is /etc/openuf/plugins/<name>.lua, which returns

	    return {
	        name = "name",
	        api  = 1,
	        vap_options = function(extra, vap, ctx) ... end,
	    }

	vap_options runs once per VAP in ucihelper.apply_config, after every
	built-in option has been put in `extra` and before wlan_add writes it. It
	edits `extra` (UCI option -> string | list of strings | ctx.DELETE) and
	may override what openUF set, mobility_domain for instance. `vap` is a copy
	of the parsed controller VAP without its passphrase. `ctx` carries:

	    ctx.DELETE            the "remove this option" sentinel
	    ctx.bssid(radio,ssid) this VAP's live BSSID, or nil
	    ctx.cursor()          a UCI cursor for reading other configs
	    ctx.read_file(path)   file contents or nil
	    ctx.util              {bit (band/bor/... table), is_mac, valid_ifname, read_file}
	    ctx.log(msg)          a line in the system log, prefixed with the name

	Guard rails. A plugin that fails to load, has another `api`, raises, or
	returns a bad edit is logged and skipped; the VAP is provisioned without
	its contribution and the push goes on. An edit is all-or-nothing per VAP.
	An option name must be [A-Za-z0-9_]+ (libuci drops anything else
	silently), and a plugin may not touch the section's identity (device,
	mode, ssid, encryption, network, key) or the openuf_* stamps that drive
	openUF's own enforcement.

	No teardown is needed: apply_config rebuilds every openuf_ section from
	scratch on each push (wlan_clear), so dropping a plugin from the list
	drops its options with the next push.

	A plugin is arbitrary Lua running as root, exactly as conf.lua is. This
	module is a hook, not a sandbox.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M.API = 1
M.DIR = "/etc/openuf/plugins"
-- Second opt-in source beside conf.lua: one plugin name per line, `#` starts a
-- comment. An installer edits this, never the user's conf.lua.
M.LIST = "/etc/openuf/plugins.enabled"

-- Injectable seams.
M._read_file = util.read_file
M._log = function(msg) io.stderr:write("openuf: plugin " .. msg .. "\n") end

-- Options a plugin may not set: the section's identity, which wlan_add writes
-- before `extra`, and openUF's own stamps (openuf_*).
local RESERVED = {
	device = true, mode = true, ssid = true, encryption = true,
	network = true, key = true,
}

-- Load plugin `name`: its table, or nil and the reason. Cached per process, so
-- a changed plugin file takes a restart (as conf.lua does).
local loaded = {}

function M._load(name)
	local path = M.DIR .. "/" .. name .. ".lua"
	local src = M._read_file(path)
	if not src then return nil, "cannot read " .. path end
	local chunk, err = (loadstring or load)(src, "=" .. path)
	if not chunk then return nil, err end
	local ok, mod = pcall(chunk)
	if not ok then return nil, tostring(mod) end
	return mod
end

-- Forget what has been loaded (tests).
function M._reset() loaded = {} end

local function get(name)
	if loaded[name] == nil then
		local mod, err
		if not tostring(name):match("^[%w_%-]+$") then
			err = "invalid plugin name"
		else
			mod, err = M._load(name)
		end
		if mod ~= nil and type(mod) ~= "table" then
			mod, err = nil, "did not return a table"
		end
		if mod and mod.api ~= M.API then
			mod, err = nil, string.format("api %s, this openUF speaks api %d",
				tostring(mod.api), M.API)
		end
		if mod and type(mod.vap_options) ~= "function" then
			mod, err = nil, "has no vap_options function"
		end
		if not mod then
			M._log(string.format("%s: not loaded: %s", tostring(name), tostring(err)))
		end
		loaded[name] = mod or false
	end
	return loaded[name] or nil
end

-- The plugin names asked for: conf.lua's list first, then M.LIST's lines. A
-- name listed twice appears once.
local function names_of(cfg)
	local names = cfg and cfg.config and cfg.config.plugins
	local all = {}
	if type(names) == "table" then
		for _, n in ipairs(names) do all[#all + 1] = n end
	elseif names ~= nil then
		M._log("config.plugins must be a list of names; ignored")
	end
	local text = M._read_file(M.LIST)
	if text then
		for raw in text:gmatch("[^\r\n]+") do
			local line = raw:gsub("#.*", ""):match("^%s*(.-)%s*$")
			if line ~= "" then all[#all + 1] = line end
		end
	end
	return all
end

-- The answer to M.enabled, cached for the length of one config push.
--
-- vap_options is called once per VAP, and every call walked names_of again --
-- which opens /etc/openuf/plugins.enabled -- BEFORE the `#list == 0` early
-- return, so an install with no plugins at all (every install, until someone
-- drops a file in) paid one file open per WLAN per push for a list that is
-- always empty. The list cannot change mid-push: conf.lua is read at startup
-- and _reconcile_plugins has already fingerprinted the files.
--
-- Deliberately NOT nest-safe the way ucihelper.begin_pass is: there is one
-- caller (apply_config's VAP loop) and begin_pass drops the cache on entry, so
-- a pass left open by a raise inside the loop cannot serve a stale list to the
-- next push. Outside a pass every call re-reads, which keeps the test suite's
-- per-test _read_file stubs independent of one another.
M._pass = false
M._pass_list = nil
function M.begin_pass() M._pass, M._pass_list = true, nil end
function M.end_pass()   M._pass, M._pass_list = false, nil end

-- The enabled plugins, in order. A name listed twice runs once.
function M.enabled(cfg)
	-- Keyed on the cfg table itself, not just on the pass: a caller that
	-- opened a pass and then asked about a different config gets a real
	-- answer rather than the first one.
	if M._pass and M._pass_list and M._pass_list.cfg == cfg then
		return M._pass_list.list
	end
	local out, seen = {}, {}
	for _, name in ipairs(names_of(cfg)) do
		if not seen[name] then
			seen[name] = true
			local mod = get(name)
			if mod then out[#out + 1] = {name = name, mod = mod} end
		end
	end
	if M._pass then M._pass_list = {cfg = cfg, list = out} end
	return out
end

-- A short string that moves when the set of requested plugins, or the source
-- of one of them, changes. "" when none is requested. Not a security hash: it
-- only tells openUF that the pushed WLAN options may be stale.
function M.fingerprint(cfg)
	local parts = {}
	for _, name in ipairs(names_of(cfg)) do
		local src = tostring(name):match("^[%w_%-]+$") and M._read_file(M.DIR .. "/" .. name .. ".lua")
		local h = 5381
		for i = 1, #(src or "") do h = (h * 33 + src:byte(i)) % 4294967296 end
		parts[#parts + 1] = string.format("%s:%.0f", name, src and h or -1)
	end
	return table.concat(parts, ",")
end

-- The helpers a plugin may use, so it never reaches into openUF's modules.
local function make_util()
	return {
		bit = util.bit(), is_mac = util.is_mac,
		valid_ifname = util.valid_ifname, read_file = M._read_file,
	}
end

-- Deep copy that keeps the DELETE sentinel itself: it is compared by identity.
local function copy(t, keep)
	local out = {}
	for k, v in pairs(t) do
		out[k] = (type(v) == "table" and v ~= keep) and copy(v, keep) or v
	end
	return out
end

local function same(a, b)
	if type(a) ~= "table" or type(b) ~= "table" then return a == b end
	if #a ~= #b then return false end
	for i = 1, #a do
		if a[i] ~= b[i] then return false end
	end
	return true
end

-- Why `v` is not a legal option value, or nil.
local function bad_value(v, DELETE)
	if v == DELETE then return nil end
	local t = type(v)
	if t == "string" or t == "number" or t == "boolean" then return nil end
	if t == "table" then
		for _, e in ipairs(v) do
			local et = type(e)
			if et ~= "string" and et ~= "number" then return "list element is a " .. et end
		end
		return nil
	end
	return "a " .. t
end

-- Why the edit from `before` to `after` is not allowed, or nil.
local function bad_edit(before, after, DELETE)
	for k, v in pairs(after) do
		if type(k) ~= "string" or not k:match("^[%w_]+$") then
			return "option name " .. string.format("%q", tostring(k)) .. " is not [A-Za-z0-9_]+"
		end
		if not same(before[k], v) then
			if RESERVED[k] or k:sub(1, 7) == "openuf_" then
				return "option '" .. k .. "' is reserved to openUF"
			end
			local why = bad_value(v, DELETE)
			if why then return "option '" .. k .. "' is " .. why end
		end
	end
	return nil
end

-- Run every enabled plugin's vap_options on `extra`, in place. `env` is
-- {DELETE, bssid(radio, ssid), cursor()} from ucihelper. Never raises.
function M.vap_options(extra, vap, cfg, env)
	local list = M.enabled(cfg)
	if #list == 0 then return extra end
	local view = copy(vap, env.DELETE)
	view.x_passphrase = nil
	for _, p in ipairs(list) do
		local ctx = {
			DELETE    = env.DELETE,
			bssid     = env.bssid,
			cursor    = env.cursor,
			read_file = M._read_file,
			util      = make_util(),
			log       = function(msg) M._log(p.name .. ": " .. tostring(msg)) end,
		}
		local work = copy(extra, env.DELETE)
		local ok, err = pcall(p.mod.vap_options, work, copy(view, env.DELETE), ctx)
		if ok then err = bad_edit(extra, work, env.DELETE) end
		if ok and not err then
			for k in pairs(extra) do extra[k] = nil end
			for k, v in pairs(work) do extra[k] = v end
		else
			M._log(string.format("%s: skipped for %s on %s: %s", p.name,
				tostring(vap.ssid), tostring(vap.radio), tostring(err)))
		end
	end
	return extra
end

return M
