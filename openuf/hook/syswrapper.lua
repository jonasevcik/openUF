--[[
	syswrapper.lua — adoption and inform-URL management hook.

	Called by syswrapper.sh when the UniFi controller SSHes in to adopt
	or reconfigure the device.

	Usage (via syswrapper.sh):
	  syswrapper.sh set-adopt  <inform_url> <authkey_hex32>
	  syswrapper.sh set-inform <inform_url>
	  syswrapper.sh reset-inform

	authkey_hex32: exactly 32 hex characters (= 16 bytes, AES-128 key).
	inform_url:    http(s)://host:port/inform

	Exit codes: 0 = success, 1 = invalid arguments.
]]--

local state

-- conf.lua's state_file option, read as TEXT from the conf.lua next to the
-- state.lua that was found. conf.lua cannot simply be dofile()d from here: it
-- dofile()s its modelmap by a path relative to /opt/openuf, and this hook runs
-- from wherever the controller's SSH session happens to land. One uncommented
-- assignment line is all that is needed -- the same approach install.sh takes
-- for inform_url. inform.lua and announce.lua honour the option too, so the
-- three processes that touch state.json agree on where it is; before this none
-- of them did and the option was documentation only.
local function conf_state_file(dir)
	local f = io.open(dir .. "conf.lua", "r")
	if not f then return nil end
	local src = f:read("*a")
	f:close()
	for line in src:gmatch("[^\n]+") do
		local v = line:match('^%s*state_file%s*=%s*"([^"]+)"')
		if v then return v end
	end
	return nil
end

-- Allow the state module path to be injected for testing
local function load_state()
	if state then return state end
	-- Try relative paths: called from openuf/ dir or from an absolute install path
	local paths = {"state.lua", "openuf/state.lua", "/opt/openuf/state.lua"}
	for _, p in ipairs(paths) do
		local f = io.open(p, "r")
		if f then
			f:close()
			state = dofile(p)
			local sf = conf_state_file(p:match("^(.*/)") or "")
			if sf then state._state_file = sf end
			return state
		end
	end
	error("syswrapper: cannot find state.lua")
end

local function usage()
	io.stderr:write(
		"Usage: syswrapper.sh set-adopt <url> <key32hex>\n" ..
		"       syswrapper.sh set-inform <url>\n" ..
		"       syswrapper.sh reset-inform\n" ..
		"\n" ..
		"key32hex: exactly 32 hexadecimal characters (16 bytes, AES-128)\n"
	)
end

local function is_hex32(s)
	return type(s) == "string" and #s == 32 and s:match("^[0-9a-fA-F]+$") ~= nil
end

local function is_url(s)
	return type(s) == "string" and (s:match("^https?://") ~= nil)
end

-- ─── Commands ────────────────────────────────────────────────────────────────

-- set-adopt <url> <key>
-- Called by the controller after clicking Adopt.  Stores the new authkey
-- and marks the device as adopted.
local function cmd_set_adopt(url, key)
	if not is_url(url) then
		io.stderr:write("syswrapper: invalid URL: " .. tostring(url) .. "\n")
		return false
	end
	if not is_hex32(key) then
		io.stderr:write("syswrapper: invalid authkey (expected 32 hex chars): "
			.. tostring(key) .. "\n")
		return false
	end
	local st = load_state()
	local s  = st.load()
	s.inform_url = url
	s.authkey    = key:lower()
	s.adopted    = true
	st.save(s)
	io.stdout:write("syswrapper: adopted; inform_url=" .. url .. "\n")
	return true
end

-- set-inform <url>
-- Manually point the device at a controller URL (pre-adoption L3 setup).
local function cmd_set_inform(url)
	if not is_url(url) then
		io.stderr:write("syswrapper: invalid URL: " .. tostring(url) .. "\n")
		return false
	end
	local st = load_state()
	local s  = st.load()
	s.inform_url = url
	st.save(s)
	io.stdout:write("syswrapper: inform_url set to " .. url .. "\n")
	return true
end

-- reset-inform
-- Return to factory defaults: clears authkey and marks as un-adopted.
local function cmd_reset_inform()
	local st = load_state()
	st.reset()
	io.stdout:write("syswrapper: reset to defaults\n")
	return true
end

-- ─── Entry point ─────────────────────────────────────────────────────────────

local function main(args)
	local cmd = args[1]
	if cmd == "set-adopt" then
		if not cmd_set_adopt(args[2], args[3]) then
			usage(); os.exit(1)
		end
	elseif cmd == "set-inform" then
		if not cmd_set_inform(args[2]) then
			usage(); os.exit(1)
		end
	elseif cmd == "reset-inform" then
		cmd_reset_inform()
	else
		io.stderr:write("syswrapper: unknown command: " .. tostring(cmd) .. "\n")
		usage()
		os.exit(1)
	end
	os.exit(0)
end

-- When executed as a script, arg[1..] are the command-line arguments.
-- When required/dofile'd in tests, SYSWRAPPER_TEST_MODE must be set.
if not SYSWRAPPER_TEST_MODE then
	main(arg or {})
end

-- Export command functions for unit testing
return {
	cmd_set_adopt  = cmd_set_adopt,
	cmd_set_inform = cmd_set_inform,
	cmd_reset_inform = cmd_reset_inform,
	is_hex32 = is_hex32,
	is_url   = is_url,
	_set_state = function(s) state = s end,
	_conf_state_file = conf_state_file,
}
