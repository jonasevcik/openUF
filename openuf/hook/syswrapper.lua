--[[
	syswrapper.lua — adoption and inform-URL management hook.

	Called by syswrapper.sh when the UniFi controller SSHes in to adopt
	or reconfigure the device.

	Usage (via syswrapper.sh):
	  syswrapper.sh set-adopt  <inform_url> <authkey_hex32> [<mac>]
	  syswrapper.sh set-inform <inform_url>
	  syswrapper.sh reset-inform
	  syswrapper.sh 11k-scan          -- the controller's nightly cron job
	  syswrapper.sh dfs-reset         -- its other one: back onto a fixed DFS channel

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
		"Usage: syswrapper.sh set-adopt <url> <key32hex> [<mac>]\n" ..
		"       syswrapper.sh set-inform <url>\n" ..
		"       syswrapper.sh reset-inform\n" ..
		"       syswrapper.sh 11k-scan\n" ..
		"       syswrapper.sh dfs-reset\n" ..
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

local function is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

-- ─── Commands ────────────────────────────────────────────────────────────────

-- set-adopt <url> <key> [<mac>]
-- Called by the controller after clicking Adopt.  Stores the new authkey
-- and marks the device as adopted.
-- A MAC that differs from the one this device informs with is refused: the
-- controller is adopting another device at this address.
local function cmd_set_adopt(url, key, mac)
	if not is_url(url) then
		io.stderr:write("syswrapper: invalid URL: " .. tostring(url) .. "\n")
		return false
	end
	if not is_hex32(key) then
		io.stderr:write("syswrapper: invalid authkey (expected 32 hex chars): "
			.. tostring(key) .. "\n")
		return false
	end
	if mac ~= nil and not is_mac(mac) then
		io.stderr:write("syswrapper: invalid MAC: " .. tostring(mac) .. "\n")
		return false
	end
	local st = load_state()
	local s  = st.load()
	if mac and type(s.mac) == "string" and s.mac:lower() ~= mac:lower() then
		io.stderr:write("syswrapper: set-adopt names " .. mac .. ", this device is "
			.. s.mac .. "\n")
		return false
	end
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

-- 11k-scan
-- What the controller's pushed cron job runs at 04:00 every night (see
-- sysconf.lua): a neighbour scan on every radio. The scan itself is the
-- inform daemon's job -- it owns the radios' netdev names and the scan
-- cache, and its next heartbeat carries the result out -- so this only
-- leaves a request file that inform.lua's _maybe_service_scan_request reads
-- each heartbeat.
--
-- The request holds two due times, as UniFi firmware schedules this job
-- (syswrapper.sh elevenk_scan -> elevenk_sched 3600 2, firmware-confirmed for
-- 4.0.15): two scans inside one hour, each 10 s plus a random delay drawn from
-- what is left of the hour. Every AP's crond fires at 04:00 sharp, so without
-- the random delay all APs go off-channel at the same second and each one's
-- sweep finds its neighbours off-channel too. A new request replaces a pending
-- one, as elevenk_sched kills the previous run. The randomness comes from
-- /dev/urandom like the firmware's: math.random seeded from the clock would
-- give two APs started by the same cron second the same delays.
local scan_request_file = "/tmp/openuf-scan-request"
local SCAN_WINDOW, SCAN_COUNT, SCAN_DELAY = 3600, 2, 10

-- A uniform integer in [0, n). Injectable for tests.
local function urandom_below(n)
	local f = io.open("/dev/urandom", "rb")
	local b = f and f:read(3)
	if f then f:close() end
	if not b or #b < 3 then return math.random(0, n - 1) end
	-- 24 bits: far more than a 3600 s window needs, and clear of the
	-- 2^31 limit of the APs' LNUM-patched Lua.
	return ((b:byte(1) * 256 + b:byte(2)) * 256 + b:byte(3)) % n
end
local rand_below = urandom_below
local now = os.time

-- elevenk_run's arithmetic: the window shrinks by each delay taken, so the
-- second scan always lands after the first and both inside the window.
local function scan_due_times(t0)
	local left, at, due = SCAN_WINDOW, t0, {}
	for i = 1, SCAN_COUNT do
		left = left - SCAN_DELAY
		if left < 1 then left = 1 end
		local r = rand_below(left)
		left = left - r
		at = at + SCAN_DELAY + r
		due[i] = at
	end
	return due
end

local function cmd_11k_scan()
	local t0 = now()
	local due = scan_due_times(t0)
	local f = io.open(scan_request_file, "w")
	if not f then
		io.stderr:write("syswrapper: cannot write " .. scan_request_file .. "\n")
		return false
	end
	f:write(table.concat(due, "\n"), "\n")
	f:close()
	local ins = {}
	for i, t in ipairs(due) do ins[i] = tostring(t - t0) .. " s" end
	io.stdout:write("syswrapper: neighbour scans requested in " .. table.concat(ins, " and ") ..
		"; the inform daemon runs each on the heartbeat after it falls due\n")
	return true
end

-- dfs-reset
-- The controller's other pushed cron job (02:00 nightly, see sysconf.lua),
-- scheduled whenever the site has a 5 GHz radio pinned to a fixed DFS
-- channel. After a radar hit the radio leaves that channel for another one
-- and never comes back on its own; this job puts it back once the 30-minute
-- non-occupancy list has expired.
--
-- Like 11k-scan, the work belongs to the inform daemon -- it owns the radios'
-- netdev names, the live channel and the control sockets -- so this only
-- leaves a request file that inform._maybe_service_dfs_reset reads on its
-- next heartbeat. No randomisation here, unlike the scan: the firmware's
-- dfs_reset has none either, and a channel switch is not an off-channel sweep
-- that neighbouring APs can spoil for each other.
local dfs_request_file = "/tmp/openuf-dfs-reset-request"

local function cmd_dfs_reset()
	local f = io.open(dfs_request_file, "w")
	if not f then
		io.stderr:write("syswrapper: cannot write " .. dfs_request_file .. "\n")
		return false
	end
	f:write(tostring(now()), "\n")
	f:close()
	io.stdout:write("syswrapper: DFS channel reset requested; the inform daemon"
		.. " checks each 5 GHz radio on its next heartbeat\n")
	return true
end

-- ─── Entry point ─────────────────────────────────────────────────────────────

local function main(args)
	local cmd = args[1]
	if cmd == "set-adopt" then
		if not cmd_set_adopt(args[2], args[3], args[4]) then
			usage(); os.exit(1)
		end
	elseif cmd == "set-inform" then
		if not cmd_set_inform(args[2]) then
			usage(); os.exit(1)
		end
	elseif cmd == "reset-inform" then
		cmd_reset_inform()
	elseif cmd == "11k-scan" then
		if not cmd_11k_scan() then os.exit(1) end
	elseif cmd == "dfs-reset" then
		if not cmd_dfs_reset() then os.exit(1) end
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
	cmd_11k_scan = cmd_11k_scan,
	cmd_dfs_reset = cmd_dfs_reset,
	_set_scan_request_file = function(p) scan_request_file = p end,
	_set_dfs_request_file = function(p) dfs_request_file = p end,
	_set_rand = function(f) rand_below = f or urandom_below end,
	_set_clock = function(f) now = f or os.time end,
	_urandom_below = urandom_below,
	SCAN_WINDOW = SCAN_WINDOW,
	is_hex32 = is_hex32,
	is_url   = is_url,
	_set_state = function(s) state = s end,
	_conf_state_file = conf_state_file,
}
