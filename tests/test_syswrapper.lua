-- Tests for openuf/hook/syswrapper.lua (set-adopt, set-inform, reset-inform, 11k-scan, dfs-reset).
-- Run from project root: lua tests/run_tests.lua

SYSWRAPPER_TEST_MODE = true

-- syswrapper.lua needs to find state.lua; load state first and inject it
local state = dofile("openuf/state.lua")

-- Redirect state to a temp file so tests don't touch /etc/openuf
state._state_file = "/tmp/openuf_test_sysw.json"

local sw = dofile("openuf/hook/syswrapper.lua")

-- Inject state module into syswrapper
sw._set_state(state)

-- Helper: reset the state file before each test
local function reset_state()
	os.remove("/tmp/openuf_test_sysw.json")
end

return {
	-- ── is_hex32 ──────────────────────────────────────────────────────────
	{
		name = "syswrapper: is_hex32 accepts valid 32-char hex",
		fn = function()
			assert_true(sw.is_hex32("ba86f2bbe107c7c57eb5f2690775c712"), "valid key")
			assert_true(sw.is_hex32("AABBCCDDEEFF00112233445566778899"), "uppercase")
		end
	},
	{
		name = "syswrapper: is_hex32 rejects wrong length",
		fn = function()
			assert_false(sw.is_hex32("ba86f2"),                              "too short")
			assert_false(sw.is_hex32("ba86f2bbe107c7c57eb5f2690775c712aa"), "too long")
			assert_false(sw.is_hex32(""),                                    "empty")
		end
	},
	{
		name = "syswrapper: is_hex32 rejects non-hex characters",
		fn = function()
			assert_false(sw.is_hex32("zz86f2bbe107c7c57eb5f2690775c712"), "non-hex z")
			assert_false(sw.is_hex32("ba86f2bbe107c7c57eb5f26907_5c712"), "underscore")
		end
	},
	-- ── is_url ────────────────────────────────────────────────────────────
	{
		name = "syswrapper: is_url accepts http and https",
		fn = function()
			assert_true(sw.is_url("http://192.168.1.1:8080/inform"),  "http")
			assert_true(sw.is_url("https://unifi.example.com/inform"), "https")
		end
	},
	{
		name = "syswrapper: is_url rejects bare hostname and other schemes",
		fn = function()
			assert_false(sw.is_url("192.168.1.1:8080/inform"), "no scheme")
			assert_false(sw.is_url("ftp://host/path"),         "ftp scheme")
			assert_false(sw.is_url(""),                        "empty")
		end
	},
	-- ── set-adopt ─────────────────────────────────────────────────────────
	{
		name = "syswrapper: set-adopt stores authkey and sets adopted=true",
		fn = function()
			reset_state()
			local key = "deadbeefdeadbeefdeadbeefdeadbeef"
			local url = "http://10.0.0.1:8080/inform"
			assert_true(sw.cmd_set_adopt(url, key), "set-adopt succeeds")
			local st = state.load()
			assert_true(st.adopted,          "adopted is true")
			assert_eq(st.authkey, key,       "authkey stored")
			assert_eq(st.inform_url, url,    "inform_url stored")
		end
	},
	{
		name = "syswrapper: set-adopt normalises authkey to lowercase",
		fn = function()
			reset_state()
			local key_upper = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
			sw.cmd_set_adopt("http://10.0.0.1:8080/inform", key_upper)
			local st = state.load()
			assert_eq(st.authkey, key_upper:lower(), "authkey lowercased")
		end
	},
	{
		name = "syswrapper: set-adopt rejects invalid authkey",
		fn = function()
			reset_state()
			assert_false(sw.cmd_set_adopt("http://10.0.0.1:8080/inform", "tooshort"), "short key rejected")
			assert_false(sw.cmd_set_adopt("http://10.0.0.1:8080/inform", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), "non-hex rejected")
		end
	},
	{
		name = "syswrapper: set-adopt rejects invalid URL",
		fn = function()
			reset_state()
			local key = "deadbeefdeadbeefdeadbeefdeadbeef"
			assert_false(sw.cmd_set_adopt("10.0.0.1:8080/inform", key), "no scheme rejected")
		end
	},
	{
		name = "syswrapper: set-adopt takes this device's MAC in any case and refuses another",
		fn = function()
			reset_state()
			local s = state.load()
			s.mac = "00:00:5e:00:53:01"
			state.save(s)
			local key = "deadbeefdeadbeefdeadbeefdeadbeef"
			local url = "http://192.0.2.1:8080/inform"
			local real = io.stderr
			io.stderr = {write = function() end}
			local other = sw.cmd_set_adopt(url, key, "00:00:5e:00:53:02")
			local bad = sw.cmd_set_adopt(url, key, "not-a-mac")
			io.stderr = real
			assert_false(other, "another device's MAC is refused")
			assert_false(bad, "a malformed MAC is refused")
			assert_false(state.load().adopted, "neither adopted the device")
			assert_true(sw.cmd_set_adopt(url, key, "00:00:5E:00:53:01"), "own MAC, upper case")
			assert_true(state.load().adopted, "adopted")
		end
	},
	{
		name = "adopt-shell: accepts the 10.6 form with the absolute path and an optional MAC",
		fn = function()
			-- A copy of the shell that execs a stub instead of /usr/bin/syswrapper.sh.
			local dir = "/tmp/openuf_test_adoptshell_" .. tostring(os.time())
			os.execute("mkdir -p '" .. dir .. "'")
			local f = io.open("openuf/hook/adopt-shell.sh", "r")
			local src = f:read("*a")
			f:close()
			local n
			src, n = src:gsub("\nSYSWRAPPER=/usr/bin/syswrapper.sh\n",
				"\nSYSWRAPPER=" .. dir .. "/sw\n")
			assert_eq(n, 1, "the shell names its syswrapper in one assignment")
			f = io.open(dir .. "/adopt-shell.sh", "w")
			f:write(src)
			f:close()
			f = io.open(dir .. "/sw", "w")
			f:write('#!/bin/sh\necho "RAN $*"\n')
			f:close()
			os.execute("chmod +x '" .. dir .. "/sw'")
			local function run(cmd)
				local h = io.popen("sh '" .. dir .. "/adopt-shell.sh' -c '" .. cmd .. "' 2>&1")
				local out = h:read("*a")
				h:close()
				return out
			end
			local url = "http://192.0.2.1:8080/inform"
			local key = string.rep("ab", 16)
			local mac = "00:00:5e:00:53:01"
			local sw_path = dir .. "/sw"

			assert_contains(run("syswrapper.sh set-adopt " .. url .. " " .. key),
				"RAN set-adopt " .. url .. " " .. key, "the bare form")
			assert_contains(run(sw_path .. " set-adopt " .. url .. " " .. key),
				"RAN set-adopt " .. url .. " " .. key, "the absolute path 10.6 sends")
			assert_contains(run(sw_path .. " set-adopt " .. url .. " " .. key .. " " .. mac),
				"RAN set-adopt " .. url .. " " .. key .. " " .. mac, "the MAC is passed on")
			assert_contains(run(sw_path .. " set-adopt " .. url .. " " .. key .. " 00:00:5e:00:53"),
				"invalid mac", "a short MAC is refused")
			assert_contains(run(sw_path .. " set-adopt " .. url .. " " .. key .. " " .. mac .. " x"),
				"malformed command", "a sixth word is refused")
			assert_contains(run("/bin/sh -c id"), "not permitted", "other commands are refused")
			assert_true(run(sw_path .. " set-adopt " .. url .. " " .. key .. "; id")
				:find("RAN", 1, true) == nil, "no command chaining")
			os.execute("rm -rf '" .. dir .. "'")
		end
	},
	-- ── set-inform ────────────────────────────────────────────────────────
	{
		name = "syswrapper: set-inform updates inform_url without touching authkey",
		fn = function()
			reset_state()
			-- Pre-set a custom authkey via adopt
			sw.cmd_set_adopt("http://old:8080/inform", "deadbeefdeadbeefdeadbeefdeadbeef")
			local key_before = state.load().authkey

			sw.cmd_set_inform("http://new-controller:8080/inform")
			local st = state.load()
			assert_eq(st.inform_url, "http://new-controller:8080/inform", "url updated")
			assert_eq(st.authkey, key_before, "authkey unchanged by set-inform")
		end
	},
	{
		name = "syswrapper: set-inform rejects invalid URL",
		fn = function()
			assert_false(sw.cmd_set_inform("not-a-url"), "rejected")
		end
	},
	-- ── reset-inform ──────────────────────────────────────────────────────
	{
		name = "syswrapper: reset-inform sets adopted=false and clears authkey",
		fn = function()
			reset_state()
			-- First adopt
			sw.cmd_set_adopt("http://10.0.0.1:8080/inform", "deadbeefdeadbeefdeadbeefdeadbeef")
			assert_true(state.load().adopted, "sanity: adopted before reset")

			sw.cmd_reset_inform()
			local st = state.load()
			assert_false(st.adopted,                        "adopted is false after reset")
			assert_eq(st.authkey, state.DEFAULT_KEY,        "authkey reset to default")
		end
	},
	{
		name = "syswrapper: conf.lua's state_file is honoured, so all three processes agree",
		fn = function()
			-- The option was documented for years and read by nothing: every
			-- entry point used state.lua's hardcoded default, so a device that
			-- set it had inform.lua writing one file and syswrapper's
			-- SSH set-adopt writing another. conf.lua cannot be dofile()d from
			-- this hook (it dofile()s its modelmap by a path relative to
			-- /opt/openuf, and the controller's SSH session lands anywhere),
			-- so the one assignment line is read as text.
			local dir = "/tmp/openuf_test_conf_" .. tostring(os.time()) .. "/"
			os.execute("mkdir -p '" .. dir .. "'")
			local f = io.open(dir .. "conf.lua", "w")
			f:write("config = {\n")
			f:write("\t-- state_file = \"/decoy/commented-out.json\"\n")
			f:write("\tinform_url = \"http://unifi:8080/inform\",\n")
			f:write("\tstate_file = \"/srv/openuf/state.json\",\n")
			f:write("}\n")
			f:close()
			local got = sw._conf_state_file(dir)
			os.execute("rm -rf '" .. dir .. "'")
			assert_eq(got, "/srv/openuf/state.json", "the live assignment is read")
		end
	},
	{
		name = "syswrapper: a conf.lua without state_file leaves the default alone",
		fn = function()
			local dir = "/tmp/openuf_test_conf2_" .. tostring(os.time()) .. "/"
			os.execute("mkdir -p '" .. dir .. "'")
			local f = io.open(dir .. "conf.lua", "w")
			f:write('config = {\n\tinform_url = "http://unifi:8080/inform",\n}\n')
			f:close()
			local got = sw._conf_state_file(dir)
			os.execute("rm -rf '" .. dir .. "'")
			assert_nil(got, "no option, no override")
			assert_nil(sw._conf_state_file("/nonexistent-dir-openuf/"),
				"no conf.lua at all is not an error either")
		end
	},
	{
		name = "syswrapper: 11k-scan leaves two due times inside the hour, spread as UniFi firmware does",
		fn = function()
			local FILE = "/tmp/openuf_test_sysw_scan"
			os.remove(FILE)
			sw._set_scan_request_file(FILE)
			sw._set_clock(function() return 1000000 end)
			local asked = {}
			local function run(pick)
				asked = {}
				sw._set_rand(function(n) asked[#asked + 1] = n; return pick(n) end)
				local real = io.stdout
				io.stdout = {write = function() end}
				local ok = sw.cmd_11k_scan()
				io.stdout = real
				local f = io.open(FILE, "r")
				local body = f and f:read("*a")
				if f then f:close() end
				local due = {}
				for d in (body or ""):gmatch("%d+") do due[#due + 1] = tonumber(d) end
				return ok, due
			end

			local ok, low = run(function() return 0 end)
			local asked_low = asked
			local _, high = run(function(n) return n - 1 end)
			local asked_high = asked
			local _, mid = run(function() return 1000 end)

			-- The real source: in range, and not constant.
			local seen, inrange = {}, true
			for _ = 1, 50 do
				local v = sw._urandom_below(3590)
				if v < 0 or v >= 3590 or v ~= math.floor(v) then inrange = false end
				seen[v] = true
			end
			local distinct = 0
			for _ in pairs(seen) do distinct = distinct + 1 end

			os.remove(FILE)
			sw._set_rand(nil)
			sw._set_clock(nil)

			assert_true(ok, "succeeds")
			assert_eq(#low, 2, "two scans")
			assert_eq(low[1], 1000010, "the earliest is 10 s out")
			assert_eq(low[2], 1000020, "the second 10 s after the first")
			assert_eq(asked_low[1], 3590, "the first delay is drawn from the hour less 10 s")
			assert_eq(asked_low[2], 3580, "the second from what is left, less 10 s")
			assert_eq(high[1], 1000000 + 10 + 3589, "the latest first scan is just inside the hour")
			assert_eq(asked_high[2], 1, "which leaves the second no room to wander")
			assert_true(high[2] <= 1000000 + sw.SCAN_WINDOW + 10, "but it still lands at the window's end")
			assert_eq(mid[1], 1001010, "10 s + the random delay")
			assert_eq(mid[2], 1002020, "then 10 s + another")
			assert_true(inrange, "/dev/urandom gives integers in [0, n)")
			assert_true(distinct > 10, "that vary")

			-- An unwritable path fails loudly rather than pretending.
			sw._set_scan_request_file("/nonexistent-dir/x")
			local err = ""
			local rs = io.stderr
			io.stderr = {write = function(_, s) err = err .. s end}
			assert_false(sw.cmd_11k_scan(), "fails")
			io.stderr = rs
			assert_contains(err, "cannot write", "says so")
			sw._set_scan_request_file("/tmp/openuf-scan-request")
		end
	},
	{
		name = "syswrapper: dfs-reset leaves a stamped request for the daemon",
		fn = function()
			local FILE = "/tmp/openuf_test_sysw_dfs"
			os.remove(FILE)
			sw._set_dfs_request_file(FILE)
			sw._set_clock(function() return 1000000 end)
			local real = io.stdout
			io.stdout = {write = function() end}
			local ok = sw.cmd_dfs_reset()
			io.stdout = real
			local f = io.open(FILE, "r")
			local body = f and f:read("*a")
			if f then f:close() end
			os.remove(FILE)
			sw._set_clock(nil)
			assert_true(ok, "succeeds")
			-- One timestamp and nothing else: the hook does no radio work and
			-- holds no policy, so there is nothing else to pass on.
			assert_eq(body, "1000000\n", "the request is the time it was made")

			sw._set_dfs_request_file("/nonexistent-dir/x")
			local err = ""
			local rs = io.stderr
			io.stderr = {write = function(_, s) err = err .. s end}
			assert_false(sw.cmd_dfs_reset(), "an unwritable path fails")
			io.stderr = rs
			assert_contains(err, "cannot write", "and says so")
			sw._set_dfs_request_file("/tmp/openuf-dfs-reset-request")
		end
	},
}
