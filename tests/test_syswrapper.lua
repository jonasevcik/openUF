-- Tests for openuf/hook/syswrapper.lua (set-adopt, set-inform, reset-inform).
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
}
