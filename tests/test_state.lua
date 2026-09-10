-- Tests for openuf/state.lua (state persistence).
-- Run from project root: lua tests/run_tests.lua

local state = dofile("openuf/state.lua")
local TMP = "/tmp/openuf_test_state.json"
local DEFKEY = state.DEFAULT_KEY

-- Helper: redirect state file to temp path for isolation
local function with_tmp(fn)
	state._state_file = TMP
	os.remove(TMP)
	local ok, err = pcall(fn)
	os.remove(TMP)
	state._state_file = "/etc/openuf/state.json"  -- restore
	if not ok then error(err, 2) end
end

-- Capture what the module writes to stderr while fn runs.
local function with_stderr(fn)
	local orig, buf = io.stderr, {}
	io.stderr = {write = function(_, ...)
		for _, v in ipairs({...}) do buf[#buf + 1] = tostring(v) end
	end}
	local ok, err = pcall(fn)
	io.stderr = orig
	if not ok then error(err, 0) end
	return table.concat(buf)
end

return {
	{
		name = "state: load from missing file returns defaults",
		fn = function()
			with_tmp(function()
				local st = state.load()
				assert_eq(st.authkey,    DEFKEY,                      "authkey default")
				assert_eq(st.adopted,    false,                       "adopted default")
				assert_eq(st.cfgversion, "",                          "cfgversion default")
				assert_eq(st.inform_url, "http://unifi:8080/inform",  "inform_url default")
			end)
		end
	},
	{
		name = "state: save + load round-trip preserves all fields",
		fn = function()
			with_tmp(function()
				local saved = {
					authkey    = "aabbccddeeff00112233445566778899",
					adopted    = true,
					cfgversion = "abc123",
					inform_url = "http://10.0.0.1:8080/inform",
				}
				state.save(saved)
				local loaded = state.load()
				assert_eq(loaded.authkey,    saved.authkey,    "authkey round-trip")
				assert_eq(loaded.adopted,    saved.adopted,    "adopted round-trip")
				assert_eq(loaded.cfgversion, saved.cfgversion, "cfgversion round-trip")
				assert_eq(loaded.inform_url, saved.inform_url, "inform_url round-trip")
			end)
		end
	},
	{
		name = "state: load resets authkey to default when adopted=false",
		fn = function()
			with_tmp(function()
				-- Save a state that claims not-adopted but has a custom key
				state.save({
					authkey    = "deadbeefdeadbeefdeadbeefdeadbeef",
					adopted    = false,
					cfgversion = "",
					inform_url = "http://unifi:8080/inform",
				})
				local loaded = state.load()
				assert_eq(loaded.authkey, DEFKEY, "authkey reset to default when not adopted")
				assert_eq(loaded.adopted, false,  "adopted still false")
			end)
		end
	},
	{
		name = "state: load preserves custom authkey when adopted=true",
		fn = function()
			with_tmp(function()
				local custom = "aabbccddeeff00112233445566778899"
				state.save({
					authkey    = custom,
					adopted    = true,
					cfgversion = "v1",
					inform_url = "http://unifi:8080/inform",
				})
				local loaded = state.load()
				assert_eq(loaded.authkey, custom, "custom authkey preserved when adopted")
				assert_eq(loaded.adopted, true,   "adopted preserved")
			end)
		end
	},
	{
		name = "state: reset sets adopted=false and clears authkey",
		fn = function()
			with_tmp(function()
				-- First save a custom adopted state
				state.save({
					authkey = "aabbccddeeff00112233445566778899",
					adopted = true,
					cfgversion = "v5",
					inform_url = "http://controller/inform",
				})
				-- Now reset
				local st = state.reset()
				assert_eq(st.authkey,    DEFKEY,                     "authkey reset")
				assert_eq(st.adopted,    false,                      "adopted reset")
				assert_eq(st.cfgversion, "",                         "cfgversion reset")
				assert_eq(st.inform_url, "http://unifi:8080/inform", "inform_url reset")
				-- Verify the file was also written
				local loaded = state.load()
				assert_eq(loaded.authkey, DEFKEY, "persisted authkey after reset")
			end)
		end
	},
	{
		name = "state: use_gcm field defaults to false and round-trips",
		fn = function()
			with_tmp(function()
				local st = state.load()
				assert_false(st.use_gcm, "use_gcm defaults to false")
				st.use_gcm = true
				st.adopted = true  -- need adopted=true to keep custom authkey
				state.save(st)
				local loaded = state.load()
				assert_true(loaded.use_gcm, "use_gcm round-trips as true")
				-- reset() must also clear use_gcm
				local fresh = state.reset()
				assert_false(fresh.use_gcm, "use_gcm cleared by reset")
			end)
		end
	},
	{
		name = "state: load from malformed JSON returns defaults",
		fn = function()
			with_tmp(function()
				local f = io.open(TMP, "w")
				f:write("this is not json {{{")
				f:close()
				local st
				with_stderr(function() st = state.load() end)
				assert_eq(st.authkey, DEFKEY, "defaults on bad JSON")
				assert_eq(st.adopted, false,  "defaults on bad JSON")
			end)
		end
	},
	{
		name = "state: blocked_stas and upgrade_requested_* round-trip type-checked",
		fn = function()
			-- These load() type-checks existed but were never exercised: a
			-- valid table/string round-trips, a wrong-typed value on disk
			-- falls back to the default instead of poisoning the state.
			with_tmp(function()
				local st = state.load()
				st.adopted = true
				st.blocked_stas = {"aa:bb:cc:dd:ee:ff"}
				st.upgrade_requested_version = "6.8.2"
				st.upgrade_requested_url = "http://x/fw.bin"
				state.save(st)
				local loaded = state.load()
				assert_eq(loaded.blocked_stas[1], "aa:bb:cc:dd:ee:ff", "block list round-trips")
				assert_eq(loaded.upgrade_requested_version, "6.8.2", "version round-trips")
				assert_eq(loaded.upgrade_requested_url, "http://x/fw.bin", "url round-trips")

				local f = io.open(TMP, "w")
				f:write('{"adopted":false,"blocked_stas":"not-a-table",'
					.. '"upgrade_requested_version":42}')
				f:close()
				local bad = state.load()
				assert_eq(type(bad.blocked_stas), "table", "wrong-typed block list -> default table")
				assert_eq(#bad.blocked_stas, 0, "default block list is empty")
				assert_eq(bad.upgrade_requested_version, "", "wrong-typed version -> default")
			end)
		end
	},
	{
		name = "state: every field any module writes survives a save/load round trip",
		fn = function()
			-- The invariant, checked against the SOURCE rather than a list
			-- kept in step by hand: save() encodes the whole table, load()
			-- copies back only what M.FIELDS names, so a field a caller sets
			-- and nobody registered is written to disk, looks persisted, and
			-- returns nil on the next start. Ten had accumulated that way --
			-- the per-port VLAN reversibility ledger, the LED toggle, the
			-- locate flag, the static-vs-DHCP guard, and the identity MAC the
			-- IDENTITY MAC CHANGED diagnostic compares against, which could
			-- therefore never fire at all.
			local writers = {}
			local h = io.popen(
				"grep -rhoE 'st\\.[a-z_]+ *=[^=]' openuf/*.lua 2>/dev/null")
			if not h then return end
			for line in h:lines() do
				local f = line:match("^st%.([a-z_]+)")
				if f then writers[f] = true end
			end
			h:close()
			assert_true(next(writers) ~= nil, "found state writers to check")

			local missing = {}
			for f in pairs(writers) do
				if not state.FIELDS[f] then missing[#missing + 1] = f end
			end
			table.sort(missing)
			assert_eq(table.concat(missing, ", "), "",
				"fields written to state but not registered in state.FIELDS "
					.. "(they persist to disk and load back as nil)")
		end
	},
	{
		name = "state: save replaces the file atomically and leaves no temp behind",
		fn = function()
			with_tmp(function()
				state.save({adopted = true, authkey = "f00d"})
				local tmp = io.open(TMP .. ".tmp", "r")
				if tmp then tmp:close() end
				assert_nil(tmp, "the sibling temp file is renamed away, not left behind")

				-- The observable half of writing via rename(2): replacing a
				-- file needs permission on the DIRECTORY, not on the file. The
				-- old in-place io.open(path, "w") failed outright here, and
				-- since a truncated state.json reads back as "not adopted",
				-- the same property is what stops a power cut mid-write from
				-- costing the adoption.
				os.execute("chmod 0444 '" .. TMP .. "'")
				local ok = pcall(state.save, {adopted = true, authkey = "beef"})
				os.execute("chmod 0644 '" .. TMP .. "' 2>/dev/null")
				assert_true(ok, "an unwritable-but-replaceable state file is still saved")
				assert_eq(state.load().authkey, "beef", "and it holds the new contents")
			end)
		end
	},
	{
		name = "state: a corrupt state.json says so instead of quietly un-adopting",
		fn = function()
			with_tmp(function()
				local f = io.open(TMP, "w")
				f:write('{"adopted":true,"authkey":"f00d"')   -- truncated
				f:close()
				local warned = with_stderr(function()
					local st = state.load()
					assert_false(st.adopted, "unparseable state falls back to defaults")
					assert_eq(st.authkey, DEFKEY, "and to the well-known key")
				end)
				assert_true(warned:find("not valid JSON") ~= nil,
					"the fallback is announced -- from the controller's side it is "
						.. "indistinguishable from a factory reset")

				-- An empty file is the normal bootstrap case (install.sh
				-- --bootstrap-adopt pre-creates one) and must stay quiet.
				local e = io.open(TMP, "w"); e:write("\n"); e:close()
				local quiet = with_stderr(function() state.load() end)
				assert_eq(quiet, "", "an empty state file warns about nothing")
			end)
		end
	},
	{
		name = "state: a registered field round-trips, and a wrong type is refused",
		fn = function()
			local path = os.tmpname()
			local orig = state._state_file
			state._state_file = path
			local ok, err = pcall(function()
				state.save({
					adopted = true, authkey = "f00d",
					mac = "d4:53:2a:38:80:cf", led_enabled = false,
					locating = true, locate_prev_trigger = "phy0tpt",
					ip_mode = "static", swvlan_backup = {["10"] = "0t 2 3"},
				})
				local st = state.load()
				assert_eq(st.mac, "d4:53:2a:38:80:cf", "identity mac survives")
				assert_false(st.led_enabled, "led_enabled survives as false, not nil")
				assert_true(st.locating, "locating survives")
				assert_eq(st.locate_prev_trigger, "phy0tpt", "the LED's trigger survives")
				assert_eq(st.ip_mode, "static", "the static-vs-DHCP guard survives")
				assert_eq(st.swvlan_backup["10"], "0t 2 3", "the VLAN ledger survives")

				-- Absent stays absent: readers test `~= nil` for "never set",
				-- so a field must not materialise out of nowhere.
				state.save({adopted = true, authkey = "f00d"})
				local bare = state.load()
				assert_nil(bare.led_enabled, "an unset field loads as nil, not false")
				assert_nil(bare.swvlan_backup, "and not as an empty table")

				-- state.json is hand-editable and syswrapper-written; a wrong
				-- type must be dropped at the boundary rather than reaching a
				-- caller that will index it.
				local f = io.open(path, "w")
				f:write('{"adopted":true,"authkey":"f00d","blocked_stas":"not-a-table",'
					.. '"led_enabled":"yes","mac":42}')
				f:close()
				local bad = state.load()
				assert_eq(type(bad.blocked_stas), "table", "bad blocked_stas falls to the default")
				assert_nil(bad.led_enabled, "a string led_enabled is refused")
				assert_nil(bad.mac, "a numeric mac is refused")
			end)
			state._state_file = orig
			os.remove(path)
			if not ok then error(err, 0) end
		end
	},
	{
		-- B1: conf.lua's inform_url was documented as the first-boot URL and
		-- read by nothing -- defaults() carried its own hardcoded copy, so
		-- editing conf.lua moved no traffic, while install.sh parsed that key
		-- to decide whether an https:// controller needed luasec.
		name = "state: DEFAULT_INFORM_URL supplies the first-boot URL and yields to state.json",
		fn = function()
			local orig_default = state.DEFAULT_INFORM_URL
			with_tmp(function()
				local path = TMP
				state.DEFAULT_INFORM_URL = "https://unifi.example.com:8443/inform"

				-- No file at all: the conf.lua-supplied default is what a fresh
				-- device informs to.
				os.remove(path)
				assert_eq(state.load().inform_url,
					"https://unifi.example.com:8443/inform",
					"first boot uses the configured URL")

				-- A file with no inform_url is the same case.
				local f = io.open(path, "w")
				f:write('{"adopted":false}')
				f:close()
				assert_eq(state.load().inform_url,
					"https://unifi.example.com:8443/inform",
					"a state file without a URL still falls back to it")

				-- An adopted device keeps whatever the controller assigned:
				-- the default must never override a stored URL.
				f = io.open(path, "w")
				f:write('{"adopted":true,"authkey":"'
					.. string.rep("a", 32) .. '","inform_url":"http://10.0.0.5:8080/inform"}')
				f:close()
				assert_eq(state.load().inform_url, "http://10.0.0.5:8080/inform",
					"a controller-assigned URL wins over the default")
			end)
			state.DEFAULT_INFORM_URL = orig_default
		end
	},
}
