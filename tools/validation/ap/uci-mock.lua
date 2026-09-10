--[[
	Fake `uci` Lua module for the disposable validation AP container ONLY.

	This is not part of openUF -- it exists purely so `openuf/ucihelper.lua`'s
	`require("uci")` fallback resolves to something real inside this
	hardware-less Alpine container, unblocking the parts of
	PROTOCOL-VALIDATION.md that need a non-empty radio_table (SSID push, VLAN
	join, Fast Roaming, TX power, RF-scan trigger). openUF's product code is
	untouched -- ucihelper.lua already has the `M._uci` injection seam this
	relies on for unit tests; this file just makes the SAME fallback path
	(`require("uci")`, used when `M._uci` is nil) resolve to an in-memory
	backend instead of a real UCI binding that doesn't exist here.

	Implements only the subset of the real `uci` Lua binding's cursor API
	that ucihelper.lua actually calls: cursor:foreach/set/delete/commit.
	Mirrors the exact same mock shape already proven correct by
	tests/test_ucihelper.lua's `new_mock_uci()` -- same semantics, just
	exposed as a real requirable module instead of an in-process table.

	Seeded with two wifi-device radio sections (radio0 = 2.4GHz, radio1 =
	5GHz) matching openuf/modelmap/generic-dualband-ap.lua's
	`dev.openuf.uap.hwassign` -- the real target hardware's documented radio
	naming convention -- so get_radio_table() returns real, non-empty
	entries immediately, exactly as real OpenWrt's wireless driver would
	populate at boot regardless of any configured SSID.
]]--

local M = {}

local db = {}             -- db[config][section] = { [".name"]=, [".type"]=, key=val, ... }
local section_order = {}  -- section_order[config] = {name, ...} (foreach iteration order)

-- Where the mock's UCI state lives between processes.
--
-- Real UCI is /etc/config/*, which survives a reboot -- and openUF leans on
-- exactly that: the Multicast/Broadcast Blocker and the WiFi Speed Limit are
-- rebuilt at startup from openuf_bcfilt/openuf_ratelimit_* stamped on each
-- managed section, because the nftables and tc state they describe dies with
-- the reboot. An in-memory mock reseeded on every process start could not model
-- that at all: it made the lab structurally unable to test any
-- "does this survive a restart?" question about UCI, which is a whole class of
-- openUF bug. Persisting here closes that.
--
-- Cleared by `docker compose down -v` (it lives in the container's writable
-- layer, so recreating the container is a factory reset), or explicitly with
-- M._reset() -- see the README.
local STATE_PATH = "/var/lib/openuf-uci-mock.json"

local function json()
	local ok, cjson = pcall(require, "cjson")
	return ok and cjson or nil
end

-- Written to a temp file and renamed, for the same reason state.lua does it:
-- a half-written file would come back as "no state at all" on the next start,
-- silently reseeding and looking like a factory reset.
local function save()
	local cj = json()
	if not cj then return end
	local ok, encoded = pcall(cj.encode, {db = db, section_order = section_order})
	if not ok then return end
	local tmp = STATE_PATH .. ".tmp"
	local f = io.open(tmp, "w")
	if not f then return end
	f:write(encoded)
	f:close()
	os.rename(tmp, STATE_PATH)
end

local function load_persisted()
	local cj = json()
	if not cj then return false end
	local f = io.open(STATE_PATH, "r")
	if not f then return false end
	local raw = f:read("*a")
	f:close()
	local ok, t = pcall(cj.decode, raw)
	if not ok or type(t) ~= "table" or type(t.db) ~= "table" then return false end
	db, section_order = t.db, t.section_order or {}
	-- cjson turns an empty Lua table into {} and reads it back as a table, so
	-- an empty section_order list for a config is fine; nothing here depends on
	-- it being an array specifically.
	return true
end

local function seed()
	db.wireless = {
		radio0 = {
			[".name"] = "radio0", [".type"] = "wifi-device",
			channel = "6", htmode = "HT40", txpower = "20", disabled = "0",
		},
		radio1 = {
			[".name"] = "radio1", [".type"] = "wifi-device",
			channel = "36", htmode = "VHT80", txpower = "20", disabled = "0",
		},
	}
	section_order.wireless = {"radio0", "radio1"}
	db.network = {}
	section_order.network = {}
end

-- First run in a fresh container seeds; every later process picks up what the
-- previous one wrote, the way a real /etc/config would.
if not load_persisted() then
	seed()
	save()
end

-- Wipe and reseed, for a clean run without recreating the container.
-- Validation-only, not part of the real uci API.
function M._reset()
	db, section_order = {}, {}
	seed()
	save()
end

function M.cursor()
	local cursor = {}

	function cursor:set(config, section, a, b)
		db[config] = db[config] or {}
		if not db[config][section] then
			db[config][section] = {[".name"] = section}
			section_order[config] = section_order[config] or {}
			section_order[config][#section_order[config] + 1] = section
		end
		if b == nil then
			db[config][section][".type"] = a
		else
			db[config][section][a] = b
		end
		save()
	end

	-- Real libuci has get(); this mock did not, and the omission was not
	-- harmless. usteer.set_enabled's no-op guard calls
	-- cursor:get("usteer", "local", ...) on every WiFi setparam, so every
	-- setparam in this environment died there with "attempt to call method
	-- 'get' (a nil value)" -- inside _tick's pcall around handle_response, so
	-- it surfaced as one stderr line and nothing else. Everything AFTER that
	-- call was therefore never exercised in the lab: the bcfilter and shaper
	-- reconciles, the switchvlan pass, and handle_response's own
	-- M._state.save(st) at the end -- which is why a pushed static IP reached
	-- the interface and never reached state.json. Found 2026-09-10 while
	-- validating the startup-reapply fixes.
	--
	-- Two forms, both real: get(config, section) returns the section TYPE,
	-- get(config, section, option) returns the option value. Absent config,
	-- section or option is nil, which is what callers test for.
	function cursor:get(config, section, option)
		local c = db[config]
		local s = c and c[section]
		if not s then return nil end
		if option == nil then return s[".type"] end
		return s[option]
	end

	function cursor:foreach(config, stype, fn)
		for _, name in ipairs(section_order[config] or {}) do
			local s = db[config] and db[config][name]
			if s and s[".type"] == stype then fn(s) end
		end
	end

	-- Real libuci: delete(config, section, option) removes ONE OPTION;
	-- delete(config, section) removes the whole section. This mock ignored the
	-- third argument and removed the section either way -- so every call of the
	-- option form destroyed the section it was editing. That is not a rare
	-- path: rf_config deletes txpower/basic_rate/supported_rates/legacy_rates
	-- on essentially every radio push, and wlan_add deletes macfilter/maclist
	-- on every WLAN that has no MAC filter, which is the common case. The lab
	-- was therefore wiping its own radio0/radio1 wifi-device sections and its
	-- freshly written wifi-iface sections, on the ordinary push. Fixed
	-- 2026-09-10; the unit-test mock in tests/test_ucihelper.lua always had
	-- this right, which is why unit tests never showed it.
	function cursor:delete(config, section, option)
		if option ~= nil then
			if db[config] and db[config][section] then
				db[config][section][option] = nil
			end
			save()
			return
		end
		if db[config] then db[config][section] = nil end
		if section_order[config] then
			for i, name in ipairs(section_order[config]) do
				if name == section then table.remove(section_order[config], i); break end
			end
		end
		save()
	end

	-- Debug-only: dump this config's sections to a file on every commit, so
	-- the long-running real `inform.lua` process's actual mock state (a
	-- separate in-memory instance per-process -- a fresh `lua -e` script
	-- always sees its own freshly-seeded mock, never the live process's) can
	-- be inspected from outside that process. Not part of the real uci API.
	function cursor:commit(config)
		local ok_j, cjson = pcall(require, "cjson")
		if not ok_j then return end
		local ok_e, encoded = pcall(cjson.encode, db[config] or {})
		if not ok_e then return end
		local f = io.open("/var/log/openuf-uci-mock-" .. config .. ".json", "w")
		if f then
			f:write(encoded)
			f:close()
		end
	end

	return cursor
end

-- Test/debug hook only -- not part of the real uci API, but handy for
-- inspecting the mock's live state from a REPL during validation work.
M._db = db

return M
