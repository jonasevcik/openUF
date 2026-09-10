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
seed()

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

	function cursor:delete(config, section)
		if db[config] then db[config][section] = nil end
		if section_order[config] then
			for i, name in ipairs(section_order[config]) do
				if name == section then table.remove(section_order[config], i); break end
			end
		end
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
