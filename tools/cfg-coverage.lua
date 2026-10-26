#!/usr/bin/env lua
--[[
	cfg-coverage.lua -- which keys of a captured controller push openUF acts on.

	    eval $(luarocks path --local)
	    lua tools/cfg-coverage.lua <capture-file> [--values] [--shapes]

	The capture is a raw `system_cfg` blob: the dotted key=value lines the
	controller sends, as recovered from config.debug_dump_file (see
	tools/validation/README.md). Run from the project root.

	WHY THIS EXISTS

	inform.lua's _report_dropped_keys already prints what no pass RECOGNIZES,
	but its pattern list is prefix-coarse on purpose: `^aaa%.%d+%.` claims every
	per-WLAN security key, including the ones openUF reads nothing from
	(auth_cache, eapol_version, tdls_prohibit, ...). So "recognized" is a claim,
	not a fact, and the 2026-10-26 firmware sweep had to hand-check 166 keys to
	get past it.

	HOW IT DECIDES -- differential replay, not a grep

	Baseline: run every PURE parser over the blob and canonically serialize the
	result. Then, per line, probe it three ways -- delete the line, and set its
	value to each of two sentinels -- and compare each result with the baseline.

	  - the output moves  -> CONSUMED. Proof, not inference: some parser read it.
	  - the output is identical -> the key changes nothing AT THIS VALUE. Split
	    by whether the recognized list claims it:
	      inert     the list claims it, yet removing it changes nothing. A key
	                read only in a branch this value does not take -- or a
	                decoy. (`wireless.<n>.mac_acl.policy` lands here.)
	      ignored   not claimed and not used: nothing in openUF looks at it.

	A CONSUMED verdict is sound. An inert/ignored one is scoped to the captured
	VALUE -- which is exactly the decoy rule from CLAUDE.md: a key constant
	across a controller toggle proves nothing, so diff two captures (one per
	toggle state) and compare the two reports rather than trusting one.

	Side-effecting consumers (netconfig, nft, UCI, the guest HTTP listener) are
	NOT replayed. Their inputs are reached through the pure parsers that feed
	them, so a key only those act on still shows as consumed; but a key that
	only ever reaches, say, an `nft` argument through no parser at all would be
	missed. Today no such path exists -- every system_cfg consumer in openUF
	goes through one of the parsers below.
]]

local CAPTURE, WANT_VALUES, WANT_SHAPES

-- ─── Secrets ─────────────────────────────────────────────────────────────────

-- A capture carries PSKs, the RADIUS shared secret, the FT iapp_key and the
-- controller's authkey. --values prints wire values (the decoy rule needs
-- them), so these leaves are redacted even then: the output of this tool ends
-- up pasted into PROTOCOL-VALIDATION.md and into commit messages.
local SECRET_LEAF = {
	"psk", "authkey", "key", "secret", "password", "passphrase",
	"iapp_key", "radius%.%d+%.secret", "sae%.psk",
}

local function redact(key, value)
	for _, pat in ipairs(SECRET_LEAF) do
		if key:match("%." .. pat .. "$") or key:match("^" .. pat .. "$")
				or key:match("%." .. pat .. "%.") then
			return "<redacted>"
		end
	end
	if #value > 60 then return value:sub(1, 57) .. "..." end
	return value
end

-- ─── Canonical serialization ─────────────────────────────────────────────────

-- Deep, order-independent dump of a parser result. Sorts keys by their string
-- form so a mixed numeric/string table (vap_table is an array, macacl's acl is
-- index-keyed) serializes the same way on every run and under any Lua.
local function dump(v, out)
	out = out or {}
	local t = type(v)
	if t == "table" then
		local keys = {}
		for k in pairs(v) do keys[#keys + 1] = k end
		table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
		out[#out + 1] = "{"
		for _, k in ipairs(keys) do
			out[#out + 1] = tostring(k) .. "="
			dump(v[k], out)
			out[#out + 1] = ";"
		end
		out[#out + 1] = "}"
	else
		out[#out + 1] = t .. ":" .. tostring(v)
	end
	return out
end

local function canon(v) return table.concat(dump(v)) end

-- ─── The parser set ──────────────────────────────────────────────────────────

local M = {}

-- Every pure system_cfg parser in openUF, as a list of {label, fn(blob)}.
-- Keep this in step with handle_response: a parser missing here makes its keys
-- look ignored.
function M.parsers(inform, mods)
	return {
		{"wifi", function(blob)
			local radio_table, vap_table = inform._parse_wifi_system_cfg(blob)
			-- _steering_flags MUTATES vap_table (band-steering + the device
			-- level bandsteering.* block), so it has to run on this same
			-- table, in handle_response's order, to be covered at all.
			inform._steering_flags(vap_table, blob)
			return {radio_table, vap_table, inform._guest_wlans(vap_table, blob)}
		end},
		{"bandsteering", function(blob) return inform._parse_bandsteering_system_cfg(blob) end},
		{"switch",       function(blob) return inform._parse_switch_system_cfg(blob) end},
		{"net",          function(blob) return inform._parse_net_system_cfg(blob) end},
		{"sysconf",      function(blob) return mods.sysconf.parse(blob) end},
		{"l2guard",      function(blob) return mods.l2guard.parse(blob) end},
		{"guestportal",  function(blob) return mods.guestportal.parse(blob) end},
		{"airtime",      function(blob) return mods.airtime.parse(blob) end},
	}
end

-- One combined fingerprint of every parser's output for a blob. A parser that
-- raises is recorded as its error text rather than aborting the sweep: a
-- deletion that turns a parse into an error has still changed the outcome, so
-- the key counts as consumed.
function M.fingerprint(parsers, blob)
	local parts = {}
	for _, p in ipairs(parsers) do
		local ok, res = pcall(p[2], blob)
		parts[#parts + 1] = p[1] .. "=" .. (ok and canon(res) or ("ERR:" .. tostring(res)))
	end
	return table.concat(parts, "|")
end

-- ─── The sweep ───────────────────────────────────────────────────────────────

local function claimed(key, patterns)
	for _, pat in ipairs(patterns) do
		if key:match(pat) then return true end
	end
	return false
end

-- Collapse indices so a four-WLAN capture reports one row per key SHAPE.
local function shape(key)
	return (key:gsub("%.%d+%.", ".<n>."):gsub("%.%d+$", ".<n>"))
end

--[[
	analyse(blob, parsers, recognized) -> report

	report = {
	  consumed = {{key=, value=, line=}, ...},   -- deleting it moved a parser
	  inert    = {...},                          -- claimed, yet no effect
	  ignored  = {...},                          -- not claimed, no effect
	  lines = <key=value lines seen>, blanks = <skipped>,
	}
	Rows keep wire order within each bucket.
]]
function M.analyse(blob, parsers, recognized)
	local order = {}
	for line in (blob .. "\n"):gmatch("([^\n]*)\n") do
		order[#order + 1] = line
	end
	-- Drop the trailing empty element gmatch's "\n" guard produces.
	if order[#order] == "" then order[#order] = nil end

	local report = {consumed = {}, inert = {}, ignored = {}, lines = 0, blanks = 0}

	-- Mute stderr for the whole sweep. The parsers warn on what they find
	-- (a WPA-Enterprise WLAN with no RADIUS client, a malformed address), and
	-- they run once per line: on a 250-key capture that is 250 copies of every
	-- warning drowning the report. The sink is restored below, including when
	-- a parser raises -- hence the pcall rather than a plain call.
	local real_stderr = io.stderr
	io.stderr = {write = function() end}
	local ok, err = pcall(function()

	local base = M.fingerprint(parsers, blob)

	for i, line in ipairs(order) do
		local k, v = line:match("^([^=]+)=(.*)$")
		-- A radio-less push carries the literal comment
		-- "# no wlan provisioned as no radio found".
		if not k or line:match("^%s*#") then
			report.blanks = report.blanks + 1
		else
			report.lines = report.lines + 1
			local kept = {}
			for j, l in ipairs(order) do
				if j ~= i then kept[#kept + 1] = l end
			end
			local row = {key = k, value = v, line = i}
			-- Three probes, not one. Deletion alone misses a key covered by a
			-- REDUNDANT one: radio.<n>.countrycode falls back to the unindexed
			-- radio.countrycode, so dropping either leaves the regdomain
			-- unchanged and both look inert. Mutating the value instead makes
			-- a read visible however many fallbacks surround it. Two sentinels
			-- because one alone can coincide with the parser's own default:
			-- an empty value and a token no wire value equals.
			local probes = {table.concat(kept, "\n")}
			for _, sentinel in ipairs({"", "openuf_probe_0"}) do
				local mutated = {}
				for j, l in ipairs(order) do
					mutated[j] = (j == i) and (k .. "=" .. sentinel) or l
				end
				probes[#probes + 1] = table.concat(mutated, "\n")
			end
			local moved = false
			for _, probe in ipairs(probes) do
				if M.fingerprint(parsers, probe) ~= base then moved = true break end
			end
			if moved then
				report.consumed[#report.consumed + 1] = row
			elseif claimed(k, recognized) then
				report.inert[#report.inert + 1] = row
			else
				report.ignored[#report.ignored + 1] = row
			end
		end
	end

	end)
	io.stderr = real_stderr
	if not ok then error(err, 0) end
	return report
end

-- ─── Reporting ───────────────────────────────────────────────────────────────

local BUCKETS = {
	{"consumed", "CONSUMED -- removing the key moves a parser's output"},
	{"inert",    "INERT -- the recognized list claims it, yet removing it changes nothing"},
	{"ignored",  "IGNORED -- nothing in openUF looks at it"},
}

function M.format(report, opts)
	opts = opts or {}
	local out = {}
	local function w(s) out[#out + 1] = s end
	w(("%d key=value line(s), %d blank/comment line(s) skipped")
		:format(report.lines, report.blanks))
	for _, b in ipairs(BUCKETS) do
		local rows = report[b[1]]
		w("")
		w(("== %s (%d) =="):format(b[2], #rows))
		if opts.shapes then
			local counts, seen = {}, {}
			for _, r in ipairs(rows) do
				local s = shape(r.key)
				if not counts[s] then counts[s] = 0 seen[#seen + 1] = s end
				counts[s] = counts[s] + 1
			end
			table.sort(seen)
			for _, s in ipairs(seen) do w(("  %s x%d"):format(s, counts[s])) end
		else
			for _, r in ipairs(rows) do
				if opts.values then
					w(("  %s = %s"):format(r.key, redact(r.key, r.value)))
				else
					w("  " .. r.key)
				end
			end
		end
	end
	return table.concat(out, "\n")
end

-- ─── Script entry ────────────────────────────────────────────────────────────

-- Loaded as a module by the test suite (tests/test_inform_packet.lua), run as
-- a script otherwise. `arg` is nil under dofile from a test.
if arg and arg[0] and arg[0]:match("cfg%-coverage%.lua$") then
	for i = 1, #arg do
		if arg[i] == "--values" then WANT_VALUES = true
		elseif arg[i] == "--shapes" then WANT_SHAPES = true
		elseif arg[i]:match("^%-") then
			io.stderr:write("cfg-coverage: unknown option " .. arg[i] .. "\n")
			os.exit(2)
		else CAPTURE = arg[i] end
	end
	if not CAPTURE then
		io.stderr:write(
			"usage: lua tools/cfg-coverage.lua <system_cfg-capture> [--values] [--shapes]\n"
			.. "  --values  print the wire value per key (secrets redacted)\n"
			.. "  --shapes  collapse indices and count, instead of listing keys\n")
		os.exit(2)
	end
	local fh, err = io.open(CAPTURE, "r")
	if not fh then
		io.stderr:write("cfg-coverage: " .. tostring(err) .. "\n")
		os.exit(1)
	end
	local blob = fh:read("*a")
	fh:close()

	-- OPENUF_TEST_MODE keeps dofile("openuf/inform.lua") from starting a second
	-- inform loop against the live controller.
	OPENUF_TEST_MODE = true
	dofile("openuf/lib/lib.lua")
	local inform = dofile("openuf/inform.lua")
	local mods = {
		sysconf     = inform._sysconf,
		l2guard     = inform._l2guard,
		guestportal = inform._guestportal,
		airtime     = inform._airtime,
	}
	local report = M.analyse(blob, M.parsers(inform, mods), inform.RECOGNIZED_SYSTEM_CFG)
	print(M.format(report, {values = WANT_VALUES, shapes = WANT_SHAPES}))
end

return M
