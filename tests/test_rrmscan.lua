-- Tests for openuf/rrmscan.lua (802.11k client-assisted RF environment
-- enrichment). Run from project root: lua tests/run_tests.lua
--
-- Both fixtures are REAL captures taken 2026-09-02 off an Archer C5 and an
-- AX3000T: tests/fixtures/ubus_beacon_report.txt is verbatim
-- `ubus subscribe hostapd.phy0-ap0` output while beacon requests were in
-- flight, and ubus_get_clients_rrm.txt carries the four distinct RRM
-- capability shapes actually seen on the network.

local rrmscan = dofile("openuf/rrmscan.lua")

local function read_fixture(name)
	local f = assert(io.open("tests/fixtures/" .. name, "r"))
	local s = f:read("*a")
	f:close()
	return s
end

-- Drive harvest() off a fixture instead of the live collector file.
local function with_events(text, fn)
	local orig_file, orig_now = rrmscan.EVENT_FILE, rrmscan._now
	local path = os.tmpname()
	local f = assert(io.open(path, "w"))
	f:write(text)
	f:close()
	rrmscan.EVENT_FILE = path
	rrmscan._now = function() return 1000 end
	local ok, err = pcall(fn)
	rrmscan.EVENT_FILE, rrmscan._now = orig_file, orig_now
	os.remove(path)
	if not ok then error(err, 0) end
end

local function with_popen(answer, fn)
	local orig = rrmscan._popen
	local seen = {}
	rrmscan._popen = function(cmd)
		seen[#seen + 1] = cmd
		return type(answer) == "function" and answer(cmd) or answer
	end
	local ok, err = pcall(fn, seen)
	rrmscan._popen = orig
	if not ok then error(err, 0) end
end

local function with_exec(fn)
	local orig = rrmscan._exec
	local cmds = {}
	rrmscan._exec = function(cmd) cmds[#cmds + 1] = cmd; return true end
	local ok, err = pcall(fn, cmds)
	rrmscan._exec = orig
	if not ok then error(err, 0) end
end

local function by_bssid(list)
	local m = {}
	for _, e in ipairs(list) do m[e.bssid] = e end
	return m
end

-- A Beacon Report element as hex, from its parts. body_ies = nil means no
-- Reported Frame Body; frag = {num, more} adds a Fragment ID subelement.
local function hexs(str)
	return (str:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local function ie(id, bytes) return string.char(id, #bytes) .. bytes end
local function report_hex(o)
	local fixed = string.char(o.op or 115, o.channel or 36) .. string.rep("\0", 8)
		.. string.char(0, 0, 0, o.rcpi or 122, 0)
		.. string.char(0x00, 0x00, 0x5e, 0x00, 0x53, o.last or 0x02)
		.. string.rep("\0", 5)
	local subs = ""
	if o.body_ies then
		local cap = o.privacy and 0x11 or 0x01
		local body = string.rep("\0", 8) .. string.char(0x64, 0, cap, 0) .. o.body_ies
		subs = subs .. string.char(1, #body) .. body
	end
	if o.frag then
		subs = subs .. string.char(2, 2, 1, o.frag[1] + (o.frag[2] and 128 or 0))
	end
	return hexs(fixed .. subs)
end
local RSN = ie(48, string.char(1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0))

local function with_width(fn)
	local orig = rrmscan._channel_width
	rrmscan._channel_width = dofile("openuf/sysinfo.lua").channel_width
	local ok, err = pcall(fn)
	rrmscan._channel_width = orig
	if not ok then error(err, 0) end
end

return {
	{
		-- A real BEACON-RESP-RX from the Archer C5's 5 GHz BSS, 2026-10-12
		-- (MAC and SSID replaced): a 205-byte frame body, cut, holding the
		-- SSID, RSN, HT and VHT operation of an 80 MHz BSS on channel 36.
		name = "rrmscan: a control-socket report yields SSID, security, width and primary",
		fn = function()
			local line = read_fixture("hostapd_beacon_resp_rx.txt")
			local hex = line:match("(%x+)%s*$")
			with_width(function()
				local r = rrmscan.parse_report(hex)
				assert_eq(r.bssid, "00:00:5e:00:53:01", "bssid")
				assert_eq(r.essid, "HomeTest", "SSID from the frame body")
				assert_eq(r.security, "wpa2", "RSN element")
				assert_eq(r.bw, 80, "VHT operation width 1")
				assert_eq(r.channel, 36, "primary channel")
				assert_eq(r.band, "na", "band")
				assert_eq(r.signal, -49, "rcpi 122")
			end)
			-- Without the shared width function the width is unknown, not guessed.
			assert_nil(rrmscan.parse_report(hex).bw, "no width function, no width")
		end
	},
	{
		name = "rrmscan: a report's fields are taken only where the body proves them",
		fn = function()
			with_width(function()
				local P = rrmscan.parse_report
				-- Hidden SSID: empty or NUL-filled.
				assert_nil(P(report_hex({body_ies = ie(0, "") .. RSN})).essid, "empty SSID")
				assert_nil(P(report_hex({body_ies = ie(0, "\0\0\0") .. RSN})).essid, "NUL SSID")
				-- Privacy bit clear: open, even when the body was cut.
				assert_eq(P(report_hex({body_ies = ie(0, "x"), frag = {0, true}})).security,
					"open", "privacy clear is open")
				-- Privacy set, no RSN/WPA: unknown, flagged cut or not. Clients
				-- shorten bodies without saying so (seen live), and proving WPA
				-- absent would take the very end of the beacon.
				assert_nil(P(report_hex({privacy = true, body_ies = ie(0, "x")})).security,
					"no RSN in the body is not proof of wep")
				assert_nil(P(report_hex({privacy = true, body_ies = ie(0, "x"),
					frag = {0, true}})).security, "nor in a flagged-cut body")
				-- WPA vendor element.
				local wpa = ie(221, string.char(0x00, 0x50, 0xf2, 0x01, 1, 0))
				assert_eq(P(report_hex({privacy = true, body_ies = wpa})).security, "wpa", "WPA")
				-- The fixed field names the centre channel; HT operation the primary.
				local ht40 = ie(61, string.char(36, 1) .. string.rep("\0", 20))
				local tpe  = ie(195, string.char(2, 0x2e, 0x2e, 0x2e))
				local r = P(report_hex({channel = 38, privacy = true, body_ies = RSN .. ht40 .. tpe}))
				assert_eq(r.channel, 36, "primary from HT operation")
				-- HT-only on 5 GHz: the VHT element may just not have been sent,
				-- and element order proves nothing (seen out of order live).
				assert_nil(r.bw, "5 GHz HT-only body: width unknown")
				-- On 2.4 GHz HT operation is the width.
				local ht40_ng = ie(61, string.char(1, 1) .. string.rep("\0", 20))
				assert_eq(P(report_hex({channel = 1, privacy = true, body_ies = RSN .. ht40_ng})).bw,
					40, "2.4 GHz HT40")
				-- No operation elements at all: unknown, the merge's 20 floor.
				assert_nil(P(report_hex({privacy = true, body_ies = RSN})).bw, "no op elements")
				-- A continuation fragment is a report of its own for the same
				-- BSSID; it must not stand in for fragment 0.
				assert_nil(P(report_hex({privacy = true, body_ies = ie(0, "x") .. RSN,
					frag = {1, false}})), "continuation fragment dropped")
				-- A filtered body (live: SSID + one vendor element, privacy set).
				local fb = P(report_hex({privacy = true,
					body_ies = ie(0, "x") .. ie(221, string.char(0x00, 0x10, 0x18, 2, 0))}))
				assert_nil(fb.security, "filtered body: security unknown")
				assert_nil(fb.bw, "and width unknown")
				-- No body at all: what ubus gives, and nothing more.
				local nb = P(report_hex({channel = 6}))
				assert_nil(nb.essid, "no body, no SSID")
				assert_nil(nb.security, "no body, no security")
				assert_eq(nb.band, "ng", "band from the fixed channel")
				-- Malformed.
				assert_nil(P("zz"), "not hex")
				assert_nil(P("0011"), "too short")
				assert_nil(P(report_hex({}) .. "0"), "odd length")
			end)
		end
	},
	{
		name = "rrmscan: harvest prefers the control-socket record and counts its reporter",
		fn = function()
			local ctrl = read_fixture("hostapd_beacon_resp_rx.txt")
			local ubus = '{ "beacon-report": {"address":"00:00:5e:00:53:11","op-class":81,'
				.. '"channel":42,"rcpi":120,"bssid":"00:00:5e:00:53:01","rep-mode":0} }\n'
			with_width(function()
				with_events(ubus .. ctrl, function()
					local out, reporters = rrmscan.harvest()
					assert_eq(#out, 1, "one record per BSSID")
					assert_eq(out[1].essid, "HomeTest", "the control-socket record wins")
					assert_eq(out[1].channel, 36, "with its primary channel, not 42")
					assert_true(reporters["00:00:5e:00:53:10"] == true, "ctrl reporter counted")
					assert_true(reporters["00:00:5e:00:53:11"] == true, "ubus reporter counted")
				end)
			end)
			-- Fragment 1 of the same BSSID arriving first does not take its place.
			local hex = ctrl:match("(%x+)%s*$")
			local cont = "BEACON-RESP-RX 00:00:5e:00:53:10 60 00 " .. hex:sub(1, 52)
				.. "01020000" .. "02020101\n"
			with_width(function()
				with_events(cont .. ctrl, function()
					local out = rrmscan.harvest()
					assert_eq(#out, 1, "one record")
					assert_eq(out[1].essid, "HomeTest", "fragment 0 kept")
				end)
			end)
			-- A non-zero report mode is a refusal on this path too.
			local refused = ctrl:gsub("BEACON%-RESP%-RX (%S+) (%d+) 00", "BEACON-RESP-RX %1 %2 04")
			with_events(refused, function()
				local out, reporters = rrmscan.harvest()
				assert_eq(#out, 0, "refusal reports nothing")
				assert_nil(reporters["00:00:5e:00:53:10"], "and is not an answer")
			end)
		end
	},
	{
		name = "rrmscan: merge carries proven fields, skips own and sibling BSSIDs",
		fn = function()
			local n = {
				{bssid = "00:00:5e:00:53:01", band = "na", channel = 36, signal = -60,
					seen_at = 100, essid = "Neighbour", security = "wpa2", bw = 80},
				{bssid = "00:00:5e:00:53:02", band = "na", channel = 48, signal = -70,
					seen_at = 100, essid = "SiteNet", security = "wpa2"},
				{bssid = "00:00:5E:00:53:03", band = "na", channel = 36, signal = -20,
					seen_at = 100, essid = "SiteNet", security = "wpa2"},
			}
			local out = by_bssid(rrmscan.merge_into({}, n, {
				band = "na", radio = "na", radio_name = "radio0", now = 105,
				skip = {["00:00:5e:00:53:03"] = true},
				site_ssids = {SiteNet = true},
			}))
			local a = out["00:00:5e:00:53:01"]
			assert_eq(a.essid, "Neighbour", "essid carried")
			assert_eq(a.security, "wpa2", "security carried")
			assert_eq(a.bw, 80, "width carried")
			local b = out["00:00:5e:00:53:02"]
			assert_nil(b.essid, "a site SSID from an unknown BSS is withheld")
			assert_eq(b.security, "wpa2", "its security is still reported")
			assert_eq(b.bw, 20, "unknown width falls to the 20 MHz floor")
			assert_nil(out["00:00:5E:00:53:03"], "own/sibling BSSID skipped, any case")
		end
	},
	{
		name = "rrmscan: siblings are read from usteer's remote nodes",
		fn = function()
			with_popen('{"192.0.2.4#hostapd.phy0-ap0": {"bssid": "00:00:5E:00:53:21",'
				.. '"ssid": "SiteNet"}, "192.0.2.4#hostapd.phy1-ap0": {"bssid":'
				.. '"00:00:5e:00:53:22"}}', function(seen)
				local s = rrmscan.sibling_bssids()
				assert_true(s["00:00:5e:00:53:21"] == true, "lowercased")
				assert_true(s["00:00:5e:00:53:22"] == true, "second node")
				assert_true(seen[1]:find("usteer remote_info", 1, true) ~= nil, "asks usteer")
			end)
			with_popen(nil, function()
				assert_true(next(rrmscan.sibling_bssids()) == nil, "no usteer, no siblings")
			end)
		end
	},
	{
		name = "rrmscan: one control-socket monitor per BSS, restarted only when missing",
		fn = function()
			local orig = rrmscan.ACTION_SCRIPT
			rrmscan.ACTION_SCRIPT = os.tmpname()
			os.remove(rrmscan.ACTION_SCRIPT)
			local ok, err = pcall(function()
				local ps = ""
				local answers = function(cmd)
					if cmd:find("^ls ") then return "global\nphy0-ap0\nphy1-ap0\n" end
					if cmd:find("^ps ") then return ps end
					return ""
				end
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_eq(rrmscan.monitors_ensure(), 2, "one per BSS, not global")
						local all = table.concat(cmds, "\n")
						assert_true(all:find("kill $(pgrep -f '[h]ostapd_cli", 1, true) ~= nil,
							"a new script replaces any old monitor")
						assert_true(all:find("hostapd_cli -p /var/run/hostapd -i phy1-ap0 -a "
							.. rrmscan.ACTION_SCRIPT .. " -B", 1, true) ~= nil, "started detached")
						assert_false(all:find("-i global", 1, true) ~= nil, "global skipped")
					end)
				end)
				ps = " 1 root 1152 S hostapd_cli -p /var/run/hostapd -i phy0-ap0 -a "
					.. rrmscan.ACTION_SCRIPT .. " -B\n"
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_eq(rrmscan.monitors_ensure(), 1, "only the missing one")
						assert_true(cmds[1]:find("-i phy1-ap0", 1, true) ~= nil, "phy1-ap0")
					end)
				end)
			end)
			os.remove(rrmscan.ACTION_SCRIPT)
			rrmscan.ACTION_SCRIPT = orig
			if not ok then error(err, 0) end
		end
	},
	{
		-- The action script is shell, run per event by hostapd_cli as
		-- "<script> <ifname> <event words...>". Run it for real and feed what
		-- it writes back through harvest.
		name = "rrmscan: the action script appends only beacon reports, in a line harvest reads",
		fn = function()
			local orig_ev, orig_sc = rrmscan.EVENT_FILE, rrmscan.ACTION_SCRIPT
			rrmscan.EVENT_FILE, rrmscan.ACTION_SCRIPT = os.tmpname(), os.tmpname()
			local ok, err = pcall(function()
				local f = assert(io.open(rrmscan.ACTION_SCRIPT, "w"))
				f:write(rrmscan.action_script())
				f:close()
				local hex = read_fixture("hostapd_beacon_resp_rx.txt"):match("(%x+)%s*$")
				os.execute("sh " .. rrmscan.ACTION_SCRIPT .. " phy0-ap0 AP-STA-CONNECTED 00:00:5e:00:53:10 2>/dev/null")
				os.execute("sh " .. rrmscan.ACTION_SCRIPT
					.. " phy0-ap0 BEACON-RESP-RX 00:00:5e:00:53:10 60 00 " .. hex .. " 2>/dev/null")
				local g = assert(io.open(rrmscan.EVENT_FILE, "r"))
				local text = g:read("*a")
				g:close()
				assert_false(text:find("AP-STA-CONNECTED", 1, true) ~= nil, "other events ignored")
				local out = rrmscan.harvest(text)
				assert_eq(#out, 1, "the report is read back")
				assert_eq(out[1].essid, "HomeTest", "intact")
			end)
			os.remove(rrmscan.EVENT_FILE)
			os.remove(rrmscan.ACTION_SCRIPT)
			rrmscan.EVENT_FILE, rrmscan.ACTION_SCRIPT = orig_ev, orig_sc
			if not ok then error(err, 0) end
		end
	},
	{
		name = "rrmscan: RCPI converts on the 0.5-dBm scale anchored at -110",
		fn = function()
			-- The anchor and the step are both load-bearing: an off-by-one in
			-- either turns every neighbour's signal into a plausible-looking
			-- but wrong dBm, which nothing downstream can detect.
			assert_eq(rrmscan.rcpi_to_dbm(124), -48, "strong (own AP) sighting")
			assert_eq(rrmscan.rcpi_to_dbm(32), -94, "far neighbour")
			assert_eq(rrmscan.rcpi_to_dbm(0), -110, "the scale's floor")
			assert_nil(rrmscan.rcpi_to_dbm(nil), "absent RCPI stays absent")
		end
	},
	{
		name = "rrmscan: a reported channel maps to a band and a frequency",
		fn = function()
			assert_eq(rrmscan.band_of_channel(11), "ng", "2.4 GHz")
			assert_eq(rrmscan.band_of_channel(44), "na", "5 GHz")
			assert_eq(rrmscan.freq_of_channel(11), 2462, "ch 11")
			assert_eq(rrmscan.freq_of_channel(14), 2484, "ch 14 is the exception")
			assert_eq(rrmscan.freq_of_channel(44), 5220, "ch 44")
			-- Channels 15..31 exist in no band openUF reports; guessing one
			-- would file a neighbour under the wrong radio.
			assert_nil(rrmscan.band_of_channel(20), "no band for ch 20")
		end
	},
	{
		name = "rrmscan: only clients that can actually go and look are asked",
		fn = function()
			with_popen(read_fixture("ubus_get_clients_rrm.txt"), function()
				local stas = rrmscan.capable_stations("phy0-ap0")
				local set = {}
				for _, m in ipairs(stas) do set[m] = true end
				-- rrm=115 (passive+active+table) and rrm=50 (passive+active).
				assert_true(set["00:00:5e:00:53:10"], "full RRM client asked")
				assert_true(set["00:00:5e:00:53:1b"], "passive+active client asked")
				-- rrm=75 is beacon-TABLE only: acked every real request and
				-- answered none, and hostapd refuses a passive request for it
				-- outright. Asking it is pure airtime for no data.
				assert_false(set["00:00:5e:00:53:22"],
					"beacon-table-only client is NOT asked")
				-- rrm=0 -- most clients on a real network.
				assert_false(set["00:00:5e:00:53:18"], "non-802.11k client is not asked")
				assert_eq(#stas, 2, "exactly the two capable ones")
			end)
		end
	},
	{
		name = "rrmscan: harvest parses real notifications and drops the junk",
		fn = function()
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local n = rrmscan.harvest()
				local m = by_bssid(n)
				assert_eq(m["00:00:5e:00:53:11"].channel, 1, "2.4 GHz neighbour")
				assert_eq(m["00:00:5e:00:53:11"].band, "ng", "banded from the channel")
				assert_eq(m["00:00:5e:00:53:11"].signal, -73, "rcpi 74 -> -73 dBm")
				assert_eq(m["00:00:5e:00:53:15"].band, "na", "5 GHz neighbour")
				-- The captured rep-mode 4 report ("refused / incapable")
				-- carries an all-zero BSSID on channel 0. Both the BSSID
				-- guard and the rep-mode guard reject it, so this assertion
				-- alone does not prove the rep-mode one works -- see the next
				-- test for that.
				assert_nil(m["00:00:00:00:00:00"], "refused measurement dropped")
				-- Two clients both reported 00:00:5e:00:53:15.
				local count = 0
				for _, e in ipairs(n) do
					if e.bssid == "00:00:5e:00:53:15" then count = count + 1 end
				end
				assert_eq(count, 1, "a BSS seen by two clients is carried once")
				-- `probe` and `link-measurement-report` share the stream and
				-- are not neighbours.
				assert_nil(m["ff:ff:ff:ff:ff:ff"], "probe events are not neighbours")
			end)
		end
	},
	{
		name = "rrmscan: a non-zero rep-mode is dropped even with a real BSSID",
		fn = function()
			-- SYNTHETIC, unlike the other fixtures here: every captured
			-- refusal happened to also carry an all-zero BSSID, so the
			-- capture cannot distinguish the rep-mode guard from the BSSID
			-- guard. rep-mode is a bitfield (incapable / refused / late), and
			-- a client may set it while still naming the BSS it failed to
			-- measure properly -- which must not be published as a sighting.
			local ev =
				'{ "beacon-report": {"channel":11,"rcpi":80,' ..
				'"bssid":"aa:bb:cc:dd:ee:0f","rep-mode":2} }\n' ..
				'{ "beacon-report": {"channel":11,"rcpi":80,' ..
				'"bssid":"aa:bb:cc:dd:ee:10","rep-mode":0} }\n'
			with_events(ev, function()
				local m = by_bssid(rrmscan.harvest())
				assert_nil(m["aa:bb:cc:dd:ee:0f"],
					"refused measurement dropped despite a valid BSSID")
				assert_not_nil(m["aa:bb:cc:dd:ee:10"],
					"the accepted measurement beside it still lands")
			end)
		end
	},
	{
		name = "rrmscan: harvest survives a 64-bit start-time it cannot represent",
		fn = function()
			-- Real clients emit a raw TSF that overflows a double
			-- (-7160986498777481216 was captured). Parsing the payload as JSON
			-- is what made this a hazard; the fields we use are matched
			-- directly, so the report still lands.
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local m = by_bssid(rrmscan.harvest())
				assert_not_nil(m["00:00:5e:00:53:15"],
					"report with an out-of-range start-time still parsed")
			end)
		end
	},
	{
		name = "rrmscan: harvest drains the file so a report is never counted twice",
		fn = function()
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				assert_true(#rrmscan.harvest() > 0, "first drain returns reports")
				assert_eq(#rrmscan.harvest(), 0, "second drain is empty")
			end)
		end
	},
	{
		name = "rrmscan: merge only adds new BSSIDs, on the matching band",
		fn = function()
			local passive = {
				{bssid = "00:00:5e:00:53:14", essid = "Home LAN",
				 security = "wpa2", channel = 6, bw = 40},
			}
			local neigh = {
				-- already known passively, with a richer record
				{bssid = "00:00:5e:00:53:14", channel = 6, band = "ng", signal = -48, seen_at = 100},
				-- new, same band
				{bssid = "00:00:5e:00:53:11", channel = 1, band = "ng", signal = -73, seen_at = 100},
				-- new, WRONG band for this radio
				{bssid = "00:00:5e:00:53:17", channel = 48, band = "na", signal = -80, seen_at = 100},
			}
			local out = rrmscan.merge_into(passive, neigh,
				{band = "ng", radio = "ng", radio_name = "radio0", now = 105})
			local m = by_bssid(out)
			assert_eq(#out, 2, "one appended, nothing duplicated or cross-banded")
			assert_eq(m["00:00:5e:00:53:14"].essid, "Home LAN",
				"the passive cache's richer record wins")
			assert_eq(m["00:00:5e:00:53:14"].bw, 40, "and keeps its real width")
			assert_nil(m["00:00:5e:00:53:17"], "other band not merged into this radio")
			local added = m["00:00:5e:00:53:11"]
			assert_eq(added.channel, 1, "channel carried")
			assert_eq(added.freq, 2412, "frequency derived")
			assert_eq(added.signal, -73, "signal carried")
			assert_eq(added.age, 5, "age is time since the client reported it")
			assert_eq(added.bw, 20, "width defaulted -- the Ch. Width cell "
				.. "renders nothing for a falsy value")
			-- The Environment tab filters on `band` upstream of every visible
			-- filter; an entry without it disappears with no error and no
			-- visible cause. Same trap inform.lua documents for scan_table.
			assert_eq(added.band, "ng", "band set, or the row silently vanishes")
			-- Defaulting this to "open" told the operator that four WPA2
			-- neighbours were unencrypted. A beacon report measures no
			-- security mode, so the field must be absent, not guessed.
			assert_nil(added.security, "security is never invented")
			assert_nil(added.essid, "SSID is never invented either")
			assert_eq(added.radio_name, "radio0", "attributed to the radio")
		end
	},
	{
		name = "rrmscan: merge drops sightings the controller would discard",
		fn = function()
			-- The controller's rogue-AP ingestion silently drops any entry
			-- with age >= 30. Carrying one past that is payload nobody reads.
			local neigh = {
				{bssid = "00:00:5e:00:53:11", channel = 1, band = "ng", signal = -73, seen_at = 100},
			}
			local fresh = rrmscan.merge_into({}, neigh,
				{band = "ng", now = 129, max_age = 30})
			assert_eq(#fresh, 1, "29 s old is still reportable")
			local stale = rrmscan.merge_into({}, neigh,
				{band = "ng", now = 130, max_age = 30})
			assert_eq(#stale, 0, "30 s old is dropped")
		end
	},
	{
		name = "rrmscan: the collector is started only when it is not running",
		fn = function()
			local orig_script = rrmscan.COLLECTOR_SCRIPT
			rrmscan.COLLECTOR_SCRIPT = os.tmpname()
			local ok, err = pcall(function()
				with_popen(function(cmd)
					if cmd:find("pgrep", 1, true) then return "" end   -- not running
					if cmd:find("ubus list", 1, true) then
						return "hostapd.phy0-ap0\nhostapd.phy1-ap0\nnetwork.wireless\n"
					end
					return ""
				end, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure(), "starts when absent")
						local all = table.concat(cmds, "\n")
						assert_true(all:find("sh " .. rrmscan.COLLECTOR_SCRIPT
							.. " hostapd.phy0-ap0 hostapd.phy1-ap0", 1, true) ~= nil,
							"runs the script over every hostapd BSS at once")
						assert_true(all:find("&") ~= nil, "runs in the background")
						local script = rrmscan._read_file(rrmscan.COLLECTOR_SCRIPT)
						-- `ubus listen` catches broadcast events and receives
						-- NOTHING here; only subscribe gets hostapd's per-object
						-- notifications. Confirmed live.
						assert_true(script:find('ubus subscribe "$@"', 1, true) ~= nil,
							"the script subscribes to the objects it is given")
						assert_false(script:find("ubus listen", 1, true) ~= nil,
							"never uses listen, which sees no beacon reports")
						-- So collector_running keeps matching the live process.
						assert_true(("ubus subscribe hostapd.phy0-ap0"):find("ubus subscribe hostapd", 1, true) ~= nil,
							"the spawned process still matches the liveness pattern")
					end)
				end)

				-- Running, and it is this script unchanged: left alone.
				with_popen(function(cmd)
					if cmd:find("pgrep", 1, true) then return "4711\n" end  -- running
					return ""
				end, function()
					with_exec(function(cmds)
						assert_false(rrmscan.collector_ensure(), "no-op while running")
						assert_eq(#cmds, 0, "spawns no second collector")
					end)
				end)
			end)
			os.remove(rrmscan.COLLECTOR_SCRIPT)
			rrmscan.COLLECTOR_SCRIPT = orig_script
			if not ok then error(err, 0) end
		end
	},
	{
		-- A collector is reparented to init, so it survives an openUF upgrade
		-- and a config change. One from an older openUF writes untimestamped
		-- lines; one without the on_auth hook leaves stale set evidence in
		-- place. Either must be replaced, not merely found alive.
		name = "rrmscan: a running collector that is not the wanted script is replaced",
		fn = function()
			local orig_script = rrmscan.COLLECTOR_SCRIPT
			rrmscan.COLLECTOR_SCRIPT = os.tmpname()
			local ok, err = pcall(function()
				local answers = function(cmd)
					if cmd:find("pgrep", 1, true) then return "4711\n" end
					if cmd:find("ubus list", 1, true) then return "hostapd.phy0-ap0\n" end
					return ""
				end
				-- Old-style collector: ubus subscribe is alive, no script file.
				os.remove(rrmscan.COLLECTOR_SCRIPT)
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure(), "replaced")
						local all = table.concat(cmds, "\n")
						assert_true(all:find("kill $(pgrep", 1, true) ~= nil, "the old one is stopped")
						assert_true(all:find("sh " .. rrmscan.COLLECTOR_SCRIPT, 1, true) ~= nil,
							"and the script started")
					end)
				end)
				-- Same script but a hook is now wanted: replaced again.
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure({on_auth = "true"}), "replaced on opts change")
					end)
				end)
				-- And left alone once it matches.
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_false(rrmscan.collector_ensure({on_auth = "true"}), "kept when unchanged")
						assert_eq(#cmds, 0, "nothing spawned or killed")
					end)
				end)
			end)
			os.remove(rrmscan.COLLECTOR_SCRIPT)
			rrmscan.COLLECTOR_SCRIPT = orig_script
			if not ok then error(err, 0) end
		end
	},
	{
		-- Roam reports (assoctrack.lua): the old AP learns that a station
		-- left from its bridge, which moves the address to the uplink in the
		-- same second. The fdb half runs beside the subscriber, in the
		-- background, and writes lines assoctrack.parse_events reads.
		name = "rrmscan: opts.fdb adds a bridge monitor to the collector, stamped like the rest",
		fn = function()
			local plain = rrmscan.collector_script({on_auth = "true"})
			assert_false(plain:find("bridge", 1, true) ~= nil, "no fdb half unless asked")
			local s = rrmscan.collector_script({on_auth = "true", fdb = true})
			local b = s:find("bridge monitor fdb", 1, true)
			local u = s:find('ubus subscribe "$@"', 1, true)
			assert_true(b ~= nil and u ~= nil and b < u, "the monitor is started before the subscriber")
			assert_true(s:find("done &\n", b, true) ~= nil, "in the background: the subscriber keeps the foreground")
			assert_true(s:find("Deleted*|*' self'*) continue", 1, true) ~= nil,
				"ageing and the switch's own entries are dropped in the shell")
			assert_true(s:find("printf '%s fdb %s\\n'", 1, true) ~= nil, "uptime, then 'fdb', then the line")
			assert_true(s:find("on_auth", 1, true) == nil and s:find("true ;;", 1, true) ~= nil,
				"the auth hook is still there")
		end
	},
	{
		-- Run for real: a stub `ubus` replays the captured events through the
		-- script under sh. Probe requests never reach the file; every event a
		-- consumer reads does, stamped.
		name = "rrmscan: the collector drops probe requests in the shell, keeps the rest",
		fn = function()
			local dir = os.tmpname()
			os.remove(dir)
			assert_true(os.execute("mkdir " .. dir) ~= false, "tmp dir")
			local fixture = read_fixture("ubus_assoc_events.txt")
			local raw = {}
			for line in fixture:gmatch("[^\n]+") do raw[#raw + 1] = (line:gsub("^%d+%.%d+ ", "")) end
			local events = table.concat(raw, "\n") .. "\n"
			local function put(name, body)
				local f = io.open(dir .. "/" .. name, "w"); f:write(body); f:close()
			end
			put("events", events)
			put("uptime", "123.45 6.78\n")
			put("ubus", "#!/bin/sh\ncat " .. dir .. "/events\n")
			os.execute("chmod +x " .. dir .. "/ubus")
			local script = rrmscan.collector_script({on_auth = ":"}):gsub("/proc/uptime", dir .. "/uptime")
			put("collect.sh", script)
			local p = io.popen("PATH=" .. dir .. ":$PATH sh " .. dir .. "/collect.sh 2>&1")
			local out = p:read("*a")
			p:close()
			os.execute("rm -rf " .. dir)
			assert_true(events:find('{ "probe": ', 1, true) ~= nil, "the fixture has a probe to drop")
			assert_true(out:find('"probe"', 1, true) == nil, "no probe line written")
			local n_in, n_out = 0, 0
			for line in events:gmatch("[^\n]+") do
				if not line:find('{ "probe": ', 1, true) then n_in = n_in + 1 end
			end
			for line in out:gmatch("[^\n]+") do
				n_out = n_out + 1
				assert_true(line:sub(1, 7) == "123.45 ", "stamped: " .. line)
			end
			assert_eq(n_out, n_in, "every other event kept")
			local evs = dofile("openuf/assoctrack.lua").parse_events(out)
			assert_true(#evs >= 4, "auth/assoc/authorized/disassoc still parse")
		end
	},
	{
		-- A wifi reload kills the subscriber, never the monitor: each restart
		-- would otherwise leave one more `bridge monitor` behind.
		name = "rrmscan: the fdb half is killed before every start and on stop",
		fn = function()
			local orig_script = rrmscan.COLLECTOR_SCRIPT
			rrmscan.COLLECTOR_SCRIPT = os.tmpname()
			local ok, err = pcall(function()
				with_popen(function(cmd)
					if cmd:find("pgrep", 1, true) then return "" end
					if cmd:find("ubus list", 1, true) then return "hostapd.phy0-ap0\n" end
					return ""
				end, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure({fdb = true}), "started")
						local kill_at, start_at
						for i, c in ipairs(cmds) do
							if c:find("[b]ridge monitor fdb", 1, true) and c:find("kill", 1, true) then kill_at = kill_at or i end
							if c:find("sh " .. rrmscan.COLLECTOR_SCRIPT, 1, true) then start_at = i end
						end
						assert_true(kill_at ~= nil and start_at ~= nil and kill_at < start_at,
							"a leftover monitor is killed before the new collector starts")
					end)
				end)
			end)
			os.remove(rrmscan.COLLECTOR_SCRIPT)
			rrmscan.COLLECTOR_SCRIPT = orig_script
			if not ok then error(err, 0) end
			with_exec(function(cmds)
				rrmscan.collector_stop()
				assert_true(table.concat(cmds, "\n"):find("kill $(pgrep -f '[b]ridge monitor fdb')", 1, true) ~= nil,
					"collector_stop kills it too")
			end)
		end
	},
	{
		name = "rrmscan: harvest takes a blob drained once for several consumers",
		fn = function()
			local blob = read_fixture("ubus_beacon_report.txt")
			with_events("", function()
				assert_true(#rrmscan.harvest(blob) > 0, "parses the blob it is given")
			end)
			-- Timestamp prefixes added by the collector do not disturb it.
			local stamped = blob:gsub("([^\n]+)", "5905613.20 %1")
			with_events("", function()
				assert_eq(#rrmscan.harvest(stamped), #rrmscan.harvest(blob), "prefix-agnostic")
			end)
		end
	},
	{
		-- The collector is a detached `ubus subscribe` child reparented to
		-- init, so it outlives the daemon. It has to be killed explicitly, and
		-- the notification file has to go with it: harvest() is the only thing
		-- that truncates it, so a file left behind with no reader grows without
		-- bound on a RAM-disk /tmp.
		name = "rrmscan: collector_stop kills the subscriber and removes the event file",
		fn = function()
			with_exec(function(cmds)
				rrmscan.collector_stop()
				local all = table.concat(cmds, "\n")
				assert_true(all:find("kill $(pgrep -f '[u]bus subscribe hostapd')", 1, true) ~= nil,
					"kills the subscriber by the pattern collector_ensure spawns")
				-- busybox on the Archer C5 (OpenWrt 25.12) has no pkill
				-- applet: a pkill here is a no-op on real hardware.
				assert_false(all:find("pkill", 1, true) ~= nil, "does not rely on pkill")
				assert_true(all:find("rm -f " .. rrmscan.EVENT_FILE, 1, true) ~= nil,
					"removes the notification file it was appending to")
				assert_true(all:find("[h]ostapd_cli", 1, true) ~= nil,
					"stops the control-socket monitors too")
			end)
		end
	},
	{
		name = "rrmscan: a request asks for an ACTIVE all-channel measurement",
		fn = function()
			with_exec(function(cmds)
				rrmscan.request("phy1-ap0", "00:00:5e:00:53:10")
				local c = table.concat(cmds, "\n")
				assert_true(c:find("hostapd.phy1%-ap0 rrm_beacon_req") ~= nil,
					"goes to the right BSS object")
				assert_true(c:find('"addr":"00:00:5e:00:53:10"', 1, true) ~= nil,
					"names the station")
				-- mode 1 is active measurement: the client probes rather than
				-- only listening, which is what makes it report BSSes on
				-- channels it is not sitting on. mode 2 (beacon table) reports
				-- from a cache that may be empty.
				assert_true(c:find('"mode":1', 1, true) ~= nil, "active measurement")
				-- 255 means every channel in the operating class; a single
				-- channel would report only what the radio already knows.
				assert_true(c:find('"channel":255', 1, true) ~= nil, "sweeps all channels")
			end)
		end
	},
	{
		name = "rrmscan: harvest names the stations that actually answered",
		fn = function()
			-- A station's RRM capability bits are not a promise: one can
			-- advertise passive, active AND table measurement and answer every
			-- variant with report mode 0x02, "incapable". hostapd notifies
			-- over ubus only when a report BODY arrived, so a bodiless refusal
			-- never reaches this file and its ABSENCE is the only signal the
			-- caller has. Returned alongside the neighbours so the caller can
			-- stop asking a station that never reports.
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local _, reporters = rrmscan.harvest()
				assert_true(reporters["00:00:5e:00:53:10"] == true,
					"the station whose reports carried bodies is a reporter")
				assert_true(reporters["00:00:5e:00:53:1b"] == true, "and so is the second one")
			end)

			-- A bodied refusal is a station declining too, and must not count
			-- as an answer.
			with_events('{ "beacon-report": {"address":"aa:bb:cc:dd:ee:ff","op-class":115,'
				.. '"channel":0,"rcpi":0,"bssid":"00:00:00:00:00:00","rep-mode":4} }\n',
				function()
					local out, reporters = rrmscan.harvest()
					assert_eq(#out, 0, "and reports no neighbour")
					assert_nil(reporters["aa:bb:cc:dd:ee:ff"], "a refusal is not an answer")
				end)
		end
	},
	{
		name = "rrmscan: rcpi_verdict tells a signed-dBm client from a standard one",
		fn = function()
			-- Live 2026-10-13: own AP at 0xbf, hostapd measured -71 dBm.
			assert_true(rrmscan.rcpi_verdict(0xbf, -71) == true, "signed dBm")
			-- The capture rcpi_to_dbm was checked on: 124 -> -48.
			assert_true(rrmscan.rcpi_verdict(124, -50) == false, "standard RCPI")
			assert_nil(rrmscan.rcpi_verdict(124, -80), "neither fits: no verdict")
			assert_nil(rrmscan.rcpi_verdict(nil, -70), "no reading")
			assert_nil(rrmscan.rcpi_verdict(0xbf, nil), "no measurement")
			-- Below 128 the byte cannot be a negative dBm value.
			assert_true(rrmscan.rcpi_verdict(100, -60) == false, "100 is RCPI -60")
		end
	},
	{
		name = "rrmscan: harvest calibrates each client on its own AP's report",
		fn = function()
			local function line(sta, last, rcpi)
				return "100.5 phy0-ap1 BEACON-RESP-RX " .. sta .. " 7 00 "
					.. report_hex({op = 81, channel = 1, last = last, rcpi = rcpi,
						body_ies = ie(0, "N" .. last) .. RSN}) .. "\n"
			end
			local signed_sta, std_sta = "00:00:5e:00:53:10", "00:00:5e:00:53:11"
			-- Own AP is ...:02. The signed client reports a neighbour ...:03 at
			-- 0xa6 (-90) first and its AP at 0xbf (-65); the standard one gives
			-- 124 (-48) for its AP and 40 (-90) for the neighbour ...:04. The
			-- neighbour line comes first: calibration must find the AP's.
			local blob = line(signed_sta, 0x03, 0xa6) .. line(signed_sta, 0x02, 0xbf)
				.. line(std_sta, 0x02, 124) .. line(std_sta, 0x04, 40)
			local orig = rrmscan._rcpi_signed
			rrmscan._rcpi_signed = {}
			local ok, err = pcall(function()
				with_popen(function(cmd)
					if cmd:find(" info", 1, true) then return "Interface phy0-ap1\n\taddr 00:00:5e:00:53:02\n" end
					if cmd:find(signed_sta, 1, true) then return "\tsignal avg:\t-70 [-71, -77] dBm\n" end
					if cmd:find(std_sta, 1, true) then return "\tsignal avg:\t-50 [-51, -55] dBm\n" end
				end, function()
					local m = by_bssid(rrmscan.harvest(blob))
					assert_eq(m["00:00:5e:00:53:02"].signal, -65, "own AP, signed reading")
					assert_eq(m["00:00:5e:00:53:03"].signal, -90, "neighbour, signed reading")
					assert_eq(m["00:00:5e:00:53:04"].signal, -90, "standard client unchanged")
					assert_true(m["00:00:5e:00:53:03"].body == true, "a bodied record says so")
				end)
				-- The verdict outlives the drain: the same station's bodiless ubus
				-- copy, arriving later, is read the same way.
				local ubus = '{ "beacon-report": {"address":"' .. signed_sta
					.. '","op-class":81,"channel":6,"rcpi":178,"bssid":"00:00:5e:00:53:05","rep-mode":0} }\n'
				local m = by_bssid(rrmscan.harvest(ubus))
				assert_eq(m["00:00:5e:00:53:05"].signal, -78, "remembered for the ubus path")
				assert_nil(m["00:00:5e:00:53:05"].body, "and a ubus record has no body")
				-- An unknown station is read the standard way.
				local other = ubus:gsub(signed_sta, "00:00:5e:00:53:12")
				assert_eq(rrmscan.harvest(other)[1].signal, -21, "uncalibrated: RCPI")
			end)
			rrmscan._rcpi_signed = orig
			if not ok then error(err, 0) end
			-- Names off the event file never reach a shell unchecked.
			assert_nil(rrmscan.iface_bssid("phy0;reboot"), "bad ifname refused")
			assert_nil(rrmscan.sta_signal("phy0-ap1", "x; reboot"), "bad station refused")
		end
	},
	{
		name = "rrmscan: channel_of_freq inverts freq_of_channel, and refuses the gaps",
		fn = function()
			local C = rrmscan.channel_of_freq
			for _, ch in ipairs({1, 6, 11, 13, 14, 36, 52, 100, 144, 165}) do
				assert_eq(C(rrmscan.freq_of_channel(ch)), ch,
					"round trip for channel " .. ch)
			end
			-- A frequency off the 5 MHz grid is not a channel.
			assert_nil(C(5503), "off-grid 5 GHz")
			assert_nil(C(2400), "below the 2.4 GHz band")
			assert_nil(C(6115), "6 GHz: no channel vocabulary here")
			assert_nil(C(nil), "nil")
			assert_nil(C("radar"), "not a number")
		end
	},
	{
		name = "rrmscan: is_dfs_channel covers the whole 52-144 span and nothing else",
		fn = function()
			local D = rrmscan.is_dfs_channel
			assert_eq(D(52), true, "52")
			assert_eq(D(100), true, "100")
			assert_eq(D(144), true, "144")
			assert_eq(D("100"), true, "a string channel, as UCI stores it")
			assert_eq(D(48), false, "48 is non-DFS")
			assert_eq(D(149), false, "149 is non-DFS")
			assert_eq(D(11), false, "2.4 GHz")
			assert_eq(D("auto"), false, "auto is not a channel")
			assert_eq(D(nil), false, "nil")
		end
	},
	{
		name = "rrmscan: parse_dfs_states reads the per-channel DFS state machine",
		fn = function()
			-- Verbatim shape of `iw phy phy1 channels` on the AX3000T
			-- (OpenWrt 25.12, mt76), with one channel put on the
			-- non-occupancy list by hand -- which is the state no live read
			-- can be made to show on demand.
			local blob = table.concat({
				"Band 2:",
				"\t* 5180 MHz [36] ",
				"\t  Maximum TX power: 23.0 dBm",
				"\t  Channel widths: 20MHz HT40+ VHT80 VHT160",
				"\t* 5500 MHz [100] ",
				"\t  Maximum TX power: 26.0 dBm",
				"\t  Radar detection",
				"\t  Channel widths: 20MHz HT40+ VHT80 VHT160",
				"\t  DFS state: available (for 349821 sec)",
				"\t  DFS CAC time: 60000 ms",
				"\t* 5520 MHz [104] ",
				"\t  Maximum TX power: 26.0 dBm",
				"\t  Radar detection",
				"\t  DFS state: unavailable (for 1766 sec)",
				"\t  DFS CAC time: 60000 ms",
				"\t* 5540 MHz [108] ",
				"\t  Radar detection",
				"\t  DFS state: usable (for 0 sec)",
			}, "\n") .. "\n"
			local s = rrmscan.parse_dfs_states(blob)
			assert_eq(s[100].state, "available", "CAC done, may beacon")
			assert_eq(s[100].secs, 349821, "and for how long")
			assert_eq(s[104].state, "unavailable", "on the NOL after a radar hit")
			assert_eq(s[104].secs, 1766, "the NOL has 1766 s left")
			assert_eq(s[108].state, "usable", "a DFS channel awaiting CAC")
			-- A non-DFS channel is absent rather than claimed usable, so
			-- "not a DFS channel" stays distinguishable from "free".
			assert_nil(s[36], "36 has no DFS state at all")
			assert_eq(rrmscan.channel_in_nol(s, 104), true, "104 is blocked")
			assert_eq(rrmscan.channel_in_nol(s, "104"), true, "a string channel")
			assert_eq(rrmscan.channel_in_nol(s, 100), false, "100 is not")
			assert_eq(rrmscan.channel_in_nol(s, 108), false,
				"CAC pending is not the NOL -- hostapd does the CAC itself")
			assert_eq(rrmscan.channel_in_nol(s, 36), false, "no state, not blocked")
			assert_eq(rrmscan.channel_in_nol(nil, 100), false, "no dump at all")
			assert_eq(next(rrmscan.parse_dfs_states(nil)), nil, "no blob")
			assert_eq(next(rrmscan.parse_dfs_states("")), nil, "empty blob")
		end
	},
	{
		name = "rrmscan: chan_switch_args rebuilds a CSA for each 5 GHz width",
		fn = function()
			local A = rrmscan.chan_switch_args
			-- 80 MHz on channel 100: the live values read off the AX3000T's
			-- own hostapd (secondary_channel=1, centr_freq_seg0_idx=106).
			assert_eq(A(100, 80),
				"5500 sec_channel_offset=1 center_freq1=5530 bandwidth=80 vht",
				"ch 100 at 80 MHz")
			-- 104 is the upper half of the same 40 MHz pair, so its
			-- secondary sits below it, and the 80 MHz centre is unchanged.
			assert_eq(A(104, 80),
				"5520 sec_channel_offset=-1 center_freq1=5530 bandwidth=80 vht",
				"ch 104 at 80 MHz")
			assert_eq(A(36, 80),
				"5180 sec_channel_offset=1 center_freq1=5210 bandwidth=80 vht",
				"ch 36 at 80 MHz")
			assert_eq(A(149, 80),
				"5745 sec_channel_offset=1 center_freq1=5775 bandwidth=80 vht",
				"the UNII-3 block anchors on 149")
			assert_eq(A(100, 160),
				"5500 sec_channel_offset=1 center_freq1=5570 bandwidth=160 vht",
				"160 MHz spans 100-128, centre 5570")
			assert_eq(A(100, 40),
				"5500 sec_channel_offset=1 center_freq1=5510 bandwidth=40 ht",
				"40 MHz: ht, and the centre is between the pair")
			assert_eq(A(104, 40),
				"5520 sec_channel_offset=-1 center_freq1=5510 bandwidth=40 ht",
				"the same pair from the other side")
			-- 20 MHz carries nothing but the frequency: no secondary, no
			-- centre, and no ht/vht token to mis-declare the width with.
			assert_eq(A(100, 20), "5500", "20 MHz")
			assert_eq(A(100, nil), "5500", "unknown width is read as 20 MHz")
			-- 165 sits alone: no 40 MHz partner, so no bonded width at all.
			assert_nil(A(165, 40), "165 has no partner")
			assert_nil(A(165, 80), "and no 80 MHz block")
			assert_eq(A(165, 20), "5825", "but it is a perfectly good 20 MHz channel")
			assert_eq(rrmscan.block_center(149, 80), 155,
				"UNII-3's centre is 155, not the 154 an anchor-on-36 formula gives")
			assert_nil(A(11, 80), "2.4 GHz has no DFS and no block anchor")
			assert_nil(A(100, 60), "not a width hostapd knows")
			assert_nil(A("auto", 80), "auto is not a channel")
			assert_nil(A(nil, 80), "nil")
		end
	},
	{
		name = "rrmscan: parse_dfs reads a radar detection, and only a radar detection",
		fn = function()
			-- hostapd's own wording, as the hook stamps it:
			-- "<uptime> <ifname> <event words>".
			local blob = table.concat({
				"1234.56 phy1-ap0 DFS-CAC-START freq=5500 chan=100 sec_chan=1 width=1",
				"1299.01 phy1-ap0 DFS-RADAR-DETECTED freq=5500 ht_enabled=0 "
					.. "chan_offset=0 chan_width=1 cf1=5530 cf2=0",
				"1299.02 phy1-ap0 DFS-NEW-CHANNEL freq=5180 chan_offset=1 chan_width=1",
				"1300.00 phy1-ap0 BEACON-RESP-RX 00:00:5e:00:53:02 1 00 73240000",
				'1300.50 { "assoc": {"address":"00:00:5e:00:53:03"} }',
			}, "\n") .. "\n"
			local d = rrmscan.parse_dfs(blob)
			assert_eq(#d, 1, "one detection, not the CAC or the channel change")
			assert_eq(d[1].freq, 5500, "freq as hostapd reported it")
			assert_eq(d[1].channel, 100, "channel derived from the freq")
			assert_eq(d[1].ifname, "phy1-ap0", "the BSS it came from")
			assert_eq(d[1].t, 1299.01, "the hook's uptime stamp")
			-- The radar frequency is not cf1: on a wide channel they differ,
			-- and freq is the one that says where the radar was.
			assert_eq(rrmscan.channel_of_freq(5530), 106, "cf1 would be another channel")
			-- Nothing to report rather than a guessed channel.
			assert_eq(#rrmscan.parse_dfs(
				"1.0 phy1-ap0 DFS-RADAR-DETECTED ht_enabled=0\n"), 0, "no freq")
			assert_eq(#rrmscan.parse_dfs(
				"1.0 phy1-ap0 DFS-RADAR-DETECTED freq=5503\n"), 0, "unusable freq")
			assert_eq(#rrmscan.parse_dfs(nil), 0, "no blob")
			assert_eq(#rrmscan.parse_dfs(""), 0, "empty blob")
		end
	},
	{
		name = "rrmscan: the control-socket hook passes DFS events beside beacon reports",
		fn = function()
			local s = rrmscan.action_script()
			-- The hook is `sh`, so the filter is testable by running it.
			local path = os.tmpname()
			local events = os.tmpname()
			local orig = rrmscan.EVENT_FILE
			rrmscan.EVENT_FILE = events
			local f = assert(io.open(path, "w"))
			f:write(rrmscan.action_script())
			f:close()
			rrmscan.EVENT_FILE = orig
			local function run(args)
				os.execute("sh " .. path .. " " .. args .. " >/dev/null 2>&1")
			end
			run("phy1-ap0 DFS-RADAR-DETECTED freq=5500")
			run("phy1-ap0 BEACON-RESP-RX 00:00:5e:00:53:02 1 00 7324")
			run("phy1-ap0 AP-STA-CONNECTED 00:00:5e:00:53:03")
			local g = assert(io.open(events, "r"))
			local out = g:read("*a")
			g:close()
			os.remove(path)
			os.remove(events)
			assert_eq(out:find("DFS-RADAR-DETECTED", 1, true) ~= nil, true,
				"radar passed")
			assert_eq(out:find("BEACON-RESP-RX", 1, true) ~= nil, true,
				"beacon report still passed")
			assert_eq(out:find("AP-STA-CONNECTED", 1, true), nil,
				"everything else is still dropped at the hook")
			-- Both kinds land as "<uptime> <ifname> <event...>", so one drain
			-- reads both. The stamp is only checked where /proc/uptime exists:
			-- the dev box is macOS, where the hook's `read` finds no such file
			-- and leaves it empty. parse_dfs's own test pins the stamped form.
			local up = io.open("/proc/uptime", "r")
			if up then
				up:close()
				for line in out:gmatch("[^\n]+") do
					assert_eq(line:match("^%d+%.?%d*%s") ~= nil, true, "stamped: " .. line)
				end
			end
			for line in out:gmatch("[^\n]+") do
				assert_eq(line:find("phy1-ap0 ", 1, true) ~= nil, true,
					"carries the interface: " .. line)
			end
			assert_eq(s, rrmscan.action_script(), "the script is stable")
		end
	},
}
