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

return {
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
				assert_true(set["2a:1a:ec:4a:c0:df"], "full RRM client asked")
				assert_true(set["94:27:70:79:aa:18"], "passive+active client asked")
				-- rrm=75 is beacon-TABLE only: acked every real request and
				-- answered none, and hostapd refuses a passive request for it
				-- outright. Asking it is pure airtime for no data.
				assert_false(set["82:e0:6b:a2:f6:84"],
					"beacon-table-only client is NOT asked")
				-- rrm=0 -- most clients on a real network.
				assert_false(set["2a:85:dc:4f:87:e4"], "non-802.11k client is not asked")
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
				assert_eq(m["84:78:48:a4:fb:21"].channel, 1, "2.4 GHz neighbour")
				assert_eq(m["84:78:48:a4:fb:21"].band, "ng", "banded from the channel")
				assert_eq(m["84:78:48:a4:fb:21"].signal, -73, "rcpi 74 -> -73 dBm")
				assert_eq(m["30:b5:c2:d7:b6:59"].band, "na", "5 GHz neighbour")
				-- The captured rep-mode 4 report ("refused / incapable")
				-- carries an all-zero BSSID on channel 0. Both the BSSID
				-- guard and the rep-mode guard reject it, so this assertion
				-- alone does not prove the rep-mode one works -- see the next
				-- test for that.
				assert_nil(m["00:00:00:00:00:00"], "refused measurement dropped")
				-- Two clients both reported 30:b5:c2:d7:b6:59.
				local count = 0
				for _, e in ipairs(n) do
					if e.bssid == "30:b5:c2:d7:b6:59" then count = count + 1 end
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
				assert_not_nil(m["30:b5:c2:d7:b6:59"],
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
				{bssid = "30:b5:c2:d7:b6:5a", essid = "Home LAN",
				 security = "wpa2", channel = 6, bw = 40},
			}
			local neigh = {
				-- already known passively, with a richer record
				{bssid = "30:b5:c2:d7:b6:5a", channel = 6, band = "ng", signal = -48, seen_at = 100},
				-- new, same band
				{bssid = "84:78:48:a4:fb:21", channel = 1, band = "ng", signal = -73, seen_at = 100},
				-- new, WRONG band for this radio
				{bssid = "54:af:97:55:14:78", channel = 48, band = "na", signal = -80, seen_at = 100},
			}
			local out = rrmscan.merge_into(passive, neigh,
				{band = "ng", radio = "ng", radio_name = "radio0", now = 105})
			local m = by_bssid(out)
			assert_eq(#out, 2, "one appended, nothing duplicated or cross-banded")
			assert_eq(m["30:b5:c2:d7:b6:5a"].essid, "Home LAN",
				"the passive cache's richer record wins")
			assert_eq(m["30:b5:c2:d7:b6:5a"].bw, 40, "and keeps its real width")
			assert_nil(m["54:af:97:55:14:78"], "other band not merged into this radio")
			local added = m["84:78:48:a4:fb:21"]
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
				{bssid = "84:78:48:a4:fb:21", channel = 1, band = "ng", signal = -73, seen_at = 100},
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
					assert_true(all:find("ubus subscribe hostapd.phy0-ap0 hostapd.phy1-ap0", 1, true) ~= nil,
						"subscribes to every hostapd BSS at once")
					-- `ubus listen` catches broadcast events and receives
					-- NOTHING here; only subscribe gets hostapd's per-object
					-- notifications. Confirmed live.
					assert_false(all:find("ubus listen", 1, true) ~= nil,
						"never uses listen, which sees no beacon reports")
					assert_true(all:find("&") ~= nil, "runs in the background")
				end)
			end)

			with_popen(function(cmd)
				if cmd:find("pgrep", 1, true) then return "4711\n" end  -- running
				return ""
			end, function()
				with_exec(function(cmds)
					assert_false(rrmscan.collector_ensure(), "no-op while running")
					assert_eq(#cmds, 0, "spawns no second collector")
				end)
			end)
		end
	},
	{
		name = "rrmscan: a request asks for an ACTIVE all-channel measurement",
		fn = function()
			with_exec(function(cmds)
				rrmscan.request("phy1-ap0", "2a:1a:ec:4a:c0:df")
				local c = table.concat(cmds, "\n")
				assert_true(c:find("hostapd.phy1%-ap0 rrm_beacon_req") ~= nil,
					"goes to the right BSS object")
				assert_true(c:find('"addr":"2a:1a:ec:4a:c0:df"', 1, true) ~= nil,
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
				assert_true(reporters["2a:1a:ec:4a:c0:df"] == true,
					"the station whose reports carried bodies is a reporter")
				assert_true(reporters["94:27:70:79:aa:18"] == true, "and so is the second one")
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
}
