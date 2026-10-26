-- Tests for openuf/sysinfo.lua (/proc and iw parsing).
-- Run from project root: lua tests/run_tests.lua

local sysinfo = dofile("openuf/sysinfo.lua")

-- Fixture file loader
local function fixture(name)
	local f = io.open("tests/fixtures/" .. name, "r")
	if not f then error("fixture not found: " .. name) end
	local s = f:read("*a"); f:close()
	return s
end

-- Inject fixture data for _read_file and _run_cmd
local function with_fixtures(file_map, cmd_map, fn)
	local orig_rf  = sysinfo._read_file
	local orig_cmd = sysinfo._run_cmd
	-- `iw phy` output is cached per phy with a TTL (it describes hardware).
	-- Swapping the fixtures underneath it is exactly the thing that cache is
	-- not built for, so drop it on the way in AND on the way out: a test
	-- feeding a canned phy dump must not leak those caps into a later one.
	sysinfo._phy_info_cache = {}
	-- Same reasoning for the lookup pass and for the uplink cache, which holds
	-- an `ip route` answer for five minutes: a pass or an entry left behind
	-- would memoize one test's fixtures into the next.
	sysinfo.end_pass()
	sysinfo._uplink_cache = {}
	sysinfo._peer_cache = {}
	sysinfo._akm_cache = {}
	sysinfo._read_file = function(path)
		for k, v in pairs(file_map) do
			if path == k or path:find(k, 1, true) then return v end
		end
		return nil
	end
	sysinfo._run_cmd = function(cmd)
		for k, v in pairs(cmd_map or {}) do
			if cmd:find(k, 1, true) then return v end
		end
		return ""
	end
	local ok, err = pcall(fn)
	sysinfo._read_file = orig_rf
	sysinfo._run_cmd   = orig_cmd
	sysinfo._phy_info_cache = {}
	sysinfo._uplink_cache = {}
	sysinfo._peer_cache = {}
	sysinfo._akm_cache = {}
	sysinfo.end_pass()
	if not ok then error(err, 2) end
end

return {
	{
		name = "sysinfo: uptime() parses /proc/uptime correctly",
		fn = function()
			with_fixtures({["/proc/uptime"] = fixture("proc_uptime.txt")}, {}, function()
				local up = sysinfo.uptime()
				assert_eq(up, 12345, "uptime seconds (floor)")
			end)
		end
	},
	{
		name = "sysinfo: uptime() returns 0 when file missing",
		fn = function()
			with_fixtures({}, {}, function()
				assert_eq(sysinfo.uptime(), 0, "0 when missing")
			end)
		end
	},
	{
		name = "sysinfo: meminfo() parses /proc/meminfo total and free",
		fn = function()
			with_fixtures({["/proc/meminfo"] = fixture("proc_meminfo.txt")}, {}, function()
				local m = sysinfo.meminfo()
				assert_eq(m.total_kb, 131072, "total_kb")
				assert_eq(m.free_kb,   65536, "free_kb")
				assert_eq(m.buffers_kb, 2048, "buffers_kb")
			end)
		end
	},
	{
		name = "sysinfo: loadavg() returns /proc/loadavg's three strings, zeros without it",
		fn = function()
			with_fixtures({["/proc/loadavg"] = "1.07 0.66 0.30 2/71 4321\n"}, {}, function()
				local a, b, c = sysinfo.loadavg()
				assert_eq(a, "1.07", "1 min")
				assert_eq(b, "0.66", "5 min")
				assert_eq(c, "0.30", "15 min")
			end)
			with_fixtures({}, {}, function()
				local a, b, c = sysinfo.loadavg()
				assert_eq(a .. " " .. b .. " " .. c, "0.00 0.00 0.00", "firmware's default")
			end)
		end
	},
	{
		name = "sysinfo: ext_offset() puts the secondary 20 MHz on the primary's 40 MHz partner",
		fn = function()
			assert_eq(sysinfo.ext_offset(2437, 20, 2437), 0, "20 MHz: none")
			assert_eq(sysinfo.ext_offset(2412, 40, 2422), 1, "HT40+ ch 1: above")
			assert_eq(sysinfo.ext_offset(2462, 40, 2452), -1, "HT40- ch 11: below")
			-- 80 MHz block 100-112 (center 5530): 40 MHz pairs 100/104, 108/112.
			assert_eq(sysinfo.ext_offset(5500, 80, 5530), 1, "ch 100: partner 104 above")
			assert_eq(sysinfo.ext_offset(5520, 80, 5530), -1, "ch 104: partner 100 below")
			assert_eq(sysinfo.ext_offset(5540, 80, 5530), 1, "ch 108: partner 112 above")
			assert_eq(sysinfo.ext_offset(5560, 80, 5530), -1, "ch 112: partner 108 below")
			-- 160 MHz block 36-64 (center 5250): ch 44's partner is 48.
			assert_eq(sysinfo.ext_offset(5220, 160, 5250), 1, "160 MHz ch 44: above")
			assert_eq(sysinfo.ext_offset(nil, 40, 2422), 0, "no frequency: none")
		end
	},
	{
		name = "sysinfo: interfaces() parses /proc/net/dev rx_bytes and tx_bytes",
		fn = function()
			with_fixtures(
				{
					["/proc/net/dev"]    = fixture("proc_net_dev.txt"),
					["/sys/class/net/"]  = "",   -- no MAC, returns ""
				},
				{},
				function()
					local ifaces = sysinfo.interfaces()
					-- Should have lo, eth0, eth1
					assert_true(#ifaces >= 3, "at least 3 interfaces")
					local eth0
					for _, i in ipairs(ifaces) do
						if i.name == "eth0" then eth0 = i end
					end
					assert_not_nil(eth0, "eth0 found")
					assert_eq(eth0.rx_bytes,  9876543, "eth0 rx_bytes")
					assert_eq(eth0.tx_bytes,   654321, "eth0 tx_bytes")
					assert_eq(eth0.rx_packets,   5432, "eth0 rx_packets")
					assert_eq(eth0.tx_errors,       1, "eth0 tx_errors")
				end
			)
		end
	},
	{
		name = "sysinfo: sta_table() parses iw station dump output",
		fn = function()
			with_fixtures({}, {["station dump"] = fixture("iw_station_dump.txt")}, function()
				local stas = sysinfo.sta_table("wlan0")
				assert_eq(#stas, 2, "two clients")
				assert_eq(stas[1].mac,      "aa:bb:cc:dd:ee:ff", "first client MAC")
				assert_eq(stas[1].signal,   -62,                 "first client signal")
				assert_eq(stas[1].rx_bytes, 45678,               "first client rx_bytes")
				assert_eq(stas[1].tx_bytes, 98765,               "first client tx_bytes")
				assert_eq(stas[1].tx_retries, 4,                 "first client tx_retries")
				assert_eq(stas[1].tx_failed,  0,                 "first client tx_failed")
				assert_eq(stas[1].connected_sec, 3600,           "first client connected_sec")
				assert_eq(stas[1].tx_mcs, 15,                    "first client tx_mcs from 'MCS 15'")
				assert_eq(stas[1].rx_mcs, 7,                     "first client rx_mcs from 'MCS 7'")
				assert_eq(stas[1].tx_generation, "n",            "first client is plain HT (bare MCS)")
				assert_eq(stas[1].tx_nss, 2,                     "first client nss from MCS 15 -> floor(15/8)+1")
				assert_eq(stas[1].rx_generation, "n",            "rx generation parsed from the rx bitrate line")
				assert_eq(stas[1].rx_nss, 1,                     "rx nss from the rx line's own MCS 7 -> floor(7/8)+1")
				assert_eq(stas[2].mac,      "11:22:33:44:55:66", "second client MAC")
				assert_eq(stas[2].signal,   -75,                 "second client signal")
				assert_eq(stas[2].connected_sec, 42,              "second client connected_sec")
				assert_eq(stas[2].tx_mcs, 6,                      "second client tx_mcs from 'MCS 6'")
				assert_eq(stas[2].rx_mcs, 5,                      "second client rx_mcs from 'MCS 5'")
				assert_eq(stas[2].tx_generation, "n",            "second client is plain HT (bare MCS)")
				assert_eq(stas[2].tx_nss, 1,                     "second client nss from MCS 6 -> floor(6/8)+1")
				assert_eq(stas[1].signal_avg, -63,               "running average, its own line")
				assert_eq(stas[2].signal_avg, -74,               "second client signal_avg")
			end)
		end
	},
	{
		name = "sysinfo: sta_table() derives generation/nss from VHT and HE bitrate lines",
		fn = function()
			local dump = "Station cc:cc:cc:cc:cc:cc (on wlan1)\n"
				.. "\tsignal:  \t-50 dBm\n"
				.. "\ttx bitrate:\t866.7 MBit/s VHT-MCS 9 VHT-NSS 2 80MHz short GI\n"
				.. "\trx bitrate:\t780.0 MBit/s VHT-MCS 8 VHT-NSS 2 80MHz short GI\n"
				.. "Station dd:dd:dd:dd:dd:dd (on wlan1)\n"
				.. "\tsignal:  \t-45 dBm\n"
				.. "\ttx bitrate:\t1200.9 MBit/s HE-MCS 11 HE-NSS 2 80MHz\n"
				.. "\trx bitrate:\t1080.1 MBit/s HE-MCS 9 HE-NSS 2 80MHz\n"
				.. "Station ee:ee:ee:ee:ee:ee (on wlan1)\n"
				.. "\tsignal:  \t-70 dBm\n"
				.. "\ttx bitrate:\t54.0 MBit/s\n"
				.. "\trx bitrate:\t48.0 MBit/s\n"
			with_fixtures({}, {["station dump"] = dump}, function()
				local stas = sysinfo.sta_table("wlan1")
				assert_eq(#stas, 3, "three stations")
				assert_eq(stas[1].tx_generation, "ac", "VHT-MCS -> generation ac")
				assert_eq(stas[1].tx_nss, 2, "VHT-NSS 2 read directly")
				assert_eq(stas[2].tx_generation, "ax", "HE-MCS -> generation ax")
				assert_eq(stas[2].tx_nss, 2, "HE-NSS 2 read directly")
				assert_eq(stas[3].tx_generation, nil, "legacy rate has no generation token")
				assert_eq(stas[3].tx_nss, nil, "legacy rate has no nss token")
			end)
		end
	},
	{
		name = "sysinfo: sta_table() reads the tx rate's channel width, 20 MHz when iw prints none",
		fn = function()
			local dump = "Station cc:cc:cc:cc:cc:cc (on wlan1)\n"
				.. "\ttx bitrate:\t390.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 1\n"
				.. "\trx bitrate:\t433.3 MBit/s VHT-MCS 9 160MHz short GI VHT-NSS 1\n"
				.. "Station dd:dd:dd:dd:dd:dd (on wlan1)\n"
				.. "\ttx bitrate:\t65.0 MBit/s MCS 7\n"
			with_fixtures({}, {["station dump"] = dump}, function()
				local stas = sysinfo.sta_table("wlan1")
				assert_eq(stas[1].tx_width, 80, "80MHz token on the tx line")
				assert_eq(stas[2].tx_width, 20, "no token: 20 MHz")
				assert_eq(stas[1].rx_width, 160, "the rx line's own width")
				assert_eq(stas[2].rx_width, nil, "no rx line: no rx width")
			end)
		end
	},
	{
		name = "sysinfo: sta_table() reads an underflowed u32 retry counter as 0",
		fn = function()
			-- mt76 (OpenWrt 25.12) adds count - 1 with no guard for count 0:
			-- a fresh station's counters read 2^32 - 1, which the controller
			-- added to its per-band totals as a 2^32 jump.
			local dump = "Station cc:cc:cc:cc:cc:cc (on wlan1)\n"
				.. "\ttx packets:\t12\n"
				.. "\ttx retries:\t4294967295\n"
				.. "\ttx failed:\t4294967295\n"
				.. "Station dd:dd:dd:dd:dd:dd (on wlan1)\n"
				.. "\ttx packets:\t5000\n"
				.. "\ttx retries:\t2147483647\n"
				.. "\ttx failed:\t7\n"
			with_fixtures({}, {["station dump"] = dump}, function()
				local stas = sysinfo.sta_table("wlan1")
				assert_eq(stas[1].tx_retries, 0, "-1 as u32 is no retry count")
				assert_eq(stas[1].tx_failed, 0, "nor a failed count")
				assert_eq(stas[2].tx_retries, 2147483647, "2^31 - 1 is still a count")
				assert_eq(stas[2].tx_failed, 7, "small counts pass")
			end)
		end
	},
	{
		name = "sysinfo: wifi_driver() reads the netdev's driver once, without a fork",
		fn = function()
			sysinfo._driver_cache = {}
			local reads, forks = 0, 0
			with_fixtures({["/sys/class/net/phy1-ap0/device/uevent"] =
				"OF_NAME=wifi\nDRIVER=mt798x-wmac\nMODALIAS=of:Nwifi\n"}, {}, function()
				local orig, orig_cmd = sysinfo._read_file, sysinfo._run_cmd
				sysinfo._read_file = function(p) reads = reads + 1; return orig(p) end
				sysinfo._run_cmd = function(cmd) forks = forks + 1; return orig_cmd(cmd) end
				assert_eq(sysinfo.wifi_driver("phy1-ap0"), "mt798x-wmac", "the uevent's DRIVER=")
				assert_eq(sysinfo.wifi_driver("phy1-ap0"), "mt798x-wmac", "cached")
				sysinfo._read_file, sysinfo._run_cmd = orig, orig_cmd
			end)
			assert_eq(reads, 1, "one read per netdev")
			assert_eq(forks, 0, "and no fork")
			with_fixtures({}, {}, function()
				assert_nil(sysinfo.wifi_driver("lo"), "no driver link: nil")
			end)
			assert_nil(sysinfo.wifi_driver(nil), "no netdev: nil")
			sysinfo._driver_cache = {}
		end
	},
	{
		name = "sysinfo: sta_powersave() reads PS_STA only where mac80211 tracks it",
		fn = function()
			local D = "/sys/kernel/debug/ieee80211/"
			local st = D .. "phy1/netdev:phy1-ap0/stations/"
			sysinfo._ps_phy_cache = {}
			with_fixtures({
				["/sys/class/net/phy1-ap0/phy80211/name"] = "phy1\n",
				[D .. "phy1/hwflags"] = "RX_INCLUDES_FCS\nSIGNAL_DBM\nPS_NULLFUNC_STACK\n",
				[st .. "00:00:5e:00:53:31/flags"] = "AUTH\nASSOC\nPS_STA\nAUTHORIZED\n",
				[st .. "00:00:5e:00:53:32/flags"] = "AUTH\nASSOC\nAUTHORIZED\n",
			}, {}, function()
				assert_eq(sysinfo.sta_powersave("phy1-ap0", "00:00:5e:00:53:31"), true, "PS_STA: dozing")
				assert_eq(sysinfo.sta_powersave("phy1-ap0", "00:00:5e:00:53:32"), false, "no PS_STA: awake")
				assert_eq(sysinfo.sta_powersave("phy1-ap0", "00:00:5e:00:53:33"), nil, "no station dir: unknown")
			end)
			-- ath10k and mt76 set AP_LINK_PS: the driver owns power save and
			-- PS_STA never appears, so the answer is unknown, not "awake".
			sysinfo._ps_phy_cache = {}
			with_fixtures({
				["/sys/class/net/phy0-ap0/phy80211/name"] = "phy0\n",
				[D .. "phy0/hwflags"] = "SIGNAL_DBM\nAP_LINK_PS\nSUPPORTS_TX_ENCAP_OFFLOAD\n",
				[D .. "phy0/netdev:phy0-ap0/stations/00:00:5e:00:53:31/flags"] = "AUTH\nASSOC\nAUTHORIZED\n",
			}, {}, function()
				assert_eq(sysinfo.sta_powersave("phy0-ap0", "00:00:5e:00:53:31"), nil, "AP_LINK_PS: unknown")
			end)
			-- No debugfs at all.
			sysinfo._ps_phy_cache = {}
			with_fixtures({["/sys/class/net/phy0-ap0/phy80211/name"] = "phy0\n"}, {}, function()
				assert_eq(sysinfo.sta_powersave("phy0-ap0", "00:00:5e:00:53:31"), nil, "no hwflags: unknown")
			end)
			sysinfo._ps_phy_cache = {}
		end
	},
	{
		name = "sysinfo: radio_timeouts() reads ath9k's GTT and CST interrupt counts",
		fn = function()
			local D = "/sys/kernel/debug/ieee80211/"
			-- Trimmed from the Archer C5's 2.4 GHz radio (2026-10-10).
			local irq = "                 RXLP:  391606534\n             WATCHDOG:       1147\n"
				.. "                   TX:  281575066\n                 SWBA:  468345888\n"
				.. "                  CST:     263611\n                  GTT:     312203\n"
				.. "                TOTAL: 1123082953\nSYNC_CAUSE stats:\n             Sync-All:          0\n"
			with_fixtures({
				["/sys/class/net/phy1-ap0/phy80211/name"] = "phy1\n",
				[D .. "phy1/ath9k/interrupt"] = irq,
			}, {}, function()
				local txto, cst = sysinfo.radio_timeouts("phy1-ap0")
				assert_eq(txto, 312203, "ast_txto = GTT, global transmit timeouts")
				assert_eq(cst, 263611, "ast_cst = CST, carrier sense timeouts")
			end)
			-- ath10k and mt76: no ath9k directory.
			with_fixtures({["/sys/class/net/phy0-ap0/phy80211/name"] = "phy0\n"}, {}, function()
				assert_nil(sysinfo.radio_timeouts("phy0-ap0"), "not ath9k: nil")
			end)
			-- Half a pair is not read as one.
			for _, only in ipairs({"CST", "GTT"}) do
				with_fixtures({
					["/sys/class/net/phy1-ap0/phy80211/name"] = "phy1\n",
					[D .. "phy1/ath9k/interrupt"] = "                  " .. only .. ":     263611\n",
				}, {}, function()
					assert_nil(sysinfo.radio_timeouts("phy1-ap0"), "only " .. only .. ": nil")
				end)
			end
			assert_nil(sysinfo.radio_timeouts(nil), "no netdev: nil")
		end
	},
	{
		name = "sysinfo: sta_akms() parses hostapd all_sta, akm_is_ft() knows the FT suites",
		fn = function()
			local seen
			with_fixtures({}, {["all_sta"] =
				"00:00:5e:00:53:31\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][MFP]\naid=3\n"
				.. "AKMSuiteSelector=00-0f-ac-9\nhostapdWPAPTKState=11\n"
				.. "00:00:5e:00:53:32\nflags=[AUTH][ASSOC][AUTHORIZED]\nAKMSuiteSelector=00-0f-ac-2\n"
				.. "00:00:5e:00:53:33\nflags=[AUTH][ASSOC][AUTHORIZED]\n"}, function()
				local orig = sysinfo._run_cmd
				sysinfo._run_cmd = function(cmd) seen = cmd; return orig(cmd) end
				local a, listed = sysinfo.sta_akms({"phy0-ap0", "phy0-ap1", "bad;name"})
				sysinfo._run_cmd = orig
				assert_eq(a["00:00:5e:00:53:31"], "00-0f-ac-9", "FT-SAE station")
				assert_eq(a["00:00:5e:00:53:32"], "00-0f-ac-2", "PSK station")
				assert_eq(a["00:00:5e:00:53:33"], nil, "open station: no AKM line")
				assert_true(listed["00:00:5e:00:53:33"], "but listed")
				assert_eq(listed["00:00:5e:00:53:34"], nil, "a station hostapd did not print is not")
			end)
			assert_true(seen:find("for b in phy0-ap0 phy0-ap1;", 1, true) ~= nil, "one run over both BSSes")
			assert_true(seen:find("bad;name", 1, true) == nil, "a name unsafe for the shell is dropped")
			with_fixtures({}, {}, function()
				local n = 0
				local orig = sysinfo._run_cmd
				sysinfo._run_cmd = function(cmd) n = n + 1; return orig(cmd) end
				assert_eq(next((sysinfo.sta_akms({}))), nil, "no BSS: empty")
				sysinfo._run_cmd = orig
				assert_eq(n, 0, "no BSS: nothing run")
			end)
			for _, akm in ipairs({"00-0f-ac-3", "00-0f-ac-4", "00-0f-ac-9", "00-0f-ac-13", "00-0f-ac-19", "00-0f-ac-25"}) do
				assert_true(sysinfo.akm_is_ft(akm), akm .. " is FT")
			end
			for _, akm in ipairs({"00-0f-ac-1", "00-0f-ac-2", "00-0f-ac-6", "00-0f-ac-8", "00-0f-ac-18"}) do
				assert_eq(sysinfo.akm_is_ft(akm), false, akm .. " is not FT")
			end
			assert_eq(sysinfo.akm_is_ft(nil), false, "no AKM: not FT")
		end
	},
	{
		name = "sysinfo: sta_akms_cached() asks hostapd once per association",
		fn = function()
			local files = {["/proc/uptime"] = "1000.00 0\n"}
			local A, B, C = "00:00:5e:00:53:31", "00:00:5e:00:53:32", "00:00:5e:00:53:33"
			local reply = {
				["phy0-ap0"] = A .. "\nAKMSuiteSelector=00-0f-ac-9\n" .. B .. "\nAKMSuiteSelector=00-0f-ac-2\n",
				["phy0-ap1"] = C .. "\nflags=[AUTH][ASSOC][AUTHORIZED]\n",
			}
			local runs, asked = 0, {}
			with_fixtures(files, {}, function()
				sysinfo._run_cmd = function(cmd)
					runs = runs + 1
					local out = {}
					for b in cmd:match("for b in (.-);"):gmatch("%S+") do
						asked[#asked + 1] = b
						out[#out + 1] = reply[b] or ""
					end
					return table.concat(out)
				end
				local stas = {{mac = A, bss = "phy0-ap0", conn = 100}, {mac = B, bss = "phy0-ap0", conn = 50},
					{mac = C, bss = "phy0-ap1", conn = 10}}
				local a = sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 1, "first heartbeat: one hostapd_cli run")
				assert_eq(#asked, 2, "over both BSSes")
				assert_eq(a[A], "00-0f-ac-9", "FT-SAE station")
				assert_eq(a[B], "00-0f-ac-2", "PSK station")
				assert_eq(a[C], nil, "open station: no AKM")

				-- Fifteen seconds on: the same associations, one second of jitter.
				files["/proc/uptime"] = "1015.00 0\n"
				stas[1].conn, stas[2].conn, stas[3].conn = 116, 65, 25
				a = sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 1, "steady stations: nothing run")
				assert_eq(a[A], "00-0f-ac-9", "FT-SAE from the cache")
				assert_eq(a[B], "00-0f-ac-2", "PSK from the cache")
				assert_eq(a[C], nil, "open station cached as having none")

				-- B reconnected with a new AKM between heartbeats: its connected
				-- time is still past the last one, but its start moved.
				files["/proc/uptime"] = "1030.00 0\n"
				stas[1].conn, stas[2].conn, stas[3].conn = 131, 12, 40
				reply["phy0-ap0"] = A .. "\nAKMSuiteSelector=00-0f-ac-9\n" .. B .. "\nAKMSuiteSelector=00-0f-ac-8\n"
				asked = {}
				a = sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 2, "a new association is asked again")
				assert_eq(#asked, 1, "on its BSS only")
				assert_eq(asked[1], "phy0-ap0", "phy0-ap0")
				assert_eq(a[B], "00-0f-ac-8", "with its new AKM")
				assert_eq(a[C], nil, "the other BSS still answers from the cache")

				-- A moved to the other BSS with the same connected time.
				stas[1].bss = "phy0-ap1"
				reply["phy0-ap1"] = C .. "\n" .. A .. "\nAKMSuiteSelector=00-0f-ac-4\n"
				a = sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 3, "a station on another BSS is asked again")
				assert_eq(a[A], "00-0f-ac-4", "with the AKM it holds there")

				-- hostapd did not list a station (it failed, or the station came
				-- after iw's read): nothing is kept for it.
				local D = "00:00:5e:00:53:34"
				stas[4] = {mac = D, bss = "phy0-ap1", conn = 1}
				sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 4, "a new station is asked for")
				sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 5, "and asked again while hostapd does not list it")
				stas[4] = nil

				-- A station unseen for AKM_IDLE is forgotten; a cache hit
				-- counts as seen.
				assert_true(sysinfo._akm_cache[D] == nil, "an unlisted station was never cached")
				files["/proc/uptime"] = "1250.00 0\n"
				sysinfo.sta_akms_cached({{mac = B, bss = "phy0-ap0", conn = 232}})
				assert_eq(runs, 5, "B answered from the cache")
				files["/proc/uptime"] = "1330.00 0\n"
				sysinfo.sta_akms_cached({})
				assert_true(sysinfo._akm_cache[A] ~= nil, "A kept for AKM_IDLE")
				files["/proc/uptime"] = "1331.00 0\n"
				sysinfo.sta_akms_cached({})
				assert_eq(sysinfo._akm_cache[A], nil, "and dropped after it")
				assert_true(sysinfo._akm_cache[B] ~= nil, "B, seen at 1250, kept")
				files["/proc/uptime"] = "1551.00 0\n"
				sysinfo.sta_akms_cached({})
				assert_eq(next(sysinfo._akm_cache), nil, "all gone")
			end)
		end
	},
	{
		name = "sysinfo: sta_akms_cached() without a clock asks every time",
		fn = function()
			local runs = 0
			with_fixtures({}, {}, function()
				sysinfo._run_cmd = function() runs = runs + 1 return "00:00:5e:00:53:31\nAKMSuiteSelector=00-0f-ac-9\n" end
				local stas = {{mac = "00:00:5e:00:53:31", bss = "phy0-ap0", conn = 100}}
				assert_eq(sysinfo.sta_akms_cached(stas)["00:00:5e:00:53:31"], "00-0f-ac-9", "answered")
				sysinfo.sta_akms_cached(stas)
				assert_eq(runs, 2, "asked again")
				assert_eq(next(sysinfo._akm_cache), nil, "nothing kept")
			end)
		end
	},
	{
		name = "sysinfo: sta_table() returns empty table for empty command output",
		fn = function()
			with_fixtures({}, {["station dump"] = ""}, function()
				local stas = sysinfo.sta_table("wlan0")
				assert_eq(#stas, 0, "empty when no output")
			end)
		end
	},
	{
		name = "sysinfo: radio_stats() parses survey dump in-use channel",
		fn = function()
			with_fixtures({}, {["survey dump"] = fixture("iw_survey_dump.txt")}, function()
				local stats = sysinfo.radio_stats("wlan0")
				-- The fixture mirrors real iw output: entries come in the phy's
				-- frequency order, so the in-use channel is NOT first (here it
				-- is third of four). Nothing may assume a position.
				assert_true(#stats >= 1, "at least one entry")
				local active
				for _, s in ipairs(stats) do
					if s.freq == 2437 then active = s end
				end
				assert_not_nil(active, "2437 MHz entry found")
				assert_eq(active.noise,             -95,  "noise dBm")
				assert_eq(active.channel_time,      5000, "channel_time ms")
				assert_eq(active.channel_time_busy, 1850, "channel_time_busy ms")
				assert_eq(active.channel_time_rx,    900, "channel_time_rx ms")
				assert_eq(active.channel_time_tx,    450, "channel_time_tx ms")
				-- The "[in use]" marker is the only way to identify the
				-- operating channel; without it callers fall back to stats[1],
				-- which here is a 3 ms scan dwell.
				assert_true(active.in_use, "2437 MHz flagged in_use")
				assert_true(not stats[1].in_use, "first entry not flagged in_use")
				assert_eq(stats[1].freq, 2412, "first entry is a non-operating channel")
			end)
		end
	},
	{
		name = "sysinfo: radio_stats() does not match 'extension channel busy time' as channel_time_busy",
		fn = function()
			-- Real iw(8) emits a separate "extension channel busy time:"
			-- field (secondary 20MHz segment of a wider channel) alongside
			-- "channel busy time:" -- an unanchored pattern match would
			-- wrongly pick up the extension field's value instead of (or as
			-- well as) the primary one, since "channel busy time:" is a
			-- literal substring of "extension channel busy time:".
			local dump = "Survey data from wlan0 (on operating channel):\n"
				.. "\tfrequency:\t\t\t2437 MHz [in use]\n"
				.. "\tchannel busy time:\t\t1850 ms\n"
				.. "\textension channel busy time:\t9999 ms\n"
			with_fixtures({}, {["survey dump"] = dump}, function()
				local stats = sysinfo.radio_stats("wlan0")
				assert_eq(stats[1].channel_time_busy, 1850,
					"picks the primary field, not the extension channel's value")
			end)
		end
	},
	{
		name = "sysinfo: radio_stats() returns empty table for empty output",
		fn = function()
			with_fixtures({}, {["survey dump"] = ""}, function()
				assert_eq(#sysinfo.radio_stats("wlan0"), 0, "empty result")
			end)
		end
	},
	{
		name = "sysinfo: radio_stats() returns empty table for nil ifname",
		fn = function()
			with_fixtures({}, {}, function()
				assert_eq(#sysinfo.radio_stats(nil), 0, "nil ifname safe")
			end)
		end
	},
	{
		name = "sysinfo: cpu_percent() returns 0 on the first call (no prior sample)",
		fn = function()
			local prev = sysinfo._prev_cpu
			sysinfo._prev_cpu = nil
			with_fixtures({["/proc/stat"] = fixture("proc_stat_1.txt")}, {}, function()
				assert_eq(sysinfo.cpu_percent(), 0, "no prior sample to diff against")
			end)
			sysinfo._prev_cpu = prev
		end
	},
	{
		name = "sysinfo: cpu_percent() computes delta-based usage between two samples",
		fn = function()
			local prev = sysinfo._prev_cpu
			sysinfo._prev_cpu = nil
			with_fixtures({["/proc/stat"] = fixture("proc_stat_1.txt")}, {}, function()
				sysinfo.cpu_percent()  -- prime the first sample
			end)
			with_fixtures({["/proc/stat"] = fixture("proc_stat_2.txt")}, {}, function()
				-- total delta = 200, idle delta = 100 -> 50% busy
				assert_eq(sysinfo.cpu_percent(), 50, "delta-based CPU percent")
			end)
			sysinfo._prev_cpu = prev
		end
	},
	{
		name = "sysinfo: cpu_percent() returns 0 when /proc/stat is unavailable",
		fn = function()
			local prev = sysinfo._prev_cpu
			sysinfo._prev_cpu = nil
			with_fixtures({}, {}, function()
				assert_eq(sysinfo.cpu_percent(), 0, "missing /proc/stat is safe")
			end)
			sysinfo._prev_cpu = prev
		end
	},
	{
		name = "sysinfo: mac_table() parses bridge fdb dynamic entries, joined with arp and dhcp leases",
		fn = function()
			sysinfo._mac_first_seen = {}
			with_fixtures(
				{
					["/proc/net/arp"]   = fixture("proc_net_arp.txt"),
					["/tmp/dhcp.leases"] = fixture("dhcp_leases.txt"),
				},
				{["bridge fdb show"] = fixture("bridge_fdb_dump.txt")},
				function()
					local hosts = sysinfo.mac_table("eth1")
					assert_eq(#hosts, 2, "two dynamically-learned hosts")
					assert_eq(hosts[1].mac, "aa:bb:cc:dd:ee:01", "first host mac")
					assert_eq(hosts[1].ip,  "192.168.1.50", "first host ip from arp")
					assert_eq(hosts[1].hostname, "laptop", "first host hostname from dhcp leases")
					assert_eq(hosts[2].mac, "aa:bb:cc:dd:ee:02", "second host mac")
					assert_eq(hosts[2].ip,  "192.168.1.51", "second host ip from arp")
					assert_true(hosts[2].hostname == nil, "second host has no lease entry -- hostname stays nil")
				end
			)
		end
	},
	{
		name = "sysinfo: mac_table() excludes self/permanent and multicast/broadcast fdb entries",
		fn = function()
			-- Fixture's self/permanent lines (the bridge's own MAC, an IPv4
			-- multicast group, and a broadcast address) must never surface as
			-- hosts -- only the two dynamically-learned "master br-lan" lines
			-- should (already asserted above); this pins the exclusion itself.
			sysinfo._mac_first_seen = {}
			with_fixtures({}, {["bridge fdb show"] = fixture("bridge_fdb_dump.txt")}, function()
				local hosts = sysinfo.mac_table("eth1")
				for _, h in ipairs(hosts) do
					assert_true(h.mac ~= "de:ad:be:ef:00:01", "self-permanent entry excluded")
					assert_true(h.mac ~= "33:33:00:00:00:01", "IPv6 multicast entry excluded")
					assert_true(h.mac ~= "01:00:5e:00:00:01", "IPv4 multicast entry excluded")
					assert_true(h.mac ~= "ff:ff:ff:ff:ff:ff", "broadcast entry excluded")
				end
			end)
		end
	},
	{
		name = "sysinfo: nft_tap() parses both of the learning tap's sets",
		fn = function()
			-- Fixture is the verbatim output of `nft list table` on the real
			-- board (nftables v1.1.6), not a hand-written approximation: the
			-- continuation-line indentation, the `size 65535` nft adds itself,
			-- the `expires` suffixes and the rules in the same dump are all
			-- things the parser has to survive.
			with_fixtures({},
				{["nft list table"] = fixture("nft_list_table_openuf_learn.txt")},
				function()
					local tap = sysinfo.nft_tap()
					assert_eq(#tap.macs["lan2"], 2, "two hosts seen on lan2")
					assert_eq(tap.macs["lan2"][1], "00:00:5e:00:53:07", "sorted, first")
					assert_eq(tap.macs["lan2"][2], "00:00:5e:00:53:09", "sorted, second")
					assert_eq(#tap.macs["lan3"], 1, "one on lan3")
					-- The three-component elements are the address set and must
					-- not be counted as hosts a second time.
					assert_eq(tap.ips["lan2"]["00:00:5e:00:53:07"], "192.0.2.20",
						"the address learned for that host")
					-- Two addresses are live for one MAC; the one refreshed
					-- most recently (largest `expires`) is the current one.
					assert_eq(tap.ips["lan2"]["00:00:5e:00:53:09"], "192.0.2.22",
						"the freshest of two live addresses wins")
					-- The `type ifname . ether_addr` lines and the
					-- `iifname "lan2"` rules sit in the same dump and are
					-- tempting false matches for a looser pattern.
					assert_true(tap.macs["ether_addr"] == nil, "the type line is not an element")
					assert_eq(#tap.macs["lan2"], 2, "and the rules added no hosts")
				end
			)
		end
	},
	{
		name = "sysinfo: nft_tap() is empty when no tap is installed",
		fn = function()
			-- `nft list table` on a missing table writes to stderr and prints
			-- nothing, which _run_cmd returns as "".
			with_fixtures({}, {["nft list table"] = ""}, function()
				local tap = sysinfo.nft_tap()
				assert_eq(next(tap.macs), nil, "no tap, no hosts")
				assert_eq(next(tap.ips), nil, "and no addresses")
			end)
		end
	},
	{
		name = "sysinfo: mac_table() falls back to the tap only when asked, and only when the FDB is silent",
		fn = function()
			sysinfo._mac_first_seen = {}
			with_fixtures({},
				{
					["bridge fdb show"] = "",
					["nft list table"] = fixture("nft_list_table_openuf_learn.txt"),
				},
				function()
					-- Off by default: a board with no moved socket must never
					-- fork `nft`, so the fallback is opt-in per socket.
					assert_eq(#sysinfo.mac_table("lan2"), 0, "no tap without allow_tap")
					local hosts = sysinfo.mac_table("lan2", nil, true)
					assert_eq(#hosts, 2, "the tap's hosts for this socket")
					assert_eq(hosts[1].mac, "00:00:5e:00:53:07", "first mac")
					-- Same row shape as the FDB path: the uptime bookkeeping is
					-- shared, not reimplemented.
					assert_eq(hosts[1].age, 0, "age matches the FDB source's contract")
					assert_not_nil(hosts[1].uptime, "and uptime is filled in")
				end
			)
		end
	},
	{
		name = "sysinfo: the tap supplies an address the ARP cache cannot",
		fn = function()
			-- The whole point of the address half. An assigned socket is on a
			-- VLAN the AP holds no address on, so /proc/net/arp will never
			-- answer for a host behind it -- and without an ip the controller
			-- files that client under the untagged network.
			sysinfo._mac_first_seen = {}
			with_fixtures({},
				{
					["bridge fdb show"] = "",
					["nft list table"] = fixture("nft_list_table_openuf_learn.txt"),
				},
				function()
					local hosts = sysinfo.mac_table("lan2", nil, true)
					assert_eq(hosts[1].ip, "192.0.2.20", "address from the tap")
				end
			)
		end
	},
	{
		name = "sysinfo: the ARP cache outranks the tap where it can answer",
		fn = function()
			-- /proc/net/arp is the AP's own L3 view: where it has an entry it
			-- is the better source, and the tap is the fallback for the socket
			-- it cannot see.
			sysinfo._mac_first_seen = {}
			with_fixtures(
				{["/proc/net/arp"] =
					"IP address  HW type  Flags  HW address         Mask  Device\n"
					.. "192.0.2.77  0x1      0x2    00:00:5e:00:53:07  *     br-lan\n"},
				{
					["bridge fdb show"] = "",
					["nft list table"] = fixture("nft_list_table_openuf_learn.txt"),
				},
				function()
					local hosts = sysinfo.mac_table("lan2", nil, true)
					assert_eq(hosts[1].ip, "192.0.2.77", "the ARP answer, not the tap's")
				end
			)
		end
	},
	{
		name = "sysinfo: mac_table() prefers the FDB over the tap",
		fn = function()
			-- The tap is a fallback for a socket the kernel cannot answer for,
			-- never a second opinion about one it can. If both are populated
			-- the FDB wins, or a socket that regained learning would report
			-- whatever the tap had not expired yet.
			sysinfo._mac_first_seen = {}
			with_fixtures({},
				{
					["bridge fdb show"] = "00:00:5e:00:53:0b dev lan2 master br-lan \n",
					["nft list table"] = fixture("nft_list_table_openuf_learn.txt"),
				},
				function()
					local hosts = sysinfo.mac_table("lan2", nil, true)
					assert_eq(#hosts, 1, "the FDB's answer, not the tap's two")
					assert_eq(hosts[1].mac, "00:00:5e:00:53:0b", "from the FDB")
				end
			)
		end
	},
	{
		name = "sysinfo: mac_table() returns empty table for nil ifname",
		fn = function()
			with_fixtures({}, {}, function()
				assert_eq(#sysinfo.mac_table(nil), 0, "nil ifname safe")
			end)
		end
	},
	{
		name = "sysinfo: mac_table() age is 0 and uptime grows across calls for the same host",
		fn = function()
			sysinfo._mac_first_seen = {}
			local orig_time = sysinfo._time
			sysinfo._time = function() return 1000 end
			with_fixtures({}, {["bridge fdb show"] = fixture("bridge_fdb_dump.txt")}, function()
				local hosts = sysinfo.mac_table("eth1")
				assert_eq(hosts[1].age, 0, "age is 0 -- freshly observed on this fdb dump")
				assert_eq(hosts[1].uptime, 0, "uptime 0 on first observation")
			end)
			sysinfo._time = function() return 1100 end
			with_fixtures({}, {["bridge fdb show"] = fixture("bridge_fdb_dump.txt")}, function()
				local hosts = sysinfo.mac_table("eth1")
				assert_eq(hosts[1].uptime, 100, "uptime grows from the first-seen cache")
			end)
			sysinfo._time = orig_time
			sysinfo._mac_first_seen = {}
		end
	},
	{
		name = "sysinfo: a host not seen for an hour is forgotten, so the cache is bounded",
		fn = function()
			-- _mac_first_seen is keyed by "<source> mac" and was never emptied
			-- -- on a daemon that runs for months in a place with transient
			-- clients it only ever grew. A host back after the forget window
			-- gets a fresh uptime, which is what a real switch reports for it
			-- as well.
			sysinfo._mac_first_seen, sysinfo._mac_last_seen = {}, {}
			local orig_time = sysinfo._time

			sysinfo._time = function() return 1000 end
			assert_eq(sysinfo._note_seen("eth1 aa:bb:cc:dd:ee:01", 1000), 1000, "first sighting")
			assert_eq(sysinfo._note_seen("eth1 aa:bb:cc:dd:ee:02", 1000), 1000, "and a second host")

			-- Still inside the window: both remembered, and the first-seen
			-- stamp of the one that is still around is unchanged.
			assert_eq(sysinfo._note_seen("eth1 aa:bb:cc:dd:ee:01", 1000 + 3599), 1000,
				"a host seen again keeps its original first-seen stamp")

			-- Past it: the host that stopped being seen is dropped, and comes
			-- back as new if it ever returns.
			local later = 1000 + 3601 + 3601
			assert_eq(sysinfo._note_seen("eth1 aa:bb:cc:dd:ee:01", later), later,
				"a host back after the window is a fresh sighting")
			assert_nil(sysinfo._mac_first_seen["eth1 aa:bb:cc:dd:ee:02"],
				"and the one that never came back is gone from the cache")
			assert_nil(sysinfo._mac_last_seen["eth1 aa:bb:cc:dd:ee:02"],
				"from both halves of it")

			sysinfo._time = orig_time
			sysinfo._mac_first_seen, sysinfo._mac_last_seen = {}, {}
		end
	},
	{
		name = "sysinfo: the forget sweep runs once a minute, not once per wired host",
		fn = function()
			-- It walked every remembered host on every sighting: N hosts per
			-- heartbeat made it N*N steps. A host back after the window still
			-- starts a fresh uptime when the sweep hasn't reached it yet.
			sysinfo._mac_first_seen, sysinfo._mac_last_seen = {}, {}
			sysinfo._mac_swept_at = nil
			local A, B, C, E = "eth1 aa:bb:cc:dd:ee:01", "eth1 aa:bb:cc:dd:ee:02",
				"eth1 aa:bb:cc:dd:ee:03", "eth1 aa:bb:cc:dd:ee:05"
			sysinfo._note_seen(A, 1000)                 -- sweeps (first ever)
			sysinfo._note_seen(B, 1050)                 -- inside the minute: no sweep
			sysinfo._note_seen(E, 1055)
			sysinfo._note_seen(C, 4601)                 -- sweeps: A is 3601 s old
			assert_nil(sysinfo._mac_last_seen[A], "A forgotten by the sweep")
			sysinfo._note_seen(C, 4652)                 -- B is 3602 s old, but no sweep yet
			assert_not_nil(sysinfo._mac_last_seen[B], "B waits for the next sweep")
			assert_eq(sysinfo._note_seen(B, 4655), 4655,
				"yet B back now is a fresh sighting, not one from 1050")
			sysinfo._note_seen(C, 4661)                 -- a minute after 4601: sweeps
			assert_nil(sysinfo._mac_last_seen[E], "E (3606 s old) forgotten")
			assert_nil(sysinfo._mac_first_seen[E], "from both halves")
			assert_eq(sysinfo._note_seen(B, 4662), 4655, "B keeps its new stamp")
			-- A clock stepped back must not stall the sweep until it catches up.
			local F = "eth1 aa:bb:cc:dd:ee:06"
			sysinfo._note_seen(F, 100)
			sysinfo._note_seen(C, 3800)
			assert_nil(sysinfo._mac_last_seen[F], "swept after the clock stepped back")
			sysinfo._mac_first_seen, sysinfo._mac_last_seen = {}, {}
			sysinfo._mac_swept_at = nil
		end
	},
	{
		-- Both swconfig fixtures are verbatim captures from the two real APs
		-- (MACs anonymized): an AR9344 that exposes per-port MIB counters and
		-- an AR8327 that answers "mib: ???" because its poll interval is 0.
		name = "sysinfo: switch_status() reads per-port link, speed, duplex and pvid",
		fn = function()
			with_fixtures({}, {["swconfig"] = fixture("swconfig_show_ar9344.txt")}, function()
				local st = sysinfo.switch_status("switch0")
				assert_eq(st.ports[0].speed, 1000, "CPU port link is the internal 1000")
				-- The socket the uplink cable is in had negotiated 100baseT
				-- while the CPU netdev reported 1000 -- the whole reason this
				-- reads the switch and not sysfs.
				assert_eq(st.ports[4].speed, 100, "socket 4 negotiated 100baseT")
				assert_true(st.ports[4].up, "socket 4 has link")
				assert_true(st.ports[4].full_duplex, "socket 4 is full duplex")
				assert_eq(st.ports[4].pvid, 1, "socket 4 pvid")
				assert_true(st.ports[1].up == false, "socket 1 has no link")
				assert_true(st.ports[1].speed == nil, "a down socket has no negotiated speed")
			end)
		end
	},
	{
		name = "sysinfo: switch_status() reports a half-duplex socket as half",
		fn = function()
			-- Synthetic: neither real board had a half-duplex link to capture,
			-- and full-duplex-everywhere fixtures cannot tell a real reading
			-- from the hardcoded `true` this replaced.
			local capture = table.concat({
				"Port 0:",
				"\tpvid: 1",
				"\tlink: port:0 link:up speed:10baseT half-duplex auto",
				"",
			}, "\n")
			with_fixtures({}, {["swconfig"] = capture}, function()
				local st = sysinfo.switch_status("switch0")
				assert_eq(st.ports[0].speed, 10, "10baseT")
				assert_true(st.ports[0].full_duplex == false, "half duplex is reported as half")
			end)
		end
	},
	{
		name = "sysinfo: switch_status() takes per-port byte counters only where the driver has them",
		fn = function()
			with_fixtures({}, {["swconfig"] = fixture("swconfig_show_ar9344.txt")}, function()
				local st = sysinfo.switch_status("switch0")
				assert_eq(st.ports[3].rx_bytes, 45338209, "socket 3 RxGoodByte")
				assert_eq(st.ports[3].tx_bytes, 1183354521, "socket 3 TxByte")
			end)
			with_fixtures({}, {["swconfig"] = fixture("swconfig_show_ar8327.txt")}, function()
				local st = sysinfo.switch_status("switch0")
				assert_true(st.ports[2].rx_bytes == nil,
					"an AR8327 with mib polling off reports no counters -- not zeros")
				assert_eq(st.ports[2].speed, 1000, "link is still readable without MIB")
			end)
		end
	},
	{
		name = "sysinfo: switch_status() separates ARL entries from port sections",
		fn = function()
			-- Both start with "Port <n>:" and only the MAC tells them apart;
			-- confusing the two either loses every learned host or invents a
			-- port section per host.
			with_fixtures({}, {["swconfig"] = fixture("swconfig_show_ar8327.txt")}, function()
				local st = sysinfo.switch_status("switch0")
				assert_eq(st.arl["aa:bb:cc:dd:ee:12"], 4, "host learned on socket 4")
				assert_eq(st.arl["aa:bb:cc:dd:ee:08"], 1, "host learned on socket 1")
				local n = 0
				for _ in pairs(st.ports) do n = n + 1 end
				assert_eq(n, 7, "seven port sections, not one per ARL line")
				-- The VLAN table follows the port sections and must not be
				-- parsed as one.
				assert_true(st.ports[7] == nil, "no port section invented from the VLAN table")
			end)
		end
	},
	{
		name = "sysinfo: switch_status() is empty when there is no switch",
		fn = function()
			with_fixtures({}, {}, function()
				local st = sysinfo.switch_status("switch0")
				assert_eq(next(st.ports), nil, "no ports")
				assert_eq(next(st.arl), nil, "no ARL")
			end)
		end
	},
	{
		name = "sysinfo: uplink_phys_port() finds the socket the default gateway is on",
		fn = function()
			with_fixtures(
				{["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")},
				{
					["swconfig"] = fixture("swconfig_show_ar9344.txt"),
					["ip route"] = "default via 10.0.0.1 dev br-lan \n",
				},
				function()
					local st = sysinfo.switch_status("switch0")
					assert_eq(sysinfo.uplink_phys_port(st.arl), 4, "uplink is socket 4")
				end
			)
			-- Same network, other board, cable in a different socket: the
			-- answer has to come from the ARL, not from the modelmap.
			with_fixtures(
				{["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")},
				{
					["swconfig"] = fixture("swconfig_show_ar8327.txt"),
					["ip route"] = "default via 10.0.0.1 dev br-lan \n",
				},
				function()
					local st = sysinfo.switch_status("switch0")
					assert_eq(sysinfo.uplink_phys_port(st.arl), 2, "uplink is socket 2")
				end
			)
		end
	},
	{
		name = "sysinfo: uplink_phys_port() gives up rather than guessing",
		fn = function()
			local arl = {["aa:bb:cc:dd:ee:ff"] = 4}
			-- No default route.
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")}, {}, function()
				assert_true(sysinfo.uplink_phys_port(arl) == nil, "no default route -> nil")
			end)
			-- Default route whose gateway has not been ARP-resolved.
			with_fixtures(
				{["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")},
				{["ip route"] = "default via 10.0.0.254 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_phys_port(arl) == nil, "gateway not in arp -> nil")
				end
			)
			-- Gateway resolved but never learned by the switch.
			with_fixtures(
				{["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")},
				{["ip route"] = "default via 10.0.0.1 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_phys_port({}) == nil, "gateway not in ARL -> nil")
				end
			)
		end
	},
	{
		name = "sysinfo: bridge_fdb_ports() maps learned MACs to their DSA socket",
		fn = function()
			-- Real `bridge fdb show br br-lan` off a Xiaomi AX3000T. The
			-- entry that has to be thrown away is the port's OWN address,
			-- which arrives as a master line like any other and is separable
			-- only by the trailing "permanent" -- counting it would put the
			-- AP's own socket MAC in its own client list.
			with_fixtures({},
				{["bridge fdb show br"] = fixture("bridge_fdb_br_dsa.txt")},
				function()
					local ports = sysinfo.bridge_fdb_ports("br-lan")
					assert_eq(ports["00:00:5e:00:53:12"], "wan", "gateway is on wan")
					assert_eq(ports["00:00:5e:00:53:1c"], "wan", "a host is on wan")
					-- The board's own port MAC arrives only on "permanent"
					-- lines, so it is not a host and must not be in the map.
					assert_true(ports["00:00:5e:00:53:16"] == nil,
						"the port's own permanent address is not a learned host")
				end)
			-- No bridge, or a bridge the command knows nothing about.
			assert_eq(next(sysinfo.bridge_fdb_ports(nil)), nil, "nil bridge -> empty")
			with_fixtures({}, {}, function()
				assert_eq(next(sysinfo.bridge_fdb_ports("br-lan")), nil, "no output -> empty")
			end)
		end
	},
	{
		name = "sysinfo: uplink_bridge_port() finds the socket the gateway is behind",
		fn = function()
			local cmds = {
				["bridge fdb show br"] = fixture("bridge_fdb_br_dsa.txt"),
				["ip route"] = "default via 192.0.2.1 dev br-lan \n",
			}
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")}, cmds,
				function()
					assert_eq(sysinfo.uplink_bridge_port("br-lan"), "wan",
						"uplink socket is wan")
				end)

			-- Same board, cable moved to another socket: the answer has to
			-- follow the FDB, not a constant. (Synthetic -- only one socket
			-- was cabled on the real board at capture time.)
			local moved = "00:00:5e:00:53:12 dev lan3 master br-lan \n"
				.. "00:00:5e:00:53:1c dev lan3 master br-lan \n"
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["bridge fdb show br"] = moved,
				 ["ip route"] = "default via 192.0.2.1 dev br-lan \n"},
				function()
					assert_eq(sysinfo.uplink_bridge_port("br-lan"), "lan3",
						"uplink socket followed the cable")
				end)
		end
	},
	{
		name = "sysinfo: uplink_bridge_port() gives up rather than guessing",
		fn = function()
			local fdb = fixture("bridge_fdb_br_dsa.txt")
			-- No default route.
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["bridge fdb show br"] = fdb}, function()
					assert_true(sysinfo.uplink_bridge_port("br-lan") == nil,
						"no default route -> nil")
				end)
			-- Default route whose gateway has not been ARP-resolved yet.
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["bridge fdb show br"] = fdb,
				 ["ip route"] = "default via 192.0.2.254 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_bridge_port("br-lan") == nil,
						"gateway not in arp -> nil")
				end)
			-- Gateway resolved but the bridge has not learned it.
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["ip route"] = "default via 192.0.2.1 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_bridge_port("br-lan") == nil,
						"gateway not in the FDB -> nil")
				end)
		end
	},
	{
		name = "sysinfo: bridge_of() names the bridge a socket is enslaved to",
		fn = function()
			with_fixtures({["/sys/class/net/lan3/master/uevent"] =
				"DEVTYPE=bridge\nINTERFACE=br-lan\nIFINDEX=7\n"}, {}, function()
					assert_eq(sysinfo.bridge_of("lan3"), "br-lan", "lan3 is in br-lan")
				end)
			-- A netdev that is not a bridge port has no master/ at all.
			with_fixtures({}, {}, function()
				assert_true(sysinfo.bridge_of("eth0") == nil, "not enslaved -> nil")
			end)
			assert_true(sysinfo.bridge_of(nil) == nil, "nil ifname -> nil")
		end
	},
	{
		name = "sysinfo: switch_mac_table() returns one socket's hosts, joined with arp",
		fn = function()
			sysinfo._mac_first_seen = {}
			with_fixtures(
				{["/proc/net/arp"] = fixture("proc_net_arp_switch.txt")},
				{["swconfig"] = fixture("swconfig_show_ar9344.txt")},
				function()
					local st = sysinfo.switch_status("switch0")
					local hosts = sysinfo.switch_mac_table(3, st.arl)
					assert_eq(#hosts, 1, "one host behind socket 3")
					assert_eq(hosts[1].mac, "aa:bb:cc:dd:ee:0c", "the host's mac")
					assert_eq(hosts[1].ip, "10.0.0.50", "ip joined from arp")
					assert_eq(hosts[1].age, 0, "freshly observed")
					-- Socket 4 is the uplink: the whole LAN is learned there,
					-- which is why the caller suppresses it (pinned in
					-- test_inform_json), not this function.
					assert_eq(#sysinfo.switch_mac_table(4, st.arl), 8, "uplink socket's hosts")
					assert_eq(#sysinfo.switch_mac_table(2, st.arl), 0, "an empty socket has none")
				end
			)
			sysinfo._mac_first_seen = {}
		end
	},
	{
		name = "sysinfo: switch_mac_table() drops multicast MACs and is safe without an ARL",
		fn = function()
			sysinfo._mac_first_seen = {}
			with_fixtures({}, {}, function()
				local arl = {
					["01:00:5e:00:00:01"] = 2,   -- IPv4 multicast
					["33:33:00:00:00:01"] = 2,   -- IPv6 multicast
					["ff:ff:ff:ff:ff:ff"] = 2,   -- broadcast
					["aa:bb:cc:dd:ee:01"] = 2,
				}
				local hosts = sysinfo.switch_mac_table(2, arl)
				assert_eq(#hosts, 1, "only the unicast host survives")
				assert_eq(hosts[1].mac, "aa:bb:cc:dd:ee:01", "the host")
				assert_eq(#sysinfo.switch_mac_table(nil, arl), 0, "nil port is safe")
				assert_eq(#sysinfo.switch_mac_table(2, nil), 0, "nil ARL is safe")
			end)
			sysinfo._mac_first_seen = {}
		end
	},
	{
		name = "sysinfo: scan_table() parses iw scan dump into neighbor entries",
		fn = function()
			with_fixtures({}, {["scan dump"] = fixture("iw_scan_dump.txt")}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(#nets, 2, "two neighbor networks")
				assert_eq(nets[1].bssid, "aa:bb:cc:dd:ee:01", "first bssid")
				assert_eq(nets[1].essid, "NeighborNet", "first essid")
				assert_eq(nets[1].freq, 2437, "first freq")
				assert_eq(nets[1].channel, 6, "first channel derived from freq")
				assert_eq(nets[1].signal, -55, "first signal")
				assert_eq(nets[1].security, "wpa2", "first security from RSN IE")
				assert_eq(nets[1].age, 0, "first age from '120 ms ago', floored to 0s")
				assert_eq(nets[1].bw, 40, "first bw parsed from 'BSS operating channel width: 40 MHz'")
				assert_eq(nets[2].bssid, "11:22:33:44:55:66", "second bssid")
				assert_eq(nets[2].essid, "OpenGuestWifi", "second essid")
				assert_eq(nets[2].channel, 11, "second channel derived from freq")
				assert_eq(nets[2].security, "open", "second security -- no Privacy, no RSN/WPA")
				assert_eq(nets[2].age, 0, "second age from '340 ms ago', floored to 0s")
				assert_eq(nets[2].bw, 20, "second bw defaults to 20 -- no width line for this BSS")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() tags a sibling openUF AP from the nl80211 reader",
		fn = function()
			-- OpenWrt's iw build never prints our vendor element (checked live
			-- on both boards), so the tag comes from peer_macs' ucode/nl80211
			-- read, joined on the BSSID.
			with_fixtures({}, {
				["scan dump"] = fixture("iw_scan_dump.txt"),
				["ucode -e"]  = "AA:BB:CC:DD:EE:01 00:00:5E:00:53:20\n",
			}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(nets[1].peer_mac, "00:00:5e:00:53:20", "the sibling's identity MAC, case-folded")
				assert_eq(nets[2].peer_mac, nil, "a BSS the reader did not name is not a sibling")
				assert_eq(nets[1].essid, "NeighborNet", "the iw-parsed fields are untouched")
			end)
			with_fixtures({}, {["scan dump"] = fixture("iw_scan_dump.txt")}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(#nets, 2, "no ucode on the box: the scan still reports")
				assert_eq(nets[1].peer_mac, nil, "...with no siblings")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() reads sibling tags once per BSSID, not per heartbeat",
		fn = function()
			-- The ucode reader is a fork per radio per heartbeat, for an
			-- answer that only changes when a BSS does: it runs only when the
			-- scan holds a BSSID without a live cached answer.
			local files = {["/proc/uptime"] = "1000.00 0\n"}
			local scan = fixture("iw_scan_dump.txt")
			local reads, reply = 0, "AA:BB:CC:DD:EE:01 00:00:5E:00:53:20\n"
				.. sysinfo.PEER_SCAN_DONE .. "\n"
			local cmds = {["scan dump"] = scan}
			with_fixtures(files, cmds, function()
				local orig = sysinfo._run_cmd
				sysinfo._run_cmd = function(cmd)
					if cmd:find("ucode -e", 1, true) then reads = reads + 1 return reply end
					return orig(cmd)
				end
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 1, "first heartbeat reads")
				assert_eq(nets[1].peer_mac, "00:00:5e:00:53:20", "sibling tagged")
				assert_eq(nets[2].peer_mac, nil, "stranger untagged")
				nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 1, "same BSSIDs: no second read")
				assert_eq(nets[1].peer_mac, "00:00:5e:00:53:20", "sibling still tagged from the cache")
				assert_eq(nets[2].peer_mac, nil, "stranger still untagged from the cache")
				sysinfo.scan_table("wlan1")
				assert_eq(reads, 2, "another radio has its own cache")

				cmds["scan dump"] = scan .. "BSS 00:00:5e:00:53:31(on wlan0)\n\tfreq: 2412\n"
				nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 3, "a new BSSID reads once")
				assert_eq(#nets, 3, "and is reported")
				sysinfo.scan_table("wlan0")
				assert_eq(reads, 3, "then is cached too")

				files["/proc/uptime"] = "1599.00 0\n"
				sysinfo.scan_table("wlan0")
				assert_eq(reads, 3, "a stranger is kept for ten minutes")
				files["/proc/uptime"] = "1600.00 0\n"
				sysinfo.scan_table("wlan0")
				assert_eq(reads, 4, "and read again after them")

				-- Down to the sibling alone: the strangers have expired by
				-- now, the sibling's tag holds for its hour from the last read.
				cmds["scan dump"] = scan:match("^(.-)\nBSS ") .. "\n"
				reply = "garbage"
				files["/proc/uptime"] = "5199.00 0\n"
				nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 4, "a sibling is kept for an hour")
				assert_eq(nets[1].peer_mac, "00:00:5e:00:53:20", "with its tag")
				files["/proc/uptime"] = "5200.00 0\n"
				nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 5, "and read again after it")
				assert_eq(nets[1].peer_mac, nil, "a reader that did not finish names no sibling")
				sysinfo.scan_table("wlan0")
				assert_eq(reads, 6, "...and records no stranger, so the next heartbeat reads again")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() without a clock reads sibling tags every time",
		fn = function()
			local reads = 0
			with_fixtures({}, {["scan dump"] = fixture("iw_scan_dump.txt")}, function()
				local orig = sysinfo._run_cmd
				sysinfo._run_cmd = function(cmd)
					if cmd:find("ucode -e", 1, true) then
						reads = reads + 1
						return "AA:BB:CC:DD:EE:01 00:00:5E:00:53:20\n" .. sysinfo.PEER_SCAN_DONE .. "\n"
					end
					return orig(cmd)
				end
				local nets = sysinfo.scan_table("wlan0")
				nets = sysinfo.scan_table("wlan0")
				assert_eq(reads, 2, "no /proc/uptime: no ageing, so no cache")
				assert_eq(nets[1].peer_mac, "00:00:5e:00:53:20", "still tagged")
			end)
		end
	},
	{
		name = "sysinfo: peer_scan_cmd() matches exactly the element peer_ie_hex() builds",
		fn = function()
			local hex = sysinfo.peer_ie_hex("00:00:5E:00:53:20")
			assert_eq(hex, "dd0d026f556f55460100005e005320", "hostapd vendor_elements value")
			-- The reader compares the element body's first 7 bytes (OUI,
			-- magic, version) and takes the 6 after them. Pin that prefix to
			-- the builder's, byte for byte, so the two cannot drift.
			local cmd = sysinfo.peer_scan_cmd("phy0-ap0")
			local want = hex:sub(5, 18):gsub("(%x%x)", "\\x%1")
			assert_true(cmd:find('"' .. want .. '"', 1, true) ~= nil, "prefix matches the builder")
			assert_true(cmd:find("n==13&&substr(d,0,7)==", 1, true) ~= nil, "body length is 0x0d")
			assert_true(cmd:find('dev:"phy0-ap0"', 1, true) ~= nil, "asks about the right interface")
			local tail = 'if(r!=null)print("' .. sysinfo.PEER_SCAN_DONE .. '\\n");\' 2>/dev/null'
			assert_eq(cmd:sub(-#tail), tail, "the done line is printed last, after the walk, and only for a dump that answered")
			assert_eq(sysinfo.peer_scan_cmd("x'; reboot; '"), nil, "an interface name cannot break out of the quoting")
			assert_eq(sysinfo.peer_ie_hex(nil), nil, "no identity, no IE")
			assert_eq(sysinfo.peer_ie_hex("not-a-mac"), nil, "garbage, no IE")
		end
	},
	{
		name = "sysinfo: peer_scan_cmd() also recognises a real UniFi AP's element",
		fn = function()
			-- The matcher is ucode and only runs on a device or in an OpenWrt
			-- image (tools/peer-ie-vectors.lua executes it against vectors).
			-- Here: pin the firmware layout it must encode, and that the scan
			-- command really uses it.
			local pm = sysinfo.peer_match_ucode()
			assert_true(pm:find("ord(d,0)!=0||ord(d,1)!=0x15||ord(d,2)!=0x6d", 1, true) ~= nil,
				"Ubiquiti OUI 00:15:6d")
			assert_true(pm:find("||ord(d,3)!=0||ord(d,4)!=1||ord(d,5)!=1)", 1, true) ~= nil,
				"subtype 00 01 01 (a UniFi AP), not other Ubiquiti products")
			assert_true(pm:find("for(let i=11;i+2<=n;i+=2+ord(d,i+1))", 1, true) ~= nil,
				"TLVs walked from body offset 11 by their own lengths")
			assert_true(pm:find("ord(d,i)==0x81&&ord(d,i+1)==6&&i+8<=n", 1, true) ~= nil,
				"serial TLV 0x81, 6 bytes, bounds-checked")
			local cmd = sysinfo.peer_scan_cmd("phy0-ap0")
			assert_true(cmd:find(pm, 1, true) ~= nil, "the scan command embeds the matcher")
			assert_true(cmd:find("hit=pm(e.data)", 1, true) ~= nil, "and calls it on every vendor element")
			local inner = cmd:match("^ucode %-e '(.*)' 2>/dev/null$")
			assert_true(inner ~= nil and not inner:find("'", 1, true),
				"no single quote inside the shell-quoted script")
		end
	},
	{
		name = "sysinfo: scan_table() derives width from the operation elements on iw 6.17",
		fn = function()
			-- The fixture is trimmed from real `iw dev ... scan` output taken
			-- off our own AX3000T and Archer C5 (2026-09-09, MACs and SSIDs
			-- anonymized). Both boards run iw 6.17, which prints NO
			-- "BSS operating channel width:" summary line at all -- so every
			-- neighbour went out at the 20 MHz default, including two real
			-- 80 MHz APs next door.
			with_fixtures({["/proc/uptime"] = "662790.00 1000000.00\n"},
				{["scan dump"] = fixture("iw_scan_dump_iw617.txt")}, function()
				local nets = {}
				for _, n in ipairs(sysinfo.scan_table("wlan0")) do nets[n.essid] = n end

				assert_eq(nets["NeighborNet"].bw, 80,
					"VHT width field 1 with segment 2 zero is 80 MHz")
				-- The trap this is anchored against: two lines below the VHT
				-- element sits the HT capability line "* STA channel width:
				-- 20 MHz". An unanchored pattern reads that 20 as a VHT width
				-- field -- which is >= 1, so the BSS comes out as 80 MHz.
				assert_eq(nets["LegacyNet"].bw, 20,
					"VHT width field 0 with no secondary channel is 20 MHz")
				assert_eq(nets["WideLegacy"].bw, 40,
					"no VHT element at all, but a secondary channel offset, is HT40")
				assert_eq(nets["WideNet"].bw, 160,
					"segments 8 channels apart is the modern 160 MHz encoding")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() reads the [boottime] form of 'last seen'",
		fn = function()
			-- Newer iw prints the driver's CLOCK_BOOTTIME stamp, and some
			-- entries carry ONLY that form -- seen on our own AX3000T. The
			-- "ms ago" pattern never matched those, so their age stayed at the
			-- 0 default and every stale neighbour was reported as seen this
			-- instant. The controller drops anything with age >= 30 as stale,
			-- so a wrong 0 keeps a long-gone AP in the Environment view.
			with_fixtures({["/proc/uptime"] = "662790.00 1000000.00\n"},
				{["scan dump"] = fixture("iw_scan_dump_iw617.txt")}, function()
				local nets = {}
				for _, n in ipairs(sysinfo.scan_table("wlan0")) do nets[n.essid] = n end
				-- Only the boottime line: 662790.00 - 662754.792 = 35s.
				assert_eq(nets["LegacyNet"].age, 35, "age comes from the boottime stamp")
				-- Both printed: "ms ago" wins, being what the controller's own
				-- staleness rule is written against.
				assert_eq(nets["NeighborNet"].age, 3, "'3290 ms ago' beats the boottime stamp")
				assert_eq(nets["WideNet"].age, 0, "'140 ms ago' floors to 0")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() decodes iw's \\xNN SSID escapes",
		fn = function()
			-- iw escapes every byte that is not printable ASCII. A hotspot
			-- with an accented name reached the Environment tab as literal
			-- escapes (seen live 2026-09-27), e.g. "Caf\xc3\xa9 Guest".
			local function bss(n, ssid)
				return "BSS 00:00:5e:00:53:0" .. n .. "(on wlan0)\n" ..
					"\tfreq: 2437\n\tsignal: -60.00 dBm\n" ..
					"\tlast seen: 100 ms ago\n\tSSID: " .. ssid .. "\n"
			end
			local dump = bss(1, "Caf\\xc3\\xa9 Guest") ..
				bss(2, "a\\x5cb") ..
				bss(3, "\\x20Net") ..
				bss(4, "\\x00\\x00\\x00") ..
				bss(5, "")
			with_fixtures({}, {["scan dump"] = dump}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(#nets, 5, "all five BSSes parsed")
				assert_eq(nets[1].essid,
					"Caf" .. string.char(0xc3, 0xa9) .. " Guest",
					"UTF-8 bytes decoded")
				assert_eq(nets[2].essid, "a\\b", "escaped backslash decodes to one backslash")
				assert_eq(nets[3].essid, " Net", "escaped leading space kept")
				assert_eq(nets[4].essid, nil, "NUL-filled hidden SSID has no essid")
				assert_eq(nets[5].essid, nil, "empty hidden SSID has no essid")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() reads each field from its own line, never from an SSID",
		fn = function()
			-- iw prints ':' and the rest of printable ASCII in an SSID as is.
			-- The parser used to try every pattern on every line, so a
			-- neighbour's name could set its own frequency, age, width and
			-- security, since the SSID line comes after those.
			local ssid = "x freq: 2412 last seen: 99000 ms ago capability: Privacy" ..
				" secondary channel offset: above"
			local dump = "BSS 00:00:5e:00:53:01(on wlan0)\n" ..
				"\tlast seen: 120 ms ago\n\tfreq: 5180\n" ..
				"\tcapability: ESS ShortSlotTime (0x0401)\n\tsignal: -60.00 dBm\n" ..
				"\tSSID: " .. ssid .. "\n" ..
				"\tHT operation:\n\t\t * secondary channel offset: no secondary\n"
			with_fixtures({}, {["scan dump"] = dump}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(#nets, 1, "one BSS")
				assert_eq(nets[1].essid, ssid, "the whole name is the essid")
				assert_eq(nets[1].freq, 5180, "freq from the freq line")
				assert_eq(nets[1].channel, 36, "channel from that freq")
				assert_eq(nets[1].age, 0, "age from the last seen line")
				assert_eq(nets[1].security, "open", "no Privacy in the capability line")
				assert_eq(nets[1].bw, 20, "no secondary channel")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() classifies Privacy-only (no RSN/WPA IE) as wep",
		fn = function()
			local dump = "BSS cc:cc:cc:cc:cc:cc(on wlan0)\n"
				.. "\tfreq: 2412\n"
				.. "\tcapability: ESS Privacy (0x0011)\n"
				.. "\tsignal: -60.00 dBm\n"
				.. "\tSSID: OldNetwork\n"
			with_fixtures({}, {["scan dump"] = dump}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(nets[1].security, "wep", "Privacy bit with no RSN/WPA IE classified as wep")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() converts 'last seen: N ms ago' to whole seconds",
		fn = function()
			local dump = "BSS dd:dd:dd:dd:dd:dd(on wlan0)\n"
				.. "\tfreq: 2412\n"
				.. "\tsignal: -60.00 dBm\n"
				.. "\tlast seen: 45231 ms ago\n"
				.. "\tSSID: StaleNetwork\n"
			with_fixtures({}, {["scan dump"] = dump}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(nets[1].age, 45, "45231ms floors to 45s")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() defaults age to 0 without a 'last seen' line",
		fn = function()
			local dump = "BSS ee:ee:ee:ee:ee:ee(on wlan0)\n"
				.. "\tfreq: 2412\n"
				.. "\tsignal: -60.00 dBm\n"
				.. "\tSSID: NoLastSeen\n"
			with_fixtures({}, {["scan dump"] = dump}, function()
				local nets = sysinfo.scan_table("wlan0")
				assert_eq(nets[1].age, 0, "age defaults to 0 when 'last seen' is absent")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() returns empty table for empty output",
		fn = function()
			with_fixtures({}, {["scan dump"] = ""}, function()
				assert_eq(#sysinfo.scan_table("wlan0"), 0, "empty result")
			end)
		end
	},
	{
		name = "sysinfo: scan_table() returns empty table for nil ifname",
		fn = function()
			with_fixtures({}, {}, function()
				assert_eq(#sysinfo.scan_table(nil), 0, "nil ifname safe")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() parses a 2.4GHz (HE-only, no VHT/DFS) phy correctly",
		fn = function()
			with_fixtures({}, {
				["dev wlan0 info"] = fixture("iw_dev_info.txt"),
				["phy phy0 info"]  = fixture("iw_phy_info_2g.txt"),
			}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_false(caps.is_11ac, "2.4GHz has no VHT Capabilities section")
				assert_true(caps.is_11ax, "HE PHY Capabilities present")
				assert_false(caps.is_11be, "no EHT PHY Capabilities")
				assert_false(caps.has_dfs, "no radar detection on 2.4GHz")
				assert_false(caps.has_fccdfs, "has_fccdfs mirrors has_dfs")
				assert_false(caps.has_ht160, "no 160 MHz support (no VHT at all on 2.4GHz)")
				assert_eq(caps.nss, 2, "nss from 'HT TX Max spatial streams: 2'")
				assert_eq(caps.channel, 6, "live channel from 'channel 6 (2437 MHz)...'")
				assert_eq(caps.extchannel, 0, "20 MHz: no secondary channel")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() derives nss from the HT MCS range on an HT-only radio",
		fn = function()
			-- Real ath9k output: no "HT TX Max spatial streams" summary line,
			-- and no VHT/HE MCS-set tables to count "N streams: MCS" lines in
			-- -- an HT-only radio has neither of the two sources radio_caps
			-- used, so every 2.4GHz-only radio fell through to the 1x1
			-- default. A real controller showed this board's 3-stream ath9k
			-- radio as "1x1 WiFi 4".
			local ht_only = table.concat({
				"Wiphy phy1",
				"\tBand 1:",
				"\t\tCapabilities: 0x11ef",
				"\t\t\tHT20/HT40",
				"\t\tHT TX/RX MCS rate indexes supported: 0-23",
				"\t\tFrequencies:",
				"\t\t\t* 2412.0 MHz [1] (20.0 dBm)",
			}, "\n")
			with_fixtures({}, {
				["dev wlan0 info"] = "Interface wlan0\n\twiphy 1\n\tchannel 6 (2437 MHz)\n",
				["phy phy1 info"]  = ht_only,
			}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_eq(caps.nss, 3, "MCS 0-23 is three spatial streams, not one")
				assert_false(caps.is_11ac, "and it is still correctly HT-only")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() prefers the explicit spatial-streams line over the MCS range",
		fn = function()
			-- Where both exist they must agree; the summary line stays
			-- authoritative. ("0-15, 32" -> floor(15/8)+1 = 2, same answer.)
			with_fixtures({}, {
				["dev wlan0 info"] = fixture("iw_dev_info.txt"),
				["phy phy0 info"]  = fixture("iw_phy_info_2g.txt"),
			}, function()
				assert_eq(sysinfo.radio_caps("wlan0").nss, 2, "explicit line wins, and agrees")
			end)
		end
	},
	{
		name = "sysinfo: sta_table() signal is the client's RSSI, not the ack signal",
		fn = function()
			-- `iw` prints "avg ack signal:\t-95 dBm" further down the same
			-- station block, and an unanchored "signal:%s+" pattern matches it
			-- too -- being later in the block, it overwrote the real reading,
			-- so every client on every radio was reported at the ack value
			-- regardless of its actual RSSI. That value feeds the Clients
			-- list, avg_client_signal, the satisfaction estimate, and Minimum
			-- RSSI enforcement, which would have deauthed every client on the
			-- radio the moment the feature was enabled.
			with_fixtures({}, {["station dump"] = fixture("iw_station_dump.txt")}, function()
				local stas = sysinfo.sta_table("wlan0")
				assert_eq(stas[1].signal, -62, "combined RSSI, not the -95 ack signal")
				assert_eq(stas[2].signal, -75, "and for the second client too")
				for _, s in ipairs(stas) do
					assert_neq(s.signal, -95, "no client picks up the ack-signal value")
				end
			end)
		end
	},
	{
		name = "sysinfo: sae_supported() detects SAE from the wifi config generator",
		fn = function()
			-- This decides whether openUF claims WPA3 to the controller, and
			-- the controller pushes SAE on the strength of it -- so a build
			-- whose hostapd cannot do SAE must answer false, or the radio gets
			-- a config it cannot run.
			local orig = sysinfo._read_file
			sysinfo._sae_supported_cache = nil
			sysinfo._read_file = function(path)
				if path == "/usr/share/ucode/wifi/ap.uc" then
					return "if (config.auth_type in [ 'psk-sae', 'eap-eap2' ])\n"
				end
				return nil
			end
			assert_true(sysinfo.sae_supported(), "ucode generator naming psk-sae -> supported")

			sysinfo._sae_supported_cache = nil
			sysinfo._read_file = function(path)
				if path == "/lib/netifd/hostapd.sh" then return "sae_password\n" end
				return nil
			end
			assert_true(sysinfo.sae_supported(), "legacy hostapd.sh mentioning sae -> supported")

			sysinfo._sae_supported_cache = nil
			sysinfo._read_file = function() return nil end
			assert_false(sysinfo.sae_supported(), "neither readable -> not claimed")

			sysinfo._read_file = orig
			sysinfo._sae_supported_cache = nil
		end
	},
	{
		name = "sysinfo: ppsk_supported() needs both the station generator and hostapd's VLAN support",
		fn = function()
			-- Claimed as wifi_caps 0x100000: the controller then pushes WLANs
			-- whose keys each carry a VLAN. A generator without vlanid= or a
			-- hostapd without VLAN support would put every client on the
			-- VAP's own network.
			local orig_r, orig_c = sysinfo._read_file, sysinfo._run_cmd
			local cmds
			local function probe(gen, hostapd_yes)
				sysinfo._ppsk_supported_cache = nil
				cmds = {}
				sysinfo._read_file = function(path)
					if path == "/usr/share/ucode/wifi/ap.uc" then return gen end
					return nil
				end
				sysinfo._run_cmd = function(cmd)
					cmds[#cmds + 1] = cmd
					return hostapd_yes and "yes\n" or ""
				end
				return sysinfo.ppsk_supported()
			end
			local ok, err = pcall(function()
				-- OpenWrt 25.12's ap.uc, iface_wpa_stations.
				local gen = "station = `vlanid=${sta.config.vid} ` + station;"
				assert_true(probe(gen, true), "generator + VLAN-capable hostapd -> supported")
				assert_true(cmds[1]:find("from wpa_psk_file", 1, true) ~= nil,
					"asks the hostapd binary itself")
				assert_false(probe(gen, false), "hostapd without VLAN support -> not claimed")
				assert_false(probe(nil, true), "no ucode generator -> not claimed")
				assert_eq(#cmds, 0, "and hostapd is not even searched")
				assert_false(probe("let x = 'psk-sae';", true),
					"a generator without per-station VLANs -> not claimed")
				sysinfo._read_file = function() error("probed twice") end
				assert_false(sysinfo.ppsk_supported(), "cached")
			end)
			sysinfo._read_file, sysinfo._run_cmd = orig_r, orig_c
			sysinfo._ppsk_supported_cache = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "sysinfo: eap_supported() needs both the server options and hostapd's RADIUS client",
		fn = function()
			-- Deliberately NOT a capability bit and not a provisioning gate:
			-- the controller puts no gate on a WPA2-Enterprise WLAN, so one
			-- arrives either way. This only decides whether openUF warns that
			-- the BSS will authenticate nobody.
			local orig_r, orig_c = sysinfo._read_file, sysinfo._run_cmd
			local cmds
			local function probe(gen, hostapd_yes)
				sysinfo._eap_supported_cache = nil
				cmds = {}
				sysinfo._read_file = function(path)
					if path == "/usr/share/ucode/wifi/ap.uc" then return gen end
					return nil
				end
				sysinfo._run_cmd = function(cmd)
					cmds[#cmds + 1] = cmd
					return hostapd_yes and "yes\n" or ""
				end
				return sysinfo.eap_supported()
			end
			local ok, err = pcall(function()
				-- 25.12's ap.uc, iface_authentication_server().
				local gen = "append('auth_server_addr', server);"
				assert_true(probe(gen, true), "generator + RADIUS-capable hostapd")
				assert_true(cmds[1]:find("auth_server_addr", 1, true) ~= nil,
					"asks the hostapd binary itself")
				assert_false(probe(gen, false), "a basic wpad -> not supported")
				assert_false(probe(nil, true), "no ucode generator -> not supported")
				assert_eq(#cmds, 0, "and hostapd is not even searched")
				assert_false(probe("let x = 'psk-sae';", true),
					"a generator without the server options -> not supported")
				sysinfo._read_file = function() error("probed twice") end
				assert_false(sysinfo.eap_supported(), "cached")
			end)
			sysinfo._read_file, sysinfo._run_cmd = orig_r, orig_c
			sysinfo._eap_supported_cache = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "sysinfo: hs20_supported() needs both the interworking options and a CONFIG_HS20 hostapd",
		fn = function()
			-- This one IS a capability bit (fw_caps 0x800000, and fw2_caps
			-- 0x80000 with it): the controller drops a Passpoint WLAN outright
			-- without it, so it must be claimed only where hostapd can really
			-- answer ANQP.
			local orig_r, orig_c = sysinfo._read_file, sysinfo._run_cmd
			local cmds
			local function probe(gen, hostapd_yes)
				sysinfo._hs20_supported_cache = nil
				cmds = {}
				sysinfo._read_file = function(path)
					if path == "/usr/share/ucode/wifi/ap.uc" then return gen end
					return nil
				end
				sysinfo._run_cmd = function(cmd)
					cmds[#cmds + 1] = cmd
					return hostapd_yes and "yes\n" or ""
				end
				return sysinfo.hs20_supported()
			end
			local ok, err = pcall(function()
				-- 25.12's ap.uc, iface_interworking().
				local gen = "if (!config.iw_enabled)\n\t\treturn;"
				assert_true(probe(gen, true), "generator + HS 2.0 hostapd")
				assert_true(cmds[1]:find("hs20_conn_capab", 1, true) ~= nil,
					"asks the hostapd binary itself")
				assert_false(probe(gen, false),
					"a hostapd built without CONFIG_HS20 -> not supported")
				assert_false(probe(nil, true), "no ucode generator -> not supported")
				assert_eq(#cmds, 0, "and hostapd is not even searched")
				assert_false(probe("append('auth_server_addr', server);", true),
					"a generator without the interworking options -> not supported")
				sysinfo._read_file = function() error("probed twice") end
				assert_false(sysinfo.hs20_supported(), "cached")
			end)
			sysinfo._read_file, sysinfo._run_cmd = orig_r, orig_c
			sysinfo._hs20_supported_cache = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "sysinfo: owe_supported() needs both hostapd's OWE build and the ucode generator",
		fn = function()
			-- Claimed as radio_caps2 0x8: the controller then pushes Enhanced
			-- Open WLANs, and a transition one as a pair openUF writes as one
			-- owe_transition section. Both halves must be there.
			local orig_r, orig_c = sysinfo._read_file, sysinfo._run_cmd
			local cmds
			local function probe(gen, hostapd_yes)
				sysinfo._owe_supported_cache = nil
				cmds = {}
				sysinfo._read_file = function(path)
					if path == "/usr/share/ucode/wifi/hostapd.uc" then return gen end
					return nil
				end
				sysinfo._run_cmd = function(cmd)
					cmds[#cmds + 1] = cmd
					return hostapd_yes and "yes\n" or ""
				end
				return sysinfo.owe_supported()
			end
			local ok, err = pcall(function()
				local gen = "let owe = interface.config.encryption == 'owe' && interface.config.owe_transition;"
				assert_true(probe(gen, true), "generator + hostapd -vowe -> supported")
				assert_true(cmds[1]:find("hostapd -vowe", 1, true) ~= nil, "asks hostapd itself")
				assert_false(probe(gen, false), "hostapd built without OWE -> not claimed")
				assert_false(probe(nil, true), "no ucode generator -> not claimed")
				assert_eq(#cmds, 0, "and hostapd is not even asked")
				assert_false(probe("hostapd_set_bss_options", true),
					"a generator without owe_transition cannot write transition mode")
			end)
			sysinfo._read_file, sysinfo._run_cmd = orig_r, orig_c
			sysinfo._owe_supported_cache = nil
			if not ok then error(err, 0) end
		end
	},
	{
		name = "sysinfo: sae_supported() caches its answer",
		fn = function()
			local orig, reads = sysinfo._read_file, 0
			sysinfo._sae_supported_cache = nil
			sysinfo._read_file = function(path)
				reads = reads + 1
				if path == "/usr/share/ucode/wifi/ap.uc" then return "psk-sae" end
				return nil
			end
			sysinfo.sae_supported(); sysinfo.sae_supported(); sysinfo.sae_supported()
			sysinfo._read_file = orig
			sysinfo._sae_supported_cache = nil
			assert_eq(reads, 1, "probed once, not on every inform")
		end
	},
	{
		name = "sysinfo: inside a pass every radio's caps come off one `iw dev`, unchanged",
		fn = function()
			-- radio_caps forked `iw dev <if> info` once per radio per
			-- heartbeat; `iw dev` lists them all. Captured on both boards
			-- (ath79: one 5 GHz and two 2.4 GHz VAPs; filogic: the reverse).
			local function flat(t)
				local keys = {}
				for k in pairs(t) do keys[#keys + 1] = k end
				table.sort(keys)
				for i, k in ipairs(keys) do keys[i] = k .. "=" .. tostring(t[k]) end
				return table.concat(keys, " ")
			end
			for _, board in ipairs({"ath79", "filogic"}) do
				local info, order = {}, {}
				-- No "\0" in a pattern: 5.1 rejects it. Only the headers carry "#".
				local text = fixture("iw_dev_info_" .. board .. ".txt")
				for name, body in text:gmatch("## (%S+)\n([^#]*)") do
					info[name] = body:gsub("\n$", "")
					order[#order + 1] = name
				end
				assert_eq(#order, 3, board .. ": three interfaces in the capture")
				local dump = fixture("iw_dev_" .. board .. ".txt")
				with_fixtures({}, {}, function()
					local runs = {}
					sysinfo._run_cmd = function(cmd)
						runs[#runs + 1] = cmd
						if cmd == "iw dev" then return dump end
						local i = cmd:match("^iw dev (%S+) info$")
						if i then return info[i] or "" end
						local p = cmd:match("^iw phy phy(%d+) info$")
						if p then return fixture(p == "0" and "iw_phy_info_5g.txt" or "iw_phy_info_2g.txt") end
						return ""
					end
					local want = {}
					for _, i in ipairs(order) do want[i] = flat(sysinfo.radio_caps(i)) end
					runs = {}
					sysinfo.begin_pass()
					for _, i in ipairs(order) do
						assert_eq(flat(sysinfo.radio_caps(i)), want[i],
							board .. " " .. i .. ": the same caps as its own `info`")
					end
					sysinfo.end_pass()
					local n_dump, n_info = 0, 0
					for _, c in ipairs(runs) do
						if c == "iw dev" then n_dump = n_dump + 1 end
						if c:match(" info$") and c:match("^iw dev") then n_info = n_info + 1 end
					end
					assert_eq(n_dump, 1, board .. ": one `iw dev` for the pass")
					assert_eq(n_info, 0, board .. ": and no per-interface `info`")
				end)
			end
		end
	},
	{
		name = "sysinfo: the `iw dev` dump skips unnamed entries and falls back for unlisted interfaces",
		fn = function()
			with_fixtures({}, {}, function()
				local runs = {}
				sysinfo._run_cmd = function(cmd)
					runs[#runs + 1] = cmd
					if cmd == "iw dev" then
						-- A P2P device lists after the VAP with its own
						-- channel; read as part of wlan0 it would have given
						-- a down VAP that channel.
						return "phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\ttype AP\n"
							.. "\tUnnamed/non-netdev interface\n\t\twdev 0x2\n\t\ttype P2P-device\n"
							.. "\t\tchannel 11 (2462 MHz), width: 20 MHz, center1: 2462 MHz\n"
					end
					if cmd == "iw dev wlan9 info" then
						return "Interface wlan9\n\twiphy 0\n\tchannel 6 (2437 MHz)\n"
					end
					if cmd == "iw phy phy0 info" then return fixture("iw_phy_info_2g.txt") end
					return ""
				end
				sysinfo.begin_pass()
				local caps = sysinfo.radio_caps("wlan0")
				assert_eq(caps.nss, 2, "wlan0 resolved to phy0 off the dump")
				assert_nil(caps.channel, "and the P2P device's channel is not wlan0's")
				assert_eq(sysinfo.radio_caps("wlan9").channel, 6,
					"an interface the dump lacks is asked for on its own")
				sysinfo.end_pass()
				local dumps = 0
				for _, c in ipairs(runs) do if c == "iw dev" then dumps = dumps + 1 end end
				assert_eq(dumps, 1, "the dump still runs once")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() reports the live TX power as whole dBm",
		fn = function()
			-- Same rationale as the live channel: with the controller's
			-- Transmit Power set to Auto, UCI carries no `txpower` option at
			-- all, so the payload's tx_power was nil and the Radios view
			-- reported every radio as transmitting at 0 dBm while the
			-- hardware was really at 23 dBm (5GHz) / 17 dBm (2.4GHz).
			with_fixtures({}, {
				["dev wlan0 info"] = fixture("iw_dev_info.txt"),
				["phy phy0 info"]  = fixture("iw_phy_info_2g.txt"),
			}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_eq(caps.tx_power, 20, "live txpower from 'txpower 20.00 dBm'")
				assert_eq(tostring(caps.tx_power), "20", "whole dBm, not the 20.0 iw prints")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() omits tx_power when iw reports none",
		fn = function()
			-- nil (not 0) so build_json's merge leaves whatever UCI had:
			-- pairs() skips absent keys, so a configured fixed power survives
			-- when the driver can't be asked.
			with_fixtures({}, {
				["dev wlan0 info"] = "Interface wlan0\n\twiphy 0\n\tchannel 6 (2437 MHz)\n",
				["phy phy0 info"]  = fixture("iw_phy_info_2g.txt"),
			}, function()
				assert_nil(sysinfo.radio_caps("wlan0").tx_power, "no txpower line -> nil")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() parses a 5GHz (VHT+HE, DFS, 160MHz) phy correctly",
		fn = function()
			with_fixtures({}, {
				["dev wlan0 info"] = fixture("iw_dev_info.txt"):gsub("wiphy 0", "wiphy 1"),
				["phy phy1 info"]  = fixture("iw_phy_info_5g.txt"),
			}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_true(caps.is_11ac, "VHT Capabilities present")
				assert_true(caps.is_11ax, "HE PHY Capabilities present")
				assert_false(caps.is_11be, "no EHT PHY Capabilities")
				assert_true(caps.has_dfs, "radar detection present on several 5GHz channels")
				assert_true(caps.has_fccdfs, "has_fccdfs mirrors has_dfs")
				assert_true(caps.has_ht160, "'Supported Channel Width: 160 MHz, 80+80 MHz'")
				assert_eq(caps.nss, 2, "nss from 'HT TX Max spatial streams: 2'")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() falls back to counting VHT MCS stream lines when the spatial-streams summary line is absent",
		fn = function()
			local phy_info = fixture("iw_phy_info_5g.txt"):gsub("HT TX Max spatial streams: 2\n", "")
			with_fixtures({}, {
				["dev wlan0 info"] = fixture("iw_dev_info.txt"),
				["phy phy0 info"]  = phy_info,
			}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_eq(caps.nss, 2, "max of the 'N streams: MCS ...' lines (1 and 2 both supported)")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() returns empty table for nil ifname",
		fn = function()
			with_fixtures({}, {}, function()
				local caps = sysinfo.radio_caps(nil)
				assert_eq(next(caps), nil, "empty table for nil ifname")
			end)
		end
	},
	{
		name = "sysinfo: radio_caps() returns empty table when the wiphy can't be resolved",
		fn = function()
			with_fixtures({}, {["dev wlan0 info"] = "Interface wlan0\n\ttype AP\n"}, function()
				local caps = sysinfo.radio_caps("wlan0")
				assert_eq(next(caps), nil, "empty table -- no 'wiphy N' line to resolve")
			end)
		end
	},
	{
		name = "sysinfo: `iw phy` is cached per phy, `iw dev` is not",
		fn = function()
			-- `iw phy phyN info` is tens of kilobytes and was fetched and
			-- parsed for every radio on every 10-second heartbeat, though it
			-- describes the hardware plus the regulatory domain and changes
			-- only with the latter. `iw dev <if> info` stays uncached: it
			-- carries the LIVE channel and TX power, which is the point of
			-- reading it every time.
			local orig_cmd, orig_time = sysinfo._run_cmd, sysinfo._time
			local phy_reads, dev_reads, clock = 0, 0, 1000
			sysinfo._time = function() return clock end
			sysinfo._phy_info_cache = {}
			sysinfo._run_cmd = function(cmd)
				if cmd:find("iw phy") then
					phy_reads = phy_reads + 1
					return "\tBand 2:\n\t\tVHT Capabilities (0x00000000):\n"
				end
				dev_reads = dev_reads + 1
				return "\twiphy 0\n\tchannel 36 (5180 MHz)\n\ttxpower 23.00 dBm\n"
			end

			sysinfo.radio_caps("wlan0")
			sysinfo.radio_caps("wlan0")
			sysinfo.radio_caps("wlan0")
			assert_eq(phy_reads, 1, "the hardware description is read once")
			assert_eq(dev_reads, 3, "the live channel and TX power are read every time")

			-- Past the TTL, so a regdomain change is picked up within minutes.
			clock = clock + sysinfo.PHY_INFO_TTL + 1
			sysinfo.radio_caps("wlan0")
			assert_eq(phy_reads, 2, "and re-read once the TTL is up")

			sysinfo._run_cmd, sysinfo._time = orig_cmd, orig_time
			sysinfo._phy_info_cache = {}
		end
	},
	{
		name = "sysinfo: a pass reads /proc/net/arp and the leases once, not once per port",
		fn = function()
			-- _ip_by_mac/_hostname_by_mac are called from BOTH mac_table and
			-- switch_mac_table, which build_json runs once per downstream
			-- socket -- five reads of the ARP cache and four of the lease file
			-- per heartbeat on the Archer C5, plus the ARL walked whole once
			-- per socket. One pass answers every socket.
			local orig_rf, orig_cmd = sysinfo._read_file, sysinfo._run_cmd
			local arp_reads, lease_reads = 0, 0
			sysinfo._read_file = function(path)
				if path == "/proc/net/arp" then
					arp_reads = arp_reads + 1
					return "10.0.0.7 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n"
				elseif path == "/tmp/dhcp.leases" then
					lease_reads = lease_reads + 1
					return "1700000000 aa:bb:cc:dd:ee:01 10.0.0.7 laptop *\n"
				end
				return nil
			end
			sysinfo._run_cmd = function() return "" end

			-- No pass open: every call reads, exactly as before.
			sysinfo.end_pass()
			sysinfo._ip_by_mac(); sysinfo._ip_by_mac()
			sysinfo._hostname_by_mac(); sysinfo._hostname_by_mac()
			assert_eq(arp_reads, 2, "no pass open -- every call reads, as before")
			assert_eq(lease_reads, 2, "and the same for the lease file")

			arp_reads, lease_reads = 0, 0
			sysinfo.begin_pass()
			local arl = {["aa:bb:cc:dd:ee:01"] = 2, ["aa:bb:cc:dd:ee:02"] = 3}
			local p2 = sysinfo.switch_mac_table(2, arl)
			local p3 = sysinfo.switch_mac_table(3, arl)
			sysinfo.switch_mac_table(4, arl)
			assert_eq(arp_reads, 1, "one ARP read for every socket in the payload")
			assert_eq(lease_reads, 1, "one lease read for every socket in the payload")
			-- ...and the answers are still right, per socket.
			assert_eq(#p2, 1, "port 2 keeps its own host")
			assert_eq(p2[1].mac, "aa:bb:cc:dd:ee:01", "the right one")
			assert_eq(p2[1].ip, "10.0.0.7", "with its IP from the shared ARP read")
			assert_eq(p2[1].hostname, "laptop", "and its lease hostname")
			assert_eq(#p3, 1, "port 3 keeps its own host")
			assert_eq(p3[1].mac, "aa:bb:cc:dd:ee:02", "the right one")

			-- A fresh ARL inside the same pass is bucketed afresh: the memo is
			-- keyed on the table, so a new dump is never served a stale one.
			local arl2 = {["aa:bb:cc:dd:ee:03"] = 2}
			local again = sysinfo.switch_mac_table(2, arl2)
			assert_eq(#again, 1, "a new ARL is bucketed, not served from the old one")
			assert_eq(again[1].mac, "aa:bb:cc:dd:ee:03", "with its own host")

			-- Closing the pass restores the un-memoized behaviour, and RELEASES
			-- what it held: the memo pins an ARP map and a bucketed ARL, which
			-- must not sit in a long-running daemon between heartbeats.
			sysinfo.end_pass()
			assert_nil(sysinfo._pass_cache, "end_pass releases the memo")
			arp_reads = 0
			sysinfo._ip_by_mac(); sysinfo._ip_by_mac()
			assert_eq(arp_reads, 2, "the pass is closed -- every call reads again")

			sysinfo._read_file, sysinfo._run_cmd = orig_rf, orig_cmd
			sysinfo.end_pass()
		end
	},
	{
		name = "sysinfo: an absent lease file is not re-opened once per socket",
		fn = function()
			-- An AP is usually not the DHCP server, so _hostname_by_mac's read
			-- returns nil -- which must be memoized as "computed and empty",
			-- not as "not computed yet", or the common case keeps re-opening a
			-- file that is not there.
			local orig_rf = sysinfo._read_file
			local lease_reads = 0
			sysinfo._read_file = function(path)
				if path == "/tmp/dhcp.leases" then
					lease_reads = lease_reads + 1
					return nil
				end
				return nil
			end
			sysinfo.begin_pass()
			sysinfo._hostname_by_mac()
			sysinfo._hostname_by_mac()
			sysinfo._hostname_by_mac()
			assert_eq(lease_reads, 1, "the missing file is opened once, not once per socket")
			sysinfo.end_pass()
			sysinfo._read_file = orig_rf
		end
	},
	{
		name = "sysinfo: one `bridge fdb show br` serves every socket in a payload",
		fn = function()
			-- uplink_bridge_port already dumps the WHOLE bridge FDB to find the
			-- gateway's socket, and that one dump carries every socket's hosts.
			-- mac_table forked `bridge fdb show dev <socket>` per socket anyway
			-- -- four more forks a heartbeat on the AX3000T for a strict subset
			-- of what was already in hand. Given the bridge, it reads the
			-- shared dump; without one it forks exactly as before.
			local orig_cmd = sysinfo._run_cmd
			local br_dumps, dev_dumps = 0, 0
			sysinfo._run_cmd = function(cmd)
				if cmd:find("bridge fdb show br", 1, true) then
					br_dumps = br_dumps + 1
					return table.concat({
						"aa:bb:cc:dd:ee:01 dev lan2 master br-lan ",
						"aa:bb:cc:dd:ee:02 dev lan3 master br-lan ",
						"01:00:5e:00:00:01 dev lan3 master br-lan ",   -- multicast
						"00:00:5e:00:53:20 dev lan2 master br-lan permanent",
						"aa:bb:cc:dd:ee:02 dev lan3 self ",
					}, "\n") .. "\n"
				elseif cmd:find("bridge fdb show dev", 1, true) then
					dev_dumps = dev_dumps + 1
					return "aa:bb:cc:dd:ee:09 dev lan9 master br-lan \n"
				end
				return ""
			end

			sysinfo.begin_pass()
			local l2 = sysinfo.mac_table("lan2", "br-lan")
			local l3 = sysinfo.mac_table("lan3", "br-lan")
			local l4 = sysinfo.mac_table("lan4", "br-lan")
			assert_eq(br_dumps, 1, "one dump of the kernel FDB for every socket")
			assert_eq(dev_dumps, 0, "and not one per-socket fork")
			assert_eq(#l2, 1, "lan2's own host")
			assert_eq(l2[1].mac, "aa:bb:cc:dd:ee:01", "the right one")
			assert_eq(#l3, 1, "lan3's own host -- multicast and self dropped")
			assert_eq(l3[1].mac, "aa:bb:cc:dd:ee:02", "the right one")
			assert_eq(#l4, 0, "a socket with nothing on it reports no hosts")
			-- `permanent` is the socket's OWN address; counting it would put
			-- this device's socket in its own client list.
			for _, h in ipairs(l2) do
				assert_true(h.mac ~= "00:00:5e:00:53:20", "never the port's own address")
			end

			-- The uplink question and the host lists share the one dump.
			assert_eq(sysinfo.bridge_fdb_ports("br-lan")["aa:bb:cc:dd:ee:01"], "lan2",
				"the same dump still answers which socket a MAC is behind")
			assert_eq(br_dumps, 1, "without a second fork")

			-- No bridge given: the per-socket fork, exactly as before.
			local solo = sysinfo.mac_table("lan9")
			assert_eq(dev_dumps, 1, "no bridge -- mac_table forks per socket, as before")
			assert_eq(#solo, 1, "and still answers")
			assert_eq(solo[1].mac, "aa:bb:cc:dd:ee:09", "with that socket's host")

			-- Outside a pass the shared dump is re-read every time.
			sysinfo.end_pass()
			br_dumps = 0
			sysinfo.mac_table("lan2", "br-lan")
			sysinfo.mac_table("lan3", "br-lan")
			assert_eq(br_dumps, 2, "the pass is closed -- every call dumps again")

			sysinfo._run_cmd = orig_cmd
			sysinfo.end_pass()
		end
	},
	{
		name = "sysinfo: the phy dump is parsed once per TTL, not once per radio per heartbeat",
		fn = function()
			-- Caching the phy dump's TEXT still left ~8 scans and a gmatch over
			-- 40-odd kilobytes running per radio per heartbeat. Everything but
			-- the live channel and TX power is derived from that text and is
			-- exactly as static as it is, so the derivation is cached with it.
			local orig_cmd, orig_time = sysinfo._run_cmd, sysinfo._time
			local clock = 1000
			sysinfo._time = function() return clock end
			sysinfo._phy_info_cache = {}
			sysinfo._run_cmd = function(cmd)
				if cmd:find("iw phy") then
					return "\t\tHT TX Max spatial streams: 3\n"
						.. "\t\tVHT Capabilities (0x00000000):\n"
				end
				return "\twiphy 0\n\tchannel 36 (5180 MHz)\n\ttxpower 23.00 dBm\n"
			end

			local first = sysinfo.radio_caps("wlan0")
			assert_eq(first.nss, 3, "the hardware's real stream count")
			assert_true(first.is_11ac, "and its PHY generation")
			assert_eq(first.channel, 36, "with the live channel merged on top")
			assert_eq(first.tx_power, 23, "and the live TX power")

			-- Reads come from the cached derivation, not from a fresh parse:
			-- poison the cached half and it shows through.
			sysinfo._phy_info_cache["0"].caps.nss = 99
			assert_eq(sysinfo.radio_caps("wlan0").nss, 99,
				"the hardware half is served from the cache, not re-parsed")

			-- ...but the caller gets a COPY. build_json writes radio_caps and
			-- wpa3_supported onto what it gets back, and one radio's payload
			-- fields must not leak into the next radio's -- or into the cache.
			local mine = sysinfo.radio_caps("wlan0")
			mine.nss, mine.wpa3_supported = 1, true
			local theirs = sysinfo.radio_caps("wlan0")
			assert_eq(theirs.nss, 99, "a caller's writes do not reach the cache")
			assert_nil(theirs.wpa3_supported, "nor its added fields")

			-- Past the TTL everything is re-read AND re-derived, so a regdomain
			-- change still lands within minutes.
			clock = clock + sysinfo.PHY_INFO_TTL + 1
			assert_eq(sysinfo.radio_caps("wlan0").nss, 3, "re-parsed once the TTL is up")

			sysinfo._run_cmd, sysinfo._time = orig_cmd, orig_time
			sysinfo._phy_info_cache = {}
		end
	},
	{
		name = "sysinfo: the uplink's near-static input is cached, the cable-following ones are not",
		fn = function()
			-- Which socket the cable is in must stay measured every heartbeat.
			-- What the default route's gateway IP is, is not a measurement of
			-- the cable and changes only when the network is reconfigured -- a
			-- fork a heartbeat, forever. Which BRIDGE a netdev is on is a sysfs
			-- read, asked live and never forked.
			local orig_cmd, orig_rf, orig_time =
				sysinfo._run_cmd, sysinfo._read_file, sysinfo._time
			local clock = 5000
			sysinfo._time = function() return clock end
			sysinfo._uplink_cache = {}
			local masters, routes, forks = 0, 0, 0
			local gw = "192.0.2.1"
			sysinfo._run_cmd = function(cmd)
				forks = forks + 1
				if cmd:find("ip route") then
					routes = routes + 1
					return "default via " .. gw .. " dev br-lan \n"
				end
				return ""
			end
			local arp_reads = 0
			sysinfo._read_file = function(path)
				if path == "/proc/net/arp" then
					arp_reads = arp_reads + 1
					return gw .. " 0x1 0x2 aa:bb:cc:00:00:01 * br-lan\n"
						.. "192.0.2.9 0x1 0x2 aa:bb:cc:00:00:09 * br-lan\n"
				elseif path == "/sys/class/net/wan/master/uevent" then
					masters = masters + 1
					return "INTERFACE=br-lan\n"
				end
				return nil
			end

			assert_eq(sysinfo.bridge_of("wan"), "br-lan", "the bridge is found")
			sysinfo.bridge_of("wan"); sysinfo.bridge_of("wan")
			assert_eq(masters, 3, "asked live each time")
			assert_eq(forks, 0, "and never forked")

			assert_eq(sysinfo._default_gateway_mac(), "aa:bb:cc:00:00:01", "the gateway")
			sysinfo._default_gateway_mac()
			assert_eq(routes, 1, "the default route is asked for once")
			assert_eq(arp_reads, 2, "but the ARP cache is read every time -- it follows the cable")

			-- The gateway moving to another socket is picked up immediately:
			-- the same IP, a different MAC in the ARP cache.
			sysinfo._read_file = function(path)
				if path == "/proc/net/arp" then
					return gw .. " 0x1 0x2 aa:bb:cc:00:00:0f * br-lan\n"
				end
				return nil
			end
			assert_eq(sysinfo._default_gateway_mac(), "aa:bb:cc:00:00:0f",
				"a change on the live half lands on the very next heartbeat")

			-- Past the TTL the near-static half is re-asked too.
			clock = clock + sysinfo.UPLINK_TTL + 1
			sysinfo._default_gateway_mac()
			assert_eq(routes, 2, "the default route is re-asked once the TTL is up")

			sysinfo._run_cmd, sysinfo._read_file, sysinfo._time =
				orig_cmd, orig_rf, orig_time
			sysinfo._uplink_cache = {}
		end
	},
	{
		name = "sysinfo: a device with no default route yet keeps asking",
		fn = function()
			-- "No default route" and "not a bridge port" are ordinary states
			-- during boot, before DHCP has settled or netifd has finished.
			-- Remembering them would leave the device unable to find its uplink
			-- for the next five minutes.
			local orig_cmd, orig_rf = sysinfo._run_cmd, sysinfo._read_file
			sysinfo._uplink_cache = {}
			local up = false
			sysinfo._run_cmd = function(cmd)
				if not up then return "" end
				if cmd:find("ip route") then return "default via 10.0.0.1 dev br-lan \n" end
				return ""
			end
			sysinfo._read_file = function(path)
				if path == "/proc/net/arp" then
					return "10.0.0.1 0x1 0x2 aa:bb:cc:00:00:01 * br-lan\n"
				end
				if up and path == "/sys/class/net/wan/master/uevent" then
					return "INTERFACE=br-lan\n"
				end
				return nil
			end
			assert_nil(sysinfo.bridge_of("wan"), "nothing to find yet")
			assert_nil(sysinfo._default_gateway_mac(), "nor a gateway")
			up = true
			assert_eq(sysinfo.bridge_of("wan"), "br-lan", "and it is found as soon as it exists")
			assert_eq(sysinfo._default_gateway_mac(), "aa:bb:cc:00:00:01", "gateway too")

			sysinfo._run_cmd, sysinfo._read_file = orig_cmd, orig_rf
			sysinfo._uplink_cache = {}
		end
	},
	{
		name = "sysinfo: one read of /proc/net/arp serves the whole payload",
		fn = function()
			-- _default_gateway_mac had its own inline read of the ARP cache,
			-- separate from _ip_by_mac's -- so the pass covered four of the
			-- five reads a heartbeat, not all five. Both go through one now.
			local orig_rf, orig_cmd = sysinfo._read_file, sysinfo._run_cmd
			sysinfo._uplink_cache = {}
			local arp_reads = 0
			sysinfo._read_file = function(path)
				if path == "/proc/net/arp" then
					arp_reads = arp_reads + 1
					return "10.0.0.1 0x1 0x2 aa:bb:cc:00:00:01 * br-lan\n"
				end
				return nil
			end
			sysinfo._run_cmd = function(cmd)
				if cmd:find("ip route") then return "default via 10.0.0.1 dev br-lan \n" end
				return ""
			end
			sysinfo.begin_pass()
			sysinfo._default_gateway_mac()
			sysinfo._ip_by_mac()
			sysinfo._default_gateway_mac()
			assert_eq(arp_reads, 1, "the uplink lookup and the host join share one read")
			sysinfo.end_pass()

			sysinfo._read_file, sysinfo._run_cmd = orig_rf, orig_cmd
			sysinfo._uplink_cache = {}
		end
	},
	{
		name = "sysinfo: /proc/uptime is read once per payload, not once per radio",
		fn = function()
			-- build_json reports the uptime once, and scan_table reads it again
			-- per radio as the CLOCK_BOOTTIME reference for each BSS's "last
			-- seen" -- three opens a heartbeat on a two-radio box.
			local orig_rf = sysinfo._read_file
			local reads = 0
			sysinfo._read_file = function(path)
				if path == "/proc/uptime" then
					reads = reads + 1
					return "12345.67 98765.43\n"
				end
				return nil
			end

			sysinfo.end_pass()
			sysinfo.uptime(); sysinfo.uptime()
			assert_eq(reads, 2, "no pass open -- every call reads, as before")

			reads = 0
			sysinfo.begin_pass()
			assert_eq(sysinfo.uptime(), 12345, "the uptime")
			sysinfo.uptime(); sysinfo.uptime()
			assert_eq(reads, 1, "one read for the whole payload")
			sysinfo.end_pass()

			sysinfo._read_file = orig_rf
		end
	},
}
