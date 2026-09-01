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
		name = "sysinfo: loadavg() parses /proc/loadavg correctly",
		fn = function()
			with_fixtures({["/proc/loadavg"] = fixture("proc_loadavg.txt")}, {}, function()
				local la = sysinfo.loadavg()
				assert_eq(la.one,     0.42, "1-min load")
				assert_eq(la.five,    0.31, "5-min load")
				assert_eq(la.fifteen, 0.19, "15-min load")
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
			end)
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
					assert_eq(ports["5a:d6:1f:40:e2:f6"], "wan", "gateway is on wan")
					assert_eq(ports["00:04:4b:86:81:77"], "wan", "a host is on wan")
					-- The board's own port MAC arrives only on "permanent"
					-- lines, so it is not a host and must not be in the map.
					assert_true(ports["d4:53:2a:38:80:cf"] == nil,
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
				["ip route"] = "default via 192.168.200.1 dev br-lan \n",
			}
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")}, cmds,
				function()
					assert_eq(sysinfo.uplink_bridge_port("br-lan"), "wan",
						"uplink socket is wan")
				end)

			-- Same board, cable moved to another socket: the answer has to
			-- follow the FDB, not a constant. (Synthetic -- only one socket
			-- was cabled on the real board at capture time.)
			local moved = "5a:d6:1f:40:e2:f6 dev lan3 master br-lan \n"
				.. "00:04:4b:86:81:77 dev lan3 master br-lan \n"
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["bridge fdb show br"] = moved,
				 ["ip route"] = "default via 192.168.200.1 dev br-lan \n"},
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
				 ["ip route"] = "default via 192.168.200.254 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_bridge_port("br-lan") == nil,
						"gateway not in arp -> nil")
				end)
			-- Gateway resolved but the bridge has not learned it.
			with_fixtures({["/proc/net/arp"] = fixture("proc_net_arp_dsa.txt")},
				{["ip route"] = "default via 192.168.200.1 dev br-lan \n"},
				function()
					assert_true(sysinfo.uplink_bridge_port("br-lan") == nil,
						"gateway not in the FDB -> nil")
				end)
		end
	},
	{
		name = "sysinfo: bridge_of() names the bridge a socket is enslaved to",
		fn = function()
			with_fixtures({}, {["readlink"] =
				"../../../../../../../../virtual/net/br-lan\n"}, function()
					assert_eq(sysinfo.bridge_of("lan3"), "br-lan", "lan3 is in br-lan")
				end)
			-- A netdev that is not a bridge port: readlink prints nothing.
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
}
