-- Integration test: inform.build_json() produces a well-formed payload.
-- Tests the full JSON structure without needing a real controller.
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
dofile("openuf/lib/lib.lua")

local cjson  = require("cjson")
local state  = dofile("openuf/state.lua")
local inform = dofile("openuf/inform.lua")

local function fixture(name)
	local f = io.open("tests/fixtures/" .. name, "r")
	if not f then return "" end
	local s = f:read("*a"); f:close(); return s
end

-- Inject sysinfo fixtures via inform's exposed _sysinfo reference
-- (inform.lua loads its own sysinfo instance; M._sysinfo is that instance)
-- with_clients: when true, sta_table()/radio_stats() return real fixture data
-- (2 connected clients, one in-use channel survey entry) instead of empty.
-- with_wired: when true, mac_table()'s bridge fdb/arp/dhcp-lease sources
-- return real fixture data (2 wired hosts) instead of empty.
-- with_scan: when true, scan_table()'s `iw scan dump` source returns real
-- fixture data (2 neighboring networks) instead of empty.
-- with_radio_caps: when true, radio_caps()'s `iw dev ... info` / `iw phy ...
-- info` sources return a real 5GHz (VHT+HE+DFS+160MHz) fixture instead of
-- empty.
local function inject_sysinfo(with_clients, with_wired, with_scan, with_radio_caps)
	-- Caches whose whole point is to outlive a heartbeat: swapping the
	-- fixtures underneath them is exactly what they are not built for, so each
	-- payload starts from a clean one. (with_fixtures in test_sysinfo.lua does
	-- the same, on the way in and out.)
	inform._sysinfo._phy_info_cache = {}
	inform._sysinfo._uplink_cache   = {}
	inform._sysinfo.end_pass()
	inform._sysinfo._read_file = function(path)
		if path:find("uptime")  then return fixture("proc_uptime.txt")  end
		if path:find("loadavg") then return fixture("proc_loadavg.txt") end
		if path:find("meminfo") then return fixture("proc_meminfo.txt") end
		if path:find("net/dev") then return fixture("proc_net_dev.txt") end
		if with_wired and path:find("net/arp")     then return fixture("proc_net_arp.txt") end
		if with_wired and path:find("dhcp.leases") then return fixture("dhcp_leases.txt")  end
		return ""
	end
	inform._sysinfo._run_cmd = function(cmd)
		-- Keyed on the interface, like the real `iw dev <if> station dump`.
		-- A blanket match would return the same stations for every netdev,
		-- which is precisely the failure mode this suite needs to be able to
		-- see: a second WLAN on a radio must come back empty, not with the
		-- first WLAN's clients.
		if with_clients and cmd:find("dev wlan0 station dump", 1, true) then
			return fixture("iw_station_dump.txt")
		end
		if cmd:find("station dump") then return "" end
		if with_clients and cmd:find("survey dump") then
			return fixture("iw_survey_dump.txt")
		end
		if with_wired and cmd:find("bridge fdb show") then
			return fixture("bridge_fdb_dump.txt")
		end
		if with_scan and cmd:find("scan dump") then
			return fixture("iw_scan_dump.txt")
		end
		if with_radio_caps and cmd:find("dev wlan0 info") then
			return fixture("iw_dev_info.txt")
		end
		if with_radio_caps and cmd:find("phy phy0 info") then
			return fixture("iw_phy_info_5g.txt")
		end
		return ""
	end
	-- Return empty neighbor list (no lldpd on dev machine). The neighbour list
	-- is TTL-cached for a minute, so a test that fed it a real lldpctl reply
	-- would otherwise keep answering for the tests after it.
	inform._lldp._run_cmd = function() return "" end
	inform._lldp._neighbours_cache = nil
	inform._lldp._port_idx_cache   = {}
end

-- Inject a mock ucihelper so build_json's radio/vap/stats wiring can be
-- exercised without a real UCI environment.
local function inject_ucihelper()
	inform._ucihelper = {
		get_radio_table = function()
			return {
				-- channel is numeric, mirroring the real get_radio_table's
				-- tonumber coercion (the literal "auto" is the only
				-- non-numeric value that passes through).
				{ name = "radio0", radio = "ng", channel = 6, ht = "HT20", tx_power = "20",
				  disabled = false, builtin_antenna = true, builtin_ant_gain = 3,
				  max_txpower = 20 },
			}
		end,
		get_vap_table = function()
			return {
				{ name = "openuf_test", essid = "test", radio = "ng", radio_name = "radio0",
				  encryption = "psk2", disabled = false, bssid = "aa:bb:cc:00:00:01",
				  channel = 6, tx_power = "20", usage = "user" },
			}
		end,
		-- Strict on purpose: real get_ifname_for_radio() resolves a UCI
		-- device name ("radio0"/"radio1"), not the band vap.radio reports
		-- ("ng"/"na") -- returning nil for anything else catches a caller
		-- that regresses back to passing vap.radio here (sta_table would
		-- silently stay empty on every real inform).
		get_ifname_for_radio = function(radio) if radio == "radio0" then return "wlan0" end return nil end,
		-- Per-VAP resolution, keyed on BOTH radio and ssid, the way the real
		-- one matches SSIDs inside a radio's interface list. Modelled per-SSID
		-- so a second WLAN on the same radio gets its own netdev -- a mock
		-- that ignored the ssid would happily pass a build that hands every
		-- vap on a radio the first vap's clients, which is the live bug this
		-- guards.
		get_ifname_for_vap = function(radio, ssid)
			if radio ~= "radio0" then return nil end
			if ssid == "test" then return "wlan0" end
			if ssid == "guest" then return "wlan0-1" end
			return nil
		end,
	}
end

-- Minimal ufhw matching the u6iw model
local ufhw = {
	uap = {
		platform = "U6IW",
		model    = "U6IW",
		fw       = {pre="U6IW.", ver="6.6.55", buildtime="230801.1200", factoryver="6.5.28"},
		required_version = "6.0.0",
		bootver  = "",
	}
}

local function build(opts)
	inject_sysinfo(opts and opts.with_clients, opts and opts.with_wired, opts and opts.with_scan,
		opts and opts.with_radio_caps)
	if opts and opts.with_uci then inject_ucihelper() end
	local st = {
		authkey    = state.DEFAULT_KEY,
		adopted    = opts and opts.adopted or false,
		cfgversion = opts and opts.cfgversion or "",
		inform_url = "http://10.0.0.1:8080/inform",
		mac        = "aa:bb:cc:dd:ee:ff",
		ip         = "192.168.1.100",
		hostname   = "testap",
		locating   = opts and opts.locating,
	}
	local json_str = inform.build_json(st, nil, ufhw)
	return cjson.decode(json_str), st
end

-- A socket-shaped modelmap: one port_idx per physical switch socket, and no
-- static uplink flag -- which socket the cable is in is detected from the
-- switch's ARL table. `map` is the board's swconfig port numbering.
local function switch_cfg(map)
	local ports = {}
	for i, label in ipairs({"lan1", "lan2", "lan3", "lan4", "wan"}) do
		if map[label] then ports[#ports + 1] = {idx = i, swport = label} end
	end
	return {
		net  = {lan_cpueth = "eth1", lan_vlanid = 1, ports = ports},
		vlan = {cpu_lan = 0, ports = map},
	}
end

-- WDR3500 as cabled today: four LAN sockets on physical 1-4, uplink in 4.
local WDR_MAP    = {lan1 = 1, lan2 = 2, lan3 = 3, lan4 = 4}
-- Archer C5: the WAN socket is physical 1 and the LAN sockets are 2-5, with
-- the uplink in physical 2 -- a different socket, same detection.
local ARCHER_MAP = {lan1 = 2, lan2 = 3, lan3 = 4, lan4 = 5, wan = 1}

-- build() for a board with a switch: same payload, plus the swconfig capture,
-- default route and ARP table that per-socket reporting reads.
local function build_switch(opts)
	opts = opts or {}
	inject_sysinfo(opts.with_clients, false, false, false)
	local base_read = inform._sysinfo._read_file
	local base_cmd  = inform._sysinfo._run_cmd
	inform._sysinfo._read_file = function(path)
		if path:find("net/arp") then
			return opts.arp or fixture("proc_net_arp_switch.txt")
		end
		return base_read(path)
	end
	inform._sysinfo._run_cmd = function(cmd)
		if cmd:find("swconfig") then return opts.swconfig or "" end
		if cmd:find("ip route") then
			return "default via " .. (opts.gateway or "10.0.0.1") .. " dev br-lan \n"
		end
		return base_cmd(cmd)
	end
	local st = {
		authkey    = state.DEFAULT_KEY,
		adopted    = true,
		cfgversion = "",
		inform_url = "http://10.0.0.1:8080/inform",
		mac        = opts.mac or "aa:bb:cc:00:11:22",
		ip         = "10.0.0.2",
		hostname   = "testap",
	}
	return cjson.decode(inform.build_json(st, opts.cfg, ufhw))
end

-- A DSA board's modelmap: no switch map at all (there is no swconfig switch
-- to map), one netdev per socket, and no static uplink flag -- the uplink is
-- detected from the bridge FDB. Modelled on the Xiaomi AX3000T, whose four
-- sockets are wan/lan2/lan3/lan4 in br-lan.
local DSA_CFG = {
	net = {
		lan_cpueth = "wan", lan_vlanid = 1,
		ports = {
			{idx = 1, ifname = "wan"},
			{idx = 2, ifname = "lan2"},
			{idx = 3, ifname = "lan3"},
			{idx = 4, ifname = "lan4"},
		},
	},
}

-- build() for a DSA board: no swconfig output at all (there is no such
-- binary), so everything comes from sysfs per socket plus the bridge FDB.
-- opts.fdb overrides the captured `bridge fdb show br br-lan`.
-- Commands the last build_dsa() run forked, by kind. Lets a test assert on the
-- COST of a payload, not only its content -- which is the only way to pin that
-- build_json actually threads the shared FDB dump down to the port loop.
local dsa_forks = {}

local function build_dsa(opts)
	opts = opts or {}
	dsa_forks = {fdb_br = 0, fdb_dev = 0, uptime = 0}
	inject_sysinfo(false, false, false, false)
	local base_read = inform._sysinfo._read_file
	local base_cmd  = inform._sysinfo._run_cmd
	inform._sysinfo._read_file = function(path)
		if path:find("net/arp") then return fixture("proc_net_arp_dsa.txt") end
		if path == "/proc/uptime" then dsa_forks.uptime = dsa_forks.uptime + 1 end
		return base_read(path)
	end
	inform._sysinfo._run_cmd = function(cmd)
		if cmd:find("swconfig") then return "" end   -- no such binary on DSA
		if cmd:find("ip route") then
			return "default via 192.168.200.1 dev br-lan \n"
		end
		if cmd:find("readlink") then
			return "../../../../../../../../virtual/net/br-lan\n"
		end
		local fdb = opts.fdb or fixture("bridge_fdb_br_dsa.txt")
		if cmd:find("bridge fdb show br", 1, true) then
			dsa_forks.fdb_br = dsa_forks.fdb_br + 1
			return fdb
		end
		-- `bridge fdb show dev <socket>`: on DSA each socket is its own
		-- bridge port, so the per-port FDB is the per-socket host list. Derived
		-- from the SAME dump rather than canned separately -- they are one
		-- kernel table, and a stub that let them disagree would hide exactly
		-- the substitution build_json now makes between them.
		local dev = cmd:match("bridge fdb show dev (%S+)")
		if dev then
			dsa_forks.fdb_dev = dsa_forks.fdb_dev + 1
			local lines = {}
			for line in fdb:gmatch("[^\n]+") do
				if line:match("dev%s+(%S+)") == dev then lines[#lines + 1] = line end
			end
			return table.concat(lines, "\n") .. "\n"
		end
		return base_cmd(cmd)
	end
	-- Per-socket sysfs: the uplink is up at gigabit, the rest are empty.
	local orig_rf = inform._read_file
	inform._read_file = function(path)
		local iface = path:match("/sys/class/net/([^/]+)/")
		if iface == (opts.live or "wan") then
			if path:find("speed")   then return "1000\n" end
			if path:find("duplex")  then return "full\n" end
			if path:find("carrier") then return "1\n"    end
		elseif iface then
			if path:find("speed")   then return "-1\n"   end
			if path:find("carrier") then return "0\n"    end
		end
		return nil
	end
	local st = {
		authkey = state.DEFAULT_KEY, adopted = true, cfgversion = "",
		inform_url = "http://192.168.200.1:8080/inform",
		mac = "d4:53:2a:38:80:cf", ip = "192.168.200.4", hostname = "testap",
	}
	local ok, out = pcall(function()
		return cjson.decode(inform.build_json(st, opts.cfg or DSA_CFG, ufhw))
	end)
	inform._read_file = orig_rf
	if not ok then error(out, 0) end
	return out
end

-- Index a payload's port_table by port_idx.
local function by_idx(port_table)
	local out = {}
	for _, p in ipairs(port_table) do out[p.port_idx] = p end
	return out
end

return {
	{
		name = "inform json: _type is 'state'",
		fn = function()
			local d = build()
			assert_eq(d._type, "state", "_type")
		end
	},
	{
		name = "inform json: required top-level fields present",
		fn = function()
			local d = build()
			for _, field in ipairs({"mac","serial","model","platform","hostname",
				"ip","version","uptime","time","mem_total","mem_used"}) do
				assert_not_nil(d[field], "field present: " .. field)
			end
		end
	},
	{
		name = "inform json: mac matches state",
		fn = function()
			local d = build()
			assert_eq(d.mac, "aa:bb:cc:dd:ee:ff", "mac")
		end
	},
	{
		name = "inform json: serial is mac without colons",
		fn = function()
			local d = build()
			assert_eq(d.serial, "aabbccddeeff", "serial")
		end
	},
	{
		name = "inform json: model and platform match u6iw",
		fn = function()
			local d = build()
			assert_eq(d.model,    "U6IW", "model")
			assert_eq(d.platform, "U6IW", "platform")
		end
	},
	{
		name = "inform json: version is the bare fw.ver, no model prefix",
		fn = function()
			-- Not model-prefixed: the controller compares this against its
			-- firmware catalog's own bare "version" field with strict string
			-- equality, so a "U6IW."-prefixed value never matches even when
			-- the numeric version is identical (see openuf/inform.lua).
			local d = build()
			assert_eq(d.version, "6.6.55", "version is bare fw.ver")
		end
	},
	{
		name = "inform json: default=true when not adopted",
		fn = function()
			local d = build({adopted = false})
			assert_true(d["default"], "default true when not adopted")
		end
	},
	{
		name = "inform json: default=false when adopted",
		fn = function()
			local d = build({adopted = true})
			assert_false(d["default"], "default false when adopted")
		end
	},
	{
		name = "inform json: uptime from fixture is 12345",
		fn = function()
			local d = build()
			assert_eq(d.uptime, 12345, "uptime from /proc/uptime fixture")
		end
	},
	{
		name = "inform json: mem_total and mem_used from fixture (bytes)",
		fn = function()
			local d = build()
			assert_eq(d.mem_total, 131072 * 1024, "mem_total bytes")
			assert_eq(d.mem_used, (131072 - 65536) * 1024, "mem_used = (total - free) bytes")
		end
	},
	{
		name = "inform json: if_table is a list",
		fn = function()
			local d = build()
			assert_not_nil(d.if_table, "if_table present")
			assert_true(type(d.if_table) == "table", "if_table is table")
			-- Fixture has lo, eth0, eth1
			assert_true(#d.if_table >= 3, "at least 3 interfaces")
		end
	},
	{
		name = "inform json: if_table entries have required fields",
		fn = function()
			local d = build()
			local eth0
			for _, iface in ipairs(d.if_table) do
				if iface.name == "eth0" then eth0 = iface end
			end
			assert_not_nil(eth0, "eth0 in if_table")
			assert_not_nil(eth0.rx_bytes,  "eth0 rx_bytes")
			assert_not_nil(eth0.tx_bytes,  "eth0 tx_bytes")
		end
	},
	{
		name = "inform json: cfgversion reflects state",
		fn = function()
			local d = build({cfgversion = "abc123"})
			assert_eq(d.cfgversion, "abc123", "cfgversion")
		end
	},
	{
		name = "inform json: inform_url present",
		fn = function()
			local d = build()
			assert_eq(d.inform_url, "http://10.0.0.1:8080/inform", "inform_url")
		end
	},
	{
		name = "inform json: lldp_table is a list (may be empty without lldpd)",
		fn = function()
			local d = build()
			assert_not_nil(d.lldp_table, "lldp_table present")
			assert_true(type(d.lldp_table) == "table", "lldp_table is table")
		end
	},
	{
		name = "inform json: lldp_table uses the real controller's field names",
		fn = function()
			-- Can't use build() here: inject_sysinfo() (which it always
			-- calls first) resets _lldp._run_cmd to return "" every time,
			-- so the lldpctl fixture override must be set after that and
			-- build_json() called directly.
			inject_sysinfo(false)
			inform._lldp._run_cmd = function(cmd)
				if cmd:find("lldpctl") then
					local f = io.open("tests/fixtures/lldpctl_output.json", "r")
					local s = f:read("*a"); f:close(); return s
				end
				return ""
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			local nbr = d.lldp_table[1]
			assert_eq(nbr.chassis_id, "aa:bb:cc:dd:ee:01", "chassis_id")
			assert_eq(nbr.port_id, "GigabitEthernet0/1", "port_id")
			assert_eq(nbr.local_port_name, "eth0", "local_port_name (was 'port')")
			assert_eq(nbr.port_descr, "Uplink port", "port_descr")
			assert_contains(nbr.chassis_descr, "UniFi Switch",
				"chassis_descr comes from the System Description TLV (chassis.descr), not chassis.name")
			assert_eq(nbr.is_wired, true, "is_wired always true for LLDP")
			assert_true(nbr.system_name == nil, "system_name is not a real wire field")
			assert_true(nbr.port == nil, "port is not a real wire field (renamed local_port_name)")
			inform._lldp._run_cmd = function() return "" end
		end
	},
	{
		name = "inform json: locating defaults to false",
		fn = function()
			local d = build()
			assert_false(d.locating, "locating false by default")
		end
	},
	{
		name = "inform json: locating reflects state.locating",
		fn = function()
			local d = build({locating = true})
			assert_true(d.locating, "locating true from state")
		end
	},
	{
		name = "inform json: system-stats present with cpu/mem/uptime (real capture key/shape)",
		fn = function()
			local d = build()
			-- Real devices report this under the hyphenated key "system-stats"
			-- (verified against a real captured USG payload) -- not "sys_stats".
			local stats = d["system-stats"]
			assert_not_nil(stats, "system-stats present")
			assert_not_nil(stats.cpu, "cpu field present")
			assert_not_nil(stats.uptime, "uptime field present")
			-- meminfo fixture: total=131072kB, free=65536kB -> 50% used
			assert_eq(stats.mem, "50", "mem percent computed from meminfo fixture")
		end
	},
	{
		name = "inform json: a second WLAN on the same radio does not inherit the first's clients",
		fn = function()
			-- The live bug: with "Home LAN" and a brand-new "Home IoT" both on
			-- radio1, the IoT WLAN reported nine connected clients -- every one
			-- of them the other WLAN's, showing the other network's IP
			-- addresses in the controller UI. sta_table was resolved per RADIO
			-- (get_ifname_for_radio returns whichever interface netifd lists
			-- first), so every secondary vap on a radio got the first vap's
			-- station dump, and with it the traffic counters, satisfaction and
			-- num_sta. The device-level aggregates double-counted too.
			inject_sysinfo(true)          -- fixture: 2 clients, on wlan0 only
			inject_ucihelper()
			local ufuci = inform._ucihelper
			local orig_vaps = ufuci.get_vap_table
			ufuci.get_vap_table = function()
				return {
					{name = "openuf_test", essid = "test", radio = "ng",
					 radio_name = "radio0", encryption = "psk2", disabled = false,
					 bssid = "aa:bb:cc:00:00:01", channel = 6, usage = "user"},
					-- Same radio, different SSID -- the IoT case.
					{name = "openuf_guest", essid = "guest", radio = "ng",
					 radio_name = "radio0", encryption = "psk2", disabled = false,
					 bssid = "aa:bb:cc:00:00:02", channel = 6, usage = "user"},
				}
			end
			local st = {authkey = state.DEFAULT_KEY, adopted = true, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap"}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			ufuci.get_vap_table = orig_vaps

			local by_essid = {}
			for _, v in ipairs(d.vap_table) do by_essid[v.essid] = v end
			assert_eq(by_essid["test"].num_sta, 2,
				"the WLAN whose netdev has the stations reports them")
			assert_eq(by_essid["guest"].num_sta, 0,
				"the other WLAN on the same radio reports none of them")
			assert_eq(#by_essid["guest"].sta_table, 0,
				"and nests no borrowed sta_table entries")
		end
	},
	{
		name = "inform json: vap_table num_sta reflects connected clients",
		fn = function()
			local d = build({with_uci = true, with_clients = true})
			assert_eq(#d.vap_table, 1, "one vap")
			assert_eq(d.vap_table[1].num_sta, 2, "two clients from fixture")
		end
	},
	{
		name = "inform json: vap_table num_sta is 0 with no clients",
		fn = function()
			local d = build({with_uci = true, with_clients = false})
			assert_eq(d.vap_table[1].num_sta, 0, "no clients")
		end
	},
	{
		name = "inform json: vap_table avg_client_signal averages connected clients' signal",
		fn = function()
			local d = build({with_uci = true, with_clients = true})
			-- fixture clients: -62 dBm and -75 dBm -> floor(-137/2) = -69
			assert_eq(d.vap_table[1].avg_client_signal, -69, "mean of the two fixture clients' signal")
		end
	},
	{
		name = "inform json: vap_table avg_client_signal is omitted with no clients",
		fn = function()
			local d = build({with_uci = true, with_clients = false})
			assert_true(d.vap_table[1].avg_client_signal == nil,
				"no clients means no valid average to report")
		end
	},
	{
		name = "inform json: radio_table_stats carries per-radio TX counters and retry pct",
		fn = function()
			-- Without these the controller's own entry ended up
			-- tx_packets=243, tx_retries=0, tx_retries_pct=100 -- rendering a
			-- permanent "TX Retries: High (100%)" on an AP whose real rate is
			-- a few percent. It does not derive them from the vap_table copies
			-- it already holds.
			local d = build({with_uci = true, with_clients = true})
			local rs = d.radio_table_stats[1]
			local vap = d.vap_table[1]
			assert_eq(rs.tx_packets, vap.tx_packets, "radio sums its VAPs' packets")
			assert_eq(rs.tx_retries, vap.tx_retries, "and their retries")
			local attempts = rs.tx_packets + rs.tx_retries
			assert_eq(rs.tx_retries_pct, math.floor(rs.tx_retries * 100 / attempts + 0.5),
				"pct is retries over total attempts, matching sta_table's definition")
			assert_true(rs.tx_retries_pct >= 0 and rs.tx_retries_pct <= 100,
				"and is a percentage")
		end
	},
	{
		name = "inform json: wifi_tx_attempts/dropped are reported per VAP and per radio",
		fn = function()
			-- The controller aggregates this pair upward into stat.ap
			-- ("<band>-wifi_tx_attempts", "radio0-wifi_tx_attempts", ...) and
			-- divides them to get a rate. openUF sent them per STATION only,
			-- so every aggregate sat at 0 and the division degenerated into
			-- the permanent "TX Retries: High (100%)" on the Devices view.
			local d = build({with_uci = true, with_clients = true})
			local vap, rs = d.vap_table[1], d.radio_table_stats[1]
			assert_eq(vap.wifi_tx_attempts, vap.tx_packets + vap.tx_retries,
				"attempts are successful + retried, as sta_table defines them")
			assert_eq(vap.wifi_tx_dropped, vap.tx_dropped, "dropped is the driver's tx_failed")
			assert_eq(rs.wifi_tx_attempts, vap.wifi_tx_attempts,
				"radio sums its VAPs' attempts")
			assert_eq(rs.wifi_tx_dropped, vap.wifi_tx_dropped, "and their drops")
			-- The per-station field this aggregates must still be there.
			assert_not_nil(vap.sta_table[1].wifi_tx_attempts, "per-station copy kept")
		end
	},
	{
		name = "inform json: no retry percentage is reported when nothing was transmitted",
		fn = function()
			-- A client associated but idle: 0% and 100% are both lies about a
			-- radio that has transmitted nothing, so the field is absent.
			-- (Built with clients so radio_table_stats entries exist at all --
			-- with none, this would assert on nothing.)
			local orig = inform._sysinfo.sta_table
			inform._sysinfo.sta_table = function()
				return {{mac = "aa:bb:cc:dd:ee:01", signal = -50,
					tx_packets = 0, tx_retries = 0, rx_packets = 0,
					tx_bytes = 0, rx_bytes = 0}}
			end
			local ok, err = pcall(function()
				local d = build({with_uci = true, with_clients = true})
				local rs = d.radio_table_stats[1]
				assert_not_nil(rs, "fixture sanity: a radio entry exists to check")
				assert_eq(rs.tx_packets, 0, "and it really did transmit nothing")
				assert_true(rs.tx_retries_pct == nil, "no attempts -> no percentage")
			end)
			inform._sysinfo.sta_table = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform json: satisfaction is aggregated to the vap and the device",
		fn = function()
			-- The controller does not derive these from the per-client scores
			-- it already holds: without them the Devices list showed
			-- "No Clients" in the Experience column on an AP with eight
			-- connected clients, each individually scored in the Clients view.
			local d = build({with_uci = true, with_clients = true})
			local vap = d.vap_table[1]
			assert_not_nil(vap.satisfaction, "vap carries a satisfaction score")
			assert_true(vap.satisfaction >= 0 and vap.satisfaction <= 100,
				"and it is a percentage")
			assert_not_nil(d.satisfaction, "device carries one too")
			-- Both are means of the same per-client scores, and this fixture
			-- has a single vap, so they must agree.
			assert_eq(d.satisfaction, vap.satisfaction,
				"device mean matches the only vap's mean")
			local sum, n = 0, 0
			for _, s in ipairs(vap.sta_table) do sum, n = sum + s.satisfaction, n + 1 end
			assert_eq(vap.satisfaction, math.floor(sum / n + 0.5),
				"and equals the mean of the clients actually reported")
		end
	},
	{
		name = "inform json: satisfaction is omitted, not zero, when nothing is connected",
		fn = function()
			-- 0 would read as "terrible experience"; absent lets the UI say
			-- "No Clients", which is what is actually true.
			local d = build({with_uci = true, with_clients = false})
			assert_true(d.vap_table[1].satisfaction == nil, "no vap score without clients")
			assert_true(d.satisfaction == nil, "no device score either")
		end
	},
	{
		name = "inform json: vap_table carries cu_total/cu_self_rx/cu_self_tx/cu_interf from its radio",
		fn = function()
			local d = build({with_uci = true, with_clients = true})
			-- same fixture survey data as the radio_table_stats test: cu_total=37,
			-- cu_self_rx=18, cu_self_tx=9, cu_interf=10
			assert_eq(d.vap_table[1].cu_total, 37, "vap cu_total matches its radio's radio_table_stats")
			assert_eq(d.vap_table[1].cu_self_rx, 18, "vap cu_self_rx matches its radio's radio_table_stats")
			assert_eq(d.vap_table[1].cu_self_tx, 9, "vap cu_self_tx matches its radio's radio_table_stats")
			assert_eq(d.vap_table[1].cu_interf, 10, "vap cu_interf matches its radio's radio_table_stats")
		end
	},
	{
		name = "inform json: vap_table nests connected clients as sta_table",
		fn = function()
			inform._sta_stats_cache = {}
			local d = build({with_uci = true, with_clients = true})
			local sta_table = d.vap_table[1].sta_table
			assert_eq(#sta_table, 2, "two entries in sta_table")
			assert_eq(sta_table[1].mac, "aa:bb:cc:dd:ee:ff", "first client mac")
			assert_eq(sta_table[1].ap_mac, "aa:bb:cc:dd:ee:ff", "ap_mac from device mac")
			-- Numeric, matching radio_table: the payload used to mix a live
			-- numeric radio_table channel with a raw UCI *string* here
			-- (including the literal "auto" on ACS radios).
			assert_eq(sta_table[1].channel, 6, "channel from vap, numeric")
			assert_eq(sta_table[1].radio, "ng", "radio from vap (the band, matching vap.radio)")
			assert_true(sta_table[1].active, "active true for a station iw actually lists")
			assert_eq(sta_table[1].signal, -62, "signal from station dump")
			assert_eq(sta_table[1].rssi, -62, "rssi aliases signal (iw doesn't distinguish them)")
			assert_eq(sta_table[1].capacity, 144, "capacity from tx_bitrate floor(144.4)")
			assert_eq(sta_table[1].throughput, 0, "throughput 0 on first sample (no prior delta)")
			assert_eq(sta_table[1].linkscore, 0, "linkscore has no local source -- placeholder")
			assert_eq(sta_table[1].multicast, 0, "multicast has no local source -- placeholder")
			-- Cumulative per-client counters -- confirmed real field names via
			-- the decompiled vapInformProcessor (com.ubnt.service.devmgr.c.
			-- KHUkYjHujLgFBD), which copies these straight off each incoming
			-- sta_table entry and computes its own deltas between informs
			-- (unlike throughput, which openUF pre-computes).
			assert_eq(sta_table[1].rx_bytes, 45678, "rx_bytes from station dump")
			assert_eq(sta_table[1].tx_bytes, 98765, "tx_bytes from station dump")
			assert_eq(sta_table[1].rx_packets, 312, "rx_packets from station dump")
			assert_eq(sta_table[1].tx_packets, 287, "tx_packets from station dump")
			-- tx_rate/rx_rate: controller expects Kbps, iw reports Mbit/s
			assert_eq(sta_table[1].tx_rate, 144400, "tx_rate converted to Kbps from 144.4 Mbit/s")
			assert_eq(sta_table[1].rx_rate, 72200, "rx_rate converted to Kbps from 72.2 Mbit/s")
			assert_eq(sta_table[1].uptime, 3600, "uptime from iw's connected time")
			assert_eq(sta_table[1].idletime, 0, "idletime floored from inactive_ms (120ms -> 0s)")
			-- tx_mcs/rx_mcs: part of the same controller-side wifi-experience-
			-- score input DTO (com.ubnt.service.l.e.AQODNNoMmBlFpWXX) as
			-- tx_rate/rx_rate/signal above. Real wire name is "tx_mcs", not
			-- "tx_mcs_index" (that's only the ucore-message JSON name).
			assert_eq(sta_table[1].tx_mcs, 15, "tx_mcs parsed from iw's 'MCS 15'")
			assert_eq(sta_table[1].rx_mcs, 7, "rx_mcs parsed from iw's 'MCS 7'")
			-- radio_proto/nss: confirmed real per-station wire fields, read
			-- independently of tx_mcs/rx_mcs by the real controller's client
			-- updater (com.ubnt.service.devmgr.TtZhv, confirmed via
			-- decompile) -- without these every station showed as generation
			-- "g" (the controller's own fallback) with no MIMO/stream count,
			-- regardless of tx_mcs/rx_mcs.
			assert_eq(sta_table[1].radio_proto, "n", "radio_proto from iw's bare 'MCS 15' (plain HT)")
			assert_eq(sta_table[1].nss, 2, "nss from MCS 15 -> floor(15/8)+1")
			-- is_11n/is_11ac/is_11ax/is_11be: the fields that ACTUALLY drive
			-- the live (still-connected) client's displayed generation --
			-- confirmed via decompile (com.ubnt.service.devmgr.HCKpgcBFPLu ->
			-- com.ubnt.g.s.jRsSex) that radio_proto's own string value is
			-- ignored entirely for a live client; only these booleans matter.
			assert_true(sta_table[1].is_11n, "plain HT (bare MCS) sets is_11n")
			assert_false(sta_table[1].is_11ac, "not VHT")
			assert_false(sta_table[1].is_11ax, "not HE")
			assert_false(sta_table[1].is_11be, "not EHT")
			-- wifi_tx_attempts/wifi_tx_retries_percentage: tx_packets(287) +
			-- tx_retries(4) = 291 attempts, 4 of them retried.
			assert_eq(sta_table[1].wifi_tx_attempts, 291, "wifi_tx_attempts = tx_packets + tx_retries")
			-- exact value round-trips through cjson's %.14g float encoding,
			-- so compare with a tolerance rather than bit-for-bit equality
			assert_true(math.abs(sta_table[1].wifi_tx_retries_percentage - 4 * 100 / 291) < 1e-10,
				"wifi_tx_retries_percentage = retries as % of attempts")
			-- satisfaction/satisfaction_now: best-effort estimate, worse of
			-- signal-quality score (-62 dBm -> ~65.7 on a -85..-50 scale) and
			-- retry-quality score (~98.6), floored.
			assert_eq(sta_table[1].satisfaction, 65, "satisfaction estimated from signal+retries")
			assert_eq(sta_table[1].satisfaction_now, 65, "satisfaction_now matches satisfaction")
		end
	},
	{
		name = "inform json: vap_table aggregates per-VAP traffic/retry counters from connected stations",
		fn = function()
			-- Real field names confirmed via the decompiled vap-stats DTO
			-- (cVbZoFIZsWYaVCquTr$QCtdvLKOBb) -- the controller UI's
			-- per-device "Air Stats" panel (Tx/Rx Pkts/Bytes, Tx/Rx Retry/
			-- Dropped) reads these. iw(8) only exposes per-station counters,
			-- not an already-aggregated per-VAP one, so build_json sums
			-- across sta_table. Fixture has two stations: rx_bytes
			-- 45678+1024, tx_bytes 98765+2048, rx_packets 312+8, tx_packets
			-- 287+12, tx_retries 4+0, tx_failed(->tx_dropped) 0+0.
			local d = build({with_uci = true, with_clients = true})
			local vap = d.vap_table[1]
			assert_eq(vap.rx_bytes,   46702, "rx_bytes summed across stations")
			assert_eq(vap.tx_bytes,  100813, "tx_bytes summed across stations")
			assert_eq(vap.rx_packets,   320, "rx_packets summed across stations")
			assert_eq(vap.tx_packets,   299, "tx_packets summed across stations")
			assert_eq(vap.tx_retries,     4, "tx_retries summed across stations")
			assert_eq(vap.tx_dropped,     0, "tx_dropped summed from tx_failed across stations")
		end
	},
	{
		name = "inform json: vap_table traffic/retry counters are 0 with no clients",
		fn = function()
			local d = build({with_uci = true, with_clients = false})
			local vap = d.vap_table[1]
			assert_eq(vap.rx_bytes, 0, "no clients -> zero rx_bytes")
			assert_eq(vap.tx_bytes, 0, "no clients -> zero tx_bytes")
			assert_eq(vap.tx_retries, 0, "no clients -> zero tx_retries")
		end
	},
	{
		name = "inform json: sta_table throughput delta-samples between calls",
		fn = function()
			inform._sta_stats_cache = {}
			local orig_time = inform._time
			inform._time = function() return 1000 end
			build({with_uci = true, with_clients = true})  -- first sample, seeds the cache

			-- Bypass build()'s inject_sysinfo() (it would reset _run_cmd to
			-- the standard fixture) so this call can use a custom fixture
			-- with advanced byte counters for the same client.
			inject_ucihelper()
			inform._sysinfo._run_cmd = function(cmd)
				if cmd:find("station dump") then
					return "Station aa:bb:cc:dd:ee:ff (on wlan0)\n" ..
						"\trx bytes:\t55678\n\ttx bytes:\t108765\n" ..
						"\tsignal:  \t-62 dBm\n\ttx bitrate:\t144.4 MBit/s MCS 15 short GI\n"
				end
				return ""
			end
			inform._time = function() return 1010 end  -- 10s later
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			-- delta = (55678-45678) + (108765-98765) = 20000 bytes over 10s = 2000 B/s
			assert_eq(d.vap_table[1].sta_table[1].throughput, 2000,
				"throughput = byte delta / elapsed seconds")

			inform._time = orig_time
			inform._sta_stats_cache = {}
		end
	},
	{
		name = "inform json: the throughput cache forgets a station that left",
		fn = function()
			-- _sta_stats_cache is keyed by CLIENT MAC and was never emptied,
			-- so on a daemon that runs for months in a place with transient
			-- clients it only ever grew. A station back after the window is a
			-- fresh association, and its 0-throughput first sample is honest.
			inform._sta_stats_cache = {}
			local orig_time = inform._time
			inform._time = function() return 1000 end
			build({with_uci = true, with_clients = true})   -- seeds one station
			local seeded = 0
			for _ in pairs(inform._sta_stats_cache) do seeded = seeded + 1 end
			assert_eq(seeded, 2, "both connected stations are cached")

			-- A later payload on which that station no longer appears.
			inform._time = function() return 1000 + inform.STA_STATS_FORGET_AFTER + 1 end
			build({with_uci = true})                        -- no clients this time
			local left = 0
			for _ in pairs(inform._sta_stats_cache) do left = left + 1 end
			assert_eq(left, 0, "and dropped once it has been gone for the whole window")

			inform._time = orig_time
			inform._sta_stats_cache = {}
		end
	},
	{
		name = "inform json: radio_table_stats derived from survey dump",
		fn = function()
			local d = build({with_uci = true, with_clients = true})
			assert_eq(#d.radio_table_stats, 1, "one radio_table_stats entry")
			assert_eq(d.radio_table_stats[1].name, "radio0", "keyed by radio name")
			assert_eq(d.radio_table_stats[1].cu_total, 37, "cu_total = busy/total*100")
			assert_eq(d.radio_table_stats[1].cu_self_rx, 18, "cu_self_rx = channel_time_rx/total*100")
			assert_eq(d.radio_table_stats[1].cu_self_tx, 9, "cu_self_tx = channel_time_tx/total*100")
			assert_eq(d.radio_table_stats[1].cu_interf, 10, "cu_interf = cu_total - cu_self_rx - cu_self_tx")
		end
	},
	{
		name = "inform json: radio_table entries carry a nested athstats object for the stat archiver",
		fn = function()
			local d = build({with_uci = true, with_clients = true})
			local radio = d.radio_table[1]
			assert_not_nil(radio.athstats, "radio_table entry has athstats")
			assert_eq(radio.athstats.cu_total, 37, "athstats.cu_total matches radio_table_stats")
			assert_eq(radio.athstats.cu_self_rx, 18, "athstats.cu_self_rx matches radio_table_stats")
			assert_eq(radio.athstats.cu_self_tx, 9, "athstats.cu_self_tx matches radio_table_stats")
			assert_eq(radio.athstats.cu_interf, 10, "athstats.cu_interf matches radio_table_stats")
		end
	},
	{
		-- "Minimum RSSI" (Devices -> [AP] -> Radios) is per-radio -- confirmed
		-- live 2026-07-14. min_rssi/min_rssi_enabled are the confirmed
		-- outbound field names (decompiled alongside radio_caps/tx_power/
		-- athstats in the same DTO). The UCI-stored value is raw wire units
		-- (an offset from the driver's noise floor, not dBm) -- build_json
		-- converts it using the live noise reading from radio_stats()'s
		-- survey dump (fixture noise: -95 dBm; raw 25 -> -95+25 = -70 dBm).
		name = "inform json: radio_table converts min_rssi from raw wire units to dBm using live noise floor",
		fn = function()
			inject_sysinfo(true)
			inject_ucihelper()
			inform._ucihelper.get_radio_table = function()
				return {
					{ name = "radio0", radio = "ng", channel = "6", ht = "HT20", tx_power = "20",
					  disabled = false, builtin_antenna = true, builtin_ant_gain = 3,
					  max_txpower = 20, min_rssi_enabled = true, min_rssi_raw = 25 },
				}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			assert_eq(d.radio_table[1].min_rssi_enabled, true, "min_rssi_enabled echoed")
			assert_eq(d.radio_table[1].min_rssi, -70, "min_rssi converted: 25 + (-95 noise) = -70 dBm")
			assert_nil(d.radio_table[1].min_rssi_raw, "raw wire units not leaked into the outbound payload")
		end
	},
	{
		-- Inconsistent UCI (flag set, threshold missing -- hand-edit or an
		-- interrupted write) used to be `nil + noise`, killing the whole
		-- inform build.
		name = "inform json: min_rssi_enabled without a raw value doesn't kill the build",
		fn = function()
			inject_sysinfo(true)
			inject_ucihelper()
			inform._ucihelper.get_radio_table = function()
				return {
					{ name = "radio0", radio = "ng", channel = "6",
					  min_rssi_enabled = true },  -- no min_rssi_raw
				}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			assert_eq(d.radio_table[1].min_rssi_enabled, true, "flag still echoed")
			assert_nil(d.radio_table[1].min_rssi, "no min_rssi emitted without a raw value")
		end
	},
	{
		-- The raw-units cleanup used to sit inside the ifname-resolved branch,
		-- so a radio whose netdev couldn't be resolved (radio down, ubus
		-- unavailable) leaked the internal wire-units field to the controller.
		name = "inform json: min_rssi_raw doesn't leak into the payload when ifname is unresolvable",
		fn = function()
			inject_sysinfo(true)
			inject_ucihelper()
			inform._ucihelper.get_radio_table = function()
				return {
					-- "radio9": the mock get_ifname_for_radio resolves only
					-- radio0, so this radio's ifname lookup fails.
					{ name = "radio9", radio = "ng", channel = "6",
					  min_rssi_enabled = true, min_rssi_raw = 15 },
				}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			assert_nil(d.radio_table[1].min_rssi_raw, "internal raw field stripped even without an ifname")
		end
	},
	{
		-- Enforcement: a station below the radio's minrssi threshold gets a
		-- single deauth via ucihelper.kick_station -- confirmed via web
		-- research this is a one-shot roaming-assist kick, not a persistent
		-- block, so it's deliberately separate from firewall.lua's
		-- block-sta feature (no nftables, no state.json).
		name = "inform json: stations below the radio's minrssi threshold get kicked, others don't",
		fn = function()
			inject_sysinfo(true)  -- fixture: aa:bb:cc:dd:ee:ff at -62 dBm, 11:22:33:44:55:66 at -75 dBm
			inject_ucihelper()
			inform._ucihelper.get_radio_table = function()
				return {
					{ name = "radio0", radio = "ng", channel = "6",
					  min_rssi_enabled = true, min_rssi_raw = 25 },  -- threshold: 25 + (-95) = -70 dBm
				}
			end
			local kicked = {}
			inform._ucihelper.kick_station = function(ifname, mac)
				kicked[#kicked + 1] = {ifname = ifname, mac = mac}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			inform.build_json(st, nil, ufhw)
			assert_eq(#kicked, 1, "exactly one station kicked")
			assert_eq(kicked[1].mac, "11:22:33:44:55:66", "the -75 dBm station (below -70 threshold) is kicked")
			assert_eq(kicked[1].ifname, "wlan0", "kicked on the resolved live ifname")
		end
	},
	{
		name = "inform json: no stations kicked when the radio's minrssi is disabled",
		fn = function()
			inject_sysinfo(true)
			inject_ucihelper()  -- default mock radio_table has no min_rssi_enabled
			local kicked = {}
			inform._ucihelper.kick_station = function(ifname, mac)
				kicked[#kicked + 1] = {ifname = ifname, mac = mac}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			inform.build_json(st, nil, ufhw)
			assert_eq(#kicked, 0, "no stations kicked when minrssi is not enabled")
		end
	},
	{
		name = "inform json: empty list fields serialize as JSON arrays, not objects",
		fn = function()
			-- cjson encodes an empty Lua table as {} (a JSON object); the
			-- controller's DTOs type these fields as lists. Only a raw-string
			-- assertion can see the difference -- every other test in this
			-- file decodes first, which erases exactly this distinction.
			inject_sysinfo(false)
			-- A previously injected _ucihelper mock would populate the very
			-- tables this test needs empty -- park it for the duration.
			local orig_uci = inform._ucihelper
			inform._ucihelper = nil
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local ok, json_str = pcall(inform.build_json, st, nil, ufhw)
			inform._ucihelper = orig_uci
			assert_true(ok, "build_json succeeded: " .. tostring(json_str))
			for _, field in ipairs({"vap_table", "radio_table", "radio_table_stats",
					"scan_radio_table", "lldp_table"}) do
				assert_contains(json_str, '"' .. field .. '":[]',
					field .. " serializes as an empty ARRAY")
			end
		end
	},
	{
		name = "inform json: _fix_empty_arrays rewrites {} to [] on old-cjson targets",
		fn = function()
			-- The validation container's lua-cjson has neither empty_array_mt
			-- nor the empty_array sentinel, so the metatable route degrades
			-- to {} exactly on the real target -- the string post-pass is
			-- what actually fixes the wire there. Pin it directly.
			local fixed = inform._fix_empty_arrays(
				'{"vap_table":{},"sta_table":{},"x":1,"nested":{"mac_table":{}}}')
			assert_eq(fixed,
				'{"vap_table":[],"sta_table":[],"x":1,"nested":{"mac_table":[]}}',
				"every known list field rewritten, other keys untouched")
			-- A non-list field named similarly must be untouched, and a quoted
			-- occurrence inside a STRING VALUE cannot match (cjson escapes the
			-- quotes there).
			local hostile = '{"ssid":"evil\\"sta_table\\":{}","sta_table":{}}'
			assert_eq(inform._fix_empty_arrays(hostile),
				'{"ssid":"evil\\"sta_table\\":{}","sta_table":[]}',
				"escaped quotes inside string values never match")
		end
	},
	{
		name = "inform json: country_code derived from the radio's UCI regdomain",
		fn = function()
			inject_sysinfo(false)
			inject_ucihelper()
			inform._ucihelper.get_radio_table = function()
				return {
					{ name = "radio0", radio = "ng", channel = 6, country = "CZ" },
				}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			assert_eq(d.country_code, 203, "UCI country=CZ -> ISO numeric 203 (was hardcoded 840)")
			assert_nil(d.radio_table[1].country, "internal country field stripped from the payload")
		end
	},
	{
		name = "inform json: country_code falls back to 840 without a UCI regdomain",
		fn = function()
			local d = build({with_uci = true})
			assert_eq(d.country_code, 840, "no country option anywhere -> historic US default")
		end
	},
	{
		name = "inform json: ACS radio's band is re-derived from the live channel (real ucihelper)",
		fn = function()
			-- The inject_ucihelper mock hardcodes radio="ng" and so bypasses
			-- the real band derivation entirely -- this test wires the REAL
			-- ucihelper to a minimal mock cursor instead. Worst case on
			-- purpose: UCI holds only channel=auto (no band, no hwmode), for
			-- which the config-first derivation still guesses "na" -- but the
			-- live iw fixture has negotiated channel 6, which must win.
			-- Pre-fix the payload reported this 2.4GHz radio as "na" (5GHz).
			inject_sysinfo(false, false, false, true)  -- with_radio_caps
			local real_uci = dofile("openuf/ucihelper.lua")
			local sections = {
				{[".name"] = "radio0", [".type"] = "wifi-device", channel = "auto"},
				{[".name"] = "openuf_radio0_test", [".type"] = "wifi-iface",
				 device = "radio0", ssid = "test", encryption = "psk2"},
			}
			real_uci._uci = {cursor = function() return {
				foreach = function(_, config, stype, fn)
					if config ~= "wireless" then return end
					for _, s in ipairs(sections) do
						if s[".type"] == stype then fn(s) end
					end
				end,
				get = function() return nil end,
				set = function() end,
				delete = function() end,
				commit = function() end,
			} end}
			real_uci._popen = function(cmd)
				if cmd:find("network.wireless", 1, true) then
					return '{"radio0":{"interfaces":[{"ifname":"wlan0"}]}}'
				end
				return ""
			end
			real_uci._read_file = function() return nil end
			real_uci._run_cmd = function() return true end

			local orig = inform._ucihelper
			inform._ucihelper = real_uci
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			inform._ucihelper = orig
			assert_eq(d.radio_table[1].channel, 6, "live negotiated channel reported, not 'auto'")
			assert_eq(d.radio_table[1].radio, "ng", "band re-derived from the live channel")
			-- The vap inherits the same live correction -- its UCI echo was
			-- the literal string "auto" here, and used to go out as-is.
			assert_eq(d.vap_table[1].channel, 6, "vap channel overridden with the live value")
			assert_eq(d.vap_table[1].radio, "ng", "vap band matches the corrected radio band")
			-- tx_power has the same UCI-echo problem: the option is absent
			-- while Transmit Power is Auto, so both copies stayed nil.
			assert_eq(d.radio_table[1].tx_power, 20, "radio reports the live driver TX power")
			assert_eq(d.vap_table[1].tx_power, 20, "and the vap inherits the same correction")
		end
	},
	{
		name = "inform json: a 5GHz ACS radio's band re-derives to na from the live channel",
		fn = function()
			-- The na twin of the "ng" re-derivation test above: without it an
			-- inverted band mapping on the 5GHz side passes the whole suite.
			-- Same real-ucihelper wiring, but the live iw fixture negotiated
			-- channel 36 (5180 MHz).
			inject_sysinfo(false, false, false, true)
			inform._sysinfo._run_cmd = function(cmd)
				if cmd:find("dev wlan0 info") then return fixture("iw_dev_info_5g.txt") end
				if cmd:find("phy phy0 info") then return fixture("iw_phy_info_5g.txt") end
				return ""
			end
			local real_uci = dofile("openuf/ucihelper.lua")
			local sections = {
				{[".name"] = "radio1", [".type"] = "wifi-device", channel = "auto"},
			}
			real_uci._uci = {cursor = function() return {
				foreach = function(_, config, stype, fn)
					if config ~= "wireless" then return end
					for _, s in ipairs(sections) do
						if s[".type"] == stype then fn(s) end
					end
				end,
				get = function() return nil end,
				set = function() end,
				delete = function() end,
				commit = function() end,
			} end}
			real_uci._popen = function(cmd)
				if cmd:find("network.wireless", 1, true) then
					return '{"radio1":{"interfaces":[{"ifname":"wlan0"}]}}'
				end
				return ""
			end
			real_uci._read_file = function() return nil end
			real_uci._run_cmd = function() return true end

			local orig = inform._ucihelper
			inform._ucihelper = real_uci
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			inform._ucihelper = orig
			assert_eq(d.radio_table[1].channel, 36, "live negotiated 5GHz channel reported")
			assert_eq(d.radio_table[1].radio, "na", "band re-derived to na from channel 36")
		end
	},
	{
		name = "inform json: radio_table_stats includes spectrum_table when cached from a prior spectrum-scan cmd",
		fn = function()
			inform._spectrum_cache = {
				radio0 = {
					table = { { channel = 6, center_freq = 2437, width = 20, utilization = 37, interference = -95 } },
					table_time = 111,
					scan_timestamp = 222,
				},
			}
			local d = build({with_uci = true, with_clients = true})
			local rts = d.radio_table_stats[1]
			-- spectrum_scanning/spectrum_scan_timestamp are device-level
			-- (top-level payload) fields, not per-radio.
			assert_eq(d.spectrum_scanning, false, "spectrum_scanning false once results are cached")
			assert_eq(d.spectrum_scan_timestamp, 222, "spectrum_scan_timestamp from cache")
			assert_eq(rts.spectrum_table_time, 111, "spectrum_table_time from cache")
			assert_eq(#rts.spectrum_table, 1, "one spectrum_table entry")
			assert_eq(rts.spectrum_table[1].channel, 6, "spectrum_table entry channel")
			inform._spectrum_cache = {}
		end
	},
	{
		name = "inform json: radio_table_stats omits spectrum_table without a prior spectrum-scan cmd",
		fn = function()
			inform._spectrum_cache = {}
			local d = build({with_uci = true, with_clients = true})
			assert_true(d.radio_table_stats[1].spectrum_table == nil,
				"no spectrum_table until a spectrum-scan cmd has run")
			assert_true(d.spectrum_scan_timestamp == nil,
				"no spectrum_scan_timestamp until a spectrum-scan cmd has run")
		end
	},
	{
		name = "inform json: radio_table includes capability defaults",
		fn = function()
			local d = build({with_uci = true})
			assert_eq(d.radio_table[1].builtin_ant_gain, 3, "builtin_ant_gain")
			assert_eq(d.radio_table[1].max_txpower, 20, "max_txpower")
		end
	},
	{
		name = "inform json: radio_table carries hardware capability fields from iw phy info",
		fn = function()
			-- Confirmed via decompile (com.ubnt.service.devmgr.PGOcbDWlbnYQdFW,
			-- copyAttrsIfPresent): the controller reads nss/is_11ac/is_11ax/
			-- is_11be/has_dfs/has_fccdfs/has_ht160 directly off each radio_table
			-- entry, independent of radio_caps/radio_caps2 -- without these,
			-- the Radios (channel-planning) tab's MIMO/capability filters
			-- excluded the device entirely, "We Couldn't Find a Match".
			inject_sysinfo(false, false, false, true)
			inject_ucihelper()
			-- Mock channel deliberately 11 while the iw fixture negotiated 6:
			-- with both at 6 (the old shape) the "live overrides UCI" claim
			-- below was indistinguishable from a plain echo of the mock.
			inform._ucihelper.get_radio_table = function()
				return {
					{ name = "radio0", radio = "ng", channel = 11, ht = "HT20", tx_power = "20",
					  disabled = false, builtin_antenna = true, builtin_ant_gain = 3,
					  max_txpower = 20 },
				}
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			local r = d.radio_table[1]
			assert_true(r.is_11ac, "VHT Capabilities present in the 5GHz fixture")
			assert_true(r.is_11ax, "HE PHY Capabilities present")
			assert_false(r.is_11be, "no EHT PHY Capabilities in the fixture")
			assert_true(r.has_dfs, "radar detection present on several channels")
			assert_true(r.has_fccdfs, "has_fccdfs mirrors has_dfs")
			assert_true(r.has_ht160, "'Supported Channel Width: 160 MHz, 80+80 MHz'")
			assert_eq(r.nss, 2, "nss from 'HT TX Max spatial streams: 2'")
			assert_eq(r.channel, 6, "live channel from 'iw dev' overrides UCI's 11")
		end
	},
	{
		name = "inform json: radio_table entries carry the correct radio_caps MIMO bitmask",
		fn = function()
			-- radio_caps is a genuine separate integer field (confirmed via
			-- decompile, `uCthhvfQNZ3.getInt("radio_caps", 0)`), not the
			-- flattened is_11ac/nss/etc. booleans -- openUF previously always
			-- left it at the controller's own default of 0, which is why the
			-- Radios tab's MIMO column stayed blank and its 1x1-4x4 filter
			-- excluded every radio outright ("We Couldn't Find a Match").
			-- The bit layout is NOT "value == nss" (confirmed live: sending
			-- radio_caps=2 for a 2x2 radio still showed blank/excluded) --
			-- it's a bitmask, reverse engineered by calling the controller's
			-- own live MIMO decoder (webpack module 927316's `e7` export)
			-- directly with a sweep of single-bit values: bit 3 (0x8) ->
			-- "1x1", bit 4 (0x10) -> "2x2", bit 5 (0x20) -> "3x3", bit 26
			-- (0x4000000) -> "4x4", checked highest-first when multiple bits
			-- are set. Confirmed live end-to-end 2026-07-14: a genuinely 2x2
			-- radio_caps=0x10 now renders "2x2" in the MIMO column and is
			-- included by the 2x2 filter checkbox.
			local d = build({with_uci = true, with_radio_caps = true})
			local r = d.radio_table[1]
			assert_eq(r.nss, 2, "fixture radio is 2x2 (nss=2)")
			assert_eq(r.radio_caps, 0x10, "radio_caps carries the bit 4 (0x10) MIMO flag for a 2x2 radio")
		end
	},
	{
		name = "inform json: radio_table carries radio_caps2 bit 0x1 -- the WPA3 gate",
		fn = function()
			-- This bit is the ONLY thing that makes the controller provision
			-- WPA3/SAE to a device. Traced through the 10.4.57 bytecode:
			-- the config generator (QSAkfnbfInKJ) calls radio.CVir(), which
			-- is (1 & ZPjpXpgFhJSgqk().orElse(0)) == 1; that accessor returns
			-- impl field iBjnA, fed from builder field SuUD, whose only
			-- setter the radio parser calls with getInt("radio_caps2").
			-- radio_caps goes somewhere else entirely (builder kJeOrfqt ->
			-- impl DbisCuTqoItCGd -> accessor FJaWnIAautY, the MIMO column).
			--
			-- Confirmed live end-to-end 2026-08-01 on real hardware: with
			-- this field absent every WPA3 WLAN was silently downgraded to
			-- WPA-PSK; adding it flipped the very next push to
			-- wpa.key.1.mgmt=SAE + wpa3.support/transition + sae.*, and both
			-- APs came up with hostapd key_mgmt "SAE FT-SAE WPA-PSK
			-- WPA-PSK-SHA256 FT-PSK". Losing this bit re-breaks WPA3
			-- entirely, and nothing else on the wire would say so.
			-- Gated on real SAE support, so both arms are pinned: claiming
			-- the bit on a build whose hostapd cannot do SAE would make the
			-- controller push a config the radio then fails to start.
			local prev = inform._sysinfo._sae_supported_cache
			inform._sysinfo._sae_supported_cache = true
			local d = build({with_uci = true, with_radio_caps = true})
			assert_eq(#d.radio_table > 0, true, "fixture produced radios")
			for _, r in ipairs(d.radio_table) do
				assert_eq(r.radio_caps2, 0x1,
					"SAE-capable: radio_caps2 bit 0x1 set, so the controller provisions WPA3")
			end

			inform._sysinfo._sae_supported_cache = false
			local d2 = build({with_uci = true, with_radio_caps = true})
			for _, r in ipairs(d2.radio_table) do
				assert_eq(r.radio_caps2, 0,
					"no SAE: the bit is NOT claimed, so no unrunnable config is pushed")
			end
			inform._sysinfo._sae_supported_cache = prev
		end
	},
	{
		name = "inform json: scan_radio_table reports neighboring networks per radio",
		fn = function()
			-- Confirmed real field names via the decompiled controller's
			-- ingestion DTOs (com.ubnt.service.aO.bLwwMKkr, literally named
			-- "PeerScan", and its consumer com.ubnt.service.aO.hhFgUVZPT) --
			-- a top-level scan_radio_table, one entry per radio, each
			-- carrying that radio's own scan_table list. Feeds Insights ->
			-- AirView -> Environment (stat/rogueap), distinct from the
			-- RF/spectrum-scan cmd's channel-utilization-only spectrum_table.
			-- Confirmed live 2026-07-14: the wire field is `age` (elapsed
			-- seconds), NOT `last_seen` -- the controller computes the
			-- absolute last_seen itself as (report_time - age), and drops
			-- any entry with age >= 30 as stale before it ever reaches the
			-- rogue-AP list, so sending an absolute timestamp under either
			-- name is silently ignored.
			local d = build({with_uci = true, with_scan = true})
			assert_eq(#d.scan_radio_table, 1, "one scan_radio_table entry (one configured radio)")
			local srt = d.scan_radio_table[1]
			assert_eq(srt.radio, "ng", "radio band from radio_table entry")
			assert_eq(srt.name, "radio0", "radio device name from radio_table entry")
			assert_eq(#srt.scan_table, 2, "two neighbor networks from the fixture")
			assert_eq(srt.scan_table[1].bssid, "aa:bb:cc:dd:ee:01", "first neighbor bssid")
			assert_eq(srt.scan_table[1].mac, "aa:bb:cc:dd:ee:01", "first neighbor mac mirrors bssid")
			assert_eq(srt.scan_table[1].band, "ng", "first neighbor band mirrors the parent radio's band")
			assert_eq(srt.scan_table[1].essid, "NeighborNet", "first neighbor essid")
			assert_eq(srt.scan_table[1].channel, 6, "first neighbor channel")
			assert_eq(srt.scan_table[1].signal, -55, "first neighbor signal")
			assert_eq(srt.scan_table[1].rssi, -55, "first neighbor rssi mirrors signal")
			assert_eq(srt.scan_table[1].security, "wpa2", "first neighbor security")
			assert_eq(srt.scan_table[1].age, 0, "first neighbor age (elapsed seconds, not a timestamp)")
			assert_eq(srt.scan_table[1].bw, 40, "first neighbor bw (Environment tab's Ch. Width column reads this directly)")
			assert_eq(srt.scan_table[2].bw, 20, "second neighbor bw defaults to 20 when iw reports no width")
			assert_eq(srt.scan_table[2].essid, "OpenGuestWifi", "second neighbor essid")
			assert_eq(srt.scan_table[2].security, "open", "second neighbor security")
		end
	},
	{
		name = "inform json: 802.11k beacon reports enrich scan_radio_table",
		fn = function()
			-- The whole point of rrmscan.lua: the passive `iw scan dump` cache
			-- only ever holds neighbours on the channel the radio is already
			-- serving, so BSSes a CLIENT saw off-channel have to reach the
			-- payload through here or they reach it not at all.
			local prev = inform._rrm_neighbours
			inform._rrm_neighbours = {
				-- a BSS the passive scan already found -- must NOT be
				-- duplicated, and must keep the scan's richer record
				{bssid = "aa:bb:cc:dd:ee:01", channel = 6, band = "ng",
				 signal = -70, seen_at = os.time()},
				-- one only the client could see
				{bssid = "84:78:48:a4:fb:21", channel = 1, band = "ng",
				 signal = -73, seen_at = os.time()},
				-- and one on the other band, which belongs to no radio here
				{bssid = "54:af:97:55:14:78", channel = 48, band = "na",
				 signal = -80, seen_at = os.time()},
			}
			local ok, d = pcall(build, {with_uci = true, with_scan = true})
			inform._rrm_neighbours = prev
			assert_true(ok, "build_json survives the merge")

			local srt = d.scan_radio_table[1]
			assert_eq(srt.radio, "ng", "the 2.4 GHz radio")
			local seen = {}
			for _, e in ipairs(srt.scan_table) do
				assert_nil(seen[e.bssid], "no BSSID appears twice: " .. tostring(e.bssid))
				seen[e.bssid] = e
			end
			assert_eq(#srt.scan_table, 3, "two scanned + one client-only neighbour")
			assert_eq(seen["aa:bb:cc:dd:ee:01"].essid, "NeighborNet",
				"the scanned record wins over the beacon report")
			assert_eq(seen["aa:bb:cc:dd:ee:01"].signal, -55, "and keeps its own signal")
			local added = seen["84:78:48:a4:fb:21"]
			assert_not_nil(added, "the client-only neighbour reached the payload")
			assert_eq(added.channel, 1, "on the channel the client reported")
			assert_eq(added.signal, -73, "with the RCPI-derived signal")
			-- Without `band` the Environment tab filters the row out upstream
			-- of every visible filter, with no error and no visible cause.
			assert_eq(added.band, "ng", "band set or the row silently vanishes")
			assert_nil(seen["54:af:97:55:14:78"],
				"a 5 GHz sighting is not filed under the 2.4 GHz radio")
		end
	},
	{
		name = "inform json: stale beacon reports never reach the payload",
		fn = function()
			-- The controller drops any entry with age >= 30 before it reaches
			-- the rogue-AP list, so carrying one is payload nobody reads.
			local prev = inform._rrm_neighbours
			inform._rrm_neighbours = {
				{bssid = "84:78:48:a4:fb:21", channel = 1, band = "ng",
				 signal = -73, seen_at = os.time() - 120},
			}
			local ok, d = pcall(build, {with_uci = true, with_scan = true})
			inform._rrm_neighbours = prev
			assert_true(ok, "build_json survives")
			assert_eq(#d.scan_radio_table[1].scan_table, 2,
				"only the two scanned neighbours; the stale sighting is dropped")
		end
	},
	{
		name = "inform json: scan_radio_table entries have empty scan_table with no neighbors detected",
		fn = function()
			local d = build({with_uci = true})
			assert_eq(#d.scan_radio_table, 1, "one scan_radio_table entry")
			assert_eq(#d.scan_radio_table[1].scan_table, 0, "no neighbors without fixtures")
		end
	},
	{
		name = "inform json: fw_caps sets the QCA-switch and OWRT-switch bits (0x110)",
		fn = function()
			-- Confirmed via decompiled controller 10.4.57: Device.hasQCASwitch()
			-- is hasFirmwareCapability(16) (gates the Ports view's projection
			-- of port_table), and Device.hasOWRTSwitch() is
			-- hasFirmwareCapability(256) (without it, the REST API's per-port
			-- VLAN validator rejects any port assignment with
			-- api.err.VlanTaggingUnsupportedByDevice -- see PROTOCOL-VALIDATION.md
			-- section 18).
			local d = build()
			assert_eq(d.fw_caps, 0x110, "fw_caps bits 0x10 | 0x100 set")
		end
	},
	{
		name = "inform json: wifi_caps2 sets the advertise-device-name-in-beacon bit (0x40)",
		fn = function()
			-- Confirmed via decompiling the controller: Device.
			-- supportAdvertisingDeviceNameInBeacon() is hasWifiCapability2(64)
			-- -- a SEPARATE bitmask from fw_caps/wifi_caps -- and gates whether
			-- wireless.<n>.advertise_ap_name is ever pushed to system_cfg at
			-- all for "Show Access Point Name in Beacon". Only this bit is
			-- claimed (see PROTOCOL-VALIDATION.md for the other wifi_caps2
			-- bits this device does not implement/claim).
			local d = build()
			assert_eq(d.wifi_caps2, 0x40, "wifi_caps2 bit 0x40 set")
		end
	},
	{
		name = "inform json: port_table has one entry per configured port, 1-based port_idx",
		fn = function()
			-- No cfg passed (build() always calls build_json with cfg=nil), so
			-- port_table falls back to the default {uplink=eth0, lan=eth1} --
			-- matching proc_net_dev.txt's interfaces.
			local d = build()
			assert_not_nil(d.port_table, "port_table present")
			assert_eq(#d.port_table, 2, "two ports (uplink + lan) from the fallback default")
			assert_eq(d.port_table[1].port_idx, 1, "first port_idx is 1-based")
			assert_eq(d.port_table[2].port_idx, 2, "second port_idx")
		end
	},
	{
		name = "inform json: port_table reports the link speed the kernel negotiated",
		fn = function()
			-- speed/full_duplex used to be hardcoded 1000/full, so the Ports
			-- view claimed "GbE" on every device and every board regardless of
			-- what the link actually came up at -- a reported metric that was
			-- never measured.
			local orig = inform._read_file
			inform._read_file = function(path)
				if path == "/sys/class/net/eth0/speed"  then return "100\n"  end
				if path == "/sys/class/net/eth0/duplex" then return "half\n" end
				if path == "/sys/class/net/eth1/speed"  then return "1000\n" end
				if path == "/sys/class/net/eth1/duplex" then return "full\n" end
				return nil
			end
			local ok, err = pcall(function()
				local d = build()
				assert_eq(d.port_table[1].speed, 100, "uplink reports its real 100Mbit link")
				assert_false(d.port_table[1].full_duplex, "and its real half duplex")
				assert_eq(d.port_table[2].speed, 1000, "the gigabit port reports 1000")
				assert_true(d.port_table[2].full_duplex, "and full duplex")
			end)
			inform._read_file = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform json: port_table reports one entry per socket, at the socket's own speed",
		fn = function()
			-- The board has four sockets behind a switch and two CPU netdevs.
			-- Reporting a netdev as "the port" reported the internal
			-- SoC<->switch link -- always 1000/full -- so a WDR3500 whose
			-- uplink socket had negotiated 100baseT told the controller GbE,
			-- contradicting the gateway's own view of the same cable.
			local d = build_switch({
				cfg = switch_cfg(WDR_MAP),
				swconfig = fixture("swconfig_show_ar9344.txt"),
			})
			assert_eq(#d.port_table, 4, "one entry per socket, not one per netdev")
			local p = by_idx(d.port_table)
			assert_eq(p[4].speed, 100, "the uplink socket's real 100baseT link")
			assert_true(p[4].full_duplex, "and its duplex")
			assert_eq(p[3].speed, 100, "a downstream socket reports its own speed")
			assert_false(p[1].up, "an empty socket has no link")
			assert_eq(p[1].speed, 0, "and no speed, rather than the 1000 fallback")
		end
	},
	{
		name = "inform json: is_uplink follows the cable, not the modelmap",
		fn = function()
			-- Same code, same network, two boards with the cable in different
			-- sockets. Nothing in either modelmap names an uplink: getting it
			-- wrong would either hide the real uplink's traffic or report the
			-- whole LAN segment as hosts plugged into the AP.
			local d = build_switch({
				cfg = switch_cfg(WDR_MAP),
				swconfig = fixture("swconfig_show_ar9344.txt"),
			})
			local p = by_idx(d.port_table)
			assert_true(p[4].is_uplink, "physical 4 carries the gateway here")
			assert_false(p[3].is_uplink, "and no other socket claims to")

			local d2 = build_switch({
				cfg = switch_cfg(ARCHER_MAP),
				swconfig = fixture("swconfig_show_ar8327.txt"),
			})
			local p2 = by_idx(d2.port_table)
			assert_eq(#d2.port_table, 5, "four LAN sockets plus the WAN socket")
			assert_true(p2[1].is_uplink, "lan1 (physical 2) carries the gateway on this board")
			assert_false(p2[4].is_uplink, "not the socket the other board used")
		end
	},
	{
		name = "inform json: a DSA board reports each socket from its own netdev",
		fn = function()
			-- No swconfig, no ARL, and none needed: on DSA every socket is a
			-- netdev, so sysfs is already per-socket rather than describing
			-- the internal CPU link the way it does on ath79.
			local d = build_dsa()
			assert_eq(#d.port_table, 4, "one entry per socket")
			local p = by_idx(d.port_table)
			assert_true(p[1].up, "the cabled socket is up")
			assert_eq(p[1].speed, 1000, "at the speed it negotiated")
			assert_true(p[1].full_duplex, "and its duplex")
			assert_false(p[2].up, "an empty socket has no link")
			assert_eq(p[2].speed, 0, "and no speed, rather than the 1000 fallback")
		end
	},
	{
		name = "inform json: is_uplink follows the cable on DSA too",
		fn = function()
			-- The same discipline the swconfig path established, on the only
			-- source a DSA board has for it. A modelmap constant would be
			-- wrong the moment the cable moves, and the socket wrongly
			-- treated as downstream reports the whole LAN as plugged into it.
			local d = build_dsa()
			local p = by_idx(d.port_table)
			assert_true(p[1].is_uplink, "wan carries the gateway as cabled today")
			assert_true(p[1].mac_table == nil, "so it reports no hosts of its own")
			assert_false(p[2].is_uplink, "and no other socket claims to")

			-- Cable moved to lan3. Nothing in the modelmap changed.
			local moved = build_dsa({
				live = "lan3",
				fdb  = "5a:d6:1f:40:e2:f6 dev lan3 master br-lan \n"
					.. "aa:bb:cc:dd:ee:01 dev lan3 master br-lan \n",
			})
			local q = by_idx(moved.port_table)
			assert_true(q[3].is_uplink, "the flag followed the cable to lan3")
			assert_false(q[1].is_uplink, "and left wan")
			assert_true(q[3].mac_table == nil, "lan3 now suppresses its hosts")
			assert_eq(#q[1].mac_table, 0, "and wan reports its own again")
		end
	},
	{
		name = "inform json: an undetectable DSA uplink falls back, never to nobody",
		fn = function()
			-- Detection that names a socket this board does not report (a
			-- guest bridge port, a stale FDB) must not silently leave every
			-- entry unflagged: the uplink would then publish a mac_table of
			-- the entire far side, which is strictly worse than the static
			-- flag the modelmap can still carry.
			local cfg = {
				net = {
					lan_cpueth = "wan", lan_vlanid = 1,
					ports = {
						{idx = 1, ifname = "wan", uplink = true},
						{idx = 2, ifname = "lan2"},
					},
				},
			}
			local d = build_dsa({cfg = cfg,
				fdb = "5a:d6:1f:40:e2:f6 dev tap0 master br-lan \n"})
			local p = by_idx(d.port_table)
			assert_true(p[1].is_uplink, "fell back to the modelmap's own flag")
			assert_false(p[2].is_uplink, "and only that one")

			-- Gateway not learned at all: same fallback.
			local d2 = build_dsa({cfg = cfg, fdb = ""})
			assert_true(by_idx(d2.port_table)[1].is_uplink, "empty FDB falls back too")
		end
	},
	{
		name = "inform json: DSA wired hosts are reported on the socket they are on",
		fn = function()
			-- The per-port bridge FDB is already per-socket here, so no ARL
			-- equivalent is needed for the host list -- only for deciding
			-- which socket to suppress. The captured dump has nothing on lan3
			-- (that board had one cable in it), so a host is added explicitly
			-- rather than fabricated into the capture.
			local d = build_dsa({fdb = fixture("bridge_fdb_br_dsa.txt")
				.. "aa:bb:cc:dd:ee:01 dev lan3 master br-lan \n"})
			local p = by_idx(d.port_table)
			assert_eq(#p[3].mac_table, 1, "the host plugged into lan3")
			assert_eq(p[3].mac_table[1].mac, "aa:bb:cc:dd:ee:01", "its mac")
			assert_eq(#p[2].mac_table, 0, "and nothing on the empty socket")
		end
	},
	{
		name = "inform json: a DSA payload dumps the bridge FDB once, not once per socket",
		fn = function()
			-- build_json already dumps the whole bridge FDB to find the uplink
			-- socket, and that dump carries every socket's hosts. Each socket
			-- forked `bridge fdb show dev <socket>` for a subset of it anyway.
			-- Asserting the host lists alone cannot catch a regression here:
			-- both sources are the same kernel table and give the same answer,
			-- so only the fork count says which one was asked.
			build_dsa({fdb = fixture("bridge_fdb_br_dsa.txt")
				.. "aa:bb:cc:dd:ee:01 dev lan3 master br-lan \n"})
			assert_eq(dsa_forks.fdb_br, 1, "one dump of the kernel FDB per payload")
			assert_eq(dsa_forks.fdb_dev, 0, "and no per-socket fork at all")
			-- The payload's very first question is the uptime, and scan_table
			-- asks it again per radio as its CLOCK_BOOTTIME reference. The pass
			-- has to be open before that first call, not partway down the
			-- function -- measuring a real heartbeat on hardware is what caught
			-- it still being read twice.
			assert_eq(dsa_forks.uptime, 1, "and /proc/uptime is read once for the payload")
		end
	},
	{
		name = "inform json: wired hosts are reported on the socket they are actually on",
		fn = function()
			-- The bridge FDB puts every wired host behind the one CPU netdev;
			-- only the switch's ARL table says which socket each is on. Until
			-- this, hosts plugged into an AP were reported by nobody and the
			-- controller attributed them to the gateway's port instead.
			local d = build_switch({
				cfg = switch_cfg(WDR_MAP),
				swconfig = fixture("swconfig_show_ar9344.txt"),
			})
			local p = by_idx(d.port_table)
			assert_eq(#p[3].mac_table, 1, "the host on socket 3")
			assert_eq(p[3].mac_table[1].mac, "aa:bb:cc:dd:ee:0c", "its mac")
			assert_eq(p[3].mac_table[1].ip, "10.0.0.50", "its ip, joined from arp")
			assert_eq(#p[2].mac_table, 0, "a socket with nothing on it reports no hosts")
			-- The uplink socket has learned the entire LAN, gateway included.
			assert_true(p[4].mac_table == nil,
				"the uplink reports no hosts -- everything there is on the far side")
		end
	},
	{
		name = "inform json: hosts on a socket outside the management VLAN are not reported",
		fn = function()
			-- The Archer C5's WAN socket is live and has learned a host, but
			-- sits on VLAN 2 with its CPU port down: that host is not on the
			-- LAN it would be listed in.
			local d = build_switch({
				cfg = switch_cfg(ARCHER_MAP),
				swconfig = fixture("swconfig_show_ar8327.txt"),
			})
			local p = by_idx(d.port_table)
			assert_true(p[5].up, "the WAN socket has link and is reported")
			assert_true(p[5].mac_table == nil, "but its host is not a client of this LAN")
			assert_eq(p[5].is_uplink, false, "and it is not the uplink")
		end
	},
	{
		name = "inform json: a socket's own MACs and wireless stations are never wired hosts",
		fn = function()
			-- A wireless client bridged into br-lan is learned by the switch
			-- on the CPU port, but a station that roamed or a device's own MAC
			-- appearing on a socket must not turn into a wired client of it.
			local capture = table.concat({
				"Global attributes:",
				"\tarl_table: address resolution table",
				"Port 0: MAC aa:bb:cc:00:00:01",
				"Port 3: MAC aa:bb:cc:dd:ee:ff",   -- a connected station
				"Port 3: MAC aa:bb:cc:00:11:22",   -- this device's own mac
				"Port 3: MAC aa:bb:cc:dd:ee:0c",   -- an actual wired host
				"Port 4: MAC aa:bb:cc:00:00:01",   -- the gateway
				"",
				"Port 3:",
				"\tpvid: 1",
				"\tlink: port:3 link:up speed:1000baseT full-duplex auto",
				"Port 4:",
				"\tpvid: 1",
				"\tlink: port:4 link:up speed:1000baseT full-duplex auto",
				"",
			}, "\n")
			local d = build_switch({
				cfg = switch_cfg(WDR_MAP),
				swconfig = capture,
				with_clients = true,
				with_uci = true,
				gateway = "10.0.0.1",
				arp = "IP address       HW type     Flags       HW address            Mask     Device\n"
					.. "10.0.0.1         0x1         0x2         aa:bb:cc:00:00:01     *        br-lan\n",
			})
			local p = by_idx(d.port_table)
			assert_eq(#p[3].mac_table, 1, "only the real wired host survives")
			assert_eq(p[3].mac_table[1].mac, "aa:bb:cc:dd:ee:0c", "the wired host")
		end
	},
	{
		name = "inform json: port counters come from the switch, falling back to the CPU netdev",
		fn = function()
			-- Per-port MIB counters where the driver exposes them (AR9344).
			local d = build_switch({
				cfg = switch_cfg(WDR_MAP),
				swconfig = fixture("swconfig_show_ar9344.txt"),
			})
			local p = by_idx(d.port_table)
			assert_eq(p[3].rx_bytes, 45338209, "socket 3's own RxGoodByte")
			assert_eq(p[3].tx_bytes, 1183354521, "socket 3's own TxByte")

			-- An AR8327 with MIB polling off has none. The uplink falls back
			-- to the CPU netdev, whose totals all crossed that one socket; a
			-- downstream socket has no honest stand-in and reports 0.
			local d2 = build_switch({
				cfg = switch_cfg(ARCHER_MAP),
				swconfig = fixture("swconfig_show_ar8327.txt"),
			})
			local p2 = by_idx(d2.port_table)
			assert_eq(p2[1].rx_bytes, 1024, "the uplink borrows eth1's counters")
			assert_eq(p2[1].tx_packets, 8, "including packets")
			assert_eq(p2[3].rx_bytes, 0, "a downstream socket reports 0, not the CPU total")
			assert_eq(p2[3].tx_bytes, 0, "in both directions")
		end
	},
	{
		name = "inform json: a socket with its own PHY is reported alongside the switch's",
		fn = function()
			-- Not every socket is behind the switch. The TL-WDR3500's four LAN
			-- sockets are, but its WAN socket has its own MAC and PHY and
			-- shows up only as a netdev (`eth1`) -- so the board's five
			-- sockets need a mixed modelmap, and reporting four of them made
			-- the Ports view disagree with the panel.
			local cfg = switch_cfg(WDR_MAP)
			cfg.net.ports[#cfg.net.ports + 1] = {idx = 5, ifname = "eth0"}
			local orig = inform._read_file
			inform._read_file = function(path)
				-- Its own PHY, so sysfs is the socket's real link here -- not
				-- the CPU's, which is what sysfs answers on a switch port.
				if path == "/sys/class/net/eth0/carrier" then return "1\n" end
				if path == "/sys/class/net/eth0/speed"   then return "100\n" end
				if path == "/sys/class/net/eth0/duplex"  then return "full\n" end
				return nil
			end
			local ok, err = pcall(function()
				local d = build_switch({
					cfg = cfg,
					swconfig = fixture("swconfig_show_ar9344.txt"),
				})
				assert_eq(#d.port_table, 5, "four switch sockets plus the PHY-direct one")
				local p = by_idx(d.port_table)
				assert_eq(p[5].speed, 100, "its own negotiated speed, from sysfs")
				assert_true(p[5].up, "and its own link state")
				assert_eq(p[5].rx_bytes, 9876543, "counters from its netdev")
				assert_false(p[5].is_uplink, "the uplink is still the socket the cable is in")
				assert_true(p[4].is_uplink, "which the switch found")
			end)
			inform._read_file = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform json: without a readable switch the netdev port shape is unchanged",
		fn = function()
			-- No swconfig (a DSA board, a missing binary, a container): the
			-- modelmap's ifname entries and everything read from sysfs behave
			-- exactly as before, rather than a socket list built on guesses.
			local d = build_switch({
				cfg = {
					net = {lan_cpueth = "eth1", ports = {
						{idx = 1, ifname = "eth0", uplink = true},
						{idx = 2, ifname = "eth1", swport = "lan1"},
					}},
					vlan = {cpu_lan = 0, ports = {lan1 = 1}},
				},
				swconfig = "",
			})
			assert_eq(#d.port_table, 2, "the modelmap's netdev ports")
			local p = by_idx(d.port_table)
			assert_true(p[1].is_uplink, "the statically flagged uplink is honoured")
			assert_eq(p[2].rx_bytes, 1024, "counters from eth1 in /proc/net/dev")
			assert_not_nil(p[2].mac_table, "downstream ports still carry a mac_table")
		end
	},
	{
		name = "inform json: a port with no carrier is reported down, at speed 0",
		fn = function()
			-- Existence in /proc/net/dev is not link state: an unused socket is
			-- present and idle. Seen on a real TL-WDR3500 whose unused WAN
			-- socket (eth1, carrier 0, kernel speed -1) went out as
			-- "up, 1000 Mbps".
			local orig = inform._read_file
			inform._read_file = function(path)
				if path == "/sys/class/net/eth0/carrier" then return "1\n" end
				if path == "/sys/class/net/eth0/speed"   then return "100\n" end
				if path == "/sys/class/net/eth1/carrier" then return "0\n" end
				if path == "/sys/class/net/eth1/speed"   then return "-1\n" end
				return nil
			end
			local ok, err = pcall(function()
				local d = build()
				assert_true(d.port_table[1].up, "eth0 has carrier -> up")
				assert_eq(d.port_table[1].speed, 100, "and its real negotiated speed")
				assert_false(d.port_table[2].up, "eth1 has no carrier -> down")
				assert_eq(d.port_table[2].speed, 0, "a down port has no speed, not the fallback")
				assert_false(d.port_table[2].full_duplex, "nor a duplex")
			end)
			inform._read_file = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform json: link state falls back to operstate, then to existence",
		fn = function()
			local orig = inform._read_file
			-- No carrier file, but operstate present.
			inform._read_file = function(path)
				if path:find("/operstate") then
					return path:find("eth1") and "down\n" or "up\n"
				end
				return nil
			end
			local ok, err = pcall(function()
				local d = build()
				assert_true(d.port_table[1].up, "operstate up")
				assert_false(d.port_table[2].up, "operstate down")
			end)
			-- Neither file readable: fall back to the netdev existing at all,
			-- which is the pre-existing behaviour.
			inform._read_file = function() return nil end
			local ok2, err2 = pcall(function()
				local d = build()
				assert_true(d.port_table[1].up, "unknown link state -> existence")
			end)
			inform._read_file = orig
			if not ok then error(err, 0) end
			if not ok2 then error(err2, 0) end
		end
	},
	{
		name = "inform json: port_table falls back when the kernel reports no speed",
		fn = function()
			-- A down interface, or a virtual device with no PHY, makes the
			-- kernel return an error or -1 for speed; neither may be sent as a
			-- link rate.
			local orig = inform._read_file
			inform._read_file = function(path)
				if path:find("/speed") then return "-1\n" end
				return nil
			end
			local ok, err = pcall(function()
				local d = build()
				assert_eq(d.port_table[1].speed, 1000, "-1 is 'unknown', not a speed")
				assert_true(d.port_table[1].full_duplex, "duplex defaults to full when unknown")
			end)
			inform._read_file = orig
			if not ok then error(err, 0) end
		end
	},
	{
		name = "inform json: port_table marks exactly the uplink port is_uplink",
		fn = function()
			local d = build()
			assert_true(d.port_table[1].is_uplink, "port 1 (wan/eth0) is the uplink")
			assert_false(d.port_table[2].is_uplink, "port 2 (lan/eth1) is not the uplink")
		end
	},
	{
		name = "inform json: port_table's uplink port carries no mac_table",
		fn = function()
			local d = build({with_wired = true})
			local uplink = d.port_table[1]
			assert_true(uplink.mac_table == nil or #uplink.mac_table == 0,
				"uplink port never reports wired clients -- the controller skips client creation on it")
		end
	},
	{
		name = "inform json: port_table's downstream port reports wired hosts from the bridge fdb",
		fn = function()
			local d = build({with_wired = true})
			local lan = d.port_table[2]
			assert_not_nil(lan.mac_table, "lan port has a mac_table")
			assert_eq(#lan.mac_table, 2, "two wired hosts from the fixture")
			assert_eq(lan.mac_table[1].mac, "aa:bb:cc:dd:ee:01", "first wired host mac")
			assert_eq(lan.mac_table[1].ip, "192.168.1.50", "first wired host ip from arp")
			assert_eq(lan.mac_table[1].hostname, "laptop", "first wired host hostname from dhcp leases")
			assert_eq(lan.mac_table[2].mac, "aa:bb:cc:dd:ee:02", "second wired host mac")
			assert_true(lan.mac_table[2].hostname == nil, "second wired host has no dhcp lease -- hostname stays nil")
		end
	},
	{
		name = "inform json: port_table's downstream port is empty without wired-client fixtures",
		fn = function()
			local d = build()
			assert_eq(#d.port_table[2].mac_table, 0, "no wired hosts without fixtures")
		end
	},
	{
		name = "inform json: a wireless station is never double-reported as a wired client",
		fn = function()
			-- One of the bridge-fdb-learned MACs coincides with a currently
			-- associated wireless station -- this must be excluded from
			-- port_table's mac_table even though it's also bridged into
			-- br-lan (and thus visible in the bridge FDB), or the same client
			-- would appear twice: once correctly as wireless, once wrongly
			-- as wired.
			inject_sysinfo(false, true)
			inject_ucihelper()
			inform._sysinfo._run_cmd = function(cmd)
				if cmd:find("station dump") then
					return "Station aa:bb:cc:dd:ee:01 (on wlan0)\n" ..
						"\tsignal:  \t-60 dBm\n\ttx bitrate:\t144.4 MBit/s\n"
				end
				if cmd:find("bridge fdb show") then
					return fixture("bridge_fdb_dump.txt")
				end
				return ""
			end
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform", mac = "aa:bb:cc:dd:ee:ff",
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			assert_eq(d.vap_table[1].num_sta, 1, "the station is reported wirelessly")
			local wired_macs = {}
			for _, host in ipairs(d.port_table[2].mac_table) do wired_macs[host.mac] = true end
			assert_true(not wired_macs["aa:bb:cc:dd:ee:01"],
				"the same MAC is excluded from the wired mac_table -- reported wireless-only")
			assert_true(wired_macs["aa:bb:cc:dd:ee:02"],
				"an unrelated bridge-learned host is still reported as wired")
		end
	},
	{
		name = "inform json: the device's own MAC is never reported as a wired client of itself",
		fn = function()
			-- proc_net_dev.txt's eth1 has a real MAC in /sys/class/net/eth1/address
			-- via inject_sysinfo's _read_file stub returning "" for that path
			-- (no MAC) -- so self-exclusion here is driven by st.mac matching
			-- one of bridge_fdb_dump.txt's fixture MACs directly.
			inject_sysinfo(false, true)
			local st = {
				authkey = state.DEFAULT_KEY, adopted = false, cfgversion = "",
				inform_url = "http://10.0.0.1:8080/inform",
				mac = "aa:bb:cc:dd:ee:01",  -- coincides with a bridge_fdb_dump.txt MAC
				ip = "192.168.1.100", hostname = "testap",
			}
			local d = cjson.decode(inform.build_json(st, nil, ufhw))
			local wired_macs = {}
			for _, host in ipairs(d.port_table[2].mac_table) do wired_macs[host.mac] = true end
			assert_true(not wired_macs["aa:bb:cc:dd:ee:01"], "device's own MAC excluded from its own mac_table")
			assert_true(wired_macs["aa:bb:cc:dd:ee:02"], "the other bridge-learned host is still reported")
		end
	},
}
