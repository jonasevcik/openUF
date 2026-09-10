--[[
	TP-Link TL-WDR3500 v1 hardware profile.

	Verified on OpenWrt 25.12.5 (ath79/generic) against the real board:
	  • radio0 = 2.4 GHz (ath9k, platform/ahb/18100000.wmac)
	  • radio1 = 5 GHz   (ath9k, pci0000:00/0000:00:00.0)
	Both radios are 2x2 802.11n (MCS 0-15). Note the ordering is the OPPOSITE
	of the Archer C5's, where radio0 is the 5 GHz radio -- band is always read
	from each radio's own UCI `band`/`hwmode`, never from this order, but it is
	the first thing to check when reading a `uci show wireless` dump.

	⚠️  8 MB flash. This board cannot run openUF from a stock OpenWrt image:
	the AES-GCM backend (lua-openssl -> libopenssl3) needs ~1.7 MB compressed
	and a stock build leaves ~1.6 MB of overlay, which no crypto backend fits
	in. It needs a custom image with lua-openssl, luasocket, lua-cjson and
	luabitop built into squashfs -- see README's hardware requirements.

	Even then, expect nftables NOT to fit alongside everything else (~490 KB
	with its kernel modules). Without it these two features are unavailable and
	openUF logs the fact rather than pretending:
	  • client Block / Unblock       (openuf/firewall.lua)
	  • Multicast and Broadcast Blocker (openuf/bcfilter.lua)
	Everything else -- adoption, SSID provisioning, 802.11r/k/v, Band Steering,
	Minimum RSSI, WiFi Speed Limit -- works, given hostapd-utils, usteer,
	ip-bridge and tc-tiny in the image.
]]--

local dev = {}
dev.conf = {}

-- OpenWrt network layout.
--
-- Deployed as an AP, this board's uplink is a LAN socket on the switch, which
-- reaches the CPU as VLAN 1 over the eth0 trunk (`eth0.1`, bridged into
-- br-lan). eth1 -- the WAN socket -- is unused and stays DOWN: confirmed on
-- the real board, where it carries zero bytes while all traffic goes over
-- eth0. That is why lan_cpueth is eth0 and not eth1 as the generic profile
-- assumes: naming eth1 here would hang controller-pushed VLAN SSIDs off a
-- dead socket.
--
-- lan_cpueth is the TRUNK (eth0), not the VLAN sub-device (eth0.1), so a
-- pushed VLAN 20 becomes eth0.20 -- a second VLAN alongside the LAN's own,
-- which is what the switch expects.
dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "eth0",
	lan_vlanid	= 1,
	wan_name	= "wan",
	wan_cpueth	= "eth1",
	wan_vlanid	= 2,
	-- The board's four LAN sockets, one port_idx each -- not the CPU netdev
	-- they share. eth0's link is the internal SoC<->switch one (always
	-- 1000/full) while the socket the cable is in had negotiated 100baseT, and
	-- every wired host behind the switch reaches the CPU through it, so
	-- neither speed nor host placement can be read from the netdev. Both come
	-- from the switch itself (sysinfo.switch_status); which socket carries the
	-- uplink is detected from its ARL table (sysinfo.uplink_phys_port) rather
	-- than declared, because it is simply wherever the cable was put -- port 4
	-- as cabled today. `idx` stays pinned to a socket so controller-side
	-- per-port overrides survive a replug.
	--
	-- The WAN socket is the fifth entry and is NOT on the switch: the AR8229
	-- has 5 ports (`swconfig dev switch0 help`: "ports: 5 (cpu @ 0)") and all
	-- four external ones are LAN sockets, while the WAN socket hangs off its
	-- own MAC and PHY -- a second `ag71xx` at 19000000.eth, connected to
	-- mdio.0:1f:04, surfacing as `eth1`. So it is described by a netdev and
	-- swconfig knows nothing about it; entries with an `ifname` and no
	-- `swport` are read from sysfs, which for a socket with its own PHY is
	-- the real link and not the CPU's. eth1 is a br-lan port here, so a host
	-- plugged into that socket is on the LAN and gets reported like any other.
	ports = {
		{idx = 1, swport = "lan1"},
		{idx = 2, swport = "lan2"},
		{idx = 3, swport = "lan3"},
		{idx = 4, swport = "lan4"},
		{idx = 5, ifname = "eth1"},
	},
}

-- Status LED for Locate and the Manage > LED toggle. The board also has
-- green:wlan2g, green:qss and green:usb; `ls /sys/class/leds` for the set.
-- (Unlike the Archer C5 there is no 5 GHz LED on this board.)
dev.conf.led = "green:system"

-- Switch layout (AR9344 built-in switch, swconfig-era ath79).
-- Stock config puts LAN sockets 1-4 on VLAN 1 with the CPU port tagged
-- ("1 2 3 4 0t"), which is what dev.conf.net above assumes.
dev.conf.vlan = {
	-- swconfig device name, as `swconfig list` reports it.
	device	= "switch0",
	cpu_lan	= 0,
	cpu_wan	= 0,
	ports	= {
		lan1	= 1,
		lan2	= 2,
		lan3	= 3,
		lan4	= 4,
	}
}

-- UniFi configuration
dev.openuf = {}

dev.openuf.uap = {
	ufmodel		= "u6iw",
	hwassign	= {"radio0", "radio1"},	-- radio0 = 2.4 GHz, radio1 = 5 GHz
}

return dev
