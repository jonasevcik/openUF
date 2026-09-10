--[[
	Xiaomi Mi Router AX3000T hardware profile.

	Verified on OpenWrt 25.12.5 (mediatek/filogic, MT7981, aarch64) against the
	real board:
	  • radio0 = 2.4 GHz (mt76, platform/soc/18000000.wifi   — HE, HT40 max)
	  • radio1 = 5 GHz   (mt76, platform/soc/18000000.wifi+1 — HE, 160 MHz)
	Real 802.11ax on both bands, so unlike the ath79 boards here nothing is
	clamped down except the 2.4 GHz width the band itself does not have.

	=== The first DSA board in this project — read this before copying it ===

	Every other modelmap describes an ath79/swconfig board, where the kernel
	sees one CPU netdev per switch and openUF has to interrogate the switch
	ASIC for anything socket-shaped. This board has NO `swconfig` binary at
	all. Its switch is DSA, which is simpler in exactly the way that matters:

	  • each socket is its own netdev (wan, lan2, lan3, lan4 — there is no
	    lan1; DSA names ports from the device tree, not from the case labels),
	    so /sys/class/net/<socket>/{carrier,speed,duplex} describes that cable
	    rather than an internal SoC<->switch link;
	  • all four are bridge ports of br-lan, so `bridge fdb show dev <socket>`
	    is already the per-socket host list, and `bridge fdb show br br-lan`
	    says which socket the gateway is behind (sysinfo.uplink_bridge_port).

	So this map carries the netdev port shape and NO dev.conf.vlan: there is
	no swconfig port numbering to map, and inventing one would be a guess.
	Per-port VLAN assignment is therefore inert here — see the note below.
]]--

local dev = {}
dev.conf = {}

-- OpenWrt network layout.
--
-- Deployed as a pure AP: br-lan carries lan2/lan3/lan4/wan, holds the L3
-- address, and the WAN socket is simply the one the uplink cable is in. There
-- is no separate WAN role and no wan interface.
--
-- lan_cpueth = "wan" is not a typo. It names the uplink SOCKET, which is what
-- the three things that read it actually need:
--   • the identity MAC — d4:53:2a:38:80:cf here, which is also the board's
--     label MAC (board.json's label_macaddr). The other netdevs share
--     eth0's d4:53:2a:b2:03:3c, so this is the more stable, more honest one.
--   • the parent of a VLAN-tagged SSID's sub-device (`wan.<vid>`, built by
--     ucihelper.ensure_vlan_network). It has to be the socket the tag arrives
--     on, not the bridge and not the DSA conduit.
--   • the L3 address, which announce.get_ip finds by following this netdev's
--     /sys/class/net/wan/master to br-lan — exactly as on the Archer C5.
dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "wan",
	lan_vlanid	= 1,
	wan_cpueth	= "wan",
	-- UniFi port_idx -> netdev. One entry per physical socket, which on DSA
	-- needs no switch map: the netdev IS the socket. `idx` is fixed to a
	-- socket and never to a role, so the controller's per-port overrides
	-- survive a cable being moved.
	--
	-- No `uplink` flag, deliberately, and no `swport`: which socket the cable
	-- is in is DETECTED at runtime from the bridge FDB
	-- (sysinfo.uplink_bridge_port), the same discipline the swconfig boards
	-- use with the switch's ARL table. A declared uplink is wrong the moment
	-- someone moves the cable, and a socket wrongly treated as downstream
	-- makes the AP report the whole LAN segment as hosts plugged into it.
	--
	-- Four sockets, not the five U6IW's model registry claims. Reporting the
	-- board's real ports is worth more than matching a fake identity's spec.
	ports = {
		{idx = 1, ifname = "wan"},
		{idx = 2, ifname = "lan2"},
		{idx = 3, ifname = "lan3"},
		{idx = 4, ifname = "lan4"},
	},
}

-- NB for topology: lldpd defaults its chassis ID to eth0's MAC, which on this
-- board is the DSA conduit and NOT the MAC openUF identifies as. The gateway
-- then learns this AP as a neighbour it cannot match to any adopted device and
-- the controller shows the wrong Parent Device. Fix on the device (USAGE § 7):
--   uci set lldpd.config.cid_interface='wan'; uci commit lldpd

-- Status LED for the controller's Locate action and its Manage > LED toggle.
--
-- REQUIRES `kmod-leds-gpio` on the device. The board's single case LED is a
-- blue/yellow pair on GPIO 521/522, declared in the device tree — but the
-- stock OpenWrt 25.12 filogic image ships no gpio-leds driver, so nothing
-- claims those GPIOs, /sys/class/leds holds only the two mt76 radio LEDs, and
-- the case LED sits at whatever the bootloader left it (a steady orange: the
-- yellow half on). Installing the module (9 KB) registers blue:status and
-- yellow:status and the LED becomes drivable. Confirmed on the real board.
--
-- Do NOT be tempted by mt76-phy0 when the module is absent. It exists, it
-- accepts writes, and it is connected to nothing on this board — Locate would
-- report success and blink an LED that does not physically exist. Verified by
-- forcing both mt76 LEDs to full brightness and watching the case: no change.
--
-- blue rather than yellow: on a UniFi AP a steady status LED means adopted
-- and healthy, and yellow is this board's own "something is wrong" colour.
-- The pair is on/off only (max_brightness 1), so there is no dimming.
dev.conf.led = "blue:status"
-- No dev.conf.vlan. There is no swconfig switch, so there is no physical port
-- numbering to map, and switchvlan.detect_backend correctly declines to act
-- (it returns "unknown" here: no `config switch`, no `config bridge-vlan`).
--
-- Consequence to know about: openUF still advertises hasOWRTSwitch (fw_caps
-- 0x100), so the controller offers Port VLAN on this device and accepts an
-- assignment — which openUF then refuses, loudly, in the log. The DSA
-- equivalent is `config bridge-vlan` and is not implemented. VLAN-tagged
-- SSIDs are a separate path and DO work here: DSA passes tags through with
-- bridge vlan_filtering off, so they need the bridge + sub-device
-- ensure_vlan_network builds and no switch trunk at all.

-- UniFi configuration
dev.openuf = {}

dev.openuf.uap = {
	ufmodel		= "u6iw",
	hwassign	= {"radio0", "radio1"},	-- radio0 = 2.4 GHz, radio1 = 5 GHz
}

return dev
