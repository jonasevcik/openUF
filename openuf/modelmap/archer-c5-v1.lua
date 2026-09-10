--[[
	TP-Link Archer C5 v1 hardware profile.

	Verified on OpenWrt 25.12.5 (ath79/generic) against the real board:
	  • radio0 = 5 GHz  (ath10k, pci0000:00/0000:00:00.0 — HT/VHT, no HE)
	  • radio1 = 2.4 GHz (ath9k, platform/ahb/18100000.wmac — HT only)
	Note the ordering: radio0 is the 5 GHz radio here, the opposite of what a
	generic profile would assume. Nothing in openUF depends on that ordering
	(each radio's band is read from its own UCI `band`/`hwmode`), but it is the
	first thing to check when reading a `uci show wireless` dump from this board.

	openUF presents itself as an 802.11ax U6-InWall on top of this 802.11n/ac
	hardware; controller-pushed channel widths are clamped down to what these
	radios can really do (see ucihelper's clamp_htmode).
]]--

local dev = {}
dev.conf = {}

-- OpenWrt network layout.
--
-- The uplink is the LAN side: this board is deployed as a pure AP, with
-- br-lan (eth1 → CPU switch port 0) carrying everything and the WAN port
-- (eth0) unused. lan_cpueth therefore names the *port*, not the bridge --
-- VLAN-tagged SSIDs need a real trunk port to hang sub-interfaces off, and
-- the IP lookup follows the bridge on its own (see announce.get_ip).
dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "eth1",
	lan_vlanid	= 1,
	wan_name	= "wan",
	wan_cpueth	= "eth0",
	wan_vlanid	= 4090,
	-- UniFi port_idx -> physical socket, for the inform payload's port_table
	-- and for per-port VLAN assignment (switchvlan.lua joins the controller's
	-- switch.port.<n> straight onto port_idx).
	--
	-- The board's five sockets, not its two netdevs. Both netdevs are CPU
	-- ports: their link is the internal SoC<->switch one, always 1000/full,
	-- and every wired host behind the switch reaches them through the same
	-- one. Reporting a netdev as "the port" therefore reported a speed no
	-- cable had negotiated and could not place a single host on a socket.
	-- The switch answers both (sysinfo.switch_status).
	--
	-- `idx` is fixed to a socket, never to a role: the controller keys per-
	-- port overrides on port_idx, so the numbering must survive a cable being
	-- moved. Which socket is the UPLINK is detected at runtime instead, from
	-- the switch's ARL table -- see sysinfo.uplink_phys_port. No `uplink` flag
	-- here, deliberately: on this board the uplink is whichever LAN socket the
	-- installer used (port 2 as cabled today).
	ports = {
		{idx = 1, swport = "lan1"},
		{idx = 2, swport = "lan2"},
		{idx = 3, swport = "lan3"},
		{idx = 4, swport = "lan4"},
		{idx = 5, swport = "wan"},
	},
}

-- NB for topology: lan_cpueth is eth1 here, so openUF's identity MAC is
-- eth1's -- but lldpd defaults its chassis ID to eth0's MAC, which on this
-- board is the unused WAN socket. The gateway then learns this AP as a
-- neighbour it cannot match to any adopted device, and the controller shows
-- the wrong Parent Device. Fix on the device (see USAGE § 7):
--   uci set lldpd.config.cid_interface='lan'; uci commit lldpd

-- Status LED for the controller's Locate action and its Manage > LED toggle.
-- The board also has green:wlan2g / green:wlan5g if you would rather flash a
-- radio LED; `ls /sys/class/leds` on the device for the full set.
dev.conf.led = "green:system"

-- Switch layout (AR8327, swconfig-era ath79).
--
-- Read off the board's own stock config rather than assumed: VLAN 2 (WAN) is
-- `ports '1 6'` and physical port 1 is the one socket that never shows link
-- on a unit cabled as an AP, so **physical 1 is the WAN socket and the four
-- LAN sockets are 2-5**. CPU port 0 serves the LAN side (eth1), CPU port 6
-- the WAN side (eth0).
--
-- An earlier revision here had lan1..lan4 = 1..4, which put "lan1" on the WAN
-- port and left the fourth LAN socket unaddressable. Latent while no port
-- carried a swport, but it surfaced the moment a tagged SSID needed a trunk:
-- the generated port string tagged the WAN socket and skipped a LAN one.
--
-- NOT verified: which *labelled* socket (LAN1..LAN4 on the case) maps to
-- which physical number -- TP-Link boards commonly reverse them. Only the
-- SET is confirmed. To settle it, watch `swconfig dev switch0 show | grep -A1
-- "^Port"` while moving one cable between sockets. Nothing openUF does today
-- depends on the ordering (the trunk tags every LAN port); a per-port VLAN
-- assignment would, so confirm before adding `swport` to dev.conf.net.ports.
dev.conf.vlan = {
	-- swconfig device name, as `swconfig list` reports it.
	device	= "switch0",
	cpu_lan	= 0,
	cpu_wan	= 6,
	ports	= {
		lan1	= 2,
		lan2	= 3,
		lan3	= 4,
		lan4	= 5,
		wan		= 1,
	}
}

-- UniFi configuration
dev.openuf = {}

dev.openuf.uap = {
	ufmodel		= "u6iw",
	hwassign	= {"radio0", "radio1"},	-- radio0 = 5 GHz, radio1 = 2.4 GHz
}

return dev
