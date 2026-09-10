--[[
	Generic dual-band OpenWrt AP hardware profile.
	Tested with: TP-Link WDR3500.

	Adjust radio names if your device uses different UCI radio identifiers.
	Run `uci show wireless` on the device to confirm interface names.

	A generic profile cannot know a board's LED name or which of its ports is
	the uplink, and the assumptions below (eth0 = WAN uplink, eth1 = a
	downstream LAN port) are wrong on plenty of boards -- an Archer C5 v1
	deployed as an AP uses eth1 as its uplink and never touches eth0, which is
	why it has its own map (modelmap/archer-c5-v1.lua). Prefer a board-specific
	map where one exists, and check these values against your hardware before
	trusting them.
]]--

local dev = {}
dev.conf = {}

-- OpenWrt network layout
dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "eth1",
	lan_vlanid	= 1,
	wan_cpueth	= "eth0",
	-- UniFi port_idx -> netdev mapping for the inform payload's port_table
	-- (separate numbering space from dev.conf.vlan.ports below, which is
	-- swconfig physical-switch-port numbering, not UniFi's port_idx).
	-- This board exposes only two netdevs (no per-physical-port netdevs),
	-- so the single "lan" entry reports every downstream host behind eth1.
	--
	-- `swport` bridges the two numbering spaces: it names a key in
	-- dev.conf.vlan.ports below (or a physical port number outright), and is
	-- what per-port VLAN assignment (switchvlan.lua) joins on. Without it that
	-- port is skipped rather than guessed at. Uplink ports never get one --
	-- reassigning the uplink's VLAN would strand the device.
	--
	-- This is the netdev-based shape, kept because a generic profile cannot
	-- know a board's socket layout. A board-specific map should instead list
	-- one entry per physical socket (`{idx = 1, swport = "lan1"}`, ...) with no
	-- `uplink` flag: openUF then reports each socket's own link speed and the
	-- hosts actually behind it, and detects the uplink socket from the
	-- switch's ARL table. See modelmap/archer-c5-v1.lua.
	ports = {
		{idx = 1, ifname = "eth0", uplink = true},
		{idx = 2, ifname = "eth1", swport = "lan1"},
	},
}

-- Status LED driven for Locate and the controller's Manage > LED toggle.
-- Left unset because a generic profile can't know the board's LED name; LED
-- control is a silent no-op until you set it. Find yours with
-- `ls /sys/class/leds` and set either a bare name or a full path, e.g.
--   dev.conf.led = "tp-link:green:wlan"
--   dev.conf.led = "/sys/class/leds/tp-link:green:wlan"
dev.conf.led = nil

-- Switch layout (common for both target devices)
dev.conf.vlan = {
	-- swconfig device name, as `swconfig list` reports it.
	device	= "switch0",
	cpu_lan	= 0,
	cpu_wan	= 6,
	ports	= {
		lan1	= 1,
		lan2	= 2,
		lan3	= 3,
		lan4	= 4,
		wan		= 5,
	}
}

-- UniFi configuration
dev.openuf = {}

dev.openuf.uap = {
	ufmodel		= "u6iw",
	-- Both radios reported. Which of them is 2.4 vs 5 GHz is NOT implied by the
	-- order here -- it varies by board (an Archer C5 v1 has radio0 = 5 GHz) and
	-- openUF reads each radio's band from its own UCI `band`/`hwmode` anyway.
	hwassign	= {"radio0", "radio1"},
}

return dev
