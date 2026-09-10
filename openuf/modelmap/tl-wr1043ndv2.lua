--[[


]]--

local dev = {}
dev.conf = {}

-- openwrt hw config
dev.conf.net = {
	lan_name 	= "lan",
	lan_cpueth 	= "eth1",
	lan_vlanid  = 1,
	wan_name 	= "wan",
	wan_cpueth 	= "eth0",
	wan_vlanid 	= 4090,
	-- UniFi port_idx -> physical socket, for the inform payload's port_table
	-- and for per-port VLAN assignment (switchvlan.lua joins the controller's
	-- switch.port.<n> onto port_idx). `swport` names a key in
	-- dev.conf.vlan.ports below -- swconfig's own port numbering, a separate
	-- space from port_idx.
	--
	-- One entry per socket, not per netdev: both netdevs here are CPU ports,
	-- whose link is the internal SoC<->switch one and behind which every wired
	-- host looks identical. The switch knows per-socket link and which socket
	-- each host is on; the netdev knows neither (sysinfo.switch_status).
	-- Which socket is the uplink is detected at runtime from the switch's ARL
	-- table, not declared -- see sysinfo.uplink_phys_port.
	--
	-- NOT verified against the real board (openUF has never run on one):
	-- dev.conf.vlan.ports below carries the generic template's numbering, and
	-- TP-Link boards commonly put the WAN socket on physical 1 with the LAN
	-- sockets at 2-5, as the Archer C5 turned out to. Check it with
	-- `swconfig dev switch0 show` and the board's stock `network` config
	-- before trusting these labels; a wrong map here mislabels ports (the
	-- uplink is still detected correctly, since that comes from the ARL).
	ports = {
		{idx = 1, swport = "lan1"},
		{idx = 2, swport = "lan2"},
		{idx = 3, swport = "lan3"},
		{idx = 4, swport = "lan4"},
		{idx = 5, swport = "wan"},
	},
}

-- Status LED driven for Locate and the controller's Manage > LED toggle.
dev.conf.led = "/sys/class/leds/tp-link:green:system"

dev.conf.vlan = {
	-- swconfig device name, as `swconfig list` reports it.
	device 	= "switch0",
	cpu_lan 	= 0,
	cpu_wan 	= 6,
	ports 		= {
		lan1 	= 1,
		lan2 	= 2,
		lan3 	= 3,
		lan4 	= 4,
		wan 	= 5
	}
}


-- unifi configurations
dev.openuf = {}

dev.openuf.uap = {
	ufmodel 	= "uapg1-lr",
	hwassign 	= {"radio0"}
}

return dev
