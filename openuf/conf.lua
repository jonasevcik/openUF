--[[
	openUF main configuration.

	Select the modelmap that matches your hardware (see openuf/modelmap/).
	Known-working modelmap files:
	  archer-c5-v1.lua        — TP-Link Archer C5 v1 (dual-band, board-specific)
	  tl-wdr3500-v1.lua       — TP-Link TL-WDR3500 v1 (dual-band, board-specific)
	  xiaomi-ax3000t.lua      — Xiaomi Mi Router AX3000T (802.11ax, DSA)
	  generic-dualband-ap.lua — any other dual-band board
	  tl-wr1043ndv2.lua       — TP-Link WR1043ND v2 (single-band)

	Prefer a board-specific map where one exists: the generic profile cannot
	know the board's LED name or which of its ports is the uplink, and gets
	both wrong on an Archer C5.

	The modelmap drives:
	  • dev.conf.net.*          network interface assignments
	  • dev.openuf.uap.ufmodel  which ufmodel/* to load (e.g. "u6iw")
	  • dev.openuf.uap.hwassign radio names to include in the inform payload

	The ufmodel controls the device identity presented to the controller:
	  u6iw.lua  — presents as U6-InWall (U6IW)  ← default for AP emulation
	  uapg1.lua — presents as UAP Gen1
	  uapg2-ac-lr.lua — presents as UAP-AC-LR

	openUF emulates a UniFi AP only. Gateway (USG) and switch (USW) emulation
	are not implemented and are not planned.
]]--

-- Select your hardware model map here:
dev = dofile("modelmap/generic-dualband-ap.lua")

config = {
	-- When true, any wifi-iface sections NOT prefixed with "openuf_" are disabled
	-- during WiFi provisioning, so the radios carry only what the controller
	-- pushed.  Set false to keep hand-configured SSIDs broadcasting; openUF
	-- stamps each SSID it disables, so switching back to false re-enables
	-- exactly those and leaves ones you disabled yourself alone.
	use_only_unifi_wlan = true,

	-- URL the inform loop posts to.  Overwritten at runtime when the controller
	-- sends a new URL or when syswrapper.sh set-inform is called.
	-- The value here is only used on first boot (before state.json exists).
	inform_url = "http://unifi:8080/inform",

	-- Path for persistent state (authkey, adopted flag, cfgversion, inform_url).
	state_file = "/etc/openuf/state.json",

	-- L2 discovery broadcasts (announce.lua, UDP port 10001). On by default:
	-- it is how the device shows up in UniFi Discover without any set-inform.
	--
	-- Set false to adopt over L3 only. This is not just noise reduction: a
	-- controller that discovers a device via L2 adopts it by SSHing in and
	-- running `syswrapper.sh set-adopt`, and if that login cannot succeed
	-- (no password auth, no bootstrap account -- see install.sh's
	-- --bootstrap-adopt) adoption fails with "Connection Interrupted" no
	-- matter how healthy the inform loop is. With broadcasts off the
	-- controller treats the device as L3-discovered instead and delivers the
	-- adoption key over the inform channel, needing no SSH at all.
	-- Takes effect on service restart (the init script reads it).
	l2_announce = true,

	-- Opt-in: when set, every decrypted controller inform response is appended
	-- verbatim (with a UTC timestamp) to this file, before dispatch. Off by
	-- default. Used to capture ground-truth payload shapes when validating
	-- against a real UniFi controller -- see PROTOCOL-VALIDATION.md.
	debug_dump_file = nil,

	-- Set (by install.sh's --bootstrap-adopt, not by hand) to the name of a
	-- temporary, non-root SSH bootstrap account matching real Ubiquiti
	-- hardware's factory-default "ubnt" login -- lets first adoption succeed
	-- without presetting a root password. nil unless that install flag was
	-- used. When set, inform.lua locks the account once the device becomes
	-- adopted and re-enables it on factory reset -- see USAGE.md's SSH
	-- prerequisite section.
	bootstrap_adopt_user = nil,
}
