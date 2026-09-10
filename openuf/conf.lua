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
	-- The value here is used only when state.json carries no URL of its own --
	-- a first boot, or the state after a factory reset.  install.sh also reads
	-- it, to decide whether an https:// controller needs luasec installed.
	inform_url = "http://unifi:8080/inform",

	-- Path for persistent state (authkey, adopted flag, cfgversion, inform_url).
	state_file = "/etc/openuf/state.json",

	-- Client-assisted RF environment enrichment (802.11k beacon reports), the
	-- same mechanism Ubiquiti's Channel AI describes as "neighbor reports and
	-- automated RRM scans".
	--
	-- The Environment tab is otherwise built from the kernel's PASSIVE scan
	-- cache, which only ever holds neighbours on the channel a radio is already
	-- serving -- 6 BSSes on a 2.4 GHz radio and 1 on a 5 GHz one, measured. With
	-- this on, openUF periodically asks ONE 802.11k-capable client to sweep and
	-- report back; the client goes off-channel, the AP never does. A single
	-- answer returned 15 BSSes across both bands.
	--
	-- Costs the AP nothing. Costs a participating client roughly a second
	-- off-channel, once per rrm_request_interval, and only clients that
	-- advertise active/passive beacon measurement are ever asked -- which in
	-- practice is a minority of them. Set false to never send a beacon request.
	rrm_enrichment = true,

	-- Seconds between beacon requests, across all radios and clients combined
	-- (they are asked one at a time, round-robin). Deliberately slow: the point
	-- is to keep the Environment tab honest, not to poll.
	rrm_request_interval = 600,

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

	-- Ceiling for that dump, in bytes (default 4 MiB). The inform loop appends
	-- to it every few seconds, and its usual home is /tmp -- a RAM disk on
	-- these boards -- so an unbounded dump eventually starves state.json
	-- writes and apk. Past the cap the file restarts, with a marker line
	-- saying so; a capture is read from its tail anyway. 0 = no cap.
	debug_dump_max_bytes = 4 * 1024 * 1024,

	-- Set (by install.sh's --bootstrap-adopt, not by hand) to the name of a
	-- temporary, non-root SSH bootstrap account matching real Ubiquiti
	-- hardware's factory-default "ubnt" login -- lets first adoption succeed
	-- without presetting a root password. nil unless that install flag was
	-- used. When set, inform.lua locks the account once the device becomes
	-- adopted and re-enables it on factory reset -- see USAGE.md's SSH
	-- prerequisite section.
	bootstrap_adopt_user = nil,
}
