--[[
	Band Steering support via OpenWrt's usteer daemon.

	CONFIRMED live 2026-07-15 (toggled "Band Steering" in the controller's
	Behavior Controls panel, diffed system_cfg via debug_dump_file): real UniFi
	sends this as a per-WLAN wire field, wireless.<n>.no2ghz_oui ("enabled"/
	"disabled", only present on the WLAN's 2.4GHz/radio0 wireless.<n> entry --
	see inform.lua's _parse_wifi_system_cfg). It is a plain on/off toggle, not
	the 3-state Device.BandsteeringMode (off/equal/prefer_5g) enum an earlier
	version of this module assumed from paultyng/go-unifi's REST model --
	that enum belongs to the controller's admin API, not this wire protocol,
	and this controller version's UI only ever exposes a single checkbox.

	OpenWrt/hostapd has no band-steering concept at all -- there is no UCI
	wireless option for it (no2ghz_oui is a madwifi/QCA driver-specific
	convention: omitting the AP's own OUI from 2.4GHz beacons/probe responses
	nudges dual-band-capable clients toward 5GHz -- mainline mac80211/hostapd
	on OpenWrt has no equivalent). Real steering on OpenWrt requires the
	separate ubus-based `usteer` daemon (/etc/config/usteer), which itself
	depends on 802.11k (neighbor reports) + BSS Transition being enabled on
	every wifi-iface -- see ucihelper.apply_config's opts.band_steering_active
	handling, which forces those on network-wide whenever steering is enabled.

	The on/off switch is band_steering_interval, read from usteer's source
	(band_steering.c): every interval, usteer sends each 2.4 GHz client that
	has a same-SSID 5 GHz interface to steer to a BSS Transition request, and
	0 disables it. The daemon default is non-zero, so a running usteer steers
	unless openUF writes 0 -- which matters because Roaming Assistant keeps
	the daemon running with Band Steering off. band_steering_threshold, which
	an earlier version toggled 5/0, only biases load balancing (policy.c
	below_assoc_threshold) and is inert while load_balancing_threshold is 0,
	the default: toggling it switched nothing.
]]--

local M = {}

-- Injectable: UCI module and command runner, for tests.
M._uci     = nil
M._run_cmd = function(cmd) return os.execute(cmd) end

-- Options in usteer.local that openUF owns. Each is written when set_enabled
-- wants a value for it and deleted when it wants none, so the daemon falls
-- back to its own default. band_steering_threshold is listed only so that a
-- value an earlier openUF wrote gets removed.
M.OWNED_OPTIONS = {"band_steering_interval", "band_steering_threshold"}

local function get_uci()
	if M._uci then return M._uci end
	return require("uci")
end

-- Enable or disable band steering, and keep the daemon running for Roaming
-- Assistant.
-- enabled:     boolean, Band Steering
-- cfg:         device configuration (from conf.lua); cfg.net.lan_name selects the
--              usteer network to bind to, defaulting to "lan" when absent.
-- roam_assist: boolean, Roaming Assistant (wireless.<n>.btm_disassoc). The
--              steering decision itself is openuf/roamassist.lua's, per WLAN;
--              it needs usteer only for its cross-AP table of which AP hears
--              which client how loudly. So Roaming Assistant alone runs the
--              daemon with band steering off (interval 0), and
--              usteer's own device-wide roam trigger (roam_trigger_snr,
--              signal_diff_threshold) is never set: it cannot be scoped to a
--              WLAN or a band, and its only scoping knob, ssid_list, switches
--              every usteer function off for the other SSIDs.
function M.set_enabled(enabled, cfg, roam_assist)
	local uci = get_uci()
	local cursor = uci.cursor()
	local network = (cfg and cfg.net and cfg.net.lan_name) or "lan"
	local run = (enabled or roam_assist) and "1" or "0"
	-- nil = delete: the daemon's own default interval is the one that
	-- steered a real client on hardware (PROTOCOL-VALIDATION.md, #25).
	local want = {band_steering_interval = (not enabled) and "0" or nil}

	-- No-op discipline (same hazard class as switchvlan's reload guard):
	-- this runs on EVERY WiFi setparam, and unconditionally committing +
	-- restarting bounced the steering daemon -- dropping its learned station
	-- table -- on every steady-state inform. Skip when UCI already matches.
	--
	-- openuf_active records whether openUF last ran or stopped the daemon.
	-- The options alone can't: with Band Steering on they are all unset,
	-- exactly as on a device openUF never touched. usteer's init script
	-- reads a fixed list of option names, so this stamp never reaches the
	-- daemon.
	local same = cursor:get("usteer", "local", "network") == network
		and cursor:get("usteer", "local", "openuf_active") == run
	for _, opt in ipairs(M.OWNED_OPTIONS) do
		if cursor:get("usteer", "local", opt) ~= want[opt] then same = false end
	end
	if same then return true end

	cursor:set("usteer", "local", "usteer")
	cursor:set("usteer", "local", "network", network)
	for _, opt in ipairs(M.OWNED_OPTIONS) do
		if want[opt] ~= nil then
			cursor:set("usteer", "local", opt, want[opt])
		elseif cursor:get("usteer", "local", opt) ~= nil then
			cursor:delete("usteer", "local", opt)
		end
	end
	cursor:set("usteer", "local", "openuf_active", run)
	cursor:commit("usteer")

	if run == "1" then
		M._run_cmd("/etc/init.d/usteer enable 2>/dev/null")
		M._run_cmd("/etc/init.d/usteer restart 2>/dev/null")
	else
		M._run_cmd("/etc/init.d/usteer stop 2>/dev/null")
		M._run_cmd("/etc/init.d/usteer disable 2>/dev/null")
	end

	return true
end

-- ─── Keep usteer's AP-to-AP sync off the air ────────────────────────────────
--
-- usteerd tells the other APs what it sees by broadcasting its whole station
-- table every remote_update_interval (1 s) to 255.255.255.255:16720 -- or
-- ff02::4150 with `ipv6` set -- plus a short update for every MAC it has not
-- seen before (usteer remote.c/sta.c). The table holds every device heard in
-- a probe request in the last local_sta_timeout (120 s), so passing phones
-- dominate it: live on 2026-10-07, 119 entries for 16 associated clients,
-- 7024 bytes per message, five IP fragments. The bridge floods each fragment
-- out of every VAP too, where Multicast Enhancement (multicast_to_unicast)
-- turns it into one unicast copy per station: ~16 KB and 10-15 frames a
-- second to every client of both APs, waking dozing phones and costing a weak
-- client ~1.5 % of the radio's airtime, for traffic only the other AP reads.
-- The peer AP is reached over the wired uplink, so dropping the sync where it
-- leaves through a VAP loses nothing.
--
-- Bridge postrouting sees both what this AP's usteerd sends and what the
-- peer's sends in over the uplink. The bridge does not reassemble, so only a
-- datagram's first fragment carries the UDP port; the later fragments are
-- matched as non-first fragments of a UDP broadcast. Nothing else sends a
-- fragmented UDP broadcast to clients (DHCP fits one frame, and a client that
-- missed the first fragment could not reassemble the rest anyway).
--
-- Own table, rebuilt from scratch like l2guard's; oifname, not oif, so a VAP
-- that a `wifi reload` is recreating does not fail the add. iifname/oifname in
-- the bridge family need kmod-nft-bridge.

M.NFT_TABLE = "bridge openuf_usteer"

M._exec = function(cmd) return os.execute(cmd) end

-- os.execute on the device's Lua 5.1 returns the raw exit status (0 =
-- success, non-zero = failure, both truthy); newer Lua returns true/nil.
local function exec_ok(status)
	return status == true or status == 0
end

local function valid_ifname(s)
	return type(s) == "string" and s:match("^[%w%-%._]+$") ~= nil and #s <= 15
end

-- Whether openUF runs usteerd, i.e. whether the filter has anything to do.
function M.filter_wanted()
	local ok, v = pcall(function()
		return get_uci().cursor():get("usteer", "local", "openuf_active")
	end)
	return ok and v == "1"
end

-- Rebuild the table to drop usteer's sync on exactly these VAP netdevs; an
-- empty or nil list removes it. Returns the number of rules installed.
function M.reconcile_filter(ifnames)
	M._exec("nft delete table " .. M.NFT_TABLE .. " 2>/dev/null")
	local names = {}
	for _, n in ipairs(ifnames or {}) do
		if valid_ifname(n) then names[#names + 1] = '"' .. n .. '"' end
	end
	if #names == 0 then return 0 end
	local set = "{ " .. table.concat(names, ", ") .. " }"
	M._exec("nft add table " .. M.NFT_TABLE)
	M._exec("nft add chain " .. M.NFT_TABLE
		.. " post '{ type filter hook postrouting priority 0; policy accept; }'")
	local rules = {
		"oifname " .. set .. " ip daddr 255.255.255.255 udp dport 16720 drop",
		"oifname " .. set .. " ip daddr 255.255.255.255 ip protocol udp ip frag-off & 0x1fff != 0 drop",
		-- usteer's own group: every fragment carries it, nothing else uses it.
		"oifname " .. set .. " ip6 daddr ff02::4150 drop",
	}
	local n = 0
	for _, r in ipairs(rules) do
		if exec_ok(M._exec("nft add rule " .. M.NFT_TABLE .. " post '" .. r .. "'")) then
			n = n + 1
		else
			io.stderr:write("openuf: usteer: nft rejected a sync filter rule (needs "
				.. "kmod-nft-bridge); usteer's broadcasts still reach every client.\n")
		end
	end
	return n
end

return M
