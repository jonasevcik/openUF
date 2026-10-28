# openUF

[![Tests](https://github.com/jonasevcik/openUF/actions/workflows/test.yml/badge.svg)](https://github.com/jonasevcik/openUF/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Lua 5.1+](https://img.shields.io/badge/Lua-5.1%2B-blue.svg)](https://www.lua.org/)

openUF is a Lua daemon that makes an OpenWrt device appear as a **Ubiquiti UniFi U6-InWall** (or other UniFi AP models) to a UniFi Network Application controller.  The controller can then adopt the device, push SSID and network configuration, and display live client and radio statistics — all without genuine Ubiquiti hardware.

<p align="center">
  <img src="docs/img/unifi-topology.jpg" alt="UniFi topology view: a real Cloud Gateway Ultra with two openUF access points below it, carrying the network's 20 wired and wireless clients">
</p>

<p align="center"><em>The controller's topology view: two openUF access points under a real UniFi Cloud Gateway Ultra, and all 20 clients on the network, 18 of them behind the openUF APs. Click for full resolution.</em></p>

<table>
<tr>
<td width="50%"><img src="docs/img/unifi-device-detail.jpg" alt="UniFi device list and the detail panel of an openUF access point"></td>
<td width="50%"><img src="docs/img/unifi-clients.jpg" alt="UniFi client list showing clients associated to openUF access points"></td>
</tr>
<tr>
<td><em>Both openUF APs online as model <code>U6 IW</code>, with radios, uplink port, firmware version, 38 days of uptime and live throughput.</em></td>
<td><em>The controller's client list — most of these clients are associated to the two openUF APs on a controller-pushed SSID, with band, channel, WiFi generation and per-client experience.</em></td>
</tr>
</table>

Those are screenshots of the author's live network taken from a real UniFi Cloud Gateway Ultra; every hostname, MAC address, IP address, SSID and ISP name in them was rewritten to a consistent fake value in the browser before capture.

Tested end-to-end against **UniFi Network Application 10.4.57 and 10.6** — both a self-hosted Docker controller and a real UniFi Cloud Gateway Ultra, adopting a TP-Link Archer C5 v1 and a Xiaomi AX3000T running openUF, with real clients associating to the pushed SSIDs.  The default device identity presented is **U6-InWall** (model `U6IW`).  openUF emulates a UniFi **access point** only — gateway (USG) and switch (USW) emulation are not implemented and not planned.

## What it does

### Adoption and transport

## What it does

Each row says what is confirmed and what is not: ✅ was driven through the real controller UI
against a live openUF device, ⚠️ names the part that is lab-only or unproven, and ❌ is not
implemented. The evidence is in [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md), the wire keys
in [docs/WIRE-REFERENCE.md](docs/WIRE-REFERENCE.md), and how to configure each feature in
[USAGE.md](USAGE.md).

### Adoption and transport

| Feature | Status |
|---|---|
| L2 UDP discovery (port 10001) | ✅ The periodic announce the controller adopts from. The same process also **answers** the UniFi app, WiFiman's Discovery tab and the Device Discovery Tool, by broadcast, unicast or the `233.89.188.1` multicast group. IPv6 (`ff02::1`) probes are not answered. ⚠️ Lab-validated only — the home APs run `l2_announce = false`, which turns the responder off with the broadcast |
| TNBU inform protocol | ✅ AES-128-CBC and AES-128-GCM |
| AES-128-GCM | ✅ **Required**: the controller will not finish provisioning a device until it receives a genuine GCM inform. Needs a GCM-capable `lua-openssl` build |
| L2 adoption (SSH `syswrapper.sh set-adopt`) | ✅ Completes to **Connected** |
| L3 adoption (`set-inform`, no SSH) | ✅ The controller skips SSH and delivers the new authkey in the `setparam` `mgmt_cfg`; openUF accepts it only while unadopted. It chooses this path when it has *not* discovered the device by broadcast, which is what `config.l2_announce = false` is for — a same-subnet device that cannot accept an SSH login needs it |
| Zero-touch bootstrap adoption | ✅ Optional (`install.sh install --bootstrap-adopt`) — a locked-down, non-root SSH account auto-disabled after adoption |
| Forget device / factory reset | ✅ The controller's Forget sends `setdefault`, and openUF removes the WLANs, VLAN bridges, per-port VLANs and radio options it wrote, as the firmware's factory reset does but without a reboot. It keeps the inform URL, so the device can be adopted again straight away ([USAGE § 4](USAGE.md#4-adoption-flow)) |
| Restart / reboot command | ✅ |
| Immediate commands and config changes (STUN wake-up) | ✅ openUF keeps a UDP socket open to the controller's STUN server and reports the mapped address, so a queued command or config change arrives at once instead of at the next heartbeat: 0.2 s after the request on the AX3000T, 1.5 s on the Archer C5 (most of that is building the payload). After upgrading it starts with the next config push — Force Provision once |
| Firmware upgrade requests | Stored (version/url), never applied — flashing controller-supplied firmware onto non-Ubiquiti hardware would brick it |

### WiFi provisioning

| Feature | Status |
|---|---|
| Controller-pushed SSID provisioning | ✅ Only `openuf_`-prefixed UCI sections are created or deleted |
| Exclusive-WLAN mode (`use_only_unifi_wlan`) | ✅ Default `true` disables hand-configured SSIDs so the radios carry only what the controller pushed; reversible, since openUF stamps what it disabled |
| WPA2 / WPA3 / WPA2-WPA3 mixed security | ✅ Needs `radio_caps2` bit `0x1` per radio, which openUF sends when hostapd can really do SAE — without it the controller silently downgrades every WPA3 WLAN to WPA2 |
| WPA-Enterprise (802.1X / RADIUS) | ⚠️ Wire → UCI → the device's own hostapd generator confirmed; **no client has authenticated.** All four security values map (WPA2, WPA3, transition and 192-bit), and 802.11r adds FT-EAP for free. Two narrowings: one port and one secret per server list, and a RADIUS-assigned VLAN gets no `wifi-vlan` section, so `dynamic_vlan=2` refuses a station whose VLAN this AP has no network for ([USAGE § 6](USAGE.md#6-wifi-provisioning)) |
| RADIUS MAC authentication + Dynamic Authorization (CoA) | ⚠️ Wire and hostapd config confirmed; **no RADIUS server at home, so no client has been admitted, denied or disconnected.** Arrives on an open or PSK WLAN as readily as an Enterprise one, with no capability gate; DAS needs `fw_caps` `0x100000`. A WLAN that asks for MAC auth and cannot have it is dropped rather than provisioned without it. The MAC format the controller sends has no OpenWrt consumer, so a server expecting anything but lower-case colons will reject the client |
| Hotspot 2.0 / Passpoint | ⚠️ Wire → UCI → hostapd confirmed, **no Passpoint client has associated.** The cumulative lists go in as raw hostapd lines, because OpenWrt's list options space-join into one malformed line. Needs `fw_caps` `0x800000` **and** `fw2_caps` `0x80000` (RadSec), the second for a feature openUF does not implement — a trade: a RadSec server now arrives distinguishable and is dropped with a log instead of being sent its secret in the clear |
| Enhanced Open (OWE), incl. transition mode | ⚠️ Lab-confirmed on the wire, **no OWE BSS has been brought up on a real AP.** Needs `radio_caps2` bit `0x8`, claimed when `hostapd -vowe` passes and the ucode generator knows `owe_transition`. OpenWrt names the hidden OWE BSS `<ssid>OWE` where UniFi reuses the SSID; clients follow the transition element either way |
| PMF / 802.11w | ✅ From `aaa.<n>.pmf.status`/`.mode`. PMF is just PMF: the WPA3-transition signal is `wpa3.support`/`wpa3.transition` |
| Fast Roaming (802.11r) | ✅ **Verified on real hardware** by forcing a roam and watching for `auth_alg=ft` with no EAPOL 4-way, both between radios on one AP and across two APs. The key-holder secret is the controller's own per-WLAN `iapp_key`; the mobility domain is openUF's own hash, so FT with a genuine UniFi AP is deliberately not attempted |
| VLAN-tagged SSIDs | ✅ End to end on both board families with a client on a tagged IoT network, from `aaa.<n>.br.devname` — the wire's only VLAN signal. A swconfig board needs a switch trunk (CPU port + uplink socket only); a DSA board needs none |
| Private Pre-Shared Keys (one SSID, a passphrase per VLAN) | ⚠️ Lab-confirmed through to UCI, **no client has joined with a VLAN key on a real AP.** Needs `wifi_caps` bit `0x100000`, claimed when the generator writes per-station VLANs and hostapd has VLAN support; without it the controller skips the WLAN entirely |
| MAC-based VLANs (a client's "Virtual Network Override") | ✅ Captured on the real controller and confirmed in live hostapd on both boards. Needs `fw_caps` `0x80000000` **and a site-wide quorum** — one AP in the site without the bit switches the feature off for every client. ⚠️ No real client has been moved by MAC ([USAGE](USAGE.md#mac-based-vlans-virtual-network-override)) |
| Plugins (third-party extensions) | ⚠️ A log-only plugin ran for both WLANs of a real AP; **no plugin that changes hostapd behaviour has run yet.** An opt-in hook (`config.plugins`, `/etc/openuf/plugins/<name>.lua`) lets a separate project edit each provisioned WLAN's UCI options. Off by default ([docs/PLUGINS.md](docs/PLUGINS.md)) |
| Channel and TX power per radio | ✅ Low/Medium/High/Custom. Channel **Auto** is written through as `channel=auto`, so hostapd ACS picks on the AP; TX power **Auto** deletes `txpower` so the driver default applies |
| Radio enable / disable | ✅ Transmit Power → **Disabled** arrives as `radio.<n>.status=disabled` → UCI `disabled`. Only an explicit value is written, so a push that omits the key leaves a hand-disabled radio alone |
| Channel width per radio | ✅ From `radio.<n>.ieee_mode`, which carries the **band and the width and nothing else** — its `ht` is Atheros-era vocabulary, not a request for 802.11n. openUF takes the width from the wire and the PHY generation from `iw phy`, then clamps to what the radio really supports |
| Device identity vs. management MAC | ✅ **Verified on real hardware.** openUF identifies by `lan_cpueth`'s MAC but reports the bridge's address; where those are different netdevs (DSA), the bridge is pinned to the identity MAC at startup, or the gateway raises an IP conflict against a correctly configured network |
| IoT Optimization: Lock 2.4 GHz to Channel 6 / DTIM Interval Lock | ✅ Both are controller-side shortcuts that arrive as an ordinary `channel=6` and `dtim_period=3` |
| IoT Optimization: Force WiFi 4 Mode | ✅ Most of the mode arrives as ordinary keys (2.4 GHz only, WPA2, PMF/BSS-transition/proxy-ARP off). ⚠️ Its one distinct effect, suppressing the QBSS Load IE via `bss_load_update_period`, is not verified on hardware |
| BSS Transition (802.11v) | ✅ Needs a full `wpad` build |
| 802.11k (per WLAN) | ✅ Lab-confirmed both ways, and deployed unchanged on both APs. REST-only — the 10.6 UI has no control — and the WLAN's toggle decides, as on a UniFi AP. Band Steering and Roaming Assistant force it on anyway, because usteer needs it. ⚠️ Without usteer nothing fills hostapd's neighbor list, so a client asking for a neighbor report gets no other AP |
| Band Steering | ✅ Via `usteer`: a real client was moved 2.4 → 5 GHz by an accepted 802.11v request, and the off switch is confirmed in the running daemon (`band_steering_interval` 0). The AP's own Prefer 5G setting is confirmed as far as the wire and the daemon go; ⚠️ a client steered by it alone has not been observed. **Balance** has no usteer equivalent and is ignored with a log line — no firmware build names it either |
| Airtime Fairness | ✅ On confirmed on both APs, all four radios. ⚠️ Off is lab-confirmed here (and on a third party's mt76 board). **Check the device's setting after upgrading:** a controller may hold it off from before openUF claimed `wifi_caps` `0x20`, and the first push then turns the kernel's fairness off. On is mac80211's own default, so only Off changes anything; the value is kept in `state.json` and reapplied at startup, since debugfs resets on reboot |
| Auto 802.11 DTIM Period | ✅ Auto and Custom both arrive as a concrete `dtim_period` |
| U-APSD (WMM power save) | ✅ Lab-confirmed both ways and on hardware (`uapsd_advertisement_enabled=0` in every BSS on both APs). The controller's setting decides — **off unless the WLAN enables it**, which is its default |
| Group Rekey Interval (GTK) | ✅ Lab-confirmed and on hardware (`wpa_group_rekey=3600` in every BSS). The controller's value decides, and **0 turns rotation off** — a WLAN created in the 10.6 UI may store 0, so check the setting |
| Multicast Enhancement (multicast-to-unicast) | ✅ From `wireless.<n>.mcast.enhance` |
| Multicast Suppression (formerly "Multicast and Broadcast Blocker") | ✅ Confirmed on real hardware for the source-MAC half (14 of 14 broadcast frames dropped from a non-allow-listed sender, 0 of 15 once allow-listed). Three positions, and the wire names none of them: the mode is the *pair* of keys, both behind `wifi_caps2` `0x400000`. No hostapd option exists for any of it, so it is enforced with nftables. **Aggressive** now honours the controller's ARP/ND/DHCP carve-out; **Conservative** rate-limits instead of blocking. ⚠️ The carve-out and the rate limit are lab-validated only, and ⚠️ the 100 pkt/s ceiling is openUF's own number — the controller sends none. **Needs `kmod-nft-bridge`**, without which only the drop rule is rejected and the control looks enabled while filtering nothing |
| Minimum Data Rate Control | ✅ Wire confirmed. Applied per **radio** — OpenWrt's rate options are `wifi-device` ones, so WLANs sharing a radio collapse to the most permissive floor. Turning it off tears the options down again, marker-tracked, leaving hand-tuned rates alone |
| Proxy ARP | ✅ → `proxy_arp`. Needs a full `wpad` build (hostapd compiles proxy-ARP in only with `CONFIG_PROXYARP`) |
| Client Isolation | ✅ → `isolate` (hostapd `ap_isolate`) |
| Hide WiFi Name | ✅ → `hidden` (hostapd `ignore_broadcast_ssid`) |
| MAC Address Filter | ✅ Arrives in a top-level `macacl.<m>.*` section keyed by **devname**, not by WLAN index → `macfilter` + `maclist`, enforced by hostapd itself |
| WiFi Speed Limit | ✅ **Per client**, as the firmware does it: each client on a limited SSID gets its own queued class each way. Live on both APs with a 5/2 Mbps SSID — a phone held 4.5 down and 1.95 up. A client's own profile or a guest's portal limit replaces the WLAN's. **Needs `tc-tiny` and `kmod-ifb`**; without `kmod-ifb` upload is policed instead of queued, and openUF logs that once. Two firmware behaviours kept on purpose: moving a client back to Default lifts its limit until it reconnects, and the 64 kbps guaranteed minimum is not applied |
| Roaming Assistant | ✅ **Verified on real hardware**: a client stuck at −80 dBm on one AP was moved to the other (−61 dBm) and stayed there. Per WLAN, 5 GHz; a weak client gets an 802.11v request toward an AP that hears it at least 8 dB louder, then a disassociation if it stays. Needs `usteer` on every AP. ⚠️ Leaving a client alone when no better AP exists is unit-tested only |
| Minimum RSSI | ⚠️ Per **radio**, not per WLAN, and enforced as the firmware does: hostapd ignores probes and refuses association below threshold + 3 dB, and a client below the threshold for 30 s is deauthenticated once (a kick, not a block). Confirmed reaching hostapd's live config and being removed again; **a refused or kicked client has not been observed** |
| Load balance (per-radio client cap) | ⚠️ REST-only (10.6's UI has no control). Over the cap, openUF deauthenticates the most idle clients once each; nothing stops a new client from joining, as on a UniFi AP. The idle-time reading works on ath10k and mt76; **no real kick has been observed** |
| WiFi Blackout Schedule | ✅ Confirmed on hardware on all three drivers: a WLAN goes off the air for its windows and comes back within one heartbeat of each edge, without touching the other SSIDs. Nothing is taken down before a controller answer agrees with the clock. ⚠️ While a WLAN is blacked out hostapd logs "Failed to set beacon parameters" every few seconds — harmless, but it crowds the log |
| SAE tuning (anti-clogging, sync, groups) | ✅ Confirmed on hardware, all radios. Not wifi-iface options, so they go in as `hostapd_bss_options` raw lines (24.10+; older releases drop them) |
| Key caching, TDLS, Country IE (`auth_cache`, `tdls_prohibit`, `country_beacon`) | ✅ `tdls_prohibit` and `country_beacon` live on both APs; ⚠️ `auth_cache` → `okc` is lab-only, since neither AP runs an Enterprise WLAN. All three are REST-only wlanconf fields. **On 5 GHz the Country IE cannot be turned off**: hostapd refuses the interface with *"Cannot enable IEEE 802.11h without IEEE 802.11d enabled"*, so the controller's "off" is honoured on 2.4 GHz only, with a log line |
| Pairwise cipher (`wpa.1.pairwise`) | ⚠️ Lab-confirmed on the wire; on hardware what is proven is the capability probe. The controller's cipher wins over openUF's derivation (`ccmp-256`/`gcmp` become an `encryption` suffix; `CCMP` writes nothing, being OpenWrt's default; `gcmp-256` cannot arrive). **Gated on the radio**, because hostapd treats an unprogrammable cipher as fatal — and the asymmetry is real: the Archer C5's ath9k 2.4 GHz radio has GCMP while its ath10k 5 GHz radio does not |

### Reporting and statistics

| Feature | Status |
|---|---|
| Wireless client statistics | ✅ Per-client traffic, signal, MIMO/generation and TX MCS, as the firmware sends them: `rssi` is the SNR, with the radio's `noise` and `is_11r` beside it. ⚠️ Power save is reported only where mac80211 tracks it (ath9k here), and has not been seen as `true` on the controller |
| Radio statistics | ✅ Channel utilization over the last inform interval (it was a since-boot average before), avg. signal/interference/airtime, per-VAP "Air Stats" and per-client "TX Retries". On mt76, underflowed retry counters read as 0 and drops are `failed − retries` |
| "Possible interference" warning | ✅ On **ath9k** radios, live: openUF sends the hardware transmit-timeout and carrier-sense-timeout counts and the controller logs the warning when either rises faster than 10/s. ath10k and mt76 keep no such counters, so they never raise it. ⚠️ On real radios the counts rise far below 10/s, so it has only fired on synthetic ones |
| Device load and memory | ✅ Live: **Memory Usage** (`system-stats`) and **Load Average** (`sys_stats`, `/proc/loadavg` verbatim). Each VAP also reports which side of the primary its secondary 20 MHz channel sits on |
| WiFi Experience / satisfaction score | ✅ UniFi's own formula, ported from the AP firmware: the lowest of SNR, the mean of tx and rx rates in fixed steps, and retries per frame over the last full minute less drops — with the reason, the anomaly bits, the per-WLAN charts and a per-radio score. The firmware's TCP and WiFi-latency terms have no mac80211 source, so they always score 100. **Trade:** a 2.4 GHz single-stream client tops out at 85 where openUF's own earlier estimate read 100. Behind a UniFi gateway `anomalies` reads −1, because the gateway's report of each client overwrites the AP's — as it would a real UniFi AP's |
| Ethernet port statistics | ✅ One entry per **physical socket**, with the speed and duplex that socket really negotiated (the CPU netdev only ever knows the internal SoC↔switch link, always 1000/full). The uplink is detected from the switch's ARL table, or from the bridge FDB on DSA, so it follows the cable. Per-socket packet/multicast/drop counts do not exist, so those columns stay empty rather than carrying the CPU port's totals |
| Wired client statistics | ✅ Hosts land on the socket they are really plugged into, with a `vlan` that puts them on the right *network* as well as the right port. A socket whose MAC learning openUF turned off is served by an nftables tap instead. ⚠️ Behind a UniFi gateway these clients' **usage history** (24 h / hourly / daily) is wildly inflated — a controller-side collision between the AP's byte-less rows and the gateway's lifetime counters, which a real U6-IW should hit too. The live totals and the port attribution are correct |
| Environment / rogue-AP scanning | ✅ Confirmed rendering live. Read from the kernel's passive BSS cache, so on its own it lists only neighbours on the radio's **own** channel; openUF never dwells off-channel behind a client's back |
| Sibling-AP recognition (no false "impersonator" warnings) | ✅ openUF APs beacon a vendor element with their device MAC and tag each other; without it every other openUF AP was flagged as a third-party AP broadcasting your SSID. openUF also reads a real UniFi AP's own element, so genuine UniFi APs are reported as UniFi on a mixed site. The reverse does not hold, deliberately: openUF does not beacon Ubiquiti's element, which a real AP would act on |
| RF environment enrichment (802.11k beacon reports) | ✅ The mechanism Ubiquiti's Channel AI describes as *"neighbor reports and automated RRM scans"*: openUF asks one 802.11k-capable **client** to sweep, so the client goes off-channel and the AP never does. Took a 5 GHz radio's list from **0 neighbours to 4**, including an AP it cannot itself hear. Rows carry SSID, security and width from hostapd's control socket, and the signal is calibrated per client, because some clients write signed dBm into the RCPI byte. One client per hour; off with `rrm_enrichment = false` |
| WiFi Connectivity (Insights → AirView) | ✅ Live. Before this the view read **0 %** on every stage: the controller builds it only from per-connection notifs. openUF reports each connection's Association, Authentication, DHCP and DNS stages with real timings, from hostapd's events and a passive nft table. A client that sends no DNS query within 30 s is not reported, because the controller's Success rule needs a DNS answer. Off with `assoc_tracker = false` |
| Roaming events (Insights → AirView) | ✅ Live, with Failed roams and the Fast Roaming and Roaming Assistant tags; ⚠️ the Minimum RSSI tag is lab-only. The AP a client left without a word learns of it from its bridge, in the same second, and stops listing the client at once — listed, the controller's 10.6 fallback records the roam a second time. Needs `ip-bridge`; off with the Connectivity reports |
| LLDP topology announcement | ✅ Via `lldpd` — **set `lldpd.config.cid_interface` to your LAN network**, or the controller shows the wrong Parent Device ([USAGE § 7](USAGE.md#7-lldp-topology)) |
| RF/spectrum scan (Airtime Scan) | ✅ Live: Scan Now scans channel by channel with the WLANs up (clients see ~200 ms bumps, not a disconnect) and the Environment tab charts per-channel utilization at 20/40/80 MHz. Coarser than a UniFi AP's own scan: survey busy time from a 200 ms listen plus the noise floor, not Qualcomm spectral analysis |
| DFS radar detection (event + alert) | ⚠️ **Lab-confirmed end to end; no live radar hit — radar cannot be produced on demand.** openUF sends `EVT_AP_RadarDetected` with the channel and frequency, so the controller logs *"&lt;AP&gt; detected radar on channel 100 (5500 MHz)"*. Read off hostapd's control socket, whose `freq` is where the radar was, not the BSS's centre. Of the eleven `EVT_AP_*` events the controller handles, this is the only one a UniFi AP sends |

### Device management

| Feature | Status |
|---|---|
| Locate (LED identify blink) | ✅ Requires `dev.conf.led` naming an LED that is **actually wired** ([USAGE § 3](USAGE.md#3-configuration)). Locate snapshots whatever trigger the LED was driving and restores it on stop, so it survives a restart landing between `set-locate` and `unset-locate` |
| Manage → LED steady on/off | ✅ Same `dev.conf.led` requirement. Persisted and re-applied at startup, and re-asserted when a Locate ends |
| L2 hardening (the controller's `ebtables.*` rules) | ✅ The BPDU drops and the inbound 802.1Q-tag drop the controller pushes for every SSID are enforced as nftables rules on the AP VAPs, rebuilt at start and whenever the VAP list changes. ⚠️ Read back with `nft list` on both APs; no frame has been sent at them. **Needs `kmod-nft-bridge`** |
| Client block / unblock | ✅ nftables enforcement that persists across restarts, plus hostapd's deny list on every SSID, as the firmware's driver does. A WiFi restart empties that list, so openUF re-checks it when hostapd recreates an SSID, every heartbeat for a minute after a push, and otherwise once a minute. Every config push also carries the site's whole block list, so a missed command is corrected. ⚠️ The list is confirmed in live hostapd; a refused real client has not been observed |
| Client → Reconnect | ✅ `kick-sta` is a one-shot deauth on every SSID, not a block: live on the AX3000T, a phone was deauthenticated and came back on its own 61 s later with no block-table entry |
| Guest portal (Hotspot) | ⚠️ **Lab-validated only, never run on hardware. Don't use it on a real guest WLAN yet.** The whole loop works in the lab: an unauthorized guest is blocked except for DHCP, ARP, DNS and the portal, its first plain-HTTP request is redirected with its MAC attached, and `authorize-guest`/`unauthorize-guest` let it through or block and disconnect it. `selfrun_guest_mode` decides what guests get when the controller is unreachable, as in the firmware; its `off` position is hardware-tested on its own. The **walled garden** is enforced in both forms — an IP entry as an ebtables rule (silently unenforced before, since a garden entry carries no port) and a domain entry resolved on the AP every ten minutes, with the last good answer kept in `state.json`. Narrower than the firmware on purpose: DNS passes for everyone, HTTPS is dropped rather than answered, and the redirect needs an IPv4 address on the guest bridge. Needs `kmod-nft-bridge` ([USAGE](USAGE.md#guest-portal-hotspot--lab-validated-only)) |
| IP Settings (DHCP / static) | ✅ Reconfigures the device's own management interface, including the DNS servers in the controller's order. DNS is applied on the static path only; on DHCP the lease supplies it. A static address is re-applied on every start |
| Per-port VLAN assignment | ✅ **Verified on real hardware on DSA** (full DHCP handshake captured at three points), where the assigned socket moves into that VLAN's `br-openuf<id>` bridge — the same L2 a tagged SSID uses — and gets **MAC learning turned off**, because the socket shares one address table with the uplink and an entry there makes the switch drop the reply in hardware while outbound stays perfect. Native VLAN only; a tagged-only port is refused out loud. ⚠️ On **swconfig** boards it writes `switch_vlan` sections, unit-tested but never run against a real switch ASIC. Needs the `hasOWRTSwitch` bit and **Port VLAN** ticked on the device |
| Timezone, NTP servers, nightly neighbour scan | ✅ Read back on both APs. The site timezone and NTP servers go to UCI with the board's originals stamped alongside, and the controller's nightly `11k-scan` job is installed in a marked crontab block. As on the firmware, it scans every radio twice at random times within the hour, so APs whose cron fires at the same second do not all go off-channel together |
| Nightly DFS channel reset (`dfs-reset`) | ⚠️ **The decision path is verified on both APs; no live radar hit, so the switch has not fired in anger.** For each 5 GHz radio openUF compares the live channel against the configured one and announces a CSA back to it, unless the channel is still on the kernel's non-occupancy list. Nothing for a radio on `auto`, nothing on 2.4 GHz, and UCI is never written — which is what makes it a *reset* |
| Auto-channel limits (site DFS switch, channel blacklist) | ⚠️ **The option reaches live hostapd on both APs; no radio here runs on Auto, so an ACS run under the restriction has not been observed.** Two per-radio keys behind `wifi_caps2` `0x10`, which openUF now claims — before, a site that excluded channels was silently ignored. The blacklist is inverted into hostapd's `chanlist`, since hostapd has no blacklist, and removed again when it leaves the wire |
| On-demand neighbour scan (`scan`, Radio AI `scan_band`) | ✅ Both trigger a real sweep of the requested radio or band, and the fresh neighbours go out on the immediate re-inform, which is what clears the controller's "scanning" flag. Before, both were silently ignored |
| Set Replacement Device / Load Configuration | ✅ Both are controller-side clones; no device-side protocol involved |
| Power / PoE reporting | Not applicable — the flagged UI field belongs to the upstream parent device, not the AP |
| Speed test | Not applicable — gateway-only feature in current UniFi Network |
| SSIDs on uplink loss | Matches UniFi firmware for this config: an AP only takes its SSIDs down when the controller sends `connectivity.status=enabled`, which it does only for devices claiming wireless-uplink support. openUF cannot claim that, so it gets `disabled` — and a UniFi AP would keep its SSIDs up too |
| USG / USW emulation | Not implemented, not planned |

## Supported hardware

A dual-band OpenWrt device with **at least 16 MB flash**, and roughly **5 MB free on
`/overlay`** after the stock image.  8 MB is not enough: the AES-GCM backend
(`lua-openssl`) pulls in `libopenssl3` at ~4.35 MB, and adoption cannot complete without
GCM — a stock 8 MB build leaves only ~1.6 MB of overlay, which no crypto backend fits in
(`openssl-util` and `luaossl` depend on the same library).  Measured on a TL-WDR3500 v1,
which is 3.2 MB short and therefore **cannot run openUF from a stock image** — it needs
USB extroot or a custom build with the crypto baked into squashfs.  Known-working:

- **TP-Link Archer C5 v1** (dual-band 802.11n/ac) — use `modelmap/archer-c5-v1.lua`.
  **The reference device**: install, adoption, the WiFi config push, live clients and the
  radios themselves are confirmed on this board (OpenWrt 25.12.5) against a real UniFi Cloud
  Gateway Ultra — see
  [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md#findings-only-real-hardware-could-show)
- **TP-Link TL-WDR3500 v1** (dual-band 802.11n, 2x2) — use `modelmap/tl-wdr3500-v1.lua`.
  Adoption, SSID provisioning, 802.11r/k/v, Band Steering, Minimum RSSI and WiFi Speed
  Limit all confirmed on real hardware against a UCG Ultra.
  ⚠️ **8 MB flash: does not fit a stock image** (see the space requirement above) — it needs
  a custom build with the crypto in squashfs. Even then **`nftables` typically does not fit**
  (~490 KB with its kernel modules), which leaves two features unavailable on this board:
  **client Block/Unblock** and **Multicast Suppression**. Its radio order is
  also the reverse of the Archer C5's — `radio0` is 2.4 GHz here
- **Xiaomi Mi Router AX3000T** (dual-band 802.11ax, 2x2) — use `modelmap/xiaomi-ax3000t.lua`.
  The first **DSA** board here (mediatek/filogic, MT7981) and the first with real 802.11ax:
  HE on both bands, 160 MHz on 5 GHz, nothing clamped except the 40 MHz ceiling 2.4 GHz has
  anyway. Plenty of room — 128 MB RAM, ~56 MB free overlay, every optional feature fits.
  Two board notes: its four sockets are the netdevs `wan`/`lan2`/`lan3`/`lan4` (there is no
  `lan1` — DSA names ports from the device tree, not the case labels), and it exposes **no
  status LED** (`/sys/class/leds` holds only the two mt76 radio LEDs), so Locate blinks
  `blue:status` — **install `kmod-leds-gpio`** (9 KB) or the board has no drivable LED at
  all: its case LED is a blue/yellow GPIO pair the stock filogic image ships no driver for,
  leaving it stuck on whatever the bootloader set (a steady orange). `install.sh` adds the
  module when it sees that situation. Do not point `dev.conf.led` at `mt76-phy0` instead —
  it exists and accepts writes, but is wired to nothing on this board
- **BT Home Hub 5 Type A** (dual-band 802.11n/ac) — use `modelmap/bt-homehub-v5a.lua`.
  lantiq/xrx200 with a DSA switch (GSWIP): `lan1`..`lan4` are bridge ports of `br-lan`, the
  `wan` socket is not used by an AP and not reported. `radio0` is 5 GHz (ath10k, QCA988x),
  `radio1` 2.4 GHz (ath9k). Adoption, the WiFi config push and live clients are confirmed
  on OpenWrt 25.12.6 against a UCG Ultra; plenty of room (~98 MB free overlay, ~35 MB RAM
  available before openUF). Locate drives `green:broadband`, the DSL LED, which has no
  other consumer on an AP. Not yet confirmed on this board: `install.sh`, the controller's
  radio settings (channel, width, power) and Locate itself. VLAN-tagged SSIDs build on
  `lan1`, so they assume the uplink cable is in `lan1`
- **TP-Link WR1043ND v2** (single-band 802.11n) — use `modelmap/tl-wr1043ndv2.lua`

The *modelmap* describes your real hardware; the *ufmodel* picks the UniFi identity to present.  `ufmodel/u6iw.lua` (U6-InWall) is the default and the only one validated end-to-end — `uapg1`, `uapg1-lr`, and `uapg2-ac-lr` are also provided but untested.

## Quick start

```sh
# 1. SSH into the OpenWrt device, install dependencies (OpenWrt 25.12+ uses apk;
#    on 24.10 and earlier the same names go through `opkg install`)
apk update
apk add lua lua-cjson luasocket lua-openssl luabitop libuci-lua iw lldpd nftables kmod-nft-bridge hostapd-utils usteer ip-bridge tc-tiny kmod-ifb
# A stock image ships wpad-basic-*, which a controller-pushed WLAN takes down.
# Swap it for the full build of the same library in one transaction (on
# opkg: opkg remove wpad-basic-mbedtls && opkg install wpad-mbedtls):
apk add wpad-mbedtls '!wpad-basic-mbedtls'

# 2. Download and install the latest release (no git client or scp needed)
mkdir openuf-install && cd openuf-install
wget https://github.com/jonasevcik/openUF/releases/latest/download/openuf.tar.gz
tar xzf openuf.tar.gz
sh install.sh install

# 3a. L2 adoption (device and controller on same subnet)
#     — The device will appear in UniFi Discover automatically.
#     — Click Adopt in the controller UI.

# 3b. L3 adoption (different subnets — no SSH from the controller needed)
ssh root@<device> syswrapper.sh set-inform http://<controller-ip>:8080/inform
#     — The device will appear as Pending in the controller.
#     — Click Adopt.
```

Both adoption paths complete to **Connected**.  L2 requires the controller to
SSH in (set a root password first, or use `--bootstrap-adopt`); L3 skips SSH
entirely and delivers the adoption key over the inform channel.

Step 1 is optional: `install.sh install` installs every dependency that is
missing, including `usteer` and a full `wpad` build — both required for BSS
Transition (802.11v) and Band Steering to work at all. A full build is
recognised by the hostapd binary itself, so any one counts and is left in place.
A `wpad-basic-*` build (what stock images ship) is replaced by the full build of
the same crypto library, in one transaction on apk, so a failed download leaves
the basic one working. It has to be: the controller sends `bss_transition` with
every WLAN, and a basic hostapd stops at "unknown configuration item
'bss_transition'" with the radio down.

`install.sh install` also registers `/etc/openuf/` and `/opt/openuf/conf.lua` with
`sysupgrade`, so an adopted AP stays adopted across a firmware upgrade — stock
`sysupgrade` backs up neither, and would take the authkey and the modelmap selection with
it. Existing entries in `/etc/sysupgrade.conf` are left alone; see
[USAGE.md](USAGE.md) for what uninstall does to them.

Installing from a git checkout instead (for contributors/dev builds) still works — `scp -r
openuf/ install.sh root@<device>:/tmp/openuf/` and run `install.sh` from there.

See [USAGE.md](USAGE.md) for full dependency details, configuration reference, and troubleshooting.

## Local testing (no hardware required)

```sh
# Install Lua on macOS/Linux
brew install lua luarocks      # macOS
# or: apt install lua5.1 luarocks  # Debian/Ubuntu

# Install test dependencies
luarocks install --local lua-cjson

# Run unit tests (all pure Lua)
eval $(luarocks path --local)
lua tests/run_tests.lua

# Full end-to-end adoption round-trip against the Python controller stub
# (needs pycryptodome, luasocket and lua-cjson):
sh tools/simulate.sh --adopt

# Or drive it manually:
pip install pycryptodome
python3 tools/test_controller.py --adopt --verbose
# In another terminal, run from inside the openuf/ dir (the scripts load
# conf.lua and the modelmap with cwd-relative paths):
cd openuf && lua inform.lua
```

`tools/cfg-coverage.lua <capture>` answers the other half of a capture: of the
keys the controller pushed, which ones openUF actually reads. It replays the blob
through every parser, once per key with that key removed and once with its value
changed, and reports each key as consumed, inert or ignored — so a consumer wired
to a key nothing produces shows up as a row instead of as a silent no-op. See
[`tools/validation/README.md`](tools/validation/README.md).

On a real AP, `tools/heartbeat-probe.lua` reports what one inform actually costs
that board — every process spawned and file opened, per command and path — by
building its own payload in a throwaway process alongside the running daemon.
See [USAGE § 8](USAGE.md#measuring-what-a-heartbeat-costs-on-the-device).

## Protocol notes

openUF implements the **TNBU binary inform protocol**:

- HTTP POST to `/inform` every 10 seconds, or at the interval the controller's `noop` asks for (clamped to 5–300 s)
- Binary header: `TNBU` magic + version + MAC + flags + 16-byte IV + data version + payload length
- Payload: JSON, AES-128 encrypted with the device's authkey — CBC, or GCM (with a
  40-byte AAD) once the controller sets `use_aes_gcm`.  Controller responses may be
  zlib-compressed; openUF decompresses them with a bundled pure-Lua inflater
- Default pre-adoption key: `ba86f2bbe107c7c57eb5f2690775c712`
- Adoption: L2 — controller SSHes in and calls `syswrapper.sh set-adopt <url> <newkey>`;
  L3 — new authkey arrives in the `setparam` response's `mgmt_cfg`

Key reference material:
- [docs/WIRE-REFERENCE.md](docs/WIRE-REFERENCE.md) — the protocol itself as openUF implements it: envelope, response types, every `system_cfg` key and every field openUF sends back
- [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md) — how each of those claims was established, what the lab cannot show, and what is still open; supersedes the below where they disagree
- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway) — primary protocol reference; live Python daemon tested against real controllers
- [jeffreykog/unifi-inform-protocol](https://github.com/jeffreykog/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)

## Questions, bugs and ideas

- **Bug or a controller setting that has no effect:** open an [issue](https://github.com/jonasevcik/openUF/issues/new/choose) with the bug template. It asks for what the device itself reports (`logread`, `/var/run/hostapd-*.conf`, `nft list`), not only the UCI you wrote.
- **A feature the controller can push:** open an issue with the feature template. A before/after diff of `system_cfg` across the toggle is the most useful evidence.
- **A question, or an idea you want to talk through before building it:** use [Discussions](https://github.com/jonasevcik/openUF/discussions). Please start there before sending a pull request for a larger change.
- **This is a public repository, so mask what you paste.** Replace real MACs and IPs with placeholders (`00:00:5e:00:53:01`, `192.0.2.1`). Never paste `/etc/openuf/state.json` (it holds the adoption `authkey`), a raw `system_cfg` (WLAN passphrases and `iapp_key`), or an unredacted `/var/run/hostapd-*.conf`.

## License

MIT — see [LICENSE](LICENSE).
