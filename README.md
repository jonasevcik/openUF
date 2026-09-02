# openUF

[![Tests](https://github.com/jonasevcik/openUF/actions/workflows/test.yml/badge.svg)](https://github.com/jonasevcik/openUF/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Lua 5.1+](https://img.shields.io/badge/Lua-5.1%2B-blue.svg)](https://www.lua.org/)

openUF is a Lua daemon that makes an OpenWrt device appear as a **Ubiquiti UniFi U6-InWall** (or other UniFi AP models) to a UniFi Network Application controller.  The controller can then adopt the device, push SSID and network configuration, and display live client and radio statistics — all without genuine Ubiquiti hardware.

Tested end-to-end against **UniFi Network Application 10.4.57** — both a self-hosted Docker controller and a real UniFi Cloud Gateway Ultra adopting a TP-Link Archer C5 v1 running openUF, with real clients associating to the pushed SSID.  The default device identity presented is **U6-InWall** (model `U6IW`).  openUF emulates a UniFi **access point** only — gateway (USG) and switch (USW) emulation are not implemented and not planned.

Most rows below marked ✅ were verified by driving the real controller UI against a live openUF device and reading back the resulting wire capture; [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md) records the evidence, including where a claim rests on decompiling the controller rather than a live capture.

## What it does

### Adoption and transport

| Feature | Status |
|---|---|
| L2 UDP discovery (port 10001) | ✅ Working |
| TNBU inform protocol | ✅ Working — AES-128-CBC and AES-128-GCM |
| AES-128-GCM | ✅ Working — **required**: 10.4.57 will not finish provisioning a device until it receives a genuine GCM inform. Needs a GCM-capable `lua-openssl` build |
| L2 adoption (SSH `syswrapper.sh set-adopt`) | ✅ Working — completes to **Connected** |
| L3 adoption (`set-inform`, no SSH) | ✅ Working — the controller skips SSH entirely and delivers the new authkey in the `setparam` `mgmt_cfg`; openUF accepts it only while unadopted. The controller chooses this path when it has *not* discovered the device via broadcast, which is what `config.l2_announce = false` is for — same-subnet devices that can't accept an SSH login need it |
| Zero-touch bootstrap adoption | ✅ Optional (`install.sh install --bootstrap-adopt`) — a locked-down, non-root SSH account auto-disabled after adoption |
| Forget device / factory reset | ✅ Working (`syswrapper.sh reset-inform`) |
| Restart / reboot command | ✅ Working |
| Firmware upgrade requests | Stored (version/url), never applied — flashing controller-supplied firmware onto non-Ubiquiti hardware would brick it |

### WiFi provisioning

| Feature | Status |
|---|---|
| Controller-pushed SSID provisioning | ✅ Working (UCI); only `openuf_`-prefixed sections are created or deleted |
| Exclusive-WLAN mode (`use_only_unifi_wlan`) | ✅ Working — default `true` disables hand-configured SSIDs so the radios carry only what the controller pushed; reversible (openUF stamps what it disabled) |
| WPA2 / WPA3 / WPA2-WPA3 mixed security | ✅ Working — derived from the pushed AKM set plus `wpa3.support`/`wpa3.transition`. Requires `radio_caps2` bit `0x1` on each radio, which openUF sends when hostapd can really do SAE — without it the controller silently downgrades every WPA3 WLAN to WPA2. **WPA-Enterprise (802.1X) is not supported**: the wire protocol carries no RADIUS server, port or secret, so such a WLAN is skipped with a log line rather than mis-provisioned as a keyless WPA2 SSID |
| PMF / 802.11w (`ieee80211w`) | ✅ Working — from `aaa.<n>.pmf.status`/`pmf.mode`. PMF is just PMF: the WPA3-transition signal is `wpa3.support`/`wpa3.transition`, not these keys |
| Fast Roaming (802.11r) | ✅ Working — **verified on real hardware** by forcing a roam and watching for `auth_alg=ft` with no EAPOL 4-way, both between radios on one AP and between two APs. Both the WLAN-level `ft.status` and the SAE-only `wpa3.ft.status` are read; FT is enabled if either asks for it, since OpenWrt cannot enable 802.11r for one AKM alone. openUF sets the mobility domain (derived from the SSID, so every AP agrees without coordination) but deliberately leaves `ft_psk_generate_local` alone — pinning it broke fast roaming for every WPA3 client, see USAGE § 3 |
| VLAN-tagged SSIDs | ✅ Working — verified end-to-end on real hardware with a client on a tagged IoT network. From `aaa.<n>.br.devname` (`br0.<vlan>`), the wire's only VLAN signal: openUF builds a `br-openuf<id>` bridge holding the tagged uplink sub-device, joins the VAP to it, and — on a swconfig board — trunks the VID through the switch (a DSA board needs no trunk: with bridge VLAN filtering off the switch passes tags through, and the sub-device on the uplink socket takes its VID before the bridge sees it) — tagging the CPU port and the uplink socket only, never the LAN sockets, since on `ar8216`-family switches the tag flag is one global per-port bitmask and tagging a socket for the IoT VLAN makes it egress-tagged in VLAN 1 too, deafening the untagged wired client on it. Keep VLAN ids **below the switch's VLAN table size** (16 on some boards) — netifd has no `vid` option, so the id doubles as the table slot |
| Channel and TX power per radio | ✅ Working (Low/Medium/High/Custom; channel **Auto** is written through as UCI `channel=auto`, i.e. hostapd ACS picks on the AP; TX power **Auto** deletes the `txpower` option so the driver default applies again) |
| Radio enable / disable | ✅ Working — Transmit Power → **Disabled** arrives as `radio.<n>.status=disabled` (plus `wireless.<n>.status` on each of that radio's WLANs) → UCI `disabled`. Only an explicit value is written, so a push that omits the key leaves a hand-disabled radio alone |
| Channel width per radio | ✅ Working — from `radio.<n>.ieee_mode` (`11nght20`/`11naht40`/…), which carries the **band and the width and nothing else**: its `ht` is Atheros-era vocabulary, not a request for 802.11n (a real U6-InWall runs `11naht40` as HE40). openUF takes the width from the wire and the PHY generation from `iw phy`, then clamps down to what the radio really supports — a WiFi-6 identity also invites HE pushes at n/ac hardware, which hostapd would refuse to start on |
| IoT Optimization: Lock 2.4 GHz to Channel 6 / DTIM Interval Lock | ✅ Working — both are controller-side shortcuts that arrive as an ordinary `radio.<n>.channel=6` and `dtim_period=3`, needing no dedicated handling |
| IoT Optimization: Force WiFi 4 Mode | ✅ Wire protocol confirmed live (`wireless.<n>.iot` + `qbssload`); most of the mode arrives as ordinary keys (2.4 GHz-only, WPA2, PMF/BSS-transition/proxy-ARP off). Its one distinct effect, suppressing the QBSS Load IE via `bss_load_update_period`, is not verified against real hardware |
| BSS Transition (802.11v) | ✅ Working (`bss_transition`) — needs a full `wpad` build |
| Band Steering | ✅ Working via `usteer` — requires the `usteer` package and a full `wpad` build (see Quick start) |
| Auto 802.11 DTIM Period | ✅ Working — Auto and Custom both arrive as a concrete `dtim_period` |
| Multicast Enhancement (multicast-to-unicast) | ✅ Working — from `wireless.<n>.mcast.enhance` |
| Multicast and Broadcast Blocker | ✅ Confirmed on real hardware. No hostapd/OpenWrt option exists for it, so it is enforced with nftables in a dedicated `bridge openuf_bcfilt` table: 14 of 14 broadcast frames from a non-allow-listed sender were dropped on the way out the VAP, 0 of 15 once that sender was allow-listed. **Needs `kmod-nft-bridge`** — the drop rule is openUF's only bridge-family `meta` match and a stock image has no `nft_meta_bridge`, in which case the table, chain and allow-list all still build and only the rule is rejected. **Blocks LAN→WLAN broadcast/multicast except from allow-listed source MACs — this breaks DHCP for wireless clients unless the DHCP server's MAC is on the list**, which is Ubiquiti's own documented behavior |
| Minimum Data Rate Control | ✅ Wire protocol confirmed live (`wireless.<n>.minrate_data` + `beacon_rate`/`minrate_cck_rates.status`/`minrate_below_disable`). Applied per **radio** — OpenWrt's `basic_rate`/`supported_rates`/`legacy_rates`/`beacon_rate` are `wifi-device` options, so WLANs sharing a radio collapse to the most permissive floor. Turning the control off tears the options down again (marker-tracked, hand-tuned rates untouched) |
| Proxy ARP | ✅ Wire protocol confirmed live (`aaa.<n>.proxy_arp`) → `proxy_arp`. Needs a full `wpad` build (hostapd only compiles proxy-ARP support in with `CONFIG_PROXYARP`) |
| Client Isolation | ✅ Wire protocol confirmed live (`wireless.<n>.l2_isolation`) → `isolate` (hostapd `ap_isolate`) |
| Hide WiFi Name | ✅ Wire protocol confirmed live (`wireless.<n>.hide_ssid`, duplicated as `aaa.<n>.hide_ssid`) → `hidden` (hostapd `ignore_broadcast_ssid`) |
| MAC Address Filter | ✅ Wire protocol confirmed live. Arrives in a top-level `macacl.<m>.*` section keyed by **devname**, not by WLAN index, so it is joined on `wireless.<n>.devname` → `macfilter` + `maclist`. Allow/deny policy maps 1:1 onto OpenWrt's; enforced by hostapd itself |
| WiFi Speed Limit | ⚠️ Wire protocol confirmed live (top-level `qos.vap.<m>.*`, joined on devname; kbps; a **per-VAP aggregate** cap, not per-client). Needs a speed-limit profile to exist in site settings before the per-WLAN toggle emits anything. No hostapd/OpenWrt option expresses a throughput cap, so it is enforced with `tc` — HTB on egress for downlink, ingress policing for uplink. The generated commands are verified against real `tc`, but the on-air throughput is not (no real radios available). **Needs `tc-tiny` *and* `kmod-sched-act-police`**: the uplink half uses the `police` action, which is a separate module absent from some images — without it the download cap applies and the upload cap silently does not (`install.sh` installs both) |
| Minimum RSSI | ✅ Working — per **radio**, not per WLAN; enforced by deauthenticating clients below the threshold (a one-shot kick, not a persistent block). Disabling it in the controller stops the enforcement (the wire signals disable by omitting the whole `stamgr.<n>` block) |
| Show Access Point Name in Beacon | ✅ Wire protocol confirmed live (requires reporting the `wifi_caps2` capability bit); the OpenWrt-side beacon effect uses the standard WPS Device Name element, not independently verified against real hardware |
| SAE Anti-clogging / SAE Sync Time | ⚠️ Implemented from a decompile of the controller's WLAN-config generator. The controller only emits these for a genuine WPA3/SAE WLAN — not the mixed "WPA2/WPA3" option — and that emitting case was never reachable in the validation environment, so it is unconfirmed on the wire |

### Reporting and statistics

| Feature | Status |
|---|---|
| Wireless client statistics | ✅ Working — per-client traffic, signal, MIMO/generation, TX MCS (`vap_table[].sta_table`) |
| Radio statistics | ✅ Working — channel utilization, avg. signal/interference/airtime, per-VAP "Air Stats" |
| WiFi Experience / satisfaction score | ✅ Working — device-computed, confirmed rendering live |
| Ethernet port statistics (`port_table[]`) | ✅ Working — one entry per **physical socket** on swconfig boards, each with the link speed and duplex that socket actually negotiated, read from the switch (the CPU netdev only ever knows the internal SoC↔switch link, which is always 1000/full). Which socket is the uplink is detected from the switch's ARL table, so it follows the cable. Per-port byte counters from the switch's MIB, which openUF switches on at startup where the driver ships it off (`ar8xxx_mib_poll_interval`); packet/multicast/broadcast/drop counts are not available per socket, so those columns stay empty rather than carrying the CPU port's totals. Anomaly, STP and Profile are controller-side or USW-only — they read `-` for a real UniFi gateway's ports too. On a **DSA** board (no `swconfig`) the same shape comes for free from sysfs — each socket is its own netdev there, so its speed and duplex are its own — and the uplink is detected from the bridge FDB instead (`bridge fdb show br br-lan` names the port each MAC was learned on). Boards where neither source can answer keep the netdev-based single-port shape and a statically flagged uplink |
| Wired client statistics (`port_table[].mac_table`) | ✅ Working — hosts are placed on the socket they are really plugged into, from the switch's ARL table on swconfig boards (there `bridge fdb` can only ever say "behind the CPU port") and from the per-socket bridge FDB on DSA, where each socket is its own bridge port. The uplink socket and any socket outside the management VLAN report none, and the AP's own MACs and its wireless stations are never reported as wired clients |
| Environment / rogue-AP scanning (`scan_radio_table`) | ✅ Working — confirmed rendering live in the Environment tab |
| LLDP topology announcement | ✅ Working (via `lldpd`) — **set `lldpd.config.cid_interface` to your LAN network**, or the controller shows the wrong Parent Device: lldpd's default chassis ID is some other interface's MAC, which the controller can't match to the MAC openUF is adopted under. See [USAGE](USAGE.md#7-lldp-topology) |
| RF/spectrum scan | ⚠️ Best-effort trigger only — the result-reporting wire format is unconfirmed |

### Device management

| Feature | Status |
|---|---|
| Locate (LED identify blink) | ✅ Working — requires `dev.conf.led` set per board, naming an LED that is **actually wired** (see USAGE § 3). The LED need not be a dedicated status light: Locate snapshots whatever trigger it was driving, persists it, and restores it on stop, so it survives a restart landing between the controller's `set-locate` and `unset-locate` — and an interrupted Locate is torn down at the next start rather than blinking forever |
| Manage → LED steady on/off toggle | ✅ Working — same `dev.conf.led` requirement. Persisted and re-applied at startup, so it survives a reboot; it is also re-asserted when a Locate ends, since restoring the blink's previous trigger alone would leave a status LED dark |
| Client block / unblock | ✅ Working — enforced via nftables, persists across restarts |
| IP Settings (DHCP / static) | ✅ Working — reconfigures the device's own management interface, including the DNS servers (`resolv.nameserver.<k>.ip` → `/etc/resolv.conf`, in the controller's primary/secondary order). DNS is applied on the static path only; on DHCP the lease supplies it |
| Per-port VLAN assignment | ⚠️ Wire format fully mapped live (`switch.*`: device-level gate, per-VLAN table, per-port `pvid` plus a tagged/untagged/`exclude` matrix joined on `port_table[].port_idx`); requires reporting the `hasOWRTSwitch` capability bit and ticking **Port VLAN** on the device. Applied two ways depending on the board. On **swconfig** boards, as `switch_vlan` sections; requires a `dev.conf.vlan` port map plus a `swport` on the port, never touches the socket the uplink cable is in (detected at runtime, and refused outright when it cannot be determined), and is reversible — unticking the device-level **Port VLAN** box tears openUF's sections down and restores the stock port strings. The generated UCI is unit-tested, but that it programs a real switch ASIC is **not verified** (no switch hardware here). On **DSA** boards there is no switch table to write and `bridge-vlan` is deliberately not used: the assigned socket is moved out of `br-lan` and into that VLAN's `br-openuf<id>` bridge — the same L2 a tagged SSID on the same VLAN already uses, since they are one broadcast domain. `br-lan` keeps the uplink and the management address and nothing ever runs with `vlan_filtering`, so a wrong answer cannot strand the AP. **Verified on real hardware**; Native VLAN only (a tagged-only port is refused out loud) |
| Set Replacement Device / Load Configuration | ✅ Working — both are controller-side clones; no device-side protocol involved |
| Power / PoE reporting | Not applicable — the flagged UI field belongs to the upstream parent device, not the AP |
| Speed test | Not applicable — gateway-only feature in current UniFi Network |
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
  Gateway Ultra — see [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md#the-first-real-hardware-run)
- **TP-Link TL-WDR3500 v1** (dual-band 802.11n, 2x2) — use `modelmap/tl-wdr3500-v1.lua`.
  Adoption, SSID provisioning, 802.11r/k/v, Band Steering, Minimum RSSI and WiFi Speed
  Limit all confirmed on real hardware against a UCG Ultra.
  ⚠️ **8 MB flash: does not fit a stock image** (see the space requirement above) — it needs
  a custom build with the crypto in squashfs. Even then **`nftables` typically does not fit**
  (~490 KB with its kernel modules), which leaves two features unavailable on this board:
  **client Block/Unblock** and the **Multicast and Broadcast Blocker**. Its radio order is
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
- **TP-Link WR1043ND v2** (single-band 802.11n) — use `modelmap/tl-wr1043ndv2.lua`

The *modelmap* describes your real hardware; the *ufmodel* picks the UniFi identity to present.  `ufmodel/u6iw.lua` (U6-InWall) is the default and the only one validated end-to-end — `uapg1`, `uapg1-lr`, and `uapg2-ac-lr` are also provided but untested.

## Quick start

```sh
# 1. SSH into the OpenWrt device, install dependencies (OpenWrt 25.12+ uses apk)
apk update
apk add lua lua-cjson luasocket lua-openssl luabitop iw lldpd nftables kmod-nft-bridge hostapd-utils usteer ip-bridge tc-tiny wpad-wolfssl

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
Transition (802.11v) and Band Steering to work at all. Any full build counts
(`wpad`, `wpad-wolfssl`, `wpad-openssl`, `wpad-mbedtls`), and an existing one is
left in place. `wpad-basic-*` builds lack 802.11v support entirely and will error
with "unknown configuration item 'bss_transition'"; if you've manually installed
a basic build, replace it with `apk add wpad-wolfssl` first.

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

## Protocol notes

openUF implements the **TNBU binary inform protocol**:

- HTTP POST to `/inform` every 10 seconds
- Binary header: `TNBU` magic + version + MAC + flags + 16-byte IV + data version + payload length
- Payload: JSON, AES-128 encrypted with the device's authkey — CBC, or GCM (with a
  40-byte AAD) once the controller sets `use_aes_gcm`.  Controller responses may be
  zlib-compressed; openUF decompresses them with a bundled pure-Lua inflater
- Default pre-adoption key: `ba86f2bbe107c7c57eb5f2690775c712`
- Adoption: L2 — controller SSHes in and calls `syswrapper.sh set-adopt <url> <newkey>`;
  L3 — new authkey arrives in the `setparam` response's `mgmt_cfg`

Key reference material:
- [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md) — this project's own findings from running openUF against a real self-hosted UniFi controller; supersedes the below where they disagree
- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway) — primary protocol reference; live Python daemon tested against real controllers
- [jeffreykog/unifi-inform-protocol](https://github.com/jeffreykog/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)

## License

MIT — see [LICENSE](LICENSE).
