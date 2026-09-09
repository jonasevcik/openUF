# openUF — Usage Guide

## 1. Dependencies

Install the following apk packages on the OpenWrt device before running openUF.
OpenWrt 25.12 replaced `opkg` with `apk`; on 24.10 and earlier substitute
`opkg update` / `opkg install`.

```sh
apk update
apk add lua lua-cjson luasocket lua-openssl luabitop libuci-lua iw lldpd nftables kmod-nft-bridge hostapd-utils usteer ip-bridge tc-tiny wpad-wolfssl
```

On OpenWrt 24.10 and earlier the package manager is `opkg install` rather than
`apk add`; the package names are the same, and `install.sh` picks whichever one
the device has.

| Package | Purpose |
|---|---|
| `lua` | Lua 5.1 runtime |
| `lua-cjson` | Fast JSON encode/decode |
| `luasocket` | TCP client for HTTP POST to controller |
| `lua-openssl` | AES-128-CBC **and AES-128-GCM** (replaces `luacrypto`, which was dropped from the 25.12 feeds). Effectively mandatory — see the GCM note below |
| `luabitop` | bit operations for Lua 5.1 |
| `libuci-lua` | `require("uci")` — every radio and WLAN read and write goes through it. Not pulled in by `lua`. Without it the device adopts, reports its ports and statistics and looks perfectly healthy, while `radio_table` goes out **empty** and the controller has no radio to push a WLAN onto: pushes are accepted and no SSID is ever created. openUF says so at startup rather than leaving you to find it |
| `iw` | Radio and station statistics |
| `lldpd` | LLDP topology announcement and neighbor discovery |
| `openssl-util` | `openssl` CLI — last-resort AES-**CBC** fallback if `lua-openssl` is unavailable. This path cannot do GCM, so it is not sufficient to complete adoption on its own |
| `nftables` | Client block/unblock (`openuf/firewall.lua`) **and** the Multicast/Broadcast Blocker (`openuf/bcfilter.lua`). ~490 KB with its kernel modules — the first thing that won't fit on a small-flash board, which leaves both features unavailable (openUF logs that rather than pretending) |
| `kmod-nft-bridge` | The Multicast/Broadcast Blocker only. `nftables` does not pull it in, and without `nft_meta_bridge` the bridge family has no `meta` expression — so the blocker's drop rule is rejected while its table, chain and allow-list set all build normally. Client block/unblock matches on `ether saddr` alone and does not need it |
| `hostapd-utils` | `hostapd_cli` — immediate deauth of a just-blocked wireless client, client kick (Roaming Assistance) and Minimum RSSI enforcement |
| `tc-tiny` | `tc` — WiFi Speed Limit (`openuf/shaper.lua`). Busybox has no `tc`; without it the limit is recorded in UCI and never enforced |
| `kmod-sched-act-police` | The **upload** half of WiFi Speed Limit only. `police` is a tc *action*, a separate module from the ingress qdisc and absent from a stock filogic image. Without it the download cap applies and the upload cap does not — openUF logs which interface `tc` rejected and names this package rather than reporting the whole limit as applied |
| `coreutils-stat` | `stat` — only if your build has no `stat` applet (some do not). `inform.lua` uses `stat -c %Y` to notice an out-of-process `state.json` write, i.e. an SSH `set-adopt` or a manual `reset-inform`; without it those are ignored until restart. Enabling busybox's own `stat` applet is smaller |
| `usteer` | Band Steering (Behavior Controls) — ubus-based client-steering daemon, driven by `openuf/usteer.lua` |
| `wpad-wolfssl` (or `wpad-openssl`, `wpad-mbedtls`, `wpad`) | Full hostapd build with 802.11k/v support — required for BSS Transition and Band Steering. Any of the full builds will do; `wpad-basic-*` lacks `bss_transition` entirely and errors with "unknown configuration item 'bss_transition'" |

`install.sh install` installs all of the above automatically when missing, so a
manual `apk add` is only needed if you're not using the installer. It treats any
full `wpad` build as sufficient and leaves an existing one alone — notably
`wpad-mbedtls`, which is what OpenWrt 25.12 ships on ath79 — rather than swapping
it for `wpad-wolfssl` and bouncing every SSID on the device for no gain.

> **AES-GCM is required for adoption.** UniFi Network Application 10.4.57 will
> not finish provisioning a device until it has received a genuine
> AES-128-GCM-encrypted inform; a device that can only do CBC stays stuck at
> "Adopting" indefinitely. openUF's GCM support needs a `lua-openssl` build with
> AEAD/GCM available — the `openssl-util` CLI fallback above is CBC-only and will
> not get you adopted. See PROTOCOL-VALIDATION.md's "The GCM provisioning gate".

There is no Lua zlib binding in the OpenWrt 25.12 feeds. openUF therefore sends
inform payloads uncompressed and decompresses zlib-compressed controller
responses with a bundled pure-Lua inflater (`openuf/inflate.lua`), so no zlib
package is required.

Only required if your inform URL uses `https://` (uncommon — the UniFi default
is `http://…:8080/inform`): `apk add luasec` for the TLS client. Without it, an
`https://` URL fails with a clear error instead of connecting in cleartext.
`install.sh` installs it for you when — and only when — the URL it finds (the
adopted `state.json`, else `conf.lua`'s default) actually is `https://`.

---

## 2. Installation

Download the latest release directly on the device over SSH — no git client or scp required:

```sh
# On the OpenWrt device
mkdir openuf-install && cd openuf-install
wget https://github.com/jonasevcik/openUF/releases/latest/download/openuf.tar.gz
tar xzf openuf.tar.gz
sh install.sh install
```

Optionally verify the download before installing:

```sh
wget https://github.com/jonasevcik/openUF/releases/latest/download/openuf.tar.gz.sha256
sha256sum -c openuf.tar.gz.sha256
```

Releases are tagged `vX.Y.Z`; each tag push builds and publishes a new `openuf.tar.gz` via
GitHub Actions. If you're working from a git checkout instead (e.g. for development), the old
transfer-then-install flow still works:

```sh
# From your development machine
scp -r openuf/ install.sh root@<device-ip>:/tmp/openuf/
ssh root@<device-ip> "cd /tmp/openuf && sh install.sh install"
```

What `install.sh install` does:
- Copies `openuf/` to `/opt/openuf/` — **an existing `conf.lua` is kept**, and the shipped
  default lands beside it as `conf.lua.dist`. That file holds the modelmap selection,
  `l2_announce` and `bootstrap_adopt_user`, none of it re-derivable; overwriting it on an
  adopted AP resets the board to the generic profile, which changes `lan_cpueth`, changes
  the identity MAC, and leaves the controller unable to recognise the device. Because it is
  preserved, **re-running the installer is safe** — which is how you top up a dependency
  added by a later version
- Creates `/etc/openuf/` (state directory)
- Adds `/etc/openuf/` and `/opt/openuf/conf.lua` to `/etc/sysupgrade.conf`, so that a
  firmware upgrade keeps them. `sysupgrade` preserves `/etc/config` and a short built-in
  list and knows nothing about either path; without this a stock upgrade takes
  `state.json` — mac, authkey, cfgversion, `swvlan_backup` — and the modelmap selection
  with it, and the AP comes back unadopted, posing as a generic dualband AP the
  controller no longer recognises. Each line is appended only if it is not already there
  and nothing else in the file is touched, so a keep list you maintain yourself is safe.
  The Lua tree is deliberately *not* preserved: the installer reinstalls it, and carrying
  an old copy onto a new OpenWrt is a silent version mismatch
- Symlinks `/opt/openuf/hook/syswrapper.sh` → `/usr/bin/syswrapper.sh`
- Creates `/etc/init.d/openuf` with two procd service instances (announce + inform)
- Enables and starts the service
- Enables and starts `lldpd`

To uninstall:
```sh
sh install.sh uninstall
```

Uninstall removes the `/opt/openuf/conf.lua` line from `/etc/sysupgrade.conf` — the file
is gone with `/opt/openuf/` — but **keeps the `/etc/openuf/` line**. The state directory
itself is left intact so that the authkey survives, and un-registering it would let the
next firmware upgrade delete exactly what it is being kept for. Remove that line by hand
if you also delete `/etc/openuf/`; leaving it costs nothing either way.

---

## 3. Configuration

### Hardware model map (`openuf/conf.lua`)

Select the modelmap that matches your hardware:

```lua
-- For TP-Link Archer C5 v1 (dual-band, board-specific):
dev = dofile("modelmap/archer-c5-v1.lua")

-- For TP-Link TL-WDR3500 v1 (dual-band, board-specific):
dev = dofile("modelmap/tl-wdr3500-v1.lua")

-- For Xiaomi Mi Router AX3000T (802.11ax, DSA — no swconfig):
dev = dofile("modelmap/xiaomi-ax3000t.lua")

-- For any other dual-band OpenWrt AP:
dev = dofile("modelmap/generic-dualband-ap.lua")

-- For TP-Link WR1043ND v2 (single-band):
dev = dofile("modelmap/tl-wr1043ndv2.lua")
```

Prefer a board-specific map where one exists. A generic profile cannot know your
board's LED name (so Locate and the LED toggle do nothing) or which of its ports
is the uplink — and it gets the uplink wrong on an Archer C5 deployed as an AP,
which uses `eth1` and never touches `eth0`.

**swconfig or DSA?** `which swconfig` on the device settles it. A board with no
`swconfig` binary (anything on a modern target — mediatek/filogic, ath79's
successors, ipq40xx…) is DSA, and its map looks different: each socket is
already its own netdev, so the ports are listed by `ifname` and there is **no
`dev.conf.vlan` at all**. Don't invent one — it is what makes openUF shell out
to a `swconfig` that isn't there. `modelmap/xiaomi-ax3000t.lua` is the worked
example.

The modelmap sets:
- `dev.conf.net.lan_cpueth` — LAN CPU ethernet port (e.g. `eth1`); also the trunk port
  used to create VLAN-tagged sub-interfaces (`eth1.<vlanid>`) for controller-pushed VLAN SSIDs
- `dev.conf.vlan.mib_poll_ms` — how often the switch driver refreshes its per-port byte
  counters, which is where the Ports view's Tx/Rx figures come from. openUF turns polling on
  at startup (500 ms) when the driver ships it off, which an AR8327 does; set `false` to
  leave the switch alone, at the cost of 0 B on every socket
- `dev.conf.net.ports`      — the ports openUF reports to the controller, one entry per
  **physical socket** on a board with a switch: `{idx = 1, swport = "lan1"}`, where `idx`
  is the UniFi `port_idx` and `swport` names a key in `dev.conf.vlan.ports`. Pin each
  `idx` to a socket and leave it alone — the controller keys per-port settings on it.
  Do **not** flag one as `uplink`: openUF detects which socket the uplink cable is in
  from the switch's ARL table, so the flag follows a replug and the other sockets report
  their own link speed and their own wired clients. A board with no switch map instead
  uses the netdev shape (`{idx = 1, ifname = "eth0", uplink = true}`), which on a switch
  board can report only the CPU port's internal link. The two mix: a socket wired to its
  own MAC/PHY instead of the switch (the TL-WDR3500's WAN socket, `eth1`) is listed with an
  `ifname` and no `swport`, and sysfs then describes that socket correctly. Count the RJ45
  sockets on the case — the list should have one entry each.
  On a **DSA** board every socket takes the netdev shape and still gets no `uplink` flag:
  there the uplink is detected from the bridge FDB (`bridge fdb show br br-lan`, which
  names the port each MAC was learned on) instead of from a switch ARL table. Keep the
  flag only for a board where neither source can answer
- `dev.conf.net.wan_iface`  — WAN interface (e.g. `eth0`)
- `dev.conf.switch`         — Switch device name (e.g. `switch0`)
- `dev.conf.led`            — status LED, driven by the controller's Locate action and its
  **Manage → LED** toggle. Accepts a full sysfs path (`/sys/class/leds/tp-link:green:wlan`)
  or a bare LED name (`tp-link:green:wlan`). `nil` by default, since a generic profile can't
  know the board's LED — LED control is a silent no-op until you set it. Find yours with
  `ls /sys/class/leds`.
  ⚠️ **Check the LED you name is actually wired.** `/sys/class/leds` lists what the drivers
  registered, not what the case has. A radio LED (`mt76-phy0`, `phy0-led`) is registered by
  the wireless driver on every board whether or not the pin goes anywhere — Locate will
  report success and blink nothing. And a board whose LEDs are on GPIO needs the
  `kmod-leds-gpio` module: without it the device tree's LEDs never register at all, the
  GPIOs stay unclaimed at whatever the bootloader left, and only the radio LEDs show up.
  Both were true of a Xiaomi AX3000T. Confirm by writing to it and looking at the box:
  ```sh
  echo none > /sys/class/leds/<led>/trigger; echo 1 > /sys/class/leds/<led>/brightness
  ```
- `dev.openuf.uap.ufmodel`  — Which ufmodel file to load (e.g. `"u6iw"`)
- `dev.openuf.uap.hwassign` — UCI radio names to report to the controller
  (e.g. `{"radio0", "radio1"}`). Every other `wifi-device` on the board is left out of
  `radio_table`, so a radio the emulated model doesn't have (a third phy, a mesh- or
  monitor-only one) is neither shown nor configurable in the UI. Omit it — or leave it
  empty — to report every radio UCI knows about, which is what a modelmap without the
  field means. openUF never touches an unreported radio: a config push naming one is
  refused rather than applied

### Device identity (`openuf/ufmodel/u6iw.lua`)

The U6-InWall identity is configured in `ufmodel/u6iw.lua`.  The firmware version
(`fw.ver`) must be accepted by your controller.  If the controller rejects the
device with "firmware too old" or similar, increment `fw.ver` and try again.

```lua
uap = {
    platform = "U6IW",
    model    = "U6IW",
    fw = {
        pre        = "U6IW.",
        ver        = "6.6.55",    -- tune this if the controller rejects the device
        buildtime  = "230801.1200",
        factoryver = "6.5.28"
    },
    ...
}
```

### Paths and options (`openuf/conf.lua`)

```lua
config = {
    use_only_unifi_wlan = true,  -- disable non-openuf_ SSIDs during provisioning
    inform_url  = "http://unifi:8080/inform",   -- default URL (overwritten at adoption)
    state_file  = "/etc/openuf/state.json",
    l2_announce = true,          -- see below
    debug_dump_file = nil,       -- see below
    debug_dump_max_bytes = 4194304,
    bootstrap_adopt_user = nil,  -- see below
}
```

`l2_announce` — on by default; sends the UDP discovery broadcasts that make the
device appear in UniFi Discover with no `set-inform` at all. Set it to `false`
to be adopted over L3 only, and restart the service (the init script reads this
and simply doesn't start the broadcaster). The reason to turn it off isn't
noise: a controller that discovered a device via L2 adopts it *by SSHing in*,
so on a device that can't accept that login, adoption fails while the inform
loop looks perfectly healthy — see § 4.

`debug_dump_file` — opt-in, off by default. When set to a path (e.g.
`"/var/log/openuf-informs.log"`), every decrypted controller inform response is
appended verbatim, with a UTC timestamp, before it's dispatched. Used to capture
ground-truth payload shapes when validating field assumptions (`system_cfg`,
`cmd` dispatch, etc.) against a real UniFi controller — see
[PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md).

`debug_dump_max_bytes` — ceiling for that dump, default 4 MiB, `0` for none.
The dump is append-only and the inform loop writes to it every few seconds, so
left unattended it grows without bound — and its usual home is `/tmp`, which on
these boards is a RAM disk. One left on for five weeks reached 31.7 MB, 55% of a
59 MB tmpfs, on course to starve `state.json` writes and `apk` alike. Past the
cap the file **restarts** rather than rotating, leaving a marker line saying so:
a second generation would double the peak footprint on exactly the boards least
able to afford it, and a capture is read from its tail anyway.

The same flag also turns on a **dropped-key report** on stderr: one line per
config blob listing the keys no parser consumed, collapsed to key shapes with
counts, e.g.

```
inform: mgmt_cfg: 5 dropped key(s): capability x1, mgmt_url x1, report_crash x1, selfrun_guest_mode x1, stun_url x1
inform: system_cfg: 12 dropped key(s): switch.port.<n>.name x5, switch.vlan.<n>.id x4, ...
```

Most of what it lists is dropped deliberately (each case is explained in
PROTOCOL-VALIDATION.md's `system_cfg` section) — its value is showing you when
the controller starts sending something openUF has *never* seen, which is how
two whole features sat unnoticed in every capture for months. Key names and
counts only: these blobs carry passphrases and the adoption key, so no value is
ever logged.

`bootstrap_adopt_user` — set by `install.sh install --bootstrap-adopt`, not by
hand. Names the temporary SSH bootstrap account (see § SSH prerequisite below)
that `inform.lua` should lock/unlock as the device's adopted state changes.

---

## 4. Adoption flow

### SSH prerequisite

The controller SSHes into the device as `root` to run `syswrapper.sh set-adopt` during adoption.  **SSH must be accessible and the root password must be set** before clicking Adopt:

```sh
# On the OpenWrt device — set a root password if not already done
passwd root
```

Confirm SSH works from the controller's network before attempting adoption.  A fresh OpenWrt install often has a blank root password and SSH enabled; set the password first.

> **Security note:** openUF accepts a new `authkey` from the `mgmt_cfg` payload
> only while **not yet adopted** (needed for L3 adoption to complete at all — see
> the L3 section below and [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md)).
> Once adopted, that field is ignored — key rotation only happens via the SSH
> `set-adopt` path from that point on, matching real L2 hardware behavior.

#### Optional: zero-touch bootstrap adoption (`--bootstrap-adopt`)

Real Ubiquiti hardware ships a factory-default `ubnt`/`ubnt` SSH account
specifically so first adoption works without presetting anything — live testing
against a real controller (see PROTOCOL-VALIDATION.md) confirmed the controller's
SSH client tries exactly that account for L2-discovered, not-yet-adopted devices,
regardless of any admin-configured "Device SSH Authentication" credentials.
`install.sh install --bootstrap-adopt` sets up the same thing, scoped as tightly
as this project can manage:

```sh
sh install.sh install --bootstrap-adopt
```

- The account is **non-root**, a member of a dedicated `openuf` group with
  write access to `/etc/openuf` only — no other privilege, ever, even
  transiently.
- Its login shell (`openuf/hook/adopt-shell.sh`) is a forced-command wrapper
  that permits exactly one thing: running `syswrapper.sh set-adopt <url>
  <key>`. Any other command, or a plain interactive login attempt, is refused
  outright — the account can never be used as a general-purpose shell.
- Once the device is adopted, `inform.lua` locks the account (`passwd -l`) —
  it detects this within one poll interval (~10s) of the SSH-driven
  `set-adopt` writing new state. It re-enables the account automatically on
  a factory reset (`reset-inform`, or a controller-initiated "Forget Device"),
  so re-adoption after a reset works the same zero-touch way.
- This is entirely opt-in: a plain `install.sh install` (no flag) never
  creates this account and behaves exactly as documented above — the admin
  sets their own root password.

`uninstall` always removes the bootstrap account if present, regardless of
whether `--bootstrap-adopt` is passed to it.

### L2 adoption (device and controller on the same subnet)

1. Start openUF (`/etc/init.d/openuf start` or `sh install.sh install`)
2. The `announce.lua` process sends UDP broadcasts to port 10001 every 10 seconds
3. The device appears in **UniFi Discover** with model "U6IW"
4. Click **Adopt** in the controller
5. The controller SSHes into the device and runs:
   ```sh
   syswrapper.sh set-adopt http://<controller>:8080/inform <32-char-hex-key>
   ```
6. `syswrapper.lua` stores the new authkey and sets `adopted = true` in `/etc/openuf/state.json`
7. The device appears as **Connected** in the controller

> **The controller picks the adoption path from how it discovered the device,
> not from where it is.** A device it heard via L2 broadcast gets the SSH
> treatment above even when it sits on the controller's own subnet and informs
> perfectly — confirmed against a real UniFi OS gateway, which SSHed in three
> times on the Adopt click, failed (`Login attempt for nonexistent user`), and
> parked the device at **Connection Interrupted** while the inform loop kept
> running normally. If SSH can't succeed on your device, set
> `config.l2_announce = false` in `conf.lua` and restart: with no broadcasts the
> controller treats it as L3-discovered and delivers the key over the inform
> channel instead. Forget any device record created while broadcasts were on
> first — the controller remembers how it found it.

### L3 adoption (device and controller on different subnets)

1. Manually point the device at the controller:
   ```sh
   syswrapper.sh set-inform http://<controller-ip>:8080/inform
   ```
2. The device starts sending inform packets to the controller
3. It appears as **Pending** in the controller
4. Click **Adopt**

> **No SSH is involved in L3 adoption.** For **L3-discovered** devices the
> controller explicitly logs `discovered via L3 inform, skip SSH adoption` and
> never attempts SSH at all — unlike the L2 flow documented above. It delivers
> the new `authkey` directly in the `mgmt_cfg` field of the `setparam` response
> sent right after the Adopt click — confirmed against a real controller
> (`linuxserver/unifi-network-application:10.4.57`), reproduced from a clean
> environment. openUF's `inform.lua` accepts this only while unadopted, matching
> `amd989/unifi-gateway`'s reference behavior. Adoption completes to
> **Connected** — provided the device can encrypt with AES-GCM (see § 1). An
> earlier version of this guide reported every newly-adopted device getting stuck
> at "Adopting"; that was the missing GCM backend, not a controller-side issue,
> and it is resolved — see [PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md).

---

## 5. State file

Persistent state is stored at `/etc/openuf/state.json` — or wherever
`conf.lua`'s `state_file` points, which the inform daemon, the L2 broadcaster
and `syswrapper.sh` all read, so all three agree on one file. Change it before
adoption: moving it afterwards leaves the authkey behind and the controller
stops recognising the device.

It is written through a sibling `.tmp` and renamed into place, so an
interrupted write can never leave a half-file behind. That matters because a
`state.json` that will not parse is read as "start from defaults" — the device
comes back up unadopted, with the well-known key. If that ever happens it is
announced on stderr rather than passed off as a fresh install.


```json
{
  "adopted":    false,
  "authkey":    "ba86f2bbe107c7c57eb5f2690775c712",
  "cfgversion": "",
  "inform_url": "http://unifi:8080/inform",
  "use_gcm":    false,
  "upgrade_requested_version": "",
  "upgrade_requested_url":     "",
  "blocked_stas": []
}
```

| Field | Description |
|---|---|
| `adopted` | `true` after successful adoption; `false` resets `authkey` to default on load |
| `authkey` | 32 hex chars (16-byte AES-128 key); default = pre-adoption key |
| `cfgversion` | Opaque string the controller uses to push config updates |
| `upgrade_requested_version` / `upgrade_requested_url` | Set when the controller sends an `upgrade` command; stored for visibility only — openUF never downloads or flashes firmware (see below) |
| `inform_url` | URL for the 10-second inform heartbeat |
| `use_gcm` | `true` when the controller has requested AES-128-GCM encryption (`use_aes_gcm=true` in mgmt_cfg) |
| `blocked_stas` | MACs blocked from the controller's Clients view; re-applied to nftables on startup so blocks survive restarts |
| `swvlan_backup` | Original `ports` strings of the stock `switch_vlan` sections, snapshotted before per-port VLAN assignment first modifies them; used to restore them (see § 6) |
| `ip_mode`, `static_ip`, `static_netmask`, `static_gateway`, `static_dns` | The last "IP Settings" push. `ip_mode` is `"static"` or `"dhcp"`; the `static_*` fields are set only in static mode and cleared on a revert to DHCP. `static_dns` is an array in the controller's primary/secondary order, written to `/etc/resolv.conf`. On DHCP, DNS is left to the lease and openUF does not touch `resolv.conf` |

To reset to factory defaults:
```sh
syswrapper.sh reset-inform
```

---

## 6. WiFi provisioning

When the controller pushes a config, `ucihelper.lua` applies it via OpenWrt UCI.  Only sections prefixed with `openuf_` are created or deleted.

`use_only_unifi_wlan` (default `true`) additionally sets `disabled=1` on every *other* `wifi-iface`, so the radios carry only what the controller provisioned.  openUF stamps each SSID it turns off with `openuf_autodisabled=1`; setting the option back to `false` re-enables exactly those and leaves everything else as-is, so an SSID you had disabled yourself is never switched back on.  Set it to `false` from the start to keep hand-configured SSIDs broadcasting alongside the controller's.

A `wifi-iface` whose `mode` is not `ap` — an 802.11s mesh point, or a station interface — is exempt regardless. Those are *links*, not SSIDs competing on the air, and one of them may be the AP's own uplink: switching it off would take the device off the network entirely. If an earlier openUF had already stamped one, it is switched back on.

Settings carried through from the controller:

| Controller setting | Applied as |
|---|---|
| SSID, passphrase, security | `wifi-iface` ssid/key/encryption |
| Hide WiFi Name | `hidden` (hostapd `ignore_broadcast_ssid`) |
| MAC Address Filter | `macfilter` (`disable`/`allow`/`deny`) + `maclist` |
| WiFi Speed Limit | `tc` shaping per VAP, not a hostapd option (plus `openuf_ratelimit_down`/`openuf_ratelimit_up` on the section for visibility) |
| WPA2 / WPA3 / WPA2-WPA3 mixed | `encryption=psk2`/`sae`/`sae-mixed`, from the pushed AKM set **plus** `wpa3.transition` — SAE replaces WPA-PSK on the wire, so the AKM alone cannot tell mixed from WPA3-only. Depends on openUF advertising `radio_caps2` bit `0x1` |
| WPA-Enterprise (802.1X) | **not supported** — the WLAN is skipped and logged. The wire protocol carries no RADIUS server/port/secret to write, so there is nothing openUF could provision |
| PMF (802.11w) | `ieee80211w` (0 disabled / 1 optional / 2 required) |
| Fast Roaming (802.11r) | `ieee80211r`. The controller carries **two** toggles — `ft.status` for the WLAN and `wpa3.ft.status` for the SAE akm alone (SAE pushes only). OpenWrt has one switch feeding hostapd's `key_mgmt`, and on `sae-mixed` it yields FT-PSK *and* FT-SAE together, so FT is enabled if **either** asks for it and a disagreement is logged |
| BSS Transition (802.11v) | `bss_transition` — **needs a full `wpad` build** |
| Band Steering | `usteer` config, not a hostapd option |
| Auto/Custom DTIM Period | `dtim_period` |
| Multicast Enhancement | `multicast_to_unicast` |
| Minimum Data Rate | per-**radio** `basic_rate` / `supported_rates` / `legacy_rates` / `beacon_rate` |
| Multicast and Broadcast Blocker | nftables rules, not a hostapd option (plus `openuf_bcfilt`/`openuf_bcfilt_macs` on the section for visibility) |
| Proxy ARP | `proxy_arp` — **needs a full `wpad` build** |
| Client Isolation | `isolate` (hostapd `ap_isolate`) |
| Network / VLAN assignment | a per-VLAN bridge (`br-openuf<id>`) holding the tagged uplink sub-device (`eth1.<id>`), which the VAP joins — plus a `switch_vlan` trunk on swconfig boards. See below |
| Channel, TX power | `wifi-device` channel/txpower; the controller's **Auto** channel is written as the literal `channel=auto`, engaging hostapd ACS (the AP surveys the band at radio bring-up and picks the least-busy channel). **Auto** TX power *deletes* the `txpower` option (UCI has no auto value; absent = driver default/max), so reverting from a fixed dBm actually takes effect |
| Radio enable/disable (TX Power → Disabled) | `wifi-device` `disabled`; the radio's WLANs get `wifi-iface` `disabled` too, keeping their config for a later re-enable |
| Channel width | `wifi-device` htmode, from the radio's `ieee_mode` token, **clamped to what the radio can actually do** — see below |
| IoT Optimization: Lock 2.4 GHz to Channel 6 | nothing new — arrives as `channel=6` on the 2.4 GHz radio |
| IoT Optimization: DTIM Interval Lock | nothing new — arrives as `dtim_period=3` on the 2.4 GHz SSID |
| IoT Optimization: Force WiFi 4 Mode | `bss_load_update_period=0` (suppresses the QBSS Load IE) + an `openuf_iot` marker |
| Minimum RSSI | per-**radio**; enforced by openUF deauthenticating clients below the threshold, not by hostapd |
| Per-port VLAN (Ports → *port* → Native VLAN) | swconfig `switch_vlan` sections named `openuf_swvlan<id>` — see below |

**Channel width is clamped to the hardware.** openUF presents itself as a
U6-InWall (802.11ax) whatever the host radios really are, so a controller will
happily push `ieee_mode=11nahe80` at an 802.11n/ac radio. Written to UCI
verbatim that produces a config file that looks perfectly correct and a hostapd
that refuses to start — no SSID on the air, and nothing in the config to explain
why. openUF therefore probes `iw phy` for each band's real PHY and maximum
width and clamps the request **downward only** (`HE80` → `VHT80` on an ac
radio, `HE40` → `HT40` on an n-only 2.4 GHz radio); a request the hardware can
already satisfy is never touched, and every clamp is logged:

```
openuf: radio0: controller asked for htmode HE80, hardware supports VHT80 -- clamped
```

If `iw` is unavailable or its output can't be parsed, the controller's value is
written through unchanged rather than clamped to a guess. The same probe supplies
each radio's real `max_txpower` (the ceiling the controller's TX Power slider
uses) instead of a static default.

**The PHY generation comes from the hardware, not from the wire.** What a real
controller actually sends is `radio.<n>.ieee_mode=11nght20` / `11naht40` — its
vocabulary is Atheros-era (the same push names the VAPs `ath0`/`ath1`/`ath2`),
and that `ht` is *not* a request for 802.11n. It is the only thing this key has
ever said: the **band** and the **width**. A real U6-InWall receiving `11naht40`
runs it as HE40. So openUF takes the width from the wire and the PHY from
`iw phy`, then clamps as above — a 2.4 GHz-capable ax radio given `11nght20`
gets `HE20`, an n-only one gets `HT20`. Reading the token literally pinned every
802.11ax radio to 802.11n permanently, which is invisible in the controller (it
shows the width, which was right) and visible only in `iw dev`. An explicit
`vht`/`he`/`eht` token, if one ever arrives, is honoured as written.

> **SSID punctuation is sanitized into the UCI section name.** A UCI section name may
> contain only `[A-Za-z0-9_]`, so an SSID of `Guest-WiFi` becomes the section
> `openuf_radio0_Guest_WiFi` — the SSID *itself* is stored and broadcast unchanged. This
> matters because libuci enforces the rule **silently**: `set()` returns true, `commit()`
> returns true, and a section whose name contains anything else is discarded before it
> reaches `/etc/config`. An unsanitized character therefore costs the entire WLAN with
> nothing logged anywhere. Two SSIDs differing only in punctuation (`a-b` and `a_b`) share
> one section, which has always been true of spaces.

**Fast Roaming (802.11r) and the `ft_psk_generate_local` trap.** openUF sets
`ieee80211r`, a `mobility_domain` derived from the SSID (so every AP computes the same one
with no coordination) and `ft_over_ds=0` — and deliberately does **not** set
`ft_psk_generate_local`. That option looks harmless and is not:

- It means "derive PMK-R0/R1 locally from the PSK", which only exists for **FT-PSK**. FT-SAE
  derives PMK-R0 from the per-session SAE PMK, which no passphrase can reproduce, so its
  PMK-R1 has to be pulled from the origin AP over an `r0kh`/`r1kh` key-holder relationship.
- OpenWrt only configures those key holders when `ft_psk_generate_local` is **0**, and only
  defaults it to 0 when nothing has overridden it. Setting it to 1 therefore silently
  disables fast roaming for every WPA3 client on a `sae-mixed` WLAN — which is most of them.

Left unset, `hostapd.sh` keys it on the auth type (`psk` → 1, anything else → 0) and, at 0,
derives wildcard key holders from `md5(mobility_domain/psk)`. That is deterministic, so
independent APs sharing an SSID and passphrase arrive at the same key — the same reasoning
behind the derived mobility domain. Worth knowing: that key is therefore derivable by anyone
who knows the passphrase, i.e. anyone already on the network; a real UniFi controller
distributes a random one instead.

**How to tell whether a transition was actually fast**, since nothing in the controller
shows it — force one and read the target AP's log:

```sh
hostapd_cli -i <vap> bss_tm_req <sta-mac> pref=1 \
    neighbor=<target-bssid>,0x0000,<op-class>,<channel>,7 \
    disassoc_imminent=1 disassoc_timer=30
logread | grep AP-STA-CONNECTED
```

`auth_alg=ft` **and no `EAPOL-4WAY-HS-COMPLETED`** is a real fast transition. `auth_alg=sae`
followed by a 4-way handshake is the fallback — the client roamed, it just paid full
authentication for it. `hostapd_cli -i <vap> sta <mac>` shows the negotiated
`AKMSuiteSelector`: `00-0f-ac-4` is FT-PSK, `00-0f-ac-9` FT-SAE, `00-0f-ac-8` plain SAE.

**VLAN-tagged SSIDs** (assigning a WiFi network to a non-native network) need three
things on the AP, and openUF builds all three:

1. a tagged sub-device on the uplink — `eth1.<vlan>`;
2. a **bridge** holding it, `br-openuf<vlan>`, which the VAP joins. This is the part
   that is easy to miss: point the VAP's network at the bare sub-device instead and
   netifd brings the interface up, `ip link` shows both netdevs, hostapd starts, and a
   client associates and gets *nothing* — because the VAP and the uplink are two
   separate masterless interfaces. Everything looks healthy except `ip link`'s missing
   `master`;
3. on swconfig boards, a `switch_vlan` **trunk** so the switch passes the VID at all.
   Without it an ASIC that filters unknown VIDs drops every frame (confirmed: 100%
   packet loss on an AR8327 until the entry existed). openUF tags exactly two ports —
   the CPU port and the uplink socket, the latter found at runtime by
   `sysinfo.uplink_phys_port()`. That is the whole path a tagged SSID's frames take
   (`VAP → br-openuf<id> → eth0.<id> → CPU → uplink → gateway`); no LAN socket is on it.
   If the uplink cannot be resolved openUF leaves any existing trunk alone rather than
   guessing.

   **On a DSA board step 3 does not exist and is not needed.** With bridge VLAN
   filtering off — the OpenWrt default, and the state a `config bridge-vlan`-free
   `br-lan` is in — the switch passes tagged frames straight through, and the
   sub-device on the uplink socket (`wan.<vlan>` on an AX3000T) takes its VID
   before the bridge ever sees it. Steps 1 and 2 are the whole path there.

> **Why not simply tag every socket.** openUF used to, and it broke every untagged
> wired client behind an AP running a tagged SSID. On the `ar8216`/`ar8226`/`ar8229`/
> `ar8236` driver family the tag flag is **not** per (port, VLAN): `ar8xxx_sw_set_ports()`
> folds it into one global per-port bitmask (`priv->vlan_tagged`) from which
> `__ar8216_setup_port()` picks add-tag vs strip-tag *for every VLAN at once*. Tagging a
> socket into VLAN 10 therefore made it egress-tagged in VLAN 1 too, and the printer
> plugged into it went deaf while still transmitting — UCI read `1 2 3 4 0t` while the
> switch reported `0t 1t 2t 3t 4t`. The AR8327 has a real per-(port, VLAN) tag table and
> showed none of it, which is how the bug survived. A consequence worth knowing on the
> global-bitmask chips: a port cannot be untagged in VLAN 1 *and* tagged in VLAN 10, so
> running a tagged wireless VLAN necessarily leaves the **uplink** socket egress-tagged
> for VLAN 1 as well. UniFi gateways accept that, and it is confined to the one port
> facing the gateway.

> **Keep VLAN ids below the switch's VLAN table size.** netifd has no `vid` option
> (`strings /sbin/netifd` lists only `vlan` and `ports`), so a `switch_vlan` section's
> `vlan` value is *both* the table slot and the VLAN id. Small switches have small
> tables — the TL-WDR3500's AR8229 reports `vlans: 16` in `swconfig dev switch0 help` —
> and a section naming a slot the hardware lacks is skipped by netifd **silently**.
> openUF reads that size and logs the mismatch instead of writing config that will be
> ignored. Whether it actually breaks traffic depends on the ASIC: the AR8327 filters
> unknown VIDs and needs the entry, the AR8229 forwards them and the SSID works without
> one. Choosing a VLAN id under 16 keeps both boards properly configured.

Changing a network's VLAN id, or deleting the WLAN, tears the old bridge and interface
down again — only `openuf_`-prefixed sections are ever removed.

**Per-port VLAN assignment** must be switched on twice: once on the device
(Devices → *AP* → Settings → IP Settings → **Port VLAN**, which is what flips the wire's
`switch.status`/`switch.vlan.status` gates), then per port under **Ports**. Until the
device-level box is ticked the per-port VLAN controls stay greyed out and nothing reaches
the wire.

openUF applies it only on **swconfig** boards (ath79-era). It writes one
`config switch_vlan` section per VLAN, named `openuf_swvlan<id>`, translating the
controller's `untagged`/`tagged`/`exclude` per-port modes into swconfig's port syntax
(`1`, `1t`, omitted) with the CPU port always tagged in.

**On a DSA board it works differently, and deliberately not via `config bridge-vlan`.**
The socket assigned to VLAN 10 is moved out of `br-lan` and into `br-openuf10` — the
bridge that already holds the tagged uplink sub-device `wan.10`, and the IoT VAP if a
tagged SSID sits on the same VLAN:

```
device on lan3 --untagged--> lan3 -> br-openuf10 -> wan.10 --tagged--> uplink -> gateway
```

That a wired port and a wireless client on VLAN 10 land in the *same* bridge is the point,
not a coincidence: they are one broadcast domain and the controller models them as one
network. `br-lan` keeps the uplink socket, the unassigned sockets and the AP's management
address, untouched.

The `bridge-vlan` + `vlan_filtering` route was rejected for two reasons, both worth knowing
if you are tempted to add it:

1. `br-lan` carries the AP's own management address. Turning `vlan_filtering` on there means
   every VLAN — the management one included — must be declared exactly right, or the device
   is stranded at the far end of a cable. Nothing openUF does should be able to do that.
2. It would silently fight the tagged-SSID path. `wan.10` is an 8021q device on the `wan`
   **bridge port**, and `vlan_do_receive()` runs ahead of the bridge's `rx_handler`, so
   VLAN 10 frames are taken by `wan.10` before `br-lan` ever sees them. A `bridge-vlan`
   declaring VLAN 10 on `br-lan` would receive nothing while looking perfectly correct.

Scope on DSA: **Native VLAN only.** A bridge gives a port exactly one untagged home, which
is what a Native VLAN is and what an AP's downstream socket needs. A port given nothing but
*tagged* VLANs is refused with a log line rather than half-applied. (The controller's default
"Tagged VLAN Management: Allow All" marks every non-native VLAN tagged — that is a default,
not a request, and is not warned about.)

Reversibility on DSA is `st.dsa_brlan_ports`: `br-lan`'s port list exactly as the board
shipped it, snapshotted once before the first socket moves. Unticking **Port VLAN** puts it
back verbatim and returns the sockets from the VLAN bridges.

> Unticking the box is what triggers that teardown, and it needs a config push to act on —
> the controller sends one when you hit **Apply Changes**, not merely when the device
> reconnects. Note the off signal is an *absence*: a device that has had Port VLAN on and
> then has it unticked receives a `system_cfg` with no `switch.*` keys at all rather than
> the gates set to `disabled`. openUF treats that as off only while it holds a ledger, so
> there is something to undo.

> **Reassigning a port does not re-address the device plugged into it.** Moving a socket
> between bridges is invisible to the attached host: its link never drops, so it keeps the
> lease it already had — now on the wrong subnet — and simply goes quiet. Bounce the port
> (`ip link set lan2 down; ip link set lan2 up`) to make it re-DHCP, and be aware that some
> devices still will not: an IKEA Trådfri hub, moved to an IoT VLAN this way, re-sent a
> DHCP DISCOVER roughly once a minute for fifteen minutes without ever taking the offer,
> and needed the port put back. Verify the move by watching the counters rather than by
> waiting for the client to reappear — `cat /proc/net/dev` should show the socket's rx
> bytes and the tagged uplink's tx bytes climb by *the same amount*, which is the whole
> path proving itself. Power-cycle the attached device if it does not settle.

Three things must line up or the port is skipped rather than guessed at:

- `dev.conf.vlan` must exist in your modelmap (`cpu_lan` + a `ports` name→number map).
  Without it openUF has no idea what the physical switch ports are, and guessing strands
  the device.
- the port needs a `swport` in `dev.conf.net.ports`, naming its `dev.conf.vlan.ports` key.
- the port must not be the uplink — reassigning the uplink's VLAN would cut the device off
  the network, so that is refused outright. On a modelmap that declares sockets rather
  than netdevs, the uplink is whichever socket the default gateway is reached through
  (found in the switch's ARL table); if that cannot be determined, **every** port is
  refused rather than risking the wrong one.

Because assigning a port to a VLAN means removing it from the stock VLAN's port list
(swconfig allows one *untagged* VLAN per port), this is the one place openUF modifies UCI
sections it did not create: a port moved untagged onto an openUF VLAN loses its untagged
membership in every other `switch_vlan` section, and an explicit *exclude* drops the
port's membership from that VLAN. Two safety refusals apply — an exclude that would leave
the port untagged **nowhere** is ignored, and the management VLAN is never stripped of
its last downstream port. openUF snapshots the original `ports` strings into `state.json`
(`swvlan_backup`) before the first change, and `switchvlan.restore()` puts them back. Unticking the device-level **Port VLAN** box runs
that restore automatically (the wire keeps the `switch.*` block with both gates at
`disabled`, which openUF treats as the explicit off signal); a push that carries no
`switch.*` block at all leaves the switch untouched. Inspect the result with
`uci show network` and `swconfig dev switch0 show`.

> The generated UCI is unit-tested, but **openUF has no switch hardware to verify against** —
> that these sections actually program the switch ASIC, and that
> `/etc/init.d/network reload` behaves on real ath79, are unconfirmed.

**Band Steering** is `usteer`'s decision, not openUF's: openUF configures the daemon
(`usteer.local.band_steering_threshold`) and forces 802.11k neighbour reports plus
`bss_transition=1` onto every VAP, since usteer cannot work without them. If a client is
not being steered, check `ubus call usteer get_clients` for a 5 GHz sighting of it and
`ubus call hostapd.<iface> get_clients` for its `rrm` bits and the BSS-Transition bit in
`extended_capabilities` — a client with neither cannot be steered by any AP, and usteer's
per-BSS `roam_events` counters do not increment for BTM-driven band steers, so they are
not a useful health check. A successful steer looks like
`BSS-TM-RESP <sta> status_code=0 target_bssid=<the 5 GHz BSSID>` in `logread`.

The **Environment** tab (Insights → AirView) is fed from `iw dev <ifname> scan dump`, the
kernel's passive BSS cache. That cache is filled from beacons the radio overhears **on the
channel it is already serving**, so on its own the tab lists near-channel neighbours and
nothing else — openUF never dwells off-channel behind your clients' backs. Measured on an
AX3000T: 6 neighbours on a 2.4 GHz radio on ch 11, and exactly 1 on a 5 GHz radio on ch 44.
On the Archer C5's 5 GHz radio the passive cache held **nothing at all**.

openUF closes that gap the way Ubiquiti's Channel AI describes — *"neighbor reports and
automated RRM scans"* — rather than by scanning. Every `rrm_request_interval` seconds
(default 600) it asks **one** 802.11k-capable client for an active beacon measurement: the
*client* leaves the channel, sweeps, and reports what it saw, while the AP keeps serving.
One answer returned 15 BSSes across both bands at once, and a client sitting on 5 GHz
routinely reports 2.4 GHz too — so a single report enriches both radios. It took that
empty 5 GHz list from 0 neighbours to 4, one of them an AP the radio cannot hear at all.

| Setting | Meaning |
|---|---|
| `rrm_enrichment` | `true` by default. Set `false` to never send a beacon request |
| `rrm_request_interval` | Seconds between requests, across all radios and clients combined — they are asked one at a time, round-robin |

Only clients advertising **active or passive** beacon measurement are ever asked. Clients
advertising *beacon-table* only are skipped on purpose: the one real example acknowledged
every request at the MAC layer and never sent a report, and hostapd refuses a passive
request for such a client outright. In practice this is a minority of clients — of 13
surveyed across two APs, 9 had no 802.11k at all — so this supplements the passive cache
and never replaces it.

The request names the operating class the *client* can measure: 81 (2.4 GHz) for a station
on a 2.4 GHz BSS, 115 (5 GHz U-NII-1) for one on 5 GHz. A dual-band client answers 115 for
both bands, which is where the cross-band bonus above comes from — but a 2.4 GHz-only
client answers it with report mode `0x02`, *incapable*, and nothing else.

Capability bits are not a promise, either: a client can advertise every measurement mode
and still refuse them all. hostapd only notifies openUF when a report body arrives, so
such a station is indistinguishable from one that never answers — after two unanswered
requests it is left alone for six hours, then tried once more. Any report at all puts it
straight back into the rotation.

Rows sourced this way show a **blank WiFi Name and Security** (the controller renders the
BSSID instead of a name). That is deliberate: a beacon report carries a BSSID, a channel
and an RCPI, and nothing else. openUF will not invent a security mode it did not measure —
an earlier draft defaulted it to `open` and told the operator that four WPA2 neighbours
were unencrypted.

To see the machinery: `pgrep -f 'ubus subscribe hostapd'` is the collector that receives
the reports (hostapd delivers them as ubus *notifications*, so `ubus listen` shows nothing
— only `ubus subscribe` works), `logread | grep BEACON-REQ-TX-STATUS` shows requests going
out, and `/tmp/openuf-rrm.jsonl` is the spool, drained on every inform.

Use the controller's RF scan (`spectrum-scan`) when you want a real full sweep.

The **Multicast and Broadcast Blocker** has no hostapd or OpenWrt equivalent — hostapd
can suppress group-addressed frames wholesale but has no notion of an allow-list — so
openUF enforces it with nftables, in its own `bridge openuf_bcfilt` table (separate
from the client-blocking `bridge openuf` table, which is rebuilt wholesale on every
block/unblock and would otherwise wipe these rules). Frames leaving a filtered SSID are
dropped unless the *sender's* MAC is allow-listed.

This needs **`kmod-nft-bridge`**, and it is the only feature that does. The drop rule is
openUF's one bridge-family `meta` match, and `nft_meta_bridge` is a separate module that
`nftables` does not depend on — absent from a stock filogic *and* ath79 image alike. The
failure is quiet in the worst way: the table, the chain and the per-VAP allow-list set
are all created and populated, and only the drop rule is rejected, so the control reads
as enabled in the controller and `nft list table bridge openuf_bcfilt` shows a table that
filters nothing. openUF now logs `nft rejected the drop rule for <ifname> -- install
kmod-nft-bridge` when this happens.

> **This deliberately breaks DHCP for wireless clients unless you add the DHCP server's
> MAC to the excepted-devices list.** That is Ubiquiti's own documented behavior for
> this control, so openUF reproduces it faithfully rather than adding DHCP/ARP
> exemptions of its own — a silent exemption would be harder to debug than the
> documented breakage. Inspect the live rules with `nft list table bridge openuf_bcfilt`.

**Minimum Data Rate** is set per WLAN in the controller but OpenWrt's rate options
(`basic_rate`, `supported_rates`, `legacy_rates`, `beacon_rate`) are `wifi-device`
options, so two WLANs sharing a radio cannot each get their own floor. openUF applies
the most permissive of them — the lowest floor, CCK still allowed if any WLAN allows
it — because the stricter choice would silently lock clients out of a co-hosted WLAN
that was meant to admit them. Give a WLAN its own radio if it needs its floor enforced
exactly. Note also that the floor is enforced by making it the sole *basic* rate (a
station must support every basic rate to associate); the "advertising rates" sub-toggle
additionally trims `supported_rates`. Rate options openUF writes are stamped with an
`openuf_rates` marker on the radio section: turning the control off (the wire simply
omits every `minrate_*` key) tears down exactly the marked options, while rate options
you hand-tuned on an unmarked radio are never touched.

Minimum RSSI is a *radio* setting in the controller UI (Devices → AP → Radios), not a per-WLAN one, and the wire value is an offset from an assumed noise floor rather than a dBm figure — openUF converts it using a live noise reading. The controller signals *disable* by omitting the whole `stamgr.<n>` block from the next config push; openUF treats that as an explicit off and clears `minrssi_enabled` in UCI (the stored threshold stays parked for a later re-enable).

The reported **country code** comes from the wifi-device's UCI `country` option (the
regulatory domain OpenWrt programs), mapped best-effort from ISO alpha-2 to the numeric
code the controller expects; an absent or unrecognized regdomain falls back to 840 (US),
the value that used to be hardcoded for every deployment.

The **IoT Optimization** panel (Settings → WiFi → *WLAN* → IoT Optimization) is mostly controller-side sugar: two of its three toggles just set values the protocol already had — channel 6 on the 2.4 GHz radio, and DTIM 3 — so they need no dedicated support. "Force WiFi 4 Mode" additionally drops the WLAN's 5 GHz vap, pins WPA2, and turns off PMF, BSS Transition, proxy ARP, fast roaming and band steering; those all arrive as their ordinary keys. Note that it does *not* narrow the radio: the shared 2.4 GHz radio keeps whatever channel width it is configured for, so `htmode` is untouched.

To verify provisioned SSIDs:
```sh
uci show wireless | grep openuf_
```

To remove all provisioned SSIDs:
```sh
lua -e "dofile('/opt/openuf/ucihelper.lua').wlan_clear()"
# or simply reset-inform and re-adopt
```

---

## 7. LLDP topology

`lldpd` must be running for topology announcements to work.  openUF queries `lldpctl -f json` and includes the neighbor table in each inform payload so the controller can render the upstream switch on its topology map.

Check LLDP status:
```sh
lldpctl          # show neighbors
lldpctl -f json  # JSON output (what openUF reads)
```

If `lldpd` is absent or returns no neighbors, `lldp.lua` returns an empty table — non-fatal.

### Point lldpd's chassis ID at the same interface as `lan_cpueth`

```sh
uci set lldpd.config.cid_interface='lan'
uci commit lldpd && /etc/init.d/lldpd restart
```

**Without this the controller cannot place the AP on its topology map**, and shows
some unrelated device (here the ISP's uplink) as the AP's Parent Device.

The reason is that two different MACs are involved. openUF identifies the device
by the MAC of `dev.conf.net.lan_cpueth`, and that is the MAC the controller
adopts it under. `lldpd`, left to itself, picks its chassis ID from whichever
interface it likes — in practice the lowest-numbered one, i.e. `eth0`. The
upstream gateway therefore learns the AP as a neighbour under a chassis ID that
does not match any adopted device, and silently declines to join the two.

Whether that bites is pure luck of the board's port naming:

| Board | `eth0` | `lan_cpueth` | Default chassis ID | Topology |
|---|---|---|---|---|
| TL-WDR3500 v1 | LAN trunk | `eth0` | matches identity | resolves by accident |
| Archer C5 v1 | unused WAN socket | `eth1` | **`eth0`, wrong** | Parent Device wrong |
| Mi Router AX3000T | DSA conduit | `wan` | **`eth0`, wrong** | Parent Device wrong |

Setting `cid_interface` to the LAN network makes the chassis ID the same MAC
openUF reports, and the controller resolves the uplink immediately — confirmed
live: an Archer C5 went from no `uplink_mac` at all to
`Cloud Gateway Ultra, port 4` on the next LLDP advertisement.

On a **DSA** board name the socket, not the network: `br-lan` covers every
socket and carries `eth0`'s MAC, so `cid_interface='lan'` reproduces the very
mismatch it is meant to fix. Use the one `lan_cpueth` names —

```sh
uci set lldpd.config.cid_interface='wan'   # the AX3000T's uplink socket
uci commit lldpd && /etc/init.d/lldpd restart
```

Verify the two agree:
```sh
lldpcli show chassis | grep ChassisID          # lldpd's identity
grep -o '"mac":"[^"]*"' /etc/openuf/state.json # openUF's identity
```

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Device doesn't appear in UniFi Discover | `announce.lua` not running, or UDP port 10001 blocked |
| Controller shows device as "Disconnected" | `inform.lua` not running, or wrong `inform_url` |
| Adoption fails with SSH error | SSH not reachable from controller, or root password not set — run `passwd root` on the device, or reinstall with `--bootstrap-adopt` |
| Device stays stuck at "Adopting" forever | No AES-GCM backend — `lua-openssl` missing or built without AEAD support. The CLI `openssl-util` fallback is CBC-only and will not work (see § 1) |
| Controller rejects device ("firmware incompatible") | Adjust `fw.ver` in `ufmodel/u6iw.lua` |
| hostapd fails: "unknown configuration item 'bss_transition'" | A `wpad-basic-*` build is installed — replace it with `apk add wpad-wolfssl` |
| Band Steering has no effect | `usteer` not installed or not running — `/etc/init.d/usteer status` |
| Locate/LED does nothing | `dev.conf.led` is `nil` in your modelmap — set it to a path from `ls /sys/class/leds` |
| JSON decode error in controller logs | AES key mismatch — try `syswrapper.sh reset-inform` |
| SSID not appearing after adoption | Check `uci show wireless`, check `loglevel` in `/var/log/openuf.log` |
| `lldp_table` empty | `lldpd` not running — run `/etc/init.d/lldpd start` |
| Wired clients reach LAN peers but not the gateway or internet, while WiFi clients on the same AP are fine (DSA boards) | The VLAN-SSID bridge shares the physical uplink with `br-lan`, so the switch's single hardware FDB learns the router's MAC against the tagged port. openUF sets `learning '0'` on that port to prevent it — check `bridge fdb show` for the router's MAC carrying `offload` on `<uplink>.<vid>` instead of the bare uplink, and confirm `network.openuf_brport<vid>` exists |
| Bootstrap account (`ubnt`) doesn't lock after adoption, or doesn't re-enable after a factory reset | `inform.lua` must be running for this — it's what detects the state change and runs `passwd -l`/`-u` (see § SSH prerequisite). Check `/var/log/openuf.log`. |

Log file: `/var/log/openuf.log`

For development testing without hardware, see `tools/test_controller.py`.
