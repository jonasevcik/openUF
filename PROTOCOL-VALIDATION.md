# Protocol validation findings

openUF's assumptions about the UniFi inform protocol were originally inferred from
third-party reference material — [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway)
and [paultyng/go-unifi](https://github.com/paultyng/go-unifi) — never checked against a
real UniFi Network Application. This document is the project's own ground truth,
established by running openUF against a real self-hosted controller, capturing decrypted
inform responses (`debug_dump_file`, see [USAGE.md](USAGE.md#3-configuration)), and
decompiling the controller's own Java bytecode and React bundles.

**Where this document and the third-party references disagree, this document wins.**
In particular, go-unifi models the controller's *admin REST API*, which is a different
surface from the inform wire protocol — several fields that exist there
(`bandsteering_mode`, `dtim_mode`, `roamingAssistant*`) have no counterpart on the wire.

This is a **reference for the confirmed current state**, not a lab journal. Superseded
hypotheses and the investigation trails that produced these facts have been removed;
git history has them if needed. Decompiled evidence is retained inline wherever a claim
would otherwise be hard to re-verify.

**Environments:**

- `lscr.io/linuxserver/unifi-network-application:10.4.57` (Docker, pinned), with openUF as
  the AP in a disposable Alpine container on the same Docker network (`tools/validation/`).
  Mocked `uci`/`ubus`, no radios.
- **Real hardware, 2026-07-28:** a TP-Link Archer C5 v1 (OpenWrt 25.12.5, ath79/mips_24kc,
  ath9k 2.4GHz + ath10k 5GHz) adopted by a **UniFi Cloud Gateway Ultra running Network
  10.4.57** — the same version as the Docker baseline, so the two are directly comparable.
  See [the first real-hardware run](#the-first-real-hardware-run) and
  [the first DSA / 802.11ax board](#the-first-dsa--80211ax-board) for what only appears
  once genuine `netifd`/`hostapd`/radios are in the loop.

**Status:** adoption, provisioning, and every UI-surfaced feature listed in the
[feature matrix](#feature-matrix) are confirmed working end-to-end against a real
controller, except where a row says otherwise. Adoption, the WiFi config push, live
clients and the radios themselves are additionally confirmed on real hardware.

---

## Validation environment

Everything in this section is about `tools/validation/`, not about openUF's product code.
Real OpenWrt target hardware has genuine `uci`/`iw`/`ubus`/`hostapd` and hits none of it.

### Required setup, in order

1. **`lua-openssl` must be present in the AP container.** Without an AES-GCM backend the
   controller will never provision the device — see
   [the GCM provisioning gate](#the-gcm-provisioning-gate). `tools/validation/ap/Dockerfile`
   builds the `zhaozg/lua-openssl` rock (`luarocks-5.1 install openssl`); no prebuilt Alpine
   apk exists. `install.sh` already installs `lua-openssl` on real OpenWrt hardware.
2. **Set the Inform Host Override before adopting anything.** Devices → Device Updates and
   Settings → Device SSH Settings. It must be the controller container's **literal IP** —
   the controller rejects a bare hostname with `ERROR inform - dev[<mac>] invalid inform_ip
   <hostname>`. This setting lives in the controller's own DB and is wiped by every
   `docker compose down -v`.
3. **Set a Device SSH Authentication password** (≥12 characters, enforced by the controller's
   own validator). Needed for L2/SSH adoption.

Skipping (2) presents as adoption silently stalling: `state.json` never flips
`adopted: true`, and `server.log` logs `inform decryption failed with defaultAuthKey=false`
— the controller *did* issue a per-device key, but the device never received a usable
config push. That is a setup omission, not a new bug.

### Always reset fully; never patch live state

Validation runs start from `docker compose down -v && docker compose up -d --build`.
Hand-editing a running container's `state.json`, or a device doc in Mongo, produces
results that do not reproduce — see [the minidev cache](#the-minidev-cache-never-sees-external-writes).

### The mocks, and their one sharp edge

The Alpine container has no `uci`, `ubus`, `iw`, `bridge`, or `hostapd`. Four
validation-only shims stand in, all outside `openuf/`:

| Shim | Stands in for | Notes |
|---|---|---|
| `ap/uci-mock.lua` | `require("uci")` | Installed at `/usr/local/share/lua/5.1/uci.lua`. Seeded with `radio0`/`radio1` `wifi-device` sections matching `generic-dualband-ap.lua`'s `hwassign`. |
| `ap/ubus-mock.sh` | `ubus call network.wireless status` | Static `radio0`→`wlan0`, `radio1`→`wlan1` map. |
| `ap/iw-mock.sh` | `iw dev … survey/station/scan dump` | Three fake stations with independently growing counters, plus fake neighbour BSSes. |
| `ap/bridge-mock.sh` | `bridge fdb show` | Two fake wired hosts; `entrypoint.sh` seeds `/proc/net/arp` via `ip neigh replace` (kernel state can't be baked into an image layer). |

**`uci-mock.lua` is in-memory only, per process.** Its `db` table is seeded fresh at
process start and only ever one-way dumped to a debug JSON file on `commit()` — never read
back. Consequences:

- Restarting `inform.lua` to pick up code changes **wipes any WiFi network config that was
  only ever pushed to the previous process's memory.** Recreate the WLAN in the controller
  UI afterwards to force a fresh `system_cfg` push.
- A throwaway `lua5.1 script.lua` invocation gets its own pristine mock state and proves
  nothing about the running daemon. **The only reliable way to check live wire data is to
  read what the controller actually received** (Mongo, or the REST API), never a fresh
  local script.

### Other environment facts

- **`cap_add: [NET_ADMIN]`** is required on the `ap` service — `netconfig.lua`'s `ip addr
  add`/`ip route replace` and `firewall.lua`'s `nft` both fail with `Operation not
  permitted` without it. Docker drops the capability by default even for root.
- **A `docker stop`/`start` of an AP container yields a fresh MAC from Docker**, so a
  restarted container is a brand-new device to the controller. Convenient for producing
  fresh adoption targets; means a stopped device's controller entry can never be resumed.
- **`ap2` compose service** (`replacement` profile) provides a second same-model device for
  the replace/clone flows; recipes in `tools/validation/README.md` §6.
- A `reboot` handled inside the container genuinely exits the container (no init to survive
  it). `docker start` the stopped — not removed — container to recover logs.
- Background `127.0.0.1:9080/api/ucore/manifest` and `get-ulp-manifest` connection-refused
  errors appear in `server.log` regardless of device activity. Pre-existing and harmless.

---

## The first real-hardware run

2026-07-28, Archer C5 v1 + UniFi Cloud Gateway Ultra (Network 10.4.57). Everything below
is what the Docker environment structurally *cannot* show: it mocks `uci`/`ubus` and has no
radios, so a config that `apply_config` writes "successfully" is never handed to `netifd`,
`hostapd`, or a regulatory domain. Three of the four findings are of the same shape — UCI
that reads perfectly and not one SSID on the air.

### The discovery path decides the adoption method, not the subnet

A controller that has heard a device's L2 broadcasts adopts it **by SSH**, even when it sits
on the controller's own subnet and its informs are landing perfectly. On the Adopt click the
gateway opened three SSH connections to the AP within 20 seconds:

```
dropbear[3746]: Child connection from 192.168.200.1:33114
dropbear[3746]: Login attempt for nonexistent user from 192.168.200.1:33114
```

and, failing them, parked the device at **Connection Interrupted** while the inform loop kept
running normally. The device record remembers this: removing it, stopping the broadcaster
(`config.l2_announce = false`), and letting the device re-appear from L3 informs alone made
the very next Adopt click complete over the inform channel with no SSH attempted at all.

So a device that cannot accept the controller's SSH login (no password auth, no bootstrap
account) **must** have `l2_announce` off, regardless of topology. "L3 adoption" names how the
controller discovered the device, not where it is.

### `macfilter="disable"` takes both radios off the air

OpenWrt's own schema (`/usr/share/schema/wireless.wifi-iface.json`) declares the option as
`enum: ["allow","deny"]`. 25.12's ucode validator does not ignore an out-of-enum value — it
aborts the radio setup:

```
wifi-scripts: macfilter: disable has to be one of [ "allow", "deny" ]
netifd: radio0 (4179): Died   (validate.uc:47 → die())
```

openUF wrote `macfilter="disable"` whenever the MAC filter was off, i.e. by default, so
**every** config push killed both radios. "Off" is the absence of the option: `ap.uc`'s
`iface_macfilter()` emits `accept_mac_file`/`deny_mac_file` for the two enum values and
returns for anything else. Fixed by deleting the option instead.

### `beacon_rate` is fatal on a driver that cannot program it

hostapd does not treat an unsupported beacon rate as a hint:

```
nl80211: Driver does not support setting Beacon frame rate (legacy)
Failed to set beacon parameters
Interface initialization failed
```

The 2.4GHz ath9k radio never came up, while the ath10k 5GHz radio — which the controller sent
no `beacon_rate` for — was fine. The capability is `NL80211_EXT_FEATURE_BEACON_RATE_LEGACY`,
reported **per phy** in `iw phy`'s "Supported extended features" list; neither phy on this
board has it. openUF now gates the option on that flag and still applies the rate floor
itself (`basic_rate`/`supported_rates`), which needs no driver support.

### The regulatory domain arrives as a numeric code, and nothing was applying it

`get_radio_table` has always *read* UCI `country` to derive the payload's `country_code`, but
nothing ever wrote it — so the radios kept whatever regdomain OpenWrt booted with while
reporting `840`/US back (the fallback when the option is unset). On the wire it is an
**ISO 3166-1 numeric** code, sent both unindexed and per radio:

```
radio.countrycode=203
radio.1.countrycode=203      # radio.1.phyname=radio0
radio.2.countrycode=203      # radio.2.phyname=radio1
```

UCI wants alpha-2, so 203 → `CZ`. Applying it moved the device from `country US: DFS-FCC` to
`country CZ: DFS-ETSI` and the 2.4GHz radio to channel 13 — legal in CZ, not in the US.

Worth knowing for anyone reading channel numbers off a live AP afterwards: with
`channel=auto` (which is what the controller sends unless a channel is pinned) hostapd ACS
picks freely within the new domain, and its choice can be a poor one in practice — it landed
on 5GHz channel 165, which CZ caps at **13 dBm**, and on 2.4GHz channel 13, which plenty of
client devices refuse outright. The controller's site-level Channel Plan exclusions are not
on the wire; pinning the channel per radio in the device's Radios settings is the remedy, and
that push (Auto → 6 / 36) was confirmed reaching UCI and the live radios within one inform
cycle.

### What the real controller sends that the Docker one did not

`radio.<n>.ieee_mode` came through as **`11naht40`** (5GHz) and **`11nght20`** (2.4GHz) — HT,
not HE, even though the device presents as an 802.11ax U6-InWall. openUF's downward clamp of
the PHY generation was therefore never triggered on this site; it remains insurance for a
site configured with wider/newer channel widths, not a confirmed-exercised path.

WPA2/WPA3 transition with PMF Optional arrives as `aaa.<n>.wpa=2` +
`wpa.key.1.mgmt=WPA-PSK` + `pmf.status=enabled` + `pmf.mode=1` — no SAE key-mgmt on the wire
at all, confirming the earlier Docker-era note that this controller signals WPA3-mixed purely
through PMF for a madwifi-driver model.

---

## The ports an AP reported were the CPU's, not the board's — FIXED

2026-08-02, two APs on the real UCG Ultra: a TL-WDR3500 (`Bedroom AP`) and an Archer C5 v1
(`Living room AP`). The Ports view showed **one port per AP**, and the number on it was
wrong. The investigation started from the user's own reading of the UI — only the uplink is
listed, and what is listed looks like it came from the gateway.

What the controller held for each AP (`/proxy/network/api/s/default/stat/device`):

```
port_table: [{port_idx:1, is_uplink:true, speed:1000, full_duplex:true, name:"PoE Out + Data"}]
ethernet_table: []      lldp_table: []
uplink: {..., uplink_remote_port:4, uplink_source:"lldp_downlink"}
```

Three separate things were wrong, all of them on the openUF side:

- **The speed was the CPU port's.** Both modelmaps declared a single port naming the CPU
  netdev, whose link is the internal SoC↔switch one — always `1000/full`. The Bedroom AP's
  actual uplink socket had negotiated 100baseT: `swconfig dev switch0 port 4 get link` said
  `speed:100baseT`, and the gateway's own row for the same cable said **FE** while the AP's
  row said **GbE**. A metric that contradicts the device on the other end of the wire.
- **The other sockets did not exist.** Both boards had live links on sockets the controller
  never heard of (the Archer C5 had three sockets up, of which one was reported).
- **Wired clients were attributed to the gateway.** Two hosts plugged into the APs' own LAN
  sockets showed up as `last_uplink_name: "Cloud Gateway Ultra"`, `sw_port` 2 and 4,
  `sw_depth: 1` — the gateway learned them through its downlink and, since the AP they sit
  behind reported no downstream port at all, the gateway's account was the only one.

The old code's premise was that MAC↔socket mapping "is knowable only from the switch's own
ARL table, which openUF does not read". The fix is that it now does. One
`swconfig dev switch0 show` returns per-port `link`/`pvid`, the ARL table, and (driver
permitting) per-port MIB counters — see the [`port_table[]` entry](#port_table-entry)
reference for what each field is sourced from now.

**Which socket is the uplink is measured, not declared.** The default route's gateway IP →
its MAC in `/proc/net/arp` → that MAC's port in the ARL. On these two boards the same
gateway MAC was learned on physical port 4 and physical port 2 respectively, matching the
cabling — a modelmap constant would have been wrong on one of them, and would go wrong on
either the next time a cable moves. It is also the guard on per-port VLAN: that socket is
refused an assignment, and a board that cannot determine it refuses every port.

**A side effect worth recording:** per-port VLAN assignment was unreachable on both real
boards before this. The only reported port was the uplink, and uplink ports deliberately
carry no `swport` — so the Port Manager had exactly one port and it was the one port that
must never be reassigned.

Two things looked broken and are not openUF's doing: `lldp_table` is empty because `lldpd`
on the APs receives nothing (the UCG Ultra does not transmit LLDP to them, though it happily
parses theirs), and `ethernet_table` is not sent at all — no evidence yet on what the
controller does with it, so it stays unsent rather than guessed at.

### The Ports view's other columns

Empty is the right answer for most of them, and the real gateway is the control group:

| Column | Source | On this site |
|---|---|---|
| **Anomaly** | Controller-side, from its own stats history ("24h AI Anomaly Score") | `0` on every AP port; `20` on the UCG's port facing the 100baseT-linked AP — the same conclusion it records on the device as `detailed_states.negotiated_low_uplink_port_speed: true`, which only appeared once openUF stopped claiming 1000 |
| **STP** | `stp_state`/`stp_pathcost`, a USW port property | `-` for every port, the gateway's own included |
| **Profile** | Port profile (`portconf_id` in `port_overrides`), controller-side config | `-` for every port, the gateway's own included |
| **Operation** | `op_mode` (`switch`/`mirror`/`aggregate`) | The controller writes `op_mode: "switch"` and `forward: "all"` onto openUF's ports **although openUF sends neither** — server-side defaults. `switch` is the truthful value for these sockets anyway |
| **Tx/Rx Sum, Tx/Rx Rate** | `rx_bytes`/`tx_bytes` | Populated from the per-port MIB — see below |
| **Tx/Rx Multicast, Broadcast, Dropped, Packets** | `rx_multicast`, `tx_broadcast`, `rx_dropped`, … | Sent by the gateway, not by openUF: swconfig's per-port MIB exposes `RxGoodByte`/`TxByte` and nothing else, and the CPU netdev's totals belong to every socket at once |

**Per-port counters are a driver setting, not a capability.** The ar8xxx driver only maintains
the MIB while `ar8xxx_mib_poll_interval` is non-zero, and boards differ: the AR9344 shipped at
`500` and reported counters, the AR8327 shipped at `0` and answered "Operation not supported"
for every port, so one AP's Ports view was populated and the other's read 0 B everywhere. One
`swconfig dev switch0 set ar8xxx_mib_poll_interval 500` produced counters on the next read, so
openUF now does that once at startup when the attribute exists and reads 0
(`switchvlan.enable_mib_polling`, opt out with `dev.conf.vlan.mib_poll_ms = false`).

---

## A tagged SSID's trunk deafened every wired client on the AP — FIXED

2026-08-02, same two APs. The user reported a printer at a static `192.168.200.11`, cabled
into the Bedroom AP, that nothing could reach and that never appeared in the controller UI.
It was an openUF bug, and the printer was only the visible half of it — a second host on
another socket had been dead the same way, unnoticed.

The printer was alive and talking: the AP's switch had learned its MAC in the ARL on
physical port 2, and that was the MAC the laptop's ARP cache held for `.11`. Frames got
*from* it and never *to* it.

**UCI and the switch disagreed**, which is the tell:

| | UCI `switch_vlan` for VLAN 1 | live `swconfig dev switch0 show` |
|---|---|---|
| WDR3500 — **AR8229**, `vlans: 16` | `1 2 3 4 0t` (sockets untagged) | `0t 1t 2t 3t 4t` — **all tagged** |
| Archer C5 — **AR8327**, `vlans: 4096` | `0 1 2 3 4 5` | `0 1t 2 3 4 5` — as written |

Both APs carried an identical `openuf_swvlan10` trunk of `0t 1t 2t 3t 4t`, written by
`switchvlan.trunk_ports()` for the tagged IoT SSID. Only the AR8229 let it bleed into
VLAN 1.

**On the `ar8216`/`ar8226`/`ar8229`/`ar8236` driver family, tagging is not a property of
(port, VLAN) — it is one global per-port bitmask.** `ar8xxx_sw_set_ports()` does

```c
if (p->flags & (1 << SWITCH_PORT_FLAG_TAGGED))
        priv->vlan_tagged |= (1 << p->id);
```

and `__ar8216_setup_port()` reads that single bitmask to choose `AR8216_OUT_ADD_VLAN` vs
`AR8216_OUT_STRIP_VLAN`, for every VLAN at once. So marking socket 2 tagged for VLAN 10
made it egress-tagged in VLAN 1 too, and the untagged printer dropped every frame. The
AR8327 escapes this because `ar8327.c` overrides the get/set-ports ops with a real
per-(port, VLAN) tag table — which is exactly why the bug shipped: **it is invisible on
the board the feature was developed against.**

The fix trunks only the CPU port and the uplink socket, which is the entire path a tagged
SSID's frames take. The old code's stated reason for tagging everything — that the uplink
socket is not knowable from config — had gone stale: `sysinfo.uplink_phys_port()` measures
it from the switch's own ARL, and `switchvlan.apply()` already had the answer in hand.
When it cannot be resolved openUF now holds any existing trunk rather than guessing;
letting a transient nil fall through to the reconcile pass would delete a working trunk
and reload, then rewrite it on the next inform, bouncing the IoT WLAN in a loop.

Verified live on both boards. WDR3500: VLAN 1 back to `0t 1 2 3 4t`, printer and the
second host answering ICMP from the AP and from a laptop two hops away. Archer C5: VLAN 1
untouched, VLAN 10 down from `0t 2t 3t 4t 5t` to `0t 2t`. On both, a one-shot
`udhcpc -i br-openuf10` still took a lease from the VLAN 20 gateway, so the feature the
trunk exists for is intact.

**A hardware limit that follows, and cannot be fixed in software.** On a global-bitmask
chip a port cannot be untagged in VLAN 1 *and* tagged in VLAN 10. Running a tagged
wireless VLAN therefore leaves the **uplink** socket egress-tagged for VLAN 1 as well —
visible above as the `4t` in `0t 1 2 3 4t`. The UCG Ultra accepts tagged VLAN 1 on that
port (it is the live, working state), and the effect is confined to the one socket facing
the gateway rather than every socket facing a client.

**Generalising:** this is the third finding in the same shape as the first real-hardware
run — config that reads perfectly and hardware that does something else. A `swconfig`
port string is a *request*; `swconfig dev <sw> show` is the only account of what the ASIC
actually holds, and the two must be compared on each chip family, not one.

---

## Controller behaviors that are not openUF bugs

Each of these cost real investigation time at least once.

### A 404 with an empty body does not mean the inform was rejected

A well-formed, correctly-encrypted first-contact inform gets **HTTP 404 with
`Content-Length: 0`**, with zero corresponding entry in the controller's `inform` logger —
yet the device is created server-side and shows as "1 device is ready to adopt." Verified at
the wire level through a raw byte-logging TCP relay: the `100 Continue` handshake completes
normally and the response genuinely has an empty body.

Malformed packets behave differently and are easy to tell apart: they get **400** with a
specific logged reason (`Bad packet magic`, `Data version 0 is not supported`,
`Content too short`).

Ruled out as causes, so they aren't re-tried: compression (a real zlib-compressed,
correctly-flagged payload gets the same 404) and GCM-vs-CBC (both get the same 404).

`http_post` treats any non-200 as a hard failure and never inspects the body. In every case
observed the body was genuinely empty, so nothing is lost — but the client cannot
distinguish "processed, nothing to say" from "rejected," and backs off identically either way.

**When you see this on a fresh device: click Adopt.** That is the correct next move, not
more debugging.

### Historical stats live in the `unifi_stat` database, on a 5-minute cadence

CPU/memory graphs, per-client Traffic Activity, the Radios tab's "Avg." columns, and the
Ports view's Bps chart are **not** rendered from live inform data. They are read from
`unifi_stat`'s `stat_5minutes` / `stat_hourly` / `stat_archive` collections, written by a
periodic archiver (`com.ubnt.service.system.QDcGUYAmLvJwylXw`, internally labelled
`stat-processor`).

So: a flat/empty graph checked two minutes after adoption is expected. Allow ~15 minutes, or
a few 5-minute buckets, before treating it as a defect. Query
`unifi_stat.stat_5minutes` directly to check whether the data is landing — `db.stat` in the
**`unifi`** database is a different, empty collection and querying it is misleading.

### The minidev cache never sees external writes

`com.ubnt.service.devmgr.SNMiFVJXxaonBOtqbJ`'s device lookup is cache-then-DB-fallback: an
in-memory "minidev" summary (`_id`, `site_id`, `authkeys`, `x_aes_gcm`, `hash_id`) keyed
`("global", "minidev", mac)`, populated once on the first DB hit and never invalidated by an
external write. Editing a device doc in Mongo while the controller runs therefore has no
observable effect. Restarting the controller to force a reload introduces its own artifact:
the device flips to **Offline** in the UI even while `last_seen` keeps advancing and informs
keep landing, and does not self-heal within a normal observation window.

This is why the "always reset fully" rule exists. It also explains why "Remove"
(factory-reset) leaves informs decrypting successfully afterwards — they are being served
from a stale cache entry while the underlying doc is already gone.

### Config sync can get stuck after informs stabilise

Observed while trying to force pure-WPA3 emission: switching the test WLAN's Security
Protocol to WPA3 made the controller **stop pushing the WLAN's `aaa.<n>`/`wireless.<n>`
blocks entirely** — not just the SAE fields — and reverting the setting did not restore
pushes, even across an `inform.lua` restart. No related error in `server.log`.

**Reusable warning:** a live no-op does *not* always mean "the controller is deliberately
withholding this field because of a capability gate" (which is exactly what it meant for
`advertise_ap_name`). Sometimes it means the environment's config sync is stuck. Decompile
the emitter to tell the two apart before concluding anything.

### Controller-side UI quirks

- **Environment tab (AirView) stops updating ~10 s after mount**, with no user interaction:
  the row disappears, "No WiFi broadcasts found" renders, and the sidebar filters grey out.
  Clicking any other Time Range tab instantly restores everything. Verified the data is
  present server-side the whole time (10/10 direct `stat/rogueap` polls over 23 s returned
  all entries). Consistent with the table capturing `rowsPerPage` from the pre-fetch, empty
  selector result at mount (`useState({pageNumber:0,from:0,rowsPerPage:r.length})`) and never
  recomputing it. A genuine defect in the controller's own frontend, outside openUF's control.
- **Radios tab's "Type" filter shows nothing until one option is explicitly checked**, unlike
  Band/MIMO/Status on the same page, where an empty selection means "show all." "Type" here
  means the **AP's own uplink** connection type, so a wired-uplinked AP correctly appears
  under "Wired" — the radios themselves being wireless is irrelevant.
- **"Remove" on a client sends no wire command at all** — pure controller-side bookkeeping.
  A still-present client reappears on the very next inform.
- **The upgrade confirmation dialog truncates versions to 3 components**, so a genuine
  full-string mismatch can render as "Update U6 IW from 6.8.2 to 6.8.2?".

---

## Decompiling the controller

The controller is a Java app, and Java bytecode retains field-name string constants in the
class-file constant pool even under ProGuard-style class/method obfuscation — a far friendlier
analysis target than the AP's encrypted ARM firmware (see [dead ends](#dead-ends--do-not-re-attempt)).

**Procedure:**

1. Extract `/usr/lib/unifi/lib/internal/internal-dependencies.jar` from the container — the
   real ~29 MB application jar. (`ace.jar` is only a license-protected bootstrap `Launcher`.)
2. **Unzip it on a case-sensitive filesystem.** `com.ubnt.service.aa` and
   `com.ubnt.service.aA` — and ~55 other package pairs differing only by case — are distinct
   real packages. macOS silently folds them into one directory, corrupting the extraction and
   producing a decompile of the *wrong* class's method body with no warning. Do the
   `unzip` + decompile inside a Linux container (`docker cp` the jar into the controller
   image itself, which already has a JVM).
3. **Use CFR (`cfr.jar` 0.152) for large methods.** `jadx` silently drops method bodies it
   can't reconstruct — no marker, just absent output. The ~5,182-unit method that gates
   provisioning was invisible to jadx and decompiled cleanly under CFR. jadx is still fine
   for browsing and for properly-scoped class listings.
4. For frontend behavior, fetch the live controller's own React chunks
   (`react-app-wrapper.*.js`, `radiosPage.*.js`, `swai.*.js`, `airview.*.js`) and grep them.
   Where a decode function's logic matters, the webpack module registry
   (`window["webpackChunk…"].push([[Symbol()], {}, req => …])`) gives a direct reference to
   the **live** function, which can be called with a sweep of inputs — ground truth, not a guess.

**Logging:** the controller's loggers use flat, hand-picked names (`inform`, `adopt`,
`inform.uap`, `core.lock`, `web.api`), not package paths — see
`com.ubnt.service.system.HCKpgcBFPLu`. Setting `com.ubnt` to DEBUG does nothing for them. A
custom `logback.xml` with explicit `<logger name="inform" level="DEBUG"/>` entries, wired in
via `-Dlogback.configurationFile=`, is needed. Note that most handlers only log on their
*short-circuit* branch, so silence is consistent with everything passing normally.

### Class index

| Class | Role |
|---|---|
| `com.ubnt.service.devmgr.l.MiVjHefaf` | Inform handler / adoption state machine; the provisioning gate; upgrade-offer gate |
| `com.ubnt.service.devmgr.PGOcbDWlbnYQdFW` | `uap`/`uacc` state processor — `radio_table`, `port_table`, `scan_radio_table` ingestion |
| `com.ubnt.service.devmgr.tFhABnrHYJqvjaoEa` | Sibling state processor; power/PoE field copy; `radio_caps` passthrough |
| `com.ubnt.service.devmgr.c.KHUkYjHujLgFBD` | vapInformProcessor — filters `vap_table`, copies `sta_table` attrs |
| `com.ubnt.service.devmgr.DyonYyyYJkiyv` | Per-port `mac_table` processing |
| `com.ubnt.service.devmgr.TtZhv` | Client record writer (wired + disconnect-time wireless archive) |
| `com.ubnt.service.devmgr.HCKpgcBFPLu` → `com.ubnt.g.s.jRsSex` | **Live** (still-connected) client generation display |
| `com.ubnt.service.devmgr.SNMiFVJXxaonBOtqbJ` | Device lookup / minidev cache; replace + clone config services |
| `com.ubnt.service.system.QDcGUYAmLvJwylXw` | Stat archiver (`stat-processor`) — writes `stat_5minutes` `o:"ap"` buckets |
| `com.ubnt.service.system.x.htDMji` | Archiver method that reads `radio_table[].athstats` |
| `com.ubnt.service.aO.hhFgUVZPT` / `aO.bLwwMKkr` | Scan ingestion; the `"PeerScan"` DTO |
| `com.ubnt.service.config.eWivisHeQsnaqDtx` | WLAN/radio config generator (emits `system_cfg`) |
| `com.ubnt.service.config.ubntconf.OXMua` | SAE field emitter |
| `com.ubnt.ace.api.e.VVyiC` | REST per-port VLAN validator |
| `com.ubnt.data.cVbZoFIZsWYaVCquTr` (+ ~90 nested) | The controller's entire internal Device model — one nested class per wire sub-object |
| `com.ubnt.data.cVbZoFIZsWYaVCquTr$QCtdvLKOBb` | vap-stats DTO (**not** the unrelated top-level `com.ubnt.data.QCtdvLKOBb`, a FirewallRule — obfuscated short names collide across packages, always extract by full path) |
| `com.ubnt.data.uuvchZbWVhirD` | Device DTO — `hasFirmwareCapability`, `hasWifiCapability2`, `isSwitch` |
| `com.ubnt.data.dhdeXcHqLRBKMUZk` | Model registry (per-model port count and feature set) |
| `com.ubnt.g.f.e.rYtJfMBbtgWvku` | Radio band enum: `ng`, `na`, `ad`, `6e` |

---

## The inform protocol

### Envelope

Header layout, flags (`0x01` encrypted, `0x02` compressed), zlib-before-encrypt ordering,
AES-128-CBC + PKCS#7, and the default `http://unifi:8080/inform` URL all match openUF's
implementation and fxkr/unifi-protocol-reverse-engineering's published documentation.
`PKT_VERSION` is 1; the GCM AAD is the 40-byte header.

`mgmt_cfg` is a newline-delimited `key=value` **string**, not JSON.

### The GCM provisioning gate

**On 10.4.57 the controller will not provision a device until it has received a genuine
AES-GCM-encrypted inform.** `x_aes_gcm` is set *only* in the decrypt path — `InformServlet`
reads the packet's on-the-wire encryption flag (`header.isGcm()`) and the handler does
`dev.set("x_aes_gcm", true)`. **There is no JSON/payload field that sets it.** The controller
always requests GCM (`use_aes_gcm=true` is written unconditionally into every `mgmt_cfg`), and
once `x_aes_gcm` is set it rejects a GCM→CBC downgrade outright (`"tried to downgrade inform
encryption from AES-GCM to AES-CBC, rejecting"`).

The gate itself, in `MiVjHefaf`:

```java
if (!(dev.isUnsupported() || dev.aesGcmInformEncryptionOnly() || <globalFlag>)) {
    // "dev[..] : mgmt config update before provision"
    resp = new setparam; resp.put("mgmt_cfg", ...);
    dev.set("cfgversion", <fresh random 16-hex>);   // rolls every cycle
    return resp;                                     // returns BEFORE provisioning
}
```

`aesGcmInformEncryptionOnly()` just returns the device doc's `x_aes_gcm` boolean. While it is
false, **every** inform hits this branch, gets a brand-new random `cfgversion`, and returns
early — never reaching `cfgversion`-convergence provisioning, and never reaching the
`wait_for_initial_inform` clear.

**The diagnostic signature** of a device stuck here: adoption reports as completed, informs
decrypt fine, `last_seen` advances — but `cfgversion` is different on *every single* cycle,
`x_aes_gcm` stays false, `provisioned_at` is absent, and the UI shows "Adopting" forever.

Once GCM is sent, all of it resolves in one cycle: `x_aes_gcm` → true, `cfgversion` stabilises,
`provisioned_at` set, `wait_for_initial_inform` cleared, device Connected.

`crypto.lua`'s GCM code works against the `zhaozg/lua-openssl` binding with no changes. The
`openssl(1)` CLI fallback **cannot** do GCM (`enc` refuses AEAD ciphers), so a container
without a real binding silently downgrades to CBC and hangs on this gate.

### Adoption: L2 vs L3

**L3 (inform-only, no SSH).** The controller logs `discovered via L3 inform, skip SSH adoption`
and delivers the new `authkey` directly in the `mgmt_cfg` of the `setparam` sent right after
the Adopt click:

```json
{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat\nselfrun_guest_mode=pass\ncfgversion=e07e7991b8c62b47\nled_enabled=true\nstun_url=stun://172.19.0.4:3478/\nmgmt_url=https://172.19.0.4:8443/manage/site/default\nauthkey=ccc32a3bbe40157773294de8ed683627\ninform_url=http://172.19.0.4:8080/inform\nuse_aes_gcm=true\nreport_crash=true\n","server_time_in_utc":"1783841863822"}
```

openUF accepts a hex32 `authkey` from `mgmt_cfg` **only while `st.adopted == false`** — while
unadopted the device is still using the well-known default key, so this exchange carries no
less confidentiality than the rest of L3 provisioning already assumes.

**L2 (broadcast discovery + real SSH).** With `announce.lua` broadcasting, the controller runs
genuine SSH on the Adopt click and executes `syswrapper.sh set-adopt <url> <key>`. The existing
`syswrapper.lua`/`state.lua` shape (`adopted`, `authkey`, `inform_url`, `cfgversion`, `use_gcm`)
is what real SSH adoption expects — confirmed by a real round-trip.

Two things real hardware does that the validation container had to be taught:

- The controller's SSH client (`sshj`) offers only legacy `ssh-rsa` (SHA-1), matching aging
  UBNT firmware; OpenSSH ≥8.8 excludes it by default. `HostKeyAlgorithms +ssh-rsa` /
  `PubkeyAcceptedAlgorithms +ssh-rsa` are needed in `sshd_config`.
- The controller authenticates as the Ubiquiti factory-default account **`ubnt`/`ubnt`**, not
  the admin-configured Device SSH credentials — correct behavior, because `announce.lua`'s
  `IsDefault` byte (`0x17` in the TLV blob, `make_blob_17_1a`) correctly declares the device
  unadopted.

`mgmt_url` is the **web UI deep link** (`https://host:8443/manage/site/default`), *not* an
alias for `inform_url`. Treating them as the same key makes the device overwrite its working
inform endpoint on the first routine post-adopt `setparam` and disappear permanently.

### Response `_type`s

The complete set, per `InformServlet`: `noop`, `setparam`, `cmd`, `upgrade`, `reboot`,
`setdefault`. There is no export/backup/dump command.

| `_type` | Shape | Notes |
|---|---|---|
| `noop` | `{"_type":"noop","interval":…}` | Steady state. |
| `setparam` | `{"_type":"setparam","mgmt_cfg":"…","system_cfg":"…","server_time_in_utc":"…"}` | Both configs are flat `key=value` blobs. See [system_cfg](#system_cfg-the-real-config-channel). |
| `cmd` | `{"_type":"cmd","cmd":"…","mac":"…","device_id":"…",…}` | See command table below. |
| `upgrade` | `{"_type":"upgrade","version":"6.8.2.15592","md5sum":"…","url":"http://fw-download.ubnt.com/…"}` | Fire-and-forget, sent exactly once; no retry, no confirmation expected. |
| `reboot` | `{"_type":"reboot","reboot_type":"soft",…}` | The top-level form is the real one; `{"_type":"cmd","cmd":"restart"}` is not the path this action takes. `reboot_type` is unused by openUF. |
| `setdefault` | — | Handler exists but has never been observed dispatched live; see [open questions](#open-questions). |

**After executing a `cmd`, the device must send another inform immediately** (documented by
fxkr and confirmed live: the controller's next `noop` lands in the same second).

Confirmed `cmd` strings:

| `cmd` | Trigger | Payload |
|---|---|---|
| `set-locate` | Locate button | `{"cmd":"set-locate","device_id":…}` |
| `block-sta` | Block client | `{"cmd":"block-sta","mac":"…"}` |
| `unblock-sta` | Unblock client | `{"cmd":"unblock-sta","mac":"…"}` |
| `spectrum-scan` | — | Handler implemented; no UI affordance found in 10.4.57 to fire it. |

Block/unblock are **one-shot commands**, not persistent per-inform state. The candidate
persistent field `include_blocks` (present on every response) was ruled out — it stays `[]`
even while a client is genuinely blocked. The device is expected to remember the block itself,
which is why `state.json` carries `blocked_stas` and `firewall.reconcile()` runs at startup.

---

## `system_cfg`: the real config channel

**A real controller never sends `resp.vap_table` / `radio_table` / `network_table` as JSON.**
All device configuration — WiFi, radios, IP settings, per-port VLAN, minimum RSSI — arrives
inside the flat, OpenWrt/hostapd-style `system_cfg` key=value blob on a `setparam`.
`inform.lua`'s `M._parse_wifi_system_cfg()` translates it into the `{radio_table, vap_table}`
shape `ucihelper.apply_config()` expects.

Conventions used throughout: booleans are `"enabled"`/`"disabled"` (sometimes `"true"`/`"1"`);
an **absent block means disabled** — there is generally no explicit `status=false`.

### `aaa.<n>.*` — per-SSID security

| Key | Meaning |
|---|---|
| `ssid` | SSID |
| `id` | The wlanconf Mongo ObjectId. **Must be echoed back** — see [`vap_table`](#vap_table-entry). |
| `wpa` | WPA protocol version (`2`/`3`). Stays `2` even for a WPA2/WPA3 transition WLAN. |
| `wpa.psk` | Passphrase |
| `wpa.key.<k>.mgmt` | AKM set (`WPA-PSK`, `SAE`, …). **This**, not `wpa`, is what distinguishes SAE. |
| `pmf.status` / `pmf.mode` | 802.11w. `mode` is `0`\|`1`\|`2` (disabled/optional/required), mapping 1:1 onto hostapd's `ieee80211w`. On this madwifi model, **WPA2/WPA3 transition intent is carried entirely by these fields** — dropping them silently collapses mixed mode to plain WPA2. |
| `pmf.cipher` | `AES-128-CMAC`. Not translated — hostapd's default BIP group-mgmt cipher already is this. |
| `ft.status` | Fast Roaming (802.11r) for the WLAN. No `mobility_domain`/`r0kh`/`r1kh` on the wire — the controller computes and syncs those internally across the site; `ucihelper.derive_mobility_domain()` fills the gap locally. |
| `wpa3.ft.status` | FT for the **SAE akm alone**, a separate toggle from `ft.status`, from the wlanconf's `isWpa3SaeFastRoamingEnabled()`. Emitted unconditionally on any SAE push (the first key `OXMua` writes) and absent otherwise. OpenWrt has one `ieee80211r` switch feeding hostapd's `key_mgmt`, and on `sae-mixed` it yields FT-PSK **and** FT-SAE together, so openUF enables FT if *either* toggle asks and logs the disagreement. |
| `bss_transition` | 802.11v. Present on every band's block, flips independently of Fast Roaming. |
| `br.devname` | `br0` untagged, **`br0.<vlan>`** when the WLAN is assigned to a VLAN network — CONFIRMED live 2026-08-01, the first capture of a tagged WLAN on real hardware. This suffix is the *only* per-WLAN VLAN signal; there is no `network_table`/`networkconf_id` join anywhere in the wire format. |
| `sae.anti_clogging` / `sae.sync` | Plain integers, emitted only when > 0 **and** the WLAN is genuinely WPA3 (see below). |
| `driver` | `madwifi` — confirms the controller is talking to this model as madwifi-era firmware, which explains several value encodings below. |

A VLAN assignment also produces companion `vlan.*`, `bridge.*` and `netconf.*` blocks.
**The `bridge.*` block is a specification, not decoration** — an earlier revision of this
document said openUF "does not need to reproduce these", which cost a live debugging
session. Captured 2026-08-01 when a WLAN was put on VLAN 20:

```
bridge.1.devname=br0            bridge.2.devname=br0.20
bridge.1.port.1.devname=eth0    bridge.2.port.1.devname=ath2      ← the vap
bridge.1.port.2.devname=ath0    bridge.2.port.2.devname=eth0.20   ← the tagged uplink
bridge.1.port.3.devname=ath1    bridge.2.stp.status=disabled
```

That second bridge is exactly the L2 a tagged SSID needs, and openUF must build the
equivalent (`br-openuf<vlan>` holding `<cpueth>.<vlan>`, with the VAP joined to it).
Skipping it yields a VAP and an uplink sub-device that are both up and completely
unconnected: the client associates and gets no DHCP, no gateway, nothing, while UCI,
netifd and hostapd all look correct.

`netconf.*` blocks are per-device-interface and stay anchored: the AP's own IP settings
remained at `netconf.1` (`devname=br0`) with the VLAN's entries taking later indices, so
inform.lua's `^netconf%.1%.` anchor is safe against a VLAN being added.

**Provisioning is not driven by `cfgversion` alone.** A device reporting a stale or bogus
version sometimes gets an immediate full push and sometimes only `noop`s, indefinitely,
even across restarts and fresh random values. An empty string is ignored outright. The
reliable trigger is a real config change in the controller — and note that a UI form
failing validation (e.g. switching a 2.4-GHz-only WLAN to Manual, where Band Steering
demands two bands) saves nothing and pushes nothing, with no error surfaced beyond the
form itself.

**SAE gating.** `com.ubnt.service.config.ubntconf.OXMua`'s emitter is capability-gate-free:

```
n = wlan.getInt("sae_anti_clogging", -1); if (n > 0) emit "aaa.<idx>.sae.anti_clogging" = n
s = wlan.getInt("sae_sync", -1);          if (s > 0) emit "aaa.<idx>.sae.sync" = s
```

but is only *called* when `wlan.isWpa3() || wlan.isOn6GHzBand()`. `isWpa3()` reads the DB flag
`wpa3_support`, which the **"WPA2/WPA3" dropdown does set** — read live from this site's
wlanconf: `wpa3_support: true`, `wpa3_transition: true`, `pmf_mode: optional`. (An earlier
revision of this document claimed the mixed choice left `wpa3_support` false and that a mixed
WLAN therefore never emits these keys. Wrong: the WLAN-side gate passes; what suppresses the
whole SAE block is the *per-device radio* capability check described in the WPA3 section.)
openUF maps these to hostapd's `sae_anti_clogging_threshold` / `sae_sync`
(the older name, still the broadly-supported one across the OpenWrt/wpad versions targeted).

### `wireless.<n>.*` — per-SSID radio binding and behavior

| Key | Meaning |
|---|---|
| `ssid`, `parent` | SSID, and the owning radio (`radio0`/`radio1`) |
| `dtim_period` | Plain integer, **always present** regardless of the WLAN's Auto/Custom DTIM toggle. There is no `dtim_mode`/`dtim_ng`/`dtim_na` key on the wire — go-unifi's band-split shape describes the REST API, not this protocol. |
| `no2ghz_oui` | **Band Steering's real wire representation.** Not a per-device `mgmt_cfg` field. Toggling Band Steering changes only this key, and only on the 2.4 GHz entry (the 5 GHz entry stays `disabled` — nothing to toggle there). A madwifi/QCA convention: omitting the AP's OUI from 2.4 GHz beacons nudges dual-band clients toward 5 GHz. Mainline mac80211/hostapd has no equivalent, so openUF derives a single device-wide `steering_active` boolean (true if *any* vap has it) and drives `usteer`, which is itself a device-wide daemon. |
| `mcast.enhance` | Multicast Enhancement / Multicast-to-Unicast. `0`\|`1`. |
| `minrate_data`, `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status`, `minrate_below_disable`, `pureg` | **Minimum Data Rate Control.** `minrate_data` is the floor in kb/s; `beacon_rate`/`mgmt_rate` simply mirror it. `minrate_cck_rates.status` and `pureg` are derived consequences on 2.4 GHz (a 12 Mbps floor is OFDM, so CCK goes `false` and `pureg` goes `1`). `minrate_below_disable` is the separate "advertising rates" sub-toggle. Emitted per band and **absent entirely** when that band's control is off — not band-gated, which an early reading of a 2.4-GHz-only capture suggested. |
| `bcfilt.status`, `bcfilt.<k>.mac`, `bcfilt.<k>.status` | **Multicast and Broadcast Blocker** (REST `bc_filter_enabled`/`bc_filter_list`). `status` appears whenever the control is on, including with an empty allow-list; the indexed entries only once it is non-empty. `<k>` is 1-based and does **not** follow the REST list's order — adding a second MAC renumbered the first — so the index means nothing beyond grouping. Emitted on both band entries. |
| `l2_isolation` | **Client Isolation.** `enabled`\|`disabled`, always present, emitted on both band entries. → OpenWrt `isolate` (hostapd `ap_isolate`). |
| `devname` | The Ubiquiti-side netdev for this vap (`ath0`…`ath3`). **The join key for the top-level [`macacl.*`](#macacl--mac-address-filter) section**, whose own indices do not line up with `<n>`. Not a name that exists on OpenWrt — enforcement resolves the real netdev via `ubus`. |
| `mac_acl.status`, `mac_acl.policy` | ⚠️ **Decoys — not the MAC Address Filter.** Sit at `enabled`/`deny` with the control off and do not move when it is toggled; the real feature is the top-level [`macacl.*`](#macacl--mac-address-filter) section. |
| `hide_ssid` | **Hide WiFi Name.** `true`\|`false` — note the vocabulary, not the `enabled`/`disabled` most keys here use. Always present, emitted on both band entries, and duplicated verbatim as `aaa.<n>.hide_ssid`. → OpenWrt `hidden` (hostapd `ignore_broadcast_ssid`). |
| `mcastrate` | Multicast rate. Observed only ever as `auto` — no WLAN-level control in 10.4.57's UI moves it, and OpenWrt's `mcast_rate` is adhoc/mesh-only anyway, so openUF does not map it. |
| `advertise_ap_name` | "Show Access Point Name in Beacon". **Only emitted when the device declares `wifi_caps2` bit `0x40`** — see [capability bitmasks](#capability-bitmasks). |
| `iot`, `qbssload` | **"Force WiFi 4 Mode"** (IoT Optimization; REST field `enhanced_iot`). Absent entirely when off; appear together as `iot=enabled` + `qbssload=disabled` on the WLAN's 2.4 GHz entry when on. The parent radio is *not* touched — `radio.<n>.ieee_mode` keeps the site's configured width — so this is a per-BSS flag only. `qbssload` is its one distinct on-air effect (suppress the QBSS Load IE); the rest of the mode arrives as ordinary keys: the 5 GHz vap is dropped outright, security pinned to WPA2, and `bss_transition`/`proxy_arp`/`no2ghz_oui`/PMF/`advertise_ap_name` all forced off. |

### `radio.<n>.*` — per-radio config

`phyname` (`radio0`), `channel` (integer or the literal `auto`), `txpower` (integer or `auto`),
`txpower_mode` (`auto`/`custom`/`disabled`), `status`, `ieee_mode`. When no radio is
provisionable the blob contains the literal comment `# no wlan provisioned as no radio found`
and the **unindexed** `radio.status=disabled` — see
[`radio_table` must not be empty](#radio_table-entry).

Do not confuse that unindexed key with the **indexed** `radio.<n>.status`, which is the real
per-radio enable/disable control — see
[`radio.<n>.status` — per-radio disable](#radionstatus--per-radio-disable).

`ieee_mode` is **the wire's only channel-width signal**: a compound `11` + band (`ng`/`na`) +
PHY and width token — `11nght20`, `11nght40`, `11naht40`, `11acvht80`, `11axhe80`. Changing
Devices → [AP] → Settings → Radios → "2.4 GHz Channel Width" from 20 to 40 changes exactly this
key (alongside `cwm.mode` 0→1, a redundant channel-width-management flag carrying no extra
information). openUF maps it to UCI `wifi-device.htmode`; on OpenWrt/mac80211 that option is the
PHY ceiling, so `HT20`/`HT40` also *is* "802.11n only". There is no separate 11n/11ac/11ax mode
key — an earlier version of openUF expected one, never populated it, and so silently never
applied channel width at all.

### `stamgr.<n>.*` — per-radio Station Manager (Minimum RSSI)

Indexed the same as `radio.<n>`, **not** tied to any SSID. This is a device/radio-level
setting (Devices → [AP] → Radios), not a WLAN one — distinct from the WLAN Advanced panel's
"Roaming Assistant", which is a different feature with its own REST fields
(`roamingAssistantNaEnabled`/`Rssi`) that never appear on the wire.

```
stamgr.1.status=true
stamgr.1.radio=ng
stamgr.1.minrssi.status=true
stamgr.1.minrssi.rssi=15
stamgr.1.loadbalance.status=false
```

**The threshold is not plain dBm.** UI `-80 dBm` → wire `15`; UI `-85 dBm` → wire `10` —
consistent with `wire = dbm + 95`, an offset from an assumed -95 dBm noise floor (a madwifi
convention, matching `aaa.1.driver=madwifi`). openUF stores the raw wire value in UCI and
converts to dBm only where a live noise-floor reading exists (`sysinfo.radio_stats()`'s
`iw survey dump` parse), falling back to the -95 assumption otherwise.

`loadbalance.status` is a sibling sub-feature sharing the block; unimplemented.

**Enforcement semantics** (from web research — this is client-facing AP behavior, not a wire
format): Minimum RSSI is a **roaming aid, not a block**. The AP sends a single deauth frame to
a below-threshold client; there is no persistent drop rule and the client may reassociate
immediately, even to the same AP. This is materially different from `block-sta`, so it has its
own helper, `ucihelper.kick_station()`, rather than reusing `firewall.deauth()`.

### `macacl.*` — MAC Address Filter

A **top-level section keyed by devname**, not by the `wireless.<n>` index. Confirmed live
2026-07-18 by enabling the control on one WLAN with a single allow-listed MAC:

```
macacl.status=enabled                       # global gate
macacl.1.devname=ath0                       # join key -> wireless.<n>.devname
macacl.1.status=enabled
macacl.1.acl.status=enabled
macacl.1.acl.policy=allow                   # allow | deny  (UI "Filter Type")
macacl.1.acl.1.mac=02:11:22:33:44:55
macacl.1.acl.1.status=enabled
macacl.1.acl.1.type=user
macacl.2.devname=ath2                       # the same WLAN's 5 GHz vap
```

Only the vaps belonging to the filtered WLAN get a block, and they are numbered from 1
independently of `wireless.<n>` — in this capture `macacl.1`/`macacl.2` correspond to
`wireless.1`/`wireless.3`. **A join on `devname` is mandatory**; an index-based reading
misfiles the filter onto the wrong WLAN.

Like `bcfilt.<k>`, the `acl.<k>` index carries no meaning beyond grouping, so openUF sorts
the list. Maps onto OpenWrt's `macfilter` (`disable`\|`allow`\|`deny`) + `maclist`, whose
policy vocabulary lines up 1:1 with the controller's.

⚠️ **Two decoys excluded by the same diff.** `wireless.<n>.mac_acl.status` /
`wireless.<n>.mac_acl.policy` sit at `enabled`/`deny` with the control **off** and did not
move when it was toggled — the same shape as `radio.<n>.bcmc_l2_filter.status` was for the
broadcast blocker. `aaa.<n>.radius.macacl.status` is the unrelated RADIUS MAC Authentication
control. Do not re-investigate these.

### `qos.*` — WiFi Speed Limit

Another **top-level section keyed by devname**. Confirmed live 2026-07-18 by creating a
speed-limit profile (33 Mbps down / 17 Mbps up) and assigning it to one WLAN. Note the
per-WLAN toggle does nothing until at least one profile exists in the site settings — with no
profile there is nothing to select and nothing reaches the wire.

```
qos.status=enabled
qos.mode=1
qos.if.1.devname=eth0 / .devspeed=1000 / .type=uplink   # interface inventory
qos.if.2.devname=ath0 / .devspeed=570
qos.vap.1.devname=ath0                                  # join key
qos.vap.1.dwnlink.maxspeed=33000                        # kbps  (UI Mbps x 1000)
qos.vap.1.dwnlink.minspeed=33000
qos.vap.1.uplink.1.devname=eth0
qos.vap.1.uplink.1.maxspeed=17000                       # kbps
qos.ebt.1.cmd=PREROUTING --in-interface ath0 -j mark --mark-or 0x1000 ...
```

| Detail | |
|---|---|
| Units | **kbps**. The UI's Mbps value × 1000. |
| Discriminator | **Presence of `maxspeed`.** Not `qos.status` (global), and *not the block itself*: an unlimited vap still gets a `qos.vap.<m>` block carrying only `minspeed`, set to that radio's raw `devspeed` (570 on 2.4 GHz, 2400 on 5 GHz here). Treating the block as "limited" would cap every WLAN at its own PHY rate. |
| Scope | A **per-VAP aggregate** cap, not per-client — there is no per-station structure on the wire. All clients on the SSID share the ceiling, which is what makes one qdisc per VAP sufficient. |
| `qos.ebt.<n>.cmd` | Literal ebtables fragments the stock firmware would replay to fwmark each VAP. openUF implements the intent with `tc` instead (`shaper.lua`), since ebtables is not a given on OpenWrt while `tc` ships in the base iproute2. |

### `netconf.*` / `dhcpc.*` / `route.*` / `resolv.*` — IP settings

```
netconf.1.devname=br0
netconf.1.ip=172.19.0.50
netconf.1.netmask=255.255.255.0
netconf.1.autoip.status=disabled
route.1.gateway=172.19.0.1
resolv.nameserver.1.ip=192.168.1.1
resolv.host.1.name=<device name>      # also the source for wps_device_name
dhcpc.status=enabled
dhcpc.1.status / dhcpc.1.devname      # the actual DHCP-vs-static signal
```

**A fresh device's very first post-adopt `setparam` always carries `dhcpc.1.status=enabled`** —
a brand-new device is in DHCP by definition. Acting on that unconditionally (flush + `udhcpc`)
strands the interface if no DHCP server can grant a fresh lease. `netconfig.apply_dhcp` is
therefore only called when `st.ip_mode == "static"` already, i.e. when genuinely reverting our
own prior static push; first contact and steady-state reaffirmations are a no-op, matching how
real hardware's continuously-running DHCP client needs no manual re-invocation.

### `switch.*` — per-port VLAN

Appears only once the device declares switch capability. Fully mapped live 2026-07-19 by
diffing `system_cfg` across five states. An earlier version of this section claimed the
controller "manages VLAN membership server-side and only needs the device to *accept* the
push" — **that was wrong**, and it is why README claimed the feature worked while no code
existed. The device is sent a complete, actionable VLAN table.

**Baseline (B0) — Port VLAN off**, the state every device sits in until the control is
enabled:

```
switch.status=disabled
switch.vlan.status=disabled
switch.dot1x.status=disabled
switch.jumboframes=disabled
switch.port.1.name=PoE Out + Data   / .opmode=switch
switch.port.2.name=Data             / .opmode=switch     # ... through port 5
```

The `switch.port.N` entries are always present — one per the **model registry's** port count
(5 for U6IW), not per whatever `port_table` openUF reports. They carry only `name`/`opmode`
and never move; they are inventory, not control.

**The discriminator is `switch.status` / `switch.vlan.status` flipping to `enabled`.** Both
sit at `disabled` in B0, so — unlike `wireless.<n>.mac_acl.*` or `radio.<n>.bcmc_l2_filter.status`
— these are genuine gates, not decoys. They are driven by a **device-level** checkbox
(Devices → [AP] → Settings → IP Settings → **Port VLAN**), not by anything per-port, and until
it is ticked the whole per-port VLAN UI is greyed out.

**C1 — Port VLAN enabled, no port override.** The site's VLANs appear as a table:

```
switch.status=enabled
switch.vlan.status=enabled
switch.vlan.1.id=1      / .mode=untagged / .status=enabled
switch.vlan.2.id=20     / .mode=tagged   / .status=enabled
```

`switch.vlan.<m>` is a slot number; `.id` is the real VLAN id. `.mode` here is the VLAN's
device-wide default.

**C2 — port 2's Native VLAN set to the VLAN-20 network.** Three keys are added:

```
switch.port.2.pvid=20              # the port's untagged/native VLAN
switch.vlan.1.port.2.mode=tagged   # VLAN 1 is tagged on port 2
switch.vlan.2.port.2.mode=untagged # VLAN 20 is untagged on port 2
```

So membership is expressed **twice, redundantly**: once per-port (`pvid`) and once as a
per-VLAN-per-port matrix (`switch.vlan.<m>.port.<n>.mode`). The matrix is the authoritative
one — it is what carries tagging, and `pvid` is derivable from it (the VLAN whose mode is
`untagged`).

**`switch.port.<n>` joins directly to `port_table[].port_idx`** — no devname indirection,
unlike `macacl.*`/`qos.vap.*`. Confirmed by the Port Manager UI listing exactly the two ports
openUF reports at the time (not the registry's five) and the override landing on wire index
2, openUF's port_idx 2. This join is why `port_idx` is pinned to a physical socket in the
modelmaps and must not be renumbered: the controller stores a port's settings against it.

**C3 — Tagged VLAN Management → Block All.** One key changes:

```
switch.vlan.1.port.2.mode=exclude   # was "tagged"
```

giving the full mode vocabulary: **`untagged` | `tagged` | `exclude`**, which maps 1:1 onto
swconfig's untagged/tagged/absent port membership.

**C4 — port reverted to default.** The three per-port keys from C2 simply **disappear**, and
the blob returns byte-identical to C1. Teardown is therefore expressible: absence means
default (untagged on the management VLAN, all others tagged), the same "absent block means
disabled" convention used everywhere else in this format.

### `radio.<n>.status` — per-radio disable

Also settled 2026-07-19, in the same session. Setting a radio's **Transmit Power → Disabled**
(Devices → [AP] → Settings → Radios) moves four keys:

```
radio.1.status=disabled            # was enabled
radio.1.txpower_mode=disabled      # was auto
radio.1.virtual.1.status=disabled  # was enabled
wireless.1.status=disabled         # and every other vap on that radio
wireless.2.status=disabled
```

This corrects an earlier reading of this document, which recorded `radio.status=disabled`
only as part of the radio-less `# no wlan provisioned as no radio found` case and concluded
the key carried no per-radio signal. **The indexed `radio.<n>.status` is a real control.**

openUF maps `radio.<n>.status` onto UCI `wifi-device.disabled` and `wireless.<n>.status` onto
each `wifi-iface.disabled`, and reports both back out (`radio_table[].disabled` /
`vap_table[].disabled` already read them off UCI), so the controller sees its own push
reflected. Two details worth keeping:

- The read is **tri-state**. An absent `status` key writes nothing, so a blob that never
  carries it cannot re-enable a radio or SSID the operator disabled by hand in
  `/etc/config/wireless`; only an explicit `enabled`/`disabled` writes. An explicit
  `enabled` must clear the flag, or a radio could never be switched back on.
- Only the **indexed** key is read. The unindexed `radio.status=disabled` in the radio-less
  blob would otherwise take every radio on the device down — the tokenizer's
  `radio.<n>.<key>` shape cannot match a two-component key, so this is structural, but it is
  pinned by a test.

A disabled WLAN is still provisioned, just with `disabled=1`, so its configuration survives
a re-enable.

---

## The first DSA / 802.11ax board

2026-09-01, Xiaomi Mi Router AX3000T (mediatek/filogic MT7981, OpenWrt 25.12.5) + the same
UCG Ultra. It replaced the TL-WDR3500 in the bedroom. Everything the ath79 boards could not
show, because they are all swconfig and all 802.11n on 2.4 GHz.

### Verified working on the board

Adoption over L3 (identity MAC `d4:53:2a:38:80:cf`, the board's label MAC, `use_gcm: true`),
LLDP topology (`cid_interface='wan'` → Parent Device *Cloud Gateway Ultra, Port 2*),
per-socket `port_table` including a genuine FE/GbE split and wired clients on the right
sockets, both radios on air, Locate and the LED toggle on the real case LED, and the
tagged-VLAN SSID path.

### A tagged SSID needs no switch trunk on DSA

The swconfig boards need a `switch_vlan` trunk or the ASIC drops every frame of an unknown
VID. DSA needs nothing: with bridge VLAN filtering off — the state a `br-lan` with no
`config bridge-vlan` is in — the switch passes tags straight through, and the 8021q device
on the uplink *bridge port* (`wan.10`) takes its VID before the bridge sees it, because
`vlan_do_receive` runs ahead of the bridge's rx_handler. Confirmed live: `br-openuf10`
holding `wan.10` and the IoT VAP, `wan.10` counting 1.9 MB inbound, the gateway's MAC
learned on it, and untagged wired clients on the other sockets unaffected.

### Per-port VLAN on DSA is a bridge move, not `bridge-vlan`

Same insight, applied to the wired side: assigning a socket to VLAN 10 puts it in
`br-openuf10`, the bridge that already holds `wan.10`. `br-lan` keeps the uplink, the
unassigned sockets and the management address, and nothing runs with `vlan_filtering` — so
a wrong answer here cannot strand the AP, which `config bridge-vlan` on `br-lan` very much
could. It would also have fought the tagged-SSID path for the same `vlan_do_receive`
reason: a `bridge-vlan` for VLAN 10 on `br-lan` would never receive anything, because
`wan.10` takes those frames first.

Confirmed live: port 2 assigned to the IoT network moved `lan2` into `br-openuf10` next to
the IoT VAP, left `br-lan` holding `wan`/`lan4`, and the attached device's frames appeared
on the tagged uplink **byte for byte** — each 342-byte DHCP DISCOVER on `lan2` showed up as
exactly 342 bytes of `wan.10` tx. That counter identity is the cleanest proof the path is
real, and the way to verify a move without relying on the client.

**Turning the feature off does not always announce itself.** The gates were once observed
staying on the wire at `switch.status=disabled`, and openUF treated an absent `switch.*`
block as "say nothing, change nothing" so an older controller or a partial push could not
trigger a teardown. But a device that has HAD Port VLAN on and then has it unticked gets a
full `system_cfg` with **no `switch.*` keys at all** — so the affirmative off signal never
arrived, the teardown never ran, and `br-lan` kept openUF's port list indefinitely. Absence
now counts as off as well, gated on openUF holding a reversibility ledger: that is proof it
applied something, which is proof the controller was sending `switch.*` until now. It is
reachable only inside `type(sys_raw) == "string"`, so a noop response can never trigger it,
and `restore()` spends the ledger so it cannot flap.

What the client does next is its own business: an IKEA Trådfri hub kept the Home LAN lease
it already held (the link never drops when a port changes bridge), and after a link bounce
re-sent DISCOVER once a minute for fifteen minutes without ever accepting an offer. Scope
on DSA is the Native VLAN — a bridge gives a port one untagged home — and a tagged-only
port is refused out loud rather than half-applied.

### `radio.<n>.ieee_mode` carries a width, not a PHY generation

The wire says `11nght20` / `11naht40`. Read literally that pins an 802.11ax radio to
802.11n, and the AX3000T's 5 GHz radio came up **HT40 on hardware that does HE160**. The
vocabulary is Atheros-era throughout — the same push names the VAPs `ath0`/`ath1`/`ath2` —
and a real U6-InWall receives the identical string and runs it as HE40. The controller has
no field in which to request a PHY generation at all; that is the device's own business.

Invisible from the controller, which renders the width and got it right. `iw dev` is the
only place it showed. Fixed by taking the width from the wire and the PHY from `iw phy`;
confirmed on both boards, the AX3000T going HE20/HE40 and the Archer C5's 5 GHz going
HT40 → **VHT40** while its HT-only 2.4 GHz radio correctly stayed HT20.

### An HE 2.4 GHz radio is the first that can be over-clamped

`phy_caps` derived a band's max width from the PHY generation, so HE implied 80 MHz on
*both* bands. True while every 2.4 GHz radio here was ath9k; wrong on the first ax board,
where the band still stops at 40 (`board.json` agrees). `clamp_htmode` narrows to 40 only
for kind `HT`, so a pushed HE80 would have reached hostapd, which treats an unprogrammable
width as fatal — the radio simply never starts.

### `/sys/class/leds` lists what drivers registered, not what the case has

The AX3000T's case LED sat a steady orange throughout, and forcing **both** mt76 LEDs to
full brightness changed nothing on it: `mt76-phy0`/`mt76-phy1` are registered by the driver
on every board it supports, wired or not. The real LED is the blue/yellow GPIO pair the
device tree declares, which never registered because the stock filogic image ships no
`gpio-leds` driver — the platform device is there, nothing claims it, and the GPIOs keep
whatever the bootloader set. `kmod-leds-gpio` (9 KB) registers `blue:status` and
`yellow:status`; Locate then blinks the actual box at 4 Hz.

### state.json persisted ten fields it could never read back

`save()` encodes the whole table, `load()` copied back a hardcoded eight. The rest were
written to disk, visible in the file, and nil on the next start — including the per-port
VLAN reversibility ledger, the LED toggle, the locate flag, the static-vs-DHCP guard, and
the identity MAC that `_warn_identity_change` compares against, which made that entire
diagnostic unreachable. Surfaced here because this is the first board whose LED idles at
something other than off, so "the toggle forgets itself on reboot" was finally *visible*.

### 802.11r was configured, advertised, and not working

Everything visible said fast roaming worked: `ieee80211r=1` and `mobility_domain=82d8`
identical on both APs, the Mobility Domain element in both beacons (`iw` prints it as
`Unknown IE (54): 82 d8 00` — it does not decode element 54, which reads like an absence),
and `PSK FT/PSK PSK/SHA-256 SAE FT/SAE` advertised in the RSN IE. Nothing in the controller
contradicts any of it.

Forcing a roam is what settled it. A station that had negotiated **FT-SAE** reassociated
with `auth_alg=sae` plus a full `EAPOL-4WAY-HS-COMPLETED` — a real fast transition shows
`auth_alg=ft` and no 4-way at all. It failed even between two BSSes on the *same radio*, so
it was never about the APs failing to reach each other.

Cause: openUF pinned `ft_psk_generate_local=1`. Local key generation is **FT-PSK only** —
each AP derives PMK-R0/R1 from the PSK it already holds — while FT-SAE derives PMK-R0 from
the per-session SAE PMK, which no passphrase can reproduce; its PMK-R1 must be pulled from
the origin AP over an `r0kh`/`r1kh` relationship. OpenWrt configures those key holders only
when the option is `0`, and only defaults it to `0` when nothing overrode it. Pinning it to
`1` therefore removed the one mechanism FT-SAE needs, on a `sae-mixed` WLAN where every
WPA3-capable client picks SAE. Measured AKMs at the time: 3× FT-SAE, 3× SAE, 1× PSK,
**0× FT-PSK** — nothing was on the path that would have worked.

Leaving the option unset lets `hostapd.sh` key it on auth type (`psk` → 1, else → 0) and
derive wildcard key holders from `md5(mobility_domain/psk)` — deterministic, so independent
APs sharing an SSID and passphrase compute the same key with no coordination, which is the
same reasoning as the derived mobility domain. Both APs then produced
`r0kh=ff:ff:ff:ff:ff:ff * 8f017bfa84f587a708a51c185973596e`, byte-identical, and the same
forced roam gave `auth_alg=ft` with no 4-way — first between radios on one AP, then across
the two APs, which is the case that needs the PMK-R1 actually pulled over `br-lan`.

The lesson generalises past this option: a wireless feature can be correct in UCI, correct
in the generated hostapd config, correct in the beacon, and still not happen. Only the
station's own state transition proves it.

### Channel choice, for a two-AP site in CZ

`iw reg get` after adoption: 5150–5250 at 23 dBm with no DFS, 5250–5350 and 5470–5725 DFS,
5725–5875 at only 13 dBm. So the non-DFS channels at usable power are exactly **36/40/44/48**
— one 80 MHz block, or two 40 MHz ones. With the other AP on 36+40, this one belongs on
44+48: auto had picked DFS ch 52, which costs 3 dB and a 60 s CAC on every radio start.

On 2.4 GHz auto picked ch 13 because it was genuinely empty. It was also carrying the IoT
SSID, and ch 12–13 are invisible to any client that only scans 1–11 — which most ESP-class
gear does. Moving to ch 11 took that radio from **0 associated clients to 4**.


## Outbound payload field reference

Everything openUF sends. Names were audited against the controller's own Device model
(`com.ubnt.data.cVbZoFIZsWYaVCquTr` and its ~90 nested per-sub-object classes).

### Top level

| Field | Value / notes |
|---|---|
| `_type` | `"state"` |
| `default`, `state` | `not adopted`; `2` connected / `0` unadopted |
| `mac`, `serial`, `model`, `platform`, `hostname`, `ip` | `serial` is the MAC with colons stripped |
| `inform_url`, `cfgversion`, `uptime`, `time` | |
| **`version`** | **Bare firmware version only — never model-prefixed.** See below. |
| `required_version`, `bootrom_version`, `country_code` | `bootrom_version` has no counterpart anywhere in the device schema (closest is `boot_time`, a timestamp); likely ignored, left as-is for want of evidence to rename it to. |
| `mem_total`, **`mem_used`** | Bytes. `mem_used = total − free`; the schema has `mem_used`, not `mem_free`. |
| **`system-stats`** | Hyphenated key, `{cpu, mem, uptime}` — all three **strings**, cpu/mem as percentages. Not `sys_stats`, and not loadavgs. `cpu` is `0` on the very first inform (delta-sampling `/proc/stat` has no prior sample). |
| **`fw_caps`** | `0x110` — see [capability bitmasks](#capability-bitmasks) |
| **`wifi_caps2`** | `0x40` — see [capability bitmasks](#capability-bitmasks) |
| `spectrum_scanning`, `spectrum_scan_timestamp` | **Device-level**, not per-radio (the per-radio fields are `spectrum_table`/`spectrum_table_time`) |
| `if_table[]` | `name`, `mac`, `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `tx_errors` |
| `radio_table[]`, `radio_table_stats[]`, `vap_table[]`, `scan_radio_table[]`, `port_table[]`, `lldp_table[]` | See below |

**Why `version` must be bare.** The upgrade-offer gate in `MiVjHefaf`:

```java
private boolean chgwykfBxZCAuEHPPQ(String string, String string2) {
    return this.TgovGTpPRqBiOa(string) && !StringUtils.equals(string, string2);
}
// object3 = ProductInfo.version         -- e.g. "6.8.2.15592" (bare)
// string  = inform.getString("version")
```

A **strict, unnormalized `StringUtils.equals`** — no prefix stripping, no numeric parsing.
Sending `"U6IW.6.8.2.15592"` never matches `"6.8.2.15592"`, so the "Update Available" banner is
permanent regardless of the actual firmware version. The catalog's version is confirmed bare
by the controller's own startup log: `firmware[U6IW] new version (6.8.2.15592) is available`.

`fw.pre` (`"U6IW."`) remains correct and untouched in `announce.lua`'s L2 discovery
"firmware version verbose" TLV — a different protocol surface. Do not reuse it here.

### Capability bitmasks

| Field | Bit | Controller method | Effect if absent |
|---|---|---|---|
| `fw_caps` | `0x10` (16) | `Device.hasQCASwitch()` = `hasFirmwareCapability(16)` | The Ports view's projection of `port_table` into the device DTO doesn't happen. Wired-client *ingestion* is gated only on `isSwitch()` (a model-registry property), so clients still appear in the list — but the Ports view stays empty. |
| `fw_caps` | `0x100` (256) | `Device.hasOWRTSwitch()` = `hasFirmwareCapability(256)` | Per-port VLAN assignment is rejected outright — see below. |
| `wifi_caps2` | `0x40` (64) | `Device.supportAdvertisingDeviceNameInBeacon()` = `hasWifiCapability2(64)` | The controller never emits `wireless.<n>.advertise_ap_name` at all, and doesn't even re-push config on the toggle. |

`wifi_caps2` is a **second, entirely separate** bitmask from `wifi_caps` (which gates
`supportBandsteering()`/`supportZeroHandoff()` — openUF sets neither). Only bit `0x40` is
claimed; the mask also gates Mesh MLO, assisted roaming, and quick/neighbour scan, which
openUF does not implement and must not claim.

**The per-port VLAN validator** (`com.ubnt.ace.api.e.VVyiC`, reachable only once
`hasQCASwitch()` is true):

```java
private void chgwykfBxZCAuEHPPQ(UCthhvfQNZ port, boolean hasOWRTSwitch, boolean hasSwitchVlanCap8) {
    nwTNVfYOnNbEWSoCkPq.guoZiIiLhURleoJ(port).ifPresent(forwardMode -> {
        if (!((forwardMode != ALL && forwardMode != CUSTOMIZE) || hasOWRTSwitch)) {
            throw new QnvUxbsXyAJZ(VLAN_TAGGING_UNSUPPORTED, ...);
        }
        if (hasSwitchVlanCap8 && forwardMode NOT IN {CUSTOMIZE, NATIVE, DISABLED}) {
            throw new QnvUxbsXyAJZ(VLAN_TAGGING_UNSUPPORTED, ...);
        }
    });
}
```

For a port with no explicit `forward` override — the default `ALL` mode, true for every port
openUF sends — the first branch collapses to `!hasOWRTSwitch()`. Without bit `0x100`, **every
default-mode port is unconditionally rejected** with `api.err.VlanTaggingUnsupportedByDevice`,
before `vlan_caps` or anything port-specific is consulted. (Sweeping `switch_caps.vlan_caps`
through 0/3/4/5/6/7/15/31/255 only changed *which* of two near-identical errors fired.)
"OpenWrt switch" as opposed to a QCA hardware switch ASIC is, fittingly, exactly what this is.

### `radio_table[]` entry

| Field | Notes |
|---|---|
| `name` | UCI device name (`radio0`) |
| **`radio`** | **The band** (`ng`/`na`), from `band_for_channel()` — channels 1-14 → `ng`, else `na`. Parsed by `com.ubnt.g.f.e.rYtJfMBbtgWvku`'s `String.toLowerCase()` factory, which has **no null guard**: omitting this field throws an NPE inside the controller's adopt processing on *every* inform, corrupting its UI-facing device cache (Devices list shows "No UniFi Devices Have Been Adopted" while Mongo says adopted). 60 GHz/6 GHz aren't disambiguable from channel number alone and are unsupported. |
| `channel` | Live negotiated channel from `iw dev`, more authoritative than UCI's value (frequently the literal `"auto"`, which the controller will not resolve to a number) |
| **`ht`**, **`tx_power`** | Not `htmode`/`txpower` |
| `disabled`, `builtin_antenna`, `builtin_ant_gain`, `max_txpower` | |
| `nss`, `is_11ac`, `is_11ax`, `is_11be`, `has_dfs`, `has_fccdfs`, `has_ht160`, `has_eht240`, `has_eht320` | Read directly off each entry by `PGOcbDWlbnYQdFW`'s `copyAttrsIfPresent`, **independent of `radio_caps`**. Derived by `sysinfo.radio_caps()` from `iw phy phyN info`. |
| **`radio_caps`** | A separate **integer bitmask**, not `nss`. See below. |
| `min_rssi`, `min_rssi_enabled` | `min_rssi` is **dBm** on the wire (converted from the raw `stamgr` units using the live noise floor) |
| **`athstats`** | Nested `{cu_total, cu_self_rx, cu_self_tx, cu_interf}`. See below. |

**An empty `radio_table` blocks a large amount of downstream behavior.** The controller checks
`if (list3.isEmpty()) { … "Missing radio_table in inform…" }` and this is exactly the
"no radio found" condition that suppresses WLAN provisioning. Real OpenWrt hardware has genuine
`wifi-device` sections populated by the driver at boot, independent of any configured SSID.

**`radio_caps` MIMO bits.** The controller's Java side only ever passes this int through
verbatim (`uCthhvfQNZ2.put("radio_caps", uCthhvfQNZ3.getInt("radio_caps", 0))`); the decode into
`"1x1"`…`"4x4"` happens **client-side only**, in the Radios tab's `mimo: e7(radio.radio_caps)`.
Reverse-engineered by calling the live `e7` decoder through the webpack module registry with a
single-bit sweep:

| `nss` | bit |
|---|---|
| 1 | `0x8` |
| 2 | `0x10` |
| 3 | `0x20` |
| 4 | `0x4000000` |

Checked highest-first when multiple bits are set. It is **not** simply `radio_caps == nss`
(live-tested and refuted). Left at the default `0`, the MIMO column is blank *and* the
1x1–4x4 filter checkboxes exclude the radio outright rather than merely filtering it wrong.

**`athstats` is required for the "Avg. Interference"/"Avg. Airtime" columns.** The archiver
method `com.ubnt.service.system.x.htDMji` iterates `radio_table` — not `radio_table_stats`, not
`vap_table` — and:

```java
if (!uCthhvfQNZ.containsField("athstats")) continue;
```

then reads `cu_total`/`cu_self_rx`/`cu_self_tx`/`satisfaction`/`cu_interf` off that nested
sub-object. Sending the same four fields on `radio_table_stats` and `vap_table` (both real, both
used by other paths) leaves every archived bucket without them. Named after the legacy Atheros
`ath9k`/`ath10k` stats struct UniFi firmware historically exposed under this name.

### `radio_table_stats[]` entry

Parallel to `radio_table` — the real controller's own split of static config vs. live stats.

`name`, `channel`, `cu_total`, **`cu_self_rx`**, **`cu_self_tx`** (two separate fields, not one
combined `cu_self`), `cu_interf`, plus `spectrum_table` / `spectrum_table_time` when a
`spectrum-scan` cmd has populated `M._spectrum_cache`.

All `cu_*` are percentages derived from `iw dev <ifname> survey dump`;
`cu_interf = max(0, cu_total − cu_self_rx − cu_self_tx)` — airtime busy for reasons other than
this radio's own tx/rx.

> **`iw` survey field names.** The real binary prints `channel active time:`,
> `channel busy time:`, `channel receive time:`, `channel transmit time:` — *not*
> `channel time:`/`channel time busy:`/etc. Patterns must be anchored to line start so
> `channel busy time:` doesn't also match inside `extension channel busy time:`, which `iw`
> emits on wider channels.

> **The operating channel's entry is not first — pick it by `[in use]`.** `survey dump`
> emits one entry per channel the phy supports, in the phy's own frequency order, so the
> operating channel sits wherever it falls: measured live on 2026-08-02, entry **11 of 13**
> for a 2.4GHz radio on ch11 and **3 of 24** for a 5GHz radio on ch44. Every other entry is
> a scan dwell carrying only a few milliseconds of accumulated time (3–146 ms observed).
> Deriving `cu_*` from `stats[1]` therefore divided a busy figure by a ~3 ms active time and
> reported a genuinely 24%-busy 2.4GHz channel to the controller as **100%**, and a 1.9%-busy
> 5GHz channel as **75%** — which is what made both APs look like they were drowning in
> interference. The same wrong entry also fed the noise floor used to convert Minimum RSSI
> back to dBm. Fixed by flagging `in_use` in `sysinfo.radio_stats()` and selecting it in
> `inform.lua`'s `_in_use_survey()`; the test fixture now mirrors the real ordering, and
> reverting the selection fails 4 tests.

`spectrum_table[]` entries carry `channel`, `center_freq`, `width`, `utilization`,
`interference` (field names recovered from two independent Lombok DTO constant pools).
`channel`/`center_freq`/`utilization` come mechanically from survey dump; `width` and
`interference` are best-effort — see [best-effort fields](#best-effort-and-unverified-fields).

### `vap_table[]` entry

| Field | Notes |
|---|---|
| `name` | UCI section name |
| **`essid`** | Not `ssid` |
| **`id`** and **`wlanconf_id`** | Both carry the wlanconf ObjectId from `aaa.<n>.id`. **Mandatory.** See below. |
| **`radio`** | The **band** (`ng`/`na`), same enum as `radio_table`. Sending `radio0` here logs `WARN stat - unexpected radio[radio0] while processing stats` on every inform and silently drops that vap's stats aggregation. |
| **`radio_name`** | The UCI device name (`radio0`) — a separate, real field on the same DTO. This is what `get_ifname_for_radio()` needs. |
| `encryption`, `disabled`, `bssid`, `channel`, `tx_power`, `usage` | `usage` is `"user"` |
| `num_sta` | Coexists with the nested `sta_table` on the real DTO |
| `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `tx_retries`, `tx_dropped` | The UI's "Air Stats" panel. `iw` exposes these only per-station, so they're summed across connected stations while building `sta_table`. `rx_dropped`/`rx_errors`/`tx_errors`/`satisfaction` have no source in `iw` output at all — left unset rather than invented (802.11 ARQ retry/failure counters are inherently TX-side only). |
| `avg_client_signal` | Mean `signal` of associated clients, dBm. Omitted entirely when the VAP has no clients. |
| `cu_total`, `cu_self_rx`, `cu_self_tx`, `cu_interf` | Mirrored from the radio |
| `sta_table[]` | Nested — see below |

**`id` is mandatory or the entire VAP is discarded.** `com.ubnt.service.devmgr.c.KHUkYjHujLgFBD`
(vapInformProcessor) filters the raw `vap_table` *before* any per-station processing runs. For a
`usage=user` VAP it requires a non-`"unknown"` `id`, then re-looks it up via
`configCache.get(siteId, id)` to attach `wlanconf_id`/`ap_mac`/`site_id`/`is_guest`/`is_wep`.
A missing `id` is checked with `!"unknown".equals(id)` and drops the VAP **silently** —
no log line, no error, taking the nested `sta_table` and every wireless client with it.
The `"Inconsistent vap"`/`"Invalid id"` warn paths only fire on an actual lookup *failure*.

**"Air Stats" needs growing counters, not just non-zero ones.** The widget renders a
rate/delta between informs. Static counters produce a zero delta even when the absolute value
is correct — which is why `iw-mock.sh`'s fake counters must increase monotonically.

### `sta_table[]` entry (nested inside each `vap_table` entry)

Nested, **not** a flat top-level `user_table`.

| Field | Notes |
|---|---|
| `active`, `mac`, `ap_mac`, `channel`, `radio` | `active` is always `true` — an entry only exists while `iw station dump` lists the station |
| `signal`, `rssi` | Both the same value; `iw` exposes no separately-measured RSSI |
| `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets` | **Raw cumulative counters.** The vapInformProcessor computes its own `tx_bytes-d`/`rx_bytes-d`/`bytes-d`/`bytes-r` deltas server-side keyed by `time_delta` — never send a pre-computed rate here. |
| `tx_rate`, `rx_rate` | **Kbps** (`iw` reports Mbit/s, so ×1000) |
| `uptime`, `idletime` | `iw`'s "connected time" / "inactive time", both in seconds |
| **`tx_mcs`**, `rx_mcs` | Not `tx_mcs_index` (that name is only the ucore-message JSON name for a different internal event). Absent for legacy pre-11n rates. |
| `nss` | Read directly by the controller, no derivation |
| `radio_proto` | Read only by the **disconnect-time** archive path (`TtZhv`) |
| **`is_11n`, `is_11ac`, `is_11ax`, `is_11be`** | What the **live** display actually uses — see below |
| `wifi_tx_attempts`, `wifi_tx_retries_percentage` | `attempts = tx_packets + tx_retries` |
| `satisfaction`, `satisfaction_now` | Best-effort estimate — see below |
| `capacity`, `throughput`, `linkscore`, `multicast` | Best-effort / placeholders — see below |
| `name` | Omitted — controller/admin-assigned, no local source |

The attribute list `KHUkYjHujLgFBD` copies verbatim off each incoming entry is exactly:
`"channel", "radio", "name", "signal", "rssi", "tx_rate", "rx_rate", "tx_packets",
"rx_packets", "tx_bytes", "rx_bytes"`.

**Why the `is_11*` booleans matter more than `radio_proto`.** The live, still-connected client
display is computed by `com.ubnt.service.devmgr.HCKpgcBFPLu` → `com.ubnt.g.s.jRsSex`, which
**ignores the `radio_proto` string entirely**:

```java
private static jRsSex lhPagEPcc(UCthhvfQNZ uCthhvfQNZ) {  // 2.4GHz (ng) path
    if (uCthhvfQNZ.is("is_11be", false)) return BE;
    if (uCthhvfQNZ.is("is_11ax", false)) return AX;
    if (uCthhvfQNZ.is("is_11n",  false)) return NG;
    if (uCthhvfQNZ.is("is_11b",  false)) return B;
    return G;   // fallthrough when none are set
}
```

Sending only `radio_proto` leaves every live client showing `"g"` (2.4 GHz) or `"a"` (5 GHz),
while `nss` — read directly, no derivation — works immediately. Both must be sent.

**Generation/NSS derivation** from `iw`'s own bitrate line tokens (format strings confirmed via
`strings /usr/sbin/iw`):

| Token | Generation | NSS |
|---|---|---|
| bare `MCS N` | `n` | `floor(N/8)+1` (HT MCS layout: 0-7 = 1 stream, 8-15 = 2, …) |
| `VHT-MCS` / `VHT-NSS` | `ac` | read directly |
| `HE-MCS` / `HE-NSS` | `ax` | read directly |
| `EHT-MCS` / `EHT-NSS` | `be` | read directly |
| none (legacy) | falls back to the band: `a` on `na`, `g` on `ng` | 1 |

Never `b` — real dual-band 11n+ hardware doesn't negotiate down to 802.11b-only rates.

**`satisfaction` is a device-computed field.** The controller's `wifi_experience_score` is a
straight passthrough — `com.ubnt.service.l.e.AcrQJeJCScLn`:
`wifi_experience_score = doc.getOptionalInt("satisfaction")`. The wireless-client model
(`com.ubnt.service.l.e.AQODNNoMmBlFpWXX`) reads `satisfaction`, `satisfaction_now`,
`satisfaction_real`, `satisfaction_reason`, `wifi_tx_attempts`, `wifi_tx_retries_percentage`,
`tx_mcs`, `ccq`, `noise`, `nss` as **plain data**; the controller computes nothing itself beyond
a running `satisfaction_avg` accumulator. Real AP firmware computes it on-device with a
proprietary formula. Sending nothing renders as "No Experience", correctly.

### `port_table[]` entry

Processed only when `Device.isSwitch()` is true for the reported model —
`hasFeature(UiHQyVmgX) || hasFeature(yojQKHv)`. The model registry
(`com.ubnt.data.dhdeXcHqLRBKMUZk`) registers `U6IW` as device type `uap` with **5 ethernet
ports** and the switch feature, matching reality (a U6-InWall has a built-in 4-port downstream
switch). A plain AP like `U6MP` is not a switch. So for the model openUF impersonates, this is
not optional: an empty `port_table` means zero wired clients can ever appear.

One entry per `cfg.net.ports`. Each entry carries `port_idx` (1-based), `name`, `media`,
`up`, `enable`, `speed`, `full_duplex`, `is_uplink`, `speed_caps`, `port_poe`, `poe_caps`
and `rx_bytes`/`tx_bytes`/`rx_packets`/`tx_packets`/`rx_errors`/`tx_errors`. Where those
facts come from depends on what the board can be asked:

**Per-socket (swconfig board, modelmap field `{idx, swport}`).** One entry per physical
socket. `up`/`speed`/`full_duplex`/`pvid` and the ARL table come from a single
`swconfig dev <sw> show` (`sysinfo.switch_status`), and `is_uplink` is set on the socket the
default gateway's MAC was learned on (`sysinfo.uplink_phys_port`) — detected, never declared,
because on an AP the cable is in whichever LAN socket the installer used. Counters are the
switch's own per-port MIB (`RxGoodByte`/`TxByte`; there are no per-port packet or error
counts, and an AR8327 with `ar8xxx_mib_poll_interval: 0` has no MIB at all), falling back on
the uplink entry only to the CPU netdev's `sysinfo.interfaces()` counters — everything the
CPU sent or received crossed that socket. Other sockets report `0` rather than a fabricated
share of the same total.

The two shapes mix within one board, per port: an entry with no `swport` falls through to
the netdev source below even when the switch answered. That is not a fallback but the right
answer for a socket wired to its own MAC and PHY rather than to the switch — the
TL-WDR3500's WAN socket is a second `ag71xx` surfacing as `eth1`, so sysfs there describes
that socket and not the CPU's link.

**Netdev (no switch, no swconfig, or no identifiable uplink — modelmap field
`{idx, ifname, uplink}`, defaulting to `{wan_cpueth=uplink, lan_cpueth=lan}`).** `up` from
sysfs `carrier`/`operstate`, `speed`/`full_duplex` from sysfs, counters from
`sysinfo.interfaces()`, `is_uplink` from the modelmap. On a swconfig board every one of
those describes the *CPU port* — the internal SoC↔switch link, always 1000/full — which is
why this is the fallback and not the default. Confirmed live: a TL-WDR3500 reported GbE on
an uplink whose socket had negotiated 100baseT, and the gateway's own Ports view said FE for
the same cable.

**On a DSA board the netdev path is not a fallback — it is the right source.** There is no
`swconfig` binary at all, and none is wanted: each socket is its own netdev (`wan`, `lan2`,
`lan3`, `lan4` on a Xiaomi AX3000T — no `lan1`, since DSA names ports from the device tree
rather than the case labels), so sysfs already describes that socket's own cable. The one
thing sysfs cannot say — which socket faces the controller — comes from the bridge instead
of an ARL table: `bridge fdb show br br-lan` names the port each MAC was learned on, and
`sysinfo.uplink_bridge_port` looks up the default gateway's there. Same discipline as the
swconfig path (measured, never declared), different source. Filter on `master` *and*
`permanent`: the port's own address arrives as `<mac> dev wan master br-lan permanent`, a
master line like any other, and counting it puts the AP's own socket MAC in its client list.

Verified live on an AX3000T against a real UCG Ultra: four ports rendered, port 1 flagged
uplink at GbE with no `mac_table`, port 2 at **FE** with its host, port 3 disconnected, port
4 at GbE with its host and the controller's own IP for it. The FE/GbE split is the thing
worth noting — the netdev path reported two different negotiated speeds on one board, which
is exactly what the swconfig CPU-port path could never do.

**Non-uplink ports additionally carry `mac_table[]`** — `{mac, ip, hostname, age, uptime}`,
joined with `/proc/net/arp` for IPs and `/tmp/dhcp.leases` when present for hostnames
(optional — an AP is usually not the DHCP server; `hostname` stays absent rather than
invented). The host list itself is per-socket from the ARL table
(`sysinfo.switch_mac_table`, multicast/broadcast MACs filtered on the address bit), or
`sysinfo.mac_table(ifname)` off `bridge fdb show dev <ifname>` on the netdev path (dynamic
`master br-lan` entries only; `self`/`permanent` and multicast/broadcast filtered).
`bridge fdb` can only ever say "behind the CPU port", so on a switch board it cannot place a
host on a socket — that is what the ARL adds. Sockets whose `pvid` is not the management
VLAN carry no `mac_table` either: the Archer C5's WAN socket is live and has learned a host,
but it sits on VLAN 2 with its CPU port down, so that host is not on the LAN it would be
listed in.

Ports flagged `is_uplink: true` are skipped by the controller for client creation, since that
port faces the controller's own network.

Two exclusion filters prevent double-reporting: the device's **own** MACs, and any MAC
currently associated as a wireless station — a wireless client bridged into `br-lan` genuinely
appears in the bridge FDB too.

**Wired hosts will never show per-client traffic**, by design. `TtZhv` reads only
`mac`/`ip`/`hostname`/`age`/`uptime` off each `mac_table` entry; there is no per-client byte
counter anywhere in the wired-client wire protocol. A wired client's traffic is attributed via
its switch port's own counters.

### `scan_radio_table[]` entry

Backs Insights → AirView → **Environment** (`GET /api/s/default/stat/rogueap`). Built from
`iw dev <ifname> scan dump` — the kernel's already-cached BSS list, cheap and non-disruptive,
unlike the `spectrum-scan` cmd's real scan trigger.

Nested shape (confirmed against `PGOcbDWlbnYQdFW`, which reads a top-level `scan_radio_table`
array and hands each entry's nested `scan_table` to the ingestion service — not a flat list):

```
scan_radio_table[] = { radio, name, scan_table[] }
```

Per `scan_table[]` entry — the consumer DTO `com.ubnt.service.aO.bLwwMKkr` (literally named
`"PeerScan"` in its own builder's `toString`) confirms the full field list:

| Field | Notes |
|---|---|
| `mac`, `bssid`, `essid`, `channel`, `freq`, `signal`, `rssi`, `security` | |
| `radio`, `radio_name` | |
| **`band`** | A field **distinct from `radio`** but taking the identical enum values. The Environment tab's list selector applies an *unconditional* filter upstream of every visible sidebar filter: `A.filter(A=>!!T.R?.[A?.band]?.[A?.bw>0?A.bw:m.L?.[A?.band]])`. `T.R[undefined]` is `undefined`, so an entry without `band` fails silently for every row — indistinguishable from "no data", regardless of filter state. |
| **`bw`** | Channel width MHz. The "Ch. Width" cell reads it directly and renders nothing when falsy: `renderCell:({bw:A})=>A?…:null`. Parsed from `iw`'s `BSS operating channel width: N MHz` (only present for HE/VHT-capable neighbours), defaulting to `20` — legacy-safe and valid on both bands. |
| **`age`** | **Elapsed seconds, not an absolute timestamp.** The ingestion code reads `getInt("age")` and computes `last_seen = report_time − age` itself; it also **silently drops any entry with `age >= 30`** as a staleness guard. Sending an absolute timestamp under either key yields an empty result with no error. Parsed from `iw`'s `last seen: N ms ago`. |

`is_rogue` is much narrower than the tab name suggests: set true only when a neighbouring BSSID
broadcasts the **same essid as one of the site's own configured networks** (an evil-twin check
raising `EVT_AP_DetectRogueAP`). Ordinary neighbours correctly have `is_rogue: false` and still
appear in the Environment list.

### `lldp_table[]` entry

Field names from the real DTO (`OXMua`): `chassis_descr`, `chassis_id`, `local_port_name`,
`local_port_idx`, `is_wired`, `port_id`, `port_descr`.

- `chassis_descr` comes from `chassis.descr`, **not** `chassis.name` — System Description and
  System Name are different LLDP TLVs.
- `local_port_idx` is read from `/sys/class/net/<port>/ifindex` — this is *our own* local
  interface, not something lldpctl reports about the neighbour, so it is a local sysfs lookup
  rather than a protocol field. Omitted when unavailable.
- `is_wired` is unconditionally `true` — LLDP is inherently a wired-link protocol.

### Best-effort and unverified fields

These are explicitly approximations, flagged as such in the code. Listed here so nobody mistakes
them for measured values.

| Field | Status |
|---|---|
| `sta_table[].capacity` | Negotiated `tx_bitrate` (Mbps, floored) as a proxy for "available bandwidth to this client" |
| `sta_table[].throughput` | Delta-sampled byte rate (bytes/sec); `0` on first sample for a given MAC |
| `sta_table[].linkscore`, `.multicast` | `0` placeholders — **no local source and no public reference found for either.** Neither `paultyng/go-unifi`'s `User` model nor `unpoller/unifi`'s `clients.go` has them at all. Still needs live-capture verification. |
| `sta_table[].satisfaction` | `estimate_satisfaction()`: worse of a signal score (−85 dBm → 0, −50 dBm → 100) and a retry score (`100 − retries%`), matching community descriptions of the real behavior. A proxy for Ubiquiti's undocumented on-device formula. |
| `spectrum_table[].width` | The radio's configured `htmode` (e.g. `HT40` → 40) as a uniform approximation — no live-scan source gives per-channel width |
| `spectrum_table[].interference` | Noise-floor dBm passed through; `iw survey dump` has no interference metric of its own. Falls back to the pre-sweep reading for any frequency whose post-scan noise comes back `0` (see [the first real-hardware run](#the-first-real-hardware-run)) |
| `radio_table[].builtin_antenna` = `true`, `.builtin_ant_gain` = `3` (dBi) | **Constants — no software source exists for either.** Not inert: the controller adds the gain to TX power to display EIRP, so a board with different antennas reports a wrong EIRP. Change them in `ucihelper.RADIO_DEFAULTS` if your hardware differs. |
| `radio_caps().has_fccdfs` | Mirrors `has_dfs`; `iw` exposes no separate FCC-DFS indication |
| `radio_caps().has_eht240` / `.has_eht320` | Hardcoded `false` — openUF has no 802.11be target hardware to derive them from |
| `port_table[].media` = `"GE"`, `.enable` = `true`, `.speed_caps` = `0`, `.port_poe` = `false`, `.poe_caps` = `0` | Constants. The PoE ones are honest for every target board (none source PoE); `media`/`speed_caps` are unmodelled. `speed`/`full_duplex`/`up` **are** measured — per physical socket via swconfig where the board has a switch, else from sysfs |
| `port_table[].rx_packets`/`tx_packets`/`rx_errors`/`tx_errors` on a per-socket entry | `0`. swconfig's per-port MIB exposes byte counters only (`RxGoodByte`/`TxByte`), and the CPU netdev's packet/error totals belong to every socket at once. A downstream socket's `rx_bytes`/`tx_bytes` are likewise `0` on a driver with no MIB (AR8327 with polling off) rather than a share of the CPU total |
| `serial` | Derived from the device MAC with the colons stripped — a real AP's serial is a separate factory value openUF has no equivalent of |
| `spectrum_scanning` = `false` | Always false: scans are run synchronously inside the cmd handler, so the device is never "currently scanning" when a payload is built |
| `lldp_table[].is_wired` = `true` | LLDP is inherently a wired-link protocol |
| `model` / `platform` / `version` / `required_version` / `bootrom_version` | The emulated UniFi identity from `ufmodel/*.lua` — deliberately not the host hardware. This is the point of the project, not an accidental approximation |
| `fw_caps` = `0x110`, `wifi_caps2` = `0x40` | Claimed capability bits, each derived from the controller's own bytecode and confirmed live — see [Capability bitmasks](#capability-bitmasks). openUF claims only bits whose features it actually implements |
| `ucihelper` `wps_device_name` / `ap_setup_locked` | Standards-based rather than Ubiquiti-derived — see the beacon row in the [feature matrix](#feature-matrix) |
| `usteer.lua`'s `USTEER_DEFAULTS` | Guessed `/etc/config/usteer` option names; verify against the package's own shipped defaults if usteer is ever installed in the validation container |

Everything not listed above is measured from the running system. Several fields
*used* to belong in this table and no longer do — `max_txpower`, `tx_power`,
`nss`, per-client `signal`, `hostname`, and `port_table[].speed`/`full_duplex`
were all constants or misparsed values until the first real-hardware run
surfaced them; they are now read from `iw`, sysfs and `/proc`.

### WPA3 was silently downgraded to WPA2 — the radio must claim the SAE bit — FIXED

Before `radio_caps2` was sent (see below), a WLAN set to **WPA2/WPA3** in the UI
reached openUF as plain WPA2, and nothing anywhere said so. The captured
`system_cfg` contained no `sae`, no `wpa3`, just:

```
aaa.1.wpa=2
aaa.1.wpa.key.1.mgmt=WPA-PSK
aaa.1.pmf.status=enabled     aaa.1.pmf.mode=1
```

openUF applies that faithfully, so hostapd runs
`wpa_key_mgmt=WPA-PSK FT-PSK WPA-PSK-SHA256` and every client — WPA3-capable
ones included — associates with AKM `00-0f-ac-2`/`-4`/`-6`. Never `00-0f-ac-8`
(SAE).

This is **not** the controller's WLAN being misconfigured. Its REST API confirms
the wlanconf really does carry `wpa3_support: true`, `wpa3_transition: true`.
The downgrade is per device, in `com.ubnt.service.config.ubntconf.QSAkfnbfInKJ`:

```java
if (wlanconf.isWpa3()) {                      // wlanconf field wpa3_support
    if (!radio.CVir()) {                      // radio lacks the SAE capability
        if (wlanconf.isWpa3LegacyEnabled())   // wlanconf field wpa3_transition
            return downgrade(wlanconf, radio);          // ← silent WPA2
        log.warn("SAE cannot provision {} to {}", name, mac);
        return null;                                     // WLAN dropped entirely
    }
```

So a **transition-mode** WLAN degrades quietly, while a **WPA3-only** WLAN would
be dropped from the device altogether with that one server-side log line.

`CVir()` tests **bit `0x1` of `radio_caps2`** — see the next section for the
field-level trace. openUF used to send `radio_caps` (the MIMO column:
`0x8`/`0x10`/`0x20`/`0x4000000` for 1x1…4x4) and **no `radio_caps2` at all**, so
the bit was clear and every WPA3 WLAN was downgraded on every openUF device.
That is fixed: `radio_caps2 = 0x1` now ships on each SAE-capable radio.

The emission side is gated separately, on the WLAN alone
(`com.ubnt.service.config.j.rYtJfMBbtgWvku`: `isWpa3() || band == 6E`), and
produces `wpa3.support=enabled` + `wpa3.transition=enabled|disabled` — the keys
openUF's `_parse_wifi_system_cfg` would need to read, since **SAE never arrives
as a `wpa.key.<n>.mgmt` value**. `SECURITY_MAP`'s `wpa3` → `sae` and
`wpa2/wpa3` → `sae-mixed` entries were unreachable for exactly as long as the
capability bit was missing; both are now exercised on real hardware. (An earlier note in this document read the
PMF keys as the controller's way of signalling WPA3-mixed for a madwifi-driver
model. That was wrong — PMF is just PMF, and the real signal is these two keys.)

### The capability is `radio_caps2` bit `0x1` — RESOLVED

`CVir()` is a bit test, and tracing which field backs it settles the whole
question. The chain, all from the 10.4.57 bytecode:

```
config gen (QSAkfnbfInKJ)   calls radio.CVir()
CVir()                      = (1 & ZPjpXpgFhJSgqk().orElse(0)) == 1
ZPjpXpgFhJSgqk()            -> impl field iBjnA          (com.ubnt.g.f.e.jRsSex)
iBjnA                       <- builder field SuUD
SuUD                        <- setter rMxwXnPhhdotvjERKoA(int)
that setter is called with  getInt("radio_caps2")        ← the wire field
```

`radio_caps` lands somewhere else entirely — builder `kJeOrfqt` → impl
`DbisCuTqoItCGd` → accessor `FJaWnIAautY()`, which is the MIMO column and
nothing more. **The two capability integers are not interchangeable, and the one
that gates WPA3 is the one openUF never sent.** It arrived as `0` on every
inform (the parser's `getInt` default), `0` fails the bit test, and so every
WPA3 WLAN was silently downgraded on every openUF device.

**Confirmed live end-to-end, 2026-08-01, real hardware.** Sending
`radio_caps2 = 0x1` (gated on `sysinfo.sae_supported()`) flipped the very next
config push:

```
aaa.1.wpa.key.1.mgmt=SAE          (was WPA-PSK)
aaa.1.wpa3.support=enabled
aaa.1.wpa3.transition=enabled
aaa.1.wpa3.ft.status=disabled
aaa.1.sae.anti_clogging=5   aaa.1.sae.sync=5
```

and both APs came up controller-driven, no manual step:

```
UCI:     encryption='sae-mixed'  ieee80211w='1'  ieee80211r='1'
         sae_sync='5'  sae_anti_clogging_threshold='5'
hostapd: wpa_key_mgmt = SAE FT-SAE WPA-PSK WPA-PSK-SHA256 FT-PSK
```

Note the push also carries `wpa3.ft.status=disabled` alongside `ft.status=enabled`
— the exact disagreement case described in the [`aaa.<n>` table](#aaan--per-ssid-security-and-behavior).

#### What was wrong before, and why

Three earlier claims in this document are now retracted:

1. *"`wpa3_supported` is the gate."* It is not read at all — see below.
2. *"`radio_caps`/`radio_caps2` bit `0x1` were both set live with no effect."*
   The conclusion was wrong. Whatever that experiment actually set, sending
   `radio_caps2 = 0x1` from the radio-table builder works reproducibly on both
   APs. Suspected cause: the config was never regenerated, so no push followed
   — a device-state change alone does not trigger one. Clearing the stored
   `cfgversion` and restarting forces a full push, which is how this was tested.
3. *"The capability comes from the controller's model registry, so no payload
   field can unlock WPA3."* The model registry exists —
   `getModel().radiosByBand().getOrDefault(band, EMPTY_DEVICE_MODEL_RADIO)`,
   with the U6-InWall's entry mapping `BAND_NA→2400`, `BAND_NG→570` — but it
   returns `com.ubnt.g.f.VVyiC`, a **different type** from the device radio DTO
   `com.ubnt.g.f.e.VVyiC` that `CVir()` is invoked on. It is not on this path.
   Checking the receiver type is what broke the deadlock.

`wpa3_supported` genuinely is inert, and that part stands: the only class
carrying the literal (`com.ubnt.net.k.aI.jRsSex`, a record of `wpa3Supported` /
`band6GHzSupported` / `oweSupported`) is **constructed, never parsed** — built
from an injected `com.ubnt.service.wifi` service, ignoring the device parameter
— and reading the persisted device back confirms it: `radio_caps` round-trips
verbatim while `wpa3_supported` and `owe_supported` come back `undefined`.
openUF still sends it, because it is truthful and another version may read it,
but it unlocks nothing.

### What a transition-mode push looks like

Reconstructed from the emitters rather than captured, since no openUF device can
provoke one. Two classes produce it — `com.ubnt.service.config.eWivisHeQsnaqDtx`
for the WLAN block (prefix recipe `aaa.`, so keys are `aaa.<idx>.…`) and
`com.ubnt.service.config.ubntconf.OXMua` for the SAE sub-block — both behind the
same gate, `com.ubnt.service.config.j.rYtJfMBbtgWvku`:
**`isWpa3() || radioBand == 6E`** (that second clause is why 6 GHz always gets
WPA3). The key-mgmt method in full:

```java
String mgmt = "WPA-PSK";
if (gate(wlan)) {
    mgmt = "SAE";                       // replaces — never appended
    OXMua.emit(sb, wlan, "aaa." + i);   // the sae.* / wpa3.ft.status block
}
emit("aaa." + i, "wpa.key.1.mgmt", mgmt, "wpa.psk", wlan.getWpaPreSharedKey());
```

For a WPA2/WPA3 WLAN with PMF Optional and 802.11r on, that yields:

```
aaa.1.wpa=2                       # stays 2 — WPA3 never makes this 3
aaa.1.wpa.1.pairwise=CCMP         # the legacy flag is inverted under WPA3, so never "TKIP CCMP"
aaa.1.wpa.key.1.mgmt=SAE          # replaces WPA-PSK; both never appear together
aaa.1.wpa.psk=<psk>
aaa.1.wpa3.support=enabled
aaa.1.wpa3.transition=enabled     # "disabled" here means WPA3-only
aaa.1.wpa3.ft.status=enabled
aaa.1.pmf.status=enabled  aaa.1.pmf.mode=1  aaa.1.pmf.cipher=<cipher>
aaa.1.ft.status=enabled
```

plus, only when the site actually sets them: `sae.anti_clogging` / `sae.sync`
(each when > 0), `sae.groups.<n>.group` with `sae.has_groups=enabled` (from
`sae_groups`), `sae.psk.<n>.psk`/`.mac`/`.id`/`.vlan` (SAE private PSKs), and
`wpa3.enhanced_192=enabled` for EAP with Enhanced 192-bit.

**The structural trap:** `SAE` *replaces* `WPA-PSK` — the wire never carries
both, so the AKM set alone cannot distinguish transition mode from WPA3-only.
Only `wpa3.transition` does. Reading the AKM by itself provisions a mixed WLAN
as pure WPA3 and locks out every WPA2 client.

### The device side works — verified end-to-end

With the capability bit in place the controller sends transition mode of its own
accord, and openUF provisions it correctly on real hardware:

```
UCI:     encryption='sae-mixed'
hostapd: wpa_key_mgmt = SAE FT-SAE WPA-PSK WPA-PSK-SHA256 FT-PSK
         sae_require_mfp=1  sae_pwe=2  sae_groups=19 20 21
```

Live clients then split exactly as transition mode intends — a Pixel 9
negotiated `00-0f-ac-9` (FT-SAE) while older devices stayed on `00-0f-ac-2`
(WPA2-PSK) on the same SSID.

`wpad-mbedtls`, OpenWrt 25.12's ath79 default, does support SAE
(`sae_password`, `sae_groups`, `psk-sae` in `ap.uc`), so claiming it is honest
on that hardware.

### Fixtures must be verbatim command output

Three of the bugs found on real hardware were invisible to a green test suite
because the fixtures under `tests/fixtures/` were *tidier than reality*:

- `iw_station_dump.txt` had no `avg ack signal:` lines, so nothing caught an
  unanchored `signal:` pattern matching them and reporting every client at the
  ack value instead of its RSSI.
- `iw_phy_info_*.txt` carried an `HT TX Max spatial streams:` line that real
  ath9k/ath10k never emit, hiding that an HT-only radio has no source for `nss`
  at all and always fell back to 1x1.
- `iw_dev_info.txt` omitted the `ssid` and `multicast TXQ` blocks real output
  carries.

A fixture is a *recording*, not an illustration: paste real output from a real
device, including the lines that look irrelevant. The ones that look irrelevant
are exactly where unanchored patterns go wrong.

---

## Feature matrix

Every controller-UI control exercised against a live openUF device. "Confirmed" means driven
through the real UI with the resulting wire payload captured or the effect verified.

| # | Control / feature | Wire mechanism | Status |
|---|---|---|---|
| 1 | Adopt (L2/SSH, L3/mgmt_cfg) | SSH `syswrapper.sh set-adopt`, or `authkey` in `mgmt_cfg` | ✅ Confirmed both paths |
| 2 | Baseline post-adopt inform | `setparam` + `mgmt_cfg` | ✅ Confirmed |
| 3 | SSID push (no VLAN) | `system_cfg` `aaa.*`/`wireless.*`/`radio.*` | ✅ Confirmed |
| 4 | VLAN-tagged network + SSID assignment | `aaa.<n>.br.devname = br0.<vlan>` | ✅ Confirmed. The switch trunk carries the CPU port and the uplink socket only — tagging the LAN sockets deafens untagged wired clients on `ar8216`-family switches, where the tag flag is one global per-port bitmask |
| 5 | Fast Roaming (802.11r) | `aaa.<n>.ft.status` only | ✅ Confirmed by byte-for-byte `system_cfg` diff, both directions |
| 6 | TX power / channel per radio | `radio.<n>.channel`/`.txpower`/`.txpower_mode` | ✅ Confirmed |
| 7 | Locate | `cmd:"set-locate"` | ✅ Confirmed, including the **LED hardware effect on a real board** (Archer C5, `dev.conf.led = "green:system"`): `locate_start` writes `trigger=timer` + 250/250 ms, `locate_stop` restores `trigger=none`, and the Manage → LED toggle drives `brightness` 1/0 |
| 8 | RF/spectrum scan trigger | `cmd:"spectrum-scan"` | ✅ Handler exercised **against real radios** — 27 channels on 5 GHz, 13 on 2.4 GHz, with genuine per-channel utilization and noise. Still **no manual trigger control exists anywhere in 10.4.57's UI** (AirView is passive), so it has never been fired *by the controller*; the handler was invoked directly on the device. |
| 9 | Firmware upgrade | `_type:"upgrade"` | ✅ Confirmed. openUF stores `upgrade_requested_version`/`_url` and logs — it never downloads, verifies, flashes, or reboots. Verified live: no side effects, device stayed Connected. The pushed `md5sum`/filename match Ubiquiti's real CDN artifact byte-for-byte. |
| 10 | Forget device / factory reset | `_type:"setdefault"` | ⚠️ UI action and server-side deletion work, but **no `setdefault` was ever dispatched on the wire**; handler unverified. See [open questions](#open-questions). |
| 11 | `fw.ver` acceptance | — | ✅ Accepted verbatim, no validation beyond storage |
| 12 | Restart | `_type:"reboot"` (top-level, **not** `cmd:"restart"`) | ✅ Confirmed; real container reboot observed |
| 13 | Manage LED on/off | `mgmt_cfg` `led_enabled` | ✅ Confirmed both values live. `led.set_enabled()` uses `trigger=none` + `brightness=1/0`, distinct from the locate blink's timer trigger. |
| 14 | IP Settings (DHCP/Static) | `system_cfg` `netconf.*`/`dhcpc.*`/`route.*` | ✅ Confirmed end-to-end: real kernel interface change, real route, informing from the new address, controller Overview reflecting it back |
| 15 | Power / PoE | `power_source`, `power_source_voltage`, `psu_table`, `power-monitor`, `total_max_power`, `led_state`, `outlet_table` — copied straight off the inform when present | 🔍 Not implemented. The "Power: -" element lives in the **Parent Device** subsection (properties of the upstream LLDP-linked switch), and this environment has no PoE switch. Field names confirmed; values/format not researched, and openUF has no local signal for a real PoE class. |
| 16 | Set Replacement Device / Load Configuration | **None** — controller-side Mongo document clone (`commonDeviceCloneConfigService`), then an ordinary adopt + `setparam` | ✅ Both confirmed live; zero product code needed. Replacement auto-adopts the target ~50 s after the source goes away. |
| 17 | Wired clients | `port_table[]` + per-port `mac_table[]` | ✅ Confirmed live: both fake hosts under Connection → Wired, on the correct port; Ports view renders them. Hosts are placed on the physical socket the switch learned them on (ARL table) as of 2026-08-02 — before that, real wired clients behind an AP were reported by nobody and the controller credited them to the gateway's port |
| 18 | Per-port VLAN assignment | `fw_caps` bit `0x100`; controller pushes `switch.*` | ⚠️ Wire format fully mapped live 2026-07-19 (gate, per-VLAN table, per-port `pvid` + tagged/untagged/exclude matrix, teardown). The **controller side** is confirmed — it accepts the assignment and pushes an actionable table. Device-side apply is swconfig-only and unverifiable here (the validation AP has no switch). Note it was unreachable on both real boards until 2026-08-02: the only port they reported was the uplink, which is exactly the port that must never be reassigned |
| 19 | Client block / unblock | `cmd:"block-sta"` / `"unblock-sta"` | ✅ Confirmed live including real nftables enforcement and survival across a simulated reboot. `hostapd_cli` deauth is unit-tested only (no real hostapd here). |
| 20 | Environment / rogue-AP scan | `scan_radio_table[]` | ✅ openUF's payload and the controller's ingestion both confirmed correct (10/10 direct API polls). The tab's own display bug is [controller-side](#controller-side-ui-quirks). |
| 21 | Radios tab + client MIMO/generation | `radio_table` capability fields; per-station `nss`/`is_11*` | ✅ Confirmed live on four stations spanning HT/VHT/HE/legacy |
| 22 | Radios tab Avg. Signal / Interference / Airtime / MIMO | `vap_table.avg_client_signal`; `radio_table.athstats`; `radio_table.radio_caps` | ✅ All four confirmed live on a fresh reset (`-64`/`-50 dBm`, `3%`, `7%`, `2x2`), with bidirectional filter behavior verified |
| 23 | Minimum RSSI | `system_cfg` `stamgr.<n>.*`; outbound `min_rssi`/`min_rssi_enabled` | ✅ Wire format and field names confirmed. Enforcement (`kick_station`) is unit-tested only — no real radios here. |
| 24 | Security tab WPA2/WPA3 protocol options | **None** | ℹ️ Not capability-driven from anything openUF sends. No security-capability field exists in the payload; `ucihelper`'s `SECURITY_MAP` (`wpa2`→`psk2`, `wpa3`→`sae`, `wpa2/wpa3`→`sae-mixed`, `wpa-enterprise`→`wpa2+ccmp`) is a one-way map of a choice the controller has already made. The dropdown's options come from the controller's own internal per-model database, keyed on the reported `model`/`platform`. Not fixable here. |
| 25 | Band Steering / BSS Transition / DTIM | `wireless.<n>.no2ghz_oui` / `aaa.<n>.bss_transition` / `wireless.<n>.dtim_period` | ✅ All three confirmed live by individual before/after `system_cfg` diffs |
| 26 | Show AP Name in Beacon | `wifi_caps2` bit `0x40` → `wireless.<n>.advertise_ap_name` | ✅ Wire protocol and capability gating confirmed live, both directions. **The OpenWrt/hostapd side is not verified** — implemented via the WPS/WSC Device Name attribute (`wps_device_name` + `ap_setup_locked=1`, the standard mechanism, per hostapd's README-WPS/`beacon.c` and OpenWrt's wifi-iface schema) rather than an unknown Ubiquiti vendor IE. Needs real hardware to confirm hostapd accepts it and the beacon changes. |
| 27 | SAE Anti-clogging / Sync Time | `aaa.<n>.sae.anti_clogging` / `.sae.sync` | ⚠️ Key names, integer shape, and `isWpa3()` gating confirmed via an unambiguous decompiled method body. The **emitting** (true WPA3) case could not be live-diffed — forcing pure WPA3 tripped the [config-sync issue](#config-sync-can-get-stuck-after-informs-stabilise). |
| 28 | PMF (802.11w) / Multicast Enhancement | `aaa.<n>.pmf.status`/`.pmf.mode`; `wireless.<n>.mcast.enhance` | ✅ Confirmed live by `system_cfg` diff. PMF is what actually carries WPA2/WPA3 transition intent on this model. |
| 29 | Channel width | `radio.<n>.ieee_mode` → `wifi-device.htmode` | ✅ Confirmed live both directions: `11nght20`↔`11nght40` follows the per-AP 2.4 GHz Channel Width control, and the pushed value reaches UCI (`radio0` `HT20`, `radio1` `HT40`). Previously parsed by nothing, so width never applied. |
| 30 | IoT Optimization: Lock 2.4 GHz to Channel 6 | `radio.<n>.channel` (no dedicated key) | ✅ Confirmed live end-to-end: the toggle changes the 2.4 GHz radio's `channel` from `auto` to `6`, and UCI `radio0.channel` follows (verified 11 → 6, so it is not a coincidence of the default). |
| 31 | IoT Optimization: DTIM Interval Lock | `wireless.<n>.dtim_period` (no dedicated key) | ✅ Confirmed live end-to-end: pins the 2.4 GHz vap's `dtim_period` to `3` (REST `iot_dtim_lock` → `dtim_ng: 3`), which reaches UCI. |
| 32 | IoT Optimization: Force WiFi 4 Mode | `wireless.<n>.iot` + `wireless.<n>.qbssload` | ✅ Wire signature confirmed live by before/after diff, and both keys now reach UCI (`openuf_iot=1`, `bss_load_update_period=0`). **The hostapd side of `bss_load_update_period` is not verified on real hardware** — it is hostapd's own option name (0 suppresses the QBSS Load IE), assumed to pass through OpenWrt's wifi-iface schema. The rest of the mode is carried by keys openUF already applied. |
| 33 | Proxy ARP / Client Isolation | `aaa.<n>.proxy_arp` / `wireless.<n>.l2_isolation` | ✅ Confirmed live 2026-07-18 by REST-toggling `wlanconf.proxy_arp` + `l2_isolation` and diffing `system_cfg`: exactly these two keys flipped `disabled`→`enabled`, on **both** the 2.4 GHz and 5 GHz entries of the WLAN, nothing else moved. Both are always present on their block, so "off" is explicit. `proxy_arp` had been visible in the Force WiFi 4 Mode diff all along but was never parsed. |
| 34 | Minimum Data Rate Control | `wireless.<n>.minrate_data` (+ `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status`, `minrate_below_disable`, `pureg`) | ✅ Confirmed live 2026-07-18 by REST-setting `minrate_setting_preference=manual` + `minrate_ng_data_rate_kbps=12000` and diffing: `minrate_data`/`beacon_rate`/`mgmt_rate` 1000→12000, `minrate_cck_rates.status` true→false, `pureg` 0→1. Separately confirmed **not band-gated** — enabling `minrate_na` (24 Mbps) made the same keys appear on the 5 GHz entries. **The OpenWrt side is radio-level**, not per-BSS (verified in OpenWrt's `hostapd.sh`: these are `hostapd_common_add_device_config` options), so openUF aggregates a radio's VAPs to the most permissive floor. Note `beacon_rate` is passed to hostapd **verbatim in 100-kbps units** while `basic_rate`/`supported_rates` are divided by 100 by `hostapd_add_rate` — openUF converts only the former. Not verified on real hardware. |
| 35 | Multicast and Broadcast Blocker | `wireless.<n>.bcfilt.status` + `bcfilt.<k>.mac`/`.status` | ✅ Wire format confirmed live 2026-07-18 across four diffs (on with one MAC, with two MACs, on with an empty list, off). Two keys already on the wire were **excluded** as candidates by the same diffs: `radio.<n>.bcmc_l2_filter.status` (sits at `enabled` with the control off) and `wireless.<n>.multicast.inspect` — neither moved. ✅ Enforcement confirmed on real hardware 2026-09-02 (AX3000T, nftables 1.1.6, kernel 6.12), measured with counter-only probe rules carrying the same predicate: broadcast sourced onto the VLAN from a second AP and flooded out the IoT VAP matched the drop rule **14 of 14** times with that sender absent from the allow-list, and **0 of 15** times after adding it through the controller — both halves of the control, and the `bcfilt.<k>.mac` parse, end to end. ⚠️ Requires `kmod-nft-bridge`: the drop rule is openUF's only bridge-family `meta` match, `nft_meta_bridge` is absent from stock filogic and ath79 images alike, and without it the kernel returns a bare `Could not process rule: No such file or directory` **only for that rule** — table, chain and allow-list set all build, so the control appeared enabled everywhere while filtering nothing. `firewall.lua`'s block-sta matches on `ether saddr` alone, needs no module, and worked throughout, which is what hid this. |
| 36 | Hide WiFi Name | `wireless.<n>.hide_ssid` (+ duplicate `aaa.<n>.hide_ssid`) | ✅ Confirmed live 2026-07-18 by toggling the control in the UI and diffing `system_cfg`: exactly those two keys flipped `false`→`true`, on both band entries of the WLAN, nothing else moved. Always present, so "off" is explicit and is written back out as `hidden=0`. Note the `true`/`false` vocabulary rather than `enabled`/`disabled`. Previously **documented in USAGE.md as already applied, but no code read or wrote it** — the same doc-vs-code drift as `use_only_unifi_wlan`. |
| 37 | MAC Address Filter | top-level `macacl.<m>.*`, joined on `wireless.<n>.devname` | ✅ Confirmed live 2026-07-18 by enabling the control with one allow-listed MAC and diffing `system_cfg`: the whole `macacl` section appeared at once, keyed by devname (`ath0`/`ath2`) and numbered independently of `wireless.<n>`, so **the devname join is mandatory**. Two keys already on the wire were **excluded** by the same diff: `wireless.<n>.mac_acl.status`/`.policy` (sit at `enabled`/`deny` with the control off) and `aaa.<n>.radius.macacl.status` (the separate RADIUS MAC Authentication control). → OpenWrt `macfilter` + `maclist`, whose allow/deny vocabulary matches the controller's 1:1. Enforced by hostapd itself, so no openUF-side ruleset is involved. |
| 38 | WiFi Speed Limit | top-level `qos.vap.<m>.*`, joined on `wireless.<n>.devname` | ✅ Wire format confirmed live 2026-07-18 by creating a speed-limit profile (33/17 Mbps) and assigning it to a WLAN. Values are **kbps**, and the discriminator is the presence of `maxspeed` — an unlimited vap still gets a block, carrying only `minspeed` set to its raw `devspeed`. The cap is a **per-VAP aggregate**, not per-client. Requires a profile to exist before the per-WLAN toggle does anything. ⚠️ Enforcement is openUF's own `tc` ruleset (`shaper.lua`), since no hostapd/OpenWrt option expresses a throughput cap: HTB on egress for downlink, ingress policing for uplink. Every generated command is verified against real tc (iproute2 6.9.0), but the on-air throughput is unverified (no real radios). |

---

## Open questions

- **`setdefault` is never dispatched.** Clicking Remove deletes the device server-side and
  flips the UI to "ready to adopt", but no `setdefault` reaches the wire and `state.json` keeps
  `adopted: true` with the old authkey. Whether a real `setdefault` is sent under different
  circumstances (e.g. only over SSH for L2-discovered devices, mirroring how initial adopt
  differs by discovery method) is unconfirmed. openUF's handler is untested but there is no
  evidence it is wrong.
- **`linkscore` and `multicast`** have no known source or reference; currently `0`. Needs a
  live capture from real hardware.
- **`bootrom_version`** has no counterpart in the device schema. Probably ignored.
- **The `spectrum-scan` cmd handler** has never received a real controller-issued command.
- **openUF's `usteer` config option names** are unverified against the real package.
- **hostapd's acceptance of `wps_device_name`/`ap_setup_locked`** needs real hardware.
- **PoE self-reporting** could be reopened if the validation environment ever gains a real
  switch container, or if a non-Parent-Device UI surface for those fields is found.

---

## Dead ends — do not re-attempt

- **Extracting the AP→controller protocol from U6-InWall firmware.** The official image
  (`v6.8.2+15592`, pulled from `fw-update.ubnt.com`, md5
  `0fec04452cadd2d025777d36ab2974ea`) is a **kernel-only OTA delta**. Its GPT has 5 partitions
  of which only `HLOS` has data; there is no system/rootfs/application partition at all.
  `HLOS.img` is at flat 8.0 bits/byte entropy across ~95% of the file (computed per-1MB block,
  not eyeballed from a binwalk graph), with no compression magic and zero `strings` hits for a
  kernel banner, driver names, or any of `scan`/`spectrum`/`rssi`/`noise`/`channel`/`bssid`.
  Only the last ~1.3 MB is plaintext, and that is device-tree blobs. The inform-client binary
  simply is not in this artifact. Untried alternatives if this ever matters: a pre-2023 build
  that might predate encrypted/kernel-only packaging; pulling the binary off a live owned
  device over SSH; or a LAN packet capture between real hardware and a real controller.
- **Chasing `wait_for_initial_inform` as a thing in itself.** It is downstream of
  [the GCM gate](#the-gcm-provisioning-gate). Editing it in Mongo does nothing (the process
  never re-reads), and restarting the controller to force a reload introduces a separate
  "Offline" artifact.
- **Looking for a manual RF-scan trigger in 10.4.57's UI.** There isn't one — AirView is fed
  entirely by passive, continuously-collected stats. Settings search for "spectrum" returns
  nothing, and no `_type:"cmd"` arrives on its own while the page is open.
- **`strings` on concatenated Java class files on macOS.** `0xCAFEBABE` is both the Java class
  magic and the Mach-O fat-binary magic, so macOS `strings` chokes. Extract printable-ASCII
  runs in Python instead.
- **Deleting a stale wireless client record and waiting for it to reappear.** The pattern works
  for wired clients but wireless ones never came back (45+ s). Recreate the WLAN instead.
