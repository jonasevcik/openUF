# Protocol validation findings

openUF's assumptions about the UniFi inform protocol were originally inferred from
third-party reference material — [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway)
and [paultyng/go-unifi](https://github.com/paultyng/go-unifi) — and never checked against a
real UniFi Network Application. This document is the project's own ground truth: how each
claim was established, what the environments can and cannot show, which findings cost real
debugging time, and what is still open.

**The wire format itself lives in [docs/WIRE-REFERENCE.md](docs/WIRE-REFERENCE.md)** — the
envelope, the response `_type`s, every `system_cfg` key and every outbound field. This
document is the evidence log beside it. Neither is a lab journal: superseded hypotheses and
the trails that produced a fact are removed, and git history has them.

Captures come from the device's own `debug_dump_file` (see
[USAGE.md](USAGE.md#3-configuration)), which holds inbound responses, from the controller's
Mongo/REST state, and from decompiling the controller's Java bytecode and React bundles.

**Where things live.** Sections that moved to the wire reference, with the names code
comments cite them by:

| Looking for | Now in |
|---|---|
| Envelope, GCM gate, L2 vs L3 adoption, Discovery requests, Response _types, the cmd list, blocked_sta, Guest portal, the walled garden, STA_ASSOC_TRACKER, Roam reports | WIRE-REFERENCE § The inform protocol |
| `aaa.<n>.*`, `radius.*`, `hs20.*`, `wireless.<n>.*`, `radio.<n>.*`, `stamgr.<n>.*`, schedules, `btm_disassoc`, `macacl.*`, `qos.*`, `netconf.*`, `switch.*`, `ebtables.*`, system settings, `connectivity.*` | WIRE-REFERENCE § `system_cfg` |
| Top-level fields, Capability bitmasks, `radio_table`, `radio_table_stats`, Airtime Scan, `vap_table`, `sta_table`, satisfaction, STUN, `port_table`, `scan_radio_table`, 802.11k, `lldp_table`, best-effort fields, WPA3/SAE | WIRE-REFERENCE § Outbound payload field reference |

**Environments.**

- **Docker lab** (`tools/validation/`): `lscr.io/linuxserver/unifi-network-application`
  pinned to the version the home gateway runs (10.6.106 today; 10.4.57 for the older
  captures), with openUF as the AP in a disposable Alpine container on the same Docker
  network. Mocked `uci`/`ubus`, no radios.
- **Real hardware:** a TP-Link Archer C5 v1 (OpenWrt 25.12.x, ath79/mips_24kc, ath9k 2.4 GHz
  + ath10k 5 GHz) and a Xiaomi Mi Router AX3000T (mediatek/filogic MT7981, DSA), both adopted
  by a **UniFi Cloud Gateway Ultra**. Only radios, hostapd, regdomains and switch ASICs can be
  settled here.
- **UAP firmware:** every plaintext MIPS/QCA956x build (BZ2 3.9.27 to 4.3.28, U7LR/U7PG2
  6.8.2), extracted with `tools/fw-extract.sh`. The ARM64 U6/U7 images, including the U6-IW
  openUF impersonates, stay opaque — a claim read from a MIPS build is labelled with that
  build and is not generalised to Wi-Fi 6/7 APs.

**Status:** adoption, provisioning and every UI-surfaced feature in the
[feature matrix](#feature-matrix) are confirmed working end-to-end against a real controller,
except where a row says otherwise. Adoption, the WiFi config push, live clients and the radios
themselves are additionally confirmed on real hardware.

---

## Validation environment

Everything in this section is about `tools/validation/`, not about openUF's product code. Real
OpenWrt target hardware has genuine `uci`/`iw`/`ubus`/`hostapd` and hits none of it.

### Required setup, in order

1. **`lua-openssl` must be present in the AP container.** Without an AES-GCM backend the
   controller will never provision the device (see the GCM provisioning gate in the wire
   reference). `tools/validation/ap/Dockerfile` builds the `zhaozg/lua-openssl` rock
   (`luarocks-5.1 install openssl`); no prebuilt Alpine apk exists. `install.sh` already
   installs `lua-openssl` on real OpenWrt hardware.
2. **Set the Inform Host Override before adopting anything.** Devices → Device Updates and
   Settings → Device SSH Settings. It must be the controller container's **literal IP** — a
   bare hostname is rejected with `ERROR inform - dev[<mac>] invalid inform_ip <hostname>`.
   This setting lives in the controller's own DB and is wiped by every `docker compose down -v`.
3. **Set a Device SSH Authentication password** (≥ 12 characters, enforced by the controller's
   own validator). Needed for L2/SSH adoption.

Skipping (2) presents as adoption silently stalling: `state.json` never flips `adopted: true`
and `server.log` logs `inform decryption failed with defaultAuthKey=false` — the controller
*did* issue a per-device key, but the device never received a usable config push. A setup
omission, not a bug.

### Always reset fully; never patch live state

Validation runs start from `docker compose down -v && docker compose up -d --build`.
Hand-editing a running container's `state.json`, or a device doc in Mongo, produces results
that do not reproduce — see [the minidev cache](#the-minidev-cache-never-sees-external-writes).

### The mocks, and their one sharp edge

The Alpine container has no `uci`, `ubus`, `iw`, `bridge` or `hostapd`. Four validation-only
shims stand in, all outside `openuf/`:

| Shim | Stands in for | Notes |
|---|---|---|
| `ap/uci-mock.lua` | `require("uci")` | Installed at `/usr/local/share/lua/5.1/uci.lua`. Seeded with `radio0`/`radio1` `wifi-device` sections matching `generic-dualband-ap.lua`'s `hwassign`. |
| `ap/ubus-mock.sh` | `ubus call network.wireless status` | Static `radio0`→`wlan0`, `radio1`→`wlan1` map. |
| `ap/iw-mock.sh` | `iw dev … survey/station/scan dump` | Three fake stations with independently growing counters, plus fake neighbour BSSes. |
| `ap/bridge-mock.sh` | `bridge fdb show` | Two fake wired hosts; `entrypoint.sh` seeds `/proc/net/arp` via `ip neigh replace` (kernel state can't be baked into an image layer). |

**`uci-mock.lua` is in-memory only, per process.** Its `db` table is seeded fresh at process
start and only ever one-way dumped to a debug JSON file on `commit()` — never read back.
Consequences:

- Restarting `inform.lua` to pick up code changes **wipes any WiFi network config that was
  only ever pushed to the previous process's memory.** Recreate the WLAN in the controller UI
  afterwards to force a fresh `system_cfg` push.
- A throwaway `lua5.1 script.lua` invocation gets its own pristine mock state and proves
  nothing about the running daemon. **The only reliable way to check live wire data is to read
  what the controller actually received** (Mongo, or the REST API), never a fresh local script.

### Other environment facts

- **`cap_add: [NET_ADMIN]`** is required on the `ap` service — `netconfig.lua`'s `ip addr
  add`/`ip route replace` and `firewall.lua`'s `nft` both fail with `Operation not permitted`
  without it. Docker drops the capability by default even for root.
- **A `docker stop`/`start` of an AP container yields a fresh MAC from Docker**, so a restarted
  container is a brand-new device to the controller. Convenient for producing fresh adoption
  targets; means a stopped device's controller entry can never be resumed.
- **`ap2` compose service** (`replacement` profile) provides a second same-model device for the
  replace/clone flows; recipes in `tools/validation/README.md` §6.
- A `reboot` handled inside the container genuinely exits the container (no init to survive
  it). `docker start` the stopped — not removed — container to recover logs.
- Background `127.0.0.1:9080/api/ucore/manifest` and `get-ulp-manifest` connection-refused
  errors appear in `server.log` regardless of device activity. Pre-existing and harmless.
- The lab cannot create network namespaces (`ip netns add` fails with `mount --make-shared
  /var/run/netns failed: Operation not permitted`), which is why frame-level filtering claims
  stay unproven there.
- **The lab site has no gateway**, so any feature behind a site-wide gateway quorum (MAC-based
  VLANs) cannot be emitted there at all. Those captures come from the home controller.

---

## Findings only real hardware could show

Three of the four first-run findings share one shape: **UCI that reads perfectly and not one
SSID on the air.** For anything that can keep an interface from starting, the check is `iw dev`
showing an SSID and a channel, not the config file.

### The discovery path decides the adoption method, not the subnet

A controller that has heard a device's L2 broadcasts adopts it **by SSH**, even when it sits on
the controller's own subnet and its informs are landing perfectly. On the Adopt click the
gateway opened three SSH connections to the AP within 20 seconds:

```
dropbear[3746]: Child connection from 192.0.2.1:33114
dropbear[3746]: Login attempt for nonexistent user from 192.0.2.1:33114
```

and, failing them, parked the device at **Connection Interrupted** while the inform loop kept
running normally. The device record remembers this: removing it, stopping the broadcaster
(`config.l2_announce = false`), and letting the device re-appear from L3 informs alone made the
very next Adopt click complete over the inform channel with no SSH attempted at all.

So a device that cannot accept the controller's SSH login (no password auth, no bootstrap
account) **must** have `l2_announce` off, regardless of topology. "L3 adoption" names how the
controller discovered the device, not where it is.

### `macfilter="disable"` takes both radios off the air

OpenWrt's own schema (`/usr/share/schema/wireless.wifi-iface.json`) declares the option as
`enum: ["allow","deny"]`, and 25.12's ucode validator does not ignore an out-of-enum value — it
aborts the radio setup:

```
wifi-scripts: macfilter: disable has to be one of [ "allow", "deny" ]
netifd: radio0 (4179): Died   (validate.uc:47 → die())
```

openUF wrote `macfilter="disable"` whenever the MAC filter was off, i.e. by default, so
**every** config push killed both radios. "Off" is the absence of the option: `ap.uc`'s
`iface_macfilter()` emits `accept_mac_file`/`deny_mac_file` for the two enum values and returns
for anything else.

### `beacon_rate` is fatal on a driver that cannot program it

hostapd does not treat an unsupported beacon rate as a hint:

```
nl80211: Driver does not support setting Beacon frame rate (legacy)
Failed to set beacon parameters
Interface initialization failed
```

The 2.4 GHz ath9k radio never came up, while the ath10k 5 GHz radio — which the controller sent
no `beacon_rate` for — was fine. The capability is `NL80211_EXT_FEATURE_BEACON_RATE_LEGACY`,
reported **per phy** in `iw phy`'s "Supported extended features" list; neither phy on this board
has it. openUF gates the option on that flag and still applies the rate floor itself
(`basic_rate`/`supported_rates`), which needs no driver support.

### The regulatory domain arrives as a numeric code

`get_radio_table` always *read* UCI `country` to derive the payload's `country_code`, but
nothing ever wrote it — so the radios kept whatever regdomain OpenWrt booted with while
reporting `840`/US back (the fallback when the option is unset). On the wire it is an
**ISO 3166-1 numeric** code, sent both unindexed and per radio:

```
radio.countrycode=203
radio.1.countrycode=203      # radio.1.phyname=radio0
radio.2.countrycode=203      # radio.2.phyname=radio1
```

UCI wants alpha-2, so 203 → `CZ`. Applying it moved the device from `country US: DFS-FCC` to
`country CZ: DFS-ETSI` and the 2.4 GHz radio to channel 13 — legal in CZ, not in the US.

Worth knowing when reading channel numbers off a live AP afterwards: with `channel=auto` (what
the controller sends unless a channel is pinned) hostapd ACS picks freely within the new
domain, and its choice can be a poor one — it landed on 5 GHz channel 165, which CZ caps at
**13 dBm**, and on 2.4 GHz channel 13, which plenty of client devices refuse outright. The
controller's site-level Channel Plan exclusions are not on the wire unless `wifi_caps2` `0x10`
is claimed (see the wire reference's auto-channel section); pinning the channel per radio in
the device's Radios settings is the remedy.

### The ports an AP reported were the CPU's, not the board's

Two APs showed **one port each** in the Ports view, with the wrong number on it:

```
port_table: [{port_idx:1, is_uplink:true, speed:1000, full_duplex:true, name:"PoE Out + Data"}]
ethernet_table: []      lldp_table: []
uplink: {..., uplink_remote_port:4, uplink_source:"lldp_downlink"}
```

Three separate things were wrong, all on the openUF side:

- **The speed was the CPU port's.** Both modelmaps declared a single port naming the CPU
  netdev, whose link is the internal SoC↔switch one — always `1000/full`. One AP's actual
  uplink socket had negotiated 100baseT (`swconfig dev switch0 port 4 get link` →
  `speed:100baseT`), and the gateway's own row for the same cable said **FE** while the AP's
  said **GbE**: a metric that contradicts the device on the other end of the wire.
- **The other sockets did not exist.** Both boards had live links on sockets the controller
  never heard of.
- **Wired clients were attributed to the gateway**, since the AP they sit behind reported no
  downstream port at all.

The fix reads the switch's own ARL table — one `swconfig dev switch0 show` returns per-port
`link`/`pvid`, the ARL, and (driver permitting) per-port MIB counters. **Which socket is the
uplink is measured, not declared:** the default route's gateway IP → its MAC in
`/proc/net/arp` → that MAC's port in the ARL. On the two boards the same gateway MAC was
learned on physical port 4 and physical port 2, matching the cabling — a modelmap constant
would have been wrong on one of them, and would go wrong on either the next time a cable moves.
It is also the guard on per-port VLAN: that socket is refused an assignment, and a board that
cannot determine it refuses every port. (A side effect worth recording: per-port VLAN was
unreachable on both real boards before this, because the only reported port was the uplink —
the one port that must never be reassigned.)

Two things looked broken and are not openUF's doing: `lldp_table` is empty because `lldpd` on
the APs receives nothing (the UCG Ultra does not transmit LLDP to them, though it happily
parses theirs), and `ethernet_table` is not sent at all.

**Per-port counters are a driver setting, not a capability.** The ar8xxx driver only maintains
the MIB while `ar8xxx_mib_poll_interval` is non-zero, and boards differ: the AR9344 shipped at
`500` and reported counters, the AR8327 shipped at `0` and answered "Operation not supported"
for every port, so one AP's Ports view was populated and the other's read 0 B everywhere. One
`swconfig dev switch0 set ar8xxx_mib_poll_interval 500` produced counters on the next read, so
openUF does that once at startup when the attribute exists and reads 0
(`switchvlan.enable_mib_polling`, opt out with `dev.conf.vlan.mib_poll_ms = false`).

#### The Ports view's other columns

Empty is the right answer for most of them, and the real gateway is the control group:

| Column | Source | On this site |
|---|---|---|
| **Anomaly** | Controller-side, from its own stats history ("24h AI Anomaly Score") | `0` on every AP port; `20` on the UCG's port facing the 100baseT-linked AP — the same conclusion it records as `detailed_states.negotiated_low_uplink_port_speed: true`, which only appeared once openUF stopped claiming 1000 |
| **STP** | `stp_state`/`stp_pathcost`, a USW port property | `-` for every port, the gateway's own included |
| **Profile** | Port profile (`portconf_id` in `port_overrides`), controller-side config | `-` for every port, the gateway's own included |
| **Operation** | `op_mode` (`switch`/`mirror`/`aggregate`) | The controller writes `op_mode: "switch"` and `forward: "all"` onto openUF's ports **although openUF sends neither** — server-side defaults, and `switch` is truthful for these sockets anyway |
| **Tx/Rx Sum, Tx/Rx Rate** | `rx_bytes`/`tx_bytes` | Populated from the per-port MIB |
| **Tx/Rx Multicast, Broadcast, Dropped, Packets** | `rx_multicast`, `tx_broadcast`, `rx_dropped`, … | Sent by the gateway, not by openUF: swconfig's per-port MIB exposes `RxGoodByte`/`TxByte` and nothing else, and the CPU netdev's totals belong to every socket at once |

#### A wired client's usage history grows by the gateway's lifetime counter — controller-side, NOT FIXED

A media player cabled into one AP showed **968 TB** of 24 h usage; a second wired host on the
other AP was inflated the same way. The live client totals (`stat/sta`
`wired-tx_bytes`/`wired-rx_bytes`) were sane; only the per-client report rows
(`5minutes`/`hourly`/`daily` `user`) were wrong, and they started growing the day openUF began
reporting real sockets and their hosts.

Mechanism: the per-client report accumulator is a counter diff that adds `value − last` when
positive and stores `last = value` even when the value went down. The gateway feeds that key
every cycle with its own lifetime per-client counters (≈ 266.94 GB for this player), while an
AP feeds the same key for each wired host in its `port_table[].mac_table`. The gate is
`hasStationStat()`, decided by **device type** (`uap`, `udm`, `uxg`, `ugw`, `uacc` true; `usw`
false), with no override for a port-host context, so a wired host on a `uap` takes the same
path as a wireless station and its row becomes a report record with no byte fields — 0. Every
`0 → lifetime` alternation therefore adds the gateway's whole lifetime counter. Confirmed by
polling the 5-minute row every 2 s against the AP's informs: six informs in a row, each
followed within 0–4 s by a jump of exactly +266.94 GB.

**A real U6-IW should do the same** — the gate depends on device type, not on anything openUF
sends. Firmware cannot confirm what such an AP puts in `mac_table`: BZ2 4.0.15 has no port or
MAC table at all, and every in-wall build back to 3.9.27 is encrypted.

**Not fixed in openUF, by decision.** No lever is clean: counters in `mac_table` rows still
inflate on each alternation with any second source; a wireless-event type on the row does not
help, because a host alone on its port is processed anyway; a mismatched `vlan` skips the host,
which is the same as not reporting it; and not reporting wired hosts at all loses the port
attribution that real-socket reporting exists for. The live totals, the port attribution and
the Ports view all stay correct.

### A tagged SSID's trunk deafened every wired client on the AP

A printer cabled into one AP was alive and talking — the switch had learned its MAC in the ARL,
and that was the MAC the laptop's ARP cache held — but frames got *from* it and never *to* it.
**UCI and the switch disagreed**, which is the tell:

| | UCI `switch_vlan` for VLAN 1 | live `swconfig dev switch0 show` |
|---|---|---|
| WDR3500 — **AR8229**, `vlans: 16` | `1 2 3 4 0t` (sockets untagged) | `0t 1t 2t 3t 4t` — **all tagged** |
| Archer C5 — **AR8327**, `vlans: 4096` | `0 1 2 3 4 5` | `0 1t 2 3 4 5` — as written |

Both APs carried an identical `openuf_swvlan10` trunk of `0t 1t 2t 3t 4t`, written for the
tagged IoT SSID. Only the AR8229 let it bleed into VLAN 1: **on the
`ar8216`/`ar8226`/`ar8229`/`ar8236` driver family, tagging is not a property of (port, VLAN) —
it is one global per-port bitmask.** `ar8xxx_sw_set_ports()` does

```c
if (p->flags & (1 << SWITCH_PORT_FLAG_TAGGED))
        priv->vlan_tagged |= (1 << p->id);
```

and `__ar8216_setup_port()` reads that single bitmask to choose `AR8216_OUT_ADD_VLAN` vs
`AR8216_OUT_STRIP_VLAN`, for every VLAN at once. So marking socket 2 tagged for VLAN 10 made it
egress-tagged in VLAN 1 too, and the untagged printer dropped every frame. The AR8327 escapes
this because `ar8327.c` overrides the get/set-ports ops with a real per-(port, VLAN) tag table
— which is exactly why the bug shipped: **it is invisible on the board the feature was
developed against.**

The fix trunks only the CPU port and the uplink socket, the entire path a tagged SSID's frames
take. When the uplink cannot be resolved openUF holds any existing trunk rather than guessing;
letting a transient nil fall through to the reconcile pass would delete a working trunk and
reload, then rewrite it on the next inform, bouncing the IoT WLAN in a loop.

**A hardware limit that follows, and cannot be fixed in software.** On a global-bitmask chip a
port cannot be untagged in VLAN 1 *and* tagged in VLAN 10. Running a tagged wireless VLAN
therefore leaves the **uplink** socket egress-tagged for VLAN 1 as well (the `4t` in
`0t 1 2 3 4t`). The UCG Ultra accepts tagged VLAN 1 on that port, and the effect is confined to
the one socket facing the gateway rather than every socket facing a client.

**Generalising:** a `swconfig` port string is a *request*; `swconfig dev <sw> show` is the only
account of what the ASIC actually holds, and the two must be compared on each chip family, not
one.

### Fixtures are recordings, not illustrations

Three bugs found on real hardware were invisible to a green test suite because the fixtures
under `tests/fixtures/` were *tidier than reality*: `iw_station_dump.txt` had no
`avg ack signal:` lines, so nothing caught an unanchored `signal:` pattern matching them and
reporting every client at the ack value; `iw_phy_info_*.txt` carried an `HT TX Max spatial
streams:` line real ath9k/ath10k never emit, hiding that an HT-only radio has no source for
`nss` at all; and `iw_dev_info.txt` omitted the `ssid` and `multicast TXQ` blocks real output
carries. Paste real output from a real device, including the lines that look irrelevant —
those are exactly where unanchored patterns go wrong.

---

## The first DSA / 802.11ax board

Xiaomi Mi Router AX3000T (mediatek/filogic MT7981, OpenWrt 25.12.x) on the same UCG Ultra:
everything the ath79 boards cannot show, because they are all swconfig and all 802.11n on
2.4 GHz. Verified working there: L3 adoption, LLDP topology (`cid_interface='wan'` → Parent
Device *Cloud Gateway Ultra, Port 2*), per-socket `port_table` with a genuine FE/GbE split and
wired clients on the right sockets, both radios on air, Locate and the LED toggle on the real
case LED, and the tagged-VLAN SSID path.

### A tagged SSID needs no switch trunk on DSA

The swconfig boards need a `switch_vlan` trunk or the ASIC drops every frame of an unknown VID.
DSA needs nothing: with bridge VLAN filtering off — the state a `br-lan` with no `config
bridge-vlan` is in — the switch passes tags straight through, and the 8021q device on the
uplink *bridge port* (`wan.10`) takes its VID before the bridge sees it, because
`vlan_do_receive` runs ahead of the bridge's rx_handler. Confirmed live hop by hop with the IoT
WLAN on VLAN 10:

| Hop | Evidence |
|---|---|
| VAP → VLAN bridge | hostapd's generated config puts the second BSS on the right bridge: `bss=phy0-ap1` / `bridge=br-openuf10`, while `interface=phy0-ap0` keeps `bridge=br-lan`. The kernel agrees (`phy0-ap1 … master br-openuf10`) |
| Bridge → tagged uplink | `wan.10@wan … master br-openuf10 state forwarding` — the 8021q device on the uplink *socket*, no `config bridge-vlan` and no swconfig trunk |
| Tagged uplink → the VLAN's DHCP server | `udhcpc -i br-openuf10` from the AP itself took a real lease on the VLAN's own subnet, from the VLAN's own server |
| Untagged clients unaffected | `phy0-ap0` and the wired sockets stayed on `br-lan` throughout |

⚠️ What that leaves unproven is only the 802.11 association itself, which is not openUF's code:
no second radio in the house can act as a station on the IoT WLAN's band.

### Per-port VLAN on DSA is a bridge move, not `bridge-vlan`

Assigning a socket to VLAN 10 puts it in `br-openuf10`, the bridge that already holds `wan.10`.
`br-lan` keeps the uplink, the unassigned sockets and the management address, and nothing runs
with `vlan_filtering` — so a wrong answer here cannot strand the AP, which `config bridge-vlan`
on `br-lan` very much could. It would also have fought the tagged-SSID path for the same
`vlan_do_receive` reason: a `bridge-vlan` for VLAN 10 on `br-lan` would never receive anything,
because `wan.10` takes those frames first.

Confirmed live: port 2 assigned to the IoT network moved `lan2` into `br-openuf10` next to the
IoT VAP, left `br-lan` holding `wan`/`lan4`, and the attached device's frames appeared on the
tagged uplink **byte for byte** — each 342-byte DHCP DISCOVER on `lan2` showed up as exactly
342 bytes of `wan.10` tx.

**Turning the feature off does not always announce itself.** A device that has HAD Port VLAN on
and then has it unticked gets a full `system_cfg` with **no `switch.*` keys at all**, so an
affirmative off signal never arrives and a teardown keyed on one never runs — `br-lan` kept
openUF's port list indefinitely. Absence now counts as off as well, gated on openUF holding a
reversibility ledger: that is proof it applied something, which is proof the controller was
sending `switch.*` until now. It is reachable only inside `type(sys_raw) == "string"`, so a
noop response can never trigger it, and `restore()` spends the ledger so it cannot flap.

An attached client keeps the lease it already held, because the link never drops when a port
changes bridge; a link bounce is what makes it re-DHCP. Scope on DSA is the Native VLAN — a
bridge gives a port one untagged home — and a tagged-only port is refused out loud rather than
half-applied.

### The moved socket must stop learning, or the port is a one-way street

`br-openuf<vid>` is a software bridge — `wan.10` is an 8021q device the ASIC knows nothing
about — but the moved socket is still a real port on the same ASIC as the uplink, and **that
ASIC has one address table**. With learning on it files the client against `lan2`
(`00:00:5e:00:53:03 dev lan2 self`). A reply arriving VLAN-tagged on the physical uplink port
then hits that entry; `lan2` is no longer in the uplink's bridge port matrix, so the switch
resolves the frame in hardware and drops it instead of punting it to the CPU, where the
software bridge would have delivered it.

Captured at three points at once, hub on port 2:

| | learning on | learning off |
|---|---|---|
| DISCOVER on `lan2` | 4 | 1 |
| same frame on `wan.10` | 4 | 1 |
| same frame on `wan`, tagged | 4 | 1 |
| **any reply, anywhere** | **0** | OFFER + ACK, 2 ms |

**Outbound is perfect in both columns**, which is what makes this class so expensive: the
`/proc/net/dev` counter identity offered above as the honest proof of a port move *passes*
while the port is dead, every log line is clean, and the controller shows a correct config. A
hardware-dropped frame never reaches the CPU, so it is absent from a capture on the physical
port too — the evidence looks like the gateway never answered.

`switchvlan.dsa_apply` writes `openuf_brport<vid>_<socket>` with `learning '0'` for each socket
it moves, the same shape `ucihelper` uses for the tagged uplink. `strings /sbin/netifd` carries
`brport/learning`, and the persistence was measured rather than assumed: forcing `bridge link
set dev lan2 learning on` and reloading the network put it back to `0`, while the unassigned
`lan4` stayed at `1`. Two costs: an entry the ASIC learned *before* the move cannot be deleted
(`bridge fdb del … self` → `No such file or directory`, `bridge fdb flush` → `Not supported`)
and survives a link bounce, ageing out in ~140 s; and the socket's hosts leave `bridge fdb show
dev <socket>`.

### The attribution row was a client

One day after that fix, the wired IoT device on the assigned socket was listed in Client Devices
under **Cloud Gateway Ultra** at the gateway's **GbE**, instead of under this AP's **Port 2** at
the **FE** that socket had negotiated. `bridge fdb show dev lan2` returned nothing at all,
against 2 entries for `lan4` and 22 for the uplink. **The bridge FDB is not one of several
wired-host sources — it is the only one on a DSA board.** A second, independent defect surfaced
while tracing it: `port_table` resolved the *uplink's* bridge once and asked it about every
socket, so a socket living in any other bridge reported nothing even with learning on.

#### Why `learning '1'` cannot come back

| Attempt | Outcome |
| --- | --- |
| Learn in software, not in the ASIC | One `BR_LEARNING` flag per bridge port, mirrored into the driver by DSA's `port_bridge_flags`. No split knob exists |
| Flush the offending ASIC entry | ENOENT / EOPNOTSUPP, survives a link bounce, and re-learned on the client's next frame |
| `locked on` + `mab on` | Locked FDB entries are deliberately *not* pushed to switchdev — the exact split wanted — but `locked` blocks the client until an authenticator authorises it, and authorising means a **static** entry, which *is* offloaded. mt7530 does not offer `BR_PORT_LOCKED` either |
| Per-bridge FID | `mt7530_port_set_vlan_unaware()` puts VLAN-unaware bridges in transparent/fallback mode on VID 0, so every VLAN-unaware bridge shares one learning domain no matter which Linux bridge owns the port. That *is* the measured failure |

**The one that would work, and why openUF does not do it.** `vlan_filtering '1'` on `br-lan`
plus `config bridge-vlan` makes MT7531 VLAN-aware; `mt7530_hw_vlan_add()` sets `IVL_MAC`
(independent VLAN learning), so the client's entry would be keyed per-VLAN and the uplink would
be a member of that VLAN — the reply gets forwarded in hardware instead of dropped. It is
blocked on **netifd**, not on the switch:

- netifd's `bridge_enable_member()` deletes the auto-added VLAN 1 from *every* member as soon as
  the bridge has any VLANs, and a member with no explicit `bridge-vlan` entry gets no VLAN at
  all. Every `br-lan` port would need an explicit entry — including the wifi VAPs, whose
  ifnames are generated at runtime and recreated by `wpad` on each wireless reload. One missed
  entry silently blacks out an SSID or the management VLAN.
- OpenWrt [#16314](https://github.com/openwrt/openwrt/issues/16314) is exactly that failing at
  runtime: enabling VLAN filtering does not add WLAN interfaces to the bridge, and the
  workarounds are a reboot or a manual `bridge vlan add`. openUF applies controller pushes at
  runtime and never reboots.
- OpenWrt [#9089](https://github.com/openwrt/openwrt/issues/9089): bridge-vlan ports are not
  applied when the bridge was previously empty; a second netifd reload is needed.
- `wan.<vid>` would have to go — 8021q's `vlan_do_receive()` runs before the bridge's
  `rx_handler`, so `wan.10` swallows every VLAN-10 frame before `br-lan` could see it, and the
  uplink cannot be a tagged VLAN member while that sub-device exists. That drags the working,
  verified tagged-SSID path into the same change.

#### What openUF does instead

A bridge-family nftables tap on the moved socket, filing `ether saddr` into a dynamic set that
`sysinfo.mac_table` reads when the FDB has nothing. It works for the same reason the original
bug existed: the socket's bridge holds a software device, so it cannot be hardware-offloaded
and every frame on that socket reaches the CPU.

```
table bridge openuf_learn {
	set portmacs {
		type ifname . ether_addr
		flags dynamic,timeout
		timeout 5m
		elements = { "lan2" . 00:00:5e:00:53:07 expires 4m34s10ms }
	}
	chain learn {
		type filter hook prerouting priority dstnat; policy accept;
		iifname "lan2" update @portmacs { iifname . ether saddr }
	}
}
```

Verified on the board (nftables v1.1.6): `nft --check` on the generated commands first, then
installed for real, where the tap picked up the wired IoT device's address on the assigned
socket and the controller moved it to **Office AP Port 2 / FE**. The set timeout matches the
bridge's own FDB ageing, so a host expires exactly as it used to. The FDB always wins where it
has an answer; the tap is only consulted for a socket whose bridge is not the uplink's, so no
other board ever forks `nft`.

#### `mac_table[].vlan` — how a wired client gets its network

Reporting the host was not enough: credited to the AP's port, the client was listed under the
**management LAN** even though its IP was on the IoT subnet and the Ports view's own **Native
VLAN = IoT** column agreed. Supplying `mac_table[].ip` did not move it, and neither did a fresh
association. The wired-client processor iterates the site's layer-2 networks and per network
keeps only the reported hosts whose `vlan` matches:

```java
// com.ubnt.service.devmgr.isqI
for (VpKpWhVyVFmo host : list) {
    if (network.getVlan() != host.getInt("vlan", 1)) continue;
    ...
}
```

**Defaulting to 1**, so omitting `vlan` makes every reported host claim the untagged network.
Two corroborating sites in the same build: the mac_table dedup key is `mac` .. `vlan`
(`wRSpUfdrmMXnppHBKZ`), so one host reachable on two VLANs is two rows; and the wired base
class copies `vlan` from the report into the client record, dropping it when it is 1. openUF
reads the VLAN off the bridge the socket sits in — `br-openuf<vid>` names its own VLAN — rather
than plumbing it down from the `switch.*` push, so it cannot disagree with where the frames
actually go, and leaves it nil for the management VLAN. The live record then reads
`last_connection_network_name: "IoT"`, `vlan: 10`, `last_uplink_name: "Office AP"`,
`last_uplink_remote_port: 2`, at **FE**.

This does **not** contradict the swconfig rule that a socket outside the management VLAN
reports no hosts: there, the Archer C5's WAN socket sits on a VLAN openUF does not carry with
its CPU port down, so the host genuinely is not reachable on the LAN it would be listed in.
Here openUF bridges the VLAN itself.

Also found and not implemented: **`port_table[].mac_table_ipv6`**. The same processor reads it
alongside `mac_table`, mapping each entry's `ip` into the client's `ipv6_addresses`, and
requests it only from devices whose model declares `supportIpv6ClientsReporting()`. openUF
declares no such capability.

### Identity and reported address must come off the same netdev

Symptom: a gateway alert reading *"IP Address Conflict — multiple devices are using the same
192.0.2.4 address"* against a correctly configured network.

openUF takes its IDENTITY from `dev.conf.net.lan_cpueth` — that MAC is what the controller keys
the adopted device on and what `lldpd.config.cid_interface` advertises — and its reported IP
from the same name, but `announce.get_ip` deliberately hops to the **bridge** that port is
enslaved to, because a bridge member carries no address of its own. MAC from the port, address
from the bridge: safe only while the two share a MAC, which on every swconfig board here they
do. On DSA it is false — `lan_cpueth` names a *socket* (`wan`, whose MAC is `board.json`'s
`label_macaddr`) while `br-lan` inherits the DSA conduit's (`eth0`) — so the AP announced
itself as one MAC while every frame it sourced, and the ARP entry for the very address it
reported, carried another. The controller sees one device claiming the IP and another using it.
Not a DHCP problem: this AP is `proto 'static'` with no `udhcpc` running at all.

`ucihelper.ensure_bridge_identity`, run once at startup from `inform.M.run`, pins the bridge's
`macaddr` to `lan_cpueth`'s MAC when — and only when — the two differ. That is what a real
UniFi AP looks like: one MAC for identity, LLDP and management traffic. Adoption is keyed on
`lan_cpueth`'s MAC, which is untouched, so the device record survives. Verified on hardware,
with the Archer C5 (whose port and bridge already agree) left entirely alone.

> On a DHCP-addressed board the new L2 identity means a new lease and possibly a new address.
> Adoption is unaffected and openUF reports the change on the next inform, but that is why this
> logs loudly rather than acting silently.

### `radio.<n>.ieee_mode` carries a width, not a PHY generation

Read literally, `11nght20` / `11naht40` pins an 802.11ax radio to 802.11n, and the AX3000T's
5 GHz radio came up **HT40 on hardware that does HE160**. The vocabulary is Atheros-era
throughout — the same push names the VAPs `ath0`/`ath1`/`ath2` — and a real U6-InWall receives
the identical string and runs it as HE40. The controller has no field in which to request a PHY
generation at all; that is the device's own business. Invisible from the controller, which
renders the width and got it right; `iw dev` is the only place it showed. Fixed by taking the
width from the wire and the PHY from `iw phy`: the AX3000T goes HE20/HE40 and the Archer C5's
5 GHz goes HT40 → **VHT40** while its HT-only 2.4 GHz radio correctly stays HT20.

### An HE 2.4 GHz radio is the first that can be over-clamped

`phy_caps` derived a band's max width from the PHY generation, so HE implied 80 MHz on *both*
bands. True while every 2.4 GHz radio here was ath9k; wrong on the first ax board, where the
band still stops at 40 (`board.json` agrees). `clamp_htmode` narrows to 40 only for kind `HT`,
so a pushed HE80 would have reached hostapd, which treats an unprogrammable width as fatal —
the radio simply never starts.

### `/sys/class/leds` lists what drivers registered, not what the case has

The AX3000T's case LED sat a steady orange, and forcing **both** mt76 LEDs to full brightness
changed nothing on it: `mt76-phy0`/`mt76-phy1` are registered by the driver on every board it
supports, wired or not. The real LED is the blue/yellow GPIO pair the device tree declares,
which never registered because the stock filogic image ships no `gpio-leds` driver — the
platform device is there, nothing claims it, and the GPIOs keep whatever the bootloader set.
`kmod-leds-gpio` (9 KB) registers `blue:status` and `yellow:status`; Locate then blinks the
actual box at 4 Hz.

### state.json persisted ten fields it could never read back

`save()` encodes the whole table, `load()` copied back a hardcoded eight. The rest were written
to disk, visible in the file, and nil on the next start — including the per-port VLAN
reversibility ledger, the LED toggle, the locate flag, the static-vs-DHCP guard, and the
identity MAC that `_warn_identity_change` compares against, which made that entire diagnostic
unreachable. `state.lua` now carries an explicit `M.FIELDS` list that save and load share.

### 802.11r key holders (`iapp_key`)

openUF used to derive the FT key-holder secret from the passphrase (OpenWrt's
`md5(mobility_domain/psk)`), on the belief that the controller sends no such secret. It does:
`aaa.<n>.iapp_key`. It was never reported as dropped because the dropped-key audit treats the
whole `aaa.<n>.*` namespace as recognized — the shape `tools/cfg-coverage.lua` now exists to
catch.

**Controller:** the wlanconf field `x_iapp_key` is matched against `[0-9A-Fa-f]{32}` and filled
with 32 random hex chars, both by the database migration and for new WLANs. The `system_cfg`
emitter writes `aaa.<n>.iapp_key` when `iapp_enabled` is true and the key is non-empty, and
does **not** check `ft.status`; a migration switches `iapp_enabled` on everywhere. Seen on the
wire from both the lab and the UCG Ultra, with the same value on both radios.

**Firmware** (firmware-confirmed for 3.9.27 to 4.0.15, `ubntbox` and `wpad` disassembled):

- `ubntbox` writes `iapp_key=<hex>` into the hostapd config and, unconditionally,
  `wlan_id=<hex(SHA1("salt" ‖ ssid zero-padded to 32 bytes)[0..1])>`. With `ft.status` on it
  adds `mobility_domain` (`aaa.<n>.mobility_domain` if present, which the controller never
  sends, else that same hash) and `nas_identifier` (the device MAC), plus fixed
  `r0_key_lifetime=10000`, `r1_key_holder=020055424e54`, `reassociation_deadline=3000`,
  `pmk_r1_push=1`, `ft_over_ds=0`. There are **no `r0kh`/`r1kh` lines and no
  `ft_psk_generate_local`**.
- `iapp_key` and `wlan_id` are options only in Ubiquiti's patched hostapd (2.7-devel). On every
  association, `wpa_ft_roam` broadcasts an RRB frame (ethertype 0x890d) carrying the STA MAC, a
  timestamp and the `wlan_id`, AES-key-wrapped with `iapp_key`; a peer with the same `wlan_id`
  unwraps it and, if it is under 60 s old, disassociates that STA locally. A second RRB message,
  also wrapped with `iapp_key`, makes `wpa_ft_rrb_rx` allocate an R0KH and an R1KH entry for an
  unknown sender with `iapp_key` as their secret, and `pmk_r1_push` then goes to every peer
  learned this way.

So UniFi APs **learn** their key holders at runtime, and the shared secret is the controller's
random per-WLAN key.

**openUF** writes the wildcard key holders OpenWrt itself would generate, with that key in place
of the md5: `r0kh = ff:ff:ff:ff:ff:ff,*,<iapp_key>`,
`r1kh = 00:00:00:00:00:00,00:00:00:00:00:00,<iapp_key>`. OpenWrt reads them only when
`ft_psk_generate_local` is 0 (`ap.uc`'s `iface_roaming`, and `hostapd.sh` on 24.10), so FT-PSK
keeps local derivation and FT-SAE/EAP use the controller's key; without a key the md5 fallback
still applies. openUF also copies the firmware template's `pmk_r1_push=1` and
`reassociation_deadline=3000` (OpenWrt defaults 0 and 20000 TU) — hardware-confirmed in all
four FT BSSes' `/var/run/hostapd-phy*.conf`. Stock hostapd's `wpa_ft_push_pmk_r1` skips an R1KH
whose address or ID is all zeroes, so the wildcard entry never receives a push; a peer gets
pushes once it has been learned from its first pull (`wpa_ft_rrb_add_r1kh`, kept for
`rkh_pos_timeout`, a day by default), which is close to the firmware's learned-peer push.
`r1_key_holder` stays unset so hostapd uses the BSSID, because the firmware's fixed
`020055424e54` would give every AP the same R1KH-ID.

The mobility domain deliberately keeps openUF's own hash, not UniFi's: stock hostapd cannot
speak the learned-peer RRB messages, so FT between openUF and a real UAP cannot work, and a
shared mobility domain would only make clients try it.

**Cross-AP FT with the controller's key is confirmed** on hardware: a plain `bss_tm_req` was
declined (status 6, no suitable candidate), and with `disassoc_imminent` the client accepted
(status 0) and the target logged `AP-STA-CONNECTED … auth_alg=ft` with no
`EAPOL-4WAY-HS-COMPLETED`. The log does not say whether the target got the PMK-R1 by push or by
pull.

#### hostapd's RRB socket can be bound to a dead ifindex

One steer ended in a full SAE + 4-way instead, with the target AP's hostapd logging
`l2_packet_send - send: No such device or address`. Its `0x88b7` (RRB OUI: the PMK-R1
pull/response/push frames) packet socket was bound to **ifindex -1**, which the kernel sets when
a bound interface is unregistered, while the same hostapd's other packet sockets were on
`br-lan`'s current ifindex. hostapd shares one `0x88b7` socket per `ft_iface` name and frees it
only when no BSS uses it any more, while its other sockets are reopened on each BSS
reconfiguration — so the likely cause is a boot-time race where the socket was opened on a
`br-lan` netifd then replaced, with no reload ever releasing it. A clean reboot did not
reproduce it. Until hostapd reopens that socket the AP can neither pull nor answer a pull, so a
cross-AP FT involving it cannot succeed. Check with `/proc/net/packet`: the `88b7` row of
hostapd's sockets must carry `br-lan`'s current ifindex. openUF checks that once a minute and
restarts wpad at a cheap moment (`rrbguard.lua`, USAGE § 3). The `-1` marker was reproduced on
a real kernel (an `AF_PACKET` socket for `0x88b7` bound to a dummy interface read `Iface 12`,
then `-1` after `ip link del`), and `rrbguard.stale()` flagged the second dump and not the
first.

### 802.11r was configured, advertised, and not working

Everything visible said fast roaming worked: `ieee80211r=1` and the same `mobility_domain` on
both APs, the Mobility Domain element in both beacons (`iw` prints it as `Unknown IE (54): 82
d8 00` — it does not decode element 54, which reads like an absence), and `PSK FT/PSK
PSK/SHA-256 SAE FT/SAE` advertised in the RSN IE. Forcing a roam is what settled it: a station
that had negotiated **FT-SAE** reassociated with `auth_alg=sae` plus a full
`EAPOL-4WAY-HS-COMPLETED`, and it failed even between two BSSes on the *same radio*.

Cause: openUF pinned `ft_psk_generate_local=1`. Local key generation is **FT-PSK only** — each
AP derives PMK-R0/R1 from the PSK it already holds — while FT-SAE derives PMK-R0 from the
per-session SAE PMK, which no passphrase can reproduce; its PMK-R1 must be pulled from the
origin AP over an `r0kh`/`r1kh` relationship. OpenWrt configures those key holders only when
the option is `0`. Measured AKMs at the time: 3× FT-SAE, 3× SAE, 1× PSK, **0× FT-PSK** —
nothing was on the path that would have worked.

**The lesson generalises past this option:** a wireless feature can be correct in UCI, correct
in the generated hostapd config, correct in the beacon, and still not happen. Only the
station's own state transition proves it.

### Channel choice, for a two-AP site in CZ

`iw reg get` after adoption: 5150–5250 at 23 dBm with no DFS, 5250–5350 and 5470–5725 DFS,
5725–5875 at only 13 dBm. So the non-DFS channels at usable power are exactly **36/40/44/48** —
one 80 MHz block, or two 40 MHz ones. With one AP on 36+40 the other belongs on 44+48; auto had
picked DFS ch 52, which costs 3 dB and a 60 s CAC on every radio start. On 2.4 GHz auto picked
ch 13 because it was genuinely empty — and ch 12–13 are invisible to any client that only scans
1–11, which most ESP-class gear does. Moving to ch 11 took that radio from **0 associated
clients to 4**.

### Two facts the DFS channel restore turned up

openUF answers the controller's pushed `dfs-reset` job in-daemon, moving a 5 GHz radio back to
its configured channel with a CSA on the BSS control socket (`hostapd_cli chan_switch`) instead
of the firmware's driver-level channel set. Two things that cost a reading each:

- **The bonded-block centres are not evenly spaced.** UNII-3 starts at 149, which is not
  `36 + 16k`, so an anchor-on-36 formula gives the 149–161 block a centre of channel 154
  instead of 155 — a `center_freq1` hostapd accepts and then beacons a 5 MHz-shifted operation
  element with. `rrmscan.BLOCK_CENTERS` is therefore a table of the real centres (40 MHz:
  38…159, 80 MHz: 42…155, 160 MHz: 50/114/163), and a channel belongs to the block whose centre
  is within `width/10 − 2` channels.
- **`iw phy … channels` is the only place the non-occupancy list is visible.** Verified on both
  boards: each radio's own 80 MHz block reads `available` (CAC done) and every other DFS channel
  `usable`, on ath10k and mt76 alike, while non-DFS channels have no DFS state line at all —
  which is why `channel_in_nol` treats an absent entry as "not blocked" rather than as usable.
  `logread` never shows the NOL; nor does `hostapd_cli status`. hostapd's own
  `DFS-RADAR-DETECTED` line gives `freq` (where the radar was) and `cf1` (the BSS's centre), and
  on an 80 MHz channel those are different channels, so the reported channel comes from `freq`.

---

## Controller behaviors that are not openUF bugs

Each of these cost real investigation time at least once.

### A 404 with an empty body does not mean the inform was rejected

A well-formed, correctly-encrypted first-contact inform gets **HTTP 404 with
`Content-Length: 0`**, with zero corresponding entry in the controller's `inform` logger — yet
the device is created server-side and shows as "1 device is ready to adopt." Verified at the
wire level through a raw byte-logging TCP relay: the `100 Continue` handshake completes normally
and the response genuinely has an empty body. Malformed packets behave differently and are easy
to tell apart: **400** with a specific logged reason (`Bad packet magic`, `Data version 0 is not
supported`, `Content too short`). Ruled out as causes, so they are not re-tried: compression (a
real zlib-compressed, correctly-flagged payload gets the same 404) and GCM-vs-CBC (both get the
same 404).

`http_post` treats any non-200 as a hard failure and never inspects the body. In every case
observed the body was genuinely empty, so nothing is lost — but the client cannot distinguish
"processed, nothing to say" from "rejected," and backs off identically either way. **When you
see this on a fresh device: click Adopt.** That is the correct next move, not more debugging.

### Historical stats live in the `unifi_stat` database, on a 5-minute cadence

CPU/memory graphs, per-client Traffic Activity, the Radios tab's "Avg." columns and the Ports
view's Bps chart are **not** rendered from live inform data. They are read from `unifi_stat`'s
`stat_5minutes` / `stat_hourly` / `stat_archive` collections, written by a periodic archiver
(`com.ubnt.service.system.QDcGUYAmLvJwylXw`, internally labelled `stat-processor`). So a
flat/empty graph checked two minutes after adoption is expected; allow ~15 minutes, or a few
5-minute buckets, before treating it as a defect. Query `unifi_stat.stat_5minutes` directly to
check whether the data is landing — `db.stat` in the **`unifi`** database is a different, empty
collection and querying it is misleading.

### The minidev cache never sees external writes

`com.ubnt.service.devmgr.SNMiFVJXxaonBOtqbJ`'s device lookup is cache-then-DB-fallback: an
in-memory "minidev" summary (`_id`, `site_id`, `authkeys`, `x_aes_gcm`, `hash_id`) keyed
`("global", "minidev", mac)`, populated once on the first DB hit and never invalidated by an
external write. Editing a device doc in Mongo while the controller runs therefore has no
observable effect, and restarting the controller to force a reload introduces its own artifact:
the device flips to **Offline** in the UI even while `last_seen` keeps advancing and informs
keep landing, and does not self-heal within a normal observation window. This is why the
"always reset fully" rule exists, and why "Remove" (factory-reset) leaves informs decrypting
successfully afterwards — they are served from a stale cache entry while the underlying doc is
already gone.

### Config sync can get stuck after informs stabilise

Switching a test WLAN's Security Protocol to WPA3 once made the controller **stop pushing the
WLAN's `aaa.<n>`/`wireless.<n>` blocks entirely** — not just the SAE fields — and reverting the
setting did not restore pushes, even across an `inform.lua` restart, with no related error in
`server.log`. **Reusable warning:** a live no-op does *not* always mean "the controller is
deliberately withholding this field because of a capability gate" (which is exactly what it
meant for `advertise_ap_name`). Sometimes the environment's config sync is stuck. Decompile the
emitter to tell the two apart before concluding anything.

### Controller-side UI quirks

- **Environment tab (AirView) stops updating ~10 s after mount**, with no user interaction: the
  row disappears, "No WiFi broadcasts found" renders, and the sidebar filters grey out.
  Clicking any other Time Range tab instantly restores everything, and the data is present
  server-side the whole time (10/10 direct `stat/rogueap` polls over 23 s returned all
  entries). Consistent with the table capturing `rowsPerPage` from the pre-fetch, empty
  selector result at mount (`useState({pageNumber:0,from:0,rowsPerPage:r.length})`) and never
  recomputing it.
- **Radios tab's "Type" filter shows nothing until one option is explicitly checked**, unlike
  Band/MIMO/Status on the same page. "Type" here means the **AP's own uplink** connection type,
  so a wired-uplinked AP correctly appears under "Wired".
- **"Remove" on a client sends no wire command at all** — pure controller-side bookkeeping. A
  still-present client reappears on the very next inform.
- **The upgrade confirmation dialog truncates versions to 3 components**, so a genuine
  full-string mismatch can render as "Update U6 IW from 6.8.2 to 6.8.2?".
- **"Scanning…" on the Airtime Scan panel stays until a page reload**, because the panel holds
  the AP object it loaded with and nothing a device reports reaches it.

---

## Decompiling the controller

The controller is a Java app, and Java bytecode retains field-name string constants in the
class-file constant pool even under ProGuard-style class/method obfuscation — a far friendlier
analysis target than the AP's encrypted ARM firmware (see
[dead ends](#dead-ends--do-not-re-attempt)).

1. Extract `/usr/lib/unifi/lib/internal/internal-dependencies.jar` from the container — the
   real ~29 MB application jar. (`ace.jar` is only a license-protected bootstrap `Launcher`.)
2. **Unzip it on a case-sensitive filesystem.** `com.ubnt.service.aa` and
   `com.ubnt.service.aA` — and ~55 other package pairs differing only by case — are distinct
   real packages. macOS silently folds them into one directory, corrupting the extraction and
   producing a decompile of the *wrong* class's method body with no warning. Do the `unzip` +
   decompile inside a Linux container (`docker cp` the jar into the controller image itself,
   which already has a JVM).
3. **Use CFR (`cfr.jar` 0.152) for large methods.** `jadx` silently drops method bodies it
   can't reconstruct — no marker, just absent output. The ~5,182-unit method that gates
   provisioning was invisible to jadx and decompiled cleanly under CFR. jadx is still fine for
   browsing and for properly-scoped class listings.
4. For frontend behavior, fetch the live controller's own React chunks
   (`react-app-wrapper.*.js`, `radiosPage.*.js`, `swai.*.js`, `airview.*.js`) and grep them.
   Where a decode function's logic matters, the webpack module registry
   (`window["webpackChunk…"].push([[Symbol()], {}, req => …])`) gives a direct reference to the
   **live** function, which can be called with a sweep of inputs — ground truth, not a guess.
5. The locale bundles under `webapps/ROOT/app-unifi/react/data/locales/` are a source in their
   own right: the config writer gives the wire format, the locale bundle gives the *intent*,
   and for a key with no readable firmware consumer that is the only statement of what the AP
   is supposed to do.
6. For a question of the form "can this key ever arrive?", `grep -rl` the key literal over the
   extracted classes **first**. A family with zero hits needs no capture at all; that one grep
   closed most of the firmware sweep's open rows and surfaced `multicast.suppressor`.

**Logging:** the controller's loggers use flat, hand-picked names (`inform`, `adopt`,
`inform.uap`, `core.lock`, `web.api`), not package paths — see
`com.ubnt.service.system.HCKpgcBFPLu`. Setting `com.ubnt` to DEBUG does nothing for them. A
custom `logback.xml` with explicit `<logger name="inform" level="DEBUG"/>` entries, wired in
via `-Dlogback.configurationFile=`, is needed, and `debug.device=debug` in `system.properties`
(restart required) puts the event dispatcher's own decisions in `server.log`. Note that most
handlers only log on their *short-circuit* branch, so silence is consistent with everything
passing normally.

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
| `com.ubnt.service.devmgr.isqI` | Wired-client processor — the `mac_table[].vlan` network join |
| `com.ubnt.service.devmgr.w.a.eirJvdtm` | `wifiRoamingDetector` — the roam-report pairing |
| `com.ubnt.service.system.QDcGUYAmLvJwylXw` | Stat archiver (`stat-processor`) — writes `stat_5minutes` `o:"ap"` buckets |
| `com.ubnt.service.system.x.htDMji` | Archiver method that reads `radio_table[].athstats` |
| `com.ubnt.service.aO.hhFgUVZPT` / `aO.bLwwMKkr` | Scan ingestion; the `"PeerScan"` DTO |
| `com.ubnt.service.config.eWivisHeQsnaqDtx` | WLAN/radio config generator (emits `system_cfg`) |
| `com.ubnt.service.config.VAZShipWTNxlo` | The 10.6 AP config generator — most `aaa.*`/`wireless.*`/`radio.*` keys |
| `com.ubnt.service.config.ubntconf.OXMua` | SAE field emitter |
| `com.ubnt.service.config.ubntconf.PFljhxhmKJyhpeIhf` | `acsdfs` / `blklst` (auto-channel limits) |
| `com.ubnt.service.config.ubntconf.YcZSaTCMOYFEMGE` | ebtables emitter (guest rules, BPDU drops, IP walled garden) |
| `com.ubnt.service.config.hyFnQ` | Walled-garden entry classification (address vs domain) |
| `com.ubnt.ace.api.e.VVyiC` | REST per-port VLAN validator |
| `com.ubnt.data.cVbZoFIZsWYaVCquTr` (+ ~90 nested) | The controller's entire internal Device model — one nested class per wire sub-object |
| `com.ubnt.data.cVbZoFIZsWYaVCquTr$QCtdvLKOBb` | vap-stats DTO (**not** the unrelated top-level `com.ubnt.data.QCtdvLKOBb`, a FirewallRule — obfuscated short names collide across packages, always extract by full path) |
| `com.ubnt.data.uuvchZbWVhirD` | Device DTO — `hasFirmwareCapability`, `hasWifiCapability2`, `isSwitch` |
| `com.ubnt.data.dhdeXcHqLRBKMUZk` | Model registry (per-model port count and feature set) |
| `com.ubnt.g.f.e.rYtJfMBbtgWvku` | Radio band enum: `ng`, `na`, `ad`, `6e` |

---

## Feature matrix

Every controller-UI control exercised against a live openUF device. ✅ means driven through the
real UI with the resulting wire payload captured or the effect verified; ⚠️ names what is not
proven. The wire keys themselves are in [docs/WIRE-REFERENCE.md](docs/WIRE-REFERENCE.md), the
operator view in [USAGE.md](USAGE.md).

| # | Control / feature | Wire mechanism | Status |
|---|---|---|---|
| 1 | Adopt (L2/SSH, L3/mgmt_cfg) | SSH `syswrapper.sh set-adopt`, or `authkey` in `mgmt_cfg` | ✅ Both paths |
| 2 | Baseline post-adopt inform | `setparam` + `mgmt_cfg` | ✅ |
| 3 | SSID push (no VLAN) | `aaa.*`/`wireless.*`/`radio.*` | ✅ |
| 4 | VLAN-tagged network + SSID assignment | `aaa.<n>.br.devname = br0.<vlan>` | ✅ On both board families. The swconfig trunk carries the CPU port and the uplink socket only — tagging the LAN sockets deafens untagged wired clients on `ar8216`-family switches |
| 5 | Fast Roaming (802.11r) | `aaa.<n>.ft.status`, key `aaa.<n>.iapp_key` | ✅ Cross-AP `auth_alg=ft` with no 4-way, on the controller's own key |
| 6 | TX power / channel per radio | `radio.<n>.channel`/`.txpower`/`.txpower_mode` | ✅ |
| 7 | Locate | `cmd:"set-locate"` | ✅ Including the LED hardware effect on both boards: `trigger=timer` + 250/250 ms, restored to `trigger=none` |
| 8 | Airtime Scan ("Scan Now") | `cmd:"spectrum-scan"`, `wifi_caps` `0x10` | ✅ Against real radios — 27 channels on 5 GHz, 13 on 2.4 GHz, genuine per-channel utilization and noise. openUF scans off-channel per channel instead of the firmware's whole-AP scan-mode restart |
| 9 | Firmware upgrade | `_type:"upgrade"` | ✅ Stored only: openUF never downloads, verifies, flashes or reboots. The pushed `md5sum`/filename match Ubiquiti's real CDN artifact byte-for-byte |
| 10 | Forget device / factory reset | `_type:"setdefault"` | ✅ Lab and hardware. Tears down every `openuf_` wifi-iface, private-key and VLAN section, the radio options it wrote, per-port VLANs, band steering, l2guard, the guest portal and the cron job, and restores Airtime Fairness, the LED and the user's own disabled SSIDs — without the firmware's reboot. **Kept on purpose:** timezone, NTP, each radio's channel/width/power/country, the management address and the **inform URL** (falling back to `conf.lua`'s default makes the controller refuse the L3 re-adoption with `invalid inform_ip`). Forget also deletes the controller's device record, so name, channels, port VLAN overrides and LED setting are lost controller-side, as for a real UAP |
| 11 | `fw.ver` acceptance | — | ✅ Accepted verbatim, no validation beyond storage |
| 12 | Restart | `_type:"reboot"` (top-level, **not** `cmd:"restart"`) | ✅ |
| 13 | Manage LED on/off | `mgmt_cfg` `led_enabled` | ✅ Both values live; `trigger=none` + `brightness=1/0`, distinct from the locate blink |
| 14 | IP Settings (DHCP/Static) | `netconf.*`/`dhcpc.*`/`route.*` | ✅ End to end: real kernel interface change, real route, informing from the new address |
| 15 | Power / PoE | `power_source`, `psu_table`, `power-monitor`, … | 🔍 Not implemented. The "Power: -" element lives in the **Parent Device** subsection (properties of the upstream LLDP-linked switch), and openUF has no local signal for a real PoE class |
| 16 | Set Replacement Device / Load Configuration | **None** — controller-side Mongo clone, then an ordinary adopt | ✅ Both live, zero product code. Replacement auto-adopts the target ~50 s after the source goes away |
| 17 | Wired clients | `port_table[]` + per-port `mac_table[]` | ✅ Hosts land on the physical socket the switch learned them on (ARL on swconfig, bridge FDB or the nft tap on DSA), with `vlan` placing them on the right **network** |
| 18 | Per-port VLAN assignment | `fw_caps` `0x100`; `switch.*` | ✅ swconfig and DSA both apply it; the controller accepts the assignment and pushes an actionable table. ⚠️ The lab AP has no switch, so the apply path is hardware-only evidence |
| 19 | Client block / unblock | `cmd:"block-sta"`/`"unblock-sta"` + `setparam` `blocked_sta` | ✅ nft enforcement and survival across a restart, plus hostapd's deny ACL on every BSS (confirmed in live hostapd on both APs). ⚠️ A refused real client has not been watched |
| 20 | Environment / rogue-AP scan | `scan_radio_table[]` + 802.11k `rrm_beacon_req` | ✅ Payload, ingestion and live rendering. The passive `scan dump` cache only sees the operating channel's neighbours (6 entries on 2.4 GHz ch 11, 1 on 5 GHz ch 44); 802.11k enrichment took a 5 GHz radio from **0 neighbours to 4** without leaving the channel |
| 21 | Radios tab + client MIMO/generation | `radio_table` capability fields; per-station `nss`/`is_11*` | ✅ Four stations spanning HT/VHT/HE/legacy |
| 22 | Radios tab Avg. Signal / Interference / Airtime / MIMO | `vap_table.avg_client_signal`; `radio_table.athstats`; `radio_caps` | ✅ All four live, with bidirectional filter behaviour |
| 23 | Minimum RSSI | `stamgr.<n>.*`; outbound `min_rssi`/`min_rssi_enabled` | ✅ Enforcement follows the firmware (hostapd refuses below threshold + 3 dB; kick after 30 s below), and the refusal reaching live hostapd and its teardown are hardware-confirmed. ⚠️ A refused or kicked client is unit-tested only |
| 24 | Security tab WPA2/WPA3 protocol options | **None** | ℹ️ Not capability-driven from anything openUF sends: the dropdown's options come from the controller's own per-model database, keyed on the reported `model`/`platform`. `SECURITY_MAP` is a one-way map of a choice already made |
| 25 | Band Steering / BSS Transition / DTIM | `wireless.<n>.no2ghz_oui` / `aaa.<n>.bss_transition` / `.dtim_period` | ✅ All three by before/after diff, and **a real client steered 2.4 → 5 GHz**: `BSS-TM-RESP status_code=0` naming the 5 GHz BSSID, then `associated` on the other radio in the same second, `auth_alg=ft`. Two negative results worth keeping: usteer's `roam_events` counters stay 0 through a BTM band steer, and every client that was *not* steered had a visible reason (no 5 GHz sighting, or the BSS-Transition bit clear) |
| 26 | Show AP Name in Beacon | `wifi_caps2` `0x40` → `wireless.<n>.advertise_ap_name` | ⚠️ Wire and gate confirmed; **the OpenWrt side does not work and is not implemented.** `ap.uc` emits the WSC block carrying `device_name` only under `wps_possible && length(config_methods)`, and `config_methods` comes solely from `wps_pushbutton`/`wps_label`. Turning WPS on for a cosmetic feature trades a real security surface — deliberately not done |
| 27 | SAE tuning | `aaa.<n>.sae.anti_clogging`/`.sync`/`.has_groups`/`.groups.<k>.group` | ✅ Hardware-confirmed. They are no wifi-iface option: the per-BSS raw-line list is `hostapd_bss_options`, while radio-level `hostapd_options` is silently ignored for a BSS |
| 27b | SAE station keys | `aaa.<n>.sae.psk.<k>.{psk,mac,vlan,id}` | ✅ Wire → UCI → hostapd on both APs, all radios, with VLAN netdevs bridged and removed again on delete. ⚠️ No client joined |
| 28 | PMF (802.11w) / Multicast Enhancement | `aaa.<n>.pmf.status`/`.pmf.mode`; `wireless.<n>.mcast.enhance` | ✅ |
| 29 | Channel width | `radio.<n>.ieee_mode` → `wifi-device.htmode` | ✅ Both directions; the key carries the width only, never a PHY generation |
| 30 | IoT Optimization: Lock 2.4 GHz to Channel 6 | `radio.<n>.channel` (no dedicated key) | ✅ 11 → 6 in UCI, so not a coincidence of the default |
| 31 | IoT Optimization: DTIM Interval Lock | `wireless.<n>.dtim_period` (no dedicated key) | ✅ Pins the 2.4 GHz vap to `3` |
| 32 | IoT Optimization: Force WiFi 4 Mode | `wireless.<n>.iot` + `.qbssload` | ✅ Both keys reach UCI (`openuf_iot=1`, `bss_load_update_period=0`). ⚠️ The hostapd side of `bss_load_update_period` is not verified on hardware |
| 33 | Proxy ARP / Client Isolation | `aaa.<n>.proxy_arp` / `wireless.<n>.l2_isolation` | ✅ Both always present, so "off" is explicit. Either forces `ap_isolate`, and the hairpin fix restores station-to-station reachability on a force-isolated BSS |
| 34 | Minimum Data Rate Control | `wireless.<n>.minrate_data` (+ `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status`, `minrate_below_disable`, `pureg`) | ✅ Wire confirmed, and **not band-gated**. The OpenWrt side is radio-level, not per-BSS, so openUF folds a radio's VAPs to the most permissive floor. `beacon_rate` goes to hostapd verbatim in 100-kbps units while `basic_rate`/`supported_rates` are divided by 100. ⚠️ Not verified on hardware |
| 35 | Multicast Suppression (was "Multicast and Broadcast Blocker") | `wifi_caps2` `0x400000` → `wireless.<n>.multicast.suppressor` + `bcfilt.*` | ✅ Both modes captured; the source-MAC half measured on hardware (14/14 dropped, 0/15 once allow-listed). ⚠️ Requires `kmod-nft-bridge` — without it the kernel refuses **only** the drop rule (`Could not process rule: No such file or directory`) while table, chain and allow-list build, so the control looks enabled and filters nothing. ⚠️ The bypass types and the Conservative rate limit are lab-validated only; the Conservative rate (100 pkt/s) is openUF's own number, ~30× the 1.4–3.6 multicast frames/s measured idle |
| 36 | Hide WiFi Name | `wireless.<n>.hide_ssid` (+ duplicate `aaa.<n>.hide_ssid`) | ✅ Always present, so "off" is explicit; note the `true`/`false` vocabulary |
| 37 | MAC Address Filter | top-level `macacl.<m>.*`, joined on `wireless.<n>.devname` | ✅ The devname join is mandatory — the indices are numbered independently of `wireless.<n>`. Enforced by hostapd itself |
| 38 | WiFi Speed Limit | top-level `qos.vap.<m>.*`; a client's own profile as `rate-update` | ✅ **Per client**, both directions queued (one HTB class per client, upload on an IFB): a phone held 1.97 Mbit/s up under 2 and 4.5 down under 5 on real hardware |
| 39 | Ports view Connection column on an **uplink** port | `port_table[]` with **no** `mac_table` on `is_uplink` ports | ✅ Blank (or a retained stale value) is the CORRECT state: reporting the one MAC on the other end would file the gateway into this AP's `downlink_table` and invert the topology map |
| 40 | Roaming Assistant | `wifi_caps2` `0x20` → `wireless.<n>.btm_disassoc.*` | ✅ Wire, gate and teardown, and **steering on real radios**: a client at −80 dBm heard at −52 by the other AP got a BTM request, answered `status_code=4` (refused), was disassociated 16 s later and reassociated on the other AP within 1 s at −61 dBm. Its `extended_capabilities` did not advertise BSS Transition yet it answered, so the capability bytes do not predict which clients reply. ⚠️ The no-better-AP rule is unit-tested only |
| 41 | Discovery requests (UniFi app, WiFiman, Device Discovery Tool) | UDP 10001 `01 00`/`02 08` requests, replies from port 10001 | ✅ Wire captured from a real UCG Ultra; the always-listening AP side and targeted `01 04` are firmware-confirmed for 4.0.15. ⚠️ Lab-validated only — the home APs run `l2_announce = false` |
| 42 | WPA-Enterprise (802.1X / RADIUS) | `aaa.<n>.radius.{auth,acct}.<k>.*`, `interim_update.*`, `dynamic_vlan`, `nas_identifier` | ✅ Wire captured and replayed end to end; the mapped `encryption` values run through the **device's own** ucode generator produce `wpa_key_mgmt=WPA-EAP`/`-SHA256`/`-SUITE-B-192`, plus FT-EAP with 802.11r. ⚠️ No client has authenticated |
| 43 | Hotspot 2.0 / Passpoint | `aaa.<n>.hs20.*` (55 keys), `wireless.<n>.dgaf_disable` | ✅ Wire captured, replayed, and the generated section parsed by a real hostapd v2.12-devel with zero errors. Needs `fw_caps` `0x800000` **and** `fw2_caps` `0x80000` (RadSec), the latter for a feature openUF does not implement — a stated trade. ⚠️ No Passpoint client has associated |
| 44 | Guest walled garden, both forms | `dnsmasq.walled_garden.*`, the port-less GUESTIN/GUESTOUT ebtables pair, the `refresh-walled-garden` cron job | ✅ Captured, replayed with 0 unknown shapes, and every generated nft statement accepted idempotently. The controller splits the operator's one list by whether an entry parses as an address or a domain, so the **IP half was silently unenforced** before openUF learned the port-less shape. ⚠️ Deployed and inert at home: no guest client has reached a garden site |
| 45 | RADIUS MAC authentication + Dynamic Authorization (CoA) | `aaa.<n>.radius.macacl.*`, `aaa.<n>.radius.das.*` | ✅ Captured on an **open** WLAN (neither needs WPA-Enterprise) and parsed by the APs' own hostapd with zero errors. `macaddr_acl=2` and, on a non-EAP WLAN, the auth servers go in as raw BSS lines. DAS needs `fw_caps` `0x100000`. ⚠️ No RADIUS server at home, so no MAC admitted or denied and no CoA answered on hardware |
| 46 | MAC-based VLANs (a client's "Virtual Network Override") | `aaa.<n>.accept_mac.{status,<k>.{mac,vlanid}}` | ✅ Captured on the live controller and confirmed end to end on both APs: accept file, `wifi-vlan` section, `accept_mac_file` + `vlan_file` + `vlan_no_bridge=1` in live hostapd with no `macaddr_acl`, VLAN netdev in `br-openuf10`, teardown clean. Needs `fw_caps` `0x80000000` **and a site-wide quorum**. ⚠️ The lab cannot emit the keys (no gateway in the site) and the capture used a placeholder MAC, so **no real client has been moved by MAC** |
| 47 | Connection funnel + roam reports | `STA_ASSOC_TRACKER` notifs (`wifi_caps2` `0x2000`) | ✅ AirView Connectivity and Roaming both fed live: latencies, `failure_reason: DHCP_TIMEOUT`, Failed/Success roams between named APs, `fast_roaming` and the Roaming-Assistant tag. ⚠️ The Minimum RSSI tag has not been seen live |
| 48 | DFS radar reporting | `EVT_AP_RadarDetected` notif | ✅ Handler acceptance proven in the lab with two negative controls. ⚠️ No live radar hit, and 10.6.106 stores no `event` documents this container can show |
| 49 | Auto-channel limits (site DFS switch + channel blacklist) | `wifi_caps2` `0x10` → `radio.<n>.acsdfs` / `.blklst` | ✅ One unclaimed bit was hiding two real settings. `acs_exclude_dfs` live in UCI and hostapd on both APs; the blacklist inverts into `chanlist` against each board's real channel list. ⚠️ No radio here runs on Auto, so no ACS has chosen under the restriction |
| 50 | Pushed cron jobs (`11k-scan`, `dfs-reset`) | `cron.1.job.<n>.cmd` | ✅ Both gates confirmed live, and `dfs-reset` is pushed **only because openUF reports `has_dfs` honestly**. openUF does the nightly scan and the channel restore in-daemon rather than installing crontab lines. ⚠️ The CSA itself has never run in anger |

---

## Firmware as a source

Plaintext MIPS/QCA956x builds read with `tools/fw-extract.sh`: BZ2 3.9.27, 4.0.15 (2019),
4.3.28 (2021), U7LR 6.8.2 (2026). **ARM64 U6/U7 (including the U6-IW openUF impersonates) stays
opaque; nothing here is claimed for it.** The `aaa.%d.*` key table in `ubntbox` is the
firmware's own controller-key → hostapd-line map, and `libubnt.so` holds the reporting
producers (`fill_stainfo_json`, `fill_wireless_info[_full]`, `calc_*_satisfaction`).

What each build adds: 4.0.15 has no WPA3/OWE/PPSK template; 4.3.28 adds more `aaa.*` keys;
**6.8.2 `ubntbox` holds the full hostapd generator** — `sae.{pwe,confirm_immediate,anti_clogging,sync,groups,psk.<n>.*}`,
`owe_ptk_workaround`, `fils.*`, the `ft_*` key-lifetime set, `wpa.{strict_rekey,gmk_rekey,group_update_count}`,
`wpa3.enhanced_192`, `btm_disassoc.*`, `disable_na_mcast_to_ucast` — plus its own `wpad`,
`scan-rrm` and `airtime-scan`.

**A key's absence from `ubntbox` is not evidence that the AP ignores it.** 74 keys the
controller pushes do not exist in 6.8.2's key universe at all, among them
`wireless.<n>.advertise_ap_name`, `aaa.<n>.pmf.cipher`, `aaa.<n>.wpa.key.<k>.mgmt`,
`radio.<n>.bcmc_l2_filter.status`, `atf.*`, `cron.*`, `dnsmasq.walled_garden.*` and the whole
`bridge.*`/`dhcpc.*`/`ntpclient.*`/`resolv.*`/`route.*`/`iptables.*` plumbing — consumed by the
ARM64 builds, by `syswrapper.sh`, or by plain OpenWrt-style config files.

### The sweep, and what it settled

The complete cross of the firmware's key universe, its producers and its command verbs against
openUF. **Read this before opening a new firmware question.** Counts: **627** key templates in
6.8.2 → **609** distinct keys (177 of them `switch.*`), **469** templates in 4.3.28, **234**
distinct keys in the captured pushes.

Everything that was open is now closed, each by the cheap test first — grep the key literal
over the extracted controller classes, because a key the jar never writes cannot arrive:

| Family | Verdict |
|---|---|
| `radio.<n>.acsdfs`, `.blklst` | **Implemented** behind `wifi_caps2` `0x10` (matrix #49) |
| `aaa.<n>.radius.macacl.status`, `radius.das.*` | **Implemented** (matrix #45) |
| `aaa.<n>.accept_mac.*` | **Implemented** — not RADIUS at all, but MAC-based VLANs (matrix #46) |
| `wireless.<n>.multicast.suppressor`, `bcfilt.bypass_types` | **Implemented** behind `wifi_caps2` `0x400000` (matrix #35) |
| `aaa.<n>.sae.*`, `sae.psk.*` | **Implemented** (matrix #27, #27b) |
| `auth_cache`, `eapol_version`, `country_beacon`, `tdls_prohibit`, `wpa.1.pairwise`, `p2p*`, `wireless.<n>.wmm` | Toggled in the lab and settled individually — see the `aaa.<n>.*` and `wireless.<n>.*` tables in the wire reference. `wmm`, `eapol_version` and `qos.mode` are **constants by construction** (the writer emits a literal), and `p2p*` has no consumer in OpenWrt's hostapd build |
| `radio.<n>.antenna.gain`, `radio.outdoor` | **Decline, no usable consumer.** `antenna_gain` is in 25.12's schema but appears nowhere in `/usr/share/ucode/wifi/` or `/lib/netifd/` — stored and dropped — and the value describes the *impersonated* AP's antennas anyway. `outdoor` is `iwpriv outdoor` on QCA; mac80211's nearest knob (`country3`) only changes the Country IE's environment octet, not the channel/power table |
| `radio.<n>.backup_channel`, `.scan_list.*`, `.ch144`, `wireless.<n>.advanced_isolation.*`, `intelligent_dhcp`, `dhcp_bcast2ucast.*`, `bintval`, `ubnt_discovery_filter`, `signal_led*`, `rsn_preauth*`, `reauth_period`, `rsn_group_cipher`, `wpa.{strict_rekey,gmk_rekey,group_update_count}`, `fils.*`, `disable_na_mcast_to_ucast`, `strict_specification`, `system.monitor.{host,poll_interval,status}` | **Decline, no emitter** — zero occurrences in the 10.6.106 jar, so no controller setting can produce them. (`advanced_isolation` was the most promising row: a per-MAC exception list to client isolation. The trade it would have removed was closed from the other end by the hairpin fix.) `system.monitor.*` exists only as `memory.threshold`/`critical_memory.threshold`, written from a gateway-model enum |
| `radio.<n>.ampdu.*`, `.rate.*`, `.acktimeout`, `.cwm.*`, `.bgscan.*`, `.hard_noisefloor.*`, `.clksel`; `wireless.<n>.{authmode,puren,element_adopt,autowds,vwire,addmtikie}` | **Decline:** airMAX/QCA-era radio tuning and legacy AirOS VAP flags, constant in every capture, with nothing in mac80211 that takes them |
| `mesh.*`, `aaa.<n>.owe_devname`, `wireless.<n>.{wds,parent,vwirepeers,vwirepayload*}`, `connectivity.*` | **Decline, scope:** wireless uplink / mesh. `connectivity.*` is gated on `wifi_caps` `0x1` (`supportVwire()`), which openUF deliberately does not claim |
| `ble.*` (12 keys) | **Decline:** neither board has Bluetooth |
| `switch.*` beyond the U6-IW port rows (177 keys: ACLs, STP, IGMP, LAG, SNMP, dot1x, DHCP relay, storm control, mirroring) | **Decline, wrong product:** UniFi *switch* keys in a shared `ubntbox` |
| Per-station `sta_ip_timeout`, `sta_arp_timeout`, `sta_dns_timeout`, `sta_dns_latency`, `sta_icmp_rtt`, `sta_disconnects`, `wifi_drops`, `tx_rate_avg`, `rx_rate_avg` | **Decline, no consumer in 10.6.106** — zero hits in the jar, so sending them would change nothing. (The same search explains an oddity: `wifi_retries`/`wifi_latency`, which openUF *does* send, are not in the jar either — they are satisfaction inputs the AP consumes itself) |
| `rx_tcp_lat_avg`, `tx_tcp_lat_avg` | **Decline, no OpenWrt producer.** The controller does read them (`stat.vap` archiver, as `avgRxTcpRtt`/`avgTxTcpRtt`), but they are per-station TCP round-trip averages mcad samples itself; openUF measures no TCP timing at all. Implementing them means building a passive TCP RTT sampler first |
| `commit_errors` | **Decline, gateway-only path:** read only under `hasFeature(GATEWAY)`, which an AP identity never has |
| `ethernet_table`, `antenna_table`, `hw_caps`, `fw3_caps`, `sys_error_caps` | **Decline, nothing true to claim.** `ethernet_table` is a controller-side setter 6.8.2 never emits; `hw_caps`'s bits are screen, LED colour, LCM, RPS, boot sound, smart outlet, accelerometer, LED brightness and the PoE mask — none of which an OpenWrt AP presenting as a U6-IW has |
| `EVT_AP_*` events | Of the controller's eleven handlers and the firmware's three strings, the intersection is one event — `EVT_AP_RadarDetected`, implemented (matrix #48). The other eight controller-side strings are **not device-sent** (the controller raises them itself); `EVT_AP_WirelessEvent`/`EVT_AP_Notification` have **no handler** |
| ~50 `syswrapper.sh` verbs with no openUF equivalent (the sweep's Axis 4) | **Decline, not a controller command.** The `cmd/devmgr` API has 48 command names and the handlers put a smaller set on the wire; not one of the triage verbs is in either list, so `mcad` invokes them from its own state machine, its cron or over SSH. The one route that pays is the **pushed crontab**, whose four jobs (`11k-scan`, `dfs-reset`, `refresh-walled-garden 1`, `schedule-action`) openUF answers in-daemon |
| 6.8.2's WiFi Experience model | **Decoded, deliberately not ported** — see below |

The per-station mechanics the sweep established (the satisfaction formula, `fill_stainfo_json`'s
field list, the per-driver counter meanings) live in the wire reference's `sta_table` section.

### `tools/cfg-coverage.lua`: the replay oracle

A hand check against the source is exactly the step that does not survive a refactor.
`tools/cfg-coverage.lua` re-derives it mechanically and without reading the source at all: it
replays a captured push through every pure parser, then re-replays it once per key with that key
**deleted** and once per key with its value **replaced**, sorting each key into **consumed**
(some parser's output moved — proof, not inference), **inert** (nothing moved, but
`RECOGNIZED_SYSTEM_CFG` claims the key) or **ignored**.

The value probes matter: deletion alone cannot see a key that a **redundant** key covers.
`radio.<n>.countrycode` falls back to the unindexed `radio.countrycode`, so dropping either
leaves the regdomain unchanged and a deletion-only sweep calls both unread; mutating the value
exposes the read instead, and eight keys (`system.timezone`, `cron.status`, `ntpclient.status`,
`ebtables.status`, `dhcpc.<n>.status` among them) move from inert to consumed on that probe
alone. Where two keys shadow each other outright the honest verdict is still "unobservable",
which is why a verdict needs **two** captures across the controller toggle, not one.

On a 10.6.106 lab push (four VAPs: PSK + EAP + two guest), 665 key=value lines: **296 consumed,
254 inert, 115 ignored**. What it establishes beyond a hand check:

- **`RECOGNIZED_SYSTEM_CFG` over-claims by 254 keys.** Its patterns are prefix-coarse on
  purpose (`^aaa%.%d+%.` covers the whole per-WLAN block), so `_report_dropped_keys`
  systematically *under*-reports what openUF ignores. "Recognized" is a claim about a prefix;
  only the replay is evidence about a key.
- Several keys that look load-bearing are inert because openUF joins differently from the
  firmware: `aaa.<n>.devname` (openUF joins `aaa` to `wireless` by **index**; devname feeds only
  the OWE hidden-half pairing), `aaa.<n>.ssid` (taken from `wireless.<n>.ssid`) and
  `wireless.<n>.security` (the cipher suite comes from the `wpa.key.<k>.mgmt` list). Each is a
  correct verdict, and each is a key a source grep would have scored as consumed.
- The controller pushes `aaa.<n>.wpa.psk` on a **WPA-Enterprise** WLAN too, so a capture's
  `wpa.psk` is not evidence that a WLAN is PSK.

Run it after implementing a key family and expect that family wholly in **consumed**; a row
left behind is a consumer wired to a producer that does not exist, this repo's recurring defect.
Usage is in `tools/validation/README.md`; secrets are redacted even under `--values`, since the
output is meant to be pasted here.

### 6.8.2's WiFi Experience model: decoded, not ported

4.3.28 gates a new satisfaction model behind `satisfaction_new_impl_enabled` (default 0); in
6.8.2 `calc_sta_satisfaction` *is* that model with no flag. Checked by running the real code in
an emulator (`tools/fw-oracle`) beside a disassembly: the result block sits at struct+520
(score, reason @+8, anomalies @+16, 16 sub-scores @+24) with an experimental twin at +864, and
the controller gets the first. Terms: retry (needs ≥ 30 tries; ratio p = retries·100/tries:
p ≤ 25 → 100, else 100 − (min(p,105) − 25)·51/100, so floor 60; only when the **VAP's** phy
mode is 17, 18 or 23, else 100 — oracle-exact over modes × ratios), rate (5/6 GHz only:
f(rate · free-airtime%/100), a soft-float curve, 0 below ~1000 and 92 at 20000), tcp latency
(100 − (x−100)/15), and one 0/100 or stepped term each for ip timeout, arp timeout, dns timeout
(100 − 10n), dns latency, icmp rtt, disconnects (100 − 10(n−1)), no-DHCP and drops.
`calc_sta_satisfaction_mov` averages each term over 4 samples, and the charts have 16 keys.

**Not ported because the inputs are not pinned down:** several struct offsets are named only by
inference (rate, free-airtime %, VAP phy mode, tries/retries, network flags), the enum behind
modes 17/18/23 is unknown, and the controller does not know the 8 new chart keys. A port would
also drop today's signal term, which is a visible change. A **hybrid was checked and dropped**:
the network terms (ip/arp/dns/icmp, no-DHCP) and tcp latency need probes the AP firmware makes
and OpenWrt has no source for (they would score 100, as now); rate needs the inferred
free-airtime input; disconnects and drops need the assoc tracker's window and units; and the
retry term's only differences are the ≥ 30-tries gate and the 60 floor, behind that
unidentified phy-mode gate. **The score stays the 4.0.15 formula.**

### Where the evidence lives

Extracted rootfs images, the `ubntbox` key dumps, `libubnt682.so`, `mcad682`, the captured
pushes and the CFR-decompiled jar were all produced in session scratchpads, which are not
durable. Everything above is reproducible from `tools/fw-extract.sh` plus the lab controller;
the jar recipe is in [Decompiling the controller](#decompiling-the-controller), and the build
list comes from the `fw-update.ui.com` firmware API.

---

## Open questions

- **What Conservative Multicast Suppression means on a real UniFi AP.** The controller sends a
  bare `enabled` and describes it only as "prevents storms", and the key is absent from every
  readable firmware build (6.8.2 `ubntbox` does not consume it; the U6 ARM64 image is still
  opaque), so no source states the rate UniFi uses. openUF's 100 pkt/s ceiling is its own,
  measured against real idle traffic and documented as a choice. If an ARM64 image is ever
  decrypted, this is one to check.
- **Whether the four `bcfilt.bypass_types` exemptions select the right frames on the air.**
  Every nft expression is accepted by a real nft and the ruleset loads on both boards, but
  frame-level selection is unproven: the validation container cannot create network namespaces,
  and the alternative is enabling the control on a live WLAN.
- **Whether the controller escapes a `=` in a passphrase or SSID.** The parser keeps it (unit
  test, no capture): a WLAN whose passphrase contains `=` has not been pushed from a real
  controller yet.
- **`bootrom_version`** has no counterpart in the device schema. The firmware sends it (the
  U-Boot version), so keeping it is right; whether the controller reads it is unknown.
- **What the plaintext firmware cannot settle.** UAP BZ2 4.0.15 predates OWE, PPSK, WPA3 and FT
  over SAE, Airtime Fairness off, the AP name in the beacon, Roaming Assistant, `country_beacon`,
  `tdls_prohibit`, `p2p` and band steering's Balance mode. 6.8.2 covers much of that, but it is
  Wi-Fi 5 MIPS hardware; for a Wi-Fi 6/7 behaviour the controller jar and real hardware are the
  only sources.
- **PoE self-reporting** could be reopened if the validation environment ever gains a real
  switch container, or if a non-Parent-Device UI surface for those fields is found.
- **A real client on each ⚠️ path.** The outstanding ones, each named in its matrix row: a
  client moved to a VLAN by MAC, a Passpoint or OWE association, a WPA-Enterprise or
  RADIUS-MAC authentication, a PPSK VLAN key, a refused blocked client, a Minimum RSSI kick,
  and a frame denied by `bcfilt` type.

---

## Dead ends — do not re-attempt

- **Extracting the AP→controller protocol from U6-InWall firmware.** The official image
  (`v6.8.2+15592`, md5 `0fec04452cadd2d025777d36ab2974ea`) is a **kernel-only OTA delta**: its
  GPT has 5 partitions of which only `HLOS` has data, and there is no system/rootfs/application
  partition at all. `HLOS.img` is at flat 8.0 bits/byte entropy across ~95 % of the file
  (computed per-1MB block, not eyeballed from a binwalk graph), with no compression magic and
  zero `strings` hits for a kernel banner, driver names, or any of
  `scan`/`spectrum`/`rssi`/`noise`/`channel`/`bssid`. Only the last ~1.3 MB is plaintext, and
  that is device-tree blobs. Untried alternatives if this ever matters: a pre-2023 build that
  might predate encrypted/kernel-only packaging; pulling the binary off a live owned device
  over SSH; or a LAN packet capture between real hardware and a real controller.
- **Chasing `wait_for_initial_inform` as a thing in itself.** It is downstream of the GCM gate.
  Editing it in Mongo does nothing (the process never re-reads), and restarting the controller
  to force a reload introduces a separate "Offline" artifact.
- **Looking for a manual RF-scan trigger in the UI below 10.5.** There isn't one — AirView is
  fed entirely by passive, continuously-collected stats. (The Airtime Scan "Scan Now" button is
  the trigger, and it needs `wifi_caps` `0x10`.)
- **`strings` on concatenated Java class files on macOS.** `0xCAFEBABE` is both the Java class
  magic and the Mach-O fat-binary magic, so macOS `strings` chokes. Extract printable-ASCII
  runs in Python instead.
- **Deleting a stale wireless client record and waiting for it to reappear.** The pattern works
  for wired clients but wireless ones never came back (45+ s). Recreate the WLAN instead.
- **Hand-editing UCI-mock JSON or `state.json` to fake a lab result.** See
  [the minidev cache](#the-minidev-cache-never-sees-external-writes) and the mock's one-way
  dump: nothing read that way reproduces.
