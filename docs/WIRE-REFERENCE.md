# openUF wire reference

The UniFi inform protocol as openUF implements it: the envelope, the response types, the
`system_cfg` keys the controller pushes, and every field openUF sends back. Each claim here was
established against a real UniFi Network Application, a decompiled controller jar or a
plaintext UAP firmware build — [PROTOCOL-VALIDATION.md](../PROTOCOL-VALIDATION.md) holds the
findings, the environments and the open questions, and says how to re-establish any of this.

**Where this and third-party references disagree, this document wins.** go-unifi in particular
models the controller's *admin REST API*, a different surface from the inform wire protocol:
fields that exist there (`dtim_mode`) have no counterpart on the wire.

Conventions: booleans are `"enabled"`/`"disabled"` (sometimes `"true"`/`"1"`), and an **absent
block means disabled**. Addresses in captures are rewritten to the documentation ranges.

---

## The inform protocol

### Envelope

Header layout, flags (`0x01` encrypted, `0x02` compressed), zlib-before-encrypt ordering,
AES-128-CBC + PKCS#7 and the default `http://unifi:8080/inform` URL all match openUF's
implementation and fxkr/unifi-protocol-reverse-engineering's documentation. `PKT_VERSION`
is 1; the GCM AAD is the 40-byte header. `mgmt_cfg` is a newline-delimited `key=value`
**string**, not JSON.

**A response without flag `0x01` is refused.** The controller encrypts its answer to an
encrypted inform, and the AP firmware does the same ("only support encrypted data", BZ2 4.3.28
`mcad`, beside its TNBU header checks). Taking an unflagged packet would let anyone on the
plain-HTTP path push a `setparam` without the key; `parse_packet` raises and the tick waits
its normal interval.

**HTTP status of the inform POST.** 200 carries the answer. Anything else is a failed
inform: the wait doubles from the current cadence up to 60 s (or the controller's own
interval, if longer). Two statuses are special:

| Status | Meaning | The device |
|---|---|---|
| 503 | The controller is shedding inform load ("Server is busy") | waits the cap at once |
| 404, device not adopted | The controller's normal answer to a pending device until Adopt is clicked | keeps its own cadence, logs once |

The AP firmware tells neither apart: it logs one `HTTP Status %ld != 200` and enters selfrun
after three failures in a row.

### The GCM provisioning gate

**The controller will not provision a device until it has received a genuine AES-GCM
inform.** `x_aes_gcm` is set only in the decrypt path — `InformServlet` reads the packet's
on-the-wire flag (`header.isGcm()`) and the handler does `dev.set("x_aes_gcm", true)`.
There is no JSON field that sets it. `use_aes_gcm=true` goes into every `mgmt_cfg`
unconditionally, and once `x_aes_gcm` is set a GCM→CBC downgrade is rejected outright
(`"tried to downgrade inform encryption from AES-GCM to AES-CBC, rejecting"`).

The gate, in `MiVjHefaf`:

```java
if (!(dev.isUnsupported() || dev.aesGcmInformEncryptionOnly() || <globalFlag>)) {
    // "dev[..] : mgmt config update before provision"
    resp = new setparam; resp.put("mgmt_cfg", ...);
    dev.set("cfgversion", <fresh random 16-hex>);   // rolls every cycle
    return resp;                                     // returns BEFORE provisioning
}
```

`aesGcmInformEncryptionOnly()` returns the device doc's `x_aes_gcm`. While it is false
every inform takes this branch, gets a new random `cfgversion` and returns early — never
reaching `cfgversion`-convergence provisioning or the `wait_for_initial_inform` clear.

Diagnostic signature: adoption completes, informs decrypt, `last_seen` advances, but
`cfgversion` differs on every cycle, `x_aes_gcm` stays false, `provisioned_at` is absent
and the UI shows "Adopting" forever. Once GCM is sent it all resolves in one cycle.

`crypto.lua`'s GCM works against `zhaozg/lua-openssl` unchanged. The `openssl(1)` CLI
fallback cannot do GCM (`enc` refuses AEAD ciphers), so a host without a real binding
silently downgrades to CBC and hangs here.

### Adoption: L2 vs L3

**L3 (inform-only, no SSH).** The controller logs `discovered via L3 inform, skip SSH
adoption` and delivers the new `authkey` in the `mgmt_cfg` of the `setparam` sent right
after the Adopt click:

```json
{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat\nselfrun_guest_mode=pass\ncfgversion=e07e7991b8c62b47\nled_enabled=true\nstun_url=stun://172.19.0.4:3478/\nmgmt_url=https://172.19.0.4:8443/manage/site/default\nauthkey=ccc32a3bbe40157773294de8ed683627\ninform_url=http://172.19.0.4:8080/inform\nuse_aes_gcm=true\nreport_crash=true\n","server_time_in_utc":"1783841863822"}
```

openUF accepts a hex32 `authkey` from `mgmt_cfg` **only while `st.adopted == false`** —
unadopted, the device is still on the well-known default key, so the exchange carries no
less confidentiality than L3 provisioning already assumes.

**L2 (broadcast discovery + real SSH).** With `announce.lua` broadcasting, the controller
runs genuine SSH on the Adopt click and executes `syswrapper.sh set-adopt <url> <key>`,
which is what `state.lua`'s `adopted`/`authkey`/`inform_url`/`cfgversion`/`use_gcm` shape
expects. The command may be given by its absolute path (`/usr/bin/syswrapper.sh`) and may
carry the device's MAC as a third argument; the AP firmware reads only the first two
(BZ2 4.3.28 `syswrapper.sh`), and `syswrapper.lua` refuses a MAC that differs from the `mac`
in `state.json`. Two things real hardware needs:

- The controller's SSH client (`sshj`) offers only legacy `ssh-rsa` (SHA-1), so
  `HostKeyAlgorithms +ssh-rsa` / `PubkeyAcceptedAlgorithms +ssh-rsa` are required in
  `sshd_config` on OpenSSH ≥ 8.8.
- It authenticates as the factory-default **`ubnt`/`ubnt`**, not the Device SSH
  credentials — correct, because `announce.lua`'s `IsDefault` byte (`0x17`,
  `make_blob_17_1a`) declares the device unadopted.

`mgmt_url` is the **web UI deep link** (`https://host:8443/manage/site/default`), not an
alias for `inform_url`. Treating them as one makes the device overwrite its working inform
endpoint on the first post-adopt `setparam` and disappear permanently.

### Discovery requests (UDP 10001)

Ubiquiti's tools (the UniFi app, WiFiman's Discovery tab, the Device Discovery Tool) find
devices by sending a bare request to UDP 10001 and listing whoever answers. Captured from
a real UCG Ultra (Network 10.6), requests from an ephemeral port, broadcast and unicast:

| Request | Reply |
|---|---|
| `01 00 00 00` | unicast from **UDP 10001** to the asker's port: `01 00 <len16> <TLVs>`, 504 bytes |
| `02 08 00 00` | `02 09 <len16> <TLVs>`, same body; a broadcast request also drew a second 137-byte `02 09` with announce-style TLVs (the UCG has two responders) |
| `01 04 00 06 <mac>` (right or wrong MAC), `02 06 00 00`, `01 00 00 01 00` | nothing |

The UCG body carries `0x01` hw, `0x02` (mac + ip) ×4, `0x0a` uptime, `0x0b` hostname,
`0x0c` platform, `0x03` / `0x16` firmware, `0x15`, `0x17`, `0x0e`, `0x0d`, `0x06`, `0x0f`,
and gateway-only `0x2f`, `0x2b` (UUID), `0x32` (port JSON). An AP's reply is its announce
TLVs under the reply header.

Firmware (`/bin/mcad`, firmware-confirmed for UAP BZ2 4.0.15 only): `init_mcast_sock` binds
UDP 10001 at daemon start and joins `233.89.188.1`, with no adoption check.
`mcast_sock_process` drops any datagram whose source port is 10001 (other devices'
announces) and hands version 1 to `handle_version1`: command 0 length 0 answers every
asker, command 4 length 6 answers only its own MAC, the reply header being `01` plus the
request's command byte. No version-2 handler exists in that build, so the AP side of
`02 08` rests on the UCG capture alone.

**openUF** (`announce.lua`, `reply_for` / `_serve_requests`): listens on IPv4 UDP 10001 for
the daemon's life under `l2_announce`; answers `01 00 00 00` with `01 00`, `02 08 00 00`
with `02 09`, and `01 04 00 06 <own mac>` with `01 04` (firmware-only, not seen on a UCG);
ignores everything else, including its own broadcast. One reply per asker address **and
request type** per 0.5 s — the app sends both probes back to back from one address and
port, so a limit keyed on the address alone answered only one of the two and cost an AP the
app's "AP" badge.

**Multicast.** The UCG probes `233.89.188.1:10001` and the broadcast address in the same
millisecond and `mcad` joins the group, so openUF joins too (`ip-add-membership` on the LAN
address, re-joined when the address moves, retried on failure, logged once per distinct
error). A request arriving as both a broadcast and a multicast copy is answered once.

**IPv6 (gap, not implemented).** WiFiman also probes `ff02::1` every second from a
link-local address, and `mcad` opens an `AF_INET6` socket on 10001, so a real AP may answer
there. A v4 broadcast accompanies every v6 probe, so the app is answered either way; a v6
probe to `ff02::1` drew **no reply from any device on the LAN, the UCG included**, so there
is no reply format to copy; and LuaSocket 3.0 has no scope-id handling for a `fe80::`
asker. Revisit only for a client that probes IPv6 only, and capture a UAP's v6 reply first.

### Response `_type`s

The complete set, per `InformServlet`: `noop`, `setparam`, `cmd`, `upgrade`, `reboot`,
`setdefault`. There is no export/backup/dump command.

| `_type` | Shape | Notes |
|---|---|---|
| `noop` | `{"_type":"noop","interval":…}` | Steady state. `interval` is the heartbeat cadence in seconds the controller wants; openUF waits that long, clamped to 5–300 s (pre-adoption noops are unauthenticated), and falls back to its own 10 s when a noop carries none. |
| `setparam` | `{"_type":"setparam","mgmt_cfg":"…","system_cfg":"…","server_time_in_utc":"…"}` | Both configs are flat `key=value` blobs. See [system_cfg](#system_cfg-the-real-config-channel). |
| `cmd` | `{"_type":"cmd","cmd":"…","mac":"…","device_id":"…",…}` | See the command table below. |
| `upgrade` | `{"_type":"upgrade","version":"6.8.2.15592","md5sum":"…","url":"http://fw-download.ubnt.com/…"}` | Fire-and-forget, sent once; no retry, no confirmation expected. |
| `reboot` | `{"_type":"reboot","reboot_type":"soft",…}` | The top-level form is the real one; `{"_type":"cmd","cmd":"restart"}` is not this action's path. `reboot_type` is unused. |
| `setdefault` | `{"_type":"setdefault","server_time_in_utc":"…"}` | The controller's **Forget** of a connected device (`cmd/sitemgr delete-device`). UniFi firmware runs `syswrapper.sh restore-default`: `cfgmtd -c` then `reboot` (firmware-confirmed for 4.0.15). openUF tears its own config down without a reboot; see matrix #10. |

**After executing a `cmd` the device must send another inform immediately** (documented by
fxkr, confirmed live: the controller's next `noop` lands in the same second).

Confirmed `cmd` strings:

| `cmd` | Trigger | Payload |
|---|---|---|
| `set-locate` | Locate button | `{"cmd":"set-locate","device_id":…}` |
| `block-sta` / `unblock-sta` | Block / Unblock client | `{"cmd":"block-sta","mac":"…"}` |
| `kick-sta` | Client → Reconnect | `{"cmd":"kick-sta","mac":"…"}`. Queued only to the AP in the client's `ap_mac`, no capability gate (`devmgr/KlNisgrKpTMarFmxEJt`). One-shot deauth on every BSS |
| `scan` | REST `cmd/devmgr` only (no UI action) | `{"cmd":"scan","type":"active","mode":"sync"}`, plus `freq` and `radio_name` when given. See [`scan` and `scan_band`](#scan-and-scan_band-a-neighbour-sweep-on-request) |
| `scan_band` | Radio AI full scan | `{"cmd":"scan_band","band":"na"}`, one per band |
| `spectrum-scan` | Airtime Scan ("Scan Now", frontend `SPECTRUM_SCAN`) | Needs `wifi_caps` `0x10`; without the bit the REST call is refused (`api.err.InvalidTarget`) and `stat/spectrum-scan` skips the AP. See [Airtime Scan](#airtime-scan-spectrum-scan) |

Both the block-sta deauth and `kick-sta` go to **every BSS** (`ucihelper.ap_ifnames`, VLAN
netdevs folded into their BSS). A per-radio first-interface lookup misses a client on an
AP's second SSID.

#### A block refuses association (hostapd deny ACL)

Firmware (`syswrapper.sh` `block-sta`/`unblock-sta`/`apply-blocked-sta`,
`platdep_funcs.sh`; firmware-confirmed for 3.9.27 to 4.0.15): `block-sta` runs
`driver_kick_block_sta` — on every VAP that `is_vap_user_or_guest`, `iwpriv $ath
addmac_blksta <mac>` then `kickmac`, with the MAC stored in
`/etc/persistent/cfg/blocked_sta`. `unblock-sta` removes it and runs `delmac_blksta`.
`apply-blocked-sta` (and `-ifup` for one VAP) clears the driver list (`maccmd_blksta 3`)
and re-adds every MAC in the file, because the list does not survive a VAP going down. No
ebtables or iptables rule is involved: the block is the driver refusing the station.

openUF puts every blocked MAC into hostapd's **deny ACL** on every AP-mode BSS
(`firewall.deny_sync`, `hostapd_cli -i <bss> deny_acl ADD_MAC|DEL_MAC`), which rejects
authentication and association and disassociates a station already connected.

- **Re-applied every tick.** The runtime list lives only in hostapd, and a restart or BSS
  reload resets it to the config file. While anything is blocked, every tick reads each
  BSS's `deny_acl SHOW` and adds what is missing; once empty it keeps checking until a pass
  finds nothing to remove, plus one check at startup.
- **Stateless.** Any runtime entry the BSS's own `deny_mac_file` does not list is taken to
  be openUF's and removed on unblock. That file is the controller's MAC filter in deny mode
  (`macfilter=deny`, `/var/run/hostapd-<bss>.maclist`), so unblocking a MAC the filter also
  denies does not open the SSID to it. Nothing else on OpenWrt adds deny ACL entries at
  runtime (usteer and DAWN ban through ubus).
- **nft stays as the backstop.** hostapd checks its accept list before its deny list, so a
  MAC filter in allow mode that lists a blocked MAC still admits it; the nft drop keeps it
  off the network.
- `hostapd_cli` exits 0 when hostapd answers `FAIL` and 255 when the BSS has no control
  socket. Both count as "unknown": no command is sent and the next tick retries.

Hardware-confirmed on both APs (the MAC appears on every BSS as `… VLAN_ID=0`, a hand
`DEL_MAC` is restored by the next pass, unblock removes it everywhere; one pass costs
0.15 s on the Archer C5 including module load). ⚠️ A real blocked client being refused has
not been watched — that needs a named device.

#### Every `cmd` the controller can queue to a device

Found by decompiling every `com.ubnt.service` class referencing `"cmd"` and collecting each
`"cmd", "<name>"` literal, plus the frontend's command enum and the UAP-restricted REST
handlers for names held in constants.

| Relevant to an AP | Not for an AP / correctly ignored |
|---|---|
| `set-locate`, `unset-locate`, `block-sta`, `unblock-sta`, `kick-sta`, `scan` (`type`, `mode`, `freq`, `radio_name`), `scan_band` (`band`; only for devices without `wifi_caps2` `0x200`), `authorize-guest`, `unauthorize-guest`, `rate-update` (`ul_max`, `dl_max`), `spectrum-scan` (its `spectrum-cfg`, a scan-mode `system_cfg`, is ignored on purpose), `quick-scan` (`scan-band`, `scan-bw`; refused unless `wifi_caps2` `0x80`, which openUF does not claim, so never sent). Not applied: `rate-update`'s `ul_min`/`dl_min`, a 64 kbps floor policing cannot guarantee | switch: `power-cycle`, `clear-counters`, `clear-all-counters`, `port-recovery`, `rps-port-recovery`, `show/hide-lcm-tracker`, `set-etherlight-mode` · gateway: `query-dpi-stats`, `clear-all-dpi-counters` · SmartPower: `relayctl` · mesh/Element: `set/unset-meshv3-payload`, `mesh-halt`, `run`+`shellcmd`, `unset-element-payload` · WebRTC console: `build-ssh-session`, `ssh-sdp-answer`, `close-ssh-session` · crash/support: `send-crashlog`, `send-recovery`, `send-trace`, `clear-crashlog`, `clear-recovery`, `clear-trace` |

openUF's dispatcher answers `set-locate`/`unset-locate`, `block-sta`/`unblock-sta`,
`kick-sta`, `authorize-guest`/`unauthorize-guest`, `rate-update`, `scan`/`scan_band`,
`spectrum-scan`, `upgrade` (stored only), `set-selfrun`/`unset-selfrun`,
`refresh-walled-garden` (as a cron job), `setdefault`/`restore-default`, `reboot` and
`setparam`.

An unhandled `cmd` falls through to a no-op, which still triggers the immediate re-inform,
and is logged by name with a per-name count since daemon start (`inform: unhandled cmd 'X'
(N since start) -- ignored`), as is an unknown `_type`. The count is in memory only — flash
on the small boards is too scarce for a ledger. The lab cannot provoke it: REST `cmd/devmgr`
with `clear-counters`, `send-crashlog` or `clear-crashlog` for a UAP returns `rc ok` and
queues nothing, so the unhandled path is covered by unit tests only.

Block/unblock commands are the **immediate** path. The noop field `include_blocks` is not
the block list: it stays `[]` even while a client is blocked. The persistent list is
`setparam`'s top-level `blocked_sta`.

#### `blocked_sta`: the site's block list on every config push

Every full `setparam` carries a top-level `blocked_sta` string beside `system_cfg`,
`mgmt_cfg` and `cfgversion`: the MAC of every client with `blocked: true` in the site,
joined with `"\n"` (`""` when nothing is blocked — also seen from the real UCG Ultra).

- **Builder.** For a MediaTek/Atheros/Broadcom AP the generator
  (`config/eWivisHeQsnaqDtx`) delegates to `config/eirJvdtm`, which queries clients by
  `site_id` with blocked = true and joins `mac` with `"\n"`. Site-wide, not per AP, so it
  is authoritative.
- **Gate.** Sent only when `supportBlockedSta()` is true, which holds for a U6-IW
  (`devmgr/l/MiVjHefaf:837`).
- **When.** On a config push, and as a standalone `setparam{blocked_sta, interval}`
  (`:705`) when a device the controller had marked disconnected comes back. A restart
  inside the heartbeat window is not such a reconnect. `block-sta`/`unblock-sta` send only
  the `cmd`; the list follows on the next push. A device rename triggers a push reliably,
  `force-provision` only while `cfgversion` moves.

openUF (`inform.lua` `_sync_blocked_stas`): the key **present** replaces
`st.blocked_stas`, including `""`; **absent** leaves the ledger alone. nft is rebuilt only
when the MAC set changed (`reconcile` drops and recreates the table). A MAC new to the
ledger is deauthed on every BSS, as for `block-sta`. `state.load` rebuilds the list as a
plain array — a decoded `{}` tagged as an object saves as `{"1":mac}`, whose string key
`ipairs` never sees, which silently lost a block across a restart.

#### `scan` and `scan_band`: a neighbour sweep on request

| `cmd` | Sender | Wire |
|---|---|---|
| `scan` | REST `cmd/devmgr {cmd:"scan", mac}` (`devmgr/b/g/AcrQJeJCScLn`, UAP/UDM, site admin); no frontend sends it | `{"cmd":"scan","type":"active","mode":"sync"}`. `type`/`mode` default to `active`/`sync`; `freq` and `radio_name` are passed through only when the request carries them |
| `scan_band` | Radio AI, method `FULL_SCAN`, once per band (`system/aMFTAPaY`) | `{"cmd":"scan_band","band":"na"}` |

- **What the controller expects back.** Both senders only set `scanning = true`. The next
  stats inform clears it and stamps `last_scan` (`devmgr/PGOcbDWlbnYQdFW:1033`); nothing
  else is read. Neighbours come from `scan_radio_table`, the same field the passive
  Environment view uses.
- **`scan_band` gates.** Only to devices **without** `wifi_caps2` `0x200`
  (`supportNeighbourInScan`) that have a radio on that band. Radio AI waits 5 s per device
  and 60 s before reading results, and skips the sweep while another site scan runs.
- **Lab trigger.** `POST /v2/api/site/default/radio-ai/optimize/preview` with
  `{"radios":["na"],"method":"FULL_SCAN","calculation_id":"<uuid>","include_devices":["<ap mac>"]}`;
  `calculation_id` must be a UUID or the call returns `api.err.InvalidValue`.

openUF (`inform.lua` `_handle_scan_cmd`) runs a blocking `iw dev <if> scan ap-force` on the
requested radios so the immediate re-inform carries the fresh dump: `scan_band` sweeps the
radios whose `radio` equals `band`; `scan` sweeps `radio_name`, else the radio on the band
of `freq`, else every radio. `freq` becomes `iw … scan freq <MHz> ap-force`, and
`type: "passive"` appends `passive` (iw's grammar puts frequencies before flags and
`passive` last). Hardware-confirmed on both boards for 2.4 GHz; 5 GHz is swept by the
nightly `11k-scan` through the same `_force_scan`.

#### Guest portal (Hotspot): what the controller pushes and expects

Setup that produces the push: `guest_access.portal_enabled` on with `auth: none`, then
`is_guest: true` on a WLAN. `<ctl>` is the controller's IP; `ath<n>` is each guest VAP.

| Key | Off → on | Meaning |
|---|---|---|
| `wireless.<n>.is_guest`, `aaa.<n>.is_guest` | `false` → `true` | the VAP is a guest VAP |
| `wireless.<n>.usage` | `user` → `guest` | same, the field the stats side keys on |
| `wireless.<n>.l2_isolation` | `disabled` → `enabled` | forced client isolation (mapped to `isolate`) |
| `redirector.status`, `redirector.https.status` | `disabled` → `enabled` | the AP runs the redirect target |
| `redirector.url`, `redirector.url_https` | (new) `http://<ctl>:8880/guest/s/default/` | where an unauthorized guest is sent |
| `redirector.redirect_pattern` | (new) `http://<ctl>:8882` | |
| `dnsmasq.status`, `dnsmasq.1.devname=br0`, `dnsmasq.1.status` | `disabled` → `enabled` | a local DNS answerer for unauthorized guests |
| `iptables.status` + `iptables.1..3.cmd` | `disabled` → 3 rules | `-t nat -A PREROUTING -p tcp -m mark --mark 0x40000000/0xc0000000 -j REDIRECT --to-ports 80` (`0x80000000` → 443; udp 53 → 53) |
| `ebtables.5..51.cmd` | (new) 47 rules | the enforcement itself, below |
| `ebtables.52..53.cmd` | (new) | `-t broute -A BROUTING -i ath<n> -p 802_1Q -j DROP` |
| `qos.status` + `qos.ebt.*`, `qos.if.*`, `qos.vap.*`, `qos.mode=1` | `disabled` → enabled | per-VAP marks (`0x1000`, `0x2000`) and interface speeds: the frame `rate-update` plugs into |

The ebtables ruleset, all `-t nat`:

- `-N GUESTIN -P DROP`, `-N GUESTOUT -P ACCEPT`; `PREROUTING --in-interface ath<n> -j
  GUESTIN`, `POSTROUTING --out-interface ath<n> -j GUESTOUT`.
- GUESTIN accepts EAPOL (`--proto 0x888e`), DHCP requests (broadcast, udp 68→67) and ARP,
  plus tcp 8880/8843 and 8881 to `<ctl>`. Its first rule (`-I`) sends tcp 8882 to `<ctl>`
  to `REDIRECT_HTTP`.
- DNS (udp/tcp 53) goes to `GUEST_DNS` (`-P DROP`), which jumps to `AUTHORIZED_GUESTS` and
  then `REDIRECT_DNS` (mark `0x40000000`, `-j redirect`).
- GUESTIN drops IPv6 (`0x86dd`), other broadcast, multicast `224.0.0.0/4` and the three
  `restricted_subnet_*` from `guest_access` (`192.168.0.0/16`, `10.0.0.0/8`,
  `172.16.0.0/12`).
- tcp 443 goes to `CAPTIVE_PORTAL` (`-P RETURN`, empty).
- `-N AUTHORIZED_GUESTS -P RETURN` is **pushed empty**. `GUESTIN -p 0x800 --pkttype-type
  otherhost -j AUTHORIZED_GUESTS` comes before tcp 80 `-j REDIRECT_HTTP` / tcp 443 `-j
  REDIRECT_HTTPS` (marks `0x40000000`/`0x80000000`, `-j redirect`). The device fills the
  chain itself from `authorize-guest`; anything unmatched hits GUESTIN's DROP policy.
- GUESTOUT accepts DHCP replies and ARP, drops IPv6, other broadcast and multicast.

So the controller ships its whole enforcement as ebtables + iptables; the device owns the
`AUTHORIZED_GUESTS` membership and a local HTTP/DNS answerer for the redirect marks.

**Station `authorized` is the portal state, and the controller reconciles it every inform.**
`devmgr/dhdeXcHqLRBKMUZk` runs per `vap_table[].sta_table[]` entry; on a guest VAP with the
portal on: no active guest record but `authorized` true → `unauthorize-guest` +
`guest_kicks++` (`devmgr/l/MiVjHefaf:1448`); an active record but `authorized` not true →
`authorize-guest`; a record over its usage quota → `unauthorize-guest` and the record ends.
`is("authorized", true)` defaults a **missing** key to true, so an AP that sends no
`authorized` gets `unauthorize-guest` for every guest station on every inform
(`guest_kicks` reached 77 in ten minutes in the lab). On a guest WLAN the station entries
must report `authorized` as the portal state.

openUF records the portal WLANs on every push — the `aaa.<n>.id` of each
`wireless.<n>.is_guest=true` WLAN while `redirector.status=enabled` — into
`st.guest_wlans`; `authorize-guest`/`unauthorize-guest` maintain `st.guest_authorized`;
each `sta_table[]` entry reports the ledger's answer on a portal WLAN and `true` elsewhere.

**The redirect the portal expects** (`devmgr/IXbVCbWPDmZdkfbJ`). The initial redirect
handler reads `id` (guest MAC), `ap` (AP MAC), `url` (where the guest was going), `ssid` and
`t` (the AP's epoch seconds; more than 60 s from the controller's clock is refused), and
stores them in its encrypted `ec` cookie for the login. An `ec` query parameter replaces
all of them with a cookie the AP makes from its `guest_token`, but only on devices with
`supportRedirectorInitialEC`, which `redirector.initialec=enabled` would announce; openUF
uses the plain form.

**`guest_token` is required anyway.** Every login path checks the AP's device record for a
non-empty `guest_token`, else logs `Missing Guest Token in AP[<mac>] in Site[…] during
guest authorization` and refuses — the portal still answers the browser
`{"authorized":true}`, but no guest record is written and no `authorize-guest` follows. The
record's value is copied from the stats inform (`devmgr/PGOcbDWlbnYQdFW:1040`,
`copyAttrsIfPresent(…, "guest_kicks", "guest_token")`), so the device names it. Its format
is unverified (macOS case-folding hides the decrypting class); openUF sends 32 random hex
characters, persisted, while the portal is on.

**openUF's enforcement** (⚠️ lab-validated only). `guestportal.lua` reads the facts out of
the pushed guest rules — the `(ip, port)` ACCEPTs (8880, 8843, 8881 to `<ctl>`), the
`-I … -j REDIRECT_HTTP` intercept (8882 to `<ctl>`), the `--ip-dst … -j DROP` subnets and
`redirector.url` — classifies every known shape, logs any other guest-chain rule as
unrecognised, and builds its own nft chains in the controller's order. Marked HTTP gets
`ether daddr` set to the bridge MAC plus `pkttype host` (ebtables `redirect`) and is
NAT-redirected to port 8820, where the inform loop answers with the `302`. Deliberate gaps:
unauthorized DNS is passed rather than answered locally, marked HTTPS is dropped rather
than answered, and the `redirect` needs an IPv4 address on the guest VAP's bridge.

| Wire (all `{"_type":"cmd", …, "mac":"…"}`) | Sent when |
|---|---|
| `{"cmd":"authorize-guest","mac":…}` | only from the inform reconcile above (openUF: into `st.guest_authorized`). A REST `cmd/stamgr authorize-guest` just writes the guest record (`authorized_by: "api"`, `end`) and sends nothing while the station already reports authorized |
| `{"cmd":"unauthorize-guest","mac":…}` | REST `cmd/stamgr unauthorize-guest` (ends the record, then the reconcile repeats it while the station still reports authorized), plus the reconcile and quota paths. openUF: out of `st.guest_authorized`, then a deauth on every BSS |
| `{"cmd":"rate-update","mac":…,"ul_max":2048,"ul_min":64,"dl_max":4096,"dl_min":64}` | once per association (`qos_policy_applied` latch, reset on roam and reconnect) when the guest record has `qos_overwrite` (REST `authorize-guest` with `up`/`down` in **kbps**). The maxima come from `qos_rate_max_up`/`_down`, defaulting to `-1` (no limit). Without an override the client's own WiFi Speed Limit profile is sent instead, if it is not the site default. openUF applies it per client — see "`qos.*` — WiFi Speed Limit" |

**`unauthorize-guest` disconnects the guest.** Firmware drops the MAC from
`/var/run/guest.authorized` and the authorized ipset, then runs `kick_sta`: `iwpriv <ath>
kickmac <mac>` on every VAP whose `/var/run/vapusage.<ath>` is `user` or `guest`
(firmware-confirmed for 3.9.27 to 4.0.15). It kicks unconditionally, with or without the
portal — without the kick the guest stays associated and unauthorized and its OS never
re-runs captive-portal detection, so it never sees the portal again. openUF does the same
after updating the `authorized` set (`hostapd_cli deauthenticate` on every BSS), with at
most one kick per MAC per 60 s: the firmware reports `authorized` from the list it just
changed and so gets one command, while openUF reports it only on the WLANs
`st.guest_wlans` names, and the hold keeps a disagreement from becoming a deauth storm.

**`rate-update`, openUF's answer** (⚠️ lab-validated only). `ul_max`/`dl_max` are kept in
`st.guest_rates` for an authorized MAC only (dropped on `unauthorize-guest`; `-1` = no
limit) and policed in `bridge openuf_guest`: `rate_up` (`ether saddr <mac> limit rate over
<kbps×125> bytes/second … drop`) jumped before `guestin`, `rate_down` (`ether daddr`)
before `guestout`. They are not queued, because the VAP's tc root qdisc belongs to the
per-WLAN speed limit (`shaper.lua`). Measured through a limited guest with iperf3: 2048
kbps → 2097, 4096 kbps → 4246, a 10 Mbit/s UDP flood → 2448 kbps passed (75 % dropped),
~33 Gbit/s with the rules flushed.

**`selfrun_guest_mode`.** `mgmt_cfg` carries it in **every** push, guest WLAN or not, from
the site property `config.selfrun_guest_mode`; any value other than `pass` goes out as
`off` (`config/GWoWvNEX`). It is not in the UI. Site properties live in the per-site file
`data/sites/<site name>/config.properties` (`config/bLwwMKkr` → the file service by site
name), **not** `system.properties`: a line in `system.properties` changed nothing even
across a restart, while writing `config.selfrun_guest_mode=off` to the site file took
effect on the next push with no restart.

What the AP does with it (firmware-confirmed for BZ2 3.9.27 and 4.0.15, identical):

- `/bin/mcad` enters SELFRUN (state 3, writes `/var/run/system.selfrun`, calls
  `syswrapper.sh set_selfrun`) once its consecutive-failure count reaches 3 (`fail_count`
  at object offset 0x264, `sltiu …, 3`). The first successful inform calls `unset_selfrun`.
- `syswrapper.sh` only acts while the portal is on (`redirector.status=enabled`).
  `selfrun_guest()` reads the key from `/etc/persistent/cfg/mgmt`: **only `off` is off**, so
  any other value, or none, means `pass`.
- `pass`: `ebtables -t nat -F AUTHORIZED_GUESTS; … -A AUTHORIZED_GUESTS -j ACCEPT` ("bypass
  the guest authorization"). On return, `rm -f /var/run/guest.authorized` plus
  `authorized_guests_updated` — every authorization is forgotten and the controller
  re-authorizes.
- `off`: `ifconfig $ath down` for every guest VAP (`/var/run/guest_devnames`), kept down by
  the VAP scheduler; `ifconfig $ath up` on return.

openUF keeps the value as `st.guest_selfrun`, where only `off` is off. Selfrun starts after
3 failed informs in a row (`GUEST_SELFRUN_FAILS`) and ends with the first answer. With
`pass`, the `selfrun` chain (jumped from `guestin` right after the authorized accept) gets
`meta pkttype other accept`, the firmware's AUTHORIZED_GUESTS position. With `off` the guest
VAPs go down by `ip link set`, their names kept in `st.guest_vaps_down` so they return even
across a daemon restart. On return openUF keeps its authorized list instead of clearing it,
because the controller re-authorizes the same guests either way — a deliberate difference.

Bringing a BSS back needs more than the link: on a real radio `ip link set <bss> up` alone
leaves it off the air, because hostapd does not act on the link going down and on the way
up only updates a beacon mac80211 has already stopped (reproduced on ath10k: `iw dev
phy0-ap1 info` showed no SSID and no channel). openUF returns a guest WLAN through
`wlansched.set_bss` — link up, then `hostapd_cli -i <bss> raw STOP_AP` and `update_beacon`
— and a BSS whose beacon does not restart goes down again and stays in
`st.guest_vaps_down` for the next answer to retry. Hardware-confirmed on all four radios of
both APs (ath10k ch 36, ath9k ch 1, mt76 ch 11 and ch 100 DFS): three missed informs took
both BSSes down with no SSID, one answer brought them back with SSID and channel.

#### The walled garden: two forms, split by what the entry looks like

The site's guest settings hold one flat list per direction —
`guest_access.allowed_subnet_<n>` and `restricted_subnet_<n>`, read until the first blank
index — and `com/ubnt/service/config/hyFnQ` runs each entry through three producers:

| Producer | Keeps | Used by |
|---|---|---|
| `Cuhf.V4` | IPv4 addresses and CIDRs (a `/32` as a bare address, a `/0` split into `0.0.0.0/1` + `128.0.0.0/1`) | the ebtables rules |
| `Cuhf.V6` | IPv6, same shapes | the ip6tables side openUF does not implement |
| `OWIoHe.UGwcHSHUGpYtqo` | whatever Guava's `InternetDomainName.isValid` accepts | the `dnsmasq.walled_garden` keys |

Guava's check rejects an all-digit rightmost label, so the sets never overlap: **an entry is
either an address or a name, and which list it is in does not decide how it travels.**

**The IP half.** `ubntconf/YcZSaTCMOYFEMGE` emits, per allowed address:

    -t nat -I GUESTIN  -p 0x800 --ip-dst <net> -j ACCEPT
    -t nat -I GUESTOUT -p 0x800 --ip-src <net> -j ACCEPT

and per restricted address `-t nat -A GUESTIN -p 0x800 --ip-dst <net> -j DROP`. **These
carry no port**, unlike the portal's own accepts (`--ip-proto 6 --ip-dport 8880 --ip-dst
<ctl>`) — a parser that required one rejected both lines as unknown shapes and left an IP
walled-garden entry silently unenforced. The egress rule matches `--ip-src`, so the reply
direction needs its own list (`spec.accept_out`).

**The domain half.** Three empty chains and the jumps into them, gated on the site having
any garden domain (`devmgr/kDxteQiUX`):

    -t nat -N ALLOWED_DOMAIN_IN  -P RETURN   /  -t nat -I GUESTIN  -p 0x800 -j ALLOWED_DOMAIN_IN
    -t nat -N ALLOWED_DOMAIN_OUT -P RETURN   /  -t nat -I GUESTOUT -p 0x800 -j ALLOWED_DOMAIN_OUT
    -t nat -N RESTRICTED_DOMAIN_IN -P RETURN /  -t nat -A GUESTIN  -p 0x800 -j RESTRICTED_DOMAIN_IN

plus the names and the job that keeps them fresh:

    cron.status=enabled
    cron.1.status=enabled
    cron.1.user=root
    cron.1.job.1.status=enabled
    cron.1.job.1.schedule=*/10 * * * *
    cron.1.job.1.cmd=syswrapper.sh refresh-walled-garden 1
    dnsmasq.walled_garden.1.status=enabled
    dnsmasq.walled_garden.1.site.1.allowed=www.example.net
    dnsmasq.walled_garden.1.site.2.allowed=example.com
    dnsmasq.walled_garden.1.site.1.restricted=ads.example.org

- The garden index is always `1`, and it is the firmware's `if_seq` argument
  (`refresh-walled-garden 1` → `/tmp/allowed.1.txt`, `/tmp/restricted.1.txt`).
- `allowed` and `restricted` are indexed **independently, both from 1**: `site.1.allowed`
  and `site.1.restricted` are two different sites.
- The order is a Java `Set`'s iteration order, not the operator's. The index is all there is.
- The whole block is emitted only when the **allowed** domain set is non-empty
  (`if (set.size() > 0)`), so a garden of restricted domains alone never reaches the device,
  although `RESTRICTED_DOMAIN_IN` is still pushed.
- The allowed set is wider than the operator's list: it also carries the hosts each enabled
  payment or social-login provider needs, and `images.unsplash.com` when the portal's
  background gallery is on.

**Which form arrives is a capability gate.** `ubntconf/jNUeeSBEuWe` emits an
`ipset.status=enabled` block with hash sets instead, and the caller is explicit:

    boolean bl8 = this.Gdhc.NvfcKfHPI(settings) && !hyFnQ2.supportIPSet();   // the cron job
    if (!hyFnQ2.supportIPSet()) { this.kCNoUwYXLXMAUl(stringBuilder, settings); }  // dnsmasq

`supportIPSet()` is `hasFirmwareCapability(0x40000)`; openUF sends `fw_caps 0x1110`, so the
`dnsmasq.walled_garden` form is what arrives, and claiming the bit would swap a working
encoding for one openUF does not implement.

What the firmware does with it (firmware-confirmed for U7LR 6.8.2, `/bin/walled_action.sh`):
`ubntbox` writes the names to `/tmp/allowed.1.txt` / `/tmp/restricted.1.txt`, then the
script flushes the three chains, runs `nslookup` over each name **twice** ("so we don't miss
any ip" — round-robin records), dedupes the IPv4 answers and appends
`--ip-dst … -j ACCEPT` / `--ip-src … -j ACCEPT` / `--ip-dst … -j DROP`. A failed lookup is
logged to `/tmp/walled_action.log` and skipped, leaving that site out of the garden
entirely. It runs on `ipready` and from the pushed cron job.

openUF: `guestportal.parse` reads both halves; `M._resolve` is the resolver seam
(`nslookup`, addresses taken only after the first `Name:` line, since the header gives the
resolver's own address in the same shape); `resolve_garden` asks each name twice like the
firmware and **keeps the last good answer** for a name that stops resolving, in
`state.json`'s `guest_wg_ips`. `inform._guest_wg_resync` re-resolves on the pushed cadence
(600 s) and rebuilds only when the address set moved, so
`sysconf.CRON_IN_DAEMON_PATTERNS` installs no crontab line for the job. The resolver seam
is hardware-confirmed on both boards; the enforcement is ⚠️ lab-validated only — no guest
client has reached a garden site through openUF.

### Connection tracking notifs (`STA_ASSOC_TRACKER`)

Without these notifs, Insights → AirView → Connectivity reads 0 % on Association,
Authentication, DHCP, DNS and Success with "Initial WiFi Connections (0)":
`GET /v2/api/site/<site>/wifi-connectivity` returns `total_attempts: 0`, an empty dataset
rather than failures. The roaming table on the same page is full, because the controller
derives roams from `sta_table` itself.

**The request.** Every `mgmt_cfg` carries `capability=notif,notif-assoc-stat` (built
unconditionally in `com.ubnt.service.config.GWoWvNEX`: `notif`, optional `fastapply-bg`,
then `notif-assoc-stat`).

**The servlet.** `devmgr/l/MiVjHefaf` branches on `inform_as_notif: true` before any stats
or capability handling. `notif_reason` takes the enum `devmgr/l/kuhBRF` (`event`, `cmd`,
`setparam`, `cmd-provision`, `cmd-upgrade`, `cli-upgrade`, `crashlog`, `recovery`,
`trace`). For `event`, `notif_payload.event_string` is tried against the device handler's
map, then `notif_payload.message_type` against a second map holding `STA_ASSOC_TRACKER` and
`BEACON_BLE_SCAN` (`devmgr/AxWM`). The reply is `{"_type":"noop"}` with **no `interval`**.

`STA_ASSOC_TRACKER` → `devmgr/w/a/AcrQJeJCScLn` fans out on `event_type` ∈
`association | success | failure | soft failure | fixup | sta_leave | sta_roam` (`htDMji`):

- `MiVjHefaf` (`metricsStaAssocEventHandler`) handles success, failure, soft failure, fixup
  and unknown, feeding the 5-minute stats (`sta_assoc_total`, `sta_auth_total`,
  `sta_dhcp_total`, `sta_wpa_auth_total`, `*_failures`). It reads `assoc_delta`,
  `auth_delta`, `wpa_auth_delta`, `ip_delta` (only if `ip_assign_type == "dhcp"`),
  `traffic_delta`, `auth_ts` with `getLong`/`getDouble` and the failure counts with
  `getInt`. Send every key.
- `lhuvxd` (`wifiConnectivityStaAssocTrackerEventHandler`) feeds the funnel through
  `wifiConnectionEventsService` into `unifi_stat.wifi_connectivity_event`. It needs `vap` to
  resolve to a `vap_table` entry whose `wlanconf_id` is not an "element" WLAN, and
  `auth_rssi` (or `avg_rssi`) ≥ −75 unless the event succeeded. **Success** means
  `event_type` is not `failure`, AND either (a) `soft failure` with
  `ip_assign_type == "roam"`, or (b) on a device with `supportTrafficStaTrackerEvents()`,
  `traffic_delta > 0` **and** `dns_responses > 0`, or (c) otherwise `dns_resp_seen == "yes"`.
  Failure causes map from `assoc_failures`, `auth_failures`, `wpa_auth_failures`,
  `radius_auth_status` (`success`/`failure`), `ip_failures` (DHCP_TIMEOUT),
  `traffic_failures`, `dns_resp_seen` (`yes`/`no`/`N/A`) and `dns_timeouts`.
- `eirJvdtm` (roam detection) consumes `association`, `sta_roam` and `sta_leave`; see
  [Roam reports](#roam-reports-association--sta_leave--sta_roam).

The deltas are **cumulative from `auth_ts`**: the controller computes authentication as
`wpa_auth_delta − assoc_delta`, DHCP as `ip_delta − wpa_auth_delta`, and total latency as
`traffic_delta`. A U6-IW takes success branch (b), so `traffic_delta` must be > 0 — a
`success` with `traffic_delta = 0` and `dns_responses = 2` left the funnel empty.
`vap_table[].bw` is not required (`getInt("bw")` tolerates its absence). Confirmed live on
the real UCG Ultra end to end, including `failure_reason: DHCP_TIMEOUT` from a
DHCP-request-without-lease. One device-only trap: OpenWrt's Lua formats `%d` through a
32-bit integer and raises on the millisecond `event_id` — use `%.0f`.

**hostapd side** (Archer C5, OpenWrt 25.12, hostapd ubus), one deauth + reconnect:

    5905612.55 { "disassoc": {"address":"…","ifname":"phy1-ap0"} }
    5905613.20 { "auth": {"address":"…","ifname":"phy1-ap0","target":"<bssid>","signal":-64,"freq":2412} }
    5905613.25 { "assoc": {"address":"…","ifname":"phy1-ap0","target":"<bssid>","signal":-62,"freq":2412} }
    5905613.32 { "sta-authorized": {"address":"…","ifname":"phy1-ap0","auth-alg":"open"} }

These are subscriber notifications (`ubus subscribe`, not `listen`). `sta-authorized`
coincides with `AP-STA-CONNECTED` and follows `EAPOL-4WAY-HS-COMPLETED`. `auth-alg` is the
802.11 algorithm (`open` for WPA2-PSK, `ft` for a fast roam). Nothing past the handshake is
visible to hostapd, so the DHCP/DNS evidence comes from nft (see USAGE.md).

**nft facts this relies on** (nft 1.0.9, kernel 6.12, real frames through a veth bridge):

- `add @set { ether saddr }` on an existing element does **not** refresh its timeout.
- Text listing prints `expires 1m52s974ms`; `-j` rounds to whole seconds.
- `destroy element` ignores a missing element (nft ≥ 1.0.8, kernel ≥ 6.3). Both APs run
  nft 1.1.6 on 6.12.94.
- A bare `nft -f` of a table body appends a second copy of every rule.
  `table X` / `delete table X` / `table X { … }` in one file is idempotent.

### Roam reports (`association` / `sta_leave` / `sta_roam`)

Without them, Insights → AirView → Roaming lists every event as "Roaming / Success" with no
failed roam and no Fast Roaming, Roaming Assistant or Minimum RSSI tag.

`WIFI_ROAMING` documents in `unifi_stat.wifi_connectivity_event` come from
`wifi/connectivity/c/AcrQJeJCScLn` (`wifiRoamingService`) by two paths:

1. **sta_table path.** A client's `ap_mac` changing between two heartbeats. It runs only
   when either AP lacks `supportsRoamTopologyStats()` = `hasWifiCapability2(8192)`
   (`wifi_caps2` `0x2000`), always writes `successful=true`, and its tags come only from the
   cache path 2 fills, so they are null for a device that sends no notifs.
2. **Tracker path** (`devmgr/w/a/eirJvdtm`, `wifiRoamingDetector`). It runs on
   `STA_ASSOC_TRACKER` notifs, keeps the last event per (site, client) in a Caffeine cache
   for **10 s**, and pairs a departure from one AP with an arrival at another, in either
   order:
   - `sta_leave` (`QnvUxbsXyAJZ`/`gyWdIcvdh`): reads `vap`, `mac`, `avg_rssi` (`getInt`,
     required), `assoc_status`, `last_seen`. It also tells `staManager` the client left:
     when the client is still filed under this AP and BSSID it is disconnected there at
     `receive_time - (last_inform_uptime - last_seen)`.
   - `sta_roam`: the same fields, processed **only if the sender claims `0x2000`**.
   - `association`: `vap`, `mac`, `auth_rssi` (dropped without it), `auth_algo`.
   - `fast_roaming` = `auth_algo == "ft"`. `assoc_status` bits (enum `VVyiC`): `16`
     KICKED_DUE_TO_MIN_RSSI, `8192` MOVED_DUE_TO_ROAMING_ASSISTANT.
   - `successful` = the departure was `sta_roam`, OR arrival minus departure ≤ 1000 ms.
     Both times are the controller's **receive time in whole seconds**, so a departure that
     arrives after the arrival is a negative gap and therefore a success. Otherwise a failed
     roam with `disconnect_duration` = the gap.
   - Both ends must resolve `vap` against the sender's `vap_table` and share a
     `wlanconf_id`, and the two APs must differ.
   - Without `0x2000` the funnel handler (`lhuvxd`) also feeds every funnel `success` into
     the tracker as an arrival.

`0x2000` has exactly these three callers (sta_table path, `sta_roam` gate, funnel feed).
Claiming it without sending the reports would make roams vanish; sending the reports
without it would record every roam twice. openUF does both or neither (`assoc_tracker`).

BZ2 4.0.15 has only the old success/failure tracker — the three event types are newer than
any readable build — but it does show how a UniFi AP knows a station left: its hostapd
broadcasts an `iapp_key`-wrapped RRB frame on each association and the old AP drops the
station (see [802.11r key holders](../PROTOCOL-VALIDATION.md#80211r-key-holders-iapp_key)). OpenWrt has no such
message, and hostapd keeps a roamed-away station listed until its inactivity timer or
missing ACKs drop it, **6–40 s later** on both boards — outside the 10 s window. The signal
openUF uses instead is the old AP's bridge learning the station's address on its uplink when
the new AP's hostapd announces it, which lands in the same second as the roam.
`bridge monitor fdb` piped through a shell `read` loop delivers each line within 10 ms on
both boards; the Archer C5's own timestamps are garbage (`-16843009 usec`), so the collector
stamps lines with `/proc/uptime`. DSA repeats each entry as `self`, and a VLAN-aware bridge
repeats it with `vlan 1`.

openUF (`assoctrack.lua`):

- `association` once hostapd reports `sta-authorized`, with the `assoc` notification's
  `signal` as `auth_rssi` and `auth-alg` as `auth_algo`. A failed handshake is no arrival.
- `sta_leave` on hostapd's `disassoc`, with the heartbeat's signal as `avg_rssi`, the
  event's uptime as `last_seen`, and `assoc_status` from a 60 s ledger that Minimum RSSI
  (16) and Roaming Assistant (8192, at the BTM request and at the disassociation) write
  before they act. Not sent for a station that moved to another BSS of the same AP.
- `sta_roam` when the station's address is learned on a port that is not one of this AP's
  BSSes while hostapd still lists it; hostapd's later drop is not reported again.
- The inform loop wakes every 250 ms to read the collector's file and sends a roam report
  at once — the heartbeat's 10 s would put a departure up to 10 s ahead of its arrival. The
  poll costs 3 CPU ticks per 30 s on the Archer C5.

Live-confirmed on the real UCG Ultra with both APs reporting `wifi_caps2` `0x2060`: a
20 s ban produced **Failed Roaming** between the named APs; a band change within one AP
produced none, as on a UniFi AP; a BTM-driven silent departure paired through the
fdb-triggered `sta_roam` as **Roaming … Success**; an FT roam stored `fast_roaming: true`;
a Roaming-Assistant steer stored `triggered_by_roaming_assistant: true`. ⚠️ Not seen live:
the Minimum RSSI tag (unit tests and lab payloads only).

**10.6's roam fallback** (not in 10.4.57). `wifi/connectivity/c/rGUtaVWZlySeOK` holds every
client move inferred from heartbeats for 15 s (the tracker's 10 s + 5), keyed on (site,
client, new AP), and re-emits one the tracker did not confirm as `rFCHnXVpfjjP`, which
writes a sta_table-path roam **with no `0x2000` check**. An old AP that keeps listing a
roamed-away station therefore produces a duplicate record. openUF leaves a station out of
its heartbeat from its `sta_roam` until hostapd drops it, unless the station is heard from
on this AP after the move (`assoctrack.roamed_away`). Unit-tested; live roams after the fix
produced no copy, but the long-listing case has not recurred on hardware.

---

## `system_cfg`: the real config channel

**A real controller never sends `resp.vap_table` / `radio_table` / `network_table` as JSON.**
All device configuration — WiFi, radios, IP settings, per-port VLAN, minimum RSSI — arrives
inside the flat, OpenWrt/hostapd-style `system_cfg` key=value blob on a `setparam`.
`inform.lua`'s `M._parse_wifi_system_cfg()` translates it into the `{radio_table, vap_table}`
shape `ucihelper.apply_config()` expects.

Conventions throughout: booleans are `"enabled"`/`"disabled"` (sometimes `"true"`/`"1"`), and
an **absent block means disabled** — there is generally no explicit `status=false`.

A line splits at its **first** `=`: keys never contain one, values may (a passphrase
`pass=word`, an SSID `a=b`).

**Provisioning is not driven by `cfgversion` alone.** A device reporting a stale or bogus
version sometimes gets an immediate full push and sometimes only `noop`s, indefinitely, even
across restarts and fresh random values; an empty string is ignored outright. The reliable
trigger is a real config change in the controller. A UI form that fails validation (e.g.
switching a 2.4-GHz-only WLAN to Manual, where Band Steering demands two bands) saves
nothing and pushes nothing, with no error beyond the form itself.

### `aaa.<n>.*` — per-SSID security

| Key | Meaning |
|---|---|
| `ssid` | SSID |
| `id` | The wlanconf Mongo ObjectId. **Must be echoed back** — see [`vap_table`](#vap_table-entry). |
| `wpa` | WPA protocol version (`2`/`3`). Stays `2` even for a WPA2/WPA3 transition WLAN. |
| `wpa.psk` | Passphrase |
| `wpa.key.<k>.mgmt` | AKM set (`WPA-PSK`, `SAE`, …). **This**, not `wpa`, is what distinguishes SAE. |
| `pmf.status` / `pmf.mode` | 802.11w. `mode` is `0`\|`1`\|`2` (disabled/optional/required), 1:1 onto hostapd's `ieee80211w`. On this madwifi model, **WPA2/WPA3 transition intent is carried entirely by these fields** — dropping them silently collapses mixed mode to plain WPA2. |
| `pmf.cipher` | `AES-128-CMAC`. Not translated — hostapd's default BIP group-mgmt cipher already is this. |
| `ft.status` | Fast Roaming (802.11r) for the WLAN. No `mobility_domain`/`r0kh`/`r1kh` on the wire: UniFi firmware derives the mobility domain on the AP from the SSID, and openUF does the same (`ucihelper.derive_mobility_domain()`). The key-holder secret is `iapp_key`. |
| `iapp_key` | 32 hex chars, the wlanconf's `x_iapp_key`: 128 random bits per WLAN. Sent whenever `iapp_enabled` (default on), **whatever `ft.status` says**, with the same value on every radio's block. openUF writes it as the `r0kh`/`r1kh` key. See [802.11r key holders](../PROTOCOL-VALIDATION.md#80211r-key-holders-iapp_key). |
| `wpa.group_rekey` | GTK rekey interval in seconds, from wlanconf `group_rekey` (`getInt("group_rekey", 3600)`; forced to 0 for WDS and element WLANs), sent only in the WPA branch, so an open WLAN has none. REST allows 0 or 60–86400. UniFi firmware writes it to hostapd unchanged (`ubntbox`: `aaa.%d.wpa.group_rekey` → `wpa_group_rekey=%d`, firmware-confirmed for 4.0.15). → OpenWrt `wpa_group_rekey` (hostapd's default when unset: 86400). Hardware-confirmed: every BSS on both APs ran `wpa_group_rekey=3600` after the WLANs were set to 3600. |
| `11k.status` | `enabled`/`disabled` on every WLAN, from wlanconf `rrm_enabled` (`is("rrm_enabled", false)`, ungated by security). No UI control in 10.6, so set it over REST. UniFi firmware runs `iwpriv <ath> rrm 0\|1` and, after applying wireless config, `syswrapper.sh 11k-boot <radios>` (2 scans in a 5-minute window, `elevenk_sched 300 2 init`) or `11k-stop`, filling the driver's neighbor table (firmware-confirmed for 4.0.15). → OpenWrt `ieee80211k` (+ `rrm_neighbor_report`/`rrm_beacon_report`, which default to it in both `ap.uc` and `hostapd.sh`); off leaves all three at OpenWrt's default 0. Band Steering's override keeps them at 1 regardless. Not reproduced: the OpenWrt side of the boot scan — hostapd's `rrm_nr_list` holds the other AP's same-SSID BSSes only because usteer fills it. |
| `wpa3.ft.status` | FT for the **SAE akm alone**, separate from `ft.status`, from `isWpa3SaeFastRoamingEnabled()`. Emitted unconditionally on any SAE push (the first key `OXMua` writes) and absent otherwise. OpenWrt has one `ieee80211r` switch feeding hostapd's `key_mgmt`, and on `sae-mixed` it yields FT-PSK **and** FT-SAE together, so openUF enables FT if *either* toggle asks and logs the disagreement. Forced to `disabled` unless the radio claims `radio_caps2` bit `0x2` (see [Capability bitmasks](#capability-bitmasks)). |
| `bss_transition` | 802.11v. Present on every band's block, flips independently of Fast Roaming. |
| `br.devname` | `br0` untagged, **`br0.<vlan>`** when the WLAN is on a VLAN network. This suffix is the *only* per-WLAN VLAN signal; there is no `network_table`/`networkconf_id` join anywhere in the wire format. |
| `sae.anti_clogging` / `sae.sync` | Plain integers, emitted only when > 0 **and** the WLAN is genuinely WPA3 (see below). → hostapd's `sae_anti_clogging_threshold=` / `sae_sync=`, which 6.8.2 `ubntbox` writes the same way; neither is a wifi-iface option, so they go through `hostapd_bss_options`. |
| `sae.has_groups` + `sae.groups.<k>.group` | The site's `sae_groups`, as hostapd's `sae_groups=` list (raw, same reason). |
| `sae.psk.<k>.{psk,mac,vlan,id}` | **SAE station keys** (emitter `XWWFgnDBrNRLQZ`, wlanconf `sae_psk`). An entry with `mac=ff:ff:ff:ff:ff:ff` is the WLAN's own key — on a WPA3-only WLAN it is sent here instead of `wpa.psk`, and openUF skips it; the others are station-bound (`mac` absent = any station), `vlan` ≥ 1, with `dynamic_vlan` 2 when `sae_psk_vlan_required`. The firmware writes `sae_password=<key>[\|mac=][\|vlanid=][\|id=]`; openUF writes a `wifi-station` section with `mac`/`vid`, deduped against the `psk_file` private keys, and bridges each VLAN as the PPSK path does. |
| `auth_cache` | Opportunistic key caching, from wlanconf `auth_cache` — `is("auth_cache", true)`, so **default enabled**. REST-only. Emitted **only in the generator branch that also writes `wpa.key.1.mgmt` + `wpa.psk`**, and only ever seen on a WPA-Enterprise WLAN: a WPA2-PSK WLAN's `aaa` block carries no `auth_cache`, consistent with OKC being an 802.1X notion. → OpenWrt `okc` (schema-confirmed on 25.12; `ap.uc`'s own default is on for sae/owe and for FT). |
| `tdls_prohibit` | Forbid direct station-to-station (TDLS) links, from wlanconf `tdls_prohibit` (REST-only), default disabled, on **every** `aaa` block. → OpenWrt `tdls_prohibit`, 1:1 (schema-confirmed on 25.12). |
| `country_beacon` | Advertise the regulatory domain in beacons (the 802.11d Country IE), from wlanconf `country_beacon` — `is("country_beacon", false)`, REST-only, on every `aaa` block. OpenWrt's `ieee80211d` is a **wifi-device** option, so openUF folds the per-BSS key to one setting per radio: any WLAN asking for it turns it on. The element advertises, it does not restrict, so the permissive fold costs the other WLANs nothing. **On 5 GHz openUF always writes `ieee80211d='1'`** whatever the controller says — see the outage note below. |
| `wpa.1.pairwise` | The pairwise cipher the controller chose, from wlanconf `wpa_enc` through `com.ubnt.i.b.aL.kYktyHCkPVCBdJC`: the enum is `{auto, ccmp, gcmp, ccmp-256, gcmp-256}`, `auto` becomes `CCMP` (or `TKIP CCMP` on a WPA1 WLAN), every other value is upper-cased. `ccmp`, `ccmp-256` and `gcmp` reach the wire; **`gcmp-256` is refused by the controller's own validator** and normalised back to `auto`, on both PSK and EAP WLANs. → the second `+` token of OpenWrt's `encryption` (`psk2+gcmp`), which is where `iface.uc` reads a cipher from. `CCMP` deliberately writes nothing: it is `iface.uc`'s own final default. `TKIP CCMP` is declined — WPA1 only, which openUF never maps, and TKIP is forbidden by WPA2/WPA3 certification. **Gated on the radio's cipher suites** — see below. |
| `driver` | `madwifi` — the controller is talking to this model as madwifi-era firmware, which explains several value encodings here. |

A VLAN assignment also produces companion `vlan.*`, `bridge.*` and `netconf.*` blocks.
**The `bridge.*` block is a specification, not decoration.** Captured when a WLAN was put on
VLAN 20:

```
bridge.1.devname=br0            bridge.2.devname=br0.20
bridge.1.port.1.devname=eth0    bridge.2.port.1.devname=ath2      ← the vap
bridge.1.port.2.devname=ath0    bridge.2.port.2.devname=eth0.20   ← the tagged uplink
bridge.1.port.3.devname=ath1    bridge.2.stp.status=disabled
```

That second bridge is exactly the L2 a tagged SSID needs, and openUF must build the
equivalent (`br-openuf<vlan>` holding `<cpueth>.<vlan>`, with the VAP joined to it). Skipping
it yields a VAP and an uplink sub-device that are both up and completely unconnected: the
client associates and gets no DHCP, no gateway, nothing, while UCI, netifd and hostapd all
look correct.

`netconf.*` blocks are per-device-interface and stay anchored: the AP's own IP settings
remain at `netconf.1` (`devname=br0`) with a VLAN's entries taking later indices, so
`inform.lua`'s `^netconf%.1%.` anchor is safe against a VLAN being added.

**SAE gating.** `com.ubnt.service.config.ubntconf.OXMua`'s emitter is capability-gate-free:

```
n = wlan.getInt("sae_anti_clogging", -1); if (n > 0) emit "aaa.<idx>.sae.anti_clogging" = n
s = wlan.getInt("sae_sync", -1);          if (s > 0) emit "aaa.<idx>.sae.sync" = s
```

but is only *called* when `wlan.isWpa3() || wlan.isOn6GHzBand()`. `isWpa3()` reads the DB flag
`wpa3_support`, which the "WPA2/WPA3" dropdown **does** set (`wpa3_support: true`,
`wpa3_transition: true`, `pmf_mode: optional`), so the WLAN-side gate passes on a mixed WLAN;
what suppresses the whole SAE block is the *per-device radio* capability check in the WPA3
section. openUF maps both to hostapd's `sae_anti_clogging_threshold` / `sae_sync` through
`hostapd_bss_options`: neither is a wifi-iface UCI option, and the radio-level
`hostapd_options` is ignored for a BSS.

**A pairwise cipher must be gated on the radio, not on the band or the board.** `iw` 6.17 on
25.12 prints no Supported Ciphers block, so openUF reads the suites from nl80211 directly
(`ucode -l nl80211`, `NL80211_CMD_GET_WIPHY` → `cipher_suites`, IEEE 802.11 Table 12-4's
`0x000FAC<n>`). Read on hardware:

| Board | 2.4 GHz phy | 5 GHz phy |
|---|---|---|
| Archer C5 v1 (ath9k + ath10k) | CCMP, CCMP-256, GCMP, GCMP-256 | **CCMP only** |
| Xiaomi AX3000T (mt76) | CCMP, CCMP-256, GCMP, GCMP-256 | CCMP, CCMP-256, GCMP, GCMP-256 |

The Archer C5 is the case that matters and not what anyone would guess: its *older* ath9k
2.4 GHz radio has GCMP and its newer ath10k 5 GHz radio does not. hostapd treats a pairwise
cipher the driver cannot program as fatal, so writing `psk2+gcmp` on that 5 GHz BSS takes the
WLAN off the air — strictly worse than the default CCMP. openUF keeps the default and logs
the refusal. Where two radios serve one band the band's set is the **intersection**; an
unknown or failed probe never vetoes, like every other clamp.

**`ieee80211d='0'` on a 5 GHz radio is a production outage.** `hostapd.uc`'s
`device_country_append()` emits `ieee80211h` for **every** radio with `hw_mode == 'a'` and a
country (deleted only for `hw_mode != 'a'`, and the schema defaults it to `true`), while
`ieee80211d` is emitted only when truthy. hostapd then refuses the interface outright:

```
Cannot enable IEEE 802.11h without IEEE 802.11d enabled
hostapd.add_iface failed for phy phy0 ifname=phy0-ap0
```

— no SSID on the air and nothing in UCI to explain it. Three things to carry forward:

- **A gate check must include the consumer's cross-constraints, not just the option.** That
  `ieee80211d` exists in the schema and the generator emits it was both true; hostapd's rule
  relating it to another option was the gap.
- **The failure is delayed**: it appears at the next `wifi reload`, not at the push that
  writes the option, so UCI and `hostapd-phy*.conf` read clean, consistent and wrong straight
  after a provision. For anything that can keep an interface from starting, the check is
  `iw dev` showing an SSID and a channel, not the config file.
- **Unknown band counts as 5 GHz.** `band_for_device` falls back to `band_for_channel`, which
  answers `"na"` when it cannot tell; guessing "2.4 GHz" costs a radio.

openUF writes `ieee80211d='1'` on any 5 GHz radio regardless of `country_beacon` (repairing a
radio an earlier version left at `0`), honours "off" on 2.4 GHz only, and logs `Country IE
off is not applicable on 5 GHz` once. Hardware-confirmed on the AX3000T: `phy1-ap0` back on
channel 100 at 80 MHz, `ieee80211d=1` beside `ieee80211h=1` — a DFS channel, precisely the
case 802.11h exists for.

**Three keys on this block are declines, each for a named reason** (10.6.106 generator
`com.ubnt.service.config.VAZShipWTNxlo`):

- `wireless.<n>.wmm` — a hardcoded `"enabled"` **string literal** in the generator's
  62-element `wireless.<n>` array, not read from the wlanconf at all. OpenWrt has no
  `wmm_enabled` in `wireless.wifi-iface.json` either, and hostapd defaults it on for any
  HT/VHT/HE BSS.
- `aaa.<n>.eapol_version` — derived, not configured: `securityProtocol.eapolVersion()` is `1`
  for `wpa_mode=wpa1` and `2` for everything else. openUF maps no security value to WPA1, so
  the only value it can receive is `2`, hostapd's own default.
- `aaa.<n>.p2p` and `aaa.<n>.p2p_cross_connect` — genuine settings (wlanconf `p2p` /
  `p2p_cross_connect`, default disabled, lab-confirmed to flip on the wire), but there is no
  consumer: hostapd's `manage_p2p` / `allow_cross_connection` are absent from the OpenWrt
  25.12 binary (built without `CONFIG_P2P_MANAGER`) and from the netifd schema, and writing
  them as raw BSS lines would make hostapd reject its own config file. Revisit only if an
  OpenWrt release ships the P2P manager.

### `aaa.<n>.radius.*` — WPA-Enterprise (802.1X)

Emitter: `com/ubnt/service/config/VAZShipWTNxlo`. Consumer on a genuine AP: the hostapd
generator inside `sbin/ubntbox` (firmware-confirmed for U7LR 6.8.2), which writes
`auth_server_addr`/`auth_server_port`/`auth_server_shared_secret`, the `acct` twins,
`radius_acct_interim_interval`, `dynamic_vlan` and `nas_identifier` from exactly these keys.
**The eligibility filter (`ubntconf/LsyaJoEysWb`) applies no device capability gate to a
WPA2-Enterprise WLAN**, so a controller has always been pushing this to openUF. (A capture
taken from a site with no RADIUS profile shows the block simply absent — the recurring trap
of treating a block's absence as the discriminator.)

| Key | Meaning |
|---|---|
| `radius.auth.<k>.{ip,port,secret}` | Authentication servers, 1-based, in the RADIUS profile's order. Port defaults to 1812. |
| `radius.acct.<k>.{ip,port,secret}` | Accounting servers, same shape. Port defaults to 1813. Present only with `accounting_enabled`. |
| `radius.{auth,acct}.<k>.{ca_cert,client_cert,private_key,private_key_passwd}` | RadSec. There is **no `.tls` key**. The emitter writes only certificate *filenames*, for files transferred by another channel, and only when the device claims `fw2_caps` `0x80000`; their presence is therefore the entire discriminator between a RadSec server and a plaintext one. openUF drops such a server with a log rather than sending its shared secret in the clear. |
| `interim_update.status` / `.interval` | Interim accounting updates; interval in seconds (default 3600). |
| `dynamic_vlan` | `0`/`1`/`2` from the profile's "RADIUS assigned VLAN" mode (off / optional / required). |
| `nas_identifier` | The profile's NAS id, when set. |
| `radius.das.{status,port,client,secret}` | **RADIUS Dynamic Authorization** (CoA / Disconnect), gated on `fw_caps` `0x100000` AND (`radius_das_enabled` OR `hotspot2conf_enabled`) AND the profile's `accounting_enabled`. The client address and secret are the **first accounting server's**, written once, and the port is `3800 + the WLAN's section index`. See [below](#radius-mac-authentication-and-dynamic-authorization). |
| `radius.dad.*` (`aaa.radius.dad.{status,port}` + `aaa.<n>.radius.dad.client.<k>.{cidr,secret}`) | The second DAS shape, **declined**: the firmware turns it into `radius_das_client=127.0.0.1`, accepting the request from its own daemon, which relays it after checking the CIDR. hostapd pointed at localhost would answer nobody, and `das.*` carries the same information. |
| `radius.macacl.{status,format,emptypassword}` | RADIUS **MAC authentication**, a separate control from the MAC Address Filter — and from WPA-Enterprise: `glUEhxTYZtqmhf.is("radius_mac_auth_enabled")` has **no capability bit and no security-type condition**, so it arrives on an open or PSK WLAN as readily as an EAP one, with the whole `radius.auth.<k>.*` block beside it. `status` becomes hostapd's `macaddr_acl=2`. `format` (a printf string, enum `none\|hyphen\|colon` × `lower\|upper`) and `emptypassword` are **declined, no consumer**: `macaddr_format=` and `mac_acl_empty_passwd=` are options of UniFi's *patched* hostapd and neither string occurs in OpenWrt's binary on either board, which always sends lower-case colon-separated. |
| `filter_id` | RADIUS `Filter-Id` handling, behind `fw_caps` `0x20000000` (unclaimed). Never captured — it needs a RADIUS profile variant that has not been built. |

Captured in the lab (10.6.106; a `wpaeap` wlanconf with two auth servers, one acct server,
interim updates at 900 s and `vlan_wlan_mode: required`; addresses in the documentation
range):

```
aaa.1.wpa=2
aaa.1.wpa.key.1.mgmt=WPA-EAP
aaa.1.wpa.psk=letmeinnow
aaa.1.radius.auth.1.ip=192.0.2.10     aaa.1.radius.auth.1.port=1812
aaa.1.radius.auth.1.secret=…          aaa.1.radius.auth.2.ip=192.0.2.11
aaa.1.radius.auth.2.port=1812         aaa.1.radius.auth.2.secret=…
aaa.1.radius.acct.1.ip=192.0.2.10     aaa.1.radius.acct.1.port=1813
aaa.1.radius.acct.1.secret=…          aaa.1.interim_update.status=enabled
aaa.1.interim_update.interval=900     aaa.1.dynamic_vlan=2
aaa.1.radius.macacl.status=disabled   aaa.1.hs20.status=disabled
wireless.1.security=none
```

Two decoys in that block, both pinned by tests:

- **`aaa.<n>.wpa.psk` is still sent on an EAP WLAN** — `letmeinnow`, a dummy the controller
  fills in. Carrying it into UCI would give the BSS a passphrase it must not have, so openUF
  forces `x_passphrase = nil` on an Enterprise WLAN and refuses to write a `key` for any
  encryption outside an explicit pre-shared-key allow-set.
- **`wireless.<n>.security=none` on the same push.** The discriminator is
  `aaa.<n>.wpa.key.<k>.mgmt`, as it is for SAE.

OpenWrt side, read on an Archer C5 (25.12, `wpad-mbedtls`, hostapd v2.12-devel). On 25.12
`/lib/netifd/wireless/mac80211.sh` is itself a ucode script importing `wifi.iface`, so
`/usr/share/ucode/wifi/` is the live generator and `hostapd.sh` is dead weight. Calling the
generator's own `parse_encryption()`/`wpa_key_mgmt()` on the device:

| UCI `encryption` | `auth_type` | `wpa` | pairwise | `wpa_key_mgmt` (with 802.11r) |
|---|---|---|---|---|
| `wpa2+ccmp` | `eap` | 2 | CCMP | `WPA-EAP` (`+ FT-EAP`) |
| `wpa3` | `eap2` | 2 | CCMP | `WPA-EAP-SHA256` (`+ FT-EAP`) |
| `wpa3-mixed` | `eap-eap2` | 2 | CCMP | `WPA-EAP-SHA256 FT-EAP WPA-EAP` |
| `wpa3-192` | `eap192` | 2 | GCMP-256 | `WPA-EAP-SUITE-B-192` (`+ FT-EAP-SHA384`) |
| `eap` | `eap` | **0** | — | — |

That last row is the trap: `encryption=eap` sets the right `auth_type` and then matches no
`config.wpa` wildcard, so the BSS comes up with `wpa=0` — an open network where an Enterprise
one was asked for. openUF maps the four working values and never that one.

`ap.uc`'s EAP branch writes `ieee8021x=1`, `eapol_version`, the key-mgmt list and (unless
`eap_server` is set) calls `iface_authentication_server()`/`iface_accounting_server()`
itself, so openUF writes none of those — only the server options, the interim interval, the
NAS id and `dynamic_vlan`. It also sets `vlan_possible = 1`, which is what makes
`dynamic_vlan` reach hostapd at all. `iface_ppsk()` is gated to non-EAP auth types, so an EAP
VAP's `auth_server_addr` is not re-consumed by the PPSK path.

Two schema limits, stated as narrowings in USAGE.md rather than worked around:
`auth_server_port`/`auth_server_shared_secret` are written **once** per server list, so a
server with its own port or secret cannot be expressed and is dropped with a log; and openUF
writes no `wifi-vlan` section for a RADIUS-assigned VLAN (the push enumerates none), so with
`dynamic_vlan=2` hostapd refuses a station assigned a VLAN this AP has no network for. The
schema's `auth_server`/`auth_port`/`auth_secret`/`acct_interval`/`nasid` are `"type": "alias"`
entries; openUF writes the canonical names `ap.uc` reads literally.

`radio_caps2` `0x4` (WPA3-Enterprise-192) stays **unclaimed** — see
[Capability bitmasks](#capability-bitmasks). WPA3-Enterprise needs only the SAE bit `0x1`;
WPA2-Enterprise needs no bit at all.

### RADIUS MAC authentication and Dynamic Authorization

Both are settings of a WLAN's RADIUS profile and **neither needs the WLAN to be
WPA-Enterprise** (emitter `com/ubnt/service/config/VAZShipWTNxlo`, `:639` and `:567`). The
firmware's own map names its hostapd output directly (U7LR 6.8.2 `sbin/ubntbox`):

```
aaa.%d.radius.das.port             -> radius_das_port=%u
aaa.%d.radius.das.client/.secret   -> radius_das_client=%s %s
aaa.%d.radius.dad.client.%d.secret -> radius_das_client=127.0.0.1 %s
aaa.%d.radius.macacl.status        -> macaddr_acl=2
aaa.%d.radius.macacl.format        -> macaddr_format=%s
aaa.%d.radius.macacl.emptypassword -> mac_acl_empty_passwd=%d
```

The OpenWrt consumers, read off the live 25.12 generator (`ap.uc`, identical on both boards):

- `macaddr_acl` is **not a wifi-iface option** — absent from
  `/usr/share/schema/wireless.wifi-iface.json`, and the only producers are
  `iface_macfilter()` (`allow` → 1, `deny` → 0) and `ppsk` → 2. So it goes in through
  `hostapd_bss_options` (raw lines appended last). `ppsk=1` would also set it, but in
  `case 'psk'` it additionally sets `wpa_psk_radius=2` and leaves the passphrase out — that is
  UniFi's *Private PSK* feature, not MAC auth, and would make the WLAN unjoinable.
- `iface_authentication_server()` is called **only** from the EAP branch and from
  `iface_ppsk()`, so on an open/PSK/SAE BSS the `auth_server_*` options are stored and dropped.
  `iface_accounting_server()` is called unconditionally, so `acct_server_*` is fine as an
  option. openUF therefore writes the auth servers raw on a non-EAP WLAN and through UCI on an
  EAP one.
- `radius_das_client` and `radius_das_port` are in `ap.uc`'s unconditional `append_vars` list,
  **but the join** `radius_das_client = client + ' ' + secret` (with
  `set_default(radius_das_port, 3799)`) sits inside `case 'eap'`, and `radius_das_secret` and
  its `dae_secret` alias are in the schema with no other consumer — the stored-and-dropped
  shape. openUF joins the two itself, which is both what the firmware writes and what hostapd
  parses (first token the address, the rest of the line the secret), and always writes the port
  explicitly because hostapd's own default is 0 = no listener. Splitting them into two options
  instead, which is what the schema invites, gives `Line 10: invalid DAS client` and hostapd
  refuses the interface: the join is load-bearing.

**MAC authentication fails closed.** A WLAN that asks for it and cannot have it (no usable
RADIUS server, or a `wpad` with no RADIUS client) is **dropped**, not provisioned without it:
it is an access control, and on an open WLAN it is the only one. The RADIUS-client check is not
cosmetic either — on a basic `wpad`, `auth_server_addr` is an unknown option and hostapd
refuses the whole config, so the BSS would not come up anyway.

`aaa.<n>.dynamic_vlan` on a non-EAP WLAN is **declined**: `2` (required) with no `vlan_file`
makes hostapd reject every station, and openUF writes no `wifi-vlan` sections for
RADIUS-assigned VLANs.

### `aaa.<n>.accept_mac.*` — MAC-based VLANs

The controller's per-**client** "Virtual Network Override": a client set to another network
lands on that network's VLAN whatever SSID it joins. The emitter
(`com/ubnt/service/config/ubntconf/fdwW`) reads every `user` object carrying
`virtual_network_override_enabled`, groups them by `virtual_network_override_id`, and writes
the whole site's map to **every** WLAN index:

```
aaa.<n>.accept_mac.status=enabled       (once, before the first entry)
aaa.<n>.accept_mac.<k>.mac              aaa.<n>.accept_mac.<k>.vlanid
switch.vnet.<n>.{name,vlan,mac.<k>}     (the same map for a switch identity)
```

`status` is **not** the discriminator and openUF does not read it: the writer emits it from
inside the loop that writes the first entry, so it is present exactly when entries are. The
entries are the whole signal. The override network must be a *corporate* network — the
controller refuses a VLAN-only one with
`api.err.NetworkAssignedAsVlanOverrideIsNotCorporate`.

**Two gates, the second site-wide.** `supportsMacBasedVlans()` = `fw_caps` `0x80000000`, and
beside it `com/ubnt/service/bz/bWpcUrDmeyjdNnrWeZ` requires **both**: a device that `isUbios()`
and either claims the bit or is one of 23 listed gateway models (`UDMPRO`, `UDMPROMAX`, `UXG`,
`UDMPROSE`, `UDW`, `UDM`, `UDR`, `UDRULT`, `UDMA67A`, `UDMA6B7`, `UDMA6B9`, `UCGMAX`, `UXGB`,
`UDMENT`, `UXGENT`, `UXGA6AA`, `UDMA6A8`, `UX`, `UDMA69B`, `UDMA6B4`, `UDMEA39`, `UDMEA4B`,
`UDMA6AD`); and an **empty** set difference between {devices with the `ACCESS_POINT` or
`SWITCH` feature and `HAS_CLIENTS`, minus 11 excluded switch models} and {devices claiming the
bit}. So one AP without the bit switches the feature off for every client in the site.

**The consumer is hostapd's accept-MAC list**, whose lines take an optional VLAN id after the
address (read out of hostapd v2.12-devel, the build both APs run):

- `hostapd/config_file.c:hostapd_config_read_maclist()` parses `<mac>[ \t]<vlan_id>` per line,
  `#` comments, a leading `-` removing an entry.
- `src/ap/ieee802_11_auth.c:hostapd_check_acl()` consults `accept_mac` **first, before
  `macaddr_acl` is looked at**, and a match returns `HOSTAPD_ACL_ACCEPT` carrying the VLAN; an
  unlisted station falls through to the `macaddr_acl` default. So an accept file on its own
  assigns VLANs without restricting access, which is exactly the feature.
  `hostapd_allowed_address()` keeps that VLAN for every mode but `USE_EXTERNAL_RADIUS_AUTH`,
  where `dynamic_vlan=0` clears it.
- `src/ap/ieee802_11.c:ieee802_11_set_radius_info()` then requires the VLAN to be in
  `conf->vlan` (`hostapd_vlan_valid`) or **refuses the station** — it does not fall back to the
  VAP's network. Hence a `wifi-vlan` section per VLAN, which `src/ap/vlan_init.c` confirms is
  created from `vlan_file` whatever `dynamic_vlan` says.

**Three ways in, because OpenWrt owns the same file for the MAC Address Filter**
(`ap.uc`'s `iface_macfilter`, which also has a `macfile` option appending an arbitrary file to
the one it writes):

| WLAN's MAC Address Filter | How openUF's entries reach hostapd |
|---|---|
| none | a raw `accept_mac_file=` line to openUF's own file. No `macaddr_acl` is emitted, so hostapd's default (accept-unless-denied) still admits unlisted clients |
| `allow` | the schema's `macfile`, appended by `ap.uc` to the accept file it writes from `maclist` — and openUF drops those addresses from `maclist`, so each appears exactly once. An override the allow list does not permit is skipped: adding it would widen the admin's whitelist |
| `deny` | the raw line again, minus any address on the deny list — the accept list is checked first and would otherwise let a denied client in |

`vlan_no_bridge` (which keeps hostapd out of the bridge netifd already built) sits behind
`vlan_possible && dynamic_vlan` in `iface_vlan`. `ap.uc` sets `vlan_possible` itself for every
psk/sae/eap auth type, so `dynamic_vlan=1` suffices there; on an **open or OWE** WLAN neither
is ever set, so openUF emits `vlan_no_bridge=1` raw.

**Refused outright on a WLAN with RADIUS MAC authentication**: `macaddr_acl=2` asks the server
about every client, and an accept-list entry returns ACCEPT before the question is asked. A
VLAN override is not worth bypassing an access control.

**The file is written before anything points at it.** An `accept_mac_file` naming a missing file
gives `MAC list file … not found` → `Failed to read accept_mac_file` → `Failed to set up
interface`, and so does one malformed line (`Invalid MAC address 'not-a-mac 20' at line 2`).
Either takes the WLAN off the air, so on a write failure openUF abandons the plan and
provisions the WLAN without the overrides, and every address is validated at the parser.

**The leading newline in openUF's file is load-bearing, and not for the obvious reason.**
`ap.uc` writes `join('\n', maclist)` with no terminator, so in the `macfile` case openUF's
first byte lands on the end of the last allow-list address. That does **not** fail:
`hwaddr_aton()` reads exactly six octets and ignores the rest, so the joined line is read as
that LAST address and the VLAN id is taken from after its first space — the mapped client's.
The allow-listed station would silently get the override and the intended one no entry at all.
openUF's file therefore starts with a blank line:

```
00:00:5e:00:53:09\n# openUF: MAC-based VLANs.\n00:00:5e:00:53:01 20\n
```

### `aaa.<n>.hs20.*` — Hotspot 2.0 / Passpoint

A WLAN with an embedded `hotspot2` object, pushed to an AP claiming `fw_caps` `0x800000` and
`fw2_caps` `0x80000`, carries 55 `aaa.<n>.hs20.*` keys plus `wireless.<n>.dgaf_disable`.
Emitter: `com/ubnt/service/config/VAZShipWTNxlo`. Three gates stand in front of it:

1. **`fw_caps` `0x800000`** — without it `ubntconf/LsyaJoEysWb` drops the WLAN from the AP's
   config entirely, so the push contains no `hs20` key.
2. **`fw2_caps` `0x80000`** — a *third* firmware capability mask, read by
   `hyFnQ.getFirmware2Capabilities()` from the field `"fw2_caps"`. The REST validator
   `com/ubnt/service/W/ctfbDsCjrxgkv` computes `supportsHotspot2Passpoint() =
   supportHotspot2() && supportsRadSec()` and refuses the WLAN with
   `api.err.DevicePasspointNotSupported`, so Passpoint cannot be reached without claiming
   RadSec. See [Capability bitmasks](#capability-bitmasks) for the trade.
3. **The profile must be an embedded object on the WLAN, not a reference.** `hotspot2conf_id`
   is not a `WlanConf` field and is silently dropped. The settings live in a `hotspot2` object
   inside the wlanconf, whose schema (`api/fields/WlanConf.json`) is a **subset** of the
   standalone `api/fields/Hotspot2Conf.json`.

That subset is the whole reachable keyspace. These keys exist in the emitter and **cannot be
made to arrive** on a WLAN, so openUF reads none of them: `hessid`, `anqp_domain_id`,
`network_auth_type`/`network_auth_url`, `t_c_filename`/`t_c_timestamp`, `osu_ssid`, `osu.*`,
`icon.*`, `gas_comeback_delay`/`gas_frag_limit`, `qos.map.*`/`qos.exception.*`. OSU and icons
are unimplementable anyway: the installed hostapd (`wpad-mbedtls`, v2.12-devel) has no
`osu_server_uri`, `osu_ssid` or `hs20_icon` option. `aaa.<n>.hs20.esr` does arrive but is
deliberately not read — `ap.uc` never emits `esr`, so a field for it would be a consumer with
no producer.

The captured block, verbatim apart from placeholder addresses (replayed in full by
`tests/test_inform_packet.lua`):

```
aaa.1.hs20.status=enabled              aaa.1.hs20.access_network_type=2
aaa.1.hs20.internet=enabled            aaa.1.hs20.asra=disabled
aaa.1.hs20.esr=disabled                aaa.1.hs20.uesa=disabled
aaa.1.hs20.venue_group=2               aaa.1.hs20.venue_type=8
aaa.1.hs20.disable_dgaf=disabled       aaa.1.hs20.deauth_req_timeout=60
aaa.1.hs20.network_availability=13     aaa.1.hs20.hs20_domain_name_list=example.com,example.net
aaa.1.hs20.venue_name.1.lang=eng       aaa.1.hs20.venue_name.1.name=openUF Lab
aaa.1.hs20.venue_name.1.url=https://example.com/venue
aaa.1.hs20.nai_realm.1.status=enabled  aaa.1.hs20.nai_realm.1.encoding=0
aaa.1.hs20.nai_realm.1.name=example.com
aaa.1.hs20.nai_realm.1.eap_method=13
aaa.1.hs20.nai_realm.1.eap_method.auth.1.id=5
aaa.1.hs20.nai_realm.1.eap_method.auth.1.val=6
aaa.1.hs20.1.roaming_consortium=506f9a aaa.1.hs20.2.roaming_consortium=001bc504bd
aaa.1.hs20.3gpp.1.mcc=230              aaa.1.hs20.3gpp.1.mnc=01
aaa.1.hs20.friendly_name.1.language=eng
aaa.1.hs20.friendly_name.1.text=openUF Operator
aaa.1.hs20.capab.1.protocol=6          aaa.1.hs20.capab.1.port=80
aaa.1.hs20.capab.1.status=open
aaa.1.hs20.metrics.status=enabled      aaa.1.hs20.metrics.info=1
aaa.1.hs20.metrics.downlink_speed=8000 aaa.1.hs20.metrics.uplink_speed=1000
aaa.1.hs20.metrics.downlink_load=80    aaa.1.hs20.metrics.uplink_load=40
aaa.1.hs20.metrics.measurement=3000
wireless.1.dgaf_disable=disabled
```

Key shapes, none of them the obvious one:

- The roaming-consortium index comes **before** the name (`hs20.<k>.roaming_consortium`),
  unlike every other indexed block here.
- `network_availability` is already the combined `(IPv4 availability << 2) | IPv6` octet
  hostapd wants as `ipaddr_type_availability`; the controller does the combining.
- `hs20_domain_name_list` arrives as one comma-separated string, which is also hostapd's
  `domain_name` format, so it passes through untouched.
- An MNC keeps the width it was sent with (`01` stays two digits, `002` three).
- `capab.<k>.status` is a word (`open`/`closed`/`unknown`) where hostapd wants `1`/`0`/`2`.
- `metrics.info` is a decimal on the wire and **hex in hostapd**: `hs20_wan_metrics`'s first
  field is parsed with `hexstr2bin()` over exactly two characters, so `1` must be written as
  `01`. A rejected line is a config *parse* error, and hostapd then refuses the whole BSS.

Consumer side, from `/usr/share/ucode/wifi/ap.uc` on an Archer C5 (25.12, `wpad-mbedtls`):
`iface_hs20()` is gated on `config.hs20` and `iface_interworking()` on `config.iw_enabled`,
which it turns into `interworking=1`. Two hazards make openUF write every cumulative list as
a raw `hostapd_bss_options` line instead of a UCI list option:

- `wifi.common`'s `append()` joins an array with **spaces** into one `name=a b c` line, which
  is not what `venue_name`, `nai_realm`, `roaming_consortium`, `domain_name`,
  `anqp_3gpp_cell_net`, `hs20_oper_friendly_name` or `hs20_conn_capab` means — each needs one
  line per entry.
- `iface_interworking()` contains `if (config.anqp_3gpp_cell_net) config.domain_name =
  join(',', config.anqp_3gpp_cell_net)`, i.e. it **overwrites** `domain_name` with the
  cell-net list.

Raw options are appended last by `generate()`, after every `append_vars()` call, so hostapd
reads them last. Confirmed end to end on an Archer C5: the wifi-iface section openUF
generates for the captured push, fed to the **device's own** ucode generator, produced
`interworking=1`, `hs20=1`, `hs20_wan_metrics=01:8000:1000:80:40:3000` and all fourteen raw
lines, and that config parsed on a real hostapd v2.12-devel with **zero** `Line N:` errors.
⚠️ No Passpoint client has associated, and no Passpoint WLAN exists on the production
controller.

A last consumer constraint shapes the parser: hostapd refuses `hs20=1` without
WPA2-Enterprise/CCMP ("HS 2.0: WPA2-Enterprise/CCMP configuration is required for Hotspot 2.0
functionality"), so openUF accepts an `hs20` block only on a WPA-Enterprise WLAN and logs the
drop otherwise.

### `wireless.<n>.*` — per-SSID radio binding and behavior

| Key | Meaning |
|---|---|
| `ssid`, `parent` | SSID, and the owning radio (`radio0`/`radio1`) |
| `dtim_period` | Plain integer, **always present** regardless of the WLAN's Auto/Custom DTIM toggle. There is no `dtim_mode`/`dtim_ng`/`dtim_na` key on the wire — go-unifi's band-split shape describes the REST API, not this protocol. |
| `no2ghz_oui` | **Band Steering's real wire representation.** Not a per-device `mgmt_cfg` field. Toggling Band Steering changes only this key, and only on the 2.4 GHz entry (the 5 GHz entry stays `disabled`). A madwifi/QCA convention: omitting the AP's OUI from 2.4 GHz beacons nudges dual-band clients toward 5 GHz. Mainline mac80211/hostapd has no equivalent, so openUF derives one device-wide `steering_active` boolean (true if *any* vap has it) and drives `usteer`, itself a device-wide daemon. |
| `mcast.enhance` | Multicast Enhancement / Multicast-to-Unicast. `0`\|`1`. |
| `uapsd` | **U-APSD** (WMM power save), from wlanconf `uapsd_enabled`, default `false`. `enabled`\|`disabled`, always present. UniFi firmware hands it to the driver unchanged (`ubntbox`: `iwpriv <ath> uapsd %d`, firmware-confirmed for 4.0.15), so `disabled` means off. → OpenWrt `uapsd` (hostapd `uapsd_advertisement_enabled`, OpenWrt default 1). Hardware-confirmed: all six BSSes ran `uapsd_advertisement_enabled=0` for the home WLANs' `disabled`. |
| `minrate_data`, `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status`, `minrate_below_disable`, `pureg` | **Minimum Data Rate Control.** `minrate_data` is the floor in kb/s; `beacon_rate`/`mgmt_rate` mirror it. `minrate_cck_rates.status` and `pureg` are derived consequences on 2.4 GHz (a 12 Mbps floor is OFDM, so CCK goes `false` and `pureg` goes `1`). `minrate_below_disable` is the separate "advertising rates" sub-toggle: on a UAP it becomes `iwpriv <ath> minrate_nobelow 1`, which makes the driver advertise only the legacy rates at or above the floor in beacons, probe responses and association responses (firmware-confirmed for 4.0.15, `umac.ko`: the setparam sets a VAP flag that `ieee80211_beacon_init`, `ieee80211_send_proberesp` and `ieee80211_setup_assocresp` check before swapping in the rate set `ieee80211_set_minrate_to_rateset_format` built; if no rate left in it is basic, `ieee80211_setminratebasicrates` makes the lowest one basic). That is openUF's `supported_rates` reading. The driver also trims the HT MCS set below the floor (keeping MCS 7/15/23), which OpenWrt has no option for. Emitted per band and **absent entirely** when that band's control is off — not band-gated. |
| `bcfilt.status`, `bcfilt.<k>.mac`, `bcfilt.<k>.status` | **Multicast Suppression**, Aggressive (REST `bc_filter_enabled`/`bc_filter_list`; once called "Multicast and Broadcast Blocker"). `status` appears whenever the control is on, including with an empty allow-list; the indexed entries only once it is non-empty. `<k>` is 1-based and does **not** follow the REST list's order, so the index means nothing beyond grouping. Emitted on both band entries. |
| `bcfilt.bypass_types` | The frame types the blocker must let through, as one literal string `ARP\|NSNA\|DHCPV4\|DHCPV6`. Emitted only for **Aggressive** suppression on a device claiming `wifi_caps2` `0x400000`. |
| `multicast.suppressor` | **Multicast Suppression**, `enabled` for Conservative *and* Aggressive alike, so the mode is the *pair* of keys, not this value. Needs `wifi_caps2` `0x400000`. Not `multicast.inspect`, which is a decoy — constant across the toggle. |
| `l2_isolation` | **Client Isolation.** `enabled`\|`disabled`, always present, on both band entries. → OpenWrt `isolate` (hostapd `ap_isolate`). |
| `devname` | The Ubiquiti-side netdev for this vap (`ath0`…`ath3`). **The join key for the top-level [`macacl.*`](#macacl--mac-address-filter) section**, whose indices do not line up with `<n>`. Not a name that exists on OpenWrt — enforcement resolves the real netdev via `ubus`. |
| `mac_acl.status`, `mac_acl.policy` | ⚠️ **Decoys — not the MAC Address Filter.** Sit at `enabled`/`deny` with the control off and do not move when it is toggled; the real feature is [`macacl.*`](#macacl--mac-address-filter). |
| `hide_ssid` | **Hide WiFi Name.** `true`\|`false` — not the `enabled`/`disabled` most keys here use. Always present, on both band entries, and duplicated verbatim as `aaa.<n>.hide_ssid`. → OpenWrt `hidden` (hostapd `ignore_broadcast_ssid`). |
| `mcastrate` | Multicast rate. Only ever seen as `auto`; no WLAN-level control moves it, and OpenWrt's `mcast_rate` is adhoc/mesh-only, so openUF does not map it. |
| `advertise_ap_name` | "Show Access Point Name in Beacon". **Only emitted when the device declares `wifi_caps2` bit `0x40`.** |
| `btm_disassoc.status`, `btm_disassoc.threshold` | **Roaming Assistant.** 5/6 GHz vaps only, and only when the device declares `wifi_caps2` bit `0x20` — see [below](#wirelessnbtm_disassoc--roaming-assistant). |
| `iot`, `qbssload` | **"Force WiFi 4 Mode"** (IoT Optimization; REST `enhanced_iot`). Absent when off; appear together as `iot=enabled` + `qbssload=disabled` on the WLAN's 2.4 GHz entry when on. The parent radio is *not* touched — `radio.<n>.ieee_mode` keeps the site's width — so this is a per-BSS flag. `qbssload` is its one distinct on-air effect (suppress the QBSS Load IE); the rest of the mode arrives as ordinary keys: the 5 GHz vap is dropped outright, security pinned to WPA2, and `bss_transition`/`proxy_arp`/`no2ghz_oui`/PMF/`advertise_ap_name` all forced off. |

### `radio.<n>.*` — per-radio config

`phyname` (`radio0`), `channel` (integer or the literal `auto`), `txpower` (integer or
`auto`), `txpower_mode` (`auto`/`custom`/`disabled`), `status`, `ieee_mode`. When no radio is
provisionable the blob contains the literal comment `# no wlan provisioned as no radio found`
and the **unindexed** `radio.status=disabled` — see
[`radio_table` must not be empty](#radio_table-entry). Do not confuse it with the **indexed**
`radio.<n>.status`, the real per-radio enable/disable control
([below](#radionstatus--per-radio-disable)).

`ieee_mode` is **the wire's only channel-width signal**: a compound `11` + band (`ng`/`na`) +
PHY and width token — `11nght20`, `11nght40`, `11naht40`, `11acvht80`, `11axhe80`. Changing
"2.4 GHz Channel Width" from 20 to 40 changes exactly this key (alongside `cwm.mode` 0→1, a
redundant channel-width-management flag carrying no extra information). openUF maps it to UCI
`wifi-device.htmode`; on OpenWrt/mac80211 that option is the PHY ceiling, so `HT20`/`HT40`
also *is* "802.11n only". There is no separate 11n/11ac/11ax mode key — a consumer that
expects one never applies channel width at all.

### `radio.<n>.acsdfs` / `radio.<n>.blklst` — the site's auto-channel limits

Both sit inside one `if (hyFnQ2.supportsAcsDfs())` in
`com/ubnt/service/config/ubntconf/PFljhxhmKJyhpeIhf`, where `supportsAcsDfs()` is
`hasWifiCapability2(16)` — so one unclaimed capability bit hides two real settings:

```java
if (hyFnQ2.supportsAcsDfs()) {
    // BAND_NA only: enabled/disabled from radios_configuration[radio=na].dfs
    OWIoHe.kCNoUwYXLXMAUl(stringBuilder, "radio." + n, "acsdfs", string);
    if ("auto".equals(channel)) {           // only while the radio is on Auto
        // channels_blacklist, grouped by band
        OWIoHe.kCNoUwYXLXMAUl(stringBuilder, "radio." + n, "blklst", String.join(",", set));
    }
}
```

Both come from the site's **Radio AI** setting (`get/setting/radio_ai`):
`radios_configuration` carries a `dfs` boolean per band and `channels_blacklist` a list of
`{radio, channel, channel_width}`. A default site is not empty — the `conservative` preset
blacklists every 2.4 GHz channel but 1/6/11. `blklst` arrives unsorted (a Java `Set`), so the
parser keeps what it is given.

U7LR 6.8.2 turns `blklst` into `wifitool <dev> block_acs_channel <list>` (and
`block_acs_channel 0` to clear), and `acsdfs=disabled` into the same call over the hardcoded
DFS list `52,56,…,144`. Neighbouring strings show the firmware also narrows 2.4 GHz ACS to
1/6/11 unless `acs_2g_allch` is set, which has no controller key.

openUF's equivalents, both `wifi-device` options read by hostapd's ACS: `acsdfs` →
`acs_exclude_dfs` (written as an explicit 0/1), and `blklst` → `chanlist`. hostapd has **no
blacklist**, only a candidate list, so the blacklist is inverted against the channels the
radio's regdomain allows (from `ucihelper.phy_caps`, minus `no IR` channels: an AP may not
beacon there), with `openuf_chanlist` as the ledger that lets the list be removed again
without touching a hand-set `chanlist`. Three cases write nothing, each logged: a blacklist
that excludes nothing this radio could have used, one covering the whole band (an ACS with no
candidate never comes up), and a radio on Auto whose UCI declares no `band`/`hwmode` —
`band_for_device` would fall back to the channel number, and `auto` is not one, so every
radio would read as "na" and a 2.4 GHz radio would be handed 5 GHz channels.

### `stamgr.<n>.*` — per-radio Station Manager (Minimum RSSI)

Indexed the same as `radio.<n>`, **not** tied to any SSID: a device/radio-level setting
(Devices → [AP] → Radios), distinct from the WLAN Advanced panel's
[Roaming Assistant](#wirelessnbtm_disassoc--roaming-assistant).

```
stamgr.1.status=true
stamgr.1.radio=ng
stamgr.1.minrssi.status=true
stamgr.1.minrssi.rssi=15
stamgr.1.loadbalance.status=false
```

**The threshold is not plain dBm.** UI `-80 dBm` → wire `15`; `-85 dBm` → `10`. The
generator computes `max(min_rssi + 95, 1)` with `min_rssi` defaulting to `-80`, so openUF
converts back with a fixed `- 95` (`openuf/minrssi.lua`). Adding the radio's live noise floor
instead moves the threshold by up to 12 dB between drivers (ath9k reads -107, mt76 -90/-92).
The controller's API accepts -67 to -90 only (`api/fields/Device.json`).

Two top-level keys come with it: `stamgr.status=enabled` and `stamgr.interval=1` (the site's
`config.stamgr_interval`). `stamgr.status=disabled`, with no `stamgr.<n>` block, when no radio
has Minimum RSSI or load balancing on. openUF reads neither; they stay in the dropped-key
report. `loadbalance.status`/`loadbalance.maxsta` share the block
([below](#stamgrnloadbalance--load-balance-per-radio-client-cap)).

**What the AP does with it** (firmware-confirmed for 4.0.15), two halves:

1. **Refuse.** `ubntbox` sets the driver's per-radio `minrssi` to `minrssi.rssi` plus
   `stamgr.<n>.minrssi.rssi.offset` (default 3; the controller never sends it), only while
   `minrssi.status` is true. `umac.ko` then answers no probe request and no authentication
   below it ("probe/auth: disallowed by minrssi").
2. **Kick.** `ubntbox` writes `/bin/stamgr -i <stamgr.interval, default 1> -c
   <stamgr.minrssi_conseq_fails, default 30>` into inittab, plus `-b <band> -r <rssi> -n
   <maxsta>` per radio. `stamgr` (`/bin/stainfo`) samples each station every interval, smooths
   its RSSI (0.2 × previous + 0.8 × current) and counts consecutive samples below `-r`; any
   sample at or above resets the count. At `-c` it runs `kick-sta-on` (`syswrapper.sh`), the
   same one-shot deauth as `kick-sta`. Nothing is blocked.

So the firmware kicks a client after **30 s continuously below** the threshold and lets it
back only **3 dB above** it, which is what stops a weak client looping kick → rejoin. The
controller emits neither `minrssi_conseq_fails` nor the offset, so the defaults are what every
UniFi AP runs. `stamgr`'s other kicks are off on a managed AP: `ubntbox` never passes `-t`
(inactivity), and appends `-K` (no kick for a wireless client seen on Ethernet) unless
`stamgr.kicketh.status` is false. The controller sends neither key.

openUF:

- *Refuse:* hostapd's `rssi_reject_assoc_rssi` and `rssi_ignore_probe_request` at threshold
  + 3 dBm, both `wifi-device` options (in 25.12's schema, `hostapd.uc`'s `append_vars` and
  `hostapd.sh`). Stamped `openuf_minrssi`; turning the feature off removes exactly the stamped
  options, and a hand-set value on an unstamped radio is never touched. hostapd refuses
  association (not authentication) below the threshold; that is the closest it has.
- *Kick:* openUF samples once per inform, not once a second, so it counts time: a station
  whose `signal avg` was below the threshold in every sample for 30 s gets one deauth
  (`ucihelper.kick_station`). One sample at or above restarts the count; a station that leaves
  is forgotten.
- A station below Minimum RSSI is not also handed to Roaming Assistant.
- Minimum RSSI is a **roaming aid, not a block**: one deauth, no persistent drop rule, hence
  `kick_station()` rather than `firewall.deauth()`.

Hardware-confirmed (Archer C5 2.4 GHz ath9k, real 10.6 controller): `-90 dBm` arrived as
`stamgr.2.minrssi.rssi=5`, and within ~8 s the live `/var/run/hostapd-phy1.conf` read
`rssi_reject_assoc_rssi=-87`/`rssi_ignore_probe_request=-87`, with only that radio restarting
(`AP-ENABLED` 2 s later, the 5 GHz BSS untouched). Switching it off returned both to `0` and
removed the stamp. ⚠️ Not observed: a refused association or a 30 s kick — no client was near
-87 dBm.

### `stamgr.<n>.loadbalance.*` — Load balance (per-radio client cap)

The device's `radio_table[].loadbalance_enabled` + `maxsta` (REST `rest/device`; the 10.6
schema accepts `maxsta` 1 to 200 or empty). The 10.6 web bundle has no control for it, only a
change-log label. The generator writes the `stamgr.<n>` block when the site's
`advanced_feature_enabled` is on and the radio has Minimum RSSI or Load balance on:

```
stamgr.1.status=true
stamgr.1.radio=ng
stamgr.1.minrssi.status=false
stamgr.1.minrssi.rssi=15
stamgr.1.loadbalance.status=true
stamgr.1.loadbalance.maxsta=3
stamgr.status=enabled
stamgr.interval=1
```

Off: the whole `stamgr.1` block goes and `stamgr.status=disabled`.

**What the AP does with it** (firmware-confirmed for 4.0.15). `ubntbox` passes `stamgr -n
<maxsta>` per radio, 0 unless `loadbalance.status` is true. `stamgr` ignores a maxsta of 0 or
less. Every interval it zeroes each radio's count and candidate, then walks the stations of
all the radio's VAPs: one just kicked for low RSSI is skipped, every other increments the
count, and the candidate becomes the station with the larger idle time (driver station field
`0x678`, `stainfo`'s `idle=` column; on equal idle the earlier station stays). After the walk,
if `maxsta > 0` and count `> maxsta`, it kicks the candidate with reason "Too many STAs"
(`kick-sta-on`, logged `kick-sta-on <mac> <ath> (reason:Too many STAs count:<n>)`). One kick
per radio per interval. Nothing refuses an association — no driver `maxsta` is set
(`umac.ko` has an `iwpriv maxsta`, `ubntbox` never writes it) — so a full radio admits a
newcomer and the next pass kicks whichever station is then the most idle.

openUF: the parser turns the block into the radio's `loadbalance_maxsta` (false when the block
is absent, `status` is not true, or `maxsta` is not a positive number). `rf_config` stores it
as the openUF-only `wifi-device` option `loadbalance_maxsta` and deletes it on off. On every
inform, for each radio with a cap, openUF counts the stations of all its BSSes except any
Minimum RSSI kicks in the same pass and deauthenticates the `count - maxsta` stations with the
largest `inactive time` (`iw station dump`) through `ucihelper.kick_station`; one pass does
what the firmware does over that many seconds. The cap is not echoed in `radio_table`: the
controller keeps its own copy. `iw`'s `inactive time` parses for every station on ath10k and
mt76 (the ath9k radio had none to read). ⚠️ No real kick observed — no radio at home has a cap.

### `wireless.<n>.schedule_*` — WiFi Blackout Schedule

The WLAN's `schedule_with_duration` (REST `rest/wlanconf`): a list of `{name,
start_days_of_week, start_hour, start_minute, duration_minutes}`, the windows in which the
WLAN is off. The 10.4 and 10.6 generators emit it per VAP whenever the list is non-empty
(`isScheduleEnabled()` is `hasScheduleWithDuration()`), with no capability gate. A window is
cut at midnight into per-day blocks (`HHmm`, the end as start + duration) and overlapping
blocks of a day are merged. Then:

- **`fw_caps` `0x400000` (`supportWlanScheduleInvert`)** set: the blackout blocks go out as
  they are, plus `schedule_invert=enabled`. Clear (openUF): the controller inverts them into
  the times the WLAN is ON. A day with no blackout gets `0000-2359`; a day blacked out
  entirely gets no key at all. The inverter emits a block twice when a day's last blackout
  runs to midnight (harmless).
- **`fw_caps` `0x1000` (`supportMultiBlockWlanSchedule`)** set (openUF): one key per block,
  `schedule_<day>.<i>`. Clear: every block of a day is written to the same bare
  `schedule_<day>`, so a key=value parser keeps only one.

`schedule_enabled` is `enabled` with a schedule and `disabled` without. The same push carries
a cron job, `cron.1.job.<n>.schedule=1-59/5 * * * *` with `cmd=syswrapper.sh schedule-action`.
Captured for blackouts 22:00 for 540 min Mon–Fri, 13:00 for 60 and 15:30 for 30 on Saturday,
with `fw_caps` `0x1110`:

```
wireless.1.schedule_enabled=enabled
wireless.1.schedule_sun.0=0000-2359
wireless.1.schedule_mon.0=0000-2200
wireless.1.schedule_mon.1=0000-2200
wireless.1.schedule_tue.0=0700-2200
wireless.1.schedule_tue.1=0700-2200
...                                   (wed, thu, fri as tue)
wireless.1.schedule_sat.0=0700-1300
wireless.1.schedule_sat.1=1400-1530
wireless.1.schedule_sat.2=1600-2359
```

With `fw_caps` `0x110` the same schedule comes out as `schedule_sat=` three times. A blackout
covering every whole day gives `schedule_enabled=enabled` with no day key; clearing the list
leaves `schedule_enabled=disabled` and nothing else.

**What the AP does with it** (firmware-confirmed for 4.0.15). `ubntbox`'s `do_schedule` runs
for every `wireless.<n>` and writes `/var/run/schedules/schedule.<ath>`. With
`schedule_enabled` off it writes `d=00:00-23:59` for d = 0..6. With it on, for each day
(`sun` to `sat`, `date +%w`) it reads the bare key, else `.0`, then `.1` up to `.98`, stopping
at the first missing one, `sscanf("%2d%2d-%2d%2d")`s each value into `d=HH:MM-HH:MM`, and
writes `d=00:01-00:00`, which never matches, for a day with no key. There is no
`schedule_invert` string in the firmware. `syswrapper.sh`'s `configure_vap` then decides each
user or guest VAP: `within_schedule` is true if the current minute is in one of today's blocks
(both ends included), and the VAP goes up if true, `ifconfig`'d down if false. Before
`ntpclient` has set the clock (`/var/run/ntp.ready`), `within_schedule` is always true.
`configure_vap` runs on every config apply, from the 5-minute `schedule-action` cron, and when
br0 comes up once the clock reads past 2017. (A selfrun guest VAP with
`selfrun_guest_mode=off` is down regardless.)

openUF claims `fw_caps` `0x1000`, not `0x400000`, so it gets the firmware's form. The parser
turns a VAP's keys into the firmware's lines (`wlansched.lines`, same rules and limits) and
`apply_config` stores them on the `wifi-iface` as the openUF-only option `openuf_schedule`,
absent when there is no schedule and dropped with the section by `wlan_clear`. On every
heartbeat `_sched_resync` reads them back (`ucihelper.schedule_vaps`: enabled openUF VAPs,
their BSS netdevs including an OWE transition's open BSS, not a PPSK VLAN netdev) and takes
down a BSS outside its on-times with `ip link set <bss> down`. The ledger `st.sched_vaps_down`
brings it back when the on-time starts, the schedule is removed or the WLAN goes away, also
across a restart. A BSS that a wifi reload recreated up is taken down again on the next
heartbeat. A guest BSS that `selfrun_guest_mode=off` holds down is not brought up by the
schedule, and selfrun's return does not bring up one the schedule holds. The
`schedule-action` cron job is not installed (`sysconf.CRON_IN_DAEMON`): the heartbeat does
that check, so a WLAN changes within one heartbeat instead of at the next 5-minute mark.
OpenWrt's ntpd leaves no `ntp.ready`, so openUF writes `/var/run/openuf.clock-ok` once a
controller answer's `server_time_in_utc` is within 60 s of the local clock; until then
`_sched_resync` changes nothing (after a boot every BSS starts up, the firmware's "always
up").

**Bringing a BSS back needs STOP_AP.** By its source, upstream hostapd
(`driver_nl80211.c` / `drv_callbacks.c`) handles a BSS netdev's link going down per BSS
(`bss->ctx`): it frees that BSS's stations and, on up, restarts its beacon
(`reenable_beacon`). OpenWrt 25.12's hostapd does not — hardware-confirmed on all three
drivers: the BSSes came back with no SSID or channel, the bridge port stayed disabled, and
hostapd logged "Failed to set beacon parameters", because it still treated the beacon as set
and only updated it, which mac80211 refuses once the netdev going down has stopped the AP.
`hostapd_cli raw STOP_AP` (which clears hostapd's beacon-set flag) and then `update_beacon`
(now a `START_AP`) put each one back on the air, so that is part of openUF's bring-up; a BSS
whose beacon does not start goes down again and the next heartbeat retries. netifd keeps a
bridge member that went down in the bridge (`bridge.c`: `DEV_EVENT_LINK_DOWN` acts only with
`auth`).

The trade: while a BSS is down, hostapd logs "Failed to set beacon parameters" about every
6 s for each downed BSS, because usteer calls `rrm_nr_set` on every BSS and
`ieee802_11_update_beacons` checks `beacon_set_done && started`, not the link. It is harmless,
but a long blackout pushes older lines out of logread's ring (128 KB). The per-BSS
alternative, dropping the BSS from hostapd's config through netifd (`disabled` + `wifi
reload`), restarts the whole radio when the WLAN is the radio's first BSS, which is worse.
⚠️ Not observed: a client on a WLAN as its blackout starts. The firmware does the same
`ifconfig down` there.

### `wireless.<n>.btm_disassoc.*` — Roaming Assistant

A per-WLAN, per-band setting (Settings → WiFi → *WLAN* → Advanced; REST
`roaming_assistant_na_enabled`/`_na_rssi` and `_6e_enabled`/`_6e_rssi`). Exactly two keys
appear, only on the WLAN's 5 GHz entry, and both vanish when it is switched off — absence is
off:

```
wireless.2.btm_disassoc.status=enabled
wireless.2.btm_disassoc.threshold=-72
```

- **The threshold is plain dBm**, unlike `stamgr.<n>.minrssi.rssi`.
- **The generator** is `com.ubnt.service.config.ubntconf.cZldsW`, which holds the defaults
  `-75` (5 GHz) and `-88` (6 GHz). It emits only when all of these hold:
  `Device.supportsAssistedRoaming()` (= `hasWifiCapability2(32)`, **`wifi_caps2` bit `0x20`**),
  the vap's radio is `na` or `6e`, the WLAN is neither WDS nor an Element WLAN, and that band's
  toggle is on. `status` goes through the builder's boolean helper.
- **What a UniFi AP does with it**, from the key name and the controller's
  `MOVED_DUE_TO_ROAMING_ASSISTANT` event: a BSS Transition Management request, then a
  disassociation. openUF implements that in `openuf/roamassist.lua`, but only when another AP
  on the same SSID and band hears the client at or above the threshold and at least
  `roam_assist_diff_db` (default 8) dB better. A client with no better AP is left alone.
- **usteer's own roam trigger is not used.** It is device-wide, and its only scoping knob,
  `ssid_list`, switches every usteer function off for the other SSIDs, band steering included
  (usteer `local_node.c`, 2025.10.04). openUF reads usteer's cross-AP table
  (`get_client_info`) and makes the per-vap decision itself. Every entry expires
  `local_sta_timeout` (120 s) after the client was last heard, locally or remotely, so a
  reading is at most about 2 minutes old.
- **The hostapd calls** are `bss_transition_request` with the target's neighbor-report hex
  (usteer's `rrm_nr[2]`), then, if the client is still there 10 s later, `del_client` with
  reason 12 and a 30 s `ban_time` on the source BSS only. In OpenWrt 25.12's hostapd `ubus.c`,
  `bss_transition_request` has no 802.11v capability check: the frame goes out regardless and
  a non-11v client simply ignores it.

### `macacl.*` — MAC Address Filter

A **top-level section keyed by devname**, not by the `wireless.<n>` index:

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

Only the vaps of the filtered WLAN get a block, and they are numbered from 1 independently of
`wireless.<n>` (here `macacl.1`/`macacl.2` are `wireless.1`/`wireless.3`). **A join on
`devname` is mandatory**; an index-based reading misfiles the filter onto the wrong WLAN. Like
`bcfilt.<k>`, the `acl.<k>` index carries no meaning beyond grouping, so openUF sorts the
list. Maps onto OpenWrt's `macfilter` (`disable`\|`allow`\|`deny`) + `maclist`, whose policy
vocabulary lines up 1:1 with the controller's.

⚠️ **Two decoys.** `wireless.<n>.mac_acl.status`/`.policy` sit at `enabled`/`deny` with the
control **off** and do not move when it is toggled — the same shape as
`radio.<n>.bcmc_l2_filter.status` for the broadcast blocker. `aaa.<n>.radius.macacl.status` is
the unrelated RADIUS MAC Authentication control. Do not re-investigate these.

### `qos.*` — WiFi Speed Limit

Another **top-level section keyed by devname**. The per-WLAN toggle does nothing until at
least one speed-limit profile exists in the site settings — with no profile there is nothing
to select and nothing reaches the wire. Captured for a 33 Mbps down / 17 Mbps up profile on
one WLAN:

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
| Scope | **Per client**, not a per-VAP aggregate: `maxspeed` is each station's cap (see the firmware below). |
| `qos.ebt.<n>.cmd` | Literal ebtables fragments that fwmark each VAP's frames both ways (`PREROUTING --in-interface ath0` and `POSTROUTING --out-interface ath0`, `--mark-or 0x1000` for VAP 1, `0x2000` for VAP 2). openUF matches on MAC addresses with `tc` instead (`shaper.lua`). |
| `qos.if.<n>` | The interfaces to build an HTB tree on (`eth0` typed `uplink`, then each VAP) with their link speed in Mbit/s (`devspeed`). |

**What the firmware does with it** (firmware-confirmed for 4.0.15). `ubntbox`'s `do_qos`
writes a script that runs `qosLinkInit.sh 1 <devname> <devspeed>` per `qos.if` (an HTB root
with default class `1:9000`, sfq, ceil = link speed) and `qosLinkAddVap.sh <devname> <id>
<devspeed> <devspeed> <min> <max> <maxclient>` per VAP. The VAP's class `1:<id>` gets ceil =
**link speed**, not `maxspeed`; `maxspeed` is passed down as the per-station default
(`STA_RATE_MAX`, kbps), and the script's own per-station class line is commented out. The
per-station classes come from `libubnt`'s `config_sta_qosrule` (`add_sta_qosrule` on
association, `remove_sta_qosrule` on disassociation): `tc class add dev <vap> parent 1:<id>
classid 1:<(id << 11) + associd> htb rate <min> ceil <dl_maxspeed> prio <id> quantum 1500`
plus an sfq leaf, and the same on the uplink device read from `/var/run/system.uplink` with
`ul_maxspeed`. It skips a VAP whose `maxspeed` equals its link speed. The fw filter maps the
VAP mark plus the driver's associd bits to that classid, so broadcast and multicast (no
station) fall to the unshaped default class. Both directions are queued (HTB egress on the VAP
and on `eth0`), nothing is policed. `update_sta_qosrate` (`rate-update`) runs `tc class
change` on one station's classes, adding them when the VAP had none; a negative
`dl_max`/`ul_max` sets that station's ceil to the link speed, lifting its cap even on a
limited VAP.

**`rate-update` is any client's own profile, not only a guest's.** The controller (10.6,
`TtZhv`) builds `{"cmd":"rate-update","mac","ul_max","ul_min":64,"dl_max","dl_min":64}` from a
WiFi Speed Limit profile (`qos_rate_max_up/_down`, `-1` = none). It sends it when a client's
profile is changed while it is online, for every online client of a profile that is edited,
and from the station processor's `qos_policy_applied` latch: once per association for a guest
with `qos_overwrite` or **any client whose profile is not the site default**. The latch resets
when the client roams to another AP or its reported uptime drops (reconnect). A client moved
back to Default gets the Default profile's `-1/-1`.

**openUF** (`shaper.lua`, `inform._shaper_resync`): per netdev that lists stations, one HTB
class per station matched on its MAC (u32: destination at -14/-12 for download, source at
-8/-4 on an IFB device the netdev's ingress is redirected to for upload), an fq_codel leaf
each, a catch-all class at the WLAN's rate for unicast to or from a station not yet seen, and
group-addressed frames unshaped. `rate-update` for any associated MAC goes into `st.sta_rates`
and replaces the WLAN's rate for that client (`-1`: uncapped); it is dropped when the client
leaves or its connected time drops, as the firmware's class is. Changes are incremental: a
station joining or leaving adds or removes only its class and filter. u32 keys must be 4-byte
aligned (`match u32 … at -14` is `Illegal "match"`).

Hardware-confirmed on both APs with a 5000/2000 profile on a temporary SSID (`tc-tiny`,
ath10k, ath9k and mt76), each SSID netdev's ingress redirected to its own `oufb<ifindex>`: a
phone on 2.4 GHz got class `1:10` in both directions and, sampled at the AP, ran 1.97 Mbit/s
up and 4.54 Mbit/s down; deleting the SSID removed every class and IFB.

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

**A fresh device's very first post-adopt `setparam` always carries
`dhcpc.1.status=enabled`** — a brand-new device is in DHCP by definition. Acting on that
unconditionally (flush + `udhcpc`) strands the interface if no DHCP server can grant a fresh
lease. `netconfig.apply_dhcp` is therefore only called when `st.ip_mode == "static"` already,
i.e. when genuinely reverting openUF's own prior static push; first contact and steady-state
reaffirmations are a no-op, matching how real hardware's continuously-running DHCP client
needs no manual re-invocation.

### `switch.*` — per-port VLAN

Appears only once the device declares switch capability. **The device is sent a complete,
actionable VLAN table** — it is not managed server-side.

**Baseline — Port VLAN off**, the state every device sits in until the control is enabled:

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
and never move: inventory, not control.

**The discriminator is `switch.status` / `switch.vlan.status` flipping to `enabled`.** Both
sit at `disabled` in the baseline, so unlike `wireless.<n>.mac_acl.*` or
`radio.<n>.bcmc_l2_filter.status` these are genuine gates. They are driven by a
**device-level** checkbox (Devices → [AP] → Settings → IP Settings → **Port VLAN**), not by
anything per-port, and until it is ticked the whole per-port VLAN UI is greyed out.

**Port VLAN enabled, no port override.** The site's VLANs appear as a table, where
`switch.vlan.<m>` is a slot number, `.id` the real VLAN id and `.mode` the VLAN's device-wide
default:

```
switch.status=enabled
switch.vlan.status=enabled
switch.vlan.1.id=1      / .mode=untagged / .status=enabled
switch.vlan.2.id=20     / .mode=tagged   / .status=enabled
```

**Port 2's Native VLAN set to the VLAN-20 network** adds three keys:

```
switch.port.2.pvid=20              # the port's untagged/native VLAN
switch.vlan.1.port.2.mode=tagged   # VLAN 1 is tagged on port 2
switch.vlan.2.port.2.mode=untagged # VLAN 20 is untagged on port 2
```

So membership is expressed **twice, redundantly**: per-port (`pvid`) and as a
per-VLAN-per-port matrix (`switch.vlan.<m>.port.<n>.mode`). The matrix is authoritative — it
is what carries tagging, and `pvid` is derivable from it (the VLAN whose mode is `untagged`).

**`switch.port.<n>` joins directly to `port_table[].port_idx`** — no devname indirection,
unlike `macacl.*`/`qos.vap.*`. Confirmed by the Port Manager UI listing exactly the ports
openUF reports (not the registry's five) and an override landing on wire index 2, openUF's
`port_idx` 2. This join is why `port_idx` is pinned to a physical socket in the modelmaps and
must not be renumbered: the controller stores a port's settings against it.

**Tagged VLAN Management → Block All** changes one key,
`switch.vlan.1.port.2.mode=exclude` (was `tagged`), giving the full mode vocabulary:
**`untagged` | `tagged` | `exclude`**, which maps 1:1 onto swconfig's untagged/tagged/absent
port membership.

**A port reverted to default** simply drops the three per-port keys, and the blob returns
byte-identical to the no-override state. Teardown is therefore expressible: absence means
default (untagged on the management VLAN, all others tagged), the same convention used
everywhere else in this format.

### `radio.<n>.status` — per-radio disable

Setting a radio's **Transmit Power → Disabled** (Devices → [AP] → Settings → Radios) moves
four keys:

```
radio.1.status=disabled            # was enabled
radio.1.txpower_mode=disabled      # was auto
radio.1.virtual.1.status=disabled  # was enabled
wireless.1.status=disabled         # and every other vap on that radio
wireless.2.status=disabled
```

openUF maps `radio.<n>.status` onto UCI `wifi-device.disabled` and `wireless.<n>.status` onto
each `wifi-iface.disabled`, and reports both back out (`radio_table[].disabled` /
`vap_table[].disabled` read them off UCI), so the controller sees its own push reflected. Two
details:

- The read is **tri-state.** An absent `status` key writes nothing, so a blob that never
  carries it cannot re-enable a radio or SSID the operator disabled by hand in
  `/etc/config/wireless`; only an explicit `enabled`/`disabled` writes, and an explicit
  `enabled` must clear the flag or a radio could never be switched back on.
- Only the **indexed** key is read. The unindexed `radio.status=disabled` in the radio-less
  blob would otherwise take every radio down — the tokenizer's `radio.<n>.<key>` shape cannot
  match a two-component key, so this is structural, but it is pinned by a test.

A disabled WLAN is still provisioned, just with `disabled=1`, so its configuration survives a
re-enable.

### `ebtables.*` — L2 hardening

Carried by every full push: literal ebtables fragments, which the stock firmware replays
against its `ath<n>` VAPs.

```
ebtables.status=enabled
ebtables.add_vlan.status=disabled
ebtables.<n>.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP     # per VAP
ebtables.<n>.cmd=-t nat -A POSTROUTING --out-interface ath0 -d BGA -j DROP   # per VAP
ebtables.<n>.cmd=-t broute -A BROUTING -i ath1 -p 802_1Q -j DROP             # the tagged SSID's VAP
ebtables.<n>.cmd=-t broute -A BROUTING --vlan-id 10 -p 802_1Q -j DROP        # bridge-wide
```

The `ath<n>` names are the stock firmware's and do not map onto OpenWrt netdevs, so
`l2guard.lua` keeps only the two ideas (BPDU drop, tag drop) and applies them to the live AP
VAPs; a rule of any other shape is logged verbatim and not applied.
`ebtables.add_vlan.status` is not read. On a UAP the rules are not interpreted at all
(firmware-confirmed for 4.0.15, `ubntbox`'s `do_ebtables`): it flushes the `broute`, `nat`
and `filter` tables and replays each `ebtables.<n>.cmd` as written, into atomic files
committed together — so the BGA drop in and out and the tag drop are the whole of what the
controller asks for, and the guest rule set is the same mechanism. Read back on both APs
(`nft list table bridge openuf_l2guard`): the BPDU drop in and out and the inbound 802.1Q
drop are loaded for every AP VAP, and nothing else is.

### `system.timezone` / `ntpclient.*` / `cron.*` — system settings

Carried by every full push:

```
system.timezone=IST-5:30                    # a POSIX TZ string, not an Olson name
locale.timezone=IST-5:30                    # the same value again
ntpclient.status=enabled
ntpclient.1.status=enabled
ntpclient.1.server=0.ubnt.pool.ntp.org      # x4, slots 1-4
cron.status=enabled
cron.1.status=enabled
cron.1.user=<the site's device SSH user>
cron.1.job.1.status=enabled
cron.1.job.1.schedule=0 4 * * *
cron.1.job.1.cmd=syswrapper.sh 11k-scan
```

The cron job is how the controller schedules the nightly neighbour scan: it runs through the
AP's own crond at 04:00 device-local time, which is why the timezone matters. See USAGE § 6
for what `sysconf.lua` does with each block. `cron.<n>.user` is deliberately left
unrecognized, so it shows in the dropped-key report.

What the job does on a UAP (firmware-confirmed for 4.0.15, `/usr/etc/syswrapper.sh`):
`11k-scan` → `elevenk_scan` → `elevenk_sched 3600 2 nightly all`, which kills any pending run
and starts `elevenk_run` in the background: two `syswrapper.sh scan`s in one hour. Before each
scan it sleeps 10 s plus `rand % left`, where `left` starts at 3600, loses 10 s before each
draw and loses each random delay after it, so the first scan lands uniformly in 10 s to 1 h
and the second after it, still inside the hour (or 10 s past at worst). The randomness is from
`/dev/urandom`. openUF copies that arithmetic in `hook/syswrapper.lua` and also draws from
`/dev/urandom`: every AP's crond fires at the same second, so delays seeded from the clock
would match. (`11k-boot`, two scans within 5 min after a config apply, is the same routine and
is not implemented.)

Read back on both APs: `system.timezone` holds the site's POSIX string with
`openuf_timezone_orig`/`openuf_zonename_orig` stamped beside it, `system.ntp.server` holds the
four `ubnt.pool.ntp.org` servers with the OpenWrt ones in `openuf_ntp_orig`, `date` runs on
local time, and root's crontab has the marked block with a hand-made line outside it left in
place.

### `connectivity.*`: SSIDs on uplink loss (nothing to do)

A UniFi AP that loses its uplink can take its SSIDs down so clients roam to an AP that still
reaches the gateway. **It only does so when the controller enables the monitor, and openUF is
never sent that config**, so there is nothing to implement.

What the firmware does (firmware-confirmed for 3.9.27 to 4.0.15: `ubntbox`, `mcad`,
`syswrapper.sh`): `ubntbox` starts `uplink-monitor` (part of `mcad`) only when `system_cfg`
says `connectivity.status=enabled` **and** `wireless.status=enabled`; otherwise it starts
nothing, or on some boards `uplink-monitor -p`, whose `update()` returns before calling
`syswrapper.sh state_reload`, so the VAPs are never touched. When it is enabled: the target is
the gateway or the host in `connectivity.uplink`; the interval is 15 s with a wired uplink
(5 s in `init`, 10 s in `up`); the probe is `arping -q -c 1 -I br0` twice if the target is in
the subnet, else `ping -q -c 1 -I br0 -W 2` twice; the target counts as alive without a probe
if its MAC was in the bridge FDB less than 15 s ago, and a failed probe still counts as up
with an FDB age under 90 s; losing carrier is "down" at once, any other "down" needs 5
verdicts in a row (about 60 s); recovery is immediate. "down" leads to `configure_vap up down
down`, taking every user and guest VAP down (`/var/run/system.isolated_wlan_on`, which would
keep them up, has no writer in these builds). After 1800 s isolated while in selfrun the AP
runs `soft-restart`. The firmware sends `isolated`, but current controllers ignore it and set
the device's `isolated` from the inform's top-level `uplink == "down"`, which defaults to
`"eth0"`.

What the controller sends (`eWivisHeQsnaqDtx`): `connectivity.status=enabled` only when
`device.supportVwire()` (`wifi_caps` bit `0x1`) **and** the site's `connectivity` setting is
`enabled`, with `connectivity.uplink=<host>` (`uplink_type=custom`) or
`connectivity.uplink_gateway=<ip>` plus `uplink_eth`/`uplink_wds`/`uplink_bridge`. In every
other case `connectivity.status=disabled`. openUF does not claim `wifi_caps` `0x1` (vwire /
wireless uplink, which it cannot do), and both controllers it runs under push `disabled` —
including the 10.4.57 lab, whose site `connectivity` setting is `enabled: true`. Claiming
`0x1` just to switch the monitor on would also make the controller offer wireless uplink and
meshing to a device that cannot do either. Revisit only if openUF ever does vwire. (OpenWrt
25.12 ships no `arping`; `bridge -s fdb` shows a `used <tx>/<rx>` age for the gateway's MAC,
which would serve as the FDB shortcut.)

---

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
| `required_version`, `bootrom_version`, `country_code` | `bootrom_version` has no counterpart anywhere in the device schema (closest is `boot_time`, a timestamp). A UAP does send it: `mcad` fills it from the `ubootver=` line of `/proc/ubnthal/system.info`, the U-Boot version (firmware-confirmed for 4.0.15). Whether the controller reads it is unknown, so openUF keeps sending its emulated value. |
| `mem_total`, **`mem_used`** | Bytes. `mem_used = total − free`; the schema has `mem_used`, not `mem_free`. |
| **`system-stats`** | Hyphenated key, `{cpu, mem, uptime}` — all three **strings**, cpu/mem as percentages. `cpu` is `0` on the very first inform (delta-sampling `/proc/stat` has no prior sample). |
| **`sys_stats`** | Sent beside `system-stats`, as UniFi firmware does: `loadavg_1/5/15` as `/proc/loadavg`'s strings, `mem_total`, `mem_used` (total − free), `mem_buffer` in bytes. The UI's **Load Average**. See [VAP, device and radio fields](#vap-device-and-radio-fields). |
| `connect_request_ip`, `connect_request_port` | Both **strings**, as the firmware sends them (the UCG's own record carries the port as a string too): the mapped address of the AP's STUN socket. Sent only while STUN runs and once a Binding Response has come back. See [STUN wake-up](#stun-wake-up). |
| `inform_ip` | The controller's IPv4 address, taken from `inform_url`'s host: an IP literal as it is, a host name resolved at most once every 300 s. Absent when the name does not resolve. Whether a controller needs it to accept a host-name URL is open (PROTOCOL-VALIDATION.md). The key is in the BZ2 4.3.28 `mcad` inform payload. |
| **`fw_caps`** | `0x80101110`, plus `0x800000` where Hotspot 2.0 is supported — sent as the **negative** 32-bit integer (`-2146430704`, or `-2138042096` with Hotspot 2.0), because the field is a Java `int` on the controller side and a genuine gateway reports its own caps negative for the same reason. See [capability bitmasks](#capability-bitmasks) |
| **`wifi_caps`** | `0xC`, plus `0x20` (Airtime Fairness) and `0x100000` (Private Pre-Shared Keys) where the device can do them |
| **`wifi_caps2`** | `0x60` plus the bits below |
| `spectrum_scanning` | **Device-level**, not per-radio (the per-radio fields are `spectrum_table`/`spectrum_table_time`). `spectrum_scan_timestamp` is controller-owned: it stamps it itself (ms) from quick-scan results, and nothing reads it from an inform, so openUF does not send it |
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
Sending `"U6IW.6.8.2.15592"` never matches `"6.8.2.15592"`, so the "Update Available" banner
is permanent regardless of the actual firmware version. The catalog's version is confirmed
bare by the controller's own startup log: `firmware[U6IW] new version (6.8.2.15592) is
available`. `fw.pre` (`"U6IW."`) remains correct and untouched in `announce.lua`'s L2
discovery "firmware version verbose" TLV — a different protocol surface. Do not reuse it here.

### Capability bitmasks

`wifi_caps2` is a **second, entirely separate** bitmask from `wifi_caps`. openUF sends
`wifi_caps = 0xC` plus `0x20` where it can switch airtime fairness and `0x100000` where
hostapd can put private pre-shared keys on VLANs; `wifi_caps2 = 0x60` plus `0x2000`, `0x10`
and `0x400000`; `fw_caps = 0x80101110` (plus `0x800000`); **`fw2_caps` `0x80000`**; and no
`fw3_caps` or `hw_caps` field at all, so those read as 0.

Claimed bits and what their absence costs:

| Field | Bit | Controller method | Effect if absent |
|---|---|---|---|
| `fw_caps` | `0x10` | `hasQCASwitch()` | The Ports view's projection of `port_table` into the device DTO doesn't happen. Wired-client *ingestion* is gated only on `isSwitch()` (a model-registry property), so clients still appear in the list — but the Ports view stays empty. |
| `fw_caps` | `0x100` | `hasOWRTSwitch()` | Per-port VLAN assignment is rejected outright — see the validator below. |
| `fw_caps` | `0x1000` | `supportMultiBlockWlanSchedule()` | A schedule with several blocks per day goes out as one `wireless.<n>.schedule_<day>` key per block, all under the same name, so the last one wins. With the bit they become `schedule_<day>.<i>`. |
| `fw_caps` | `0x100000` | tested inline (`hyFnQ2.hasFirmwareCapability(0x100000)` at `config/VAZShipWTNxlo:567`), AND-ed with the WLAN's `radius_das_enabled` or `hotspot2conf_enabled` | No `aaa.<n>.radius.das.*` key is emitted at all, however the RADIUS profile is configured, so CoA/Disconnect is unreachable. |
| `fw_caps` | `0x800000` | `supportHotspot2()` | A Passpoint WLAN is dropped outright (`ubntconf/LsyaJoEysWb`), so no `aaa.<n>.hs20.*` key is capturable. Claimed behind a probe: the local generator must know `iw_enabled` and the hostapd binary must carry `hs20_conn_capab` (`CONFIG_HS20`). |
| `fw_caps` | `0x80000000` (`Integer.MIN_VALUE`) | `supportsMacBasedVlans()`, AND a site-wide quorum (`com/ubnt/service/bz/bWpcUrDmeyjdNnrWeZ`) | While any client-bearing AP or switch in the site fails to claim it, the controller emits no `accept_mac.*` key for **any** device in the site — so one old AP disables every client's Virtual Network Override. |
| `fw2_caps` | `0x80000` | `supportsRadSec()` | `supportsHotspot2Passpoint() = supportHotspot2() && supportsRadSec()`, so the REST validator (`com/ubnt/service/W/ctfbDsCjrxgkv`) refuses a Passpoint WLAN with `api.err.DevicePasspointNotSupported`. **Claimed for a feature openUF does not have** — see the trade below. |
| `wifi_caps` | `0x4` + `0x8` | `supportBandsteering()` / `supportVapBasedBandsteering()` | No device-level Band Steering block at all; setting the mode does not even move `cfgversion`. Without `0x8` alone, a single unpaired WLAN also disables it. |
| `wifi_caps` | `0x10` | `supportSpectrumScan()` | REST `cmd/devmgr spectrum-scan` is refused (`api.err.InvalidTarget`) and `stat/spectrum-scan` leaves the AP out, so Airtime Scan does nothing. |
| `wifi_caps` | `0x20` | `supportATFConfig()` | No `atf.*` block, so Airtime Fairness cannot be switched. |
| `wifi_caps` | `0x100000` | `supportWpaPpsk()` | The controller logs `PPSK is not supported by <mac> and WiFi[…] will be skipped` and sends no `aaa`/`wireless` entry for the WLAN. |
| `wifi_caps2` | `0x10` | `supportsAcsDfs()` | The controller emits **neither** `radio.<n>.acsdfs` **nor** `radio.<n>.blklst`: one `if (supportsAcsDfs())` in `ubntconf/PFljhxhmKJyhpeIhf` guards the block that writes both, so the site's auto-channel DFS switch and its channel blacklist are silently dropped. |
| `wifi_caps2` | `0x20` | `supportsAssistedRoaming()` | No WLAN Roaming Assistant keys (`wireless.<n>.btm_disassoc.*`). |
| `wifi_caps2` | `0x40` | `supportAdvertisingDeviceNameInBeacon()` | `wireless.<n>.advertise_ap_name` is never emitted, and the toggle does not even re-push config. |
| `wifi_caps2` | `0x2000` | `supportsRoamTopologyStats()` | Roams are derived from `sta_table` instead, always "Success" and untagged. Claimed only while roam reports are sent — see [Roam reports](#roam-reports-association--sta_leave--sta_roam). |
| `wifi_caps2` | `0x400000` | `supportsMulticastSuppressor()` | Neither `wireless.<n>.multicast.suppressor` nor `wireless.<n>.bcfilt.bypass_types` is emitted, so a WLAN set to **Conservative** Multicast Suppression pushes *nothing at all*, and one set to **Aggressive** pushes a blocker with no ARP/DHCP carve-out. |
| `radio_caps2` | `0x1` | SAE support | Every WPA3 WLAN is silently downgraded to WPA2 — see [WPA3](#wpa3-needs-radio_caps2-bit-0x1-or-the-controller-downgrades-it-silently). |
| `radio_caps2` | `0x2` | `ytajcagDggPuTaL()`, tested in `plVcFpIybmrpXclX` | `wpa3_fast_roaming` is forced off on every SAE WLAN, and on a WPA3-only one `fast_roaming_enabled` too, so a WPA3-only WLAN never gets 802.11r. |
| `radio_caps2` | `0x8` | `NoFWvUa()`, tested in `plVcFpIybmrpXclX` | An OWE WLAN is dropped from the push entirely ("WPA3-OWE cannot provision"); with `wpa3_transition` on it arrives as a plain open WLAN. |

The sweep behind this table traced every `has*Capability` predicate on
`com.ubnt.data.dChnXOlwHH` (the `Device` class) and every `radio_caps`/`radio_caps2` bit test
on the radio DTO `com.ubnt.i.g.e.DXufmCC` to its callers, mainly the AP config generator
`com.ubnt.service.config.oHgVgY` and the per-radio WLAN security filter
`com.ubnt.service.config.ubntconf.plVcFpIybmrpXclX`. Calls on
`com.ubnt.i.g.OZQcnZuvnRweLFaaG` in oHgVgY check the **model registry**, not anything the
device sends, and are excluded.

**Band Steering** (`wifi_caps` `0x4` + `0x8`) is the AP's own setting (Devices → *AP* → Band
Steering: Off / Prefer 5G / Balance, REST `device.bandsteering_mode`), separate from the
per-WLAN toggle (`no2ghz_oui`). The generator emits `bandsteering.status=disabled` when the
mode is `off` (the default when unset), when the site's advanced features switch is off, or
when no WLAN pairs up — a pair being one WLAN's 2.4 and 5 GHz vaps with the same name,
security and passphrase and no wireless uplink. With the bits claimed and the device on
Prefer 5G:

```
bandsteering.status=enabled
bandsteering.mode=prefer_5g            (equal for Balance)
bandsteering.1.status=enabled
bandsteering.1.vap.1.devname=ath1      (vap.1 = the 2.4 GHz devname)
bandsteering.1.vap.2.devname=ath3      (vap.2 = the 5 GHz devname)
bandsteering.2.status=enabled
bandsteering.2.vap.1.devname=ath0
bandsteering.2.vap.2.devname=ath2
```

Off is `bandsteering.status=disabled`, with no mode and no pairs. openUF reads `status` and
`mode` only (`_parse_bandsteering_system_cfg`): Prefer 5G turns usteer's band steering on for
the device, in addition to any WLAN's own toggle, and `disabled` never switches the per-WLAN
toggle off, because it also means "advanced features off" or "nothing paired". The pairs are
not read — usteer only steers a client toward a same-SSID 5 GHz interface, which *is* the
pairing — so they stay in the dropped-key report. **Balance (`equal`) is not supported**: it
is logged once and changes nothing, because usteer balances client counts only through
`assoc_steering`, which rejects association requests and also balances between APs, while
`probe_steering` is compiled in but cannot be configured (not in usteer's ubus `_cfg` list or
its init script, 2025.10.04 and HEAD).

**usteer's switch is `band_steering_interval`, not `band_steering_threshold`.** usteer's own
source (`policy.c` `below_assoc_threshold`) reads the threshold only when
`load_balancing_threshold` is non-zero, and that is 0 on both APs, so a 5/0 toggle there
switches nothing. `band_steering.c` reads the interval instead: 0 disables, otherwise a BSS
Transition request goes to each steerable 2.4 GHz client every interval, and its default in
2025.10.04 is 120000 ms — so a running usteer always steered, Roaming Assistant included.
openUF writes `band_steering_interval=0` for off and deletes it for on, and removes the old
threshold. (`USTEER_DEFAULTS`' option names and the named `local` section are themselves
correct: the init script feeds every key to `ubus call usteer set_config`, and the loader's
`config_foreach uci_usteer usteer` visits named and anonymous sections alike.)

Live-confirmed on both the lab and the real UCG Ultra, and on a third-party mt7986 board
(yesrab fork): the device setting unset or Off sends `disabled` and openUF removes the
threshold from UCI (`ubus call usteer get_config` → `band_steering_interval: 0`); Prefer 5G
brings the daemon back to its default 120000 ms. ⚠️ Not seen: a 2.4 → 5 GHz steer caused by
the device setting alone — usteer only steers clients with the BTM bit, and the 5 GHz clients
at hand have it clear.

**Airtime Fairness** (`wifi_caps` `0x20`) is the AP's own setting (REST `device.atf_enabled`):

```
atf.status=enabled                 (always, whenever the bit is set)
atf.mode=enabled                   (atf_enabled=true; "disabled" for false)
```

`atf.mode` is `enabled` only when the site's `mgmt.advanced_feature_enabled` is also on, and
10.4.57 writes that back to `true` even on a full-object REST PUT, so in practice the mode
follows `atf_enabled` alone. Its default is true for every model but U7-NHD, UHD-IW, UFLHD
and UDMB (`getDefaultAirtimeFairnessEnabled`). For the 14 models in
`shouldBlockChangingAirtimeFairnessSettings()` the device-update hook copies the old
`atf_enabled` back over any change, freezing the switch at the default; the list has `UAIW6`
(MediaTek) but not `U6IW` (QCA), the model openUF presents, so the toggle goes through.

The OpenWrt counterpart is **mac80211's airtime scheduler, not hostapd**. Every station gets
weight 256 and its deficit is charged from the TX/RX airtime the driver reports, and it is on
by default (all four radios of both APs show `airtime_flags` = `AIRTIME_TX | AIRTIME_RX` and
per-station `airtime` files with moving totals). So `enabled` is left as the kernel default
(openUF writes `3`) and `disabled` writes `0` to
`/sys/kernel/debug/ieee80211/phy*/airtime_flags`, after which no airtime is charged and the
scheduler is plain round-robin. hostapd's `airtime_mode` (UCI `wifi-device` `airtime_mode`)
only picks static, dynamic or limited per-BSS **weights** on top of that scheduler; none of
its modes turns it off, so it is not the counterpart. The value is kept as `st.atf_enabled`
and reapplied at startup (`M._reapply_airtime`), because debugfs resets to `3` at boot and
the controller does not push again. Forgetting the device writes `3`. The off direction is
evidenced on third-party hardware only (the yesrab fork's mt7986 board: `atf.mode=disabled`
arrived and both phys' `airtime_flags` read back `0`); ⚠️ no real write of 0 on either of our
APs.

**Private Pre-Shared Keys** (`wifi_caps` `0x100000`). The emitter is
`com.ubnt.service.aF.hEiVLGSwaf`, called from oHgVgY's PSK branch when
`isPrivatePresharedKeysEnabled()`. Its key list comes from `aF.cZldsW`, which maps each key's
`networkconf_id` to that network's VLAN and **drops keys whose network is not a local-site
layer-2 network**. Captured with one key each on Default, a VLAN-20 and a VLAN-30 network:

```
aaa.<n>.wpa.key.1.mgmt=WPA-PSK
aaa.<n>.wpa.psk=<random 32 characters>   (passphrase_autogenerated: REST replaced ours)
aaa.<n>.dynamic_vlan=1                   (OPTIONAL)
aaa.<n>.wpa.psk_file.status=enabled
aaa.<n>.wpa.psk_file.1.psk=<key>         (Default network: VLAN 1, so no vlanid)
aaa.<n>.wpa.psk_file.2.psk=<key>
aaa.<n>.wpa.psk_file.2.vlanid=20
aaa.<n>.wpa.psk_file.3.psk=<key>
aaa.<n>.wpa.psk_file.3.vlanid=30
```

on both radios' entries, with `br.devname=br0` and **no** `vlan.*`/`bridge.*`/`netconf.*`
block for VLAN 20 or 30: a UniFi AP creates those interfaces as clients arrive. The generator
emits no vlanid for VLAN 1 (`if (1 != vlan)`), so such a key's client stays on the VAP's own
network.

The OpenWrt counterpart exists in 25.12 as is. netifd attaches a `wifi-station` section and a
`wifi-vlan` section to the wifi-iface named in its `iface` option; **one without `iface`
applies to every VAP**. `ap.uc` writes each station as a `vlanid=<vid> <mac> <key>` line of
hostapd's `wpa_psk_file` (and `<key>|mac=…|vlanid=…` into `sae_password_file` for SAE), each
VLAN as a `<vid> <ifname>-<name>` line of `vlan_file`, and emits `vlan_no_bridge` etc. only
with `dynamic_vlan` set; netifd puts the `<ifname>-<name>` netdev into the bridge of the
VLAN's `network`. Both APs run `wpad-mbedtls`, whose binary has `Assigned VLAN ID %d from
wpa_psk_file`, and the claim is gated on that string plus `vlanid=` in `ap.uc`
(`sysinfo.ppsk_supported`).

openUF writes a `wifi-station` per key and a `wifi-vlan` per VLAN (tied to the VAP by
`iface`), `dynamic_vlan=1` on the VAP, and builds each VLAN's `br-openuf<id>` with
`ensure_vlan_network`, trunked on swconfig like a tagged SSID. A key whose VLAN cannot be
built (no `lan_cpueth`) is left out, not provisioned onto the VAP's own network. A client on a
VLAN netdev is listed only by that netdev's station dump, so station reporting, the blocker,
the speed limit and l2guard include the netdevs netifd reports under
`interfaces[].vlans[].ifname`; kicks and Roaming Assistant requests go to the VAP's own
hostapd. UID IoT also passes this gate: it adds `aaa.<n>.wpa.psk_radius` = 0/1/2 (enum
decompiled from 10.6.101, **not seen on the wire**), and openUF skips a WLAN with `2`. That is
a *PSK-from-RADIUS* path (`ap.uc` sets `wpa_psk_radius=2` and `macaddr_acl=2` on a **PSK**
auth type), not 802.1X, so WPA-Enterprise support does not cover it. ⚠️ Not run on hardware:
a client joining with a VLAN key and landing on that VLAN.

**Enhanced Open / OWE** (`radio_caps2` `0x8`). With the bit, an OWE WLAN arrives as:

```
aaa.<n>.wpa.key.1.mgmt=OWE        (no aaa.<n>.wpa, no psk; pmf.status/pmf.mode as for any WLAN)
wireless.<n>.authmode=0
```

With `wpa3_transition=true`, each radio gets **two** VAPs with the same SSID, linked both ways
by `owe_devname`: the oHgVgY generator duplicates the WLAN, sets hide_ssid, and adds
`owe_wpa3_transistion_mode_supplement` to the copy:

```
aaa.1.devname=ath0  aaa.1.owe_devname=ath1  aaa.1.hide_ssid=false  (no mgmt: the open BSS)
aaa.2.devname=ath1  aaa.2.owe_devname=ath0  aaa.2.hide_ssid=true   aaa.2.wpa.key.1.mgmt=OWE
```

OpenWrt 25.12 builds this pair from **one** wifi-iface, `encryption=owe` plus
`owe_transition=1`: hostapd.uc sets up the section twice, once as the hidden OWE BSS and once
as the open BSS, and mac80211.sh gives the open one a second netdev
(`owe_transition_ifname`), which only hostapd knows (`ubus call hostapd bss_info`). So
`_parse_wifi_system_cfg` keeps the open half as a `security="owe", owe_transition=true` VAP
and drops the hidden half — provisioning both would put two sections with the same radio and
SSID into one section name, and the hidden one would win. Station reporting, the blocker, the
speed limit and l2guard read that second netdev from hostapd, so they cover both BSSes.

Two differences from UniFi firmware: OpenWrt names the hidden BSS `<ssid>OWE` where UniFi
reuses the SSID (clients follow the transition element either way), and the pushed
`pmf.status`/`pmf.mode` never reaches hostapd, because ap.uc forces `ieee80211w=2` on an OWE
BSS and writes 0 on any BSS below WPA2. Claimed per radio when `sysinfo.owe_supported()`
holds: `hostapd -vowe` must exit 0 (it exits 1 on a feature the build lacks; both APs'
`wpad-mbedtls` pass) and the ucode generator must know `owe_transition`. OWE is probed apart
from SAE. ⚠️ No OWE BSS has been brought up on a real AP, and no client has joined one.

**FT with WPA3** (`radio_caps2` `0x2`). openUF sends `radio_caps2 = 0x3` on each SAE-capable
radio. Across the switch from `0x1` to `0x3`, with two WLANs each having Fast Roaming and WPA3
fast roaming on:

```
                          radio_caps2=0x1     radio_caps2=0x3
WPA3-only  ft.status      disabled            enabled
WPA3-only  wpa3.ft.status disabled            enabled
WPA2/WPA3  ft.status      enabled             enabled
WPA2/WPA3  wpa3.ft.status disabled            enabled
```

Those six lines were the whole diff across 474 `system_cfg` lines. A mixed WLAN already had
FT, because openUF enables it when either toggle asks. ⚠️ Hardware tier not run: an FT-SAE
roam on a WPA3-only WLAN.

**Gated, and not to be claimed** — no OpenWrt equivalent, or out of scope:

- `radio_caps2` `0x400` and `wifi_caps2` `0x1`/`0x4000`/`0x8000`: MLO and Mesh-MLO.
- `radio_caps` `0x20000`: `radio.<n>.hard_noisefloor.*` / sensitivity level, a QCA
  RX-sensitivity setting.
- `wifi_caps` `0x1`/`0x80`/`0x800`/`0x4000`/`0x8000`: vwire, mesh, meshv3, multi-vport and
  Element. `0x1` also gates `connectivity.status=enabled`, the firmware's uplink monitor (see
  [`connectivity.*`](#connectivity-ssids-on-uplink-loss-nothing-to-do)).
- `wifi_caps` `0x2000` "open hostapd", `0x4000000` low-performance mode.
- `wifi_caps2` `0x4` Green AP, `0x80` quick scan, `0x200` neighbour-in-scan, `0x20000` (an
  AP-group check, purpose unclear).
- `fw_caps` `0x20000000` RADIUS `filter_id`.
- `fw2_caps` `0x20` `port_table.mac_table_ipv6`, `0x80` device command retry.
- **No callers in the controller**, so the bit does nothing: `supportMinRateCtrl` (`wifi_caps`
  `0x200`), `supportMultiAclList` (`0x400`), `supportRadiusMacAuth` (`0x1000`),
  `supportHideChWidth` (`0x10000`), `supportZeroHandoff` (`0x2`), `supportLockAp`
  (`0x1000000`).

**Left unclaimed deliberately, with a reason that is not "no equivalent":**

- `fw_caps` `0x400000` (`supportWlanScheduleInvert`): without it the controller inverts a
  schedule itself, which is the form the 4.0.15 firmware reads and openUF implements.
- `fw_caps` `0x40000` (`supportIPSet()`): with the bit, `ubntconf/jNUeeSBEuWe` sends an
  `ipset.status=enabled` block of hash sets; without it, `VAZShipWTNxlo` sends the
  `dnsmasq.walled_garden.*` names and the `*/10` refresh job, which openUF implements.
  Claiming it would swap a working form for one openUF does not implement.
- `wifi_caps` `0x40` (`bga_filter`): the ebtables emitter (`ubntconf/YcZSaTCMOYFEMGE:201`)
  computes `emit_bpdu_rules = !config.forward_bpdu && !hasWifiCapability(64)`, and
  `l2guard.lua` parses exactly those rules. Claiming the bit would make the controller **stop**
  sending them and send a single `bga_filter` key instead: no new capability, and a regression
  risk if the new key were mis-parsed.
- `radio_caps2` `0x4` (WPA3-Enterprise-192): OpenWrt's live ucode generator does have
  `encryption=wpa3-192` → `auth_type=eap192` → `wpa_key_mgmt=WPA-EAP-SUITE-B-192` with
  GCMP-256 (`iface.uc`), and openUF maps that value, but without the bit the controller never
  sends a 192-bit WLAN, so the mapping is inert and costs nothing, whereas claiming it would
  assert a Suite-B path nothing has exercised.

**The RadSec trade, stated as plainly as the win.** `fw2_caps` `0x80000` is claimed for a
feature openUF does not have, because Passpoint is unreachable without it. What the claim
changes on the wire is that a RadSec RADIUS server now arrives with its certificate
*filenames*, which is the only thing distinguishing it from a plaintext server, and openUF
drops such a server with a log instead of sending the shared secret in the clear. Before the
claim it was indistinguishable, so the claim is the safer side of the trade — but openUF
speaks no RADIUS-over-TLS, and a site that depends on RadSec will see its server dropped, not
used.

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
default-mode port is unconditionally rejected** with
`api.err.VlanTaggingUnsupportedByDevice`, before `vlan_caps` or anything port-specific is
consulted. (Sweeping `switch_caps.vlan_caps` through 0/3/4/5/6/7/15/31/255 only changed
*which* of two near-identical errors fired.) "OpenWrt switch" as opposed to a QCA hardware
switch ASIC is, fittingly, exactly what this is.

### `radio_table[]` entry

| Field | Notes |
|---|---|
| `name` | UCI device name (`radio0`) |
| **`radio`** | **The band** (`ng`/`na`), from `band_for_channel()` — channels 1-14 → `ng`, else `na`. Parsed by `com.ubnt.g.f.e.rYtJfMBbtgWvku`'s `String.toLowerCase()` factory, which has **no null guard**: omitting this field throws an NPE inside the controller's adopt processing on *every* inform, corrupting its UI-facing device cache (Devices list shows "No UniFi Devices Have Been Adopted" while Mongo says adopted). 60 GHz/6 GHz aren't disambiguable from channel number alone and are unsupported. |
| `channel` | Live negotiated channel from `iw dev`, more authoritative than UCI's value (frequently the literal `"auto"`, which the controller will not resolve to a number) |
| **`ht`**, **`tx_power`** | Not `htmode`/`txpower` |
| `disabled`, `builtin_antenna`, `builtin_ant_gain`, `max_txpower` | |
| `nss`, `is_11ac`, `is_11ax`, `is_11be`, `has_dfs`, `has_fccdfs`, `has_ht160`, `has_eht240`, `has_eht320` | Read directly off each entry by `PGOcbDWlbnYQdFW`'s `copyAttrsIfPresent`, **independent of `radio_caps`**. Derived by `sysinfo.radio_caps()` from `iw phy phyN info`. `has_dfs` also gates the pushed `dfs-reset` cron job. |
| **`radio_caps`** | A separate **integer bitmask**, not `nss`. See below. |
| **`radio_caps2`** | `0x3` on an SAE-capable radio (`0x1` WPA3, `0x2` FT with WPA3), `0` otherwise, plus `0x8` (Enhanced Open) where hostapd has OWE. |
| `min_rssi`, `min_rssi_enabled` | `min_rssi` is **dBm** on the wire (the raw `stamgr` value − 95, the controller's own encoding) |
| **`athstats`** | Nested `{cu_total, cu_self_rx, cu_self_tx, cu_interf, satisfaction}`, plus `ast_txto`/`ast_cst` on ath9k radios. See below and ["Possible interference"](#possible-interference-athstatsast_txto--ast_cst). |

**An empty `radio_table` blocks a large amount of downstream behavior.** The controller checks
`if (list3.isEmpty()) { … "Missing radio_table in inform…" }`, which is exactly the "no radio
found" condition that suppresses WLAN provisioning. Real OpenWrt hardware has genuine
`wifi-device` sections populated by the driver at boot, independent of any configured SSID.

**`radio_caps` MIMO bits.** The controller's Java side only ever passes this int through
verbatim (`uCthhvfQNZ2.put("radio_caps", uCthhvfQNZ3.getInt("radio_caps", 0))`); the decode
into `"1x1"`…`"4x4"` happens **client-side only**, in the Radios tab's
`mimo: e7(radio.radio_caps)`. Reverse-engineered by calling the live `e7` decoder through the
webpack module registry with a single-bit sweep:

| `nss` | bit |
|---|---|
| 1 | `0x8` |
| 2 | `0x10` |
| 3 | `0x20` |
| 4 | `0x4000000` |

Checked highest-first when several bits are set. It is **not** simply `radio_caps == nss`
(live-tested and refuted). Left at the default `0`, the MIMO column is blank *and* the 1x1–4x4
filter checkboxes exclude the radio outright rather than merely filtering it wrong.

**`athstats` is required for the "Avg. Interference"/"Avg. Airtime" columns.** The archiver
method `com.ubnt.service.system.x.htDMji` iterates `radio_table` — not `radio_table_stats`,
not `vap_table` — and:

```java
if (!uCthhvfQNZ.containsField("athstats")) continue;
```

then reads `cu_total`/`cu_self_rx`/`cu_self_tx`/`satisfaction`/`cu_interf` off that nested
sub-object. Sending the same four fields on `radio_table_stats` and `vap_table` (both real,
both used by other paths) leaves every archived bucket without them. Named after the legacy
Atheros `ath9k`/`ath10k` stats struct UniFi firmware historically exposed under this name.

### `radio_table_stats[]` entry

Parallel to `radio_table` — the real controller's own split of static config vs. live stats.

`name`, `channel`, `cu_total`, **`cu_self_rx`**, **`cu_self_tx`** (two separate fields, not
one combined `cu_self`), `cu_interf`, plus `spectrum_table` / `spectrum_table_time` when a
`spectrum-scan` cmd has populated `M._spectrum_cache`.

All `cu_*` are percentages derived from `iw dev <ifname> survey dump`;
`cu_interf = max(0, cu_total − cu_self_rx − cu_self_tx)` — airtime busy for reasons other than
this radio's own tx/rx. Three traps in reading that survey:

- **Field names.** The real binary prints `channel active time:`, `channel busy time:`,
  `channel receive time:`, `channel transmit time:` — *not* `channel time:`/`channel time
  busy:`. Patterns must be anchored to line start so `channel busy time:` doesn't also match
  inside `extension channel busy time:`, which `iw` emits on wider channels.
- **The operating channel's entry is not first — pick it by `[in use]`.** `survey dump` emits
  one entry per channel the phy supports, in the phy's own frequency order, so the operating
  channel sits wherever it falls: measured live as entry **11 of 13** for a 2.4 GHz radio on
  ch 11 and **3 of 24** for a 5 GHz radio on ch 44. Every other entry is a scan dwell carrying
  a few milliseconds (3–146 ms observed), so deriving `cu_*` from `stats[1]` divides a busy
  figure by a ~3 ms active time: a genuinely 24 %-busy 2.4 GHz channel was reported as
  **100 %** and a 1.9 %-busy 5 GHz channel as **75 %**, which made both APs look like they
  were drowning in interference. The same wrong entry also fed the noise floor used to convert
  Minimum RSSI back to dBm. `sysinfo.radio_stats()` flags `in_use` and `inform.lua`'s
  `_in_use_survey()` selects it.
- **`cu_*` cover the last inform interval, not the radio's lifetime.** The survey counters
  accumulate from radio bring-up, so `busy / active` is a lifetime average: a 2.4 GHz radio up
  11 h reported 25 % while measuring 15–17 % over 10 s windows. The firmware reports a window
  instead (firmware-confirmed for 4.0.15, `umac.ko`, MIPS disassembly):
  `ieee80211_beacon_chanutil_update2` runs once per VAP per beacon and, every 10 × VAP-count
  calls (10 beacon intervals, ~1 s), reads the MIB counters through
  `ic_get_mib_cycle_counts_pct` (`ic+28348`: tx_frame, rx_frame, rx_clear, cycle) and stores
  `round(Δcounter × 100 / Δcycle)` as three bytes at `ic+22788..22790` (rx_clear, rx_frame,
  tx_frame, in that order); `ath_ioctl`'s athstats reply copies those bytes into
  `cu_total`/`cu_self_rx`/`cu_self_tx` and `mcad` forwards them. (The
  `ieee80211_sysctl_chanutil_{total,selfrx,selftx}` sysctls print the same bytes.) openUF
  keeps the in-use entry's counters per radio (`_windowed_cu`) and reports the delta since the
  previous inform, rounded the same way, over a ~10 s window rather than ~1 s. The first
  reading, a channel change, or any counter going backwards (radio restart) uses the counters
  as they stand; a reading with no new active time repeats the last result. Live-confirmed:
  17 % reported against 15–17 % measured, 6 % against 5–6 %.

`spectrum_table[]` entries carry `channel`, `center_freq`, `width`, `utilization`,
`interference` (field names recovered from two independent Lombok DTO constant pools).
`channel`/`center_freq`/`utilization` come mechanically from survey dump; `interference` is
best-effort — see [best-effort fields](#best-effort-and-unverified-fields).

### Airtime Scan (`spectrum-scan`)

- **Gate.** REST `cmd/devmgr {"cmd":"spectrum-scan","mac":…}` (`devmgr/b/g/qxLeipRTLsKkMM`)
  throws `api.err.InvalidTarget` unless `supportSpectrumScan()` (`wifi_caps` `0x10`) holds and
  the AP is wired. `stat/spectrum-scan` (`stat/hhFgUVZPT`), which the UI reads results from,
  skips any AP without the same bit.
- **`spectrum_scanning`.** The controller sets it to `true` itself when it queues the cmd and
  refuses another request while it stays true (`api.err.SpectrumScanInProgress`). Every stats
  inform overwrites it with the device's own value (`PGOcbDWlbnYQdFW`:
  `is("spectrum_scanning", false)`), the inform that collects the cmd included, so it goes
  `false` before the AP has scanned anything unless the AP says otherwise. openUF marks the
  scan pending, reports `true` in the follow-up inform, sweeps once that inform is out, and
  informs again at once with the results and `false`.
- **"Scanning..." stays until a reload.** The Environment tab's panel holds the AP object it
  loaded with and Scan Now sets `spectrum_scanning: true` on that copy, so nothing a device
  reports reaches it. Frontend behaviour, not openUF's.
- **`spectrum-cfg` is a whole replacement `system_cfg`, ignored on purpose.** Captured: 278
  lines in which every WLAN is replaced by one hidden open `vport-<serial>` SSID and every
  radio has `radio.N.rfscan=enabled` and `channel=auto`. The generator
  (`config/eWivisHeQsnaqDtx`) sets `spectrum_enabled=true` on every radio unconditionally, so
  the payload carries no scan parameter. UniFi firmware writes it to `/tmp/spectrum.cfg`,
  restarts onto it (`rc stop; rc start spectrum.cfg`), runs `ubntrfclient` per radio, and
  restores with `spectrum-scan-restore` (`platdep_funcs.sh`, `syswrapper.sh`): its clients
  lose the AP for the scan.
- **openUF does not do it the UniFi way, on purpose.** A UniFi AP (a) drops every client for
  the scan, which the controller's own confirm dialog says can take over five minutes, and
  (b) measures with `ubntrfclient`, Qualcomm's spectral analysis (FFT of the raw RF, so
  non-WiFi interference counts). openUF cannot match (b) across its boards — ath9k/ath10k
  expose spectral scan through debugfs, mt76 exposes nothing comparable — so it reads the
  radio's channel survey instead (active and busy time, noise floor), which every driver has,
  and keeps clients on the AP. The cost is data quality: `utilization` is busy/active time
  over a short listen per channel rather than minutes, and `interference` is the noise floor,
  not a measured interferer.
- **Dwell: one scan per channel, 200 TU, home in between.** Measured on both APs as the
  survey's active time on an off-channel after one scan:

  | Radio | default sweep | `passive` | `duration 200` | `duration 500` |
  |---|---|---|---|---|
  | Archer C5 ath9k (2.4 GHz) | 79 ms | 119 ms | 219 ms | 518 ms |
  | Archer C5 ath10k (5 GHz) | 46–146 ms | 146 ms | 196 ms | 496 ms |
  | AX3000T mt76 (2.4 GHz) | 79–130 ms | 112–159 ms | 213–259 ms | 512–569 ms |
  | AX3000T mt76 (5 GHz) | 79–116 ms | 116–125 ms | 205–230 ms | 506–515 ms |

  All three drivers honour `duration`, though only the ath10k phy lists `SET_SCAN_DWELL`.
  `duration-mandatory` produced no dwell at all on ath9k; `passive` with `duration` is refused
  by iw. A whole sweep never returns to the operating channel: 13 channels took 13 dwells end
  to end (1 s default, 7 s at 500 TU), so a long dwell in one sweep would leave clients
  without the AP for 7–16 s. openUF therefore scans each channel on its own (`iw … scan freq F
  duration 200 ap-force`), skips the operating channel (its survey covers all the time the
  radio spends there), and spends 0.3 s back home between scans. Client impact during a real
  Scan Now, pinged from the Archer C5 to a 2.4 GHz client: no effect while the 5 GHz radio
  scanned (~20 s), then 12 round trips of 210–330 ms over ~7 s while its own radio scanned,
  and 1 of ~150 pings lost, with the client staying associated. A full scan of the C5 takes
  ~27 s.
- **The table travels in `radio_table`, not `radio_table_stats`.** The controller builds its
  own `radio_table_stats` from the inform's `radio_table` entries and reads
  `spectrum_table`/`spectrum_table_time` there, beside `athstats` and `scan_table`
  (`PGOcbDWlbnYQdFW`, the radio-stats loop over `getList("radio_table")`). Sent in
  `radio_table_stats`, they are dropped and `stat/spectrum-scan` returns empty tables after a
  real scan.
- **`spectrum_table_time` is an age, in seconds.** The controller stores
  `now − spectrum_table_time` (`PGOcbDWlbnYQdFW`, both radio-stats paths, `now` in seconds)
  and the UI shows the stored value as the scan's epoch ("N ago", `1e3 * t`). Sending the
  epoch reads as a 1970 scan.
- **One entry per (channel, width).** The UI chart averages the entries whose `width` equals
  the chart's width over each bonded block's 20 MHz channels. A third-party tool written
  against real APs (jpav88/unifi-tools `unifi_spectrum.sh`) filters `width == 20` and reads
  `interference` as dBm and `utilization` as a percentage, and also reads an optional
  `interference_type` (radar). openUF lists each 20 MHz survey reading once per width the band
  offers: 20/40 on 2.4 GHz, 20/40/80 elsewhere, and up to the configured width when wider. It
  sends no `interference_type`.

Live-confirmed on the real UCG Ultra: Scan Now on the Archer C5 delivered the cmd, the sweep
ran, and `stat/spectrum-scan` returned 81 entries on 5 GHz (27 channels × 20/40/80) and 26 on
2.4 GHz (13 × 20/40), with `spectrum_table_time` back as the scan's epoch. The chart drew the
20/40/80 MHz rows with per-channel utilization; the 160 MHz row stayed grey, as this radio
tops out at 80.

---

### `vap_table[]` entry

| Field | Notes |
|---|---|
| `name` | UCI section name |
| **`essid`** | Not `ssid` |
| **`id`** and **`wlanconf_id`** | Both carry the wlanconf ObjectId from `aaa.<n>.id`. **Mandatory.** See below. |
| **`radio`** | The **band** (`ng`/`na`), same enum as `radio_table`. Sending `radio0` here logs `WARN stat - unexpected radio[radio0] while processing stats` on every inform and silently drops that vap's stats aggregation. |
| **`radio_name`** | The UCI device name (`radio0`) — a separate, real field on the same DTO. This is what `get_ifname_for_radio()` needs. |
| `encryption`, `disabled`, `bssid`, `channel`, `tx_power`, `usage` | `usage` is `"user"` |
| `extchannel` | Secondary 20 MHz channel side: `1` above, `-1` below. Only when non-zero, as the firmware sends it. The controller copies it into `radio_table_stats[].extchannel` and the UI computes a 2.4 GHz radio's centre channel as `channel + 2 × extchannel`. openUF takes it from `iw dev <if> info` (`sysinfo.ext_offset`): the side of the primary's partner in its 40 MHz half, the block halved around the primary above 40 MHz. Live: `1` on both 5 GHz radios at 80 MHz, `0` on the 20 MHz 2.4 GHz radios. |
| `num_sta` | Coexists with the nested `sta_table` on the real DTO |
| `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `tx_retries`, `tx_dropped` | The UI's "Air Stats" panel. `iw` exposes these only per-station, so they are summed across connected stations while building `sta_table`. `rx_dropped`/`rx_errors`/`tx_errors` have no source in `iw` output at all — left unset rather than invented (802.11 ARQ retry/failure counters are inherently TX-side only). |
| `avg_client_signal` | Mean `signal` of associated clients, dBm. Omitted entirely when the VAP has no clients. |
| `cu_total`, `cu_self_rx`, `cu_self_tx`, `cu_interf` | Mirrored from the radio |
| `sta_table[]` | Nested — see below |

**`id` is mandatory or the entire VAP is discarded.**
`com.ubnt.service.devmgr.c.KHUkYjHujLgFBD` (vapInformProcessor) filters the raw `vap_table`
*before* any per-station processing runs. For a `usage=user` VAP it requires a non-`"unknown"`
`id`, then re-looks it up via `configCache.get(siteId, id)` to attach
`wlanconf_id`/`ap_mac`/`site_id`/`is_guest`/`is_wep`. A missing `id` is checked with
`!"unknown".equals(id)` and drops the VAP **silently** — no log line, no error, taking the
nested `sta_table` and every wireless client with it. The `"Inconsistent vap"`/`"Invalid id"`
warn paths only fire on an actual lookup *failure*.

**"Air Stats" needs growing counters, not just non-zero ones.** The widget renders a
rate/delta between informs, so static counters produce a zero delta even when the absolute
value is correct — which is why `iw-mock.sh`'s fake counters must increase monotonically.

**mt76 retry counters can read as 2^32 − 1.** mt76 as shipped in OpenWrt 25.12.5
(`kmod-mt7915e` 2026.03.19~39c960c3) adds `FIELD_GET(MT_TX_FREE_COUNT, info) - 1` to the u32
`tx_retries`, and that plus the failure bit to `tx_failed`, with no guard for a count of 0
(`mt7915/mac.c`, tx-free path; upstream later made it `count ? count - 1 : 0`), so a fresh
station's counters can read 4294967295. The controller keeps a delta only when it is positive
and the last value is non-zero (`devmgr/wcvb`), so a counter that goes down costs nothing but
one reading near 2^32 adds 2^32 — and `stat.ap` is cumulative, so the jump stays (seen as
47,270,605,212 tx packets and 49.4 % drops on the Office AP). openUF reads both as signed
32-bit and floors them at 0 (`sysinfo.u32_count`). The same source gives the real drop count:
`tx_failed − tx_retries` (`satisfaction.dropped`), which feeds the VAP/radio
`tx_dropped`/`wifi_tx_dropped` and the WiFi Experience drop term; counting every failed
attempt as a drop reported ≈ retries instead (6,134 against a true 181). The WED path reports
both counts from firmware, so there the difference floors at 0. ⚠️ Values already accumulated
stay in `stat.ap` until the device is re-adopted.

### VAP, device and radio fields

Firmware keys openUF does not send, each checked against what the controller reads. A key is
only worth sending if something shows it.

| Key | Firmware (3.9.27 to 4.0.15) | 10.6.106 consumer | openUF |
|---|---|---|---|
| `sys_stats` | `prepare_system_stats`: `/proc/loadavg` read with `%s %s %s` (default `0.00 0.00 0.00`) and sent as strings; `json_integer` of sysinfo `totalram`, `totalram − freeram`, `bufferram` | Stored whole on the device. UI: the device panel's **Load Average** row (`loadavg_1 / 5 / 15`, hidden when absent) and the device comparison's load column. `mem_*` have no UI reader | Sent, from `/proc/meminfo` `MemTotal`, `MemTotal − MemFree`, `Buffers`, times 1024. Live: Load Average 0.09 / 0.13 / 0.17 matching `/proc/loadavg`, `mem_buffer 0` because OpenWrt reports `Buffers: 0 kB` |
| vap `bw` | Not among the 4.0.15 firmware's vap keys | Copied into `radio_table_stats[].bw` (0 when absent) | Not sent: no firmware evidence for its unit |
| `isolated` | Sent | Ignored: derived from `uplink == "down"` | Not sent |
| `countrycode_table` | Sent | UI warns when the site country is missing from it; absent = no warning | Not sent: no list of supported countries on OpenWrt |
| `antenna_table`, radio `current_antenna_gain`, `builtin_ant_gain` | Sent | No `antenna_table` = `antenna_id -1`, `antenna_gain = builtin_ant_gain` (0 when absent); EIRP is tx power + gain | Not sent: OpenWrt has no antenna gain to report, and 0 keeps EIRP = tx power instead of inventing one |
| radio `has_restricted_channels`, `min/max_chan_cntr_frq` | Sent | UI drops channels outside the range when `has_restricted_channels` | Not sent: absent means no restriction, which is true here |
| `model_display` | Sent | UI reads it on neighbour (scan) rows only | Not sent |
| `mac_filter_rejections`, vap `wifi_tx_latency_mov` | Sent | No reader in the controller or UI | Not sent |

### "Possible interference": `athstats.ast_txto` / `ast_cst`

The controller's `EVT_AP_PossibleInterference` warning reads two hardware counters. For each
`radio_table[]` entry carrying `athstats`, the device manager diffs `ast_txto`, `ast_cst`,
`ast_ath_reset`, `fullqueue_stop` and `ast_be_xmit` against the previous inform (a missing or
zero first sample gives no delta; neither does a counter that went down) and logs the event
when the time since that inform is over 5 s, either counter rose faster than **10 per second**,
the radio has a VAP (`vap_table[].radio_name`), and no event was logged for this radio in the
last 5 minutes. The deltas are kept in `radio_table_stats[]`. The only other consumer is the
UI's sort order for the Devices list columns "TX 2.4G/5G", which sorts by `ast_be_xmit` +
`tx_packets`. In 10.6.106 the UAP handler (`iceUMDuewFNFLMOqti`, wired into the Atheros,
Broadcom and MediaTek AP config factories) passes the inform time in milliseconds; a second
copy in the gateway handler (`IPBUmPKpJrymtFQry`, wired only into the UDM/UXG managers) passes
seconds, so a gateway's built-in radios can never fire the event. That copy never sees an AP's
inform.

Firmware (firmware-confirmed for 4.0.15): mcad fills `athstats` from libubnt's
`get_radio_stat_info` (the driver's `ath_stats`); the `athstats` tool prints the same fields as
"global txmit timeout interrupts" (`ast_txto`), "carrier sense timeout interrupts" (`ast_cst`)
and "beacons transmitted" (`ast_be_xmit`). These are raw counts since the driver loaded; the
controller computes the rates.

openUF: ath9k counts the same two hardware interrupts in debugfs
(`/sys/kernel/debug/ieee80211/phyN/ath9k/interrupt`, lines `GTT` and `CST`), sent as
`ast_txto`/`ast_cst` (`sysinfo.radio_timeouts`). ath10k (whose firmware stats have a TX-timeout
count but no carrier-sense one) and mt76 have no such pair, so their radios send neither, as a
radio that never timed out would. `ast_be_xmit` is not sent: mac80211 keeps no count of
beacons sent, and the column it affects is only sorted by it. Live-confirmed: an ath9k radio
at GTT 312203 / CST 263611 after 69 days (~0.05 per second together) produced a stored
`ast_cst` delta of 1, and the mt76 radios sent nothing. At these rates the event stays quiet;
it is meant for a radio that cannot get on air.

### STUN wake-up

How the controller makes a managed AP inform at once when it has something for it, instead of
waiting for the next heartbeat. Dropping `stun_url` makes every command and config change wait
up to one inform interval.

**Controller.** The `stunService` bean is chosen by `stun.type`, default `local`: a STUN server
on UDP 3478 (jstun, classic RFC 3489) that accepts only attributes 2 (RESPONSE-ADDRESS) and 3
(CHANGE-REQUEST), rejects a Binding Request without CHANGE-REQUEST, and answers with
MAPPED-ADDRESS (the request's source), CHANGED-ADDRESS and SOURCE-ADDRESS, 56 bytes in all.
`mgmt_cfg` is built whole by one builder which always appends `stun_url` (`stun://<host>:3478/`),
so a `mgmt_cfg` without it means no STUN. The connection request is sent from the device
manager whenever it queues a command for a device in state CONNECTED and whenever a config
change bumps `cfgversion`; it needs `connect_request_ip` present and `connect_request_port` > 0
(`getInt`, which also parses a string), else the debug log says "does not have STUN
capability". The STUN socket then sends 20 bytes to that address: type `0x8888`, length 0, the
rest zero (the simulator variant puts a MAC at offset 4).

**Firmware** (mcad `stun_init`/`stun_send`/`stun_recv`, firmware-confirmed for 4.0.15):

- `stun_init` opens one UDP socket with SO_REUSEADDR, bound to `0.0.0.0:0`, with a persistent
  read event.
- `stun_send` runs on a timer and sends only when `/var/run/ipready.br0` exists, mcad's state
  is 2 (managed) and a `stun_url` is set. The packet is 28 bytes: type 1, length 8, an all-zero
  transaction id, then CHANGE-REQUEST (3), length 4, value 0. After a full send the next is due
  in 30 s; after a failure, a partial send or a not-ready state, in 5 s.
- `stun_recv`: a `0x8888` packet of at least 20 bytes is logged as `stun_connection_request`
  and triggers an inform 10 ms later (reason `stun`) unless one is already running; a `0x0101`
  Binding Response is walked attribute by attribute, and a MAPPED-ADDRESS with family 1 (IPv4;
  family 2 is also accepted) that differs from the stored address is logged as "stun info
  changed", stored, and triggers an inform at once; a receive error re-initialises the socket.
  Nothing checks the sender or the transaction id.
- The inform carries `connect_request_ip` (`json_string`) and `connect_request_port`
  (`sprintf "%d"`, then `json_string`) while the stored port is non-zero.

**openUF** (`openuf/stun.lua`) sends the same request on the same timing, but only while
adopted and not in selfrun (fewer than 3 unanswered informs, the firmware's state 3 boundary).
`stun_url` is persisted in `state.json`, because setparam is not re-sent after a restart. The
socket is read inside the inform loop's idle wait, so a connection request or a changed mapping
ends the wait at once, and a burst of queued packets is drained by one read into one inform.
Difference: openUF ignores an IPv6 mapping, because its socket is IPv4-only.

Live-confirmed on both APs against the real UCG Ultra: after a Force Provision the controller
recorded `connect_request_ip`/`connect_request_port` matching each AP's own socket (ports
stored as strings), and `set-locate`/`unset-locate` put a `0x8888` on the AP within 0.12–0.25 s
of the REST call, each followed by an inform SYN — immediately on the AX3000T, 1.3–1.6 s later
on the Archer C5, which is the time the slow ath79 takes to build the payload before it POSTs.

### `sta_table[]` entry (nested inside each `vap_table` entry)

Nested, **not** a flat top-level `user_table`.

| Field | Notes |
|---|---|
| `active`, `mac`, `ap_mac`, `channel`, `radio` | `active` is always `true` — an entry only exists while `iw station dump` lists the station |
| `signal`, `rssi`, `noise` | `signal` is `iw`'s dBm. `rssi` is the **SNR** in dB over the radio's in-use survey noise, floored at −96 as the firmware does (`signal = rssi + max(noise, −96)`); `noise` is the survey reading itself, sent unclamped as the firmware does (so below −96 dBm `rssi + noise` is less than `signal`), absent with no survey reading |
| `state`, `is_11r` | `state` carries only bit 0x10 (dozing), and only where mac80211 tracks power save; `is_11r` only when true |
| `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets` | **Raw cumulative counters.** The vapInformProcessor computes its own `tx_bytes-d`/`rx_bytes-d`/`bytes-d`/`bytes-r` deltas server-side keyed by `time_delta` — never send a pre-computed rate here. |
| `tx_rate`, `rx_rate` | **Kbps** (`iw` reports Mbit/s, so ×1000) |
| `uptime`, `idletime` | `iw`'s "connected time" / "inactive time", both in seconds |
| **`tx_mcs`**, `rx_mcs` | Not `tx_mcs_index` (that name is only the ucore-message JSON name for a different internal event). Absent for legacy pre-11n rates. |
| `nss` | Read directly by the controller, no derivation |
| `radio_proto` | Read only by the **disconnect-time** archive path (`TtZhv`) |
| **`is_11n`, `is_11ac`, `is_11ax`, `is_11be`** | What the **live** display actually uses — see below |
| **`tx_retries`**, `wifi_tx_attempts`, `wifi_tx_dropped`, `wifi_tx_retries_percentage` | Lifetime counters. `attempts = tx_packets` (retries not included); dropped is `satisfaction.dropped`; percentage = retries ÷ (retries + attempts + dropped). The controller replaces the percentage with its own from the deltas: see below |
| `satisfaction`, `satisfaction_now`, `satisfaction_reason`, `anomalies` | The firmware's own formula — see below |
| `capacity`, `throughput`, `linkscore`, `multicast` | **Not sent.** UniFi firmware's `fill_stainfo_json` sends none of the four (firmware-confirmed for 3.9.27 to 4.0.15). The controller reads `capacity`/`throughput`/`linkscore` only in `devmgr.c.KHUkYjHujLgFBD`'s `active_sta_table` builder, which runs only for a mesh **uplink** VAP's entry, and `multicast` per client as a sub-document (a number comes back `null`). None of the four appears in `stat/sta` or `stat/device` |
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

**A client's "TX Retries" is the controller's delta of `tx_retries`.** On each inform the
controller diffs the wireless client's counter keys: `tx_bytes`, `rx_bytes`, `tx_packets`,
`rx_packets` (`devmgr.KrlpWXOulbN`) plus `wifi_tx_attempts` and `tx_retries`
(`devmgr.HCKpgcBFPLu`). It keeps the positive deltas (`wcvb`), adds them to the client's stored
totals and **overwrites** `wifi_tx_retries_percentage` with `wifi.k.bLwwMKkr`: Δretries ÷
(Δretries + Δattempts + Δdropped) × 100, rounded to 0.1 (`devmgr.TtZhv`). Without a per-station
`tx_retries` every client reads "TX Retries 0.0%". `wifi_tx_dropped` is read from the same
delta but is not in the diffed key list, so its delta is 0 whatever is sent; openUF sends it
anyway as the lifetime count. **`wifi_tx_attempts` excludes retries**: firmware 4.0.15 sends no
`wifi_tx_attempts` at all, so the controller is the only source, and every rate it computes
from the field (client, `stat.ap` `tx_retries_percentage_max`, per band) uses retries +
attempts + dropped as the denominator, while the disconnect-time session archive fills
`wifi_tx_attempts` from `wifi_tx_packets`. Sending `tx_packets + tx_retries` counts the retries
twice, so openUF sends `tx_packets`, per station, per VAP and per radio, and the radio's
`tx_retries_pct` uses the same denominator. ✅ Live on both APs: 8 of 13 wireless clients had
non-zero `tx_retries` in `stat/sta`, percentages 4.2 to 15.3 on both mt76 and ath9k/ath10k, and
the client panel showed "TX Retries 7.4%" for a 2.4 GHz phone.

**`satisfaction` is a device-computed field.** The controller's `wifi_experience_score` is a
straight passthrough (`com.ubnt.service.l.e.AcrQJeJCScLn`:
`wifi_experience_score = doc.getOptionalInt("satisfaction")`), and the wireless-client model
(`com.ubnt.service.l.e.AQODNNoMmBlFpWXX`) reads `satisfaction`, `satisfaction_now`,
`satisfaction_real`, `satisfaction_reason`, `anomalies` (`getOptionalLong`), `wifi_tx_attempts`,
`wifi_tx_retries_percentage`, `tx_mcs`, `ccq`, `noise`, `nss` as **plain data**; the controller
computes nothing beyond a running `satisfaction_avg`. Sending nothing renders as "No
Experience", correctly.

**The formula is the firmware's** (firmware-confirmed for 4.0.15). `libubnt.so.1.0.0` exports
`calc_sta_satisfaction`, `calc_vap_satisfaction`, `calc_radio_satisfaction`,
`calc_ap_satisfaction` and `fill_stainfo_json` (offset → JSON key); 3.9.27 has none of them.
Decoded from the MIPS code, a client's score is the lowest of six integer terms:

| Term (reason bit) | Input (`fill_stainfo_json` key) | Score | Anomaly bit when |
|---|---|---|---|
| signal (0x1) | `rssi` = SNR in dB; `signal` is emitted as `rssi + max(noise, −96)` | < 5 → 0; 5–14 → 5·snr + 15; ≥ 15 → min(snr + 75, 100) | < 50 |
| phy_rate (0x2) | `tx_rate`, `rx_rate` (kbps): ⌊tx/2⌋ + ⌊rx/2⌋, or the non-zero one; both 0 → 100 | ≤ 6000 → 10, ≤ 12000 → 25, ≤ 18000 → 50, ≤ 24000 → 70, ≤ 36000 → 75, ≤ 54000 → 80, ≤ 100000 → 85, ≤ 200000 → 90, ≤ 400000 → 95, else 100 | ≤ 12000 |
| tcp_packet_loss (0x4) | `rx_tcp_stats.stalls` + `tx_tcp_stats.stalls` ÷ an unexported u16 | 100 − 10·min(n, 10) | < 50 |
| tcp_latency (0x8) | `rx_tcp_stats.lat_avg` + `tx_tcp_stats.lat_avg` = s | s < 100 → 100, else 100 − (min(s, 600) − 100)/5 | < 50 |
| wifi_retries (0x10) | `tx_retries_mov` ÷ `tx_packets_mov` = p % (truncated) | retries > packets → 0; no packets → 100; p ≤ 25 → 100, else 100 − ⌊(100p − 2500)/75⌋; then − min(`tx_dropped_mov`, 100), ≥ 0 | < 50 (or retries > packets) |
| wifi_latency (0x80) | `wifi_tx_latency_mov.avg` = a | 100 − min(a, 20000)/200 | a ≥ 10000 |

`satisfaction_reason` is the bit of the term that set the score: 0x1 when signal < 100, else 0,
and each later term takes it only when strictly lower. `anomalies` ORs every term's bit
whichever won. 0x20 `poor_stream_eff` and 0x40 `sleepy_client` are chart keys the function never
sets. The `_mov` counters come from the driver (`umac.ko`, not stripped): `sta_stat_iter`, run
by a 60000 ms timer (`ubnt_sta_stat_timer_expired`), stores current − snapshot and
re-snapshots, so they are the last completed minute. The TCP terms come from the driver's own
TCP inspection (`ubnt_calc_tcp_stats`) and the latency term from `_ubnt_log_txtime`; mac80211
has neither, so openUF scores them 100, which is what the formula gives with no TCP seen.

Roll-ups: a VAP's `satisfaction` is the truncated mean of its clients', capped at 100, **−1
with none**. A radio's (`athstats.satisfaction`) and the device's are Σ(clients × VAP score) ÷
Σ clients, truncated, −1 with none. `fill_wireless_info_full` also counts, per VAP, the clients
with each anomaly bit (`anomalies_bar_chart`) and each reason bit (`reasons_bar_chart`), each a
JSON object of eight keys (`anomalies_bar_chart_keys`: weak_signal, low_phy_rate,
high_tcp_packet_loss, high_tcp_latency, high_wifi_retries, poor_stream_eff, sleepy_client,
high_wifi_latency; `reasons_bar_chart_keys`: signal, phy_rate, tcp_packet_loss, tcp_latency,
wifi_retries, stream_eff, sleepy_client, wifi_latency). mcad sends `satisfaction`,
`anomalies_bar_chart`, `reasons_bar_chart` and `avg_client_signal` per VAP,
`athstats.satisfaction` per radio and `satisfaction` at the top level; openUF sends all of
them.

Controller side: `devmgr/PGOcbDWlbnYQdFW` builds `radio_table_stats[].satisfaction` from
`radio_table[].athstats.satisfaction`, default −1 (so a radio that never sends it reads −1); the
device doc copies top-level `satisfaction` only when present (`copyAttrsIfPresent`), so an
absent value keeps the last score; the stat archiver (`system/QDcGUYAmLvJwylXw`) treats a VAP's
−1 as no data.

openUF's sources: SNR from `iw`'s `signal avg` (the last frame's `signal` without it) over the
radio's in-use survey noise; rates from `tx/rx bitrate` × 1000; the retry window from
`tx packets`/`tx retries`/`tx failed` deltas over ≥ 60 s; `tx failed` as drops except on mt76
(driver name `mt7*` from `/sys/class/net/<if>/device/driver`), where it counts failed attempts
and the drops are `tx failed − tx retries`. Live-confirmed on both APs: device 89/88, radios
98/83 and 84/100, a client-less VAP −1, each client's score and reason. 5 GHz clients score
95–100 and 2.4 GHz clients 75–85, bound by phy_rate — a single-stream HT20 client's top rate
(72.2 Mbit/s) is ≤ 100000 kbps → 85, and an idle client's last rx frame is often a 6–12 Mbit/s
legacy one, which lowers the mean. (The estimator this replaced — min of downlink airtime
efficiency and SNR, EWMA-smoothed — was openUF's own design, not UniFi's.)

**Station fields.** `fill_stainfo_json` (libubnt 4.0.15, firmware-confirmed for 3.9.27 to
4.0.15) emits, per station: `mac`, `state` (u16 node flags), `state_ht` (flags & 0x8),
`state_pwrmgt` (flags & 0x10), `authorized`, `is_11b`/`is_11a`/`is_11n`/`is_11ac`, `is_11r`
(only when its flag is set), `rssi` (u8 SNR), `noise` (s16 dBm, unclamped), `signal`
(`rssi + max(noise, −96)`), `tx_rate`, `rx_rate`, `ccq`, `uptime`, `idletime`, `auth_time`,
`dhcpstart_time`, `dhcpend_time`, `hostname` and `ip` (when known), `tx_power`, the rx/tx
counters, `1x_identity` (when set), `vlan_id`, `satisfaction`, `satisfaction_reason`,
`anomalies`, `wifi_tx_latency_mov`.

What the controller does with them (the AP station processor `devmgr/MwArZjlvuVhguZnuxGE` and
the copy list in `devmgr/iceUMDuewFNFLMOqti`: `ack_rssi, anomalies, anon_client_id, ccq,
dhcpend_time, idletime, noise, nss, rx_rate, rssi, satisfaction_now, satisfaction_real,
satisfaction_reason, signal, tx_mcs, tx_power, tx_rate, tx_retry_burst_count`, each copied when
present):

| Field | Controller use | openUF |
|---|---|---|
| `rssi` | Read as SNR: mesh/uplink checks test `> 5`, the neighbour and uplink paths turn it into dBm with `rssi − 95`, the client-insight ranking (`wifi/k/rFCHnXVpfjjP`) uses it only when `> 0`, and the frontend falls back to a converted `rssi` where `signal` is missing | SNR over the in-use survey noise, floored at −96. Sending `signal` (negative dBm) here is wrong |
| `noise` | Copied; legacy `stat/sta` only (the v2 client API drops it) | Sent, from the in-use survey entry |
| `state` | `powersave_enabled = (state & 0x10) != 0`, the only bit read; shown by the AI assistant's client summary | 0x10 from mac80211 debugfs `stations/<mac>/flags` `PS_STA`, only on a radio whose `hwflags` lack `AP_LINK_PS`; absent elsewhere |
| `is_11r` | Copied as a boolean (`is("is_11r", false)`); `stat/sta` only, no 10.6 UI reader | Sent, true when hostapd's `AKMSuiteSelector` is an FT suite (00-0f-ac-3/4/9/13/19/25) |
| `anomalies` | Copied, but overwritten on a gateway site — see below | Sent |
| `ccq` | Copied; no UI reader | Not sent: mac80211 has no CCQ |
| `dhcpend_time` | Copied; no UI reader | Not sent: no UI effect, and the firmware's unit (the struct field at 0x3c) is undecoded |
| `tx_power` | Copied; the UI's `tx_power` readers are all per radio | Not sent: the per-station value's source is undecoded |
| `1x_identity` | Client doc + `last_1x_identity` | Not sent. Available (`hostapd_cli -i <bss> sta <mac>` reports `dot1xAuthSessionUserName` on an authenticated station); unimplemented, not impossible |
| `vlan_id` | Not read (the client's `vlan` comes from the network) | Not sent |
| `ack_rssi`, `tx_retry_burst_count`, `channel_width` | Read by 10.x; not in 4.0.15's list | Not sent: no reference firmware to match (current builds are encrypted) |

Power save by driver, read-only on both APs: ath9k (no `AP_LINK_PS`) showed `PS_STA` on one of
four stations in each of ten 1 s samples; ath10k and mt798x both set `AP_LINK_PS` and never
showed it, so `false` there would be a guess and `state` is left out (the controller then reads
`powersave_enabled: false` either way).

**`anomalies: -1` on a UniFi-gateway site is the controller's.** Each client's record is written
by every device that reports it, last writer wins (`URbVkSXx`, stamping `_last_seen_by_<type>`).
The gateway's host pass (`ykWHwBYcfNAYxrjv` → `yChBbiXeSTK`) puts
`anomalies = port.getInt("anomalies", -1)` on every host behind a port, with no −1 guard
(`satisfaction` has one), and the only hosts it skips are UniFi devices' own MACs and BSSIDs
(`CNSMptQSEDMQtIKop`), not their clients — so a real UniFi AP's clients get the same −1. Live:
17 of 17 WiFi clients read −1 with `_last_seen_by_ugw` newer than `_last_seen_by_uap`. A site
with no gateway keeps the AP's value.

Live-confirmed on both APs: `stat/sta` shows `rssi` 45/44 for clients at −51/−48 dBm (noise
−106 → floored −96 on ath10k, −92 on mt798x), `noise` −106 sent raw, and `is_11r: true` on the
six clients whose hostapd AKM is 00-0f-ac-9 or -4. ⚠️ `powersave_enabled: true` has not been
seen end to end — no 2.4 GHz client was on the ath9k radio during the check — though the reader
was checked against live debugfs.

**Per-driver tx counters.** `iw station dump`'s `tx retries` and `tx failed` do not mean the
same thing on every driver, and neither tracks end-to-end loss. The firmware formula reads
`tx retries` per frame (which mt76's failed-attempt count matches) and `tx failed` as frames
dropped (which mt76's does not, so it is ignored there). Each check pinged a client from the AP
150 times (1/s) and diffed the station's counters:

| driver (`/sys/class/ieee80211/phyN/device/driver`) | Δ tx packets | Δ tx retries | Δ tx failed | ICMP lost |
|---|---|---|---|---|
| `mt798x-wmac` (mt76, AX3000T 2.4 GHz), Google Home Mini at −36 dBm | 227 | 74 | 74 (33 %) | 0 / 150 |
| same AP, a clean client at −61 dBm | 1884 | 1 | 1 | 0 / 150 |
| `ath9k` (Archer C5 2.4 GHz), the same Mini at −54 dBm | 325 | 129 | 3 (0.9 %) | 0 / 150 |
| `ath10k_pci` (Archer C5 5 GHz), lifetime only | 480383 | 115379 | **0** | not tested |

- mt76: `tx retries` equals `tx failed` exactly on every station. Both count **failed
  transmission attempts**, not lost frames: in a 30 s window a −71 dBm client logged 43 failed
  on 34 packets. The power-saving Mini's 33 % were attempts made while it dozed, then re-sent
  and delivered, hence no loss.
- ath9k: `tx retries` counts every retry attempt and can exceed tx packets. `tx failed` stayed
  small, but with no loss on the link it cannot be shown to measure loss.
- ath10k: `tx failed` is never reported (0).

### `port_table[]` entry

Processed only when `Device.isSwitch()` is true for the reported model —
`hasFeature(UiHQyVmgX) || hasFeature(yojQKHv)`. The model registry
(`com.ubnt.data.dhdeXcHqLRBKMUZk`) registers `U6IW` as device type `uap` with **5 ethernet
ports** and the switch feature, matching reality (a U6-InWall has a built-in 4-port downstream
switch). A plain AP like `U6MP` is not a switch. So for the model openUF impersonates this is
not optional: an empty `port_table` means zero wired clients can ever appear.

One entry per `cfg.net.ports`, carrying `port_idx` (1-based), `name`, `media`, `up`, `enable`,
`speed`, `full_duplex`, `is_uplink`, `speed_caps`, `port_poe`, `poe_caps` and
`rx_bytes`/`tx_bytes`/`rx_packets`/`tx_packets`/`rx_errors`/`tx_errors`. Where those facts come
from depends on what the board can be asked:

**Per-socket (swconfig board, modelmap field `{idx, swport}`).** One entry per physical socket.
`up`/`speed`/`full_duplex`/`pvid` and the ARL table come from a single `swconfig dev <sw> show`
(`sysinfo.switch_status`), and `is_uplink` is set on the socket the default gateway's MAC was
learned on (`sysinfo.uplink_phys_port`) — detected, never declared, because on an AP the cable
is in whichever LAN socket the installer used. Counters are the switch's own per-port MIB
(`RxGoodByte`/`TxByte`; there are no per-port packet or error counts, and an AR8327 with
`ar8xxx_mib_poll_interval: 0` has no MIB at all), falling back on the uplink entry only to the
CPU netdev's `sysinfo.interfaces()` counters — everything the CPU sent or received crossed that
socket. Other sockets report `0` rather than a fabricated share of the same total.

The two shapes mix within one board, per port: an entry with no `swport` falls through to the
netdev source even when the switch answered. That is not a fallback but the right answer for a
socket wired to its own MAC and PHY rather than to the switch — the TL-WDR3500's WAN socket is
a second `ag71xx` surfacing as `eth1`, so sysfs there describes that socket and not the CPU's
link.

**Netdev (no switch, no swconfig, or no identifiable uplink — modelmap field
`{idx, ifname, uplink}`, defaulting to `{wan_cpueth=uplink, lan_cpueth=lan}`).** `up` from
sysfs `carrier`/`operstate`, `speed`/`full_duplex` from sysfs, counters from
`sysinfo.interfaces()`, `is_uplink` from the modelmap. On a swconfig board every one of those
describes the *CPU port* — the internal SoC↔switch link, always 1000/full — which is why this
is the fallback and not the default: a TL-WDR3500 reported GbE on an uplink whose socket had
negotiated 100baseT, and the gateway's own Ports view said FE for the same cable.

**On a DSA board the netdev path is not a fallback — it is the right source.** There is no
`swconfig` binary at all, and none is wanted: each socket is its own netdev (`wan`, `lan2`,
`lan3`, `lan4` on a Xiaomi AX3000T — no `lan1`, since DSA names ports from the device tree
rather than the case labels), so sysfs already describes that socket's own cable. The one thing
sysfs cannot say — which socket faces the controller — comes from the bridge instead of an ARL
table: `bridge fdb show br br-lan` names the port each MAC was learned on, and
`sysinfo.uplink_bridge_port` looks up the default gateway's there. Filter on `master` *and*
`permanent`: the port's own address arrives as `<mac> dev wan master br-lan permanent`, a
master line like any other, and counting it puts the AP's own socket MAC in its client list.
Live-confirmed on an AX3000T: four ports rendered, port 1 flagged uplink at GbE with no
`mac_table`, port 2 at **FE** with its host, port 3 disconnected, port 4 at GbE with its host.
The FE/GbE split is the thing worth noting — the netdev path reported two different negotiated
speeds on one board, which the swconfig CPU-port path could never do.

**Non-uplink ports additionally carry `mac_table[]`** — `{mac, ip, hostname, age, uptime,
vlan}`, where `vlan` is present only for a socket openUF has assigned to a VLAN and is what
places the client on the right *network* (absent means 1) — joined with `/proc/net/arp` for IPs
and `/tmp/dhcp.leases` when present for hostnames (optional: an AP is usually not the DHCP
server, and `hostname` stays absent rather than invented). The host list itself is per-socket
from the ARL table (`sysinfo.switch_mac_table`, multicast/broadcast MACs filtered on the
address bit), or `sysinfo.mac_table(ifname)` off `bridge fdb show dev <ifname>` on the netdev
path (dynamic `master br-lan` entries only; `self`/`permanent` and multicast/broadcast
filtered). `bridge fdb` can only ever say "behind the CPU port", so on a switch board it cannot
place a host on a socket — that is what the ARL adds. Sockets whose `pvid` is not the
management VLAN carry no `mac_table` either: the Archer C5's WAN socket is live and has learned
a host, but it sits on VLAN 2 with its CPU port down, so that host is not on the LAN it would
be listed in.

Ports flagged `is_uplink: true` are skipped by the controller for client creation, since that
port faces the controller's own network.

**An uplink port must carry no `mac_table` at all — not even the gateway.** The controller
matches every MAC on a port against its adopted devices, and a port carrying exactly one known
device files that device into this one's `downlink_table` (`wRSpUfdrmMXnppHBKZ`):

```java
bl9 = !is_uplink && device.isUplinkMac(neighbour);
if (!bl9) downlink_table.add(neighbour, port);
```

The `isUplinkMac` guard that would prevent it is ANDed with `!is_uplink`, so it disables itself
on exactly the port where it is needed — the gateway would hang beneath every AP that reported
it, inverting the topology map. A real gateway escapes this because its upstream is the ISP's
router, which is not an adopted device and never reaches that branch; openUF cannot tell the
two cases apart from the device. Verified on the live site: with both APs silent on their
uplinks, each AP's `downlink_table` is empty and the gateway's holds both APs, which is the
correct shape.

A blank Connection column on an uplink port is therefore intended. `last_connection` is only
recomputed when a port reports exactly one MAC (`wefewPevorbc`: `if (list.size() > 1) return
existing`), and is never touched at all when the port sends no `mac_table` field — which is why
a stale value there persists until cleared with the Ports view's **Clear Last Seen Device**.

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
unlike the `spectrum-scan` cmd's real scan trigger. Nested shape (confirmed against
`PGOcbDWlbnYQdFW`, which reads a top-level `scan_radio_table` array and hands each entry's
nested `scan_table` to the ingestion service — not a flat list):

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

**`essid` is decoded from iw's escaping.** `iw` prints every SSID byte that isn't printable
ASCII as `\xNN`, which covers all UTF-8 bytes, a backslash, and a leading or trailing space.
Passed through as-is, a hotspot with an accented name shows up as literal escapes (e.g.
`Caf\xc3\xa9 Guest`), and the controller's evil-twin check (`essid ∈ site SSIDs`) would also
miss a site SSID written that way. Decoding is unambiguous because iw escapes the backslash
too. An empty or NUL-filled (hidden) SSID is sent with no `essid`, and the tab shows the BSSID.

**Three Environment columns are the controller's, not the AP's** (10.6 bundle
`react-app-wrapper`, column list `Wt`):

- **Standard** (`WIFI_STANDARD`) renders `jt[row.radio.toUpperCase()]`, a fixed map whose
  English strings are `NA` "802.11n/a/be", `NG` "802.11n/b/g/be", `6E` "802.11ax/be", `NA_AC`
  "802.11n/a/ac", `NA_AX` "802.11n/a/ac/ax" and `AD` "802.11a/d". It describes no neighbour's
  PHY: the scan ingest (`com.ubnt.service.aS.qikih`) overwrites every row's `radio` with the
  **parent** `scan_radio_table[].radio` before storing it, whatever the row sent, using the
  row's `band` only for the pseudo-radio `scan`. So a stored `radio` is always a band name
  (`na`/`ng`/`6e`), every 5 GHz row reads "802.11n/a/be" even for a 2014 802.11ac router (on a
  real UniFi AP too), and the `NA_AC`/`NA_AX` keys are unreachable through `stat/rogueap`.
  Sending a per-row standard is impossible, and renaming the parent radio would mislabel every
  row the same way and break the consumers keyed on `na`/`ng` (Radio AI's band filter,
  `kFACvOhX`).
- **AP** (`AP_COUNT`) is not a per-row field. Rows are grouped by `essid` and the cell shows
  `children.length + 1` only on a group's parent row; a BSS alone under its name is blank, on a
  real UniFi AP as well.
- **Vendor** renders `oui`, which the controller fills from the BSSID. No AP sends it, and
  `PeerScan` has no such field. It stays blank for locally-administered BSSIDs (random or
  virtual, so no vendor exists) and for OUIs missing from the controller's database — live, 23
  of 42 rows resolved, and of the 19 blanks 14 were locally-administered BSSIDs.

#### Enriching it without scanning — 802.11k beacon reports

`scan dump` reads the kernel's **passive** BSS cache, which fills only from beacons the radio
overhears on the channel it already serves: measured at 6 BSSes on a 2.4 GHz radio on ch 11, 1
on a 5 GHz radio on ch 44, and **0** on the Archer C5's 5 GHz radio. An active sweep on the
same board found 21 BSSes across 8 channels on 2.4 GHz — but cost 12 % packet loss to an
associated client for the ~3 s it ran, against a 0 % baseline. Ubiquiti's own documentation
names the way out: Channel AI "scans the surrounding wireless environment using **neighbor
reports and automated RRM scans**". In an 802.11k beacon measurement the *client* leaves the
channel and reports back, so the AP never stops serving. `openuf/rrmscan.lua` implements
exactly that, and nothing else.

| | |
|---|---|
| Request | `ubus call hostapd.<iface> rrm_beacon_req '{"addr":…,"mode":1,"op_class":115,"channel":255,"duration":50}'`. mode 1 is *active*; mode 2 (beacon table) reports from a cache that may be empty. `channel: 255` means every channel in the operating class |
| Response | Arrives asynchronously as a ubus **notification** on the per-BSS object. `ubus listen` catches broadcast events and receives **nothing at all** here — a listen across two requests captured 0 notifications while a `ubus subscribe hostapd.<iface>` over the same window captured 22 |
| Fields used | `bssid`, `channel`, `rcpi`, `rep-mode`. RCPI is the 0.5-dBm scale anchored at −110 dBm (802.11-2020 9.4.2.38), so **dBm = rcpi/2 − 110** — checked against a sighting of the client's own AP at rcpi 124 → −48 dBm |
| Fields refused | A non-zero `rep-mode` means incapable/refused/late and must not be published; captured examples also carry an all-zero BSSID on channel 0 |
| Parsing hazard | `start-time` holds a raw 64-bit TSF that real clients emit past what a double represents (`-7160986498777481216` captured), so the payload is matched field-by-field rather than JSON-decoded |

One request returned **15 BSSes at once**, across 2.4 GHz channels 1/3/4/6/7/9/10/11 *and*
5 GHz channels 36/44/48 — from a client associated on a 5 GHz radio. Clients ignore the
requested operating class's band restriction, so one report enriches **both** radios; the merge
therefore keys on the reported channel's band, never on the interface the request left by.

Client support is a lottery and this can only ever supplement the passive cache. Of 13 clients
surveyed across two APs: 9 advertised no 802.11k at all (`rrm=0`), 3 advertised beacon-active +
beacon-passive and answered in full, and 1 advertised **beacon-table only**, acknowledged every
request (`BEACON-REQ-TX-STATUS … ack=1`) and never sent a report — hostapd itself refuses a
passive request for such a client with "does not support passive beacon report". Table-only is
therefore not treated as capable.

When a report carries no frame body, two fields need care on the way into `scan_table`:

- **`bw` is set to 20.** Not a guess: every AP occupies at least its 20 MHz primary. It also
  cannot safely be omitted — the tab's unconditional filter indexes
  `T.R[band][bw>0 ? bw : <per-band default>]`, and a falsy `bw` falls through to a default this
  build may not define, which drops the row silently.
- **`security` is left absent.** There is no floor to fall back on, and writing `open` states
  in the operator's rogue-AP view that a neighbour is unencrypted when nothing measured it
  (four WPA2 neighbours all rendered as "open" that way). With the field absent the cell
  renders blank, the sidebar's Security filter disappears, and the rows still render.

Live-confirmed on the Archer C5's 5 GHz radio, whose passive cache held **zero** BSSes: after
one beacon request the Environment tab listed **four**, at −53/−69/−81/−81 dBm on ch 36/44/48,
one of them the *other* AP's 5 GHz BSS, which this radio cannot hear from another room but the
client could.

**Request interval: hourly.** hostapd logs every beacon report it receives (`wpa_msg` at
`MSG_INFO`, which `hostapd -s` sends to syslog) as one `BEACON-RESP-RX` line of up to ~1 KB of
hex, about 15 per answer, and openUF cannot suppress that without lowering hostapd's log level,
which also hides `DFS-*` and `AP-STA-CONNECTED`. At a 600 s interval those lines held 72 %
(Archer C5) and 78 % (AX3000T) of a 128 KB `logread` buffer, leaving the AX3000T only ~3 h of
log. The controller does not need that rate: openUF sends a reported neighbour for only 30 s
and the controller then keeps the row on its own (live `stat/rogueap` listed rows last seen
22 h earlier). The default is 3600 s.

#### The frame body: hostapd's control socket, not ubus

Without the frame body, 5 GHz rows are named by their BSSID, with no Security, at 20 MHz.

- **ubus has no body.** The `beacon-report` notification carries `address`, `op-class`,
  `channel`, `start-time`, `duration`, `report-info`, `rcpi`, `rsni`, `bssid`, `antenna-id`,
  `parent-tsf` and `rep-mode`, and nothing else. OpenWrt's current `ubus.c` adds a base64
  `report` with the whole element; the 25.12 build (`wpad-mbedtls
  2025.08.26~ca266cc2`) does not have it — 11 notifications captured, none carried it.
- **The control socket has it.** `rrm.c` also emits `BEACON-RESP-RX <sta> <token> <rep_mode
  hex> <report hex>` to attached monitors. Subelement 1 (Reported Frame Body) holds the fixed
  fields and then SSID, rates, Country, RSN, RM capabilities, HT capabilities, HT operation,
  extended capabilities, VHT capabilities, VHT operation and Tx power envelope. Subelement 2
  (Reported Frame Body Fragment ID) `01 80` means fragment 0 with the *more* bit set: the body
  is cut and the vendor elements at the end of the beacon are lost.
- **Why clients send it.** `rrm_beacon_req` includes no Reporting Detail subelement (ubus takes
  `addr`, `mode`, `op_class`, `channel`, `duration`, `bssid`, `ssid` only), and an absent
  Reporting Detail means level 2, all fixed fields and elements.
- **`hostapd_cli -a <script>`** runs `<script> <ifname> <event words…>` for each event
  (`$1=phy0-ap0 $2=BEACON-RESP-RX $3=<sta> <token> <mode> <hex>`), about 0.9 MB RSS per process.
- **The fixed `channel` field can be the centre channel.** Several 5 GHz BSSes were reported
  with `op-class 81` or `129` and `channel 42`, including the Archer's own BSS on 36. The HT
  operation element's primary channel is the reliable one.
- **What a client actually sends varies.** Four bodies captured from one client: 205 bytes
  (fragment 0, more bit set); 218 bytes, the same; 218 bytes with a vendor element mid-list and
  Country after Tx Power Envelope, so the beacon's element order does not survive; and **32
  bytes holding only the SSID and one vendor element**, privacy set, with no fragment
  subelement — a filtered body. The rest of a fragmented body arrives as a **separate report
  for the same BSSID**, its body starting mid-beacon. A rule reading "privacy, no RSN, not
  flagged as cut" as `wep` sent that 32-byte body out as WEP at 20 MHz.

openUF (`rrmscan.parse_report`) therefore treats anything missing from a body as unknown and
takes each field only from an element that is present: `essid` from the SSID element (empty or
NUL means hidden, nil); `security` `wpa2` for RSN, `wpa` for the WPA vendor element, `open`
when the privacy bit is clear, **never `wep`**; `bw` from VHT operation on 5 GHz and HT
operation on 2.4 GHz through `sysinfo.channel_width`, the same decision as the scan cache, so a
5 GHz body without VHT operation gives no width and the merge's 20 MHz floor applies; `channel`
from the HT operation primary. A continuation fragment returns nil, so it cannot take its
BSSID's place ahead of fragment 0.

**This AP and its siblings.** Clients report the AP they sit on and its siblings like any other
BSS (live: the Archer listed its own BSSIDs at −11 dBm, and the office AP listed the Archer's
5 GHz BSS). Once the SSID is filled in, a sibling carrying a site SSID without `is_unifi`
triggers the controller's rogue check — *"This third-party access point is broadcasting your
network's SSID"* fired live on the Archer's BSS as reported by the office AP. The tag cannot
come from a report, because the identity element is a vendor element at the end of the beacon,
past the cut. So the merge skips this AP's own BSSIDs (`vap_table`) and usteer's remote-node
BSSIDs (`ubus call usteer remote_info`); if usteer is not answering, a reported BSS carrying one
of this site's SSIDs is sent without `essid`, so it cannot raise a false alert. ⚠️ An evil twin
that only a client ever saw is then not flagged.

What a real UniFi AP does (firmware-confirmed for 3.9.27 to 4.0.15, `/bin/mcad`
`prepare_scan_array`): it sends the driver's scan list (`libubnt` `get_scanlist` →
`parse_scan_results`) with no BSSID filter, dropping only an entry on the other band (decided
from the entry's mode string). Siblings therefore reach the controller, tagged
`is_unifi`/`serialno` from their vendor element, and the controller's scan ingest sends a row
with `is_unifi` down the UniFi-device path and never stores it as a `stat/rogueap` row. A radio
does not hear its own beacons, and the other radio's BSSes are on the other band, so the AP's
own BSSIDs never appear. openUF matches this: passive rows tag siblings `is_unifi` and 802.11k
rows skip own and sibling BSSIDs.

**Two copies of each report.** hostapd's `rrm.c` emits the control-socket line first and the
ubus notification second, and they reach the event file through different processes
(`hostapd_cli -a` and the `ubus subscribe` loop), often landing in different 10-second drains.
A per-BSSID cache that keeps whichever came later lets the bodiless ubus copy replace the named
record (live: every row of one office-AP report went out unnamed at 20 MHz on centre channel
42). A bodiless record now keeps the essid, security, width and primary channel that a body
proved for the same BSSID and band, and still updates the level and time.

**Not every client writes RCPI into the RCPI field.** One office 2.4 GHz client wrote signed
dBm: it reported its own AP as `0xbf`, which is −65 dBm read as signed and −14.5 dBm read as
RCPI, while `iw station get` measured it at −71 dBm, and every neighbour it reported came out
between −11 and −26 dBm. The same byte goes to both the control socket and ubus. openUF decides
per station which way it writes the byte, using the one BSS whose true level is known: the
station's own AP, which every captured report includes. The station's report for that BSSID
(`iw dev <if> info`) is compared with hostapd's `signal avg` for the station (`iw dev <if>
station get`): within 12 dB signed and more than 20 dB off as RCPI → signed; within 12 dB as
RCPI → standard; otherwise the sample decides nothing. The decision lasts for the daemon's
lifetime and applies to that station's ubus reports too, and an uncalibrated station is read
the standard way. After the fix, that client's neighbours came out at −67 to −84 dBm.

`is_rogue` is much narrower than the tab name suggests: set true only when a neighbouring BSSID
broadcasts the **same essid as one of the site's own configured networks** (an evil-twin check
raising `EVT_AP_DetectRogueAP`). Ordinary neighbours correctly have `is_rogue: false` and still
appear in the Environment list.

**The controller never checks a scanned BSSID against its own devices' `vap_table`s**
(`com.ubnt.service.aS.rhAW`, the scan-ingest loop; the only vap_table lookup in that class
feeds the wireless-uplink candidate list). Whether a BSS is "ours" is the **reporting AP's**
call, made per entry:

| Entry fields | Controller outcome |
|---|---|
| `is_unifi: true`, `serialno: <device MAC>` (or, without `serialno`, a BSSID in a Ubiquiti OUI it can map back) | Device looked up in the site. If adopted: recorded as a UniFi neighbour, **not** stored as a rogue — the row leaves the Environment list. Otherwise: rogue check below, but skipped when the MAC is a known device |
| no `is_unifi` | `is_rogue = essid ∈ site SSIDs` |

Real UniFi APs learn `is_unifi`/`serialno` from a Ubiquiti vendor IE in each other's beacons.
With nothing equivalent, a two-AP site has **all six** sibling BSSes `is_rogue: true` and
AirView flags one as a third-party AP broadcasting the network's SSID. openUF beacons its own
vendor IE on every VAP — `dd 0d 02:6f:55 6f:55:46 01 <identity MAC>` via hostapd's
`vendor_elements` — reads it back from the kernel's scan cache over nl80211 (ucode's `nl80211`
module, which OpenWrt's wifi scripts are built on), and tags matching entries `is_unifi` +
`serialno`. Not from `iw`: OpenWrt's default iw build strips the printer for unknown vendor
elements, so the element never appears in `iw scan dump` output, `-u` or not — verified live on
both boards, where the same cache read over nl80211 held it. The OUI is deliberately **not** a
Ubiquiti one: a real UniFi AP would parse our layout as its own. 802.11k-reported entries are
never tagged, since the element sits past where a client's frame body is cut.

**The UniFi AP's own element** (firmware-confirmed for 4.0.15). `umac.ko`'s
`ieee80211_add_ubnt_ie` writes it into every beacon and `libubnt`'s scan parser reads it back;
`mcad` then reports the parsed fields per scan entry (`is_ubnt`, `is_unifi`, `serialno`,
`is_default`, `is_locating`, `is_isolated`, `is_vport`, `is_vwire`, `is_meshv3`):

```
dd <len> | 00 15 6d (OUI) | 00 01 01 (UniFi AP) | <flags> | 01 02 <system id, 2 bytes>
         | 81 06 <serialno: the device MAC, 6 bytes>
         | [84 40 <64 bytes>]            only on a vport VAP of an unadopted (default) AP
         | [82 01 <x>] [83 <n> <bytes>]  only on a vwire VAP; the parser skips both
flags: 0x01 default (unadopted)  0x02 locating  0x04 vport  0x08 vwire  0x10 isolated  0x20 meshv3
```

The parser accepts only OUI `00:15:6d` with a body of at least 11 bytes, takes subtype
`00 01 01` as `is_unifi`, starts the TLVs at offset 13, and logs any tag other than `81`-`84`.
`mcad` formats `serialno` with `%02X` six times, so 12 uppercase hex digits. `00 00 00` and
`00 01 00` are other Ubiquiti products (`is_ubnt` only, system id at offset 10). openUF still
beacons its private element, not this one: a real UAP parsing an openUF beacon would take the
flags at face value, and `is_vwire`/`is_vport` feed its wireless-uplink choice
(`find_serialno_vwire_in_uplink_wds_iface_scan_records`).

openUF **reads** this element, though (`sysinfo.peer_match_ucode`): OUI `00:15:6d`, subtype
`00 01 01`, then the TLVs walked from body offset 11 to the first `81 06`, whose MAC becomes
the entry's `serialno`; the flags are ignored. Seen live from the living-room AP: a
neighbour's current-firmware UniFi AP beacons exactly this layout, with flag `0x40` on its
second BSS (not in 4.0.15) and a TLV `0x89` after `0x81` (36 bytes of ASCII, a UUID). Both of
its BSSes went out in a real heartbeat payload with `is_unifi: true` and its base MAC as
`serialno`, which is the BSSID minus one, as `0x81` carries the device MAC. The ucode cannot
run in CI or the lab; `tools/peer-ie-vectors.lua` runs the generated matcher against 12 vectors
in an OpenWrt 25.12 rootfs image.

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

These are explicitly approximations, flagged as such in the code. Listed here so nobody
mistakes them for measured values.

| Field | Status |
|---|---|
| `sta_table[].satisfaction` | The firmware's formula. Its TCP-loss, TCP-latency and WiFi-latency terms are always 100: mac80211 has no source for them |
| `spectrum_table[].width` | Each 20 MHz reading is repeated once per width the band offers; the UI averages them over a bonded block. No live-scan source measures a bonded block directly |
| `spectrum_table[].interference` | Noise-floor dBm passed through; `iw survey dump` has no interference metric of its own. Falls back to the pre-sweep reading for any frequency whose post-scan noise comes back `0` |
| `radio_table[].builtin_antenna` = `true`, `.builtin_ant_gain` = `3` (dBi) | **Constants — no software source exists for either.** Not inert: the controller adds the gain to TX power to display EIRP, so a board with different antennas reports a wrong EIRP. Change them in `ucihelper.RADIO_DEFAULTS` if your hardware differs |
| `radio_caps().has_fccdfs` | Mirrors `has_dfs`; `iw` exposes no separate FCC-DFS indication |
| `radio_caps().has_eht240` / `.has_eht320` | Hardcoded `false` — openUF has no 802.11be target hardware to derive them from |
| `port_table[].media` = `"GE"`, `.enable` = `true`, `.speed_caps` = `0`, `.port_poe` = `false`, `.poe_caps` = `0` | Constants. The PoE ones are honest for every target board (none source PoE); `media`/`speed_caps` are unmodelled. `speed`/`full_duplex`/`up` **are** measured |
| `port_table[].rx_packets`/`tx_packets`/`rx_errors`/`tx_errors` on a per-socket entry | `0`. swconfig's per-port MIB exposes byte counters only, and the CPU netdev's packet/error totals belong to every socket at once. A downstream socket's `rx_bytes`/`tx_bytes` are likewise `0` on a driver with no MIB (AR8327 with polling off) rather than a share of the CPU total |
| `serial` | Derived from the device MAC with the colons stripped — a real AP's serial is a separate factory value openUF has no equivalent of |
| `spectrum_scanning` | `true` only in the inform between the spectrum-scan cmd and its sweep |
| `lldp_table[].is_wired` = `true` | LLDP is inherently a wired-link protocol |
| `model` / `platform` / `version` / `required_version` / `bootrom_version` | The emulated UniFi identity from `ufmodel/*.lua` — deliberately not the host hardware. This is the point of the project, not an accidental approximation |
| `wps_device_name` / `ap_setup_locked` | Standards-based rather than Ubiquiti-derived, and inert: OpenWrt never emits the WPS block that would carry them |

Everything not listed above is measured from the running system.

### WPA3 needs `radio_caps2` bit `0x1`, or the controller downgrades it silently

Without the bit, a WLAN set to **WPA2/WPA3** in the UI reaches the AP as plain WPA2 and nothing
anywhere says so: the `system_cfg` contains no `sae` and no `wpa3`, just `aaa.1.wpa=2`,
`aaa.1.wpa.key.1.mgmt=WPA-PSK` and the PMF keys. Applied faithfully, hostapd then runs
`wpa_key_mgmt=WPA-PSK FT-PSK WPA-PSK-SHA256` and every client — WPA3-capable ones included —
associates with AKM `00-0f-ac-2`/`-4`/`-6`, never `00-0f-ac-8` (SAE). The downgrade is per
device, in `com.ubnt.service.config.ubntconf.QSAkfnbfInKJ`:

```java
if (wlanconf.isWpa3()) {                      // wlanconf field wpa3_support
    if (!radio.CVir()) {                      // radio lacks the SAE capability
        if (wlanconf.isWpa3LegacyEnabled())   // wlanconf field wpa3_transition
            return downgrade(wlanconf, radio);          // ← silent WPA2
        log.warn("SAE cannot provision {} to {}", name, mac);
        return null;                                     // WLAN dropped entirely
    }
```

So a **transition-mode** WLAN degrades quietly, while a **WPA3-only** WLAN is dropped from the
device altogether with that one server-side log line. `CVir()` is a bit test on `radio_caps2`,
and tracing which field backs it is what settled the question:

```
config gen (QSAkfnbfInKJ)   calls radio.CVir()
CVir()                      = (1 & ZPjpXpgFhJSgqk().orElse(0)) == 1
ZPjpXpgFhJSgqk()            -> impl field iBjnA          (com.ubnt.g.f.e.jRsSex)
iBjnA                       <- builder field SuUD
SuUD                        <- setter rMxwXnPhhdotvjERKoA(int)
that setter is called with  getInt("radio_caps2")        ← the wire field
```

`radio_caps` lands somewhere else entirely — builder `kJeOrfqt` → impl `DbisCuTqoItCGd` →
accessor `FJaWnIAautY()`, which is the MIMO column and nothing more. **The two capability
integers are not interchangeable.** Two traps this exposed, both worth keeping:

- **A device-state change alone triggers no push.** Setting a capability and waiting proves
  nothing; clearing the stored `cfgversion` and restarting forces the full push that shows
  whether the bit worked.
- **Check the receiver's type.** The model registry does exist —
  `getModel().radiosByBand().getOrDefault(band, EMPTY_DEVICE_MODEL_RADIO)`, with the
  U6-InWall's entry mapping `BAND_NA→2400`, `BAND_NG→570` — but it returns
  `com.ubnt.g.f.VVyiC`, a **different type** from the device radio DTO `com.ubnt.g.f.e.VVyiC`
  that `CVir()` is invoked on. It is not on this path, so "the capability comes from the model
  registry, no payload field can unlock WPA3" was wrong.

`wpa3_supported` genuinely is inert: the only class carrying the literal
(`com.ubnt.net.k.aI.jRsSex`, a record of `wpa3Supported` / `band6GHzSupported` /
`oweSupported`) is **constructed, never parsed** — built from an injected
`com.ubnt.service.wifi` service, ignoring the device parameter — and reading the persisted
device back confirms it: `radio_caps` round-trips verbatim while `wpa3_supported` and
`owe_supported` come back `undefined`. openUF still sends it, because it is truthful and
another version may read it, but it unlocks nothing.

The emission side is gated separately, on the WLAN alone
(`com.ubnt.service.config.j.rYtJfMBbtgWvku`: `isWpa3() || band == 6E`), and produces
`wpa3.support=enabled` + `wpa3.transition=enabled|disabled` — the keys
`_parse_wifi_system_cfg` reads, since **SAE never arrives as a `wpa.key.<n>.mgmt` value** on a
radio without the bit.

**What a transition-mode push looks like.** Two classes produce it —
`com.ubnt.service.config.eWivisHeQsnaqDtx` for the WLAN block (prefix recipe `aaa.`) and
`com.ubnt.service.config.ubntconf.OXMua` for the SAE sub-block — both behind the same gate
(`isWpa3() || radioBand == 6E`, which is why 6 GHz always gets WPA3):

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

plus, only when the site sets them: `sae.anti_clogging` / `sae.sync` (each when > 0),
`sae.groups.<n>.group` with `sae.has_groups=enabled` (from `sae_groups`),
`sae.psk.<n>.psk`/`.mac`/`.id`/`.vlan` (SAE private PSKs), and `wpa3.enhanced_192=enabled` for
EAP with Enhanced 192-bit.

**The structural trap:** `SAE` *replaces* `WPA-PSK` — the wire never carries both, so the AKM
set alone cannot distinguish transition mode from WPA3-only. Only `wpa3.transition` does.
Reading the AKM by itself provisions a mixed WLAN as pure WPA3 and locks out every WPA2 client.

Hardware-confirmed end to end on both APs: with `radio_caps2 = 0x1` the next push carried
`wpa.key.1.mgmt=SAE`, `wpa3.support=enabled`, `wpa3.transition=enabled`,
`wpa3.ft.status=disabled` beside `ft.status=enabled` (the disagreement case the `aaa.<n>` table
describes) and `sae.anti_clogging=5`/`sae.sync=5`, and the APs came up controller-driven with
`encryption='sae-mixed'`, `ieee80211w='1'`, `ieee80211r='1'`, `sae_sync='5'`,
`sae_anti_clogging_threshold='5'`, hostapd running `wpa_key_mgmt = SAE FT-SAE WPA-PSK
WPA-PSK-SHA256 FT-PSK` with `sae_require_mfp=1`, `sae_pwe=2`, `sae_groups=19 20 21`. Live
clients split exactly as transition mode intends: a Pixel 9 negotiated `00-0f-ac-9` (FT-SAE)
while older devices stayed on `00-0f-ac-2` (WPA2-PSK) on the same SSID. `wpad-mbedtls`,
OpenWrt 25.12's ath79 default, does support SAE (`sae_password`, `sae_groups`, `psk-sae` in
`ap.uc`), so claiming it is honest on that hardware.
