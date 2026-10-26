# Live controller validation environment

Disposable Docker environment for validating openUF's controller-pushed payload
assumptions against a real UniFi Network Application controller — see
[PROTOCOL-VALIDATION.md](../../PROTOCOL-VALIDATION.md) for the findings this
produces and [USAGE.md](../../USAGE.md#3-configuration) for the `debug_dump_file`
flag used to capture responses.

No target OpenWrt hardware or real Ubiquiti device needed — the controller is a
plain Docker container, and the "AP" is a disposable Alpine container reachable via
SSH. **Both L2 (broadcast + SSH) and L3 (`set-inform` only) adoption work
end-to-end** in this environment, once the setup below is followed exactly — see
PROTOCOL-VALIDATION.md's "Adoption: L2 vs L3" for how the two paths differ and
what each requires.

## 0. What this environment can and cannot show

The "AP" is Alpine with a **mocked UCI**, not OpenWrt. Two things to know before
you trust a result here:

- **UCI persists across process restarts** (since 2026-09-10). The mock writes
  `/var/lib/openuf-uci-mock.json` on every `set`/`delete` and reloads it at
  module load, the way a real `/etc/config/*` survives a reboot. That is what
  makes "does this survive a restart?" answerable here at all — the startup
  reapply of the Multicast/Broadcast Blocker and the WiFi Speed Limit rebuilds
  both from `openuf_bcfilt`/`openuf_ratelimit_*` stamped on each managed
  section, and that is now testable end to end. Before this the mock reseeded
  on every process start, so the whole question was invisible.
  Clear it with `docker compose down -v` (it lives in the container's writable
  layer) or `lua -e 'require("uci")._reset()'` for a clean run without
  recreating the container.
- **`state.json` does survive**, since it is a real file in the container's
  writable layer. `docker restart openuf-validation-ap` therefore makes a
  faithful reboot test for anything driven from state.json — the static-IP
  reapply, blocked clients, the LED toggle. The network is reset by Docker on
  restart, exactly as a reboot resets it.

The mock also gained a correct `cursor:delete(config, section, option)` on the
same date. It had ignored the third argument and deleted the whole **section**
either way — and the option form is not a rare path: `rf_config` deletes
`txpower`/`basic_rate`/`supported_rates`/`legacy_rates` on essentially every
radio push, and `wlan_add` deletes `macfilter`/`maclist` on every WLAN without a
MAC filter. The lab was destroying its own `radio0`/`radio1` wifi-device sections
and its freshly written wifi-iface sections on the ordinary push. The unit-test
mock in `tests/test_ucihelper.lua` always had this right, which is why unit tests
never showed it.

The mock gained `cursor:get()` on 2026-09-10. It had never had one, and
`usteer.set_enabled`'s no-op guard calls it on every WiFi setparam — so **every
setparam in this environment died partway through**, inside `_tick`'s pcall,
surfacing as a single stderr line. Everything after that call had therefore never
run here: the bcfilter and shaper reconciles, the switchvlan pass, and
`handle_response`'s own final `state.save`. If you see `handle_response failed`
in the AP's log, stop and fix the cause before trusting anything downstream of it.

## 1. Start the environment

```sh
# from the repo root
docker compose -f tools/validation/docker-compose.yml up -d --build
```

First boot of `unifi-db` takes a few seconds to run `init-mongo.sh`; give it a
moment before the controller container comes up healthy.

## 1b. The whole thing without a browser (recommended)

Sections 2–4 describe the UI path. **None of it needs a browser** — the entire
setup, adoption and config-push flow is the controller's own REST API, which is
far faster and is what you want when a `down -v` reset is part of the loop.
Verified end to end against 10.4.57 on 2026-09-10 and 10.6.106 on 2026-10-14.

```sh
J=/tmp/uc.jar                      # cookie jar
B=https://localhost:8443

# 1. Wait for the controller (302 = up; 000 = not yet, it takes ~60-90 s)
until [ "$(curl -sk -o /dev/null -w '%{http_code}' $B/)" != "000" ]; do sleep 10; done

# 2. First-run setup. No auth, works only while the controller is unconfigured;
#    this is the whole of the "Advanced Setup -> Skip -> credentials" wizard.
curl -sk -X POST $B/api/cmd/sitemgr -H 'Content-Type: application/json' \
  -d '{"cmd":"add-default-admin","name":"admin","email":"admin@openuf.local","x_password":"openufopenuf"}'

# 3. Log in (every later call needs -b $J)
curl -sk -c $J -X POST $B/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"openufopenuf"}'

# 4. Controller IP, then the inform-host and SSH settings of section 3.
CIP=$(docker inspect openuf-validation-controller \
      --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
SI=$(curl -sk -b $J $B/api/s/default/get/setting/super_identity \
     | python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['_id'])")
curl -sk -b $J -X PUT $B/api/s/default/set/setting/super_identity/$SI \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"super_identity\",\"hostname\":\"$CIP\"}"
MG=$(curl -sk -b $J $B/api/s/default/get/setting/mgmt \
     | python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['_id'])")
curl -sk -b $J -X PUT $B/api/s/default/set/setting/mgmt/$MG \
  -H 'Content-Type: application/json' \
  -d '{"key":"mgmt","x_ssh_enabled":true,"x_ssh_auth_password_enabled":true,"x_ssh_username":"root","x_ssh_password":"openuf"}'

# 5. Point the AP at the controller and start it (section 4, scripted).
#    By IP: a freshly adopted AP that informs to the hostname is refused with
#    "invalid inform_ip controller" (HTTP 400) on 10.6.106.
docker exec openuf-validation-ap sh -c \
  "sed -i 's|http://unifi:8080/inform|http://$CIP:8080/inform|' /opt/openuf/conf.lua"
docker exec -d openuf-validation-ap sh -c 'cd /opt/openuf && exec lua announce.lua > /tmp/announce.log 2>&1'
docker exec -d openuf-validation-ap sh -c 'cd /opt/openuf && exec lua inform.lua   > /tmp/inform.log   2>&1'

# 5b. Mark the controller as set up. This REST path never writes is_default=false,
#     so without this line the controller treats its next restart as a factory
#     default and drops its database (seen 2026-10-10: devices, WLANs, admins gone).
docker exec openuf-validation-controller sh -c \
  'echo is_default=false >> /config/data/system.properties'

# 6. Wait for it to appear (state=2, adopted=false), then adopt
sleep 25
curl -sk -b $J $B/api/s/default/stat/device | python3 -m json.tool | grep -E '"mac"|"state"|"adopted"'
MAC=<from above>
curl -sk -b $J -X POST $B/api/s/default/cmd/devmgr -H 'Content-Type: application/json' \
  -d "{\"cmd\":\"adopt\",\"mac\":\"$MAC\"}"
# state goes 2 -> 7 (adopting) -> 5 (provisioning) -> 1 (connected), ~45 s
```

Driving config from there:

```sh
# device_id comes from stat/device -- NOT from /rest/device, which 404s on this build
DEV=$(curl -sk -b $J $B/api/s/default/stat/device \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['device_id'])")

# IP Settings -> Static (emits netconf.1.*, route.1.gateway, resolv.nameserver.N.ip)
curl -sk -b $J -X PUT $B/api/s/default/rest/device/$DEV -H 'Content-Type: application/json' \
  -d '{"config_network":{"type":"static","ip":"172.19.0.50","netmask":"255.255.255.0","gateway":"172.19.0.1","dns1":"1.1.1.1","dns2":"9.9.9.9"}}'

# ...and back to DHCP
curl -sk -b $J -X PUT $B/api/s/default/rest/device/$DEV -H 'Content-Type: application/json' \
  -d '{"config_network":{"type":"dhcp"}}'

# Forget a device (its MAC changes whenever the container is RECREATED, so the
# old record lingers as state=0 and the new one arrives unadopted)
curl -sk -b $J -X POST $B/api/s/default/cmd/sitemgr -H 'Content-Type: application/json' \
  -d "{\"cmd\":\"delete-device\",\"mac\":\"$MAC\"}"
```

Three things that will cost you time otherwise:

- **Check for silent failures before believing any result:**
  `docker exec openuf-validation-ap grep -c "handle_response failed" /tmp/inform.log`
  must be `0`. `_tick` pcalls `handle_response`, so anything that raises mid-push
  costs one stderr line and skips everything after it — including the final
  `state.save`. See section 0.
- **`HTTP 404` from the inform POST is success**, not an error — see
  PROTOCOL-VALIDATION.md's "General protocol finding". A *connection* error is
  the real failure.
- **Never `pkill -f` a pattern from inside `docker exec`** if the pattern also
  matches your own command line — the exec shell kills itself and the block
  aborts with exit 143. Kill by PID, or match on something the wrapper does not
  contain.

`override_inform_host` on the `mgmt` setting did not persist on 10.4.57 in the
run above; setting `super_identity.hostname` to the controller's container IP was
enough for adoption and informs to work. If you hit `invalid inform_ip` in
`server.log`, that is the knob to revisit.

## 1c. WPA-Enterprise (802.1X): the RADIUS server

A FreeRADIUS container lives in the compose file behind the `radius` profile, so
the default workflow is unchanged. It gives the controller's RADIUS profile a
real, reachable endpoint, which is what makes the captured `aaa.<n>.radius.*`
block the one a real site would get.

**What it proves:** the wire format and openUF's parse/apply of it. **What it
does not:** nothing authenticates here — this AP container has no radios and no
hostapd, so no EAP exchange ever happens. Only real hardware can show that.

```sh
docker compose -f tools/validation/docker-compose.yml --profile radius up -d radius
RIP=$(docker inspect openuf-validation-radius \
      --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

# Sanity-check the server itself before blaming openUF. radclient is not in the
# freeradius image, so borrow it from a throwaway container on the same network:
NET=$(docker inspect openuf-validation-radius \
      --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker run --rm --network "$NET" alpine:3.21 sh -c \
  "apk add -q freeradius-utils && \
   echo 'User-Name=openuf-vlan,User-Password=openufpass' | \
   radclient -x $RIP:1812 auth openufradius"
# -> Access-Accept with Tunnel-Private-Group-Id = "10"
```

Users and secret are in `tools/validation/radius/` (`authorize`, `clients.conf`):
`openuf-test` accepts with no VLAN, `openuf-vlan` accepts with the RFC 3580
tunnel attributes, anything else is rejected. The shared secret is
`openufradius`. `docker logs openuf-validation-radius` shows every request —
the server runs in `-X` debug mode on purpose.

Then push an Enterprise WLAN (REST, continuing from section 1b's `$J` / `$B`):

```sh
RP=$(curl -sk -b $J -X POST $B/api/s/default/rest/radiusprofile \
  -H 'Content-Type: application/json' -d "{\"name\":\"openuf-lab-radius\",
   \"auth_servers\":[{\"ip\":\"$RIP\",\"port\":1812,\"x_secret\":\"openufradius\"}],
   \"accounting_enabled\":true,
   \"acct_servers\":[{\"ip\":\"$RIP\",\"port\":1813,\"x_secret\":\"openufradius\"}],
   \"interim_update_enabled\":true,\"interim_update_interval\":900,
   \"vlan_wlan_mode\":\"required\",
   \"use_usg_auth_server\":false,\"use_usg_acct_server\":false}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['_id'])")

# ap_group_ids is REQUIRED on 10.6.106 -- without it the POST fails with
# api.err.ApGroupMissing. The id comes from the v2 API; /rest/apgroup returns
# api.err.InvalidObject on this build.
AG=$(curl -sk -b $J $B/v2/api/site/default/apgroups \
     | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['_id'])")
WG=$(curl -sk -b $J $B/api/s/default/rest/wlangroup \
     | python3 -c "import sys,json;print([g['_id'] for g in json.load(sys.stdin)['data'] if g['name']=='Default'][0])")
NC=$(curl -sk -b $J $B/api/s/default/rest/networkconf \
     | python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['_id'])")

curl -sk -b $J -X POST $B/api/s/default/rest/wlanconf \
  -H 'Content-Type: application/json' -d "{\"name\":\"openuf-eap\",\"enabled\":true,
   \"security\":\"wpaeap\",\"radiusprofile_id\":\"$RP\",\"wlangroup_id\":\"$WG\",
   \"ap_group_ids\":[\"$AG\"],\"ap_group_mode\":\"all\",\"networkconf_id\":\"$NC\",
   \"wpa_mode\":\"wpa2\",\"wpa_enc\":\"ccmp\",\"is_guest\":false}"
```

Capturing the push: clear `/var/log/openuf-informs.log` first, then **change**
something (a `PUT` with identical content produces no new `cfgversion`, so no
`setparam` is sent and you will wait for a push that never comes — a
force-provision alone did not resend it either).

```sh
docker exec openuf-validation-ap sh -c ': > /var/log/openuf-informs.log'
# ...PUT the radiusprofile with a different interim_update_interval..., then
sleep 45
docker exec openuf-validation-ap sh -c 'grep setparam /var/log/openuf-informs.log' \
  | cut -d' ' -f2- | python3 -c "import sys,json;print(json.load(sys.stdin)['system_cfg'])" \
  | grep radius
```

What openUF made of it is in the mock's own dump — the real `inform.lua`
process's UCI state, which a separate `lua -e` cannot see:

```sh
docker exec openuf-validation-ap cat /var/log/openuf-uci-mock-wireless.json | python3 -m json.tool
# expect on the openuf_radio*_... section: encryption=wpa2+ccmp, NO `key`,
# auth_server_addr/port/shared_secret, acct_server_*, radius_acct_interim_interval,
# dynamic_vlan.
```

Verified end to end on 2026-10-26 against 10.6.106. Two traps that capture
pinned down, both now covered by tests:

- `aaa.<n>.wpa.psk` is **still sent on an EAP WLAN** (a dummy value the
  controller fills in). Carrying it into UCI would give the BSS a passphrase it
  must not have.
- `wireless.<n>.security=none` on the same push. The discriminator is
  `aaa.<n>.wpa.key.<k>.mgmt`, never that field.

## 2. Complete the controller's first-run setup

> The UI walkthrough, kept because it explains *what* each step is for. To just get
> a working environment, use [1b](#1b-the-whole-thing-without-a-browser-recommended).


Open `https://localhost:8443` (self-signed cert — accept the browser warning) and
step through the setup wizard: **Advanced Setup → Skip** (do not create a real
Ubiquiti cloud account) → set local admin credentials → Finish.

## 3. Set the Inform Host Override (required — do this before adopting anything)

> Scripted equivalent in [1b](#1b-the-whole-thing-without-a-browser-recommended), step 4.


Docker deployments of the UniFi Network Application don't know their own
externally-reachable address by default, and devices/informs get rejected
(`invalid inform_ip controller` in `server.log`) until this is set explicitly. This
setting lives in the controller's own database, so it's wiped by
`docker compose down -v` and must be redone after every full reset.

In the controller UI: **Devices → Device Updates and Settings → Device SSH
Settings** (or search "inform" in the settings search box) →

- Check **Inform Host Override**. **Use the controller container's real IP
  address, not the `controller` hostname** — get it with `docker inspect
  openuf-validation-controller --format '{{range .NetworkSettings.Networks}}
  {{.IPAddress}}{{end}}'`. A bare hostname here produces `invalid inform_ip
  <hostname>` in `server.log` once informs start flowing (this is what the value
  in that log line actually is — the AP's own configured `inform_url` host,
  echoed back — not, as an earlier version of this doc guessed, the override
  setting itself).
- Check **Device SSH Authentication**, username `root`, password matching the AP
  container's real sshd password (`openuf` by default per `ap/Dockerfile` — the
  controller's own password-strength validator requires ≥10 chars + uppercase +
  symbol, so if you change it here, `docker exec openuf-validation-ap sh -c "echo
  'root:<newpassword>' | chpasswd"` to match on the AP side too). **These
  credentials are only used for already-adopted devices** — see step 4.
- Apply Changes.

## 4. Start openUF inside the AP container (L2 / broadcast adoption)

> Scripted equivalent in [1b](#1b-the-whole-thing-without-a-browser-recommended), steps 5-6.


`debug_dump_file` and the `eth0` interface override are already baked into the
image (`ap/Dockerfile`), along with the real Ubiquiti factory-default `ubnt`/`ubnt`
SSH account (see below for why) and the `ssh-rsa` host key algorithm re-enable
`sshd` needs to negotiate with the controller's SSH client — no manual setup step
needed for any of that.

```sh
docker exec -it openuf-validation-ap sh
cd /opt/openuf

# Broadcast discovery (real UDP broadcast on port 10001 -- works genuinely in
# this Docker bridge network as of the announce.lua socket-creation-order fix):
lua announce.lua &

# Start the inform loop (foreground, so you can watch it live)
lua inform.lua
```

The device appears in the controller UI as a new **Access Point** entry (distinct
from any L3-only "Gateway" entry) with **Click to Adopt**. Click it — for an
L2-discovered device the controller genuinely SSHes in this time. It tries the real
Ubiquiti factory-default account, `ubnt`/`ubnt` (not the **Device SSH
Authentication** credentials from step 3 — those only apply once a device is
already adopted and reports itself as non-default), which is why the image bakes in
a `ubnt` user (UID 0) with that exact password. If adoption still fails, check
`docker exec openuf-validation-controller tail -f /config/logs/server.log` for the
`SSH adopt failed ip[...],msg[...]` line — `msg[unreachable]` with a
`HostKeyAlgorithms` complaint means the ssh-rsa fix isn't active; `msg[loginfail]`
means a credentials mismatch.

Once SSH adopt succeeds, `syswrapper.sh set-adopt` runs for real on the AP
container and writes `/etc/openuf/state.json` with a controller-issued `authkey`.
**No restart needed** — `inform.lua` reloads `state.json` on its own if the
file's mtime changes between loop iterations (`M._reload_if_changed`, checked
at the top of every ~10s cycle), so an already-running process picks up a
fresh SSH-driven adoption within one cycle. (This note used to say the
opposite — that was accurate before that reload logic was added, but got left
stale afterward. Re-verified 2026-07-12: reset an already-running, already-
adopted process's state via `reset-inform`, then re-ran `set-adopt` directly
without touching the process, and it resumed informing successfully on its
own — the only delay was the exponential backoff from the intervening failed
attempts, not a missed reload.)

## 5. Work through the validation matrix

For each row in [PROTOCOL-VALIDATION.md](../../PROTOCOL-VALIDATION.md), trigger the
scenario from the controller UI, then tail the capture file in another shell:

```sh
docker exec openuf-validation-ap tail -f /var/log/openuf-informs.log
```

Diff the captured JSON against the current code's assumptions, then record the
*confirmed end state* in `PROTOCOL-VALIDATION.md` — its field-reference tables and
feature matrix, not a narrative of the investigation. Any field-name corrections get
their own commit in the main codebase, per the project's usual per-finding commit
cadence.

**If the device never settles out of "Adopting"** — informs decrypting fine,
`last_seen` advancing, but a *different* `cfgversion` on every cycle — the AP is
sending CBC rather than AES-GCM informs, and the controller will not provision it.
See PROTOCOL-VALIDATION.md's "The GCM provisioning gate"; the AP image must have a
working `lua-openssl` build.

## 6. Device-to-device config clone ("Set Replacement Device" / "Load Configuration")

The controller's device settings (**Manage** section) can copy one device's
configuration to another — useful for spinning up a freshly-reset AP that inherits
an already-configured device's settings without redoing UI configuration.
**Neither feature involves a device-side export protocol**: both are
controller-side clones of the source device's stored DB config, followed by a
normal adopt + `setparam` push (confirmed in the decompiled controller sources —
the inform reply types are only noop/setparam/cmd/upgrade/reboot/setdefault). So
openUF supports them with no product-code changes; they just need a second
same-model device, which the `ap2` compose service provides (unique MAC/IP come
from its own `eth0`, model is the same U6-IW):

```sh
docker compose -f tools/validation/docker-compose.yml up -d ap2
```

`ap2` is behind the `replacement` compose profile, so the default
single-AP workflow is unchanged. Its mock stations are `de:ad:be:ef:02:0X`
(`ap`'s are `de:ad:be:ef:00:0X`), so the two APs never report the same
client and the controller logs no fake roams between them.

### Two APs for notif and roaming tests

Start and adopt `ap2` exactly like `ap` (step 5 with `openuf-validation-ap2`,
then step 6), and give the site a WLAN so both APs carry a `vap_table`.
Hand-made `STA_ASSOC_TRACKER` notifs can then be posted from either
container with openUF's own `build_packet`/`http_post`. Build the payload's
identity the way `inform.lua`'s entry point does: `dofile("conf.lua")`, then
`dev.conf` with `.config` and `.uap` merged in, plus the `ufmodel` as `ufhw`.
A bare `conf.lua` reports a different firmware version (6.6.55 instead of
6.8.2.15592), and the controller takes each such notif for a firmware change
(`device_upgraded=true`, visible with `debug.device=debug` in
`/config/data/system.properties`).

> **MAC caveat:** Docker hands the container a *fresh* eth0 MAC on every
> `docker stop`/`start` (observed live, 2026-07-13), so a restarted AP
> container is a brand-new device to the controller — its old device entry
> can't be resumed. Handy for minting fresh replacement targets; read MACs
> with the command in step 3 below *after* the container is up, never from
> an earlier run.

### Set Replacement Device (auto-adopt a new device with the old one's config)

1. AP1 adopted and configured as usual (steps 1–4).
2. Start `ap2` (command above), then inside it start **announce only** — the new
   device must be *detected* (announcing unadopted); do **not** adopt it in the UI:
   ```sh
   docker exec -it openuf-validation-ap2 sh -c 'cd /opt/openuf && lua announce.lua'
   ```
3. Get AP2's MAC:
   ```sh
   docker exec openuf-validation-ap2 cat /sys/class/net/eth0/address
   ```
4. In the UI on **AP1**: Settings (gear) → Manage → **Set Replacement Device** →
   enter AP2's MAC → Apply.
5. Take AP1 offline (`docker stop openuf-validation-ap`) and start AP2's inform
   loop in another shell:
   ```sh
   docker exec -it openuf-validation-ap2 sh -c 'cd /opt/openuf && lua inform.lua'
   ```
6. Once the controller marks AP1 offline, it auto-adopts AP2 (real SSH
   `set-adopt`, no "Click to Adopt" needed) and provisions it with AP1's cloned
   config. Watch it land:
   ```sh
   docker exec openuf-validation-ap2 tail -f /var/log/openuf-informs.log
   ```

### Load Configuration (clone between two adopted devices)

1. Both APs adopted (adopt AP2 normally per step 4, running its own
   `announce.lua` + `inform.lua`).
2. On the **target** device (e.g. AP2): Settings → Manage → **Load
   Configuration** → pick the source device in the dropdown (backed by
   `GET /v2/api/site/default/device/<mac>/clone-candidates`) → Apply.
3. The target receives an ordinary `setparam` push with the cloned config —
   verify via its `/var/log/openuf-informs.log` as above.

## 7. Tear down / reset

```sh
# Full reset (fresh controller + fresh AP state -- remember to redo step 3,
# Inform Host Override, after this since it lives in the wiped database).
# The --profile flags matter if you ever started ap2 (section 6) or the RADIUS
# server (section 1c): `down` ignores services whose profile isn't active, so
# without them those containers would survive the reset.
docker compose -f tools/validation/docker-compose.yml \
  --profile replacement --profile radius down -v

# Just re-adopt with a clean AP state, keep the controller/site config
# (Inform Host Override survives this since it doesn't touch unifi-db):
docker compose -f tools/validation/docker-compose.yml restart ap
docker exec openuf-validation-ap sh -c "syswrapper.sh reset-inform && rm -f /var/log/openuf-informs.log"
```
