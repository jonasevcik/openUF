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

The "AP" is Alpine with an **in-memory UCI mock**, not OpenWrt. Two consequences
worth knowing before you trust a result here:

- **UCI does not survive a process restart.** The mock's `db` is a module-local
  table seeded at load; `commit()` writes a JSON dump for inspection and nothing
  ever reads it back. So anything whose correctness depends on UCI persisting
  across a daemon restart — the startup reapply of the Multicast/Broadcast
  Blocker and the WiFi Speed Limit, for instance — **cannot** be validated here.
  What can be: that the reapply turns UCI markers into rules the real `nft` and
  `tc` accept, which this container does have.
- **`state.json` does survive**, since it is a real file in the container's
  writable layer. `docker restart openuf-validation-ap` therefore makes a
  faithful reboot test for anything driven from state.json — the static-IP
  reapply, blocked clients, the LED toggle. The network is reset by Docker on
  restart, exactly as a reboot resets it.

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

## 2. Complete the controller's first-run setup

Open `https://localhost:8443` (self-signed cert — accept the browser warning) and
step through the setup wizard: **Advanced Setup → Skip** (do not create a real
Ubiquiti cloud account) → set local admin credentials → Finish.

## 3. Set the Inform Host Override (required — do this before adopting anything)

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
single-AP workflow is unchanged.

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
# The --profile flag matters if you ever started ap2 (section 6): `down`
# ignores services whose profile isn't active, so without it the ap2
# container would survive the reset.
docker compose -f tools/validation/docker-compose.yml --profile replacement down -v

# Just re-adopt with a clean AP state, keep the controller/site config
# (Inform Host Override survives this since it doesn't touch unifi-db):
docker compose -f tools/validation/docker-compose.yml restart ap
docker exec openuf-validation-ap sh -c "syswrapper.sh reset-inform && rm -f /var/log/openuf-informs.log"
```
