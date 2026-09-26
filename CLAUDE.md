# openUF — agent instructions

openUF makes an OpenWrt AP present itself to a UniFi Network Application as a
Ubiquiti AP (default identity U6-IW). Pure Lua, runs on the device as two procd
instances (`announce`, `inform`) from `/opt/openuf/`.

## Map
- `openuf/inform.lua` — TNBU framing, inform loop, `_parse_wifi_system_cfg`
  (controller → neutral vap/radio fields), `build_json` (device → controller)
- `openuf/ucihelper.lua` — neutral fields → UCI (`apply_config`, `wlan_add`, `rf_config`)
- enforcement modules with their own nft tables / tc: `firewall.lua` (`bridge openuf`),
  `bcfilter.lua` (`bridge openuf_bcfilt`), `shaper.lua`, `l2guard.lua`
- `switchvlan.lua` (swconfig + DSA per-port VLAN), `sysinfo.lua` (iw/proc/bridge reads),
  `state.lua` (`/etc/openuf/state.json`, explicit `M.FIELDS` list), `crypto.lua`, `inflate.lua`
- `modelmap/` = board hardware profile, `ufmodel/` = presented UniFi identity
- `PROTOCOL-VALIDATION.md` — the evidence log for every wire-format claim. Read the
  relevant section before touching a protocol field; add to it when you establish one.

## Build & test
    eval $(luarocks path --local) && lua tests/run_tests.lua
- The `eval` prefix is mandatory: without it cjson fails to load and whole test FILES
  count as one failure each. If the total drops sharply, check the invocation first.
- **Target is Lua 5.1; the dev box is 5.5; CI is 5.1.** Green locally proves nothing
  for CI. No `\xNN` escapes (5.1 silently emits `x07`; use `string.char`), no `//`,
  `goto`, `\z`, `\u{}`, `table.unpack`. `os.execute` returns a number on 5.1: both
  0 and 1 are truthy, so normalise before branching.
- Syntax-check on 5.1: `docker cp openuf/<m>.lua openuf-validation-ap:/tmp/c.lua &&
  docker exec openuf-validation-ap luac -p /tmp/c.lua`
- CI failure: `gh run list` + `gh run view <id> --log-failed`. Don't guess.
- Run modules from the project root with `OPENUF_TEST_MODE = true` set; loading
  `inform.lua` without it starts a real inform loop.

## Verification: three tiers
Put every verification step into a tier and name the tier:
1. **Unit tests**: preferred. Write a test for untested code before auditing it by eye.
   Mutation-test a fix: break it and confirm a test goes red.
2. **Docker lab** (`tools/validation/`): anything driving a full inform cycle or mutating
   device state. Follow `tools/validation/README.md` § 1b (REST-only, no browser).
   - When state is ambiguous, reset fully: `docker compose down -v` + `up --build`.
     Never hand-edit UCI-mock JSON or `state.json` to fake a result.
   - The lab has no radios, no `uci` CLI, no procd/hostapd/swconfig. It proves the
     wire format and the parser, not that config reaches real UCI/hostapd. For the
     consumer side, replay a captured `system_cfg` through `_parse_wifi_system_cfg`
     + `apply_config` with a recording mock cursor.
   - Before trusting a lab run: `grep -c "handle_response failed" /tmp/inform.log` must be 0.
   - The lab has real `nft`/`tc`: execute generated commands against a dummy netdev
     (`ip link add openuf-test0 type dummy`) and check each rc. Also re-run for idempotency.
   - Local UI creds: `admin` / `openufopenuf` / `admin@openuf.local`.
3. **Real hardware**: only claims about radios, hostapd, regdomain, switch ASICs
   and DSA can be settled here. See `CLAUDE.local.md` if present.

## Engineering rules learned the hard way
- **A command that ran isn't a command that succeeded.** Read state back with the
  tool's own `show`/`list` (`swconfig ... show`, `nft list`, `/var/run/hostapd-*.conf`),
  not the UCI you wrote.
- **A UCI option must exist in the consumer.** Check `/usr/share/schema/wireless.*.json`,
  `/usr/share/ucode/wifi/` (the live generator on 25.12) and `/lib/netifd/hostapd.sh`.
  Unknown options are stored and silently dropped. Check the emitting gate too.
- UCI section names allow only `[A-Za-z0-9_]`. Invalid names commit "successfully"
  and are discarded. Test mocks must reject them.
- **Consumers keyed on producers that don't exist** are this codebase's recurring defect.
  Audit by crossing what the parser actually produces against every field read.
- Before concluding a controller setting isn't pushed, diff a real `system_cfg` across
  the toggle and read the whole keyspace. The discriminator is the field that changes,
  never a block's presence (decoys: `mac_acl.status`, `bcmc_l2_filter.status`, `qos.vap.*`).
- Controller protocol questions: decompile the controller (CFR, not jadx, on
  `internal-dependencies.jar`) or call live frontend functions. Don't infer from
  behaviour and don't read AP firmware.
- Absence of a wire key is often a sentinel for "off/auto". Tear down via an explicit
  signal, or via a marker/ledger when absence is ambiguous (`openuf_*` stamps, `st.*` ledgers).
- A controller-initiated kick (one-shot deauth) is not a block (persistent nft drop).
- `upgrade` from the controller is stored only, never flashed.
- **Report trades plainly.** If a fix makes any field worse, say so as prominently as
  the win, then keep digging. The target is a pristine fix, not an accepted trade.

## Commits & docs
- One commit per fixed finding.
- Commit message: subject + body + `Co-Authored-By` trailer only. No session URL.
- **Public repo: never commit real MACs or IPs.** Map to `192.0.2.N` (mgmt LAN),
  `198.51.100.N` (other VLANs), `00:00:5e:00:53:0X` (MACs), one placeholder per real
  value. Before every commit:
  `git diff --cached -U0 | grep "^+" | grep -nE "192\.168\.|([0-9a-f]{2}:){5}[0-9a-f]{2}"`
  and check the message too.
- A feature or confidence change updates **README.md** (capability table, ✅ live-confirmed
  / ⚠️ unconfirmed + reason) **and USAGE.md** (config keys, deps, UCI mapping,
  troubleshooting) in the same commit. Evidence goes in PROTOCOL-VALIDATION.md.
