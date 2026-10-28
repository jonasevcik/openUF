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
- `util.lua`: shared helpers (file/command reads, `exec_ok`, `is_mac`, `valid_ifname`, the
  bit shim, sysfs `master_of`/`driver_of`, `nft_apply`: rebuild an nft table in one
  `nft -f` transaction, falling back per statement to name a rejected rule). Load it through `package.loaded["openuf.util"]`
  or by path as the modules do, never with a bare `require "util"`. Point a module's
  `M._read_file`-style seams at it rather than copying a helper.
- `modelmap/` = board hardware profile, `ufmodel/` = presented UniFi identity
- `docs/WIRE-REFERENCE.md` — the wire format itself: envelope, response `_type`s, every
  `system_cfg` key, every outbound field. Read the relevant section before touching a
  protocol field. `PROTOCOL-VALIDATION.md` — how those claims were established, the
  environments, the findings that cost real debugging, the firmware sweep's verdicts, the
  open questions and the dead ends. Add to whichever one fits when you establish something.

## Build & test
    eval $(luarocks path --local) && lua tests/run_tests.lua
- The `eval` prefix is mandatory: without it cjson fails to load and whole test FILES
  count as one failure each. If the total drops sharply, check the invocation first.
- **Target is Lua 5.1; the dev box is 5.5; CI is 5.1.** Green locally proves nothing
  for CI. No `\xNN` escapes (5.1 silently emits `x07`; use `string.char`), no `//`,
  `goto`, `\z`, `\u{}`, `table.unpack`. OpenWrt's Lua carries the LNUM patch:
  `string.format("%d", x)` raises for |x| > 2^31 on the APs, but not on CI or in the lab.
  Format epochs in ms and other large values with `%.0f`. `os.execute` returns a number on 5.1: both
  0 and 1 are truthy, so normalise before branching.
- Syntax-check on 5.1: `docker cp openuf/<m>.lua openuf-validation-ap:/tmp/c.lua &&
  docker exec openuf-validation-ap luac -p /tmp/c.lua`
- **`lua tests/run_tests.lua` from the project root is not the only way the suite runs.**
  `tools/dist.sh --verify` re-runs it in a scratch tree holding only `openuf/` (stripped),
  `tests/`, `tools/` and `install.sh`, and the Release workflow builds with `--verify`, so a
  test that reads any other path passes locally and fails only on the tag. A test that
  `dofile()`s or opens something outside those four needs that path copied into the verify
  tree in the same commit. Run `sh tools/dist.sh --verify` whenever a test gains a new
  file dependency (it caught this twice: README.md at v0.10.0, `tools/cfg-coverage.lua` at
  v0.13.0 — a whole test FILE errored out, so the total dropped by one file, not one test).
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
   - Installer / package-manager behaviour (install.sh, wpad swaps, conflicts):
     `docker run --rm openwrt/rootfs:x86-64-25.12.0` (apk) and `:x86-64-24.10.8` (opkg)
     have real feeds and real hostapd binaries. Run `mkdir -p /var/lock /var/run` and
     `apk update` first; source install.sh with `OPENUF_INSTALL_SOURCE_ONLY=1` to call
     its functions. No procd or radios, so they don't prove that hostapd runs.
3. **Real hardware**: only claims about radios, hostapd, regdomain, switch ASICs
   and DSA can be settled here. See `CLAUDE.local.md` if present.

## Engineering rules learned the hard way
- **Design a new feature for weak hardware as you write it**, not in a later audit pass.
  Users run openUF on 9.6 MB-overlay ath79 boards. Hold new code against the ruleset
  before calling it done: one lookup/walk pass per tick, derived facts computed once per
  push, caches keyed on what can change them, an interval gate plus a cheap change
  detector, sysfs over forks, one `nft -f` transaction per rebuild, shared helpers in
  `util.lua` over copies, read-and-compare before a flash write, `table.concat` over `..`,
  one line → one pattern, `find` over `gsub`. Never put a blocking `io.popen` on the
  `handle_response` path without a guard and a `timeout`. State the measured cost in the
  commit body. A week of features (2026-10-22..28) gave back part of the previous
  fortnight's gains in nine places; each was cheap to avoid and expensive to find later.
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
  behaviour. For what the AP *does* with a key, read the firmware: the MIPS/QCA956x builds
  (UAP-AC family, incl. current 6.8.2) are plaintext (`/usr/etc/syswrapper.sh`,
  `/usr/bin/mcad`); ARM64 U6/U7 images are opaque. Label claims with the build read,
  e.g. "firmware-confirmed for BZ2 4.3.28", and don't generalise to Wi-Fi 6/7 APs.
  Extract a rootfs with `tools/fw-extract.sh <fw.bin> <outdir>` (needs xz, cpio, binwalk).
- Absence of a wire key is often a sentinel for "off/auto". Tear down via an explicit
  signal, or via a marker/ledger when absence is ambiguous (`openuf_*` stamps, `st.*` ledgers).
- A controller-initiated kick (one-shot deauth) is not a block (persistent nft drop).
- `upgrade` from the controller is stored only, never flashed.
- **Report trades plainly.** If a fix makes any field worse, say so as prominently as
  the win, then keep digging. The target is a pristine fix, not an accepted trade.

## Commits & docs
- **Test on the APs before committing.** Deploy the uncommitted change to the real APs
  (procedure in `CLAUDE.local.md`), confirm it works there, then commit. Unit tests and the
  lab are prerequisites, not a substitute: they can't catch device-only failures.
- **One commit per feature** (or per fixed finding). A fix found during hardware testing is
  folded into that feature's commit, not stacked on top as a follow-up.
- Commit message: subject + body + `Co-Authored-By` trailer only. No session URL.
- **Public repo: never commit real MACs or IPs.** Map to `192.0.2.N` (mgmt LAN),
  `198.51.100.N` (other VLANs), `00:00:5e:00:53:0X` (MACs), one placeholder per real
  value. Before every commit:
  `git diff --cached -U0 | grep "^+" | grep -nE "192\.168\.|([0-9a-f]{2}:){5}[0-9a-f]{2}"`
  and check the message too.
- A feature or confidence change updates **README.md** (capability table, ✅ live-confirmed
  / ⚠️ unconfirmed + reason) **and USAGE.md** (config keys, deps, UCI mapping,
  troubleshooting) in the same commit. Wire keys go in `docs/WIRE-REFERENCE.md`, evidence in
  PROTOCOL-VALIDATION.md.

## Write docs compact
Apply these while writing the feature's docs, not in a later cleanup pass.
- **One fact, one home.** README = does it work and what is the catch. USAGE = how to
  configure it and what breaks. `docs/WIRE-REFERENCE.md` = the keys and fields.
  `PROTOCOL-VALIDATION.md` = the evidence and the findings. Write a fact once and link to
  it; a fact in two files goes stale in one of them.
- **README cells are two sentences**: status mark, the gate or the reason for ⚠️, a link. A
  cell that needs a third sentence is a USAGE section.
- **Write the conclusion, not the investigation.** No "Axis N", no "Step N", no "Audit F11",
  no retelling how a capture was taken. Record the method only when it is the only way to
  re-verify the claim (`tools/fw-extract.sh`, the CFR recipe).
- **One confirmation line per claim**: "live-confirmed on both APs 2026-10-27", plus the
  single number that *is* the evidence — not the log excerpt and the narrative as well.
- **Resolve in place; never strike through.** When an open question is answered, delete the
  entry and correct the fact where it lives. No `~~…~~`, no "✅ Resolved" leftovers; git
  history is the journal.
- **Prefer a table row to a paragraph** for anything per-key or per-field, and don't restate
  the table in prose beside it.
- **Version only where it matters.** Name a controller or firmware build when the claim is
  specific to it; otherwise state the fact plainly.
- **Dead ends stay.** `## Dead ends — do not re-attempt` is never trimmed for length.
- **A doc edit that only adds is suspect.** When a feature's docs land, check whether they
  supersede text already there and delete that text in the same commit.
