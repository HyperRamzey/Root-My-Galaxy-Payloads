# Root My Galaxy Payloads

Device-specific **native side** of
[Root-My-Galaxy](https://github.com/HyperRamzey/Root-My-Galaxy) (the Android
app lives in that repository): exact firmware profiles and offsets, the
app-domain CVE-2026-43499 exploit source and compiled payloads, the root
helper / KernelSU activation driver, the verified Samsung KernelSU late-load
binaries, and the support feed consumed by the app.

This fork is the active development line (~120 commits ahead of
`BuSung-dev/Root-My-Galaxy-Payloads`) for auto root app on 5.15 kernels.

Use only on devices you own or are explicitly authorized to test.

## Current state

- Latest payload release: **v1.2.16** (tag = release; releases ship the
  committed, device-verified artifacts byte-for-byte — never CI rebuilds).
- Reference device: **Galaxy Z Fold5 `SM-F946B` / `F946BXXS7GZE5`** —
  full auto-root pipeline verified end-to-end across 9+ consecutive boots
  (5 consecutive app-flow cycles, each: first-attempt exploit, KernelSU
  live, modules applied, zero kernel panics in `/proc/last_kmsg`).
- KernelSU: **v3.3.0 LKM** (32601) with the Samsung KDP/RKP/DEFEX patch; the
  mainline manager (`me.weishu.kernelsu`) is crowned by a cert-hash patch
  inside the shipped `ksud` (see below).

## Galaxy Z Fold 5 — `f946b-F946BXXS7GZE5` (device-tested)

| | |
| --- | --- |
| Kernel | `5.15.189-android13-8-33404244-abF946BXXS7GZE5` |
| Engine | MCAST / tracefs / shaped-reclaim (PR #223 lineage) |
| Result | `uid=0(root) context=u:r:ksu:s0`, KernelSU v3.3.0 LKM, Zygisk + Vector live |
| Offsets | 66/66 BTF-verified (`docs/f946b-offset-memory.md`) |

### Manual quick start

```sh
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-app.so /data/local/tmp/f946b.so
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-root   /data/local/tmp/cve-2026-43499-root
adb push kernelsu/ksud-f946b-F946BXXS7GZE5-kdp              /data/local/tmp/ksud-f946b-F946BXXS7GZE5-kdp
adb shell "chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud-*"
adb shell "SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=3 P0_ATTEMPT_TIMEOUT_SEC=115 \
  EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 RMG_PIN_GATE_WAIT_SEC=180 \
  /data/local/tmp/cve-2026-43499-root --run-payload /data/local/tmp/f946b.so \
  /data/local/tmp/cve-2026-43499-root /data/local/tmp/f946b.log"
```

The runner performs exploit → daemon activation → KernelSU late-load →
module apply itself. Root and KernelSU are volatile; a reboot clears them.

Add `RMG_DEBUG_LOGCAT=1` to mirror every exploit log line to logcat under
the `RMG_EXPLOIT` tag — a live `adb shell logcat -s RMG_EXPLOIT` watcher
then shows stage markers in realtime, and when a kernel panic kills the
device the last mirrored line is the failure point (the on-disk log can
lose its tail). Default off.

### Automatic root restore on reboot (the e2e path)

Enable **Auto-root on boot** in the app. Per boot the pipeline is:

1. `BootReceiver` → `RootOnBootService` (single-instance, alarm-retried).
2. App stages its cached payloads over wireless ADB to `/data/local/tmp`
   (feed-managed; size change ⇒ re-download).
3. Exploit runs (flock mutex makes concurrent triggers no-ops; up to 3
   pin-gated attempts per boot, then the app's reboot-retry ladder).
4. Root daemon late-loads KernelSU; the shell-context stability keeper then
   owns module activation:
   - repairs a poisoned `/data/adb/ksud` from the feed-managed copy,
   - runs ksud `post-fs-data` / `services` / `boot-completed`,
   - restarts zygote **only if every stage succeeded**, then writes the
     boot-scoped done marker,
   - exempts the manager app from Samsung background management for next
     boot.
5. The app waits for that marker instead of touching ksud/zygote itself.

Every keeper decision is traced to `/data/local/tmp/ksu-keeper.log`;
activation to `/data/local/tmp/ksu-activate.log` (shell-readable 0644).

## How the native side works

- **Exploit (`src/`)**: CVE-2026-43499 pipe-based privilege escalation.
  Stages: boot-allocator quiet-window wait → KASLR slide/leak → fops page
  shaping → pipe physrw primitive → kernel cred overwrite (`uid=2000→0`)
  → root via usermode-helper. Two build variants: the app payload
  (`cve-2026-43499-app.so`, MCAST stack-writer route) and the shell
  preload (`cve-2026-43499`, UMH route).
- **Stability machinery** (what makes repeated boots clean):
  - cluster waker + widen-restore affinity masks keep perf cores out of
    WALT halt/core-control during choreography,
  - pin gate (`RMG_PIN_GATE_WAIT_SEC`, default 180 s) waits for a usable
    perf-core placement before the sensitive phases,
  - boot-scoped writer guard: the stack-writer runs at most once per boot,
  - stability keeper retains reclaimed kernel pages post-root (the kernel
    stays "dirty"; do not kill it).
- **Root helper (`src/su_daemon.c`)**: `--run-payload` runner, `--daemon`
  root daemon (socket su for uid-2000 clients at
  `/data/local/tmp/temp_su.sock`), activation sequence (KernelSU
  late-load → module apply), `--late-load` client entry point.
- **Work-dir hygiene (`src/workdir_hygiene.h`)**: anti-log addons
  (KillLogger-class) wipe `/data/local/tmp` and poison its SELinux label;
  the runner diagnoses, cleans stale markers, and self-heals label and
  ownership at the earliest privileged moment (UMH daemon + keeper).

## KernelSU

`kernelsu/` vendors the Samsung-hardened KernelSU build chain:

- Patches (applied to upstream v3.3.0 `932014a`; CI verifies they still
  apply):
  - `KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch` — the complete Samsung
    KDP/RKP/DEFEX delta from the tagged v3.3.0 tree (creates
    `kernel/compat/samsung_kdp.c`); `kernelsu/README.md` lists the hunks.
    The earlier v3.2.5 patch series went away with the non-Fold5 profiles and
    is readable in history at commit `17c7040`.
- `ksud-f946b-F946BXXS7GZE5-kdp`: the late-load loader with the target's
  module stream embedded. The f946b binary is **crown-patched**: the
  compiled-in manager certificate hash is replaced with the official
  `me.weishu.kernelsu` release-cert hash, so the *mainline* manager app
  gets crowned (full working manager, no fork/spoof builds).
- Prebuilt `.ko` module for reference/tooling.

## Module mounting caveat (post-exploit kernels)

The exploited kernel panics on overlayfs via the new mount API:
`__arm64_sys_fsmount` synchronous external abort, process `hybrid-mount`
(two confirmed cases: `universal-gms-doze`, `ghostgms`). Any module that
ships system files must therefore be **magic-mounted** (legacy bind
mounts) instead of overlay-mounted. In `/data/adb/hybrid-mount/config.toml`:

```toml
[rules.<module-id>]
default_mode = "magic"
```

…or set the global `default_mode = "magic"`. Full analysis, evidence and
the late-load mount-namespace caveat: `docs/stability-notes-f946b.md`.

## Supported payloads

| Payload | Models | Kernel | Status |
| --- | --- | --- | --- |
| `f946b-F946BXXS7GZE5` | Z Fold5 | 5.15.189 | **Device-tested: full auto-root e2e** |

This fork is Fold5-only: the live feed and the app build serve
`f946b-F946BXXS7GZE5` and nothing else. Profiles for other SoCs were removed
on 2026-09-27 — they can never run in this fork's app, and keeping them
shipped meant the feed, the `dist/` mirror and the KernelSU pairs drifted out
of sync with each other. Their derivation records remain in the git history
(`git log --diff-filter=D -- docs/`).

Per-device notes live in `docs/SM-F946B.md`.

## Feed delivery

The app fetches `support/targets-v3.json` (schema v3: `payloads[]` with
`exploit` / `rootHelper` / `kernelsu` entries, each `url` + `size`, plus
`slideSource`) from this repo's `main` and validates every download against
the declared size — a size change is what invalidates the app's cache and
the helper's self-update. The live feed is the effective distribution
channel; GitHub release assets are archival mirrors of the same committed
binaries (with `SHA256SUMS`).

## Build

```sh
make TARGET=f946b-F946BXXS7GZE5 ANDROID_NDK_HOME=/path/to/android-ndk API=35
```

Outputs under `build/<profile>/`: `cve-2026-43499` (shell preload),
`cve-2026-43499-app.so` (app payload), `cve-2026-43499-root` (root helper /
activation driver). On Windows, `build_f946b.bat` mirrors this with NDK r30
(`-O2 -flto=thin -march=armv8-a+crc+crypto -mtune=cortex-a715`,
`-Wl,--gc-sections`). Payloads link `liblog` with `--no-as-needed` for the
optional logcat mirror.

Porting procedure: [`docs/PORTING.md`](docs/PORTING.md). KernelSU patch and
artifact provenance: [`kernelsu/README.md`](kernelsu/README.md). Target
generator: `tools/generate_target.py`; P0 fingerprint helper:
`tools/generate_p0_fingerprint.pl`; work-dir probe: `tests/workdir_probe_main.c`.

## CI / Release

- `ci.yml` (every push): native build of the one maintained target,
  target, feed schema-v3 validation (URLs pinned to this repo, sizes
  present), KernelSU patch applicability check.
- `release.yml` (tag push): builds the target as a **compile sanity gate
  only**, then publishes the **committed `artifacts/` binaries** plus the
  vendored KernelSU binaries, feed, and `SHA256SUMS`. Release assets are
  therefore byte-identical to what the live feed serves — CI rebuilds are
  never shipped (ThinLTO output is not reproducible). The former weekly
  auto-refresh of artifacts from CI builds was removed for exactly that
  reason (commit `5efc56e`).

## Docs

- `docs/stability-notes-f946b.md` — stability milestone, fsmount/overlayfs
  panic analysis, hybrid-mount magic-mode rules, debug logcat mode
- `docs/f946b-offset-memory.md` — 66 BTF-verified offsets and memory map
- `docs/PORTING.md` — porting to a new firmware
- `docs/SM-F946B.md` — the Fold5 profile record
- `docs/REBASE-REBUILD-GUIDE.md` — KernelSU rebase + SVE-free rebuild gates
- `docs/oem-unlock-f946b-audit.md` — OEM unlock audit for the Fold5
