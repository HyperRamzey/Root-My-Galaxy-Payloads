# Root My Galaxy Payloads

Device-specific **native side** of
[Root-My-Galaxy](https://github.com/HyperRamzey/Root-My-Galaxy) (the Android
app lives in that repository): exact firmware profiles and offsets, the
app-domain CVE-2026-43499 exploit source and compiled payloads, the root
helper / KernelSU activation driver, the verified Samsung KernelSU late-load
binaries, and the support feed consumed by the app.

Use only on devices you own or are explicitly authorized to test.

## Galaxy Z Fold 5 — `f946b-F946BXXS7GZE5` (device-tested)

| | |
|---|---|
| Kernel | `5.15.189-android13-8-33404244-abF946BXXS7GZE5` |
| Engine | MCAST / tracefs / shaped-reclaim (PR #223) |
| Result | `uid=0(root) context=u:r:kernel:s0`, KernelSU v3.2.5 LKM, Zygisk + Vector live |
| Offsets | 66/66 BTF-verified (`docs/f946b-offset-memory.md`) |

### Manual quick start (one attempt per boot)

```sh
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-app.so /data/local/tmp/f946b.so
adb push artifacts/f946b-F946BXXS7GZE5/cve-2026-43499-root   /data/local/tmp/cve-2026-43499-root
adb push kernelsu/ksud-f946b-F946BXXS7GZE5-kdp              /data/local/tmp/ksud-f946b-kdp
adb shell "chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud-*"
adb shell "SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=115 \
  EXPLOIT_ATTEMPT_TIMEOUT_SEC=600 \
  /data/local/tmp/cve-2026-43499-root --run-payload /data/local/tmp/f946b.so \
  /data/local/tmp/cve-2026-43499-root /data/local/tmp/f946b.log"
adb shell "/data/local/tmp/cve-2026-43499-root --late-load"
```

Root and KernelSU are volatile; a reboot clears them.

### Automatic root restore on reboot (the e2e path)

Enable **Auto-root on boot** in the app (wireless-debugging pairing is set up
once from its Settings screen). Per boot the pipeline is:

1. `BootReceiver` → `RootOnBootService` (single-instance, alarm-retried).
2. App stages its cached payloads over wireless ADB to `/data/local/tmp`.
3. Root helper self-updates artifacts from this repo's feed (3 retries per
   download) so a stale app cache can never execute old code.
4. Exploit runs once (an flock mutex makes concurrent triggers no-ops).
5. Root daemon late-loads KernelSU; the shell-context stability keeper then
   owns module activation:
   - disables Samsung's `softdog` (its 100 s expiry was panicking the device
     mid-churn — see commit history),
   - repairs a poisoned `/data/adb/ksud` from the feed-managed copy,
   - runs ksud `post-fs-data` / `services` / `boot-completed`,
   - re-runs `services` if `vectord` lost the race,
   - restarts zygote **only if every stage succeeded**, then writes the
     boot-scoped done marker,
   - exempts the manager app from Samsung background management for next
     boot (`deviceidle whitelist`, standby bucket, `adb_wifi_enabled`).
6. The app waits for that marker instead of touching ksud/zygote itself.

Every keeper decision is traced to `/data/local/tmp/ksu-keeper.log`.

### Measured boot-to-root timing (F946BXXS7GZE5, RFCWC0G1Z1J)

| Stage | Observed |
|---|---|
| Exploit (`attempt=1`) | seconds — KASLR slide + physrw + UMH root in one pass |
| Keeper waits for KernelSU | `state=waiting-ksu` until late-load lands |
| Module apply window | `waited=10s–70s` per boot |
| Done marker | uptime 231–451 s across three consecutive boots |

Worst case (retried boots) stays under ~8 minutes from boot to rooted,
module-applied framework.

### Reliability rules encoded the hard way

- Choreography cores are compile-time literals (`CORE 0`,
  `CONSUMER_CORE CORE+1`, waiter unpinned). Any runtime affinity probing in
  the payload path destabilizes it even with identical placement; the X3
  prime rejects affinity on this firmware outright (restricted-core EINVAL),
  so `src/affinity.h` pinning applies **only to post-root background actors**
  (perf-cluster mask, never LITTLE).
- The exploit session lock (`flock`) makes overlapping manual/app runs safe.
- A pre-exploit liveness check (`su` probe + `/proc/modules` +
  `/sys/module/kernelsu` + boot-scoped public-storage marker) prevents
  re-exploitation after zygote restarts.
- Module application never kills zygote unless all ksud stages succeeded —
  retries can defer (exit 42) but cannot soft-reboot-loop.

### Anti-log addons vs `/data/local/tmp` (work-dir self-healing)

Root addons that wipe logs can break auto-root permanently: KillLogger's
late-start `service.sh` runs `rm -rf /data/local/tmp*` on every boot,
deleting the work directory itself along with every payload, log, lock and
marker. Whatever privileged process recreates the directory afterwards
labels it `system_data_file` instead of `shell_data_file`, so adbd can
never stage again — pushes silently land nothing and every recovery vector
dies before it starts. The pipeline now defends itself
(`src/workdir_hygiene.h`):

- **Launch preflight**: the exploit runner diagnoses the work dir (label +
  writability) and logs a loud warning before failing mysteriously.
- **Stale cleanup**: previous-boot markers/logs are collected at exploit
  launch. Contract: flock lock inodes are never touched, any marker whose
  embedded `boot_id` matches the live boot is never touched (this is what
  keeps anti-double-root intact), and keeper-owned logs are only rotated
  while KernelSU is provably not loaded.
- **Self-heal at the earliest privileged moment**: the UMH daemon relabels
  and reowns the directory during the post-escalation permissive window;
  the keeper repeats the heal via `su` as soon as KernelSU is live; both
  apply scripts re-apply it (`restorecon -RF /data/local /data/local/tmp`,
  `chcon` fallback). One poisoned boot therefore cannot outlive its own
  root session — the next boot stages cleanly.
- Users running KillLogger-class modules should also exclude
  `/data/local/tmp` from their module's wipe list; until then the
  self-heal loop above is what makes recovery automatic instead of
  manual.

## Supported payloads

| Payload | Models | Kernel | Status |
| --- | --- | --- | --- |
| `galaxy-s25-series-2026-06-07` | S25 family | 6.6.98 | Device-tested |
| `e3q-S928USQS6DZF2` | S24 Ultra | 6.1.145 | HW debugging |
| `e2s-S926BXXUEDZDR` | S24+ | 6.1.157 | Device-tested |
| `essi-A566EXXSCCZG6` | A56 5G | 6.6.102 | Device-tested |
| `a36xq-A366WVLS3AYG1` | A36 5G | 6.6.46 | Device-tested |
| `dm3q-S9180ZHS8ZF5` | S23 Ultra | 5.15.189 | Testing |
| `dm2q-S916BXXSAFZG1` / `-S916NKSS8FZG1` | S23+ | 5.15.189 | Shell-only |
| `f946b-F946BXXS7GZE5` | Z Fold5 | 5.15.189 | **Device-tested: full auto-root e2e** |

## Feed delivery

The app resolves this repo's current `main` commit and fetches
`support/targets-v3.json` plus every artifact from that immutable commit.
Per-artifact SHA-256 fields and manifest signatures are not part of schema
v3; sizes are enforced by both the feed parser and the helper's self-update.

## Build

```sh
make TARGET=f946b-F946BXXS7GZE5 ANDROID_NDK_HOME=/path/to/android-ndk API=35
```

Outputs under `build/<profile>/`: `cve-2026-43499` (shell preload),
`cve-2026-43499-app.so` (app payload), `cve-2026-43499-root` (root helper /
activation driver). `make … release` additionally builds the size-capped
release `.so`. On Windows, `build_f946b.bat` mirrors this with NDK r30.

Porting procedure: [`docs/PORTING.md`](docs/PORTING.md). KernelSU patch and
artifact provenance: [`kernelsu/README.md`](kernelsu/README.md).

## CI

`.github/workflows/release.yml` builds the native matrix on tag pushes,
archives the vendored KernelSU binaries + feed into a release with SHA256SUMS,
and — scheduled weekly or via workflow_dispatch — pulls the latest upstream
KernelSU source, verifies the Samsung KDP/RKP/DEFEX patch still applies, and
uploads the source snapshot.
