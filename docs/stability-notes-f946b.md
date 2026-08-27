# f946b (SM-F946B / F946BXXS7GZE5) stability notes — 2026-08-27

## Verified stability milestone (v1.2.12)

8 consecutive successful auto-root boots on RFCWC0G1Z1J (SM-F946B, Android 16,
Snapdragon 8 Gen 2), including 5 consecutive app-flow E2E cycles, each verified:

- exploit success (first attempt, every cycle)
- no kernel panic (`grep -ac "Kernel panic" /proc/last_kmsg` = 0 on the
  following boot, every cycle)
- KernelSU module loaded, `su` working (`u:r:ksu:s0`)
- modules applied, boot-scoped done marker matching `boot_id`
- GMS Doze magic-mounted (see below)

The earlier "random auto-root crashes" were traced to two causes, both resolved:

1. **Pre-v1.2.11 payload** (127424-byte artifact from the `7059e99`
   known-good-feed restore) predates the stability series (cluster waker,
   widen-restore affinity masks, pin-gate waits, boot-scoped writer guard).
   It panics readily at `durable log checkpoint stage=fops-pre-pin-little`.
   Do not deploy that artifact; the current 135936-byte payload is the
   verified one.
2. **Hybrid Mount overlayfs on the post-exploit kernel** (next section).

## Hybrid Mount overlayfs → `fsmount` synchronous external abort

With `universal-gms-doze` (Universal GMS Doze 1.9.2) installed alongside
Hybrid Mount 6.0.1, the device panicked reproducibly ~10 min into boot:

```
[604.72] hybrid-mount:27395  Internal error: synchronous external abort:
         ffffffff96000010 [#1] PREEMPT SMP
pc : __arm64_sys_fsmount+0x268/0x4d0
Kernel panic - not syncing: synchronous external abort: Fatal exception
```

Evidence: `/proc/last_kmsg` (pstore is empty on this device; last_kmsg is
root-readable). ESR DFSC=0x10 → external abort during a page-table walk.

Chain: GMS Doze is the first installed module that ships real system files
(`product/etc/sysconfig/google.xml`). Hybrid Mount's `default_mode = "overlay"`
overlays them via the new mount API (`fsmount`); that path dies on the
post-exploit ("dirty") kernel. Modules without system files (zygisk-style)
never trigger an overlay, which is why the setup appeared stable before.

**Fix (device-side, persists in /data/adb):** per-module rule in
`/data/adb/hybrid-mount/config.toml`:

```toml
[rules.universal-gms-doze]
default_mode = "magic"
```

Magic mount uses legacy bind mounts (no `fsmount`, no overlayfs). Verified:
`state.json` shows `magic_modules: ["universal-gms-doze"]`,
`overlayfs_mounts: 0`, patched `google.xml` live with the GMS
`allow-in-power-save` entry removed. If another module with system files
panics the same way, add another `[rules.<module-id>] default_mode = "magic"`
entry, or set the global `default_mode = "magic"`.

Second confirmed case (2026-08-27): **GhostGMS 3.1.3** (`id=ghostgms`)
ships ~47 system files (`system/bin/log*` zero-byte placeholders,
`system/etc/init/*.rc`) and panicked identically at uptime 183s
(`hybrid-mount` PID, `__arm64_sys_fsmount+0x268`). Fixed with
`[rules.ghostgms] default_mode = "magic"` — 53/53 mounts, 0 failures.
Note: the module lifecycle also runs inside the ksud late-load's private
mount namespace, so mounts from that pass vanish with it; the keeper's
global apply (or a manual `ksud post-fs-data/services/boot-completed`)
is what makes mounts persist.
Note: GhostGMS disables logging by design (zero-byte `logcat`/`logd`/
`tombstoned`/`dumpstate`) — `adb logcat` and the RMG_EXPLOIT debug
stream are blind while it is mounted.

Known cosmetic artifact: `state.json` may report `failed_mounts: 1` with
logcat error `Failed to add try-umount list /product, File exists` when
Hybrid Mount runs twice in one boot (second run re-adds an existing
try-umount entry). The mounts themselves are live; no action needed.

## RMG_DEBUG_LOGCAT — realtime failure-point capture

When a kernel panic kills the exploit, the on-disk `f946b.log` can lose its
tail (panic before fsync), and the device drops from adb. To capture the
failure point live, the payload mirrors every `pr_*` line to logcat under
the `RMG_EXPLOIT` tag when `RMG_DEBUG_LOGCAT=1` is set in the environment:

```sh
RMG_DEBUG_LOGCAT=1 /data/local/tmp/cve-2026-43499-root --run-payload ...
# watcher (host side):
adb shell logcat -s RMG_EXPLOIT
```

The last mirrored line before the device drops is the failure point.
Default off (one env-checked branch per log line, no logcat traffic).
Single-buffer design: format once, `fputs` to stdout, then the same text to
logcat — call-site codegen stays one variadic call (+~2 KB total).

Note: the payload links `liblog.so` with `-Wl,--no-as-needed` — the NDK's
default `--as-needed` plus ThinLTO otherwise drops the DT_NEEDED entry and
`dlopen` fails with `cannot locate symbol "__android_log_print"`.

## kgsl `hwsched_idle_check` list-corruption panic at the zygote bounce

Observed 2026-08-27 ~23:17 (boot `0b88eb74`): the device panicked ~4 s after
the apply script's `kill -9` zygote bounce, at uptime 177.8 s:

```
[177.816169] list_del corruption. next->prev should be ffffff88442e1680,
             but was ffffff8836716008
[177.816231] kernel BUG at lib/list_debug.c:64!
[177.817268] Workqueue: kgsl-workqueue hwsched_idle_check.2227.cfi_jt [msm_kgsl]
[177.817911] Call trace:
[177.817915]  __list_del_entry_valid+0xc8/0xcc
[177.817920]  process_one_work+0x174/0x510
[177.817929]  worker_thread+0x3ac/0x738
[177.817961] Kernel panic - not syncing: Oops - BUG: Fatal exception
```

Evidence: `/proc/last_kmsg` of the following boot (pstore is empty on this
device). The faulting work item is the Adreno GPU hardware scheduler's idle
check; its `work_struct` list node was corrupted while queued.

Chain: the zygote bounce kills every app process at once; the mass GPU
context teardown races the kgsl hwsched housekeeping on this
`5.15.189-android13-8` kernel. The race is flaky — the same bounce window
survived on 3 of 4 observed boots. It is NOT caused by GPU userspace
replacement: `GPU_UPDATE` carried a `disable` marker since 22:03 and its
libs were verified not mounted (`/vendor/lib64/egl/libGLESv2_adreno.so` md5
mismatch with the module copy, 0 `GPU_UPDATE` entries in `/proc/mounts`).
`ghostgms` was likewise disabled at the time.

**Fix (payload-side):** `KSU_APPLY_SCRIPT` (both copies — `src/common.h` and
`src/su_daemon.c`) now waits up to 45 s before the zygote kill until the GPU
is idle (`/sys/class/kgsl/kgsl-3d0/gpu_busy_percentage` == 0; note the file
prints `0 %`, so the value is cut on space) and 1-min loadavg < 2, so the
teardown storm starts from a quiescent scheduler. The wait logs
`apply-modules: pre-kill settle <N>s gpu_busy=<b> load=<l>`; the keeper's
120 s apply budget still covers worst case. Verified: builds pass
(`build_f946b.bat`), the loop exits in 0 s on an idle system, and the
patched binaries + on-disk `.cve43499-apply.sh` are staged on the device
(`/data/local/tmp` and the manager's `files/payloads/f946b-F946BXXS7GZE5/`).

If this panic is ever seen again despite the settle wait, the next
mitigation is to stop bouncing zygote altogether (accept that zygisk modules
only pick up on the following natural boot) — the bounce exists solely for
same-boot zygisk pickup.
