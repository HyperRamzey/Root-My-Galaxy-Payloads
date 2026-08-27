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
