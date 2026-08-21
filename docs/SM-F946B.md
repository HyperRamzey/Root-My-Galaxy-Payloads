# Galaxy Z Fold 5 (SM-F946B) — Porting Notes

## Device Overview

| Field | Value |
| ------- | ------- |
| Model | SM-F946B (Galaxy Z Fold 5, international/Europe) |
| SoC | Qualcomm Snapdragon 8 Gen 2 (SM8550-AC / Kalama) |
| Android | 16 (OneUI 8.0) |
| Kernel | 5.15.189-android13-8-33404244-abF946BXXS7GZE1 |
| Firmware | F946BXXS7GZE5 (EUY) |
| Build display ID | BP4A.251205.006 |
| Build fingerprint | samsung/f946b/f946b:16/BP4A.251205.006/F946BXXS7GZE5:user/release-keys |
| Bootloader | Binary 7 (locked, no OEM unlock toggle) |

## Status

**Kernel-panic root cause found and fixed.** The original port inherited
`task_struct` and `worker_pool` field offsets from dm3q, but the Fold5 kernel
has a completely different `task_struct` layout (0x1200 bytes with
vendor/KABI padding vs dm3q's compact layout). All 12 wrong offsets are now
corrected against the target's own BTF. Payload rebuilt and verified.
Runtime verification pending on device.

## Firmware Identity

| Artifact | Value |
| -------- | ----- |
| AP archive | SAMFW.COM_SM-F946B_EUY_F946BXXS7GZE5_fac |
| boot.img size | 100,663,296 bytes |
| boot.img SHA-256 | 2573036fbd2bfc609e55eba2a4c58feca11b420241dfd738f85d9ba64eb14e1e |
| kernel (raw Image) size | 46,860,800 bytes (0x2CB0A00) |
| kernel SHA-256 | 0e9f6691f1c030f7206fdf50ed5d0f011789aaa40487a5866abe03bb1bc2c807 |
| kernel image_size (header) | 0x02F50000 (49,610,752 bytes) |
| kernel text_offset | 0x0 (PE/COFF format) |
| vmlinux.elf (recovered) | 53,116,304 bytes |
| vmlinux.elf SHA-256 | d6c999cf0f9127c1bd358565bd8e70561d86320c2ab916787230d0eb86e3c805 |
| vmlinux.btf | 6,094,556 bytes |
| vmlinux.btf SHA-256 | 8d95924649ae54017b0b2cb62c47faeb26bbd4b61c0f325c1d27e0b120cb02e9 |
| KIMAGE_TEXT_BASE | 0xffffffc008000000 |

## Offset Derivation

All offsets were derived from the recovered `vmlinux.elf` using:

1. `vmlinux-to-elf` for ELF reconstruction from the raw kernel Image
2. `llvm-nm` for symbol extraction
3. Direct ELF field reads for struct-embedded pointers (ashmem_compat_ioctl, nfulnl_logger)
4. IDA Pro / Hex-Rays for semantic verification of stack layouts

### Verified Offsets (from vmlinux.nm)

| Symbol | Offset | Verification |
| ------ | ------ | ------------ |
| init_task | 0x02c05080 | nm exact match |
| prepare_kernel_cred | 0x0011e3c8 | nm exact match |
| commit_creds | 0x00120104 | nm exact match |
| override_creds | 0x0011f1dc | nm exact match |
| root_task_group | 0x02cb9ac0 | nm exact match |
| selinux_enforcing_boot | 0x02a3c404 | nm exact match |
| kmalloc_caches | 0x020644f8 | nm exact match |
| anon_pipe_buf_ops | 0x01e7f4e0 | nm exact match |
| system_unbound_wq | 0x02a90800 | nm exact match |
| call_usermodehelper_exec_work | 0x001045d0 | nm exact match |
| ashmem_fops | 0x0200d538 | nm exact match |
| ashmem_misc | 0x02bfcf18 | nm exact match |
| ashmem_ioctl | 0x0114c6dc | nm exact match |
| ashmem_compat_ioctl | 0x0114cd38 | file_operations+0x58 read |
| ashmem_mmap | 0x0114cd90 | nm exact match |
| ashmem_open | 0x0114d070 | nm exact match |
| ashmem_release | 0x0114d108 | nm exact match |
| ashmem_show_fdinfo | 0x0114d224 | nm exact match |
| configfs_read_iter | 0x005d7420 | nm exact match |
| configfs_bin_write_iter | 0x005d7e48 | nm exact match |
| generic_file_splice_read | 0x00528198 | nm exact match |
| noop_llseek | 0x004bbd34 | nm exact match |
| nfulnl_logger (name ptr) | 0x01d5dd0e | struct field read |
| nfulnl_logger (struct) | 0x02a91e48 | nm exact match |
| random_table | 0x02bba8c0 | nm exact match |
| sysctl_bootid | 0x02e6c0b1 | nm exact match |

### Differences from dm3q (S23 Ultra)

The Fold5 kernel shares the same SoC and kernel version but has a
**completely different `task_struct` layout** (0x1200 bytes with
android_vendor_data/android_oem_data/android_kabi_reserved padding) and a
different `worker_pool` layout. This was the root cause of the kernel panic:
the exploit built its fake task and workqueue structures at dm3q offsets,
corrupting kernel memory.

#### Symbol offsets that differ from dm3q

| Symbol | Fold5 | dm3q | Delta |
| ------ | ----- | ---- | ----- |
| kmalloc_caches | 0x020644f8 | 0x020641f8 | +0x300 |
| anon_pipe_buf_ops | 0x01e7f4e0 | 0x01e7f1e0 | +0x300 |
| ashmem_fops | 0x0200d538 | 0x0200d238 | +0x300 |
| nfulnl_logger name | 0x01d5dd0e | 0x01d5dbd6 | +0x138 |
| nfulnl_logger object | 0x02a91e48 | 0x022f2a08 | +0x79F440 |

All function offsets (init_task, prepare_kernel_cred, commit_creds, etc.)
are identical between dm3q and Fold5.

#### Struct-field offsets corrected against Fold5 BTF (panic root cause)

These were inherited from dm3q and are WRONG for the Fold5 layout. The BTF
(recovered from the exact F946BXXS7GZE5 boot.img) is ground truth. The
`commit_creds` disassembly independently confirms `real_cred` at 0x790 and
`cred` at 0x798 (`ldr x19,[x20,#0x790]` / `ldr x8,[x20,#0x798]`).

| Macro | Field | dm3q (wrong) | Fold5 BTF (correct) |
| ----- | ----- | ----------- | ------------------- |
| TASK_STRUCT_REAL_CRED_OFF | task_struct.real_cred | 0x5d8 | **0x790** |
| TASK_STRUCT_CRED_OFF | task_struct.cred | 0x5e0 | **0x798** |
| FAKE_TASK_TASK_GROUP_OFF | task_struct.sched_task_group | 0x5e0 | **0x400** |
| FAKE_TASK_USAGE_OFF | task_struct.usage | 0x40 | **0x38** |
| FAKE_TASK_PRIO_OFF | task_struct.prio | 0x84 | **0x7c** |
| FAKE_TASK_NORMAL_PRIO_OFF | task_struct.normal_prio | 0x8c | **0x84** |
| FAKE_TASK_PI_LOCK_OFF | task_struct.pi_lock | 0x924 | **0x884** |
| FAKE_TASK_PI_WAITERS_OFF | task_struct.pi_waiters | 0x938 | **0x898** |
| FAKE_TASK_PI_TOP_TASK_OFF | task_struct.pi_top_task | 0x948 | **0x8a8** |
| FAKE_TASK_PI_BLOCKED_ON_OFF | task_struct.pi_blocked_on | 0x950 | **0x8b0** |
| POOL_WORKLIST_OFF | worker_pool.worklist | 0x28 | **0x20** |
| POOL_NR_IDLE_OFF | worker_pool.nr_idle | 0x3c | **0x34** |

All 23 exploit-relevant struct-field offsets now verified against BTF with
0 mismatches (see `build/f946b-F946BXXS7GZE5/work/extract_offsets.py`).

Note: `TASK_STRUCT_CRED_OFF`/`TASK_STRUCT_REAL_CRED_OFF` are informational
only (not referenced by exploit code); the real corruption vectors were the
`FAKE_TASK_*` and `POOL_*` offsets, all now corrected.

### SLIDE_PSELECT_WORD_SHIFT

Set to 3 (inherited from dm3q, same kernel build). Static stack analysis
of the Fold5 kernel shows:

- Futex chain: `__arm64_sys_futex` (0x80) → `do_futex` (0x140) →
  `futex_wait_requeue_pi` (0x1B0), waiter at [xsp+0x98]
- Pselect chain: `__arm64_sys_pselect6` (0xA0) → `core_sys_select` (0x1C0),
  stack_fds at [xsp+0x50]

Runtime verification on device is pending.

### Tracefs Event ID and Worker Caller

`__start_ftrace_events` = 0xffffffc00aa47720, `__event_sched_blocked_reason`
= 0xffffffc00aa479e0. Section offset = 0x2C0, index = 88. With the Android
5.15 dynamic event base of 20, the runtime event ID is **108** (dm3q uses
106 — the Fold5 has 2 additional events before sched_blocked_reason).

`worker_thread` at 0x0010dacc (spans 0x10dacc–0x10e204) contains exactly ONE
`bl schedule` call site:

- 0x0010db40 (ret 0x0010db44) — the idle-worker sleep path

The dm3q-inherited value 0x000db1a0 resolves to `exit_mm` in the Fold5
kernel and is wrong. The earlier draft value 0x00110500 is inside
`workqueue_offline_cpu`, NOT `worker_thread`, and is also wrong. The correct
idle-worker schedule return address is used:

```c
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x0010db44ULL
```

`SLIDE_TRACEFS_EVENT_ID 108` confirmed live on device via
`/sys/kernel/tracing/events/sched/sched_blocked_reason/id` (safe sysfs read).

## P0 Fingerprint

Generated from the raw kernel Image at `build/f946b-F946BXXS7GZE5/work/kernel`.
32 rows (slide 0x000000 through 0x1f0000, step 0x10000), 8 LE qwords each
at page offsets 0x000–0xe00. Row 0 matches dm3q exactly (same kernel base).

Output: `src/targets/f946b-F946BXXS7GZE5/p0_fingerprint.h`

## Build

```bat
build_f946b.bat
```

Produces:

- `build/f946b-F946BXXS7GZE5/cve-2026-43499` (96,608 bytes)
- `build/f946b-F946BXXS7GZE5/cve-2026-43499-app.so` (126,016 bytes)
- `build/f946b-F946BXXS7GZE5/cve-2026-43499-root` (26,456 bytes)

## Remaining Work

1. **End-to-end exploit test** on the Fold5 (single-shot; offsets now BTF-verified)
2. **KernelSU module for f946b** — the dm3q `.ko` is symbol-ABI-compatible
   (0 CRC mismatches, all 205 symbols resolve) but **struct-incompatible**:
   its KDP code accesses `target->cred`/`target->real_cred` at dm3q's
   compiled-in offsets (0x5e0), while the Fold5 kernel has cred at 0x798.
   A Fold5-specific module must be compiled against the Fold5 kernel tree.
   Build is currently blocked (Docker/WSL unavailable on this host).
3. **SKB_DATA_DELTA** runtime confirmation (-0x1000, matches Kalama 5.15 family)

## Firmware Download Links

- SamFW: <https://samfrew.com/firmware/model/SM-F946B/upload/Desc/0/10>
- Samsung firmware portal: <https://s-update.samsungvn.com/devices/SM-F946B>

## Related Issues

- [Root-My-Galaxy #265](https://github.com/BuSung-dev/Root-My-Galaxy/issues/265): Port request for SM-F946B
- [Root-My-Galaxy-Payloads #161](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/issues/161): S23 Ultra payload compiled incorrectly (ld-linux-aarch64.so.1)
