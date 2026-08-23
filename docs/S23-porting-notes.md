# S23 series porting notes (dm3q / dm2q / dm1q — kernel 5.15.189)

Distilled from upstream
[BuSung-dev/Root-My-Galaxy-Payloads#160](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/issues/160)
(last ~30 comments as of 2026-08-09) and cross-checked against our f946b
profile and local Samsung kernel sources. Personal-device research context.

## Offset family (5.15.189 kalama kernels)

Text/data symbols move together across these firmware builds; deltas vs the
SM-S918B FZF5 baseline reported in #160:

| Symbol | S918B FZF5 | S911B SAFZE1 | f946b GZE5 (ours) |
|---|---|---|---|
| `init_task` | 0x02c05080 | +0 | 0x02c05080 |
| `prepare_kernel_cred` | 0x0011e3c8 | +0 | 0x0011e3c8 |
| `commit_creds` | 0x00120104 | +0 | 0x00120104 |
| `system_unbound_wq` | 0x02a90800 | +0 | 0x02a90800 |
| `anon_pipe_buf_ops` | 0x01e7f560 | +0xC0 | −0x80 → 0x01e7f4e0 |
| `kmalloc_caches` | 0x02064578 | +0xC0 | −0x80 → 0x020644f8 |
| `ashmem_fops` | 0x0200d5b8 | +0xC0 | −0x80 → 0x0200d538 |

Community porting flow (Meowkis/manups4e): extract pure kernel from
`boot.img`, diff symbols against a known-good baseline, apply the delta.

## Struct layouts (source-verified on SM-S911B SAFZE1 by amaplis)

Identical to our `targets/f946b-F946BXXS7GZE5/target.h` fake-waiter layout:

- `struct rt_mutex_waiter` (size 0x58): tree_entry@0x00, pi_tree_entry@0x18,
  task@0x30, lock@0x38, wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50.
- `struct file_operations`: read_iter@0x20 is the CFI target (configfs uses
  `.read_iter`, not `.read`); unlocked_ioctl@0x50, compat_ioctl@0x58,
  mmap@0x60, open@0x70, release@0x80.
- MCAST writer geometry validated from source: `group_source_req` 264 bytes
  stack-local, full copy from userspace, waiter at greqs+0x40 within a 0x330
  frame.

## Hardening constraints that shape the chain

- **KDP/RKP**: `CONFIG_KDP_CRED=y`; every cred mutation goes through an EL1→EL2
  hypervisor call with `.kdp_ro`-protected state. Direct cred overwrite is not
  viable from EL1 — exec-based root (our UMH route) or GPU-DMA routes are the
  workable endings.
- **SLUB**: `CONFIG_SLUB_CPU_PARTIAL=y` — freed slabs sit on per-CPU partial
  lists; deterministic reclaim needs CPU-partial drain / same-core pinning
  (our shaped-reclaim does this).
- **Tracefs access matrix (S918B FZF5, shell/app)**: `tracing_on`,
  `sched_blocked_reason/enable`, `per_cpu/*/trace_pipe_raw` writable/readable
  (KASLR leak path works). `events/kmem/mm_page_alloc`, `set_event_pid`,
  bulk `events/sched/enable` DENIED — no kmem PFN oracle from shell.
- **Bootargs**: `kasan=off` despite `CONFIG_KASAN_HW_TAGS=y`;
  `disable_dma32=on` — do NOT copy A536-style "skip DMA32 slabs" rules.
- kalama geometry: mm_struct 0x3e0, SLUB stride 0x400, order-3 slabs,
  32 obj/slab, min_partial 5, cpu_partial 6.

## What works / what stalls on 5.15.189

- Works: johnny-salz calibration chain — tracefs → exact KASLR slide → PFN of
  freshly faulted page via direct-map alias → mlock-filled page of fake
  objects → pselect stale-waiter overwrite → fops ARW → root. Reference:
  [root-my-galaxy-clean bridge.c](https://github.com/johnny-salz/root-my-galaxy-clean/blob/b87b7b7621877493b03fc540bcef172e2d346a19/exploit/bridge.c#L1334-L1388).
- Stalls (FPSIMD/sigreturn writer): in-handler `sched_setattr` reaches past
  +0x1ac but corruption is uncontrolled (+0x4c0 crash from userspace pointers
  leaked out of signal-delivery frames; ~75% window catch rate). See X-15 in
  #160.
- PR #168's complete-slab collector (hold all 32 objects of one slab before
  accepting the target) is the portable reclaim-hardening pattern.
- rb_erase no-op requires the erased node to be a RED leaf with color bit
  clear (X-15's disassembly of rb_erase+0x234).
- Iteration speed dominates: prefer test loops that don't require reboot;
  read panic logs between attempts.

## Status of our profiles

| Profile | State | Next step |
|---|---|---|
| dm3q-S9180ZHS8ZF5 | Testing | verify offsets against S918B-family deltas; adopt collector hardening |
| dm2q-S916BXXSAFZG1/-NKSS8FZG1 | Shell-only | same engine parity work as dm3q |
| dm1q (S911B SAFZE1) | upstream-proven | delta table above applies directly |
