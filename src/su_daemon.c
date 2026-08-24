#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <dlfcn.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define BOOTSTRAP_SOCK_PATH "/data/local/tmp/temp_su.sock"
#define HOLD_READY_SOCKET "cve43499_roothold"
#define SH_PATH "/system/bin/sh"
#define KSU_LOADER_PATH "/data/local/tmp/ksud-s25u-kdp"
#define KSU_LATE_LOAD_LOCK_PATH "/data/local/tmp/.cve43499-lateload.lock"

/*
 * The app stages ksud under its feed artifact name
 * (/data/local/tmp/ksud-<profile>-kdp); older builds only ever had the fixed
 * legacy alias above. Resolve the live loader binary on every call: prefer a
 * profile-named candidate so a stale legacy copy can never shadow it.
 */
static const char *ksu_loader_path(void) {
  static char resolved[160];
  resolved[0] = '\0';
  DIR *dir = opendir("/data/local/tmp");
  if (dir != NULL) {
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
      size_t len = strlen(ent->d_name);
      if (len > 8 && len < sizeof(resolved) - 16 &&
          strncmp(ent->d_name, "ksud-", 5) == 0 &&
          strcmp(ent->d_name + len - 4, "-kdp") == 0 &&
          strcmp(ent->d_name, "ksud-s25u-kdp") != 0) {
        snprintf(resolved, sizeof(resolved), "/data/local/tmp/%s",
                 ent->d_name);
        break;
      }
    }
    closedir(dir);
  }
  if (resolved[0] == '\0') {
    snprintf(resolved, sizeof(resolved), "%s", KSU_LOADER_PATH);
  }
  return resolved;
}

/* Self-update install target for the ksud feed artifact: keep the feed's
 * file name so the staged path identifies the profile it belongs to. */
static int ksu_selfupdate_target(const char *url, char *out, size_t out_sz) {
  const char *base = strrchr(url, '/');
  if (base == NULL || strncmp(base, "/ksud-", 6) != 0 || base[6] == '\0' ||
      strlen(base) >= out_sz - 16) {
    return -1;
  }
  snprintf(out, out_sz, "/data/local/tmp/%s", base + 1);
  return 0;
}

/*
 * KernelSU module lifecycle driver, executed via `su -c` from a
 * shell/app context (see apply_modules_core). Exits non-zero unless all
 * lifecycle stages succeeded and a zygote was actually restarted.
 *
 * Boot-safety contract: this script is retried by long-lived actors, so it
 * must never disturb a running framework unless module activation actually
 * succeeded. Exit 42 defers while the system is still booting; stage
 * failures leave the zygote untouched so retries cannot soft-reboot-loop.
 */
#define KSU_APPLY_SCRIPT \
  "mkdir -p /data/local/tmp 2>/dev/null; " \
  "chown 2000:2000 /data/local/tmp 2>/dev/null; " \
  "chmod 0771 /data/local/tmp 2>/dev/null; " \
  "restorecon -RF /data/local /data/local/tmp >/dev/null 2>&1 || " \
  "chcon -R u:object_r:shell_data_file:s0 /data/local " \
  "/data/local/tmp >/dev/null 2>&1; " \
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
  "appops set \"$PKG\" RUN_ANY_IN_BACKGROUND allow >/dev/null 2>&1; " \
  "appops set \"$PKG\" START_FOREGROUND allow >/dev/null 2>&1; " \
  "settings put global adb_wifi_enabled 1 >/dev/null 2>&1; " \
  "echo \"apply-modules: manager $PKG exempted for next boot\"; fi; " \
  "BID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null); " \
  "UP=$(cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d. -f1); " \
  "if [ -n \"$BID\" ] && [ -n \"$UP\" ]; then " \
  "echo \"$BID $UP\" > /data/local/tmp/.cve43499-modules-done 2>/dev/null; fi; " \
  "echo 'apply-modules: zygote restarted for module pickup'; " \
  "mkdir -p /data/local/tmp 2>/dev/null; " \
  "chown 2000:2000 /data/local/tmp 2>/dev/null; " \
  "chmod 0771 /data/local/tmp 2>/dev/null; " \
  "restorecon -RF /data/local /data/local/tmp >/dev/null 2>&1 || " \
  "chcon -R u:object_r:shell_data_file:s0 /data/local " \
  "/data/local/tmp >/dev/null 2>&1; " \
  "exit 0"
#define LOGCAT_PATH "/system/bin/logcat"

static uid_t allowed_client_uid = 2000;

#define SU_PROTOCOL_MAGIC 0x53553235U
#define SU_PROTOCOL_VERSION 1U
#define SU_RESPONSE_MAGIC 0x53555235U
#define SU_MAX_ARGC 256U
#define SU_MAX_ENVC 512U
#define SU_MAX_STRING 65536U
#define SU_MAX_REQUEST_BYTES (1024U * 1024U)
#define SU_PASSED_FDS 5U
#define HOLD_REF_FDS 3U

extern char **environ;

struct su_tty_state {
  uint8_t has_termios;
  uint8_t has_winsize;
  struct termios termios;
  struct winsize winsize;
};

struct su_request_header {
  uint32_t magic;
  uint32_t version;
  uint32_t argc;
  uint32_t envc;
  uint8_t interactive;
  uint8_t reserved[3];
  struct su_tty_state tty;
};

struct su_response {
  uint32_t magic;
  int32_t status;
};

struct su_request {
  struct su_request_header header;
  char **argv;
  char **envp;
  int stdin_fd;
  int stdout_fd;
  int stderr_fd;
  int cwd_fd;
  int io_fd;
};

static int saved_terminal_fd = -1;
static struct termios saved_terminal;

static void restore_terminal(void) {
  if (saved_terminal_fd >= 0) {
    tcsetattr(saved_terminal_fd, TCSANOW, &saved_terminal);
    saved_terminal_fd = -1;
  }
}

static void set_root_env(void) {
  char hostname[PROP_VALUE_MAX];

  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
  if (__system_property_get("ro.product.device", hostname) > 0) {
    setenv("HOSTNAME", hostname, 1);
  }
}

static int write_full(int fd, const void *buf, size_t len) {
  const char *p = buf;

  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = buf;

  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static uint32_t vector_count(char *const values[], uint32_t limit) {
  uint32_t count = 0;

  while (values[count]) {
    if (count == limit) {
      return UINT32_MAX;
    }
    count++;
  }
  return count;
}

static int send_fds(int socket_fd, const int fds[SU_PASSED_FDS]) {
  char marker = 'F';
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * SU_PASSED_FDS);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * SU_PASSED_FDS);

  return sendmsg(socket_fd, &msg, 0) == (ssize_t)sizeof(marker);
}

static int recv_fds(int socket_fd, int fds[SU_PASSED_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'F') {
    return 0;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * SU_PASSED_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * SU_PASSED_FDS);
  return 1;
}

static int send_vector(int fd, char *const values[], uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    size_t len = strlen(values[i]);
    if (len > SU_MAX_STRING) {
      return 0;
    }
    uint32_t wire_len = (uint32_t)len;
    if (!write_full(fd, &wire_len, sizeof(wire_len)) ||
        !write_full(fd, values[i], wire_len)) {
      return 0;
    }
  }
  return 1;
}

static char **recv_vector(int fd, uint32_t count, size_t *total_bytes) {
  char **values = calloc((size_t)count + 1, sizeof(*values));
  if (!values) {
    return NULL;
  }

  for (uint32_t i = 0; i < count; i++) {
    uint32_t len;
    if (!read_full(fd, &len, sizeof(len)) || len > SU_MAX_STRING ||
        *total_bytes + len > SU_MAX_REQUEST_BYTES) {
      goto fail;
    }
    values[i] = calloc(1, (size_t)len + 1);
    if (!values[i] || !read_full(fd, values[i], len)) {
      goto fail;
    }
    *total_bytes += len;
  }
  return values;

fail:
  for (uint32_t i = 0; i < count; i++) {
    free(values[i]);
  }
  free(values);
  return NULL;
}

static void close_request_fds(struct su_request *request) {
  int *fds[] = {&request->stdin_fd, &request->stdout_fd, &request->stderr_fd,
                &request->cwd_fd, &request->io_fd};
  for (size_t i = 0; i < SU_PASSED_FDS; i++) {
    if (*fds[i] >= 0) {
      close(*fds[i]);
      *fds[i] = -1;
    }
  }
}

static void free_request(struct su_request *request) {
  if (request->argv) {
    for (uint32_t i = 0; i < request->header.argc; i++) {
      free(request->argv[i]);
    }
    free(request->argv);
  }
  if (request->envp) {
    for (uint32_t i = 0; i < request->header.envc; i++) {
      free(request->envp[i]);
    }
    free(request->envp);
  }
  close_request_fds(request);
}

static int recv_request(int conn, struct su_request *request) {
  int fds[SU_PASSED_FDS];
  size_t total_bytes = 0;
  memset(request, 0, sizeof(*request));
  request->stdin_fd = -1;
  request->stdout_fd = -1;
  request->stderr_fd = -1;
  request->cwd_fd = -1;
  request->io_fd = -1;

  if (!recv_fds(conn, fds)) {
    return 0;
  }
  request->stdin_fd = fds[0];
  request->stdout_fd = fds[1];
  request->stderr_fd = fds[2];
  request->cwd_fd = fds[3];
  request->io_fd = fds[4];

  if (!read_full(conn, &request->header, sizeof(request->header)) ||
      request->header.magic != SU_PROTOCOL_MAGIC ||
      request->header.version != SU_PROTOCOL_VERSION ||
      request->header.argc == 0 || request->header.argc > SU_MAX_ARGC ||
      request->header.envc > SU_MAX_ENVC) {
    return 0;
  }

  request->argv =
      recv_vector(conn, request->header.argc, &total_bytes);
  if (!request->argv) {
    return 0;
  }
  request->envp =
      recv_vector(conn, request->header.envc, &total_bytes);
  return request->envp != NULL;
}

static int wait_status(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static int recv_hold_fds(int socket_fd, int fds[HOLD_REF_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * HOLD_REF_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'P') {
    return 0;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * HOLD_REF_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * HOLD_REF_FDS);
  return 1;
}

static void hold_kernel_references(int conn) {
  int fds[HOLD_REF_FDS] = {-1, -1, -1};
  if (!recv_hold_fds(conn, fds)) {
    return;
  }
  int ready_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (ready_fd < 0) {
    return;
  }
  struct sockaddr_un ready_address;
  memset(&ready_address, 0, sizeof(ready_address));
  ready_address.sun_family = AF_UNIX;
  memcpy(ready_address.sun_path + 1, HOLD_READY_SOCKET,
         sizeof(HOLD_READY_SOCKET) - 1);
  socklen_t ready_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) + sizeof(HOLD_READY_SOCKET));
  if (bind(ready_fd, (struct sockaddr *)&ready_address, ready_length) != 0 ||
      listen(ready_fd, 4) != 0) {
    close(ready_fd);
    return;
  }
  char acknowledged = 'K';
  if (!write_full(conn, &acknowledged, sizeof(acknowledged))) {
    return;
  }
  prctl(PR_SET_NAME, "cve43499-roothold", 0, 0, 0);
  close(conn);
  for (;;) {
    int probe_fd = accept4(ready_fd, NULL, NULL, SOCK_CLOEXEC);
    if (probe_fd >= 0) {
      close(probe_fd);
    }
  }
}

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};

/*
 * Pre-exploit KernelSU liveness probe. KernelSU hooks sys_reboot with the
 * 0xDEADBEEF/0xCAFEBABE magic pair and hands back an fd to its control
 * device. Without the module loaded the kernel rejects the unknown reboot
 * magic with EINVAL and never reboots, so the probe is safe on stock
 * kernels. Returns 1 when the module is already responding, 0 otherwise.
 */
static int ksu_already_active(void) {
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

/* Universal liveness probe: /proc/modules is readable from every SELinux
 * context, unlike the reboot probe above which needs CAP_SYS_BOOT. */
static int ksu_module_loaded(void) {
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
    for (size_t i = 0; i + 8 <= len; i++) {
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
 * Activation handoff marker. The exploit side (runner or preload
 * supervisor) drops this file once root is installed; the daemon's
 * activation watcher polls for it and performs KernelSU late-load + module
 * activation from its own root context, because shell-domain clients lose
 * daemon-socket access once SELinux re-enforces.
 */
#define KSU_ACTIVATE_SIGNAL_PATH "/data/local/tmp/.cve43499-activate"

static void ksu_signal_activation(void) {
  unlink(KSU_ACTIVATE_SIGNAL_PATH);
  int fd = open(KSU_ACTIVATE_SIGNAL_PATH, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd >= 0) {
    close(fd);
  }
}

/*
 * Boot-scoped active marker. After a successful activation the daemon
 * writes the current boot_id here; the pre-exploit check compares it
 * against the live boot_id to detect that KernelSU was already activated
 * this boot even when shell has no KSU root grant yet.
 */
#define KSU_ACTIVE_MARKER_PATH "/data/local/tmp/.cve43499-ksu-active"

static int read_boot_id(char *out, size_t out_len) {
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

static int ksu_active_this_boot(void) {
  return ksu_module_loaded();
}

static void ksu_mark_active_this_boot(void) {
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
 * Pre-exploit KernelSU detection via `su -c id`. Works from adb shell when
 * KernelSU is loaded and shell (uid 2000) has a root grant in the manager.
 * Bounded by a ~5s timeout so a grant dialog or a missing binary cannot
 * stall the run. Returns 1 when su reports uid=0.
 */
static int su_probe_active(void) {
  int pipefd[2];
  if (pipe2(pipefd, O_CLOEXEC) != 0) {
    return 0;
  }
  pid_t child = fork();
  if (child < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
  }
  if (child == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    execl("/system/bin/su", "su", "-c", "id", (char *)NULL);
    _exit(127);
  }
  close(pipefd[1]);

  char buf[128];
  size_t total = 0;
  buf[0] = '\0';
  for (int waited_ms = 0; waited_ms < 5000 && total + 1 < sizeof(buf);
       waited_ms += 100) {
    struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN};
    int pr = poll(&pfd, 1, 100);
    if (pr <= 0) {
      continue;
    }
    ssize_t got = read(pipefd[0], buf + total, sizeof(buf) - 1 - total);
    if (got <= 0) {
      break;
    }
    total += (size_t)got;
    buf[total] = '\0';
    if (strstr(buf, "uid=") != NULL) {
      break;
    }
  }

  int status = 0;
  int timed_out = 0;
  pid_t waited = waitpid(child, &status, WNOHANG);
  if (waited == 0) {
    usleep(200000);
    waited = waitpid(child, &status, WNOHANG);
    if (waited == 0) {
      kill(child, SIGKILL);
      do {
        waited = waitpid(child, &status, 0);
      } while (waited < 0 && errno == EINTR);
      timed_out = 1;
    }
  }
  close(pipefd[0]);
  if (timed_out) {
    return 0;
  }
  return strncmp(buf, "uid=0", 5) == 0;
}

static int verify_kernelsu_control(void) {
  int fd = -1;
  syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
  if (fd < 0) {
    dprintf(STDERR_FILENO, "late-load: KernelSU driver fd unavailable\n");
    return 13;
  }

  struct ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
  int saved_errno = errno;
  close(fd);
  if (ret != 0 || info.version == 0 || (info.flags & 1U) == 0 ||
      (info.flags & 4U) == 0) {
    dprintf(STDERR_FILENO,
            "late-load: KernelSU control check failed ret=%d errno=%d "
            "version=%u flags=0x%x\n",
            ret, saved_errno, info.version, info.flags);
    return 14;
  }

  dprintf(STDOUT_FILENO,
          "KernelSU control verified version=%u flags=0x%x "
          "uapi=%u features=0x%x\n",
          info.version, info.flags, info.uapi_version, info.features);
  return 0;
}

/*
 * Core KernelSU late-load work. Runs in the calling (already-forked)
 * process so it can be shared between the socket-request path and the
 * daemon-side activation watcher. Returns the loader/verify exit status.
 *
 * Callers are responsible for serialization via activation_lock_acquire()
 * before reaching this function (see run_kernelsu_late_load and
 * run_activation_sequence).
 */
static int kernelsu_late_load_locked(void) {
  /* Pre-stage the ksud binary so the loader's self-staging rename step
   * (/data/local/tmp/.ksud-stage -> /data/adb/ksud) always has a valid
   * source. On a clean boot the loader's own copy can fail, leaving the
   * rename source missing and the whole late-load aborted. */
  mkdir("/data/adb", 0755);
  {
    int src = open(ksu_loader_path(), O_RDONLY | O_CLOEXEC);
    if (src >= 0) {
      const char *staging_paths[] = {
          "/data/local/tmp/.ksud-stage",
          "/data/adb/ksud",
          NULL,
      };
      for (int i = 0; staging_paths[i]; i++) {
        int dst = open(staging_paths[i],
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (dst < 0) {
          continue;
        }
        char buf[65536];
        for (;;) {
          ssize_t got = read(src, buf, sizeof(buf));
          if (got <= 0) {
            break;
          }
          ssize_t off = 0;
          while (off < got) {
            ssize_t put = write(dst, buf + off, (size_t)(got - off));
            if (put <= 0) {
              break;
            }
            off += put;
          }
        }
        close(dst);
        lseek(src, 0, SEEK_SET);
      }
      close(src);
    }
  }

  if (unshare(CLONE_NEWNS) != 0 ||
      mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n",
            strerror(errno));
    return 10;
  }
  if (mount(ksu_loader_path(), LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
    dprintf(STDERR_FILENO, "late-load: bind mount: %s\n", strerror(errno));
    return 11;
  }

  pid_t loader = fork();
  if (loader < 0) {
    dprintf(STDERR_FILENO, "late-load: fork: %s\n", strerror(errno));
    return 12;
  }
  if (loader == 0) {
    /* Let the downloaded target-specific ksud select its embedded module
     * from the running kernel.  Hard-coding android15-6.6 made the shared
     * loader path unusable for exact 6.1 payloads such as E2S. */
    execl(LOGCAT_PATH, "logcat", "late-load", "--package-name",
          "me.weishu.kernelsu", (char *)NULL);
    dprintf(STDERR_FILENO, "late-load: exec: %s\n", strerror(errno));
    _exit(12);
  }

  int loader_status = wait_status(loader);
  if (loader_status != 0) {
    return loader_status;
  }
  return verify_kernelsu_control();
}

/*
 * Unlocked late-load work. Callers are responsible for serialization via
 * activation_lock_acquire() — the daemon-side activation sequence holds
 * it across this call, and run_kernelsu_late_load() takes it for socket
 * requests. Nesting another acquisition here would deadlock a forked
 * child against its own parent (flock is per open-file-description).
 */
static int kernelsu_late_load_core(void) {
  if (ksu_already_active()) {
    dprintf(STDOUT_FILENO, "late-load: KernelSU already active, skip loader\n");
    return 0;
  }
  return kernelsu_late_load_locked();
}

/*
 * Core module-activation work. Runs in the calling (already-forked)
 * process. Activates KernelSU modules via the ksud lifecycle stages, then
 * restarts zygote so the fresh zygote picks up Zygisk/LSPosed modules.
 *
 * The daemon itself lives in u:r:kernel:s0, which SELinux denies access to
 * /data/adb (magisk_file) and to signaling the zygote — that is why the
 * old direct-exec path reported "no ksud binary found" and modules stayed
 * disabled. Everything is therefore executed through /system/bin/su, which
 * transitions into the u:r:ksu:s0 domain where /data/adb, module scripts,
 * sepolicy patching and zygote signals are all permitted (uid 0 is always
 * allowed by KernelSU sucompat, no manager grant needed).
 */
/*
 * Module activation must run from a shell/app context: sucompat intercepts
 * exec("/system/bin/su") and redirects it into /data/adb, which the
 * daemon's u:r:kernel:s0 domain cannot access, so the exec fails (exit
 * 127) here. Shell-context actors — the payload's stability keeper and any
 * su client — run KSU_APPLY_SCRIPT successfully instead; this daemon-side
 * attempt stays as a best-effort probe that honestly reports failure so a
 * no-op is never mistaken for completion.
 */
static int apply_modules_core(void) {
  set_root_env();

  pid_t mp = fork();
  if (mp == 0) {
    execl("/system/bin/su", "su", "-c", KSU_APPLY_SCRIPT, (char *)NULL);
    int saved_errno = errno;
    dprintf(STDERR_FILENO, "apply-modules: exec su failed errno=%d\n",
            saved_errno);
    _exit(127);
  }
  int su_status = (mp > 0) ? wait_status(mp) : 1;
  dprintf(STDOUT_FILENO, "apply-modules: su script exit=%d\n", su_status);
  return su_status;
}

static int run_apply_modules(struct su_request *request, int conn) {
  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        fchdir(request->cwd_fd) != 0) {
      _exit(126);
    }
    close(conn);
    close_request_fds(request);
    _exit(apply_modules_core());
  }
  close_request_fds(request);
  return wait_status(pid);
}

/*
 * Exclusive cross-process lock shared by the daemon-side activation
 * sequence and socket-request late-loads so concurrent triggers
 * serialize. Never held across a fork that re-acquires it: flock is per
 * open-file-description and a child taking LOCK_EX on the same file would
 * deadlock against its own parent.
 */
static int activation_lock_acquire(void) {
  /* See common.h: the root-owned lock file forces a read-only fallback. */
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

static void activation_lock_release(int fd) {
  if (fd >= 0) {
    flock(fd, LOCK_UN);
    close(fd);
  }
}

static int run_kernelsu_late_load(struct su_request *request, int conn) {
  /* Serialize against the daemon-side activation sequence; the child
   * inherits the lock fd so the lock is held until it exits. */
  int lock_fd = activation_lock_acquire();
  int status = 1;
  pid_t pid = fork();
  if (pid < 0) {
    activation_lock_release(lock_fd);
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        fchdir(request->cwd_fd) != 0) {
      _exit(126);
    }
    close(conn);
    close_request_fds(request);
    _exit(kernelsu_late_load_core());
  }
  close_request_fds(request);
  status = wait_status(pid);
  activation_lock_release(lock_fd);
  return status;
}

/*
 * Daemon-side activation watcher.
 *
 * The exploit runner (shell domain, uid 2000) loses the ability to reach the
 * daemon socket once SELinux re-enforces, so its --late-load/--apply-modules
 * socket requests die with "Permission denied" and modules stay disabled.
 * The daemon, however, was spawned by UMH while SELinux was still permissive
 * and keeps a usable root security domain. The runner drops a marker file
 * (ksu_signal_activation) after a successful exploit; this watcher polls for
 * it and performs late-load + module activation from the daemon's own
 * context, which is always reachable. Output goes to a dedicated log so the
 * sequence is inspectable.
  */
#define ACTIVATE_LOG_PATH "/data/local/tmp/ksu-activate.log"


/*
 * Boot-scoped module-activation completion marker, keyed to the current
 * boot by mtime-versus-uptime instead of boot_id: the daemon's kernel
 * context cannot persist readable boot_id markers, while sysinfo()/stat()
 * work from every context. See common.h for the shared variants.
 */
#define KSU_MODULES_DONE_PATH "/data/local/tmp/.cve43499-modules-done"

static int modules_done_this_boot(void) {
  struct stat st;
  if (stat(KSU_MODULES_DONE_PATH, &st) != 0) {
    return 0;
  }
  struct sysinfo si;
  if (sysinfo(&si) != 0) {
    return 1;
  }
  /* Preferred format: "<boot_id> <write-time uptime>" (see common.h). The
   * boot_id scopes the marker to this boot; the uptime component is
   * immune to NTP wall-clock jumps. */
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
          return stored <= (long)si.uptime + 2;
        }
      }
    }
  }
  return st.st_mtime >= time(NULL) - (long)si.uptime - 5;
}

static void mark_modules_done(void) {
  char payload[128];
  char live_boot_id[64];
  struct sysinfo si;
  size_t len;
  if (sysinfo(&si) == 0 &&
      read_boot_id(live_boot_id, sizeof(live_boot_id))) {
    len = (size_t)snprintf(payload, sizeof(payload), "%s %ld", live_boot_id,
                           (long)si.uptime);
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
 * Work-dir self-heal (daemon-local copy; this translation unit is
 * deliberately self-contained for the kernel-context daemon, see the
 * full rationale in src/workdir_hygiene.h). Anti-log addons such as
 * KillLogger run `rm -rf /data/local/tmp*` every boot and whatever root
 * process recreates the directory labels it system_data_file, which
 * permanently denies shell-domain staging. The daemon executes this
 * during the post-escalation SELinux-permissive window — the earliest
 * point where setxattr succeeds without depending on toybox being
 * reachable. Best-effort: every failure is survivable.
 */
static void heal_work_dir(void) {
  struct stat st;
  if (stat("/data/local/tmp", &st) != 0) {
    mkdir("/data/local/tmp", 0771);
  }
  chown("/data/local/tmp", 2000, 2000);
  chmod("/data/local/tmp", 0771);
  setxattr("/data/local/tmp", "security.selinux",
           "u:object_r:shell_data_file:s0",
           sizeof("u:object_r:shell_data_file:s0") - 1, 0);
  if (stat("/data/local", &st) == 0) {
    setxattr("/data/local", "security.selinux",
             "u:object_r:shell_data_file:s0",
             sizeof("u:object_r:shell_data_file:s0") - 1, 0);
  }
}

static void run_activation_sequence(void) {
  heal_work_dir();
  int log_fd = open(ACTIVATE_LOG_PATH,
                    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (log_fd >= 0) {
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
    if (log_fd > STDERR_FILENO) {
      close(log_fd);
    }
  } else {
    /* SELinux may deny creating the log in shell_data_file depending on
     * policy version; never let that abort activation. */
    int nul = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (nul >= 0) {
      dup2(nul, STDOUT_FILENO);
      dup2(nul, STDERR_FILENO);
      if (nul > STDERR_FILENO) {
        close(nul);
      }
    }
  }

  dprintf(STDOUT_FILENO,
          "[activate] start uid=%d pid=%d ksu_active=%d done=%d\n",
          getuid(), getpid(), ksu_already_active(), modules_done_this_boot());

  /* Idempotent: several watchers/daemons can observe the same marker.
   * Everything below is serialized by the shared lock and keyed to this
   * boot via modules_done_this_boot(). */
  int lock_fd = activation_lock_acquire();
  if (ksu_already_active() && modules_done_this_boot()) {
    dprintf(STDOUT_FILENO, "[activate] already completed this boot\n");
    dprintf(STDOUT_FILENO, "[activate] done\n");
    activation_lock_release(lock_fd);
    return;
  }

  int ll_status = 1;
  if (!ksu_already_active()) {
    pid_t ll = fork();
    if (ll == 0) {
      _exit(kernelsu_late_load_core());
    }
    ll_status = (ll > 0) ? wait_status(ll) : 1;
    dprintf(STDOUT_FILENO, "[activate] late-load exit=%d\n", ll_status);
  } else {
    dprintf(STDOUT_FILENO, "[activate] KernelSU already active, skip late-load\n");
    ll_status = 0;
  }

  /* The ksud loader's self-staging rename step can fail with a non-zero
   * exit even though the kernel module loaded successfully (the rename
   * target /data/adb/ksud may already exist or the staging source may be
   * missing). Do not trust the exit code alone — re-probe the module. If
   * it is now responding, proceed with module activation regardless. */
  int ksu_up = ksu_already_active();
  dprintf(STDOUT_FILENO, "[activate] post-late-load ksu_active=%d\n", ksu_up);

  if ((ll_status == 0 || ksu_up) && !modules_done_this_boot()) {
    /* Record that KernelSU is active for this boot so future pre-exploit
     * checks can detect it without needing a shell root grant. */
    ksu_mark_active_this_boot();

    pid_t am = fork();
    if (am == 0) {
      _exit(apply_modules_core());
    }
    int am_status = (am > 0) ? wait_status(am) : 1;
    dprintf(STDOUT_FILENO, "[activate] apply-modules exit=%d\n", am_status);
    if (am_status == 0 && ksu_already_active()) {
      mark_modules_done();
    }
  } else if (modules_done_this_boot()) {
    dprintf(STDOUT_FILENO, "[activate] modules already active this boot\n");
  } else {
    dprintf(STDERR_FILENO,
            "[activate] late-load failed (%d) and module not active; "
            "skipping module activation\n",
            ll_status);
  }
  dprintf(STDOUT_FILENO, "[activate] done\n");
  activation_lock_release(lock_fd);
}

static void activation_watcher(void) {
  prctl(PR_SET_NAME, "cve43499-activate", 0, 0, 0);
  /* Bounded retry pressure: the first attempts come quickly, but a
   * persistently failing sequence degrades to a long cooldown instead of
   * hot-looping for the lifetime of the daemon. */
  int attempts = 0;
  for (;;) {
    /* Poll for marker existence instead of claiming it via rename: the
     * daemon's u:r:kernel:s0 domain may lack remove_name/rename rights on
     * shell_data_file after SELinux re-enforces, which previously left the
     * marker unclaimed forever. Completion is tracked by the boot-scoped
     * done flag and the whole sequence is flock-serialized, so duplicate
     * wake-ups are harmless. The unlink is best-effort only. */
    struct stat st;
    if (stat(KSU_ACTIVATE_SIGNAL_PATH, &st) == 0 &&
        !modules_done_this_boot()) {
      pid_t ap = fork();
      if (ap == 0) {
        run_activation_sequence();
        _exit(0);
      }
      if (ap > 0) {
        wait_status(ap);
      }
      if (modules_done_this_boot()) {
        unlink(KSU_ACTIVATE_SIGNAL_PATH);
      } else {
        attempts++;
        /* Activation incomplete; back off hard after the early window.
         * The shell-context keeper keeps its own independent schedule, so
         * a deferred apply still happens once the environment is ready. */
        sleep(attempts >= 10 ? 1800 : 5);
      }
    }
    sleep(1);
  }
}

static void send_response(int conn, int status) {
  struct su_response response = {
      .magic = SU_RESPONSE_MAGIC,
      .status = status,
  };
  write_full(conn, &response, sizeof(response));
}

static int prepare_child(struct su_request *request) {
  environ = request->envp;
  if (fchdir(request->cwd_fd) != 0) {
    return 0;
  }
  set_root_env();
  request->argv[0] = "sh";
  return 1;
}

static void close_child_request_fds(struct su_request *request) {
  close_request_fds(request);
}

static int run_direct(struct su_request *request, int conn) {
  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        !prepare_child(request)) {
      _exit(126);
    }
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }
  close_request_fds(request);
  return wait_status(pid);
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0 ||
      ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static int pump_client_io(int tty_fd, int io_fd) {
  char buf[4096];
  int tty_open = 1;

  while (1) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (tty_open) {
      pfd[nfd].fd = tty_fd;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    pfd[nfd].fd = io_fd;
    pfd[nfd].events = POLLIN;
    int io_index = nfd++;

    int ret = poll(pfd, (nfds_t)nfd, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (tty_open) {
      short events = pfd[0].revents;
      if (events & POLLIN) {
        ssize_t n = read(tty_fd, buf, sizeof(buf));
        if (n > 0) {
          if (!write_full(io_fd, buf, (size_t)n)) {
            return 0;
          }
        } else {
          tty_open = 0;
          shutdown(io_fd, SHUT_WR);
        }
      } else if (events & (POLLHUP | POLLERR | POLLNVAL)) {
        tty_open = 0;
        shutdown(io_fd, SHUT_WR);
      }
    }

    short io_events = pfd[io_index].revents;
    if (io_events & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(STDOUT_FILENO, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (io_events & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int pump_server_pty(int io_fd, int master_fd) {
  char buf[4096];

  while (1) {
    struct pollfd pfd[2] = {
        {.fd = io_fd, .events = POLLIN},
        {.fd = master_fd, .events = POLLIN},
    };
    int ret = poll(pfd, 2, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (pfd[0].revents & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(master_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 1;
      }
    }
    if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 1;
    }

    if (pfd[1].revents & POLLIN) {
      ssize_t n = read(master_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(io_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int run_interactive(struct su_request *request, int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    close_request_fds(request);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(master);
    close_request_fds(request);
    return 1;
  }
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    if (request->header.tty.has_termios) {
      tcsetattr(slave, TCSANOW, &request->header.tty.termios);
    }
    if (request->header.tty.has_winsize) {
      ioctl(slave, TIOCSWINSZ, &request->header.tty.winsize);
    }
    ioctl(slave, TIOCSCTTY, 0);
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0 || !prepare_child(request)) {
      _exit(126);
    }
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }

  int io_fd = request->io_fd;
  request->io_fd = -1;
  close_request_fds(request);
  int client_gone = pump_server_pty(io_fd, master);
  if (client_gone) {
    kill(pid, SIGHUP);
  }
  int status = wait_status(pid);
  close(master);
  close(io_fd);
  return status;
}

static int client_send_request(int conn, int argc, char **argv,
                               int interactive, int io_server_fd) {
  uint32_t envc = vector_count(environ, SU_MAX_ENVC);
  if ((uint32_t)argc > SU_MAX_ARGC || envc == UINT32_MAX) {
    return 0;
  }

  int cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cwd_fd < 0) {
    return 0;
  }
  int fds[SU_PASSED_FDS] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                            cwd_fd, io_server_fd};

  struct su_request_header header;
  memset(&header, 0, sizeof(header));
  header.magic = SU_PROTOCOL_MAGIC;
  header.version = SU_PROTOCOL_VERSION;
  header.argc = (uint32_t)argc;
  header.envc = envc;
  header.interactive = interactive != 0;
  if (interactive) {
    header.tty.has_termios =
        tcgetattr(STDIN_FILENO, &header.tty.termios) == 0;
    header.tty.has_winsize =
        ioctl(STDIN_FILENO, TIOCGWINSZ, &header.tty.winsize) == 0;
  }

  int ok = send_fds(conn, fds) &&
           write_full(conn, &header, sizeof(header)) &&
           send_vector(conn, argv, header.argc) &&
           send_vector(conn, environ, header.envc);
  close(cwd_fd);
  return ok;
}

static int client_main(int argc, char **argv) {
  int conn = connect_daemon();
  if (conn < 0) {
    /* Once SELinux re-enforces, shell-domain clients can no longer reach
     * the daemon socket. If KernelSU is in fact already active this boot,
     * a --late-load request is moot: report success instead of an error so
     * callers (the auto-root app flow) do not surface a failure. */
    if (su_probe_active() || ksu_active_this_boot()) {
      dprintf(STDERR_FILENO,
              "late-load: daemon unreachable but KernelSU is already "
              "active this boot; nothing to do\n");
      return 0;
    }
    return 127;
  }

  char auth;
  if (!read_full(conn, &auth, sizeof(auth))) {
    close(conn);
    return 1;
  }
  if (auth != 'A') {
    dprintf(STDERR_FILENO, "su: permission denied\n");
    close(conn);
    return 1;
  }

  int interactive = isatty(STDIN_FILENO);
  int io_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, io_pair) != 0) {
    close(conn);
    return 1;
  }
  if (!client_send_request(conn, argc, argv, interactive, io_pair[1])) {
    close(io_pair[0]);
    close(io_pair[1]);
    close(conn);
    return 1;
  }
  close(io_pair[1]);

  if (interactive) {
    if (tcgetattr(STDIN_FILENO, &saved_terminal) == 0) {
      struct termios raw = saved_terminal;
      cfmakeraw(&raw);
      if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
        saved_terminal_fd = STDIN_FILENO;
        atexit(restore_terminal);
      }
    }
    pump_client_io(STDIN_FILENO, io_pair[0]);
    restore_terminal();
  }
  close(io_pair[0]);

  struct su_response response;
  if (!read_full(conn, &response, sizeof(response)) ||
      response.magic != SU_RESPONSE_MAGIC) {
    close(conn);
    return 1;
  }
  close(conn);
  return response.status;
}

static int get_peer_cred(int conn, struct ucred *peer) {
  socklen_t peer_len = sizeof(*peer);
  return getsockopt(conn, SOL_SOCKET, SO_PEERCRED, peer, &peer_len) == 0 &&
         peer_len == sizeof(*peer);
}

static void serve_one(int conn) {
  struct ucred peer;
  if (!get_peer_cred(conn, &peer) || peer.uid != allowed_client_uid) {
    char denied = 'D';
    write_full(conn, &denied, sizeof(denied));
    return;
  }
  char allowed = 'A';
  if (!write_full(conn, &allowed, sizeof(allowed))) {
    return;
  }

  char operation = 0;
  if (recv(conn, &operation, sizeof(operation), MSG_PEEK) ==
          (ssize_t)sizeof(operation) &&
      operation == 'H') {
    if (!read_full(conn, &operation, sizeof(operation))) {
      return;
    }
    hold_kernel_references(conn);
    return;
  }

  struct su_request request;
  if (!recv_request(conn, &request)) {
    free_request(&request);
    send_response(conn, 1);
    return;
  }

  int is_kernelsu_late_load = request.header.argc == 2 &&
                              strcmp(request.argv[1], "--late-load") == 0;
  int is_apply_modules = request.header.argc == 2 &&
                         strcmp(request.argv[1], "--apply-modules") == 0;
  int status;
  if (is_kernelsu_late_load) {
    status = run_kernelsu_late_load(&request, conn);
  } else if (is_apply_modules) {
    status = run_apply_modules(&request, conn);
  } else if (request.header.interactive) {
    status = run_interactive(&request, conn);
  } else {
    status = run_direct(&request, conn);
  }
  send_response(conn, status);
  free_request(&request);
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  set_root_env();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  /* The UMH path can queue the daemon more than once. A second bind would
   * unlink and steal the first daemon's socket, orphaning its clients.
   * If another daemon already listens, exit quietly — activation is
   * idempotent and that instance's watcher handles everything. */
  int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (probe >= 0) {
    if (connect(probe, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
      close(probe);
      close(fd);
      return 0;
    }
    close(probe);
  }
  unlink(BOOTSTRAP_SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0 ||
      listen(fd, 16) != 0) {
    close(fd);
    return 1;
  }
  chmod(BOOTSTRAP_SOCK_PATH, 0666);

  /* Spawn the activation watcher: it polls for the runner's activation
   * marker and performs KernelSU late-load + module activation from this
   * daemon's root context (the runner's socket path becomes unreachable
   * once SELinux re-enforces). */
  pid_t watcher = fork();
  if (watcher == 0) {
    close(fd);
    setsid();
    activation_watcher();
    _exit(0);
  }

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

static int umh_main(int argc, char **argv) {
  if (geteuid() != 0) {
    return 126;
  }
  if (argc != 3) {
    return 124;
  }
  char *end = NULL;
  errno = 0;
  unsigned long parsed_uid = strtoul(argv[2], &end, 10);
  if (errno || end == argv[2] || *end || parsed_uid == 0 ||
      parsed_uid > UINT32_MAX) {
    return 123;
  }
  allowed_client_uid = (uid_t)parsed_uid;
  if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0 ||
      getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
    return 125;
  }
  return daemon_main();
}

static void relay_payload_log_tail(const char *path, int transport_fd) {
  const off_t tail_size = 64 * 1024;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(transport_fd, "[runner-tail] open failed errno=%d\n", errno);
    return;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    dprintf(transport_fd, "[runner-tail] stat failed errno=%d\n", errno);
    close(fd);
    return;
  }
  off_t start = st.st_size > tail_size ? st.st_size - tail_size : 0;
  if (lseek(fd, start, SEEK_SET) < 0) {
    dprintf(transport_fd, "[runner-tail] seek failed errno=%d\n", errno);
    close(fd);
    return;
  }
  dprintf(transport_fd, "[runner-tail] path=%s bytes=%lld start=%lld\n",
          path, (long long)st.st_size, (long long)start);
  char buffer[4096];
  for (;;) {
    ssize_t got = read(fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0 || !write_full(transport_fd, buffer, (size_t)got)) {
      break;
    }
  }
  close(fd);
}

static pid_t follow_payload_log(const char *path, int transport_fd,
                                pid_t payload_pid, int *status) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  int transport_ok = 1;
  if (fd < 0) {
    dprintf(transport_fd, "[runner-live] open failed errno=%d\n", errno);
    pid_t waited;
    do {
      waited = waitpid(payload_pid, status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited;
  }

  if (dprintf(transport_fd, "[runner-live] following path=%s interval_ms=100\n",
              path) < 0) {
    transport_ok = 0;
  }

  char buffer[4096];
  for (;;) {
    for (;;) {
      ssize_t got = read(fd, buffer, sizeof(buffer));
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got < 0) {
        if (transport_ok) {
          dprintf(transport_fd, "[runner-live] read failed errno=%d\n", errno);
        }
        close(fd);
        pid_t waited;
        do {
          waited = waitpid(payload_pid, status, 0);
        } while (waited < 0 && errno == EINTR);
        return waited;
      }
      if (got == 0) {
        break;
      }
      if (transport_ok &&
          !write_full(transport_fd, buffer, (size_t)got)) {
        transport_ok = 0;
      }
    }

    pid_t waited = waitpid(payload_pid, status, WNOHANG);
    if (waited == payload_pid) {
      /* The writer has exited. Drain bytes appended between the last EOF and
       * waitpid before returning the final status to the adb shell. */
      for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) {
          continue;
        }
        if (got <= 0) {
          break;
        }
        if (transport_ok &&
            !write_full(transport_fd, buffer, (size_t)got)) {
          transport_ok = 0;
        }
      }
      if (transport_ok) {
        dprintf(transport_fd, "[runner-live] child=%d complete status=0x%x\n",
                payload_pid, *status);
      }
      close(fd);
      return waited;
    }
    if (waited < 0) {
      close(fd);
      return waited;
    }
    usleep(100000);
  }
}

/*
 * Feed-driven artifact freshness check (auto-root self-update).
 *
 * The app caches payloads in its private storage and re-pushes the cached
 * bytes on every auto-root boot, so stale artifacts survive forever. Before
 * exploiting, fetch support/targets-v3.json from the payload repository,
 * locate the entry matching this device model, and compare each artifact's
 * recorded size against the local file. Download and atomically replace any
 * file whose size differs (raw.githubusercontent URLs do not expose a
 * usable Last-Modified, so the manifest size is the freshness signal).
 *
 * Best-effort and fail-open: any network or parse error keeps the local
 * files untouched. Set RMG_SELF_UPDATE=0 to disable.
 */
#define RMG_FEED_URL "https://raw.githubusercontent.com/HyperRamzey/" \
    "Root-My-Galaxy-Payloads/main/support/targets-v3.json"
#define RMG_CURL_PATH "/system/bin/curl"
#define RMG_TMP_BASE "/data/local/tmp/.rmg-dl"
#define RMG_ARTIFACT_COUNT 3

struct rmg_artifact_info {
  char url[512];
  long size;
};

static int rmg_fetch_url(const char *url, const char *out_path,
                         int timeout_sec) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO) {
        close(devnull);
      }
    }
    char timeout_arg[16];
    snprintf(timeout_arg, sizeof(timeout_arg), "%d", timeout_sec);
    execl(RMG_CURL_PATH, "curl", "-fsSL", "--max-time", timeout_arg, "-o",
          out_path, url, (char *)NULL);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
}

static long rmg_file_size(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return -1;
  }
  return (long)st.st_size;
}

/* Find the JSON object for this device's model and pull url/size for the
 * three artifact keys. Tolerates arbitrary whitespace around separators.
 * Entry boundaries are located via the "payloadId" token itself because
 * pretty-printed feeds do not place "{" directly adjacent to the key. */
static int rmg_parse_feed(const char *json, const char *model,
                          struct rmg_artifact_info out[RMG_ARTIFACT_COUNT]) {
  static const char *keys[RMG_ARTIFACT_COUNT] = {"exploit", "rootHelper",
                                                 "kernelsu"};
  static const char pid_token[] = "\"payloadId\"";
  /* Quote-delimited model match so we never hit a substring inside prose
   * such as the per-target notes fields. */
  char model_key[64];
  snprintf(model_key, sizeof(model_key), "\"%s\"", model);
  const char *model_pos = strstr(json, model_key);
  if (!model_pos) {
    return -1;
  }
  /* This entry starts at the nearest "payloadId" token at or before the
   * model string; it ends at the following one (or EOF). */
  const char *seg_start = NULL;
  for (const char *p = json; p < model_pos;) {
    const char *hit = strstr(p, pid_token);
    if (!hit || hit >= model_pos) {
      break;
    }
    seg_start = hit;
    p = hit + strlen(pid_token);
  }
  if (!seg_start) {
    return -1;
  }
  const char *seg_end = strstr(model_pos + 1, pid_token);
  if (!seg_end) {
    seg_end = json + strlen(json);
  }

  memset(out, 0, sizeof(*out) * RMG_ARTIFACT_COUNT);
  for (int i = 0; i < RMG_ARTIFACT_COUNT; i++) {
    char key[64];
    snprintf(key, sizeof(key), "\"%s\"", keys[i]);
    const char *kpos = NULL;
    for (const char *p = seg_start; p + strlen(key) <= seg_end; p++) {
      if (strncmp(p, key, strlen(key)) == 0) {
        kpos = p;
        break;
      }
    }
    if (!kpos) {
      continue;
    }
    const char *cursor = kpos + strlen(key);
    const char *limit = seg_end;

    const char *ukey = "\"url\"";
    const char *upos = NULL;
    for (const char *p = cursor; p + strlen(ukey) <= limit; p++) {
      if (strncmp(p, ukey, strlen(ukey)) == 0) {
        upos = p;
        break;
      }
    }
    if (upos) {
      upos = strchr(upos + strlen(ukey), ':');
      while (upos && *upos && *upos != '"') {
        upos++;
      }
      if (upos && *upos == '"' && (size_t)(limit - upos) > 1) {
        upos++;
        size_t n = 0;
        while (upos[n] && upos[n] != '"' &&
               n < sizeof(out[i].url) - 1 &&
               upos + n < limit) {
          n++;
        }
        memcpy(out[i].url, upos, n);
        out[i].url[n] = '\0';
      }
    }

    const char *skey = "\"size\"";
    const char *spos = NULL;
    for (const char *p = cursor; p + strlen(skey) <= limit; p++) {
      if (strncmp(p, skey, strlen(skey)) == 0) {
        spos = p;
        break;
      }
    }
    if (spos) {
      spos = strchr(spos + strlen(skey), ':');
      if (spos && spos < limit) {
        out[i].size = strtol(spos + 1, NULL, 10);
      }
    }
  }
  return 0;
}

/* Atomically replace target with tmp (same filesystem by construction). */
static int rmg_install(const char *tmp, const char *target) {
  chmod(tmp, 0755);
  if (rename(tmp, target) != 0) {
    unlink(tmp);
    return -1;
  }
  return 0;
}

static void self_update_artifacts(int report_fd, const char *payload_path,
                                  const char *helper_arg) {
  const char *disabled = getenv("RMG_SELF_UPDATE");
  if (disabled && strcmp(disabled, "0") == 0) {
    return;
  }

  char model[PROP_VALUE_MAX];
  if (__system_property_get("ro.product.model", model) <= 0) {
    return;
  }

  const char *feed_tmp = RMG_TMP_BASE "-feed.json";
  /* Boot-time networks (and raw.githubusercontent.com) are flaky right
   * when this runs; a failed fetch silently condemned the run to the
   * app's stale cache. Retry the feed before giving up. */
  int feed_ok = 0;
  for (int attempt = 1; attempt <= 3 && !feed_ok; attempt++) {
    unlink(feed_tmp);
    if (attempt > 1) {
      sleep(2 * attempt);
    }
    if (rmg_fetch_url(RMG_FEED_URL, feed_tmp, 20) == 0 &&
        rmg_file_size(feed_tmp) > 0) {
      feed_ok = 1;
    } else {
      dprintf(report_fd, "[self-update] feed fetch attempt %d/3 failed\n",
              attempt);
    }
  }
  if (!feed_ok) {
    dprintf(report_fd, "[self-update] feed unreachable; keeping local "
                       "artifacts\n");
    unlink(feed_tmp);
    return;
  }

  FILE *f = fopen(feed_tmp, "rb");
  if (!f) {
    unlink(feed_tmp);
    return;
  }
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (len <= 0 || len > 4 * 1024 * 1024) {
    fclose(f);
    unlink(feed_tmp);
    return;
  }
  char *json = malloc((size_t)len + 1);
  if (!json || fread(json, 1, (size_t)len, f) != (size_t)len) {
    free(json);
    fclose(f);
    unlink(feed_tmp);
    return;
  }
  json[len] = '\0';
  fclose(f);
  unlink(feed_tmp);

  struct rmg_artifact_info info[RMG_ARTIFACT_COUNT];
  if (rmg_parse_feed(json, model, info) != 0) {
    dprintf(report_fd, "[self-update] no feed entry for model %s\n", model);
    free(json);
    return;
  }
  free(json);

  const char *targets[RMG_ARTIFACT_COUNT];
  targets[0] = payload_path;   /* exploit */
  targets[1] = helper_arg;     /* rootHelper (this binary) */
  char ksu_target[160];
  if (ksu_selfupdate_target(info[2].url, ksu_target, sizeof(ksu_target)) != 0) {
    snprintf(ksu_target, sizeof(ksu_target), "%s", KSU_LOADER_PATH);
  }
  targets[2] = ksu_target      /* kernelsu */;
  static const char *names[RMG_ARTIFACT_COUNT] = {"exploit", "root-helper",
                                                  "ksud"};

  int updated = 0;
  for (int i = 0; i < RMG_ARTIFACT_COUNT; i++) {
    if (info[i].url[0] == '\0' || !targets[i]) {
      continue;
    }
    long local = rmg_file_size(targets[i]);
    if (info[i].size > 0 && local == info[i].size) {
      dprintf(report_fd, "[self-update] %s up-to-date (%ld bytes)\n",
              names[i], local);
      continue;
    }
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s-%d", RMG_TMP_BASE, i);
    int fetched = 0;
    for (int attempt = 1; attempt <= 3 && !fetched; attempt++) {
      unlink(tmp);
      if (attempt > 1) {
        sleep(2 * attempt);
        dprintf(report_fd,
                "[self-update] %s download retry %d/3\n", names[i], attempt);
      }
      if (rmg_fetch_url(info[i].url, tmp, 120) == 0) {
        long got = rmg_file_size(tmp);
        if (info[i].size <= 0 || got == info[i].size) {
          fetched = 1;
          break;
        }
        dprintf(report_fd, "[self-update] %s size mismatch got=%ld\n",
                names[i], got);
      } else {
        dprintf(report_fd, "[self-update] %s download failed (attempt %d)\n",
                names[i], attempt);
      }
    }
    unlink(tmp);
    if (!fetched) {
      continue;
    }
    if (rmg_install(tmp, targets[i]) != 0) {
      dprintf(report_fd, "[self-update] %s install failed errno=%d\n",
              names[i], errno);
      continue;
    }
    updated++;
    dprintf(report_fd, "[self-update] %s updated (%ld bytes)\n", names[i],
            rmg_file_size(targets[i]));
    if (i == 2) {
      /* Keep the pre-staged loader copy in sync with ksud. */
      long src = open(targets[2], O_RDONLY | O_CLOEXEC);
      if (src >= 0) {
        int dst = open("/data/local/tmp/.ksud-stage",
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (dst >= 0) {
          char buf[65536];
          ssize_t gotb;
          while ((gotb = read(src, buf, sizeof(buf))) > 0) {
            write_full(dst, buf, (size_t)gotb);
          }
          close(dst);
        }
        close(src);
      }
    }
  }
  dprintf(report_fd, "[self-update] finished updated=%d\n", updated);
}

static int payload_runner_main(int argc, char **argv) {
  if (argc != 5) {
    return 2;
  }

  int transport_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
  if (transport_fd < 0) {
    return errno;
  }

  /* Refresh stale artifacts from the payload repository before doing
   * anything else; the app keeps re-pushing its cached (possibly outdated)
   * copies on every auto-root boot. */
  self_update_artifacts(transport_fd, argv[2], argv[3]);

  /* Pre-exploit KernelSU liveness check. If KernelSU is already active this
   * boot (a previous run already rooted and late-loaded), skip the exploit
   * entirely — re-running it only risks a kernel panic for no gain.
   *
   * Detection uses two unprivileged signals:
   *   1. `su -c id` reports uid=0 (works when shell has a KSU root grant);
   *   2. the boot-scoped active marker matches the live boot_id (works even
   *      when shell has no grant yet).
   * The reboot-syscall probe needs CAP_SYS_BOOT and returns EPERM from the
   * shell domain even when the module is loaded, so it is not used here. */
  if (su_probe_active() || ksu_active_this_boot()) {
    dprintf(transport_fd,
            "[runner] KernelSU already active this boot; skipping exploit\n");
    close(transport_fd);
    return 0;
  }
  dprintf(transport_fd,
          "[runner] KernelSU not active; proceeding with exploit\n"
          "[runner] NOTE: grant shell (uid 2000) root in the KernelSU "
          "manager after this run so future runs can detect and reuse it\n");

  int log_fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (log_fd < 0 || dup2(log_fd, STDOUT_FILENO) < 0 ||
      dup2(log_fd, STDERR_FILENO) < 0) {
    int saved_errno = errno ? errno : EIO;
    dprintf(transport_fd, "[runner-tail] log setup failed errno=%d\n",
            saved_errno);
    close(transport_fd);
    return saved_errno;
  }
  if (log_fd > STDERR_FILENO) {
    close(log_fd);
  }
  if (setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
      setvbuf(stderr, NULL, _IONBF, 0) != 0) {
    return errno ? errno : EIO;
  }

  /*
   * RDB can drop while the allocator search is still running.  Keep a
   * waitable foreground supervisor for normal adb behavior, but execute the
   * payload in a new session so loss of the shell cannot kill the only run on
   * this boot.  The child owns the persistent log and remains observable by
   * the same helper process when the transport stays alive.
   */
  signal(SIGHUP, SIG_IGN);
  pid_t payload_pid = fork();
  if (payload_pid < 0) {
    close(transport_fd);
    return errno;
  }
  if (payload_pid > 0) {
    int status = 0;
    pid_t waited = follow_payload_log(argv[4], transport_fd, payload_pid,
                                      &status);
    if (waited < 0) {
      int saved_errno = errno;
      relay_payload_log_tail(argv[4], transport_fd);
      close(transport_fd);
      return saved_errno;
    }
    /* Exploit succeeded. The payload constructor already dropped the
     * activation marker; the root daemon's watcher performs KernelSU
     * late-load + module activation from its own context. This supervisor
     * (shell domain) cannot reliably reach the daemon socket once SELinux
     * re-enforces, so it only waits for the daemon's activation log and
     * reports the outcome. */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      dprintf(transport_fd,
              "[runner] exploit ok, waiting for daemon activation\n");
      ksu_signal_activation();
      int activated = 0;
      for (int i = 0; i < 120; i++) {
        int marker_fd = open(ACTIVATE_LOG_PATH, O_RDONLY | O_CLOEXEC);
        if (marker_fd >= 0) {
          char tail[256];
          off_t end = lseek(marker_fd, 0, SEEK_END);
          off_t start = end > (off_t)sizeof(tail) ? end - (off_t)sizeof(tail) : 0;
          lseek(marker_fd, start, SEEK_SET);
          ssize_t got = read(marker_fd, tail, sizeof(tail) - 1);
          close(marker_fd);
          if (got > 0) {
            tail[got] = '\0';
            if (strstr(tail, "[activate] done")) {
              activated = 1;
              break;
            }
          }
        }
        sleep(1);
      }
      dprintf(transport_fd, "[runner] daemon activation %s\n",
              activated ? "completed" : "timed out (check " ACTIVATE_LOG_PATH ")");
    }
    close(transport_fd);
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
      return 128 + WTERMSIG(status);
    }
    return ECHILD;
  }

  close(transport_fd);
  signal(SIGHUP, SIG_IGN);
  if (prctl(PR_SET_PDEATHSIG, 0) != 0 || setsid() < 0) {
    return errno ? errno : EPERM;
  }
  prctl(PR_SET_NAME, "cve43499-run", 0, 0, 0);

  char root_helper_path[PATH_MAX];
  if (!realpath(argv[3], root_helper_path)) {
    dprintf(STDERR_FILENO,
            "[app] root helper realpath failed path=%s errno=%d\n", argv[3],
            errno);
    return errno ? errno : ENOENT;
  }
  if (setenv("CVE43499_ROOT_HELPER", root_helper_path, 1) != 0) {
    return errno;
  }
  dprintf(STDERR_FILENO, "[app] root helper=%s\n", root_helper_path);
  dprintf(STDERR_FILENO, "[app] loading verified payload=%s\n", argv[2]);
  void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    dprintf(STDERR_FILENO, "[app] dlopen failed: %s\n", dlerror());
    return ENOEXEC;
  }
  dprintf(STDERR_FILENO, "[app] payload constructor returned\n");
  fflush(NULL);
  fsync(STDOUT_FILENO);
  return 0;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc >= 2 && strcmp(argv[1], "--run-payload") == 0) {
    return payload_runner_main(argc, argv);
  }
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  if (argc >= 2 && strcmp(argv[1], "--umh") == 0) {
    return umh_main(argc, argv);
  }
  return client_main(argc, argv);
}
