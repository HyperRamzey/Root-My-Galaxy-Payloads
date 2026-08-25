#ifndef WORKDIR_HYGIENE_H
#define WORKDIR_HYGIENE_H

/*
 * Work-directory hygiene.
 *
 * Anti-forensic root addons (the confirmed offender is the KillLogger
 * module, whose late_start service.sh runs `rm -rf /data/local/tmp*`)
 * delete the work directory itself on every boot. Whatever privileged
 * process recreates it afterwards labels it system_data_file instead of
 * shell_data_file, which permanently denies shell-domain staging: adbd
 * cannot create files there any more, app pushes report success but land
 * nothing, chmod exits ENOENT, and auto-root-on-boot can never recover
 * because every recovery vector needs that staging path first.
 *
 * Three primitives live here:
 *
 *  - rmg_diagnose_work_dir(): cheap preflight usable from every domain;
 *    security.selinux is a world-readable xattr, and the writability
 *    probe needs only create+unlink rights.
 *  - rmg_heal_work_dir(): mkdir + chown shell:shell + relabel. Needs
 *    euid 0 or an SELinux permissive window (CAP_MAC_ADMIN-gated under
 *    enforcing), so it is called from the UMH daemon's activation
 *    sequence (permissive right after escalation), from the keeper once
 *    KernelSU is up, from both apply scripts (full su context), and
 *    best-effort at exploit launch. Every step is best-effort by design:
 *    a failed step must never abort the caller.
 *  - rmg_cleanup_stale_runtime_artifacts(): launch-time garbage
 *    collection for state left behind by previous boots. Contract:
 *      * fail-safe — without a live boot_id nothing is deleted;
 *      * NEVER unlink flock lock inodes (flock identity lives on the
 *        inode; recreating the path would break session mutexes);
 *      * NEVER touch current-boot anti-double-root state: any marker
 *        whose embedded boot_id matches the live boot, or the
 *        public-storage marker named after it;
 *      * NEVER delete logs while KernelSU appears loaded — the keeper /
 *        activation writers may still hold the fds open and would keep
 *        appending to orphaned inodes, silently losing the trace.
 */

#include <sys/xattr.h>

#define RMG_WORK_DIR "/data/local/tmp"
#define RMG_SHELL_DATA_LABEL "u:object_r:shell_data_file:s0"

/*
 * Shell-side heal, executed through `su -c` by privileged actors.
 * restorecon consults the on-device file_contexts (correct even if the
 * platform ever changes its type naming); chcon is the fallback for
 * firmwares shipping without the toybox link. Idempotent per boot.
 */
#define RMG_WORK_DIR_HEAL_SH                                                   \
  "mkdir -p " RMG_WORK_DIR " 2>/dev/null; "                                    \
  "chown 2000:2000 " RMG_WORK_DIR " 2>/dev/null; "                             \
  "chmod 0771 " RMG_WORK_DIR " 2>/dev/null; "                                  \
  "restorecon -RF /data/local " RMG_WORK_DIR " >/dev/null 2>&1 || "            \
  "chcon -R u:object_r:shell_data_file:s0 /data/local " RMG_WORK_DIR           \
  " >/dev/null 2>&1; "

static inline ssize_t rmg_read_selinux_label(const char *path, char *out,
                                             size_t out_len) {
  ssize_t n = getxattr(path, "security.selinux", out, out_len - 1);
  if (n <= 0) {
    return n;
  }
  out[n] = '\0';
  return n;
}

static inline int rmg_dir_writable(const char *dir) {
  char probe[256];
  snprintf(probe, sizeof(probe), "%s/.rmg-probe-%d", dir, (int)getpid());
  int fd = open(probe, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    close(fd);
    unlink(probe);
    return 1;
  }
  return 0;
}

static inline void rmg_heal_work_dir(void) {
  struct stat st;
  if (stat(RMG_WORK_DIR, &st) != 0) {
    mkdir(RMG_WORK_DIR, 0771);
  }
  /* 2000:2000 = shell:shell, matching what init itself creates; the mode
   * mirrors the stock drwxrwx--x so adbd can stage but other apps still
   * cannot list the contents. */
  chown(RMG_WORK_DIR, 2000, 2000);
  chmod(RMG_WORK_DIR, 0771);
  /* Bionic setxattr: (path, name, value, size, flags) — no offset arg. */
  setxattr(RMG_WORK_DIR, "security.selinux", RMG_SHELL_DATA_LABEL,
           sizeof(RMG_SHELL_DATA_LABEL) - 1, 0);
  /* A poisoned parent denies traversal even over a repaired child, so
   * relabel /data/local as well (ownership there is left untouched —
   * root-owned /data/local is stock). */
  if (stat("/data/local", &st) == 0) {
    setxattr("/data/local", "security.selinux", RMG_SHELL_DATA_LABEL,
             sizeof(RMG_SHELL_DATA_LABEL) - 1, 0);
  }
}

static inline void rmg_diagnose_work_dir(void) {
  struct stat st;
  if (stat(RMG_WORK_DIR, &st) != 0) {
    pr_warning("work-dir %s missing (anti-log module wipe?); "
               "staging impossible until a privileged actor heals it\n",
               RMG_WORK_DIR);
    return;
  }
  int writable = rmg_dir_writable(RMG_WORK_DIR);
  char label[160];
  ssize_t n = rmg_read_selinux_label(RMG_WORK_DIR, label, sizeof(label));
  int mislabeled = n > 0 && strcmp(label, RMG_SHELL_DATA_LABEL) != 0;
  if (!writable || mislabeled) {
    pr_warning("work-dir degraded writable=%d label=%s expected=%s; "
               "adb staging fails until a privileged actor heals it\n",
               writable, n > 0 ? label : "<none>", RMG_SHELL_DATA_LABEL);
  } else {
    pr_info("work-dir healthy writable=%d label=%s\n", writable, label);
  }
}

/* Delete a private marker only when it provably does not belong to the
 * current boot. Current-boot content ("<live-boot-id> ..." or exactly the
 * live boot_id) is kept; empty, unreadable-while-present, legacy ("done",
 * bare uptime) and foreign-boot payloads are removed so downstream
 * consumers re-evaluate honestly instead of falling back to mtime
 * heuristics. */
static inline void rmg_unlink_boot_scoped_marker(const char *path,
                                                 const char *live) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return;
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  char buf[128];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  size_t live_len = strlen(live);
  /* EOF exactly at live_len means the file holds precisely the boot_id
   * (the bare-marker convention) — that is current-boot state. Reading
   * buf[live_len] in that case would inspect an uninitialized stack byte
   * and could delete the anti-double-root marker. */
  if (n > 0 && (size_t)n >= live_len &&
      strncmp(buf, live, live_len) == 0 &&
      ((size_t)n == live_len || buf[live_len] == ' ' ||
       buf[live_len] == '\n' || buf[live_len] == '\0')) {
    return;
  }
  unlink(path);
}

static inline void rmg_cleanup_stale_runtime_artifacts(void) {
  char live[64];
  if (!read_boot_id(live, sizeof(live))) {
    return;
  }

  /* Leftover activation handoff signal. Safe here because this session
   * owns the exploit-session flock (no sibling daemon can be polling
   * it) and the fresh signal is re-dropped by ksu_signal_activation()
   * once the kernel-write window closes. Dropping it now also closes a
   * real race: a stale signal would let the next UMH daemon wake into
   * late-load before that window opens. The activation watcher only
   * stat()s the path, so unlinking mid-poll is harmless. */
  unlink(KSU_ACTIVATE_SIGNAL_PATH);

  rmg_unlink_boot_scoped_marker(KSU_MODULES_DONE_PATH, live);
  rmg_unlink_boot_scoped_marker(KSU_ACTIVE_MARKER_PATH, live);

  /* Public-storage markers are filename-scoped by design. */
  DIR *dir = opendir("/storage/emulated/0");
  if (dir != NULL) {
    struct dirent *ent;
    size_t prefix_len = strlen(".cve43499-ksu-");
    while ((ent = readdir(dir)) != NULL) {
      if (strncmp(ent->d_name, ".cve43499-ksu-", prefix_len) != 0) {
        continue;
      }
      if (strcmp(ent->d_name + prefix_len, live) == 0) {
        continue;
      }
      char path[160];
      snprintf(path, sizeof(path), "/storage/emulated/0/%s", ent->d_name);
      unlink(path);
    }
    closedir(dir);
  }

  /* Logs: only while no KernelSU actor can still hold them open. Once
   * the module is loaded the keeper may be mid-append on an existing
   * fd; deleting then would orphan its output for the rest of the
   * boot. Previous boots' logs are gone with the boot_id-scoped checks
   * above; these files are plain diagnostics, so they are rotated only
   * ahead of a fresh attempt. */
  if (!ksu_module_loaded()) {
    unlink("/data/local/tmp/ksu-keeper.log");
    unlink("/data/local/tmp/ksu-activate.log");
  }
}

#endif
