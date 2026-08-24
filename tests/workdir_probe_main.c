/*
 * On-device probe for workdir_hygiene.h. Runs from the shell domain
 * (uid 2000) without root: exercises diagnose/heal/cleanup against the
 * live filesystem and prints what happened. Not shipped in any payload.
 */
#define _GNU_SOURCE
#include "../src/common.h"

int main(void) {
  set_unbuffer();
  pr_info("=== workdir hygiene probe start uid=%d ===\n", getuid());
  rmg_diagnose_work_dir();
  rmg_heal_work_dir();
  pr_info("probe: heal attempted (expected to fail from shell under "
          "enforcing policy)\n");
  char live[64];
  read_boot_id(live, sizeof(live));
  pr_info("probe: live boot_id=%s\n", live);
  rmg_cleanup_stale_runtime_artifacts();
  /* Report post-state of public-storage markers so the caller can diff
   * planted stale vs current entries. */
  DIR *dir = opendir("/storage/emulated/0");
  if (dir != NULL) {
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
      if (strncmp(ent->d_name, ".cve43499-", 10) == 0) {
        pr_info("probe: surviving marker %s\n", ent->d_name);
      }
    }
    closedir(dir);
  }
  pr_info("=== workdir hygiene probe done ===\n");
  return 0;
}
