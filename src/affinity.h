/*
 * CPU-cluster affinity for SM8550-class (Snapdragon 8 Gen 2) targets.
 *
 * Nominal topology on the Fold5 (SM-F946B, 5.15.189):
 *   cpu0-2  Cortex-A510 LITTLE   max 2016 MHz
 *   cpu3-6  Cortex-A715/A710 big max 2803 MHz
 *   cpu7    Cortex-X3 prime      max 3360 MHz
 *
 * Firmware reality verified on device RFCWC0G1Z1J: the kernel rejects
 * sched_setaffinity({cpu7}) with EINVAL even though the core reports
 * online — Samsung reserves the prime core (restricted-CPU class, camera
 * path). Selection is therefore PROBE-BASED: the nominal fastest core is
 * preferred, but every candidate must pass a live affinity probe before
 * it is handed out; unusable cores are dropped and selection degrades to
 * the fastest permitted perf core. On stock F946B firmware the exploit
 * choreography consequently runs on the 2.8 GHz perf cluster (never on
 * LITTLE anymore), and automatically upgrades to the X3 on firmwares
 * where the kernel permits it.
 *
 * Policy: time-sensitive choreography -> timing core; consumer/waiter
 * counterpart threads -> separate perf cores; long-lived background
 * actors -> whole permitted perf mask. Nothing is deliberately scheduled
 * onto the LITTLE cluster.
 *
 * Layout is detected at runtime from cpufreq, cross-checked with live
 * probes, falling back to the known SM8550 map when sysfs is unreadable.
 * RMG_TIMING_CORE / RMG_CONSUMER_CORE override individual picks,
 * RMG_NO_AFFINITY=1 disables all pinning (diagnostics only).
 */
#ifndef CVE43499_AFFINITY_H
#define CVE43499_AFFINITY_H

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

#define AFFINITY_MAX_CPUS 32

struct affinity_layout {
  int detected;
  int timing_core;                       /* Cortex-X3 prime core          */
  int consumer_core;                     /* first perf-cluster core       */
  int waiter_core;                       /* second perf core (or same)    */
  cpu_set_t perf_mask;                   /* perf cluster, excl. prime     */
};

static struct affinity_layout affinity_layout;

/* Live probe: may the calling task actually be pinned to cpu c? Samsung
 * restricted-core kernels answer sched_setaffinity with EINVAL for the
 * reserved prime even when it is online, so nominal frequency maps are
 * not trustworthy on their own. Probes trial-pin and immediately restore
 * the original mask. */
static inline int affinity_cpu_usable(int c) {
  if (c < 0 || c >= AFFINITY_MAX_CPUS) {
    return 0;
  }
  cpu_set_t prev;
  if (sched_getaffinity(0, sizeof(prev), &prev) != 0 ||
      !CPU_ISSET(c, &prev)) {
    return 0;
  }
  cpu_set_t want;
  CPU_ZERO(&want);
  CPU_SET(c, &want);
  if (sched_setaffinity(0, sizeof(want), &want) != 0) {
    return 0;
  }
  sched_setaffinity(0, sizeof(prev), &prev);
  return 1;
}

static inline void affinity_detect(void) {
  if (affinity_layout.detected) {
    return;
  }
  /* Fallback: known SM8550 map. */
  int fallback_freq[AFFINITY_MAX_CPUS] = {0};
  for (int c = 0; c < AFFINITY_MAX_CPUS; c++) {
    fallback_freq[c] = -1;
  }
  fallback_freq[0] = fallback_freq[1] = fallback_freq[2] = 2016000;
  fallback_freq[3] = fallback_freq[4] = fallback_freq[5] = fallback_freq[6] =
      2803200;
  fallback_freq[7] = 3360000;

  int freq[AFFINITY_MAX_CPUS];
  int max_cpu = -1;
  for (int c = 0; c < AFFINITY_MAX_CPUS; c++) {
    char path[96];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", c);
    FILE *f = fopen(path, "r");
    freq[c] = -1;
    if (f) {
      int v = -1;
      if (fscanf(f, "%d", &v) == 1 && v > 0) {
        freq[c] = v;
        if (c > max_cpu) {
          max_cpu = c;
        }
      }
      fclose(f);
    }
  }
  if (max_cpu < 1) {
    for (int c = 0; c < AFFINITY_MAX_CPUS; c++) {
      freq[c] = fallback_freq[c];
      if (fallback_freq[c] > 0 && c > max_cpu) {
        max_cpu = c;
      }
    }
  }

  int top_freq = 0, second_freq = 0;
  for (int c = 0; c <= max_cpu; c++) {
    if (freq[c] > top_freq) {
      second_freq = top_freq;
      top_freq = freq[c];
    } else if (freq[c] < top_freq && freq[c] > second_freq) {
      second_freq = freq[c];
    }
  }
  int timing = -1;
  CPU_ZERO(&affinity_layout.perf_mask);
  int perf_list[AFFINITY_MAX_CPUS];
  int perf_n = 0;
  for (int c = 0; c <= max_cpu; c++) {
    if (freq[c] == top_freq && timing < 0) {
      timing = c;
    } else if (freq[c] == second_freq || freq[c] == top_freq) {
      CPU_SET(c, &affinity_layout.perf_mask);
      perf_list[perf_n++] = c;
    }
  }
  if (timing < 0 || perf_n == 0) {
    /* Degenerate read: use the static map wholesale. */
    timing = 7;
    CPU_ZERO(&affinity_layout.perf_mask);
    perf_n = 0;
    for (int c = 3; c <= 6; c++) {
      CPU_SET(c, &affinity_layout.perf_mask);
      perf_list[perf_n++] = c;
    }
  }

  /* Cross-check the nominal map against live affinity probes. A kernel
   * that reserves the prime core (EINVAL on trial pin) demotes the
   * choreography target to the fastest permitted perf core; LITTLE cores
   * are never candidates here because their frequency sits strictly
   * below every perf-cluster entry. */
  if (!affinity_cpu_usable(timing)) {
    int best = -1;
    int best_freq = -1;
    for (int c = max_cpu; c > 2; c--) {
      if (freq[c] > best_freq && affinity_cpu_usable(c)) {
        best = c;
        best_freq = freq[c];
      }
    }
    if (best >= 0) {
      timing = best;
    } else {
      /* Perf cluster entirely unusable: last resort is any probeable
       * cpu rather than failing the run. */
      for (int c = max_cpu; c >= 0; c--) {
        if (affinity_cpu_usable(c)) {
          timing = c;
          break;
        }
      }
    }
  }

  /* Rebuild the background/consumer pool: probe-permitted cores of the
   * perf clusters (strictly below the nominal prime frequency, so the
   * X3 never takes background work), excluding the chosen choreography
   * core. Scanned high-to-low so consumer/waiter picks prefer faster
   * cores. */
  CPU_ZERO(&affinity_layout.perf_mask);
  perf_n = 0;
  for (int c = max_cpu; c >= 0 && perf_n < AFFINITY_MAX_CPUS; c--) {
    if (c == timing || freq[c] < second_freq || freq[c] >= top_freq ||
        !affinity_cpu_usable(c)) {
      continue;
    }
    CPU_SET(c, &affinity_layout.perf_mask);
    perf_list[perf_n++] = c;
  }
  affinity_layout.timing_core = timing;
  const char *env = getenv("RMG_NO_AFFINITY");
  if (env && env[0] == '1') {
    affinity_layout.consumer_core = timing;
    affinity_layout.waiter_core = timing;
    CPU_ZERO(&affinity_layout.perf_mask);
    CPU_SET(timing, &affinity_layout.perf_mask);
  } else {
    env = getenv("RMG_CONSUMER_CORE");
    if (env) {
      affinity_layout.consumer_core = atoi(env);
    } else {
      affinity_layout.consumer_core =
          perf_n > 0 ? perf_list[0] : timing;
    }
    env = getenv("RMG_TIMING_CORE");
    if (env) {
      affinity_layout.timing_core = atoi(env);
    }
    affinity_layout.waiter_core =
        perf_n > 1 ? perf_list[1] : affinity_layout.consumer_core;
  }
  if (affinity_layout.waiter_core < 0) {
    affinity_layout.waiter_core = affinity_layout.consumer_core;
  }
  if (affinity_layout.consumer_core < 0) {
    affinity_layout.consumer_core = affinity_layout.timing_core;
  }
  affinity_layout.detected = 1;
}

static inline int affinity_timing_core(void) {
  affinity_detect();
  return affinity_layout.timing_core;
}

static inline int affinity_consumer_core(void) {
  affinity_detect();
  return affinity_layout.consumer_core;
}

static inline int affinity_waiter_core(void) {
  affinity_detect();
  return affinity_layout.waiter_core;
}

/* Whole permitted perf-cluster mask for background actors ("rest of it").
 * Intersected with the caller's current affinity: a cpuset wall must not
 * turn an optimization into an error. Failures are silently ignored — the
 * scheduler default remains valid. */
static inline void pin_perf_mask(void) {
  affinity_detect();
  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
    return;
  }
  cpu_set_t want;
  CPU_ZERO(&want);
  CPU_AND(&want, &allowed, &affinity_layout.perf_mask);
  if (CPU_COUNT(&want) == 0) {
    return;
  }
  sched_setaffinity(0, sizeof(want), &want);
}

/* One-line summary of the resolved mapping for exploit logs. */
static inline void affinity_describe(char *out, size_t out_len) {
  affinity_detect();
  char perf[128];
  perf[0] = '\0';
  size_t off = 0;
  for (int c = 0; c < AFFINITY_MAX_CPUS && off < sizeof(perf) - 8; c++) {
    if (CPU_ISSET(c, &affinity_layout.perf_mask)) {
      off += (size_t)snprintf(perf + off, sizeof(perf) - off, "%s%d",
                              off ? "," : "", c);
    }
  }
  snprintf(out, out_len, "prime=%d perf=[%s] timing->%d consumer->%d",
           affinity_layout.timing_core, perf, affinity_layout.timing_core,
           affinity_layout.consumer_core);
}

#endif
