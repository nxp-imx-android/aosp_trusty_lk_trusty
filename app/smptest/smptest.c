/*
 * Copyright (c) 2018, Google Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <kernel/thread.h>
#include <lib/unittest/unittest.h>
#include <lk/init.h>
#include <stdbool.h>
#include <stdio.h>

#define SMPTEST_THREAD_COUNT 4

#define THREAD_DELAY_MS 100

static thread_t* smptest_thread[SMPTEST_THREAD_COUNT];
static volatile int smptest_thread_unblock_count[SMPTEST_THREAD_COUNT];
static volatile int smptest_thread_done_count[SMPTEST_THREAD_COUNT];

/* Check if a thread is blocked, using volatile to ensure re-read */
static bool thread_is_blocked(volatile thread_t* thread) {
    return thread->state == THREAD_BLOCKED;
}

static int smptest_thread_func(void* arg) {
    const uint i = (uintptr_t)arg;
    uint cpu = arch_curr_cpu_num();

    if (cpu != i) {
        /* Warn if the thread starts on another CPU than it was pinned to */
        printf("%s: thread %d started on wrong cpu: %d\n", __func__, i, cpu);
    }

    while (true) {
        THREAD_LOCK(state1);
        get_current_thread()->state = THREAD_BLOCKED;
        thread_block();

        cpu = arch_curr_cpu_num();
        if (cpu != i) {
            /* Don't update any state if the thread runs on the wrong CPU. */
            printf("%s: thread %d ran on wrong cpu: %d\n", __func__, i, cpu);
            continue;
        }

        /*
         * Update unblock count for this cpu so the main test thread can see
         * that it ran.
         */
        smptest_thread_unblock_count[i]++;
        THREAD_UNLOCK(state1);

        /* Sleep to simplify tracing and test CPU local timers */
        thread_sleep(THREAD_DELAY_MS);

        THREAD_LOCK(state2);
        if (i + 1 < SMPTEST_THREAD_COUNT) {
            /* Next CPU should be blocked; wake it up */
            if (thread_is_blocked(smptest_thread[i + 1])) {
                thread_unblock(smptest_thread[i + 1], false);
            } else {
                printf("%s: thread %d not blocked\n", __func__, i + 1);
            }
        } else {
            /* Print status from last CPU. */
            printf("%s: %d %d\n", __func__, i, smptest_thread_unblock_count[i]);
        }

        /*
         * Update unblock count for this cpu so the main test thread can see
         * that it completed.
         */
        smptest_thread_done_count[i]++;
        THREAD_UNLOCK(state2);
    }
    return 0;
}

TEST(smptest, run) {
    bool wait_for_cpus = false;
    int i, j;

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        if (!thread_is_blocked(smptest_thread[i])) {
            unittest_printf("[   INFO   ] thread %d not ready\n", i);
            wait_for_cpus = true;
        }
    }

    /*
     * test-runner can start the test before all CPUs have finished booting.
     * Wait another second for all the CPUs we need to be ready if needed.
     */
    if (wait_for_cpus) {
        unittest_printf("[   INFO   ] waiting for threads to be ready\n", i);
        thread_sleep(1000);
    }

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        ASSERT_EQ(thread_is_blocked(smptest_thread[i]), true,
                  "thread %d not ready\n", i);
    }

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        smptest_thread_unblock_count[i] = 0;
        smptest_thread_done_count[i] = 0;
    }

    /*
     * Repeat the test at least once, in case the CPUs don't go back to the
     * same state after the first wake-up
     */
    for (j = 1; j <= 2; j++) {
        THREAD_LOCK(state);
        /*
         * Wake up thread on CPU 0 to start a test run. Each thread 'n' should
         * wake-up thread 'n+1' until the last thread stops.
         * Check thread is blocked before unblocking to avoid asserts.
         */
        if (thread_is_blocked(smptest_thread[0])) {
            thread_unblock(smptest_thread[0], false);
        }

        THREAD_UNLOCK(state);

        /* Sleep to allow all CPUs to run with some margin */
        thread_sleep((THREAD_DELAY_MS * SMPTEST_THREAD_COUNT) + 500);

        /*
         * Check that every CPU-thread ran exactly once each time we woke up the
         * thread on CPU 0.
         */
        for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
            const int unblock_count = smptest_thread_unblock_count[i];
            const int done_count = smptest_thread_done_count[i];

            EXPECT_EQ(unblock_count, j, "cpu %d FAILED block count\n", i);
            EXPECT_EQ(done_count, j, "cpu %d FAILED done count\n", i);

            unittest_printf("[   INFO   ] smptest cpu %d run %d\n", i, j);
        }
    }

test_abort:;
}

static void smptest_setup(uint level) {
    int i;
    char thread_name[32];

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        snprintf(thread_name, sizeof(thread_name), "smptest-%d", i);
        smptest_thread[i] = thread_create(thread_name, smptest_thread_func,
                                          (void*)(uintptr_t)i, HIGH_PRIORITY,
                                          DEFAULT_STACK_SIZE);
        thread_set_pinned_cpu(smptest_thread[i], i);
    }
    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        thread_resume(smptest_thread[i]);
    }
}

LK_INIT_HOOK(smptest_hook, smptest_setup, LK_INIT_LEVEL_APPS);

PORT_TEST(smptest, "com.android.kernel.smp-unittest");
