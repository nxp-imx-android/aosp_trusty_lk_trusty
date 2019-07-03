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

#define SMPTEST_THREAD_COUNT (4)

static thread_t* smptest_thread[SMPTEST_THREAD_COUNT];
static int smptest_thread_unblock_count[SMPTEST_THREAD_COUNT];
static int smptest_thread_done_count[SMPTEST_THREAD_COUNT];

static int smptest(void* arg) {
    uint i = (uintptr_t)arg;
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
        thread_sleep(100);

        THREAD_LOCK(state2);
        if (i + 1 < SMPTEST_THREAD_COUNT) {
            /* Wake up next CPU */
            thread_unblock(smptest_thread[i + 1], false);
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

static bool run_smp_test(struct unittest* test) {
    int i;
    int j;
    bool wait_for_cpus = false;

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        if (smptest_thread[i]->state != THREAD_BLOCKED) {
            unittest_printf("smptest, thread %d not ready, wait\n", i);
            wait_for_cpus = true;
            break;
        }
    }
    if (wait_for_cpus) {
        /*
         * test-runner can start the test before all CPUs have finished booting.
         * Wait another second for all the CPUs we need to be ready.
         */
        thread_sleep(1000);
    }
    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        if (smptest_thread[i]->state != THREAD_BLOCKED) {
            unittest_printf("smptest, thread %d not ready\n", i);
            return false;
        }
    }
    unittest_printf("smptest start\n");
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
         * Wake up thread on CPU 0 to start a test run. It will wake up CPU 1,
         * CPU 1 will wake up CPU 2 and CPU 2 will wake up CPU 3.
         */
        thread_unblock(smptest_thread[0], false);
        THREAD_UNLOCK(state);

        /*
         * Sleep 1 second to allow all CPUs to run. Each CPU sleeps 100 ms, so
         * this leaves 600 ms of execution time.
         */
        thread_sleep(1000);

        /*
         * Check that every CPU-thread ran exactly once each time we woke up the
         * thread on CPU 0.
         */
        for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
            int unblock_count = smptest_thread_unblock_count[i];
            int done_count = smptest_thread_done_count[i];
            if (unblock_count < j) {
                unittest_printf("smptest cpu %d FAILED to run\n", i);
                return false;
            }
            if (done_count < j) {
                unittest_printf("smptest cpu %d FAILED to complete\n", i);
                return false;
            }
            if (unblock_count > j || done_count > j) {
                unittest_printf("smptest cpu %d FAILED to block\n", i);
                return false;
            }
            unittest_printf("smptest cpu %d ran\n", i);
        }
    }
    return true;
}

static struct unittest smp_unittest = {
        .port_name = "com.android.kernel.smp-unittest",
        .run_test = run_smp_test,
};

static void smptest_init(uint level) {
    int i;
    char thread_name[32];

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        snprintf(thread_name, sizeof(thread_name), "smptest-%d", i);
        smptest_thread[i] =
                thread_create(thread_name, smptest, (void*)(uintptr_t)i,
                              HIGH_PRIORITY, DEFAULT_STACK_SIZE);
        thread_set_pinned_cpu(smptest_thread[i], i);
    }
    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        thread_resume(smptest_thread[i]);
    }

    unittest_add(&smp_unittest);
}

LK_INIT_HOOK(smptest, smptest_init, LK_INIT_LEVEL_APPS);
