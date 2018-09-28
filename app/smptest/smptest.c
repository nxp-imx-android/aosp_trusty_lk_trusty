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

static int smptest(void* arg) {
    int i = (uintptr_t)arg;

    while (true) {
        THREAD_LOCK(state1);
        get_current_thread()->state = THREAD_BLOCKED;
        thread_block();
        smptest_thread_unblock_count[i]++;
        THREAD_UNLOCK(state1);

        thread_sleep(100);

        THREAD_LOCK(state2);
        if (i + 1 < SMPTEST_THREAD_COUNT) {
            thread_unblock(smptest_thread[i + 1], false);
        } else {
            printf("%s: %d %d\n", __func__, i, smptest_thread_unblock_count[i]);
        }
        THREAD_UNLOCK(state2);
    }
    return 0;
}

static bool run_smp_test(struct unittest* test) {
    int i;
    bool wait_for_cpus = false;

    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        if (smptest_thread[i]->state != THREAD_BLOCKED) {
            unittest_printf("smptest, thread %d not ready, wait\n", i);
            wait_for_cpus = true;
            break;
        }
    }
    if (wait_for_cpus) {
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
    }
    THREAD_LOCK(state);
    thread_unblock(smptest_thread[0], false);
    THREAD_UNLOCK(state);
    thread_sleep(1000);
    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        switch (smptest_thread_unblock_count[i]) {
        case 0:
            unittest_printf("smptest cpu %d FAILED to run\n", i);
            return false;
        case 1:
            unittest_printf("smptest cpu %d ran\n", i);
            break;
        default:
            unittest_printf("smptest cpu %d FAILED to block\n", i);
            return false;
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
        smptest_thread[i]->pinned_cpu = i;
    }
    for (i = 0; i < SMPTEST_THREAD_COUNT; i++) {
        thread_resume(smptest_thread[i]);
    }

    unittest_add(&smp_unittest);
}

LK_INIT_HOOK(smptest, smptest_init, LK_INIT_LEVEL_APPS);
