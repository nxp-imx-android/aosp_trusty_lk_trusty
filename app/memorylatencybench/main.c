/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TLOG_TAG "memlatency"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <trusty_benchmark.h>
#include <uapi/err.h>

#define BUF_SIZE 16384

typedef struct {
    uint8_t buf[BUF_SIZE];
} memlatency_state_t;

static memlatency_state_t* memlatency_state;

BENCH_SETUP(memlatency) {
    memlatency_state = calloc(1, sizeof(memlatency_state_t));
    if (memlatency_state == NULL) {
        TLOGE("Failed to Allocate memory for memlatency_state!");
        return ERR_NO_MEMORY;
    }

    return NO_ERROR;
}

BENCH_TEARDOWN(memlatency) {
    free(memlatency_state);
    memlatency_state = NULL;
}

BENCH(memlatency, latency, 20) {
    int rc = NO_ERROR;

    ASSERT_EQ(NO_ERROR, rc);

test_abort:
    return rc;
}

BENCH_RESULT(memlatency, latency, time_micro_seconds) {
    return bench_get_duration_ns();
}

PORT_TEST(memlatency, "com.android.kernel.memorylatency.bench");
