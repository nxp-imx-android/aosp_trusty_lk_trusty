/*
 * Copyright (c) 2021 Google Inc. All rights reserved
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

#define LOCAL_TRACE (0)

#include "thread_service_policy.h"
#include <assert.h>
#include <err.h>
#include <interface/thread/thread.h>
#include <lk/trace.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_uuid.h>
#include <uapi/err.h>
#include <uapi/trusty_uuid.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct set_peer_policy {
    const struct uuid* uuid;
    int (*get_peer_uuid)(uint32_t idx, const struct uuid** peer_uuid);
};

static int default_peer_policy(uint32_t idx, const struct uuid** peer_uuid) {
    return ERR_NOT_ALLOWED;
}

/* G6 Fingerprint TA's uuid: 8db26df6-9e77-4f61-b3c2-b88a788cbac2 */
static const struct uuid gf_uuid = {
        0x8db26df6,
        0x9e77,
        0x4f61,
        {0xb3, 0xc2, 0xb8, 0x8a, 0x78, 0x8c, 0xba, 0xc2},
};

/* Storage Server TA's uuid: cea8706d-6cb4-49f3-b994-29e0e478bd29 */
static const struct uuid storage_server_uuid = {
        0xcea8706d,
        0x6cb4,
        0x49f3,
        {0xb9, 0x94, 0x29, 0xe0, 0xe4, 0x78, 0xbd, 0x29},
};

static int fingerprint_peer_policy(uint32_t idx,
                                   const struct uuid** peer_uuid) {
    DEBUG_ASSERT(peer_uuid);
    if (idx == 0) {
        *peer_uuid = &storage_server_uuid;
        return NO_ERROR;
    }
    return ERR_NOT_ALLOWED;
}
#ifdef TEST_BUILD
/* Test Server TA's uuid: 023cb592-49a7-43f3-b3b8-4b83289e62ab */
static const struct uuid thread_test_uuid = {
        0x023cb592,
        0x49a7,
        0x43f3,
        {0xb3, 0xb8, 0x4b, 0x83, 0x28, 0x9e, 0x62, 0xab},
};
static const struct uuid thread_test_srv_uuid = {
        0x753e629f,
        0x877f,
        0x4aeb,
        {0xa3, 0x99, 0x73, 0xbe, 0x46, 0x14, 0xde, 0x29},
};

static int test_peer_policy(uint32_t idx, const struct uuid** peer_uuid) {
    DEBUG_ASSERT(peer_uuid);
    if (idx == 1) {
        *peer_uuid = &thread_test_srv_uuid;
        return NO_ERROR;
    }
    return ERR_NOT_ALLOWED;
}
#endif  // TEST_BUILD

/* Application specific rules for setting peer uuid affinity. */
const static struct set_peer_policy peer_policies[] = {
        {
                .uuid = &gf_uuid,
                .get_peer_uuid = fingerprint_peer_policy,
        },
#ifdef TEST_BUILD
        {
                .uuid = &thread_test_uuid,
                .get_peer_uuid = test_peer_policy,
        },
#endif  // TEST_BUILD
};

static bool equal_uuid(const struct uuid* a, const struct uuid* b) {
    return memcmp(a, b, sizeof(struct uuid)) == 0;
}

void thread_service_policy_setaffinity_load(
        const struct uuid* uuid,
        struct thread_service_policy_setaffinity* policy) {
    policy->get_peer_uuid = default_peer_policy;
    for (unsigned int i = 0; i < ARRAY_SIZE(peer_policies); i++) {
        if (equal_uuid(uuid, peer_policies[i].uuid)) {
            policy->get_peer_uuid = peer_policies[i].get_peer_uuid;
            return;
        }
    }
    return;
}
