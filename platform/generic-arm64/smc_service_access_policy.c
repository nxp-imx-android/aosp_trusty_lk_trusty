/*
 * Copyright (c) 2019 Google Inc. All rights reserved
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

#include <err.h>
#include <services/smc/acl.h>
#include <stdbool.h>
#include <string.h>
#include <uapi/trusty_uuid.h>

/* SMC test UUID : {3c321776-548e-4978-b676-843cbf1073e5} */
static struct uuid smc_test_uuid = {
        0x3c321776,
        0x548e,
        0x4978,
        {0xb6, 0x76, 0x84, 0x3c, 0xbf, 0x10, 0x73, 0xe5},
};

static bool equal_uuid(const struct uuid* a, const struct uuid* b) {
    return memcmp(a, b, sizeof(struct uuid)) == 0;
}

static int smc_test_access_policy(uint32_t smc_nr) {
    /* SMC test has access to all SMCs. */
    return NO_ERROR;
}

static int default_access_policy(uint32_t smc_nr) {
    return ERR_ACCESS_DENIED;
}

void smc_load_access_policy(const struct uuid* uuid,
                            struct smc_access_policy* policy) {
    /* On QEMU builds, only SMC test can have access to SMC service. */
    if (equal_uuid(uuid, &smc_test_uuid)) {
        policy->check_access = smc_test_access_policy;
        return;
    }
    policy->check_access = default_access_policy;
}
