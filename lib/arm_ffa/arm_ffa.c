/*
 * Copyright (c) 2019-2020 LK Trusty Authors. All Rights Reserved.
 * Copyright (c) 2022, Arm Limited. All rights reserved.
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
#include <interface/arm_ffa/arm_ffa.h>
#include <inttypes.h>
#include <lib/arm_ffa/arm_ffa.h>
#include <lib/smc/smc.h>
#include <lk/init.h>
#include <sys/types.h>
#include <trace.h>

static bool arm_ffa_init_is_success = false;

bool arm_ffa_is_init(void) {
    return arm_ffa_init_is_success;
}

static status_t arm_ffa_call_version(uint16_t major,
                                     uint16_t minor,
                                     uint16_t* major_ret,
                                     uint16_t* minor_ret) {
    struct smc_ret8 smc_ret;

    smc_ret = smc8(SMC_FC_FFA_VERSION, FFA_VERSION(major, minor), 0, 0, 0, 0, 0,
                   0);
    if (smc_ret.r0 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
        return ERR_NOT_SUPPORTED;
    }
    *major_ret = FFA_VERSION_TO_MAJOR(smc_ret.r0);
    *minor_ret = FFA_VERSION_TO_MINOR(smc_ret.r0);

    return NO_ERROR;
}

static status_t arm_ffa_setup(void) {
    status_t res;
    uint16_t ver_major_ret;
    uint16_t ver_minor_ret;

    res = arm_ffa_call_version(FFA_CURRENT_VERSION_MAJOR,
                               FFA_CURRENT_VERSION_MINOR, &ver_major_ret,
                               &ver_minor_ret);
    if (res != NO_ERROR) {
        TRACEF("No compatible FF-A version found\n");
        return res;
    } else if (FFA_CURRENT_VERSION_MAJOR != ver_major_ret ||
               FFA_CURRENT_VERSION_MINOR > ver_minor_ret) {
        /* When trusty supports more FF-A versions downgrade may be possible */
        TRACEF("Incompatible FF-A interface version, %" PRIu16 ".%" PRIu16 "\n",
               ver_major_ret, ver_minor_ret);
        return ERR_NOT_SUPPORTED;
    }
    return res;
}

static void arm_ffa_init(uint level) {
    status_t res;

    res = arm_ffa_setup();

    if (res == NO_ERROR) {
        arm_ffa_init_is_success = true;
    } else {
        TRACEF("Failed to initialize FF-A (err=%d)\n", res);
    }
}

LK_INIT_HOOK(arm_ffa_init, arm_ffa_init, LK_INIT_LEVEL_PLATFORM - 2);
