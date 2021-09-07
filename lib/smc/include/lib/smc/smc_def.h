/*
 * Copyright (c) 2013-2016 Google Inc. All rights reserved
 * Copyright (c) 2022, Arm Ltd.  All rights reserved
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

#pragma once

#define SMC_IS_FASTCALL(smc_nr) ((smc_nr)&0x80000000)
#define SMC_IS_SMC64(smc_nr) ((smc_nr)&0x40000000)
#define SMC_ENTITY(smc_nr) (((smc_nr)&0x3F000000) >> 24)
#define SMC_FUNCTION(smc_nr) ((smc_nr)&0x0000FFFF)

#define SMC_NR(entity, fn, fastcall, smc64)               \
    ((((fastcall)&0x1U) << 31) | (((smc64)&0x1U) << 30) | \
     (((entity)&0x3FU) << 24) | ((fn)&0xFFFFU))

#define SMC_FASTCALL_NR(entity, fn) SMC_NR((entity), (fn), 1, 0)
#define SMC_STDCALL_NR(entity, fn) SMC_NR((entity), (fn), 0, 0)
#define SMC_FASTCALL64_NR(entity, fn) SMC_NR((entity), (fn), 1, 1)
#define SMC_STDCALL64_NR(entity, fn) SMC_NR((entity), (fn), 0, 1)

/* ARM Architecture calls */
#define SMC_ENTITY_ARCH 0
/* CPU Service calls */
#define SMC_ENTITY_CPU 1
/* SIP Service calls */
#define SMC_ENTITY_SIP 2
/* OEM Service calls */
#define SMC_ENTITY_OEM 3
/* Standard Service calls */
#define SMC_ENTITY_STD 4
/* Reserved for future use */
#define SMC_ENTITY_RESERVED 5
/* Trusted Application calls */
#define SMC_ENTITY_TRUSTED_APP 48
/* Trusted OS calls */
#define SMC_ENTITY_TRUSTED_OS 50
/* Used for secure -> nonsecure logging */
#define SMC_ENTITY_LOGGING 51
/* Used for secure -> nonsecure tests */
#define SMC_ENTITY_TEST 52
/* Trusted OS calls internal to secure monitor */
#define SMC_ENTITY_SECURE_MONITOR 60

#define SMC_NUM_ENTITIES 64
