/*
 * Copyright (c) 2022, Google Inc. All rights reserved
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

/* Tests for ARM64 FEAT_BTI (Branch Target Identification)
 *  This is a mandatory CPU feature at ARM-A v8.5.  Prior to that level, the
 *  BTI instructions are treated as NOPs and there is no enforcement.
 *  The test here will check either case, based on build configuration and
 *  runtime target support.
 * Since this is an ARM64 feature, this should not be built for other arches.
 */
#ifndef ARCH_ARM64
#error BTI is an ARM64 feature
#endif

#include <arch/ops.h>
#include <err.h>
#include <lib/unittest/unittest.h>
#include <lk/init.h>
#include <stdio.h>

/* Assembly indirect call functions, using all BTI-relevant calls.
 *  BR via x16 and x17 is often used by linkers for veneers and has some
 *  additional handling described in the ARM Architecture Reference Manual,
 *  Table D8-36 (IYWFHD).
 */
int btitest_blr(int (*func)(void));
int btitest_br_x16(int (*func)(void));
int btitest_br_x17(int (*func)(void));
int btitest_br(int (*func)(void));

/* Assembly callee functions, return 0 on success or ERR_FAULT.
 *  These use different branch targets to cover cases in the ARM Architecture
 *  Reference Manual, Table D8-37 (ICNBPL).
 */
int btitest_callee_nop(void);
int btitest_callee_bti(void);
int btitest_callee_bti_c(void);
int btitest_callee_bti_j(void);
int btitest_callee_bti_jc(void);

/* Get the expected return code when a BTI access should be trapped */
static int bti_trap_code(void) {
#ifdef KERNEL_BTI_ENABLED
    if (arch_bti_supported()) {
        return ERR_FAULT;
    }
#endif
    /* No BTI, or not enabled - faults are not detected */
    return 0;
}

TEST(btitest, supported) {
    EXPECT_EQ(true, arch_bti_supported());
}

/* Smoke-test the callee functions; they should return 0 when called with BL */
TEST(btitest, smoke) {
    EXPECT_EQ(0, btitest_callee_nop());
    EXPECT_EQ(0, btitest_callee_bti());
    EXPECT_EQ(0, btitest_callee_bti_c());
    EXPECT_EQ(0, btitest_callee_bti_j());
    EXPECT_EQ(0, btitest_callee_bti_jc());
}

TEST(btitest, nop) {
    /* Fault on jump or call to non-bti target */
    EXPECT_EQ(bti_trap_code(), btitest_br(btitest_callee_nop));
    EXPECT_EQ(bti_trap_code(), btitest_blr(btitest_callee_nop));
    EXPECT_EQ(bti_trap_code(), btitest_br_x16(btitest_callee_nop));
    EXPECT_EQ(bti_trap_code(), btitest_br_x17(btitest_callee_nop));
}

TEST(btitest, bti) {
    /* Fault on any jump or call to non-target bti */
    EXPECT_EQ(bti_trap_code(), btitest_br(btitest_callee_bti));
    EXPECT_EQ(bti_trap_code(), btitest_blr(btitest_callee_bti));
    EXPECT_EQ(bti_trap_code(), btitest_br_x16(btitest_callee_bti));
    EXPECT_EQ(bti_trap_code(), btitest_br_x17(btitest_callee_bti));
}

TEST(btitest, bti_c) {
    /* Call or branch via x16/17 to a call target is valid */
    EXPECT_EQ(0, btitest_blr(btitest_callee_bti_c));
    EXPECT_EQ(0, btitest_br_x16(btitest_callee_bti_c));
    EXPECT_EQ(0, btitest_br_x17(btitest_callee_bti_c));

    /* Fault on branch to call target */
    EXPECT_EQ(bti_trap_code(), btitest_br(btitest_callee_bti_c));
}

TEST(btitest, bti_j) {
    /* Any branch to jump target is valid */
    EXPECT_EQ(0, btitest_br(btitest_callee_bti_j));
    EXPECT_EQ(0, btitest_br_x16(btitest_callee_bti_j));
    EXPECT_EQ(0, btitest_br_x17(btitest_callee_bti_j));

    /* Fault on call to jump target */
    EXPECT_EQ(bti_trap_code(), btitest_blr(btitest_callee_bti_j));
}

TEST(btitest, bti_jc) {
    /* Either branch type allowed to call and jump target */
    EXPECT_EQ(0, btitest_br(btitest_callee_bti_jc));
    EXPECT_EQ(0, btitest_br_x16(btitest_callee_bti_c));
    EXPECT_EQ(0, btitest_br_x17(btitest_callee_bti_c));
    EXPECT_EQ(0, btitest_blr(btitest_callee_bti_jc));
}

PORT_TEST(btitest, "com.android.kernel.btitest");
