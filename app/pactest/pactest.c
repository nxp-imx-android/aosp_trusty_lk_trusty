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

/*
 * Tests for ARM64 FEAT_Puth (Pointer Authentication Codes)
 * This is a CPU feature at ARM-A v8.3
 * Since this is an ARM64 feature, this should not be built for other arches.
 */
#ifndef ARCH_ARM64
#error PAC is an ARM64 feature
#endif

#include "pactest.h"
#include <arch/arm64/sregs.h>
#include <arch/ops.h>
#include <err.h>
#include <lib/unittest/unittest.h>
#include <lk/init.h>
#include <platform/random.h>
#include <stdio.h>

#define PACTEST_ADDRESS 0x1234567890abcdefu
#define PACTEST_MODIFIER 0xfedcba0987654321u

static uint8_t get_nibble(uint64_t reg, uint8_t shift) {
    return (reg >> shift) & 0xf;
}

static const char* get_pac_features(uint8_t nibble) {
    switch (nibble) {
    case 0b0001:
        return "PAuth";
    case 0b0010:
        return "PAuth + EPAC";
    case 0b0011:
        return "PAuth + PAuth2";
    case 0b0100:
        return "Pauth + Pauth2 + FPAC";
    case 0b0101:
        return "Pauth + Pauth2 + FPAC + FPACCOMBINE";
    }

    return "<unknown>";
}

TEST(pactest, pauth_supported) {
    if (!arch_pac_address_supported()) {
        trusty_unittest_printf("[  SKIPPED ] PAuth is not supported\n");
        return;
    }

    const uint64_t isar1 = ARM64_READ_SYSREG(id_aa64isar1_el1);
    const uint64_t isar2 = ARM64_READ_SYSREG(id_aa64isar2_el1);
    const uint8_t pacfrac = get_nibble(isar2, ID_AA64ISAR2_EL1_PAC_FRAC_SHIFT);
    const uint8_t apa3 = get_nibble(isar2, ID_AA64ISAR2_EL1_APA3_SHIFT);
    const uint8_t apa = get_nibble(isar1, ID_AA64ISAR1_EL1_APA_SHIFT);
    const uint8_t api = get_nibble(isar1, ID_AA64ISAR1_EL1_API_SHIFT);
    const char *algo = "none", *features = "", *cpf = "";

    if (apa3) {
        algo = "QARMA3";
        features = get_pac_features(apa3);
        EXPECT_EQ(apa, 0);
        EXPECT_EQ(api, 0);
    } else if (apa) {
        algo = "QARMA5";
        features = get_pac_features(apa);
        EXPECT_EQ(api, 0);
    } else if (api) {
        algo = "implementation defined";
        features = get_pac_features(api);
    }

    if (pacfrac == 1) {
        cpf = ", CONSTPACFIELD";
    } else {
        EXPECT_EQ(pacfrac, 0);
    }

    /* Log the support in case later trying to debug a test */
    trusty_unittest_printf("[   INFO   ] algo: %s\n", algo);
    trusty_unittest_printf("[   INFO   ] feat: %s%s\n", features, cpf);
}

TEST(pactest, fpac_supported) {
    uint64_t val;
    int rc;

    if (!arch_pac_exception_supported()) {
        trusty_unittest_printf("[  SKIPPED ] FPAC is not supported\n");
        return;
    }

    rc = pactest_autia(PACTEST_ADDRESS, PACTEST_MODIFIER, &val);
    EXPECT_EQ(rc, ERR_FAULT);
}

TEST(pactest, enabled) {
    const uint64_t sctlr_el1 = ARM64_READ_SYSREG(SCTLR_EL1);

    /* Check the expected keys are enabled */
    EXPECT_EQ(sctlr_el1 & SCTLR_EL1_ENIA,
              arch_pac_address_supported() ? SCTLR_EL1_ENIA : 0);
    EXPECT_EQ(sctlr_el1 & SCTLR_EL1_ENIB, 0);
    EXPECT_EQ(sctlr_el1 & SCTLR_EL1_ENDA, 0);
    EXPECT_EQ(sctlr_el1 & SCTLR_EL1_ENDB, 0);
}

TEST(pactest, instr_pacautia) {
    const uint64_t sctlr_el1 = ARM64_READ_SYSREG(SCTLR_EL1);
    uint64_t address = PACTEST_ADDRESS;
    int rc;

    if (arch_pac_address_supported() && (sctlr_el1 & SCTLR_EL1_ENIA) != 0) {
        /* Test PACIA adds a PAC */
        __asm__(".arch_extension pauth\n"
                "\tPACIA %0, %1"
                : "+r"(address)
                : "r"(PACTEST_MODIFIER));
        EXPECT_NE(PACTEST_ADDRESS, address);

        uint64_t pac_address = address;

        /* Check AUTIA returns the original pointer */
        rc = pactest_autia(address, PACTEST_MODIFIER, &address);
        EXPECT_EQ(rc, 0)
        EXPECT_EQ(PACTEST_ADDRESS, address);

        /* Check the pointer is invalidated  if the modifier is changed */
        rc = pactest_autia(pac_address, ~PACTEST_MODIFIER, &address);
        if (arch_pac_exception_supported()) {
            EXPECT_EQ(rc, ERR_FAULT);
        } else {
            /* Address should have been invalidated */
            EXPECT_EQ(rc, 0);
            EXPECT_NE(address, PACTEST_ADDRESS);
        }

    } else {
        /* Test PACIA does nothing */
        __asm__(".arch_extension pauth\n"
                "\tPACIA %0, %1"
                : "+r"(address)
                : "r"(PACTEST_MODIFIER));
        EXPECT_EQ(address, PACTEST_ADDRESS);

        /* Check AUTIA does nothing */
        rc = pactest_autia(address, PACTEST_MODIFIER, &address);
        EXPECT_EQ(rc, 0)
        EXPECT_EQ(address, PACTEST_ADDRESS);
    }
}

/* This is exactly the same as the pacautia test, but for the b key */

TEST(pactest, instr_pacautib) {
    const uint64_t sctlr_el1 = ARM64_READ_SYSREG(SCTLR_EL1);
    uint64_t address = PACTEST_ADDRESS;
    int rc;

    if (arch_pac_address_supported() && (sctlr_el1 & SCTLR_EL1_ENIB) != 0) {
        /* Test PACIB adds a PAC */
        __asm__(".arch_extension pauth\n"
                "\tPACIB %0, %1"
                : "+r"(address)
                : "r"(PACTEST_MODIFIER));
        EXPECT_NE(PACTEST_ADDRESS, address);

        uint64_t pac_address = address;

        /* Check AUTIB returns the original pointer */
        rc = pactest_autib(address, PACTEST_MODIFIER, &address);
        EXPECT_EQ(rc, 0)
        EXPECT_EQ(PACTEST_ADDRESS, address);

        /* Check the pointer is invalidated  if the modifier is changed */
        rc = pactest_autib(pac_address, ~PACTEST_MODIFIER, &address);
        if (arch_pac_exception_supported()) {
            EXPECT_EQ(rc, ERR_FAULT);
        } else {
            /* Address should have been invalidated */
            EXPECT_EQ(rc, 0);
            EXPECT_NE(address, PACTEST_ADDRESS);
        }

    } else {
        /* Test PACIB does nothing */
        __asm__(".arch_extension pauth\n"
                "\tPACIB %0, %1"
                : "+r"(address)
                : "r"(PACTEST_MODIFIER));
        EXPECT_EQ(address, PACTEST_ADDRESS);

        /* Check AUTIB does nothing */
        rc = pactest_autib(address, PACTEST_MODIFIER, &address);
        EXPECT_EQ(rc, 0)
        EXPECT_EQ(address, PACTEST_ADDRESS);
    }
}

typedef struct {
    bool translation_table;
    bool address_not_data;
} pactest_t;

static void get_params(pactest_t* p) {
    const bool* const* params = GetParam();
    p->translation_table = *params[0];
    p->address_not_data = *params[1];
}

TEST_F_SETUP(pactest) {
    get_params(_state);
}

TEST_F_TEARDOWN(pactest) {}

static void user_param_to_string(const void* param,
                                 char* buf,
                                 size_t buf_size) {
    pactest_t p;
    get_params(&p);

    snprintf(buf, buf_size, "TT%u/%s", p.translation_table ? 1 : 0,
             p.address_not_data ? "PACA" : "PACD");
}

INSTANTIATE_TEST_SUITE_P(pac_length,
                         pactest,
                         testing_Combine(testing_Bool(), testing_Bool()),
                         user_param_to_string);

TEST_P(pactest, pac_length) {
    if (!arch_pac_address_supported()) {
        trusty_unittest_printf("[  SKIPPED ] PAuth is not supported\n");
        return;
    }

    uint8_t top = 0, bot = 64;
    const uint64_t sctlr_el1 = ARM64_READ_SYSREG(SCTLR_EL1);

    /* Enable all keys */
    ARM64_WRITE_SYSREG(SCTLR_EL1, sctlr_el1 | SCTLR_EL1_ENIA | SCTLR_EL1_ENIB |
                                          SCTLR_EL1_ENDA | SCTLR_EL1_ENDB);

    /*
     * Probe a number of times in order to ensure we find the top and bottom
     * bits used.  Odds of missing correct bounds are about P=(1/2)^32.
     */
    for (uint16_t t = 0; t < 32; t++) {
        uint64_t val, orig;

        /* Get 64-bit random value */
        platform_random_get_bytes((void*)&orig, sizeof(orig));

        /*
         * Select which of T0SZ or T1SZ we should probe.
         * Address bit 55 is used to select between page translation tables
         * to use (e.g. TTBRx and TxSZ, where x is 0 or 1).
         */
        val = orig & ~(1ull << 55);
        if (_state->translation_table) {
            val |= 1ull << 55;
        }

        /* Select instruction type */
        if (_state->address_not_data) {
            __asm__(".arch_extension pauth\n"
                    "\tPACIZA %0"
                    : "+r"(val));
        } else {
            __asm__(".arch_extension pauth\n"
                    "\tPACDZA %0"
                    : "+r"(val));
        }

        /* Remove un-changed bits and clear bit 55 */
        val ^= orig;
        val &= ~(1ull << 55);

        /* Find highest and lowest set bit positions */
        if (val) {
            top = MAX(top, 63 - __builtin_clzll(val));
            bot = MIN(bot, __builtin_ctzll(val));
        }
    }

    /* If this is not true, the PAC key not be functioning */
    ASSERT_GT(top, bot);

    /* Count bit range, except bit 55 if it is in the range */
    int bits = (top + 1) - bot;
    if (bot < 55 && top > 55) {
        bits--;
    }

    trusty_unittest_printf("[   INFO   ] PAC bits %" PRIu8 ":%" PRIu8
                           " = %d effective bits\n",
                           top, bot, bits);

test_abort:
    /* Restore enabled keys */
    ARM64_WRITE_SYSREG(SCTLR_EL1, sctlr_el1);
}

PORT_TEST(pactest, "com.android.kernel.pactest");
