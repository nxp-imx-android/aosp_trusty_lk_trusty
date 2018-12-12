/*
 * Copyright (c) 2015, Google Inc. All rights reserved
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

#include <assert.h>
#include <err.h>
#include <kernel/usercopy.h>
#include <lib/unittest/unittest.h>
#include <lk/init.h>
#include <stdio.h>
#include <string.h>

static const struct {
    user_addr_t addr;
    enum {
        NO_PAGE = 0,
        USER_RW = ARCH_MMU_FLAG_PERM_USER,
        USER_RO = ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_RO,
    } arch_mmu_flags;
    enum {
        TEST_NONE = 0,
        TEST_OVERLAP_WITH_PREV = 1U << 0,
        TEST_NO_OVERLAP = 1U << 1,
        TEST_BOTH = TEST_OVERLAP_WITH_PREV | TEST_NO_OVERLAP,
    } test_with;
} user_bufs[] = {
        {PAGE_SIZE * 0x10, NO_PAGE, TEST_NO_OVERLAP},
        {PAGE_SIZE * 0x11, USER_RO, TEST_BOTH},
        {PAGE_SIZE * 0x12, NO_PAGE, TEST_OVERLAP_WITH_PREV},
        {PAGE_SIZE * 0x13, USER_RW, TEST_BOTH},
        {PAGE_SIZE * 0x14, NO_PAGE, TEST_OVERLAP_WITH_PREV},
        {PAGE_SIZE * 0x15, USER_RO, TEST_NONE},
        {PAGE_SIZE * 0x16, USER_RW, TEST_OVERLAP_WITH_PREV},
        {PAGE_SIZE * 0x17, NO_PAGE, TEST_NONE},
        {PAGE_SIZE * 0x18, USER_RW, TEST_NONE},
        {PAGE_SIZE * 0x19, USER_RO, TEST_OVERLAP_WITH_PREV},
        {PAGE_SIZE * 0x1a, NO_PAGE, TEST_NONE},
};

#define TEST_BUF_SIZE (16)
#define TEST_BUF1_SIZE (TEST_BUF_SIZE / 2)
#define TEST_BUF2_SIZE (TEST_BUF_SIZE - TEST_BUF1_SIZE)
#define TEST_BUF_COPY_START (1)
#define TEST_BUF_COPY_SIZE (TEST_BUF_SIZE - TEST_BUF_COPY_START - 1)
#define TEST_BUF1_COPY_SIZE (TEST_BUF1_SIZE - TEST_BUF_COPY_START)
#define TEST_BUF2_COPY_SIZE (TEST_BUF_COPY_SIZE - TEST_BUF1_COPY_SIZE)
#define TEST_BUF_COPY_LAST (TEST_BUF_SIZE - 1 - 1)
#define TEST_BUF2_COPY_LAST (TEST_BUF_COPY_LAST - TEST_BUF1_SIZE)

#define SRC_DATA (0x22)
#define DEST_DATA (0x11)

static int checkbuf(const char* buf, char c, size_t size) {
    int error_count = 0;
    for (size_t i = 0; i < size; i++) {
        if (buf[i] != c) {
            error_count++;
        }
    }
    return error_count;
}

static void usercopy_test_init_buf(char* kbuf1,
                                   char* kbuf2,
                                   uint8_t val,
                                   int null_offset) {
    if (kbuf1) {
        memset(kbuf1, val, TEST_BUF1_SIZE);
        if (null_offset >= 0 && null_offset < TEST_BUF1_SIZE) {
            kbuf1[null_offset] = '\0';
        }
    }
    if (kbuf2) {
        memset(kbuf2, val, TEST_BUF2_SIZE);
        if (null_offset >= TEST_BUF1_SIZE && null_offset < TEST_BUF_SIZE) {
            kbuf2[null_offset - TEST_BUF1_SIZE] = '\0';
        }
    }
}

typedef void (*user_copy_test_func_t)(user_addr_t addr,
                                      uint arch_mmu_flags_start,
                                      uint arch_mmu_flags_end);

static void usercopy_test_copy_to_user(user_addr_t addr,
                                       uint arch_mmu_flags_start,
                                       uint arch_mmu_flags_end) {
    int ret;
    char src_buf[TEST_BUF_SIZE];
    char* dest_kbuf1;
    char* dest_kbuf2;
    char expect1;
    char expect2;

    dest_kbuf1 = paddr_to_kvaddr(vaddr_to_paddr((void*)(uintptr_t)addr));
    dest_kbuf2 = paddr_to_kvaddr(
            vaddr_to_paddr((void*)(uintptr_t)addr + TEST_BUF1_SIZE));

    /* dest_kbuf1 or dest_kbuf2 should only be NULL if page is unmapped */
    ASSERT(dest_kbuf1 || arch_mmu_flags_start == 0);
    ASSERT(dest_kbuf2 || arch_mmu_flags_end == 0);

    usercopy_test_init_buf(dest_kbuf1, dest_kbuf2, DEST_DATA, -1);
    memset(src_buf, SRC_DATA, sizeof(src_buf));

    /* Zero-length copy should always succeed */
    ret = copy_to_user(addr + TEST_BUF_COPY_START, NULL, 0);
    EXPECT_EQ(0, ret);

    /* Dest buffer should be untouched after zero-length copy */
    if (dest_kbuf1) {
        EXPECT_EQ(0, checkbuf(dest_kbuf1, DEST_DATA, TEST_BUF1_SIZE));
    }
    if (dest_kbuf2) {
        EXPECT_EQ(0, checkbuf(dest_kbuf2, DEST_DATA, TEST_BUF2_SIZE));
    }

    /* Perform non-zero length copy */
    ret = copy_to_user(addr + TEST_BUF_COPY_START,
                       src_buf + TEST_BUF_COPY_START, TEST_BUF_COPY_SIZE);

    /*
     * If both pages are writeable copy_to_user should succeed otherwise it
     * should return ERR_FAULT.
     */
    if (arch_mmu_flags_start == ARCH_MMU_FLAG_PERM_USER &&
        arch_mmu_flags_end == ARCH_MMU_FLAG_PERM_USER) {
        /*
         * If both pages are writeable from user-space copy_to_user should
         * return success and every byte should be copied to dest_buf.
         */
        EXPECT_EQ(0, ret);
        expect1 = SRC_DATA;
        expect2 = SRC_DATA;
    } else {
        /*
         * If one of the pages is not writeable from user-space copy_to_user
         * should return ERR_FAULT. If only the first page is writeable everying
         * should be copied in the first page or nothing should be copied in the
         * first page. If the first page is not writeable, nothing should be
         * copied to either page. If the second page is not writeable, no data
         * should be copied to it, even if the first page was written to.
         */
        EXPECT_EQ(ERR_FAULT, ret);
        if (arch_mmu_flags_start == ARCH_MMU_FLAG_PERM_USER &&
            dest_kbuf1[TEST_BUF_COPY_START] == SRC_DATA) {
            expect1 = SRC_DATA;
        } else {
            expect1 = DEST_DATA;
        }
        expect2 = DEST_DATA;
    }

    /* copy_to_user should not modify src_buf at all */
    EXPECT_EQ(0, checkbuf(src_buf, SRC_DATA, TEST_BUF_SIZE));

    if (dest_kbuf1) {
        /* Dest byte before copied region should be untouched */
        EXPECT_EQ(DEST_DATA, dest_kbuf1[0]);

        /* Check that copied region match expected value we selected above */
        EXPECT_EQ(0, checkbuf(dest_kbuf1 + TEST_BUF_COPY_START, expect1,
                              TEST_BUF1_COPY_SIZE));
    }

    if (dest_kbuf2) {
        /* Check that copied region match expected value we selected above */
        EXPECT_EQ(0, checkbuf(dest_kbuf2, expect2, TEST_BUF2_COPY_SIZE));

        /* Dest byte after copied region should be untouched */
        EXPECT_EQ(DEST_DATA, dest_kbuf2[TEST_BUF2_SIZE - 1]);
    }
}

static void usercopy_test_copy_from_user(user_addr_t addr,
                                         uint arch_mmu_flags_start,
                                         uint arch_mmu_flags_end) {
    int ret;
    char dest_buf[TEST_BUF_SIZE];
    char* src_kbuf1;
    char* src_kbuf2;
    char expect1;
    char expect2;

    memset(dest_buf, DEST_DATA, sizeof(dest_buf));
    src_kbuf1 = paddr_to_kvaddr(vaddr_to_paddr((void*)(uintptr_t)addr));
    src_kbuf2 = paddr_to_kvaddr(
            vaddr_to_paddr((void*)(uintptr_t)addr + TEST_BUF1_SIZE));

    /* src_kbuf1 or src_kbuf2 should only be NULL if page is unmapped */
    ASSERT(src_kbuf1 || arch_mmu_flags_start == 0);
    ASSERT(src_kbuf2 || arch_mmu_flags_end == 0);

    usercopy_test_init_buf(src_kbuf1, src_kbuf2, SRC_DATA, -1);

    /* Zero-length copy should always succeed */
    ret = copy_from_user(NULL, addr + TEST_BUF_COPY_START, 0);
    EXPECT_EQ(0, ret);

    /* Dest buffer should be untouched after zero-length copy */
    EXPECT_EQ(0, checkbuf(dest_buf, DEST_DATA, TEST_BUF_SIZE));

    /* Perform non-zero length copy */
    ret = copy_from_user(dest_buf + TEST_BUF_COPY_START,
                         addr + TEST_BUF_COPY_START, TEST_BUF_COPY_SIZE);
    if (arch_mmu_flags_start & arch_mmu_flags_end & ARCH_MMU_FLAG_PERM_USER) {
        /*
         * If both pages are readable from user-space copy_from_user should
         * return success and every byte should be copied to dest_buf.
         */
        EXPECT_EQ(0, ret);
        expect1 = SRC_DATA;
        expect2 = SRC_DATA;
    } else {
        /*
         * If one of the pages is not readable from user-space copy_from_user
         * should return ERR_FAULT, and the parts of dest_buf that could not be
         * copied into should be set to 0.
         * Kernel buffer should always be written so potentially uninitialized
         * kernel data does not leak.
         */
        EXPECT_EQ(ERR_FAULT, ret);
        if (!(arch_mmu_flags_start & ARCH_MMU_FLAG_PERM_USER) ||
            !dest_buf[TEST_BUF_COPY_START]) {
            expect1 = 0;
        } else {
            expect1 = SRC_DATA;
        }
        expect2 = 0;
    }

    EXPECT_EQ(0, checkbuf(dest_buf + TEST_BUF_COPY_START, expect1,
                          TEST_BUF1_COPY_SIZE));
    EXPECT_EQ(0, checkbuf(dest_buf + TEST_BUF1_SIZE, expect2,
                          TEST_BUF2_COPY_SIZE));

    /* Dest bytes before and after copied region should be untouched */
    EXPECT_EQ(DEST_DATA, dest_buf[0]);
    EXPECT_EQ(DEST_DATA, dest_buf[TEST_BUF_SIZE - 1]);

    /* Src buffer should not be modified */
    if (src_kbuf1) {
        EXPECT_EQ(0, checkbuf(src_kbuf1, SRC_DATA, TEST_BUF1_SIZE));
    }
    if (src_kbuf2) {
        EXPECT_EQ(0, checkbuf(src_kbuf2, SRC_DATA, TEST_BUF2_SIZE));
    }
}

static void usercopy_test_strlcpy_from_user_inner(user_addr_t addr,
                                                  uint arch_mmu_flags_start,
                                                  uint arch_mmu_flags_end,
                                                  int copy_size,
                                                  int null_off) {
    int ret;
    char dest_buf[TEST_BUF_SIZE];
    char* src_kbuf1;
    char* src_kbuf2;
    size_t dest_len;

    memset(dest_buf, DEST_DATA, sizeof(dest_buf));
    src_kbuf1 = paddr_to_kvaddr(vaddr_to_paddr((void*)(uintptr_t)addr));
    src_kbuf2 = paddr_to_kvaddr(
            vaddr_to_paddr((void*)(uintptr_t)addr + TEST_BUF1_SIZE));

    /* src_kbuf1 or src_kbuf2 should only be NULL if page is unmapped */
    ASSERT(src_kbuf1 || arch_mmu_flags_start == 0);
    ASSERT(src_kbuf2 || arch_mmu_flags_end == 0);

    usercopy_test_init_buf(src_kbuf1, src_kbuf2, SRC_DATA, null_off);

    ret = strlcpy_from_user(dest_buf + TEST_BUF_COPY_START,
                            addr + TEST_BUF_COPY_START, copy_size);

    dest_len = strnlen(dest_buf + TEST_BUF_COPY_START, TEST_BUF_COPY_SIZE);
    /*
     * Kernel buffer should always be null terminated.
     */
    EXPECT_NE(TEST_BUF_COPY_SIZE, dest_len, "  null_off=%d, copy_size=%d\n",
              null_off, copy_size);

    /*
     * If the string in dest_buf is not empty it should only contain data from
     * the source string.
     */
    EXPECT_EQ(0, checkbuf(dest_buf + TEST_BUF_COPY_START, SRC_DATA, dest_len),
              "  null_off=%d, copy_size=%d\n", null_off, copy_size);

    if ((arch_mmu_flags_start & ARCH_MMU_FLAG_PERM_USER) &&
        ((arch_mmu_flags_end & ARCH_MMU_FLAG_PERM_USER) ||
         null_off < TEST_BUF1_SIZE)) {
        /*
         * If the pages readable from user-space contain a 0 terminated string,
         * strlcpy_from_user should return the length of that string and every
         * byte up to the 0 terminator that fits in dest_buf should be copied
         * there. dest_buf should always be 0 terminated.
         */
        EXPECT_EQ(null_off - TEST_BUF_COPY_START, ret,
                  "  wrong strlen returned, null_off=%d, copy_size=%d\n",
                  null_off, copy_size);
        EXPECT_EQ(MIN(null_off - TEST_BUF_COPY_START, copy_size - 1), dest_len,
                  "  null_off=%d, copy_size=%d\n", null_off, copy_size);
    } else {
        /*
         * If one of the pages is not readable from user-space strlcpy_from_user
         * should return ERR_FAULT, and dest_buf should have a null terminator
         * at the start of the faulting page or at the start of the string.
         */
        EXPECT_EQ(ERR_FAULT, ret, "  null_off=%d, copy_size=%d\n", null_off,
                  copy_size);
        if (!(arch_mmu_flags_start & ARCH_MMU_FLAG_PERM_USER)) {
            EXPECT_EQ(0, dest_len, "  null_off=%d, copy_size=%d\n", null_off,
                      copy_size);
        } else if (dest_len) {
            EXPECT_EQ(MIN(TEST_BUF1_COPY_SIZE, copy_size - 1), dest_len,
                      "  null_off=%d, copy_size=%d\n", null_off, copy_size);
        }
    }

    /* Src buffer should not be modified */
    if (src_kbuf1) {
        if (null_off < TEST_BUF1_SIZE) {
            EXPECT_EQ(0, checkbuf(src_kbuf1, SRC_DATA, null_off));
            EXPECT_EQ('\0', src_kbuf1[null_off]);
            EXPECT_EQ(0, checkbuf(src_kbuf1 + null_off + 1, SRC_DATA,
                                  TEST_BUF1_SIZE - null_off - 1));
        } else {
            EXPECT_EQ(0, checkbuf(src_kbuf1, SRC_DATA, TEST_BUF1_SIZE));
        }
    }
    if (src_kbuf2) {
        if (null_off >= TEST_BUF1_SIZE) {
            size_t null_off2 = null_off - TEST_BUF1_SIZE;
            EXPECT_EQ(0, checkbuf(src_kbuf2, SRC_DATA, null_off2));
            EXPECT_EQ('\0', src_kbuf2[null_off2]);
            EXPECT_EQ(0, checkbuf(src_kbuf2 + null_off2 + 1, SRC_DATA,
                                  TEST_BUF2_SIZE - null_off2 - 1));
        } else {
            EXPECT_EQ(0, checkbuf(src_kbuf2, SRC_DATA, TEST_BUF2_SIZE));
        }
    }

    /* Dest bytes before and after copied region should be untouched */
    EXPECT_EQ(DEST_DATA, dest_buf[0]);
    EXPECT_EQ(DEST_DATA, dest_buf[TEST_BUF_SIZE - 1]);
}

static void usercopy_test_strlcpy_from_user(user_addr_t addr,
                                            uint arch_mmu_flags_start,
                                            uint arch_mmu_flags_end) {
    size_t copy_sizes[] = {TEST_BUF1_COPY_SIZE, TEST_BUF_COPY_SIZE};
    size_t copy_sizes_index;
    int null_off;
    int copy_size;

    for (copy_sizes_index = 0; copy_sizes_index < countof(copy_sizes);
         copy_sizes_index++) {
        copy_size = copy_sizes[copy_sizes_index];
        for (null_off = TEST_BUF_COPY_START; null_off < TEST_BUF_SIZE;
             null_off++) {
            usercopy_test_strlcpy_from_user_inner(addr, arch_mmu_flags_start,
                                                  arch_mmu_flags_end, copy_size,
                                                  null_off);
        }
    }
}

static const char* usercopy_arch_mmu_flags_str(uint arch_mmu_flags) {
    switch (arch_mmu_flags) {
    case 0:
        return "--";
    case ARCH_MMU_FLAG_PERM_USER:
        return "rw";
    case ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_RO:
        return "ro";
    default:
        return "??";
    }
}

static void usercopy_test_addr(user_copy_test_func_t func,
                               user_addr_t addr,
                               uint arch_mmu_flags_start,
                               uint arch_mmu_flags_end) {
    if (!is_kernel_address(addr)) {
        unittest_printf("addr 0x%" PRIxPTR_USER " %s%s:\n", addr,
                        usercopy_arch_mmu_flags_str(arch_mmu_flags_start),
                        usercopy_arch_mmu_flags_str(arch_mmu_flags_end));
    }
    func(addr, arch_mmu_flags_start, arch_mmu_flags_end);
}

static void usercopy_test(user_copy_test_func_t func) {
    uint8_t test_buf_kstack[TEST_BUF_SIZE];

    unittest_printf("addr kernel stack:\n");
    usercopy_test_addr(func, (user_addr_t)(uintptr_t)test_buf_kstack, 0, 0);

    for (size_t i = 0; i < countof(user_bufs); i++) {
        if (user_bufs[i].test_with & TEST_OVERLAP_WITH_PREV) {
            EXPECT_NE(0, i);
            if (i) {
                usercopy_test_addr(func, user_bufs[i].addr - TEST_BUF1_SIZE,
                                   user_bufs[i - 1].arch_mmu_flags,
                                   user_bufs[i].arch_mmu_flags);
            }
        }
        if (user_bufs[i].test_with & TEST_NO_OVERLAP) {
            usercopy_test_addr(func, user_bufs[i].addr,
                               user_bufs[i].arch_mmu_flags,
                               user_bufs[i].arch_mmu_flags);
        }
    }
}

TEST(usercopytest, copy_to_user) {
    usercopy_test(usercopy_test_copy_to_user);
}

TEST(usercopytest, copy_from_user) {
    usercopy_test(usercopy_test_copy_from_user);
}

TEST(usercopytest, strlcpy_from_user) {
    usercopy_test(usercopy_test_strlcpy_from_user);
}

static bool run_usercopy_test(struct unittest* test) {
    status_t ret;
    bool tests_passed;
    struct vmm_aspace* aspace;

    ret = vmm_create_aspace(&aspace, "usercopy_test", 0);
    if (ret) {
        unittest_printf("%s: failed to create aspace\n", __func__);
        goto err_create_aspace;
    }
    for (size_t i = 0; i < countof(user_bufs); i++) {
        void* user_ptr = (void*)(uintptr_t)user_bufs[i].addr;
        if (!user_bufs[i].arch_mmu_flags) {
            continue; /* skip holes in address space used by tests */
        }
        ret = vmm_alloc(aspace, "usercopy-test", PAGE_SIZE, &user_ptr, 0,
                        VMM_FLAG_VALLOC_SPECIFIC, user_bufs[i].arch_mmu_flags);
        if (ret) {
            unittest_printf("%s: failed to allocate buffer at %x: %d\n",
                            __func__, user_bufs[i].addr, ret);
            goto err_alloc;
        }
    }

    vmm_set_active_aspace(aspace);

    tests_passed = RUN_ALL_TESTS();

    vmm_set_active_aspace(NULL);
    vmm_free_aspace(aspace);

    return tests_passed;

err_alloc:
    vmm_free_aspace(aspace);
err_create_aspace:
    return false;
}

static void usercopy_test_init(uint level) {
    static struct unittest usercopy_unittest = {
            .port_name = "com.android.kernel.usercopy-unittest",
            .run_test = run_usercopy_test,
    };

    unittest_add(&usercopy_unittest);
}

LK_INIT_HOOK(usercopy_test, usercopy_test_init, LK_INIT_LEVEL_APPS);
