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

#include <err.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <lib/unittest/unittest.h>
#include <lk/init.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int mmutest_arch_rodata_pnx(void);
int mmutest_arch_data_pnx(void);
int mmutest_arch_rodata_ro(void);

int mmutest_arch_store_uint32(uint32_t* ptr, bool user);
int mmutest_arch_nop(int ret);
int mmutest_arch_nop_end(int ret);

static int mmutest_alloc(void** ptrp, uint arch_mmu_flags) {
    int ret;
    uint arch_mmu_flags_query = ~0U;
    vmm_aspace_t* aspace = vmm_get_kernel_aspace();

    ret = vmm_alloc_contiguous(aspace, "mmutest", PAGE_SIZE, ptrp, 0, 0,
                               arch_mmu_flags);

    EXPECT_EQ(0, ret, "vmm_alloc_contiguous failed\n");
    if (ret) {
        return ret;
    }

    arch_mmu_query(&aspace->arch_aspace, (vaddr_t)*ptrp, NULL,
                   &arch_mmu_flags_query);
    EXPECT_EQ(arch_mmu_flags_query, arch_mmu_flags,
              "arch_mmu_query, 0x%x, does not match requested flags, 0x%x\n",
              arch_mmu_flags_query, arch_mmu_flags);
    return 0;
}

static int mmutest_vmm_store_uint32(uint arch_mmu_flags, bool user) {
    int ret;
    void* ptr;

    ret = mmutest_alloc(&ptr, arch_mmu_flags);
    if (ret) {
        return ret;
    }

    ret = mmutest_arch_store_uint32(ptr, user);

    vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)ptr);
    return ret;
}

static int mmutest_vmm_store_uint32_kernel(uint arch_mmu_flags) {
    return mmutest_vmm_store_uint32(arch_mmu_flags, false);
}

static int mmutest_vmm_store_uint32_user(uint arch_mmu_flags) {
    return mmutest_vmm_store_uint32(arch_mmu_flags, true);
}

static int mmu_test_nx(bool execute) {
    int ret;
    void* ptr;
    size_t len;
    int (*nop)(int ret);

    ret = mmutest_alloc(&ptr, ARCH_MMU_FLAG_PERM_NO_EXECUTE);
    if (ret) {
        return ret;
    }

    nop = ptr;
    len = mmutest_arch_nop_end - mmutest_arch_nop;

    memcpy(ptr, mmutest_arch_nop, len);
    arch_sync_cache_range((addr_t)ptr, len);

    if (execute) {
        printf("Starting fatal test, expect crash\n");
        ret = nop(0);
    }

    vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)ptr);

    return ret;
}

/* Skip kernel permission tests on ARM as it uses 1MB mappings */
#if ARCH_ARM
#define DISABLED_ON_ARM_NAME(name) DISABLED_##name
#else
#define DISABLED_ON_ARM_NAME(name) name
#endif

TEST(mmutest, alloc_last_kernel_page) {
    int ret;
    void* ptr1;
    void* ptr2;
    void* ptr3;
    vmm_aspace_t* aspace = vmm_get_kernel_aspace();

    /*
     * Perform allocations at a specific address and at a vmm chosen address
     * with and without the last page allocated. There are different code paths
     * in the vmm allocator where the virtual address can overflow for the
     * region that is being allocated and for regions already allocated.
     */

    /* Allocate last kernel aspace page. */
    ptr1 = (void*)(aspace->base + (aspace->size - PAGE_SIZE));
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr1, 0,
                    VMM_FLAG_VALLOC_SPECIFIC, 0);
    /* TODO: allow this to fail as page could already be in use */
    ASSERT_EQ(0, ret, "vmm_alloc failed last page\n");

    /* Allocate page anywhere, while the last page is allocated. */
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr2, 0, 0, 0);
    ASSERT_EQ(0, ret, "vmm_alloc failed anywhere page\n");

    /* Try to allocate last kernel aspace page again, should fail */
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr1, 0,
                    VMM_FLAG_VALLOC_SPECIFIC, 0);
    EXPECT_EQ(ERR_NO_MEMORY, ret, "vmm_alloc last page\n");

    /* Allocate 2nd last kernel aspace page, while last page is allocated. */
    ptr3 = (void*)(aspace->base + (aspace->size - 2 * PAGE_SIZE));
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr3, 0,
                    VMM_FLAG_VALLOC_SPECIFIC, 0);
    /* TODO: allow this to fail as page could already be in use */
    ASSERT_EQ(0, ret, "vmm_alloc failed 2nd last page\n");

    /* Free allocated pages */
    ret = vmm_free_region(aspace, (vaddr_t)ptr1);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");
    ret = vmm_free_region(aspace, (vaddr_t)ptr2);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");
    ret = vmm_free_region(aspace, (vaddr_t)ptr3);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");

    /* Allocate and free last page */
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr1, 0,
                    VMM_FLAG_VALLOC_SPECIFIC, 0);
    /* TODO: allow this to fail as page could be in use */
    ASSERT_EQ(0, ret, "vmm_alloc failed last page\n");
    ret = vmm_free_region(aspace, (vaddr_t)ptr1);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");

    /* Allocate and free page anywhere, while last page is free */
    ret = vmm_alloc(aspace, "mmutest", PAGE_SIZE, &ptr2, 0, 0, 0);
    ASSERT_EQ(0, ret, "vmm_alloc failed anywhere page\n");
    ret = vmm_free_region(aspace, (vaddr_t)ptr2);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");

test_abort:;
}

TEST(mmutest, DISABLED_ON_ARM_NAME(rodata_pnx)) {
    EXPECT_EQ(ERR_FAULT, mmutest_arch_rodata_pnx());
}

TEST(mmutest, DISABLED_ON_ARM_NAME(data_pnx)) {
    EXPECT_EQ(ERR_FAULT, mmutest_arch_data_pnx());
}

TEST(mmutest, DISABLED_ON_ARM_NAME(rodata_ro)) {
    EXPECT_EQ(ERR_FAULT, mmutest_arch_rodata_ro());
}

TEST(mmutest, store_kernel) {
    EXPECT_EQ(0, mmutest_vmm_store_uint32_kernel(ARCH_MMU_FLAG_CACHED));
    EXPECT_EQ(0, mmutest_vmm_store_uint32_kernel(ARCH_MMU_FLAG_CACHED |
                                                 ARCH_MMU_FLAG_PERM_USER));
    EXPECT_EQ(0, mmutest_vmm_store_uint32_kernel(
                         ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_NO_EXECUTE));
    EXPECT_EQ(0, mmutest_vmm_store_uint32_kernel(ARCH_MMU_FLAG_CACHED |
                                                 ARCH_MMU_FLAG_PERM_NO_EXECUTE |
                                                 ARCH_MMU_FLAG_PERM_USER));
    EXPECT_EQ(ERR_FAULT, mmutest_vmm_store_uint32_kernel(
                                 ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO));
    EXPECT_EQ(ERR_FAULT, mmutest_vmm_store_uint32_kernel(
                                 ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO |
                                 ARCH_MMU_FLAG_PERM_USER));
}

TEST(mmutest, store_user) {
    EXPECT_EQ(ERR_GENERIC, mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED));
    EXPECT_EQ(0, mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                               ARCH_MMU_FLAG_PERM_USER));
    EXPECT_EQ(ERR_GENERIC,
              mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                            ARCH_MMU_FLAG_PERM_NO_EXECUTE));
    EXPECT_EQ(0, mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                               ARCH_MMU_FLAG_PERM_NO_EXECUTE |
                                               ARCH_MMU_FLAG_PERM_USER));
    EXPECT_EQ(ERR_GENERIC,
              mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                            ARCH_MMU_FLAG_PERM_RO));
    EXPECT_EQ(ERR_FAULT, mmutest_vmm_store_uint32_user(
                                 ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO |
                                 ARCH_MMU_FLAG_PERM_USER));
}

/*
 * The current implementation of this test checks checks that the data is lost
 * when reading back from memory, but allows the store to reach the cache. This
 * is not the only allowed behavior and the emulator does not emulate this
 * behavior, so disable this test for now.
 */
TEST(mmutest, DISABLED_store_ns) {
    EXPECT_EQ(2, mmutest_vmm_store_uint32_kernel(ARCH_MMU_FLAG_CACHED |
                                                 ARCH_MMU_FLAG_NS));
    EXPECT_EQ(2, mmutest_vmm_store_uint32_kernel(ARCH_MMU_FLAG_CACHED |
                                                 ARCH_MMU_FLAG_NS |
                                                 ARCH_MMU_FLAG_PERM_USER));
    EXPECT_EQ(ERR_GENERIC, mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                                         ARCH_MMU_FLAG_NS));
    EXPECT_EQ(2, mmutest_vmm_store_uint32_user(ARCH_MMU_FLAG_CACHED |
                                               ARCH_MMU_FLAG_NS |
                                               ARCH_MMU_FLAG_PERM_USER));
}

TEST(mmutest, check_nx) {
    EXPECT_EQ(0, mmu_test_nx(false));
}

TEST(mmutest, DISABLED_run_nx) {
    EXPECT_EQ(ERR_FAULT, mmu_test_nx(true));
}

PORT_TEST(mmutest, "com.android.kernel.mmutest");
