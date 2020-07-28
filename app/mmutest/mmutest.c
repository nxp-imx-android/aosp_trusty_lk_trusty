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
#include <pow2.h>
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

typedef struct {
    vmm_aspace_t* aspace;
    size_t allocation_size;
} mmutestvmm_t;

TEST_F_SETUP(mmutestvmm) {
    const size_t* allocation_size_p = GetParam();
    _state->allocation_size = *allocation_size_p;
    _state->aspace = vmm_get_kernel_aspace();

    ASSERT_GE(_state->allocation_size, PAGE_SIZE);
    ASSERT_LT(_state->allocation_size, _state->aspace->size);
test_abort:;
}

static size_t mmutestvmm_allocation_sizes[] = {
        PAGE_SIZE,
        2 * 1024 * 1024, /* large enough to use section/block mapping on arm */
};

TEST_F_TEARDOWN(mmutestvmm) {}

/* Smoke test for vmm_alloc */
TEST_P(mmutestvmm, vmm_alloc) {
    int ret;
    void* ptr = NULL;
    ret = vmm_alloc(_state->aspace, "mmutest", _state->allocation_size, &ptr, 0,
                    0, 0);
    EXPECT_EQ(0, ret);
    EXPECT_NE(NULL, ptr);
    ret = vmm_free_region(_state->aspace, (vaddr_t)ptr);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");
}

/* Smoke test for vmm_alloc_contiguous */
TEST_P(mmutestvmm, vmm_alloc_contiguous) {
    int ret;
    void* ptr = NULL;
    ret = vmm_alloc_contiguous(_state->aspace, "mmutest",
                               _state->allocation_size, &ptr,
                               log2_uint(_state->allocation_size), 0, 0);
    EXPECT_EQ(0, ret);
    EXPECT_NE(NULL, ptr);
    ret = vmm_free_region(_state->aspace, (vaddr_t)ptr);
    EXPECT_EQ(0, ret, "vmm_free_region failed\n");
}

TEST(mmutest, alloc_last_kernel_page) {
    int ret;
    void* ptr1;
    void* ptr2;
    void* ptr3;
    vmm_aspace_t* aspace = vmm_get_kernel_aspace();
    struct vmm_obj_slice slice;
    vmm_obj_slice_init(&slice);

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

    /* While the last page is allocated, get an object corresponding to it */
    ret = vmm_get_obj(aspace, (vaddr_t)ptr1, PAGE_SIZE, &slice);
    EXPECT_EQ(NO_ERROR, ret, "vmm_get_obj failed to get last page object");
    /* Check the slice we got back */
    EXPECT_NE(NULL, slice.obj);
    EXPECT_EQ(PAGE_SIZE, slice.size);
    EXPECT_EQ(0, slice.offset);
    vmm_obj_slice_release(&slice);

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

/* Test suite for vmm_obj_slice and vmm_get_obj */

typedef struct {
    vmm_aspace_t *aspace;
    vaddr_t spot_a_2_page;
    vaddr_t spot_b_1_page;
    struct vmm_obj_slice slice;
} mmutest_slice_t;

TEST_F_SETUP(mmutest_slice) {
    _state->aspace = vmm_get_kernel_aspace();
    _state->spot_a_2_page = 0;
    _state->spot_b_1_page = 0;
    vmm_obj_slice_init(&_state->slice);
    ASSERT_EQ(vmm_alloc(_state->aspace, "mmutest_slice", 2 * PAGE_SIZE,
                        (void **)&_state->spot_a_2_page, 0, 0, 0),
              NO_ERROR);
    ASSERT_EQ(vmm_alloc(_state->aspace, "mmutest_slice", PAGE_SIZE,
                        (void **)&_state->spot_b_1_page, 0, 0, 0),
              NO_ERROR);
test_abort:;
}

TEST_F_TEARDOWN(mmutest_slice) {
    vmm_obj_slice_release(&_state->slice);
    if (_state->spot_a_2_page) {
        vmm_free_region(_state->aspace, (vaddr_t)_state->spot_a_2_page);
    }

    if (_state->spot_b_1_page) {
        vmm_free_region(_state->aspace, (vaddr_t)_state->spot_b_1_page);
    }
}

/*
 * Simplest use of interface - get the slice for a mapped region,
 * of the whole size
 */
TEST_F(mmutest_slice, simple) {
    ASSERT_EQ(vmm_get_obj(_state->aspace, _state->spot_b_1_page, PAGE_SIZE,
                          &_state->slice),
              NO_ERROR);
    EXPECT_EQ(_state->slice.offset, 0);
    EXPECT_EQ(_state->slice.size, PAGE_SIZE);
test_abort:;
}

/* Validate that we will reject an attempt to span two slices */
TEST_F(mmutest_slice, two_objs) {
    vaddr_t base;
    size_t size;
    vaddr_t spot_a = _state->spot_a_2_page;
    vaddr_t spot_b = _state->spot_b_1_page;

    base = MIN(spot_a, spot_b);
    size = MAX(spot_a, spot_b) - base + PAGE_SIZE;

    /* We should not be able to create a slice spanning both objects */
    EXPECT_EQ(vmm_get_obj(_state->aspace, base, size, &_state->slice),
              ERR_OUT_OF_RANGE);

test_abort:;
}

/* Check we can acquire a subslice of a mapped object */
TEST_F(mmutest_slice, subobj) {
    ASSERT_EQ(vmm_get_obj(_state->aspace, _state->spot_a_2_page + PAGE_SIZE,
                          PAGE_SIZE, &_state->slice),
              NO_ERROR);

    EXPECT_EQ(_state->slice.offset, PAGE_SIZE);
    EXPECT_EQ(_state->slice.size, PAGE_SIZE);

test_abort:;
}

/* Check for rejection of the requested range overflows */
TEST_F(mmutest_slice, overflow) {
    EXPECT_EQ(vmm_get_obj(_state->aspace, _state->spot_a_2_page, SIZE_MAX,
                          &_state->slice),
              ERR_INVALID_ARGS);
}

INSTANTIATE_TEST_SUITE_P(allocation_size,
                         mmutestvmm,
                         testing_ValuesIn(mmutestvmm_allocation_sizes));

PORT_TEST(mmutest, "com.android.kernel.mmutest");
