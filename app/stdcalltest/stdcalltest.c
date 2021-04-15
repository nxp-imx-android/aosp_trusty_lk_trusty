/*
 * Copyright (c) 2020 Google, Inc.
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
#include <kernel/vm.h>
#include <lib/sm.h>
#include <lib/sm/sm_err.h>
#include <lib/sm/smcall.h>
#include <lk/init.h>
#include <trace.h>

#include "stdcalltest.h"

static ext_mem_obj_id_t args_get_id(struct smc32_args* args) {
    return (((uint64_t)args->params[1] << 32) | args->params[0]);
}

static size_t args_get_sz(struct smc32_args* args) {
    return (size_t)args->params[2];
}

/**
 * stdcalltest_sharedmem_rw - Test shared memory buffer.
 * @id:     Shared memory id.
 * @size:   Size.
 *
 * Check that buffer contains the 64 bit integer sqequnce [0, 1, 2, ...,
 * @size / 8 - 1] and modify sequence to [@size, @size - 1, size - 2, ...,
 * @size - (@size / 8 - 1)].
 *
 * Return: 0 on success. SM_ERR_INVALID_PARAMETERS is buffer does not contain
 * expected input pattern. SM_ERR_INTERNAL_FAILURE if @id could not be mapped.
 */
static long stdcalltest_sharedmem_rw(ext_mem_client_id_t client_id,
                                     ext_mem_obj_id_t mem_obj_id,
                                     size_t size) {
    struct vmm_aspace* aspace = vmm_get_kernel_aspace();
    status_t ret;
    long status;
    void* va;
    uint64_t* va64;

    if (!IS_PAGE_ALIGNED(size)) {
        return SM_ERR_INVALID_PARAMETERS;
    }

    ret = ext_mem_map_obj_id(aspace, "stdcalltest", client_id, mem_obj_id, 0, 0,
                             size, &va, PAGE_SIZE_SHIFT, 0,
                             ARCH_MMU_FLAG_PERM_NO_EXECUTE);
    if (ret != NO_ERROR) {
        status = SM_ERR_INTERNAL_FAILURE;
        goto err_map;
    }
    va64 = va;

    for (size_t i = 0; i < size / sizeof(*va64); i++) {
        if (va64[i] != i) {
            TRACEF("input mismatch at %zd, got 0x%llx instead of 0x%zx\n", i,
                   va64[i], i);
            status = SM_ERR_INVALID_PARAMETERS;
            goto err_input_mismatch;
        }
        va64[i] = size - i;
    }
    status = 0;

err_input_mismatch:
    ret = vmm_free_region(aspace, (vaddr_t)va);
    if (ret) {
        status = SM_ERR_INTERNAL_FAILURE;
    }
err_map:
    return status;
}

static long stdcalltest_stdcall(struct smc32_args* args) {
    switch (args->smc_nr) {
    case SMC_SC_TEST_VERSION:
        return TRUSTY_STDCALLTEST_API_VERSION;
    case SMC_SC_TEST_SHARED_MEM_RW:
        return stdcalltest_sharedmem_rw(args->client_id, args_get_id(args),
                                        args_get_sz(args));
    default:
        return SM_ERR_UNDEFINED_SMC;
    }
}

static struct smc32_entity stdcalltest_sm_entity = {
        .stdcall_handler = stdcalltest_stdcall,
};

static void stdcalltest_init(uint level) {
    int err;

    err = sm_register_entity(SMC_ENTITY_TEST, &stdcalltest_sm_entity);
    if (err) {
        printf("trusty error register entity: %d\n", err);
    }
}
LK_INIT_HOOK(stdcalltest, stdcalltest_init, LK_INIT_LEVEL_APPS);
