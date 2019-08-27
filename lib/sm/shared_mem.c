/*
 * Copyright (c) 2019 LK Trusty Authors. All Rights Reserved.
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

#include <arch/ops.h>
#include <compiler.h>
#include <debug.h>
#include <err.h>
#include <kernel/mutex.h>
#include <kernel/vm.h>
#include <lib/sm.h>
#include <lib/sm/sm_err.h>
#include <lib/sm/smcall.h>
#include <lk/init.h>
#include <string.h>
#include <trace.h>

#define LOCAL_TRACE 0

static void sm_mem_obj_destroy(struct vmm_obj* vmm_obj) {
    struct ext_mem_obj* obj = containerof(vmm_obj, struct ext_mem_obj, vmm_obj);
    free(obj);
}

static struct vmm_obj_ops sm_mem_obj_ops = {
        .check_flags = ext_mem_obj_check_flags,
        .get_page = ext_mem_obj_get_page,
        .destroy = sm_mem_obj_destroy,
};

/**
 * ext_mem_get_vmm_obj - Create vmm_obj from id.
 * @client_id:  Id of external entity where the memory originated.
 * @mem_obj_id: Object id containing a packed address and attibutes.
 * @size:       Size of object.
 * @objp:       Pointer to return object in.
 * @obj_ref:    Reference to *@objp.
 *
 * The object paddr and attibutes are encoded in the id for now. Convert it to a
 * paddr and mmu-flags using the existing helper function.
 *
 * TODO: Use the id to look up an existing object.
 *
 * Return: 0 on success, negative error code if object could not be created.
 */
status_t ext_mem_get_vmm_obj(ext_mem_client_id_t client_id,
                             ext_mem_obj_id_t mem_obj_id,
                             size_t size,
                             struct vmm_obj** objp,
                             struct obj_ref* obj_ref) {
    int ret;
    struct ext_mem_obj* obj;
    struct ns_page_info pinf = {mem_obj_id};
    ns_addr_t ns_paddr;
    paddr_t paddr;
    uint arch_mmu_flags;

    ret = sm_decode_ns_memory_attr(&pinf, &ns_paddr, &arch_mmu_flags);
    if (ret) {
        return ret;
    }

    paddr = (paddr_t)ns_paddr;
    if (paddr != ns_paddr) {
        /*
         * If ns_addr_t is larger than paddr_t and we get an address that does
         * not fit, return an error as we cannot map that address.
         */
        TRACEF("unsupported paddr, 0x%0llx\n", ns_paddr);
        return ERR_INVALID_ARGS;
    }

    obj = malloc(sizeof(*obj) + ext_mem_obj_page_runs_size(1));
    if (!obj) {
        return ERR_NO_MEMORY;
    }

    arch_mmu_flags |= ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE;
    ext_mem_obj_initialize(obj, obj_ref, mem_obj_id, &sm_mem_obj_ops,
                           arch_mmu_flags, 1);
    obj->page_runs[0].paddr = paddr;
    obj->page_runs[0].size = size;
    *objp = &obj->vmm_obj;

    return 0;
}
