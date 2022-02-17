/*
 * Copyright (c) 2019-2020 LK Trusty Authors. All Rights Reserved.
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

#include <compiler.h>
#include <debug.h>
#include <err.h>
#include <kernel/mutex.h>
#include <kernel/vm.h>
#include <lib/extmem/extmem.h>
#include <lib/page_alloc.h>
#include <lib/sm.h>
#include <lib/sm/arm_ffa.h>
#include <lib/sm/smc.h>
#include <lk/init.h>
#include <string.h>
#include <trace.h>

#define LOCAL_TRACE 0

struct sm_mem_obj {
    uint16_t sender_id;
    struct ext_mem_obj ext_mem_obj;
};

static mutex_t sm_mem_ffa_lock = MUTEX_INITIAL_VALUE(sm_mem_ffa_lock);

static size_t ffa_buf_size;
static void* ffa_tx;
static void* ffa_rx;
static uint16_t ffa_local_id;
static bool supports_ns_bit = false;

static void sm_mem_obj_compat_destroy(struct vmm_obj* vmm_obj) {
    struct ext_mem_obj* obj = containerof(vmm_obj, struct ext_mem_obj, vmm_obj);
    free(obj);
}

static struct vmm_obj_ops sm_mem_obj_compat_ops = {
        .check_flags = ext_mem_obj_check_flags,
        .get_page = ext_mem_obj_get_page,
        .destroy = sm_mem_obj_compat_destroy,
};

/**
 * sm_mem_compat_get_vmm_obj - Create vmm_obj from id.
 * @client_id:  Id of external entity where the memory originated.
 * @mem_obj_id: Object id containing a packed address and attibutes.
 * @size:       Size of object.
 * @objp:       Pointer to return object in.
 * @obj_ref:    Reference to *@objp.
 *
 * The object paddr and attibutes are encoded in the id for now. Convert it to a
 * paddr and mmu-flags using the existing helper function.
 *
 * Return: 0 on success, negative error code if object could not be created.
 */
static status_t sm_mem_compat_get_vmm_obj(ext_mem_client_id_t client_id,
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
    ext_mem_obj_initialize(obj, obj_ref, mem_obj_id, 0, &sm_mem_obj_compat_ops,
                           arch_mmu_flags, 1);
    obj->page_runs[0].paddr = paddr;
    obj->page_runs[0].size = size;
    *objp = &obj->vmm_obj;

    return 0;
}

/**
 * ffa_mem_relinquish: Relinquish memory object.
 * @obj:        Object to relinquish.
 *
 * Relinquish shared memory object id with SPM/Hypervisor. Allows the sender to
 * reclaim the memory (if it has not been retrieved by anyone else).
 */
static void ffa_mem_relinquish(struct sm_mem_obj* obj) {
    struct smc_ret8 smc_ret;
    struct ffa_mem_relinquish_descriptor* req = ffa_tx;

    DEBUG_ASSERT(obj);
    DEBUG_ASSERT(is_mutex_held(&sm_mem_ffa_lock));

    if (!req) {
        TRACEF("ERROR: no FF-A buffer, skip FFA_MEM_RELINQUISH\n");
        return;
    }
    req->handle = obj->ext_mem_obj.id;
    req->flags = 0; /* Tell SPM/Hypervisor to not clear memory. */
    req->endpoint_count = 1;
    req->endpoint_array[0] = ffa_local_id;

    /* Release reference to @obj->ext_mem_obj.id in SPM/Hypervisor. */
    smc_ret = smc8(SMC_FC_FFA_MEM_RELINQUISH, 0, 0, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("bad reply: 0x%lx 0x%lx 0x%lx\n", smc_ret.r0, smc_ret.r1,
               smc_ret.r2);
    }
}

/**
 * sm_mem_obj_destroy: Destroy memory object.
 * @vmm_obj:    VMM object to destroy.
 *
 * Called after the last reference to @vmm_obj has been released. Relinquish
 * shared memory object id with SPM/Hypervisor and free local tracking object.
 */
static void sm_mem_obj_destroy(struct vmm_obj* vmm_obj) {
    struct sm_mem_obj* obj =
            containerof(vmm_obj, struct sm_mem_obj, ext_mem_obj.vmm_obj);

    mutex_acquire(&sm_mem_ffa_lock);
    ffa_mem_relinquish(obj);
    mutex_release(&sm_mem_ffa_lock);

    free(obj);
}

static struct vmm_obj_ops sm_mem_obj_ops = {
        .check_flags = ext_mem_obj_check_flags,
        .get_page = ext_mem_obj_get_page,
        .destroy = sm_mem_obj_destroy,
};

/**
 * sm_mem_alloc_obj - Allocate and initialize memory object.
 * @sender_id:      FF-A vm id of sender.
 * @mem_id:         Id of object.
 * @tag:            Tag of the object
 * @page_run_count: Number of page runs to allocate for object.
 * @arch_mmu_flags: Memory type and permissions.
 * @obj_ref:        Reference to returned object.
 *
 * Return: Pointer to &struct sm_mem_obj, or %NULL if allocation fails.
 */
static struct sm_mem_obj* sm_mem_alloc_obj(uint16_t sender_id,
                                           ext_mem_obj_id_t mem_id,
                                           uint64_t tag,
                                           size_t page_run_count,
                                           uint arch_mmu_flags,
                                           struct obj_ref* obj_ref) {
    struct sm_mem_obj* obj =
            malloc(sizeof(*obj) + ext_mem_obj_page_runs_size(page_run_count));
    if (!obj) {
        return NULL;
    }
    ext_mem_obj_initialize(&obj->ext_mem_obj, obj_ref, mem_id, tag,
                           &sm_mem_obj_ops, arch_mmu_flags, page_run_count);
    obj->sender_id = sender_id;

    return obj;
}

/**
 * ffa_mem_retrieve_req - Call SPM/Hypervisor to retrieve memory region.
 * @sender_id:  FF-A vm id of sender.
 * @handle:     FF-A allocated handle.
 *
 * Helper function to start retrieval. Does not process result.
 *
 * Return: &struct smc_ret8.
 */
static struct smc_ret8 ffa_mem_retrieve_req(uint16_t sender_id,
                                            uint64_t handle,
                                            uint64_t tag) {
    struct ffa_mtd* req = ffa_tx;

    DEBUG_ASSERT(is_mutex_held(&sm_mem_ffa_lock));

    req->sender_id = sender_id;

    /* Accept any memory region attributes. */
    req->memory_region_attributes = 0;

    req->reserved_3 = 0;
    req->flags = 0;
    req->handle = handle;

    /* We must use the same tag as the one used by the sender to retrieve. */
    req->tag = tag;
    req->reserved_24_27 = 0;

    /*
     * We only support retrieving memory for ourselves for now.
     * TODO: Also support stream endpoints. Possibly more than one.
     */
    req->emad_count = 1;
    req->emad[0].mapd.endpoint_id = ffa_local_id;

    /* Accept any memory access permissions. */
    req->emad[0].mapd.memory_access_permissions = 0;
    req->emad[0].mapd.flags = 0;

    /*
     * Set composite memory region descriptor offset to 0 to indicate that the
     * relayer should allocate the address ranges. Other values will not work
     * for relayers that use identity maps (e.g. EL3).
     */
    req->emad[0].comp_mrd_offset = 0;
    req->emad[0].reserved_8_15 = 0;

    size_t len = offsetof(struct ffa_mtd, emad[1]);

    /* Start FFA_MEM_RETRIEVE_REQ. */
    return smc8(SMC_FC_FFA_MEM_RETRIEVE_REQ, len, len, 0, 0, 0, 0, 0);
}

/**
 * ffa_mem_retrieve - Call SPM/Hypervisor to retrieve memory region.
 * @sender_id:  FF-A vm id of sender.
 * @handle:     FF-A allocated handle.
 * @objp:       Pointer to return object in.
 * @obj_ref:    Reference to *@objp.
 *
 * Return: 0 on success, lk error code on failure.
 */
static int ffa_mem_retrieve(uint16_t sender_id,
                            uint64_t handle,
                            uint64_t tag,
                            struct vmm_obj** objp,
                            struct obj_ref* obj_ref) {
    struct smc_ret8 smc_ret;
    struct ffa_mtd* resp = ffa_rx;
    struct ffa_emad* emad = resp->emad;
    struct sm_mem_obj* obj;
    struct obj_ref tmp_obj_ref = OBJ_REF_INITIAL_VALUE(tmp_obj_ref);
    int ret;
    uint arch_mmu_flags;
    struct ffa_comp_mrd* comp_mrd;

    DEBUG_ASSERT(is_mutex_held(&sm_mem_ffa_lock));
    DEBUG_ASSERT(objp);
    DEBUG_ASSERT(obj_ref);

    if (!ffa_tx) {
        TRACEF("no FF-A buffer\n");
        return ERR_NOT_READY;
    }

    smc_ret = ffa_mem_retrieve_req(sender_id, handle, tag);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_MEM_RETRIEVE_RESP) {
        TRACEF("bad reply: 0x%lx 0x%lx 0x%lx\n", smc_ret.r0, smc_ret.r1,
               smc_ret.r2);
        return ERR_IO;
    }
    size_t total_len = (uint32_t)smc_ret.r1;
    size_t fragment_len = (uint32_t)smc_ret.r2;

    /*
     * We don't retrieve the memory on behalf of anyone else, so we only
     * expect one receiver address range descriptor.
     */
    if (resp->emad_count != 1) {
        TRACEF("unexpected response count %d != 1\n", resp->emad_count);
    }

    switch (resp->flags & FFA_MTD_FLAG_TYPE_MASK) {
    case FFA_MTD_FLAG_TYPE_SHARE_MEMORY:
    case FFA_MTD_FLAG_TYPE_LEND_MEMORY:
        break;
    default:
        /* Donate or an unknown sharing type */
        TRACEF("Unknown transfer kind: 0x%x\n",
               resp->flags & FFA_MTD_FLAG_TYPE_MASK);
        return ERR_IO;
    }

    /* Check that the first fragment contains the entire header. */
    size_t header_size = offsetof(struct ffa_mtd, emad[1]);
    if (fragment_len < header_size) {
        TRACEF("fragment length %zd too short\n", fragment_len);
        return ERR_IO;
    }

    /* Check that the first fragment fits in our buffer */
    if (fragment_len > ffa_buf_size) {
        TRACEF("fragment length %zd larger than buffer size\n", fragment_len);
        return ERR_IO;
    }

    size_t comp_mrd_offset = emad->comp_mrd_offset;

    /*
     * We have already checked that fragment_len is larger than *resp. Since
     * *comp_mrd is smaller than that (verified here), the fragment_len -
     * sizeof(*comp_mrd) subtraction below will never underflow.
     */
    STATIC_ASSERT(sizeof(*resp) >= sizeof(*comp_mrd));

    if (comp_mrd_offset > fragment_len - sizeof(*comp_mrd)) {
        TRACEF("fragment length %zd too short for comp_mrd_offset %zd\n",
               fragment_len, comp_mrd_offset);
        return ERR_IO;
    }
    comp_mrd = (void*)resp + comp_mrd_offset;

    /*
     * Set arch_mmu_flags based on mem_attr returned.
     */
    switch (resp->memory_region_attributes & ~FFA_MEM_ATTR_NONSECURE) {
    case FFA_MEM_ATTR_DEVICE_NGNRE:
        arch_mmu_flags = ARCH_MMU_FLAG_UNCACHED_DEVICE;
        break;
    case FFA_MEM_ATTR_NORMAL_MEMORY_UNCACHED:
        arch_mmu_flags = ARCH_MMU_FLAG_UNCACHED;
        break;
    case (FFA_MEM_ATTR_NORMAL_MEMORY_CACHED_WB | FFA_MEM_ATTR_INNER_SHAREABLE):
        arch_mmu_flags = ARCH_MMU_FLAG_CACHED;
        break;
    default:
        TRACEF("unsupported memory attributes, 0x%x\n",
               resp->memory_region_attributes);
        return ERR_NOT_SUPPORTED;
    }

    if (!supports_ns_bit || (resp->memory_region_attributes & FFA_MEM_ATTR_NONSECURE)) {
        arch_mmu_flags |= ARCH_MMU_FLAG_NS;
    } else {
        LTRACEF("secure memory path triggered\n");
    }

    if (!(emad->mapd.memory_access_permissions & FFA_MEM_PERM_RW)) {
        arch_mmu_flags |= ARCH_MMU_FLAG_PERM_RO;
    }
    if (emad->mapd.memory_access_permissions & FFA_MEM_PERM_NX) {
        /*
         * Don't allow executable mappings if the stage 2 page tables don't
         * allow it. The hardware allows the stage 2 NX bit to only apply to
         * EL1, not EL0, but neither FF-A nor LK can currently express this, so
         * disallow both if FFA_MEM_PERM_NX is set.
         */
        arch_mmu_flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;
    }

    if ((resp->flags & FFA_MTD_FLAG_TYPE_MASK) ==
        FFA_MTD_FLAG_TYPE_SHARE_MEMORY) {
        /*
         * If memory is shared, assume it is not safe to execute out of. This
         * specifically indicates that another party may have access to the
         * memory.
         */
        arch_mmu_flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;
    }

    /*
     * Regardless of origin, we don't want to execute out of NS memory.
     */
    if (arch_mmu_flags & ARCH_MMU_FLAG_NS) {
        arch_mmu_flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;
    }

    /*
     * Check that the overall length of the message matches the expected length
     * for the number of entries specified in the header.
     */
    uint32_t address_range_descriptor_count = comp_mrd->address_range_count;
    size_t expected_len =
            comp_mrd_offset +
            offsetof(struct ffa_comp_mrd,
                     address_range_array[address_range_descriptor_count]);
    if (total_len != expected_len) {
        TRACEF("length mismatch smc %zd != computed %zd for count %d\n",
               total_len, expected_len, address_range_descriptor_count);
        return ERR_IO;
    }

    header_size = comp_mrd_offset + sizeof(*comp_mrd);

    struct ffa_cons_mrd* desc = comp_mrd->address_range_array;

    /*
     * Compute full descriptor count and size of partial descriptor in first
     * fragment.
     */
    size_t desc_count = (fragment_len - header_size) / sizeof(*desc);
    if (desc_count * sizeof(*desc) + header_size != fragment_len) {
        TRACEF("fragment length %zd, contains partial descriptor\n",
               fragment_len);
        return ERR_IO;
    }

    /* The first fragment should not be larger than the whole message */
    if (desc_count > address_range_descriptor_count) {
        TRACEF("bad fragment length %zd > %zd\n", fragment_len, total_len);
        return ERR_IO;
    }

    LTRACEF("handle %lld, desc count %d\n", handle,
            address_range_descriptor_count);

    /* Allocate a new shared memory object. */
    obj = sm_mem_alloc_obj(sender_id, handle, tag,
                           address_range_descriptor_count, arch_mmu_flags,
                           &tmp_obj_ref);
    if (!obj) {
        return ERR_NO_MEMORY;
    }

    for (uint ri = 0, di = 0; ri < address_range_descriptor_count; ri++, di++) {
        if (di >= desc_count) {
            mutex_release(&sm_mem_ffa_lock);
            /* Drop lock to allow interleaving large object retrieval */
            mutex_acquire(&sm_mem_ffa_lock);
            /*
             * All descriptors in this fragment has been consumed.
             * Fetch next fragment from the SPM/Hypervisor.
             */
            smc_ret = smc8(SMC_FC_FFA_MEM_FRAG_RX, (uint32_t)handle,
                           handle >> 32, fragment_len, 0, 0, 0, 0);
            if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_MEM_FRAG_TX) {
                TRACEF("bad reply: 0x%lx 0x%lx 0x%lx\n", smc_ret.r0, smc_ret.r1,
                       smc_ret.r2);
                ret = ERR_IO;
                goto err_mem_frag_rx;
            }
            fragment_len += (uint32_t)smc_ret.r3;

            desc = ffa_rx;
            di = 0;

            /*
             * Compute descriptor count in this fragment.
             */
            desc_count = ((uint32_t)smc_ret.r3) / sizeof(*desc);
            if ((uint32_t)smc_ret.r3 != desc_count * sizeof(*desc)) {
                TRACEF("fragment length %ld, contains partial descriptor\n",
                       smc_ret.r3);
                ret = ERR_IO;
                goto err_bad_data;
            }
        }

        /* Copy one descriptor into object */
        obj->ext_mem_obj.page_runs[ri].paddr = desc[di].address;
        if (desc[di].page_count < 1 ||
            ((size_t)desc[di].page_count > (SIZE_MAX / FFA_PAGE_SIZE))) {
            TRACEF("bad page count 0x%x at %d/%d %d/%zd\n", desc[di].page_count,
                   ri, address_range_descriptor_count, di, desc_count);
            ret = ERR_IO;
            goto err_bad_data;
        }
        obj->ext_mem_obj.page_runs[ri].size =
                (size_t)desc[di].page_count * FFA_PAGE_SIZE;
        LTRACEF("added ns memory at 0x%lx, size %zd, %d/%d %d/%zd\n",
                obj->ext_mem_obj.page_runs[ri].paddr,
                obj->ext_mem_obj.page_runs[ri].size, ri,
                address_range_descriptor_count, di, desc_count);
    }

    /* No lock needed as the object is not yet visible to anyone else */
    obj_ref_transfer(obj_ref, &tmp_obj_ref);
    *objp = &obj->ext_mem_obj.vmm_obj;

    return 0;

err_mem_frag_rx:
err_bad_data:
    DEBUG_ASSERT(obj_ref_active(&tmp_obj_ref));
    vmm_obj_del_ref(&obj->ext_mem_obj.vmm_obj, &tmp_obj_ref);

    return ret;
}

/*
 * ext_mem_get_vmm_obj - Lookup or create shared memory object.
 * @client_id:  Id of external entity where the memory originated.
 * @mem_obj_id: Id of shared memory opbject to lookup and return.
 * @size:       Size hint for object.
 * @objp:       Pointer to return object in.
 * @obj_ref:    Reference to *@objp.
 *
 * Call SPM/Hypervisor to retrieve memory region or extract address and
 * attributes from id for old clients.
 */
status_t ext_mem_get_vmm_obj(ext_mem_client_id_t client_id,
                             ext_mem_obj_id_t mem_obj_id,
                             uint64_t tag,
                             size_t size,
                             struct vmm_obj** objp,
                             struct obj_ref* obj_ref) {
    int ret;

    if (client_id == 0 && tag == 0 &&
        sm_get_api_version() < TRUSTY_API_VERSION_MEM_OBJ) {
        /* If client is not running under a hypervisor allow using old api. */
        return sm_mem_compat_get_vmm_obj(client_id, mem_obj_id, size, objp,
                                         obj_ref);
    }

    mutex_acquire(&sm_mem_ffa_lock);

    ret = ffa_mem_retrieve((uint16_t)client_id, mem_obj_id, tag, objp, obj_ref);

    mutex_release(&sm_mem_ffa_lock);

    return ret;
}

/**
 * shared_mem_init - Connect to SPM/Hypervisor.
 * @level:  Unused.
 *
 * Allocate message buffers and register them with the SPM/Hypervisor. Also
 * retrieve FF-A endpoint ID.
 */
static void shared_mem_init(uint level) {
    paddr_t tx_paddr;
    paddr_t rx_paddr;
    void* tx_vaddr;
    void* rx_vaddr;
    size_t buf_size_shift;
    size_t buf_page_count;
    struct list_node page_list = LIST_INITIAL_VALUE(page_list);
    size_t count;
    struct smc_ret8 smc_ret;

    /* Get FF-A version and check if it is compatible */
    smc_ret = smc8(SMC_FC_FFA_VERSION, FFA_CURRENT_VERSION, 0, 0, 0, 0, 0, 0);
    if (FFA_VERSION_TO_MAJOR((uint32_t)smc_ret.r0) !=
        FFA_CURRENT_VERSION_MAJOR) {
        /* TODO: support more than one (minor) version. */
        TRACEF("%s: unsupported FF-A version 0x%lx, expected 0x%x\n", __func__,
               smc_ret.r0, FFA_CURRENT_VERSION);
        goto err_version;
    }

    /* Check that SMC_FC_FFA_MEM_SHARE is implemented */
    smc_ret = smc8(SMC_FC_FFA_FEATURES, SMC_FC_FFA_MEM_SHARE, 0, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("%s: SMC_FC_FFA_FEATURES(SMC_FC_FFA_MEM_SHARE) failed 0x%lx 0x%lx 0x%lx\n",
               __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
        goto err_features;
    }

    smc_ret = smc8(SMC_FC_FFA_FEATURES, SMC_FC_FFA_MEM_RETRIEVE_REQ,
                   FFA_FEATURES2_MEM_RETRIEVE_REQ_NS_BIT, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("%s: SMC_FC_FFA_FEATURES(SMC_FC_FFA_MEM_RETRIEVE_REQ) failed 0x%lx 0x%lx 0x%lx\n",
               __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
        goto err_features;
    }

    /* Whether NS bit is filled in on RETRIEVE */
    supports_ns_bit = !!(smc_ret.r2 & FFA_FEATURES2_MEM_RETRIEVE_REQ_NS_BIT);

    if ((smc_ret.r3 & FFA_FEATURES3_MEM_RETRIEVE_REQ_REFCOUNT_MASK) < 63) {
        /*
         * Expect 64 bit reference count. If we don't have it, future calls to
         * SMC_FC_FFA_MEM_RETRIEVE_REQ can fail if we receive the same handle
         * multile times. Warn about this, but don't return an error as we only
         * receive each handle once in the typical case.
         */
        TRACEF("%s: Warning SMC_FC_FFA_MEM_RETRIEVE_REQ does not have 64 bit reference count (%ld)\n",
               __func__, (smc_ret.r3 & 0xff) + 1);
    }

    smc_ret = smc8(SMC_FC_FFA_FEATURES, SMC_FC_FFA_RXTX_MAP, 0, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("%s: SMC_FC_FFA_FEATURES(SMC_FC_FFA_RXTX_MAP) failed 0x%lx 0x%lx 0x%lx\n",
               __func__, smc_ret.r0, smc_ret.r1, smc_ret.r2);
        goto err_features;
    }

    switch (smc_ret.r2 & FFA_FEATURES2_RXTX_MAP_BUF_SIZE_MASK) {
    case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_4K:
        buf_size_shift = 12;
        break;
    case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_64K:
        buf_size_shift = 16;
        break;
    case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_16K:
        buf_size_shift = 14;
        break;
    default:
        TRACEF("%s: Invalid FFA_RXTX_MAP buf size value\n", __func__);
        goto err_features;
    }
    ffa_buf_size = 1U << buf_size_shift;
    buf_page_count = DIV_ROUND_UP(ffa_buf_size, PAGE_SIZE);

    /* Get FF-A id. */
    smc_ret = smc8(SMC_FC_FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("%s: SMC_FC_FFA_ID_GET failed 0x%lx 0x%lx 0x%lx\n", __func__,
               smc_ret.r0, smc_ret.r1, smc_ret.r2);
        goto err_id_get;
    }
    ffa_local_id = smc_ret.r2;

    ASSERT((ffa_buf_size % FFA_PAGE_SIZE) == 0);

    count = pmm_alloc_contiguous(buf_page_count, buf_size_shift, &tx_paddr,
                                 &page_list);
    if (count != buf_page_count) {
        goto err_alloc_tx;
    }
    tx_vaddr = paddr_to_kvaddr(tx_paddr);
    ASSERT(tx_vaddr);

    count = pmm_alloc_contiguous(buf_page_count, buf_size_shift, &rx_paddr,
                                 &page_list);
    if (count != buf_page_count) {
        goto err_alloc_tx;
    }
    rx_vaddr = paddr_to_kvaddr(rx_paddr);
    ASSERT(rx_vaddr);

    smc_ret = smc8(SMC_FC_FFA_RXTX_MAP, tx_paddr, rx_paddr,
                   ffa_buf_size / FFA_PAGE_SIZE, 0, 0, 0, 0);
    if ((uint32_t)smc_ret.r0 != SMC_FC_FFA_SUCCESS) {
        TRACEF("failed to map tx @ 0x%lx, rx @ 0x%lx, page count 0x%zx\n",
               tx_paddr, rx_paddr, ffa_buf_size / FFA_PAGE_SIZE);
        goto err_rxtx_map;
    }
    mutex_acquire(&sm_mem_ffa_lock);
    ffa_tx = tx_vaddr;
    ffa_rx = rx_vaddr;
    mutex_release(&sm_mem_ffa_lock);

    return;

err_rxtx_map:
err_alloc_rx:
    pmm_free(&page_list);
err_alloc_tx:
err_id_get:
err_features:
err_version:
    TRACEF("failed to initialize FF-A\n");
    if (sm_check_and_lock_api_version(TRUSTY_API_VERSION_MEM_OBJ)) {
        panic("shared_mem_init failed after mem_obj version selected\n");
    }
}

LK_INIT_HOOK(shared_mem, shared_mem_init, LK_INIT_LEVEL_APPS);
