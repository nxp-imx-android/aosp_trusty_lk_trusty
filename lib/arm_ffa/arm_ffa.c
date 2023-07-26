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

#include <assert.h>
#include <err.h>
#include <interface/arm_ffa/arm_ffa.h>
#include <inttypes.h>
#include <kernel/mutex.h>
#include <kernel/vm.h>
#include <lib/arm_ffa/arm_ffa.h>
#include <lib/smc/smc.h>
#include <lk/init.h>
#include <lk/macros.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>

static bool arm_ffa_init_is_success = false;
uint16_t ffa_local_id;
size_t ffa_buf_size;
bool supports_ns_bit = false;
void* ffa_tx;
void* ffa_rx;

static mutex_t ffa_rxtx_buffer_lock = MUTEX_INITIAL_VALUE(ffa_rxtx_buffer_lock);

bool arm_ffa_is_init(void) {
    return arm_ffa_init_is_success;
}

static status_t arm_ffa_call_id_get(uint16_t* id) {
    struct smc_ret8 smc_ret;

    smc_ret = smc8(SMC_FC_FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0);

    switch (smc_ret.r0) {
    case SMC_FC_FFA_SUCCESS:
    case SMC_FC64_FFA_SUCCESS:
        if (smc_ret.r2 & ~0xFFFFUL) {
            TRACEF("Unexpected FFA_ID_GET result: %lx\n", smc_ret.r2);
            return ERR_NOT_VALID;
        }
        *id = (uint16_t)(smc_ret.r2 & 0xFFFF);
        return NO_ERROR;

    case SMC_FC_FFA_ERROR:
        if (smc_ret.r2 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
            return ERR_NOT_SUPPORTED;
        } else {
            TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
            return ERR_NOT_VALID;
        }

    default:
        TRACEF("Unexpected FFA SMC: %lx\n", smc_ret.r0);
        return ERR_NOT_VALID;
    }
}

static status_t arm_ffa_call_version(uint16_t major,
                                     uint16_t minor,
                                     uint16_t* major_ret,
                                     uint16_t* minor_ret) {
    struct smc_ret8 smc_ret;

    uint32_t version = FFA_VERSION(major, minor);
    /* Bit 31 must be cleared. */
    ASSERT(!(version >> 31));
    smc_ret = smc8(SMC_FC_FFA_VERSION, version, 0, 0, 0, 0, 0, 0);
    if (smc_ret.r0 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
        return ERR_NOT_SUPPORTED;
    }
    *major_ret = FFA_VERSION_TO_MAJOR(smc_ret.r0);
    *minor_ret = FFA_VERSION_TO_MINOR(smc_ret.r0);

    return NO_ERROR;
}

/* TODO: When adding support for FFA version 1.1 feature ids should be added. */
static status_t arm_ffa_call_features(ulong id,
                                      bool request_ns_bit,
                                      bool* is_implemented,
                                      ffa_features2_t* features2,
                                      ffa_features3_t* features3) {
    struct smc_ret8 smc_ret;

    ASSERT(is_implemented);
    ASSERT(!request_ns_bit || id == SMC_FC_FFA_MEM_RETRIEVE_REQ ||
           id == SMC_FC64_FFA_MEM_RETRIEVE_REQ);

    /* Allow querying for NS bit - see b/292455218 */
#if 0
    /*
     * The NS bit input parameter must be zero (MBZ) in FF-A version 1.0.
     * This still requests use of the NS bit in the FFA_MEM_RETRIEVE_RESP ABI.
     * In FF-A version 1.1 the input parameter NS bit must be set to request
     * its use.  See section 10.10.4.1.1, Discovery of NS bit usage, in the
     * FF-A 1.1 BETA specification.
     * (https://developer.arm.com/documentation/den0077/c)
     */
    request_ns_bit = 0;
#endif

    smc_ret = smc8(SMC_FC_FFA_FEATURES, id,
                   request_ns_bit ? FFA_FEATURES2_MEM_RETRIEVE_REQ_NS_BIT : 0,
                   0, 0, 0, 0, 0);

    switch (smc_ret.r0) {
    case SMC_FC_FFA_SUCCESS:
    case SMC_FC64_FFA_SUCCESS:
        *is_implemented = true;
        if (features2) {
            *features2 = (ffa_features2_t)smc_ret.r2;
        }
        if (features3) {
            *features3 = (ffa_features3_t)smc_ret.r3;
        }
        return NO_ERROR;

    case SMC_FC_FFA_ERROR:
        if (smc_ret.r2 == (ulong)FFA_ERROR_NOT_SUPPORTED) {
            *is_implemented = false;
            return NO_ERROR;
        } else {
            TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
            return ERR_NOT_VALID;
        }

    default:
        TRACEF("Unexpected FFA SMC: %lx\n", smc_ret.r0);
        return ERR_NOT_VALID;
    }
}

static status_t arm_ffa_call_mem_relinquish(
        uint64_t handle,
        uint32_t flags,
        uint32_t endpoint_count,
        const ffa_endpoint_id16_t* endpoints) {
    struct smc_ret8 smc_ret;
    struct ffa_mem_relinquish_descriptor* req = ffa_tx;

    if (!req) {
        TRACEF("ERROR: no FF-A tx buffer\n");
        return ERR_NOT_CONFIGURED;
    }
    ASSERT(endpoint_count <=
           (ffa_buf_size - sizeof(struct ffa_mem_relinquish_descriptor)) /
                   sizeof(ffa_endpoint_id16_t));

    mutex_acquire(&ffa_rxtx_buffer_lock);

    req->handle = handle;
    req->flags = flags;
    req->endpoint_count = endpoint_count;

    memcpy(req->endpoint_array, endpoints,
           endpoint_count * sizeof(ffa_endpoint_id16_t));

    smc_ret = smc8(SMC_FC_FFA_MEM_RELINQUISH, 0, 0, 0, 0, 0, 0, 0);

    mutex_release(&ffa_rxtx_buffer_lock);

    switch (smc_ret.r0) {
    case SMC_FC_FFA_SUCCESS:
    case SMC_FC64_FFA_SUCCESS:
        return NO_ERROR;

    case SMC_FC_FFA_ERROR:
        switch ((int)smc_ret.r2) {
        case FFA_ERROR_NOT_SUPPORTED:
            return ERR_NOT_SUPPORTED;
        case FFA_ERROR_INVALID_PARAMETERS:
            return ERR_INVALID_ARGS;
        case FFA_ERROR_NO_MEMORY:
            return ERR_NO_MEMORY;
        case FFA_ERROR_DENIED:
            return ERR_BAD_STATE;
        case FFA_ERROR_ABORTED:
            return ERR_CANCELLED;
        default:
            TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
            return ERR_NOT_VALID;
        }
    default:
        TRACEF("Unexpected FFA SMC: %lx\n", smc_ret.r0);
        return ERR_NOT_VALID;
    }
}

static status_t arm_ffa_call_rxtx_map(paddr_t tx_paddr,
                                      paddr_t rx_paddr,
                                      size_t page_count) {
    struct smc_ret8 smc_ret;

    /* Page count specified in bits [0:5] */
    ASSERT(page_count);
    ASSERT(page_count < (1 << 6));

#if ARCH_ARM64
    smc_ret = smc8(SMC_FC64_FFA_RXTX_MAP, tx_paddr, rx_paddr, page_count, 0, 0,
                   0, 0);
#else
    smc_ret = smc8(SMC_FC_FFA_RXTX_MAP, tx_paddr, rx_paddr, page_count, 0, 0, 0,
                   0);
#endif
    switch (smc_ret.r0) {
    case SMC_FC_FFA_SUCCESS:
    case SMC_FC64_FFA_SUCCESS:
        return NO_ERROR;

    case SMC_FC_FFA_ERROR:
        switch ((int)smc_ret.r2) {
        case FFA_ERROR_NOT_SUPPORTED:
            return ERR_NOT_SUPPORTED;
        case FFA_ERROR_INVALID_PARAMETERS:
            return ERR_INVALID_ARGS;
        case FFA_ERROR_NO_MEMORY:
            return ERR_NO_MEMORY;
        case FFA_ERROR_DENIED:
            return ERR_ALREADY_EXISTS;
        default:
            TRACEF("Unexpected FFA_ERROR: %lx\n", smc_ret.r2);
            return ERR_NOT_VALID;
        }
    default:
        TRACEF("Unexpected FFA SMC: %lx\n", smc_ret.r0);
        return ERR_NOT_VALID;
    }
}

static status_t arm_ffa_rxtx_map_is_implemented(bool* is_implemented,
                                                size_t* buf_size_log2) {
    ffa_features2_t features2;
    bool is_implemented_val = false;
    status_t res;

    ASSERT(is_implemented);
#if ARCH_ARM64
    res = arm_ffa_call_features(SMC_FC64_FFA_RXTX_MAP, 0, &is_implemented_val,
                                &features2, NULL);
#else
    res = arm_ffa_call_features(SMC_FC_FFA_RXTX_MAP, 0, &is_implemented_val,
                                &features2, NULL);
#endif
    if (res != NO_ERROR) {
        TRACEF("Failed to query for feature FFA_RXTX_MAP, err = %d\n", res);
        return res;
    }
    if (!is_implemented_val) {
        *is_implemented = false;
        return NO_ERROR;
    }
    if (buf_size_log2) {
        ulong buf_size_id = features2 & FFA_FEATURES2_RXTX_MAP_BUF_SIZE_MASK;
        switch (buf_size_id) {
        case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_4K:
            *buf_size_log2 = 12;
            break;
        case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_16K:
            *buf_size_log2 = 14;
            break;
        case FFA_FEATURES2_RXTX_MAP_BUF_SIZE_64K:
            *buf_size_log2 = 16;
            break;
        default:
            TRACEF("Unexpected rxtx buffer size identifier: %lx\n",
                   buf_size_id);
            return ERR_NOT_VALID;
        }
    }

    *is_implemented = true;
    return NO_ERROR;
}

static status_t arm_ffa_mem_retrieve_req_is_implemented(
        bool request_ns_bit,
        bool* is_implemented,
        bool* dyn_alloc_supp,
        bool* has_ns_bit,
        size_t* ref_count_num_bits) {
    ffa_features2_t features2;
    ffa_features3_t features3;
    bool is_implemented_val = false;
    status_t res;

    ASSERT(is_implemented);

    res = arm_ffa_call_features(SMC_FC_FFA_MEM_RETRIEVE_REQ, request_ns_bit,
                                &is_implemented_val, &features2, &features3);
    if (res != NO_ERROR) {
        TRACEF("Failed to query for feature FFA_MEM_RETRIEVE_REQ, err = %d\n",
               res);
        return res;
    }
    if (!is_implemented_val) {
        *is_implemented = false;
        return NO_ERROR;
    }
    if (dyn_alloc_supp) {
        *dyn_alloc_supp = !!(features2 & FFA_FEATURES2_MEM_DYNAMIC_BUFFER);
    }
    if (has_ns_bit) {
        *has_ns_bit = !!(features2 & FFA_FEATURES2_MEM_RETRIEVE_REQ_NS_BIT);
    }
    if (ref_count_num_bits) {
        *ref_count_num_bits =
                (features3 & FFA_FEATURES3_MEM_RETRIEVE_REQ_REFCOUNT_MASK) + 1;
    }
    *is_implemented = true;
    return NO_ERROR;
}

status_t arm_ffa_mem_relinquish(uint64_t handle) {
    status_t res;

    /* As flags are set to 0 no request to zero the memory is made */
    res = arm_ffa_call_mem_relinquish(handle, 0, 1, &ffa_local_id);
    if (res != NO_ERROR) {
        TRACEF("Failed to relinquish memory region, err = %d\n", res);
    }

    return res;
}

static status_t arm_ffa_setup(void) {
    status_t res;
    uint16_t ver_major_ret;
    uint16_t ver_minor_ret;
    bool is_implemented;
    size_t buf_size_log2;
    size_t ref_count_num_bits;
    size_t arch_page_count;
    size_t ffa_page_count;
    size_t count;
    paddr_t tx_paddr;
    paddr_t rx_paddr;
    void* tx_vaddr;
    void* rx_vaddr;
    struct list_node page_list = LIST_INITIAL_VALUE(page_list);

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

    res = arm_ffa_call_id_get(&ffa_local_id);
    if (res != NO_ERROR) {
        TRACEF("Failed to get FF-A partition id (err=%d)\n", res);
        return res;
    }

    res = arm_ffa_rxtx_map_is_implemented(&is_implemented, &buf_size_log2);
    if (res != NO_ERROR) {
        TRACEF("Error checking if FFA_RXTX_MAP is implemented (err=%d)\n", res);
        return res;
    }
    if (!is_implemented) {
        TRACEF("FFA_RXTX_MAP is not implemented\n");
        return ERR_NOT_SUPPORTED;
    }

    res = arm_ffa_mem_retrieve_req_is_implemented(
            true, &is_implemented, NULL, &supports_ns_bit, &ref_count_num_bits);
    if (res != NO_ERROR) {
        TRACEF("Error checking if FFA_MEM_RETRIEVE_REQ is implemented (err=%d)\n",
               res);
        return res;
    }
    if (!is_implemented) {
        TRACEF("FFA_MEM_RETRIEVE_REQ is not implemented\n");
        return ERR_NOT_SUPPORTED;
    }

    if (ref_count_num_bits < 64) {
        /*
         * Expect 64 bit reference count. If we don't have it, future calls to
         * SMC_FC_FFA_MEM_RETRIEVE_REQ can fail if we receive the same handle
         * multiple times. Warn about this, but don't return an error as we only
         * receive each handle once in the typical case.
         */
        TRACEF("Warning FFA_MEM_RETRIEVE_REQ does not have 64 bit reference count (%zu)\n",
               ref_count_num_bits);
    }

    ffa_buf_size = 1U << buf_size_log2;
    ASSERT((ffa_buf_size % FFA_PAGE_SIZE) == 0);

    arch_page_count = DIV_ROUND_UP(ffa_buf_size, PAGE_SIZE);
    ffa_page_count = ffa_buf_size / FFA_PAGE_SIZE;
    count = pmm_alloc_contiguous(arch_page_count, buf_size_log2, &tx_paddr,
                                 &page_list);
    if (count != arch_page_count) {
        TRACEF("Failed to allocate tx buffer %zx!=%zx\n", count,
               arch_page_count);
        res = ERR_NO_MEMORY;
        goto err_alloc_tx;
    }
    tx_vaddr = paddr_to_kvaddr(tx_paddr);
    ASSERT(tx_vaddr);

    count = pmm_alloc_contiguous(arch_page_count, buf_size_log2, &rx_paddr,
                                 &page_list);
    if (count != arch_page_count) {
        TRACEF("Failed to allocate rx buffer %zx!=%zx\n", count,
               arch_page_count);
        res = ERR_NO_MEMORY;
        goto err_alloc_rx;
    }
    rx_vaddr = paddr_to_kvaddr(rx_paddr);
    ASSERT(rx_vaddr);

    res = arm_ffa_call_rxtx_map(tx_paddr, rx_paddr, ffa_page_count);
    if (res != NO_ERROR) {
        TRACEF("Failed to map tx @ %p, rx @ %p, page count 0x%zx (err=%d)\n",
               (void*)tx_paddr, (void*)rx_paddr, ffa_page_count, res);
        goto err_rxtx_map;
    }

    ffa_tx = tx_vaddr;
    ffa_rx = rx_vaddr;

    return res;

err_rxtx_map:
err_alloc_rx:
    pmm_free(&page_list);
err_alloc_tx:
    /* pmm_alloc_contiguous leaves the page list unchanged on failure */

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
