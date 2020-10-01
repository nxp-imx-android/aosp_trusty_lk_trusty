/*
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
 * Copyright (c) 2013, Google, Inc. All rights reserved
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

#include <lib/backtrace/backtrace.h>
#include <lib/trusty/elf.h>
#include <lib/trusty/trusty_app.h>

#include <arch.h>
#include <assert.h>
#include <compiler.h>
#include <debug.h>
#include <err.h>
#include <kernel/event.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <lib/rand/rand.h>
#include <lib/trusty/ipc.h>
#include <lk/init.h>
#include <malloc.h>
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <uapi/trusty_app_manifest_types.h>

#define LOCAL_TRACE 0

#define DEFAULT_MGMT_FLAGS TRUSTY_APP_MGMT_FLAGS_NONE

#define TRUSTY_APP_RESTART_TIMEOUT_SUCCESS (10ULL * 1000ULL * 1000ULL)
#define TRUSTY_APP_RESTART_TIMEOUT_FAILURE (5ULL * 1000ULL * 1000ULL * 1000ULL)

#ifdef TRUSTY_APP_STACK_TOP
#error "TRUSTY_APP_STACK_TOP is no longer respected"
#endif

/* Don't allow NULL to be a valid userspace address */
STATIC_ASSERT(USER_ASPACE_BASE != 0);

#ifndef DEFAULT_HEAP_SIZE
#define DEFAULT_HEAP_SIZE (4 * PAGE_SIZE)
#endif

#define PAGE_MASK (PAGE_SIZE - 1)

#undef ELF_64BIT
#if !IS_64BIT || USER_32BIT
#define ELF_64BIT 0
#else
#define ELF_64BIT 1
#endif

#if ELF_64BIT
#define ELF_SHDR Elf64_Shdr
#define ELF_EHDR Elf64_Ehdr
#define ELF_PHDR Elf64_Phdr
#define Elf_Addr Elf64_Addr

#define PRIxELF_Off "llx"
#define PRIuELF_Size "llu"
#define PRIxELF_Size "llx"
#define PRIxELF_Addr "llx"
#define PRIxELF_Flags "llx"
#else
#define ELF_SHDR Elf32_Shdr
#define ELF_EHDR Elf32_Ehdr
#define ELF_PHDR Elf32_Phdr
#define Elf_Addr Elf32_Addr

#define PRIxELF_Off "x"
#define PRIuELF_Size "u"
#define PRIxELF_Size "x"
#define PRIxELF_Addr "x"
#define PRIxELF_Flags "x"
#endif

static u_int trusty_next_app_id;
static struct list_node trusty_app_list = LIST_INITIAL_VALUE(trusty_app_list);

/* These symbols are linker defined and are declared as unsized arrays to
 * prevent compiler(clang) optimizations that break when the list is empty and
 * the symbols alias
 */
extern struct trusty_app_img __trusty_app_list_start[];
extern struct trusty_app_img __trusty_app_list_end[];

static bool apps_started;
static mutex_t apps_lock = MUTEX_INITIAL_VALUE(apps_lock);
static struct list_node app_notifier_list =
        LIST_INITIAL_VALUE(app_notifier_list);
uint als_slot_cnt;
static event_t app_mgr_event =
        EVENT_INITIAL_VALUE(app_mgr_event, 0, EVENT_FLAG_AUTOUNSIGNAL);

#define PRINT_TRUSTY_APP_UUID(tid, u)                                          \
    dprintf(SPEW,                                                              \
            "trusty_app %d uuid: 0x%x 0x%x 0x%x 0x%x%x 0x%x%x%x%x%x%x\n", tid, \
            (u)->time_low, (u)->time_mid, (u)->time_hi_and_version,            \
            (u)->clock_seq_and_node[0], (u)->clock_seq_and_node[1],            \
            (u)->clock_seq_and_node[2], (u)->clock_seq_and_node[3],            \
            (u)->clock_seq_and_node[4], (u)->clock_seq_and_node[5],            \
            (u)->clock_seq_and_node[6], (u)->clock_seq_and_node[7]);

static bool address_range_within_bounds(const void* range_start,
                                        size_t range_size,
                                        const void* lower_bound,
                                        const void* upper_bound) {
    const void* range_end = range_start + range_size;

    if (upper_bound < lower_bound) {
        LTRACEF("upper bound(%p) is below upper bound(%p)\n", upper_bound,
                lower_bound);
        return false;
    }

    if (range_end < range_start) {
        LTRACEF("Range overflows. start:%p size:%zd end:%p\n", range_start,
                range_size, range_end);
        return false;
    }

    if (range_start < lower_bound) {
        LTRACEF("Range starts(%p) before lower bound(%p)\n", range_start,
                lower_bound);
        return false;
    }

    if (range_end > upper_bound) {
        LTRACEF("Range ends(%p) past upper bound(%p)\n", range_end,
                upper_bound);
        return false;
    }

    return true;
}

static inline bool address_range_within_img(
        const void* range_start,
        size_t range_size,
        const struct trusty_app_img* appimg) {
    return address_range_within_bounds(range_start, range_size,
                                       (const void*)appimg->img_start,
                                       (const void*)appimg->img_end);
}

static bool compare_section_name(ELF_SHDR* shdr,
                                 const char* name,
                                 char* shstbl,
                                 uint32_t shstbl_size) {
    return shstbl_size - shdr->sh_name > strlen(name) &&
           !strcmp(shstbl + shdr->sh_name, name);
}

static void finalize_registration(void) {
    mutex_acquire(&apps_lock);
    apps_started = true;
    mutex_release(&apps_lock);
}

status_t trusty_register_app_notifier(struct trusty_app_notifier* n) {
    status_t ret = NO_ERROR;

    mutex_acquire(&apps_lock);
    if (!apps_started)
        list_add_tail(&app_notifier_list, &n->node);
    else
        ret = ERR_ALREADY_STARTED;
    mutex_release(&apps_lock);
    return ret;
}

int trusty_als_alloc_slot(void) {
    int ret;

    mutex_acquire(&apps_lock);
    if (!apps_started)
        ret = ++als_slot_cnt;
    else
        ret = ERR_ALREADY_STARTED;
    mutex_release(&apps_lock);
    return ret;
}

#if ELF_64BIT
#define ENTER_USPACE_FLAGS 0
#else
#define ENTER_USPACE_FLAGS ARCH_ENTER_USPACE_FLAG_32BIT
#endif

/*
 * Allocate space on the user stack.
 */
static user_addr_t user_stack_alloc(struct trusty_thread* trusty_thread,
                                    user_size_t data_len,
                                    user_size_t align,
                                    user_addr_t* stack_ptr) {
    user_addr_t ptr = round_down(*stack_ptr - data_len, align);
    if (ptr < trusty_thread->stack_start - trusty_thread->stack_size) {
        panic("stack underflow while initializing user space\n");
    }
    *stack_ptr = ptr;
    return ptr;
}

/*
 * Copy data to a preallocated spot on the user stack. This should not fail.
 */
static void copy_to_user_stack(user_addr_t dst_ptr,
                               const void* data,
                               user_size_t data_len) {
    int ret = copy_to_user(dst_ptr, data, data_len);
    if (ret) {
        panic("copy_to_user failed %d\n", ret);
    }
}

/*
 * Allocate space on the user stack and fill it with data.
 */
static user_addr_t add_to_user_stack(struct trusty_thread* trusty_thread,
                                     const void* data,
                                     user_size_t data_len,
                                     user_size_t align,
                                     user_addr_t* stack_ptr) {
    user_addr_t ptr =
            user_stack_alloc(trusty_thread, data_len, align, stack_ptr);
    copy_to_user_stack(ptr, data, data_len);
    return ptr;
}

/* TODO share a common header file. */
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_RANDOM 25

/*
 * Pass data to libc on the user stack.
 * Prevent inlining so that the stack allocations inside this function don't get
 * trapped on the kernel stack.
 */
static __NO_INLINE user_addr_t
trusty_thread_write_elf_tables(struct trusty_thread* trusty_thread,
                               user_addr_t* stack_ptr,
                               vaddr_t load_bias) {
    /* Construct the elf tables in reverse order - the stack grows down. */

    /*
     * sixteen random bytes
     */
    uint8_t rand_bytes[16] = {0};
    rand_get_bytes(rand_bytes, sizeof(rand_bytes));
    user_addr_t rand_bytes_addr = add_to_user_stack(
            trusty_thread, rand_bytes, sizeof(rand_bytes), 1, stack_ptr);
    /* auxv */
    user_addr_t auxv[] = {
            AT_PAGESZ, PAGE_SIZE,       AT_BASE, load_bias,
            AT_RANDOM, rand_bytes_addr, 0,
    };
    add_to_user_stack(trusty_thread, auxv, sizeof(auxv), sizeof(user_addr_t),
                      stack_ptr);

    /* envp - for layout compatibility, unused */
    user_addr_t envp[] = {
            0,
    };
    add_to_user_stack(trusty_thread, envp, sizeof(envp), sizeof(user_addr_t),
                      stack_ptr);

    /* argv - for layout compatibility, unused */
    user_addr_t argv[] = {
            0,
    };
    add_to_user_stack(trusty_thread, argv, sizeof(argv), sizeof(user_addr_t),
                      stack_ptr);

    /* argc */
    user_addr_t argc = 0;
    user_addr_t argc_ptr = add_to_user_stack(trusty_thread, &argc, sizeof(argc),
                                             sizeof(user_addr_t), stack_ptr);

    return argc_ptr;
}

static int trusty_thread_startup(void* arg) {
    struct trusty_thread* trusty_thread = current_trusty_thread();

    vmm_set_active_aspace(trusty_thread->app->aspace);

    user_addr_t stack_ptr = trusty_thread->stack_start;
    user_addr_t elf_tables = trusty_thread_write_elf_tables(
            trusty_thread, &stack_ptr, trusty_thread->app->load_bias);

    thread_sleep_until_ns(trusty_thread->app->min_start_time);

    arch_enter_uspace(trusty_thread->entry, stack_ptr, ENTER_USPACE_FLAGS,
                      elf_tables);

    __UNREACHABLE;
}

static status_t trusty_thread_start(struct trusty_thread* trusty_thread) {
    DEBUG_ASSERT(trusty_thread && trusty_thread->thread);

    return thread_resume(trusty_thread->thread);
}

void __NO_RETURN trusty_thread_exit(int retcode) {
    struct trusty_thread* trusty_thread = current_trusty_thread();
    vaddr_t stack_bot;

    ASSERT(trusty_thread);

    stack_bot = trusty_thread->stack_start - trusty_thread->stack_size;

    vmm_free_region(trusty_thread->app->aspace, stack_bot);

    thread_exit(retcode);
}

static struct trusty_thread* trusty_thread_create(
        const char* name,
        vaddr_t entry,
        int priority,
        size_t stack_size,
        struct trusty_app* trusty_app) {
    struct trusty_thread* trusty_thread;
    status_t err;
    vaddr_t stack_bot = 0;
    stack_size = round_up(stack_size, PAGE_SIZE);

    trusty_thread = calloc(1, sizeof(struct trusty_thread));
    if (!trusty_thread)
        return NULL;

    err = vmm_alloc(trusty_app->aspace, "stack", stack_size, (void**)&stack_bot,
                    PAGE_SIZE_SHIFT, 0,
                    ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);
    if (err != NO_ERROR) {
        dprintf(CRITICAL,
                "failed(%d) to create thread stack(0x%lx) for app %u\n", err,
                stack_bot, trusty_app->app_id);
        goto err_stack;
    }

    trusty_thread->thread = thread_create(name, trusty_thread_startup, NULL,
                                          priority, DEFAULT_STACK_SIZE);
    if (!trusty_thread->thread)
        goto err_thread;

    trusty_thread->app = trusty_app;
    trusty_thread->entry = entry;
    trusty_thread->stack_start = stack_bot + stack_size;
    trusty_thread->stack_size = stack_size;
    thread_tls_set(trusty_thread->thread, TLS_ENTRY_TRUSTY,
                   (uintptr_t)trusty_thread);

    return trusty_thread;

err_thread:
    vmm_free_region(trusty_app->aspace, stack_bot);
err_stack:
    free(trusty_thread);
    return NULL;
}

/* Must be called with the apps_lock held */
static struct manifest_port_entry* find_manifest_port_entry_locked(
        const char* port_path,
        struct trusty_app** app_out) {
    struct trusty_app* app;
    struct manifest_port_entry* entry;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));

    list_for_every_entry(&trusty_app_list, app, struct trusty_app, node) {
        list_for_every_entry(&app->props.port_entry_list, entry,
                             struct manifest_port_entry, node) {
            if (!strncmp(port_path, entry->path, entry->path_len)) {
                if (app_out)
                    *app_out = app;

                return entry;
            }
        }
    }

    return NULL;
}
/* Must be called with the apps_lock held */
static struct trusty_app* trusty_app_find_by_uuid_locked(uuid_t* uuid) {
    struct trusty_app* app;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));

    list_for_every_entry(&trusty_app_list, app, struct trusty_app, node) {
        if (!memcmp(&app->props.uuid, uuid, sizeof(uuid_t)))
            return app;
    }

    return NULL;
}

static status_t get_app_manifest_config_data(struct trusty_app* trusty_app,
                                             char** manifest_data,
                                             size_t* size) {
    struct trusty_app_img* app_img;

    app_img = trusty_app->app_img;
    if (!app_img->manifest_start) {
        dprintf(CRITICAL, "manifest section header not found\n");
        return ERR_NOT_VALID;
    }

    /* manifest data is embedded in kernel */
    dprintf(SPEW, "trusty app manifest: start %p size 0x%08lx end %p\n",
            (void*)app_img->manifest_start,
            app_img->manifest_end - app_img->manifest_start,
            (void*)app_img->manifest_end);

    *size = trusty_app->app_img->manifest_end -
            trusty_app->app_img->manifest_start;
    *manifest_data = (char*)(trusty_app->app_img->manifest_start);

    return NO_ERROR;
}

static status_t load_app_config_options(struct trusty_app* trusty_app) {
    char* manifest_data;
    size_t manifest_size;
    const char* port_name;
    uint32_t port_name_size;
    uint32_t port_flags;
    uint32_t mmio_id, mmio_arch_mmu_flags;
    uint64_t mmio_offset, mmio_size;
    struct manifest_mmio_entry* mmio_entry;
    paddr_t tmp_paddr;
    u_int *config_blob, config_blob_size;
    u_int i;
    status_t ret;
    struct manifest_port_entry* entry;

    /* init default config options before parsing manifest */
    trusty_app->props.min_heap_size = DEFAULT_HEAP_SIZE;
    trusty_app->props.min_stack_size = DEFAULT_STACK_SIZE;
    trusty_app->props.mgmt_flags = DEFAULT_MGMT_FLAGS;

    manifest_data = NULL;
    manifest_size = 0;
    ret = get_app_manifest_config_data(trusty_app, &manifest_data,
                                       &manifest_size);
    if (ret != NO_ERROR) {
        return ERR_NOT_VALID;
    }

    /* have to at least have a valid UUID */
    if (manifest_size < sizeof(uuid_t)) {
        dprintf(CRITICAL, "app %u manifest too small %zu\n", trusty_app->app_id,
                manifest_size);
        return ERR_NOT_VALID;
    }

    memcpy(&trusty_app->props.uuid, (uuid_t*)manifest_data, sizeof(uuid_t));

    PRINT_TRUSTY_APP_UUID(trusty_app->app_id, &trusty_app->props.uuid);

    if (trusty_app_find_by_uuid_locked(&trusty_app->props.uuid)) {
        dprintf(CRITICAL, "app already registered\n");
        return ERR_ALREADY_EXISTS;
    }

    manifest_data += sizeof(trusty_app->props.uuid);

    config_blob = (u_int*)manifest_data;
    config_blob_size = (manifest_size - sizeof(uuid_t));

    trusty_app->props.config_entry_cnt = config_blob_size / sizeof(u_int);

    /* if no config options we're done */
    if (trusty_app->props.config_entry_cnt == 0) {
        return NO_ERROR;
    }

    /* save off configuration blob start so it can be accessed later */
    trusty_app->props.config_blob = config_blob;

    /*
     * Step thru configuration blob.
     *
     * Save off some configuration data while we are here but
     * defer processing of other data until it is needed later.
     */
    for (i = 0; i < trusty_app->props.config_entry_cnt; i++) {
        switch (config_blob[i]) {
        case TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE:
            /* MIN_STACK_SIZE takes 1 data value */
            if ((trusty_app->props.config_entry_cnt - i) < 2) {
                dprintf(CRITICAL,
                        "app %u manifest missing MIN_STACK_SIZE value\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            trusty_app->props.min_stack_size = round_up(config_blob[++i], 4096);
            if (trusty_app->props.min_stack_size == 0) {
                dprintf(CRITICAL, "app %u manifest MIN_STACK_SIZE is 0\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            break;
        case TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE:
            /* MIN_HEAP_SIZE takes 1 data value */
            if ((trusty_app->props.config_entry_cnt - i) < 2) {
                dprintf(CRITICAL,
                        "app %u manifest missing MIN_HEAP_SIZE value\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            trusty_app->props.min_heap_size = config_blob[++i];
            break;
        case TRUSTY_APP_CONFIG_KEY_MAP_MEM:
            /* MAP_MEM takes 6 data values */
            if ((trusty_app->props.config_entry_cnt - i) < 7) {
                dprintf(CRITICAL, "app %u manifest missing MAP_MEM value\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            mmio_id = trusty_app->props.config_blob[++i];
            /*
             * TODO: add big endian support? The manifest_compiler wrote the
             * next two entries as 64 bit numbers with the byte order of the
             * build machine. The code below assumes the manifest data and
             * device are both little-endian.
             */
            mmio_offset = trusty_app->props.config_blob[++i];
            mmio_offset |= (uint64_t)trusty_app->props.config_blob[++i] << 32;
            mmio_size = round_up(trusty_app->props.config_blob[++i], PAGE_SIZE);
            mmio_size |= (uint64_t)trusty_app->props.config_blob[++i] << 32;
            mmio_arch_mmu_flags = trusty_app->props.config_blob[++i];
            trusty_app->props.map_io_mem_cnt++;

            if (!IS_PAGE_ALIGNED(mmio_offset)) {
                dprintf(CRITICAL, "app %u mmio_id %u not page aligned\n",
                        trusty_app->app_id, mmio_id);
                return ERR_NOT_VALID;
            }

            if ((paddr_t)mmio_offset != mmio_offset ||
                (size_t)mmio_size != mmio_size) {
                dprintf(CRITICAL, "app %u mmio_id %d address/size too large\n",
                        trusty_app->app_id, mmio_id);
                return ERR_NOT_VALID;
            }

            if (!mmio_size || __builtin_add_overflow(mmio_offset, mmio_size - 1,
                                                     &tmp_paddr)) {
                dprintf(CRITICAL, "app %u mmio_id %u bad size\n",
                        trusty_app->app_id, mmio_id);
                return ERR_NOT_VALID;
            }

            if (mmio_arch_mmu_flags &
                        ~(ARCH_MMU_FLAG_CACHE_MASK | ARCH_MMU_FLAG_NS) ||
                ((mmio_arch_mmu_flags & ARCH_MMU_FLAG_CACHE_MASK) !=
                         ARCH_MMU_FLAG_CACHED &&
                 (mmio_arch_mmu_flags & ARCH_MMU_FLAG_CACHE_MASK) !=
                         ARCH_MMU_FLAG_UNCACHED &&
                 (mmio_arch_mmu_flags & ARCH_MMU_FLAG_CACHE_MASK) !=
                         ARCH_MMU_FLAG_UNCACHED_DEVICE)) {
                dprintf(CRITICAL, "app %u mmio_id %u bad arch_mmu_flags 0x%x\n",
                        trusty_app->app_id, mmio_id, mmio_arch_mmu_flags);
                return ERR_NOT_VALID;
            }
            mmio_arch_mmu_flags |= ARCH_MMU_FLAG_PERM_NO_EXECUTE;

            mmio_entry = calloc(1, sizeof(struct manifest_mmio_entry));
            if (!mmio_entry) {
                dprintf(CRITICAL,
                        "Failed to allocate memory for manifest mmio %d of app %u\n",
                        mmio_id, trusty_app->app_id);
                return ERR_NO_MEMORY;
            }

            phys_mem_obj_initialize(&mmio_entry->phys_mem_obj,
                                    &mmio_entry->phys_mem_obj_self_ref,
                                    mmio_offset, mmio_size,
                                    mmio_arch_mmu_flags);
            mmio_entry->id = mmio_id;
            list_add_tail(&trusty_app->props.mmio_entry_list,
                          &mmio_entry->node);

            break;
        case TRUSTY_APP_CONFIG_KEY_MGMT_FLAGS:
            /* MGMT_FLAGS takes 1 data value */
            if (trusty_app->props.config_entry_cnt - i < 2) {
                dprintf(CRITICAL, "app %u manifest missing MGMT_FLAGS value\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            trusty_app->props.mgmt_flags = config_blob[++i];
            break;
        case TRUSTY_APP_CONFIG_KEY_START_PORT:
            /* START_PORT takes at least 3 data values */
            if (trusty_app->props.config_entry_cnt - i < 4) {
                dprintf(CRITICAL, "app %u manifest missing START_PORT values\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }

            port_flags = config_blob[++i];
            port_name_size = config_blob[++i];
            port_name = (const char*)&config_blob[++i];

            if (!address_range_within_bounds(port_name, port_name_size,
                                             config_blob,
                                             config_blob + config_blob_size)) {
                dprintf(CRITICAL,
                        "app %u manifest string out of bounds: %p size: 0x%x config_blob: %p config_blob_size: 0x%x\n",
                        trusty_app->app_id, port_name, port_name_size,
                        config_blob, config_blob_size);
                return ERR_NOT_VALID;
            }

            if (!port_name_size || port_name_size > IPC_PORT_PATH_MAX) {
                dprintf(CRITICAL,
                        "app %u manifest port name has invalid size:%#x\n",
                        trusty_app->app_id, port_name_size);
                return ERR_NOT_VALID;
            }

            size_t bound_len = strnlen(port_name, IPC_PORT_PATH_MAX);
            if (!bound_len || bound_len == IPC_PORT_PATH_MAX) {
                dprintf(CRITICAL,
                        "app %u manifest port name is empty or not null-terminated\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }

            i += DIV_ROUND_UP(port_name_size, sizeof(uint32_t)) - 1;

            entry = find_manifest_port_entry_locked(port_name, NULL);
            if (entry) {
                dprintf(CRITICAL, "Port %s is already registered\n", port_name);
                return ERR_ALREADY_EXISTS;
            }

            entry = calloc(1, sizeof(struct manifest_port_entry));
            if (!entry) {
                dprintf(CRITICAL,
                        "Failed to allocate memory for manifest port %s of app %u\n",
                        port_name, trusty_app->app_id);
                return ERR_NO_MEMORY;
            }

            entry->flags = port_flags;
            entry->path_len = port_name_size;
            entry->path = port_name;

            list_add_tail(&trusty_app->props.port_entry_list, &entry->node);

            break;
        default:
            dprintf(CRITICAL,
                    "app %u manifest contains unknown config key %u at %p\n",
                    trusty_app->app_id, config_blob[i], &config_blob[i]);
            return ERR_NOT_VALID;
        }
    }

    LTRACEF("trusty_app %p: stack_sz=0x%x\n", trusty_app,
            trusty_app->props.min_stack_size);
    LTRACEF("trusty_app %p: heap_sz=0x%x\n", trusty_app,
            trusty_app->props.min_heap_size);
    LTRACEF("trusty_app %p: num_io_mem=%d\n", trusty_app,
            trusty_app->props.map_io_mem_cnt);

    return NO_ERROR;
}

static status_t init_brk(struct trusty_app* trusty_app) {
    status_t status;
    vaddr_t start_brk;
    vaddr_t brk_size;

    /*
     * Make sure the heap is page aligned and page sized.
     * Most user space allocators assume this. Historically, we tried to
     * scavange space at the end of .bss for the heap but this misaligned the
     * heap and caused userspace allocators to behave is subtly unpredictable
     * ways.
     */
    start_brk = 0;
    brk_size = round_up(trusty_app->props.min_heap_size, PAGE_SIZE);

    /* Allocate if needed. */
    if (brk_size > 0) {
        status = vmm_alloc(
                trusty_app->aspace, "heap", brk_size, (void**)&start_brk,
                PAGE_SIZE_SHIFT, 0,
                ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);

        if (status != NO_ERROR) {
            dprintf(CRITICAL, "failed(%d) to create heap(0x%lx) for app %u\n",
                    status, start_brk, trusty_app->app_id);
            return ERR_NO_MEMORY;
        }
    }

    /* Record the location. */
    trusty_app->start_brk = start_brk;
    trusty_app->cur_brk = start_brk;
    trusty_app->end_brk = start_brk + brk_size;

    return NO_ERROR;
}

/**
 * select_load_bias() - Pick a a load bias for an ELF
 * @phdr:      Pre-validated program header array base
 * @num_phdrs: Number of program headers
 * @aspace:    The address space the bias needs to be valid in
 * @out:       Out pointer to write the selected bias to. Only valid if the
 *             function returned 0.
 *
 * This function calculates an offset that can be added to every loadable ELF
 * segment in the image and still result in a legal load address.
 *
 * Return: A status code indicating whether a bias was located. If nonzero,
 *         the bias output may be invalid.
 */
static status_t select_load_bias(ELF_PHDR* phdr,
                                 size_t num_phdrs,
                                 vmm_aspace_t* aspace,
                                 vaddr_t* out) {
    DEBUG_ASSERT(out);
#if ASLR
    vaddr_t low = VADDR_MAX;
    vaddr_t high = 0;
    for (size_t i = 0; i < num_phdrs; i++, phdr++) {
        low = MIN(low, phdr->p_vaddr);
        vaddr_t candidate_high;
        if (!__builtin_add_overflow(phdr->p_vaddr, phdr->p_memsz,
                                    &candidate_high)) {
            high = MAX(high, candidate_high);
        } else {
            dprintf(CRITICAL, "Segment %zu overflows virtual address space\n",
                    i);
            return ERR_NOT_VALID;
        }
    }
    LTRACEF("ELF Segment range: %lx->%lx\n", low, high);

    DEBUG_ASSERT(high >= low);
    size_t size = round_up(high - low, PAGE_SIZE);
    LTRACEF("Spot size: %zu\n", size);

    vaddr_t spot;
    if (!vmm_find_spot(aspace, size, &spot)) {
        return ERR_NO_MEMORY;
    }
    LTRACEF("Load target: %lx\n", spot);

    /*
     * Overflow is acceptable here, since adding the delta to the lowest
     * ELF load address will still return to spot, which was the goal.
     */
    __builtin_sub_overflow(spot, low, out);
#else
    /* If ASLR is disabled, the app is not PIE, use a load bias of 0 */
    *out = 0;
#endif

    LTRACEF("Load bias: %lx\n", *out);

    return NO_ERROR;
}

static bool elf_vaddr_mapped(struct trusty_app* trusty_app,
                             size_t vaddr,
                             ssize_t offset) {
    ELF_EHDR* elf_hdr = (ELF_EHDR*)trusty_app->app_img->img_start;
    void* trusty_app_image = (void*)trusty_app->app_img->img_start;
    ELF_PHDR* prg_hdr = (ELF_PHDR*)(trusty_app_image + elf_hdr->e_phoff);
    if (__builtin_add_overflow(vaddr, offset, &vaddr)) {
        return false;
    }
    for (size_t i = 0; i < elf_hdr->e_phnum; i++, prg_hdr++) {
        Elf_Addr end;
        __builtin_add_overflow(prg_hdr->p_vaddr, prg_hdr->p_memsz, &end);
        if (prg_hdr->p_type == PT_LOAD &&
            vaddr >= round_down(prg_hdr->p_vaddr, PAGE_SIZE) &&
            vaddr < round_up(end, PAGE_SIZE)) {
            return true;
        }
    }
    return false;
}

static status_t alloc_address_map(struct trusty_app* trusty_app) {
    ELF_EHDR* elf_hdr = (ELF_EHDR*)trusty_app->app_img->img_start;
    void* trusty_app_image;
    ELF_PHDR* prg_hdr;
    u_int i;
    status_t ret;
    trusty_app_image = (void*)trusty_app->app_img->img_start;

    prg_hdr = (ELF_PHDR*)(trusty_app_image + elf_hdr->e_phoff);

    if (!address_range_within_img(prg_hdr, sizeof(ELF_PHDR) * elf_hdr->e_phnum,
                                  trusty_app->app_img)) {
        dprintf(CRITICAL, "ELF program headers table out of bounds\n");
        return ERR_NOT_VALID;
    }

    status_t bias_result =
            select_load_bias(prg_hdr, elf_hdr->e_phnum, trusty_app->aspace,
                             &trusty_app->load_bias);
    if (bias_result) {
        return bias_result;
    }

    size_t has_guard_low = 0;
    size_t has_guard_high = 0;

    /* create mappings for PT_LOAD sections */
    for (i = 0; i < elf_hdr->e_phnum; i++, prg_hdr++) {
        /* load_bias uses overflow to lower vaddr if needed */
        Elf_Addr p_vaddr;
        __builtin_add_overflow(prg_hdr->p_vaddr, trusty_app->load_bias,
                               &p_vaddr);

        LTRACEF("trusty_app %d: ELF type 0x%x"
                ", vaddr 0x%08" PRIxELF_Addr ", paddr 0x%08" PRIxELF_Addr
                ", rsize 0x%08" PRIxELF_Size ", msize 0x%08" PRIxELF_Size
                ", flags 0x%08x\n",
                trusty_app->app_id, prg_hdr->p_type, p_vaddr, prg_hdr->p_paddr,
                prg_hdr->p_filesz, prg_hdr->p_memsz, prg_hdr->p_flags);

        if (prg_hdr->p_type != PT_LOAD)
            continue;

        if (p_vaddr < USER_ASPACE_BASE) {
            TRACEF("Attempted to load segment beneath user address space\n");
            return ERR_NOT_VALID;
        }

        vaddr_t vaddr = p_vaddr;
        vaddr_t img_kvaddr = (vaddr_t)(trusty_app_image + prg_hdr->p_offset);
        size_t mapping_size;

        if (vaddr & PAGE_MASK) {
            dprintf(CRITICAL,
                    "app %u segment %u load address 0x%lx in not page aligned\n",
                    trusty_app->app_id, i, vaddr);
            return ERR_NOT_VALID;
        }

        if (img_kvaddr & PAGE_MASK) {
            dprintf(CRITICAL,
                    "app %u segment %u image address 0x%lx in not page aligned\n",
                    trusty_app->app_id, i, img_kvaddr);
            return ERR_NOT_VALID;
        }

        uint vmm_flags = VMM_FLAG_VALLOC_SPECIFIC;
        if (elf_vaddr_mapped(trusty_app, prg_hdr->p_vaddr,
                             -(ssize_t)PAGE_SIZE)) {
            vmm_flags |= VMM_FLAG_NO_START_GUARD;
        } else {
            has_guard_low++;
        }
        if (elf_vaddr_mapped(trusty_app, prg_hdr->p_vaddr + prg_hdr->p_memsz,
                             PAGE_SIZE)) {
            vmm_flags |= VMM_FLAG_NO_END_GUARD;
        } else {
            has_guard_high++;
        }

        uint arch_mmu_flags = ARCH_MMU_FLAG_PERM_USER;
        if (!(prg_hdr->p_flags & PF_X)) {
            arch_mmu_flags += ARCH_MMU_FLAG_PERM_NO_EXECUTE;
        }

        if (prg_hdr->p_flags & PF_W) {
            paddr_t upaddr;
            void* load_kvaddr;
            size_t copy_size;
            size_t file_size;
            mapping_size = round_up(prg_hdr->p_memsz, PAGE_SIZE);

            if (!address_range_within_img((void*)img_kvaddr, prg_hdr->p_filesz,
                                          trusty_app->app_img)) {
                dprintf(CRITICAL, "ELF Program segment %u out of bounds\n", i);
                return ERR_NOT_VALID;
            }

            ret = vmm_alloc(trusty_app->aspace, "elfseg", mapping_size,
                            (void**)&vaddr, PAGE_SIZE_SHIFT, vmm_flags,
                            arch_mmu_flags);

            if (ret != NO_ERROR) {
                dprintf(CRITICAL,
                        "failed(%d) to allocate data segment(0x%lx) %u for app %u\n",
                        ret, vaddr, i, trusty_app->app_id);
                return ret;
            }

            ASSERT(vaddr == p_vaddr);

            file_size = prg_hdr->p_filesz;
            while (file_size > 0) {
                ret = arch_mmu_query(&trusty_app->aspace->arch_aspace, vaddr,
                                     &upaddr, NULL);
                if (ret != NO_ERROR) {
                    dprintf(CRITICAL, "Could not copy data segment: %d\n", ret);
                    return ret;
                }

                load_kvaddr = paddr_to_kvaddr(upaddr);
                ASSERT(load_kvaddr);
                copy_size = MIN(file_size, PAGE_SIZE);
                memcpy(load_kvaddr, (void*)img_kvaddr, copy_size);
                file_size -= copy_size;
                vaddr += copy_size;
                img_kvaddr += copy_size;
            }

        } else {
            mapping_size = round_up(prg_hdr->p_filesz, PAGE_SIZE);

            if (!address_range_within_img((void*)img_kvaddr, mapping_size,
                                          trusty_app->app_img)) {
                dprintf(CRITICAL, "ELF Program segment %u out of bounds\n", i);
                return ERR_NOT_VALID;
            }
            if (mapping_size != round_up(prg_hdr->p_memsz, PAGE_SIZE)) {
                dprintf(CRITICAL, "ELF Program segment %u bad memsz\n", i);
                return ERR_NOT_VALID;
            }

            paddr_t* paddr_arr =
                    calloc(mapping_size / PAGE_SIZE, sizeof(paddr_t));
            if (!paddr_arr) {
                dprintf(CRITICAL,
                        "Failed to allocate physical address array\n");
                return ERR_NO_MEMORY;
            }

            for (size_t j = 0; j < mapping_size / PAGE_SIZE; j++) {
                paddr_arr[j] =
                        vaddr_to_paddr((void*)(img_kvaddr + PAGE_SIZE * j));
                DEBUG_ASSERT(paddr_arr[j] && !(paddr_arr[j] & PAGE_MASK));
            }

            arch_mmu_flags += ARCH_MMU_FLAG_PERM_RO;
            ret = vmm_alloc_physical_etc(
                    trusty_app->aspace, "elfseg", mapping_size, (void**)&vaddr,
                    PAGE_SIZE_SHIFT, paddr_arr, mapping_size / PAGE_SIZE,
                    vmm_flags, arch_mmu_flags);
            if (ret != NO_ERROR) {
                dprintf(CRITICAL,
                        "failed(%d) to map RO segment(0x%lx) %u for app %u\n",
                        ret, vaddr, i, trusty_app->app_id);
                free(paddr_arr);
                return ret;
            }

            ASSERT(vaddr == p_vaddr);
            free(paddr_arr);
        }

        LTRACEF("trusty_app %d: load vaddr 0x%08lx, paddr 0x%08lx"
                ", rsize 0x%08zx, msize 0x%08" PRIxELF_Size
                ", access r%c%c, flags 0x%x\n",
                trusty_app->app_id, vaddr, vaddr_to_paddr((void*)vaddr),
                mapping_size, prg_hdr->p_memsz,
                arch_mmu_flags & ARCH_MMU_FLAG_PERM_RO ? '-' : 'w',
                arch_mmu_flags & ARCH_MMU_FLAG_PERM_NO_EXECUTE ? '-' : 'x',
                arch_mmu_flags);
    }

    ASSERT(has_guard_low);
    ASSERT(has_guard_high);
    ASSERT(has_guard_low == has_guard_high);

    ret = init_brk(trusty_app);
    if (ret != NO_ERROR) {
        dprintf(CRITICAL,
                "failed to load trusty_app: trusty_app heap creation error\n");
        return ret;
    }

    dprintf(SPEW, "trusty_app %d: brk:  start 0x%08lx end 0x%08lx\n",
            trusty_app->app_id, trusty_app->start_brk, trusty_app->end_brk);
    dprintf(SPEW, "trusty_app %d: entry 0x%08" PRIxELF_Addr "\n",
            trusty_app->app_id, elf_hdr->e_entry);

    return NO_ERROR;
}

static bool has_waiting_connection(struct trusty_app* app) {
    struct manifest_port_entry* entry;

    /*
     * Don't hold the apps lock when calling into other subsystems with calls
     * that may grab additional locks.
     */
    DEBUG_ASSERT(!is_mutex_held(&apps_lock));

    list_for_every_entry(&app->props.port_entry_list, entry,
                         struct manifest_port_entry, node) {
        if (ipc_connection_waiting_for_port(entry->path, entry->flags)) {
            return true;
        }
    }

    return false;
}

/* Must be called with the apps_lock held */
static status_t request_app_start_locked(struct trusty_app* app) {
    DEBUG_ASSERT(is_mutex_held(&apps_lock));

    if (app->state == APP_NOT_RUNNING) {
        app->state = APP_STARTING;
        event_signal(&app_mgr_event, false);
        return NO_ERROR;
    }

    return ERR_ALREADY_STARTED;
}

/*
 * Create a trusty_app from its memory image and add it to the global list of
 * apps
 */
static status_t trusty_app_create(struct trusty_app_img* app_img) {
    ELF_EHDR* ehdr;
    struct trusty_app* trusty_app;
    status_t ret;
    struct manifest_port_entry* entry;
    struct manifest_port_entry* tmp_entry;

    if (app_img->img_start & PAGE_MASK || app_img->img_end & PAGE_MASK) {
        dprintf(CRITICAL,
                "app image is not page aligned start 0x%lx end 0x%lx\n",
                app_img->img_start, app_img->img_end);
        return ERR_NOT_VALID;
    }

    dprintf(SPEW, "trusty_app: start %p size 0x%08lx end %p\n",
            (void*)app_img->img_start, app_img->img_end - app_img->img_start,
            (void*)app_img->img_end);

    trusty_app = (struct trusty_app*)calloc(1, sizeof(struct trusty_app));
    if (!trusty_app) {
        dprintf(CRITICAL,
                "trusty_app: failed to allocate memory for trusty app\n");
        return ERR_NO_MEMORY;
    }
    list_initialize(&trusty_app->props.port_entry_list);
    list_initialize(&trusty_app->props.mmio_entry_list);

    ehdr = (ELF_EHDR*)app_img->img_start;
    if (!address_range_within_img(ehdr, sizeof(ELF_EHDR), app_img)) {
        dprintf(CRITICAL, "trusty_app_create: ELF header out of bounds\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    if (strncmp((char*)ehdr->e_ident, ELFMAG, SELFMAG)) {
        dprintf(CRITICAL, "trusty_app_create: ELF header not found\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    trusty_app->app_id = trusty_next_app_id++;
    trusty_app->app_img = app_img;
    trusty_app->state = APP_NOT_RUNNING;

    mutex_acquire(&apps_lock);

    ret = load_app_config_options(trusty_app);
    if (ret == NO_ERROR) {
        list_add_tail(&trusty_app_list, &trusty_app->node);
    }

    mutex_release(&apps_lock);

    if (ret == NO_ERROR)
        return ret;

    dprintf(CRITICAL, "manifest processing failed(%d)\n", ret);

err_load:
    list_for_every_entry_safe(&trusty_app->props.port_entry_list, entry,
                              tmp_entry, struct manifest_port_entry, node) {
        list_delete(&entry->node);
        free(entry);
    }
err_hdr:
    free(trusty_app);
    return ret;
}

status_t trusty_app_setup_mmio(struct trusty_app* trusty_app,
                               uint32_t mmio_id,
                               user_addr_t* uaddr_p,
                               uint32_t map_size) {
    status_t ret;
    struct manifest_mmio_entry* mmio_entry;

    /* Should only be called on the currently running app */
    DEBUG_ASSERT(trusty_app == current_trusty_app());

    ASSERT(uaddr_p);
    void* va = (void*)(uintptr_t)(*uaddr_p);

    list_for_every_entry(&trusty_app->props.mmio_entry_list, mmio_entry,
                         struct manifest_mmio_entry, node) {
        if (mmio_entry->id != mmio_id) {
            continue;
        }

        map_size = round_up(map_size, PAGE_SIZE);

        ret = vmm_alloc_obj(
                trusty_app->aspace, "mmio", &mmio_entry->phys_mem_obj.vmm_obj,
                0, map_size, &va, 0, 0,
                ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);
        if (ret == NO_ERROR) {
            *uaddr_p = (user_addr_t)(uintptr_t)va;
            DEBUG_ASSERT((void*)(uintptr_t)(*uaddr_p) == va);
        }
        return ret;
    }

    return ERR_NOT_FOUND;
}

static status_t trusty_app_start(struct trusty_app* trusty_app) {
    char name[32];
    struct trusty_thread* trusty_thread;
    struct trusty_app_notifier* n;
    ELF_EHDR* elf_hdr;
    int ret;

    DEBUG_ASSERT(trusty_app->state == APP_STARTING);

    snprintf(name, sizeof(name), "trusty_app_%d_%08x-%04x-%04x",
             trusty_app->app_id, trusty_app->props.uuid.time_low,
             trusty_app->props.uuid.time_mid,
             trusty_app->props.uuid.time_hi_and_version);

    ret = vmm_create_aspace(&trusty_app->aspace, name, 0);
    if (ret != NO_ERROR) {
        dprintf(CRITICAL, "Failed(%d) to allocate address space for %s\n", ret,
                name);
        goto err_aspace;
    }

    ret = alloc_address_map(trusty_app);
    if (ret != NO_ERROR) {
        dprintf(CRITICAL, "failed(%d) to load address map for %s\n", ret, name);
        goto err_map;
    }

    /* attach als_cnt */
    trusty_app->als = calloc(1, als_slot_cnt * sizeof(void*));
    if (!trusty_app->als) {
        dprintf(CRITICAL, "failed to allocate local storage for %s\n", name);
        ret = ERR_NO_MEMORY;
        /* alloc_address_map gets cleaned up by destroying the address space */
        goto err_alloc;
    }

    /* call all registered startup notifiers */
    list_for_every_entry(&app_notifier_list, n, struct trusty_app_notifier,
                         node) {
        if (!n->startup)
            continue;

        ret = n->startup(trusty_app);
        if (ret != NO_ERROR) {
            dprintf(CRITICAL, "failed(%d) to invoke startup notifier for %s\n",
                    ret, name);
            goto err_notifier;
        }
    }

    elf_hdr = (ELF_EHDR*)trusty_app->app_img->img_start;
    vaddr_t entry;
    __builtin_add_overflow(elf_hdr->e_entry, trusty_app->load_bias, &entry);
    trusty_thread =
            trusty_thread_create(name, entry, DEFAULT_PRIORITY,
                                 trusty_app->props.min_stack_size, trusty_app);
    if (!trusty_thread) {
        dprintf(CRITICAL, "failed to allocate trusty thread for %s\n", name);
        ret = ERR_NO_MEMORY;
        goto err_thread;
    }

    trusty_app->thread = trusty_thread;

    trusty_app->state = APP_RUNNING;
    ret = trusty_thread_start(trusty_app->thread);

    ASSERT(ret == NO_ERROR);

    return ret;

err_thread:
err_notifier:
    for (n = list_prev_type(&app_notifier_list, &n->node,
                            struct trusty_app_notifier, node);
         n != NULL; n = list_prev_type(&app_notifier_list, &n->node,
                                       struct trusty_app_notifier, node)) {
        if (!n->shutdown)
            continue;

        if (n->shutdown(trusty_app) != NO_ERROR)
            panic("failed to invoke shutdown notifier for %s\n", name);
    }

    free(trusty_app->als);
err_alloc:
err_map:
    vmm_free_aspace(trusty_app->aspace);
err_aspace:
    return ret;
}

void trusty_app_exit(int status) {
    status_t ret;
    struct trusty_app* app;
    struct trusty_app_notifier* notifier;
    lk_time_ns_t restart_timeout;

    app = current_trusty_app();

    DEBUG_ASSERT(app->state == APP_RUNNING);

    LTRACEF("app %u exiting...\n", app->app_id);

    if (status) {
        TRACEF("%s, exited with exit code %d\n", app->aspace->name, status);
        dump_backtrace();
        if (!(app->props.mgmt_flags & TRUSTY_APP_MGMT_FLAGS_NON_CRITICAL_APP)) {
            panic("Unclean exit from critical app\n");
        }
        restart_timeout = TRUSTY_APP_RESTART_TIMEOUT_FAILURE;
    } else {
        restart_timeout = TRUSTY_APP_RESTART_TIMEOUT_SUCCESS;
    }
    app->min_start_time = current_time_ns() + restart_timeout;

    list_for_every_entry(&app_notifier_list, notifier,
                         struct trusty_app_notifier, node) {
        if (!notifier->shutdown)
            continue;

        ret = notifier->shutdown(app);
        if (ret != NO_ERROR)
            panic("shutdown notifier for app %u failed(%d)\n", app->app_id,
                  ret);
    }

    free(app->als);

    mutex_acquire(&apps_lock);
    app->state = APP_TERMINATING;
    mutex_release(&apps_lock);

    event_signal(&app_mgr_event, false);
    trusty_thread_exit(status);
}

void trusty_app_crash(void) {
    trusty_app_exit(1 /*EXIT_FAILURE*/);
}

static status_t app_mgr_handle_starting(struct trusty_app* app) {
    status_t ret;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));
    DEBUG_ASSERT(app->state == APP_STARTING);

    LTRACEF("starting app %u\n", app->app_id);

    ret = trusty_app_start(app);

    if (ret != NO_ERROR)
        app->state = APP_NOT_RUNNING;

    return ret;
}

static status_t app_mgr_handle_terminating(struct trusty_app* app) {
    status_t ret;
    int retcode;
    bool has_connection;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));
    DEBUG_ASSERT(app->state == APP_TERMINATING);

    LTRACEF("waiting for app %u to exit \n", app->app_id);

    ret = thread_join(app->thread->thread, &retcode, INFINITE_TIME);
    ASSERT(ret == NO_ERROR);
    free(app->thread);
    ret = vmm_free_aspace(app->aspace);

    /*
     * Drop the lock to call into ipc to check for connections. This is safe
     * since the app is in the APP_TERMINANTING state so it cannot be removed.
     */
    mutex_release(&apps_lock);
    has_connection = has_waiting_connection(app);
    mutex_acquire(&apps_lock);

    if (app->props.mgmt_flags & TRUSTY_APP_MGMT_FLAGS_RESTART_ON_EXIT ||
        has_connection) {
        app->state = APP_STARTING;
        event_signal(&app_mgr_event, false);
    } else {
        app->state = APP_NOT_RUNNING;
    }

    return ret;
}

static int app_mgr(void* arg) {
    status_t ret;
    struct trusty_app* app;

    while (true) {
        LTRACEF("app manager waiting for events\n");
        event_wait(&app_mgr_event);

        mutex_acquire(&apps_lock);

        list_for_every_entry(&trusty_app_list, app, struct trusty_app, node) {
            switch (app->state) {
            case APP_TERMINATING:
                ret = app_mgr_handle_terminating(app);
                if (ret != NO_ERROR)
                    panic("failed(%d) to terminate app %u\n", ret, app->app_id);
                break;
            case APP_NOT_RUNNING:
                break;
            case APP_STARTING:
                ret = app_mgr_handle_starting(app);
                if (ret != NO_ERROR)
                    panic("failed(%d) to start app %u\n", ret, app->app_id);
                break;
            case APP_RUNNING:
                break;
            default:
                panic("app %u in unknown state %u\n", app->app_id, app->state);
            }
        }

        mutex_release(&apps_lock);
    }
}

static void app_mgr_init(void) {
    status_t err;
    thread_t* app_mgr_thread;

    LTRACEF("Creating app manager thread\n");
    app_mgr_thread = thread_create("app manager", &app_mgr, NULL,
                                   DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);

    if (!app_mgr_thread)
        panic("Failed to create app manager thread\n");

    err = thread_resume(app_mgr_thread);
    if (err != NO_ERROR)
        panic("Failed to start app manager thread\n");
}

bool trusty_app_is_startup_port(const char* port_path) {
    struct manifest_port_entry* entry;

    mutex_acquire(&apps_lock);
    entry = find_manifest_port_entry_locked(port_path, NULL);
    mutex_release(&apps_lock);

    return entry != NULL;
}

status_t trusty_app_request_start_by_port(const char* port_path,
                                          const uuid_t* uuid) {
    struct manifest_port_entry* entry;
    struct trusty_app* owner = NULL;
    status_t ret;

    mutex_acquire(&apps_lock);

    entry = find_manifest_port_entry_locked(port_path, &owner);

    if (!owner || ipc_port_check_access(entry->flags, uuid) != NO_ERROR) {
        ret = ERR_NOT_FOUND;
    } else {
        ret = request_app_start_locked(owner);
    }

    mutex_release(&apps_lock);

    return ret;
}

void trusty_app_init(void) {
    struct trusty_app_img* app_img;

    finalize_registration();

    app_mgr_init();

    for (app_img = __trusty_app_list_start; app_img != __trusty_app_list_end;
         app_img++) {
        if (trusty_app_create(app_img) != NO_ERROR)
            panic("Failed to create builtin apps\n");
    }
}

/* rather export trusty_app_list?  */
void trusty_app_forall(void (*fn)(struct trusty_app* ta, void* data),
                       void* data) {
    struct trusty_app* ta;

    if (fn == NULL)
        return;

    mutex_acquire(&apps_lock);
    list_for_every_entry(&trusty_app_list, ta, struct trusty_app, node)
            fn(ta, data);
    mutex_release(&apps_lock);
}

static void start_apps(uint level) {
    struct trusty_app* trusty_app;

    mutex_acquire(&apps_lock);
    list_for_every_entry(&trusty_app_list, trusty_app, struct trusty_app,
                         node) {
        if (trusty_app->props.mgmt_flags & TRUSTY_APP_MGMT_FLAGS_DEFERRED_START)
            continue;

        request_app_start_locked(trusty_app);
    }
    mutex_release(&apps_lock);
}

LK_INIT_HOOK(libtrusty_apps, start_apps, LK_INIT_LEVEL_APPS + 1);
