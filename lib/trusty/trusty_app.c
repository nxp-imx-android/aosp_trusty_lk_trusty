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

#include <lib/trusty/trusty_app.h>

#include <arch.h>
#include <assert.h>
#include <compiler.h>
#include <debug.h>
#include <err.h>
#include <kernel/event.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <lib/syscall.h>
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
#include "elf.h"

#define LOCAL_TRACE 0

#define DEFAULT_MGMT_FLAGS TRUSTY_APP_MGMT_FLAGS_NONE

#define TRUSTY_APP_START_ADDR 0x8000

#ifndef TRUSTY_APP_STACK_TOP
#define TRUSTY_APP_STACK_TOP 0x1000000 /* 16MB */
#endif

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

#define PRIxELF_Off "llx"
#define PRIuELF_Size "llu"
#define PRIxELF_Size "llx"
#define PRIxELF_Addr "llx"
#define PRIxELF_Flags "llx"
#else
#define ELF_SHDR Elf32_Shdr
#define ELF_EHDR Elf32_Ehdr
#define ELF_PHDR Elf32_Phdr

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

static inline bool is_builtin(struct trusty_app* app) {
    return app->flags & APP_FLAGS_BUILTIN;
}

static inline bool has_unload_pending(struct trusty_app* app) {
    return app->flags & APP_FLAGS_UNLOAD_PENDING;
}

static inline bool is_deferred_start(struct trusty_app* app) {
    return app->props.mgmt_flags & TRUSTY_APP_MGMT_FLAGS_DEFERRED_START;
}

static void finalize_registration(void) {
    mutex_acquire(&apps_lock);
    apps_started = true;
    mutex_release(&apps_lock);
}

status_t trusty_register_app_notifier(trusty_app_notifier_t* n) {
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

/*
 * Pass data to libc on the user stack.
 * Prevent inlining so that the stack allocations inside this function don't get
 * trapped on the kernel stack.
 */
static __NO_INLINE user_addr_t
trusty_thread_write_elf_tables(struct trusty_thread* trusty_thread,
                               user_addr_t* stack_ptr) {
    /* Construct the elf tables in reverse order - the stack grows down. */

    /* auxv */
    user_addr_t auxv[] = {
            AT_PAGESZ,
            PAGE_SIZE,
            0,
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
    user_addr_t elf_tables =
            trusty_thread_write_elf_tables(trusty_thread, &stack_ptr);

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

static struct trusty_thread* trusty_thread_create(const char* name,
                                                  vaddr_t entry,
                                                  int priority,
                                                  vaddr_t stack_start,
                                                  size_t stack_size,
                                                  trusty_app_t* trusty_app) {
    struct trusty_thread* trusty_thread;
    status_t err;
    vaddr_t stack_bot = stack_start - stack_size;

    trusty_thread = calloc(1, sizeof(struct trusty_thread));
    if (!trusty_thread)
        return NULL;

    err = vmm_alloc(trusty_app->aspace, "stack", stack_size, (void**)&stack_bot,
                    PAGE_SIZE_SHIFT, VMM_FLAG_VALLOC_SPECIFIC,
                    ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);

    if (err != NO_ERROR) {
        dprintf(CRITICAL,
                "failed(%d) to create thread stack(0x%lx) for app %u\n", err,
                stack_bot, trusty_app->app_id);
        goto err_stack;
    }

    ASSERT(stack_bot == stack_start - stack_size);

    trusty_thread->thread = thread_create(name, trusty_thread_startup, NULL,
                                          priority, DEFAULT_STACK_SIZE);
    if (!trusty_thread->thread)
        goto err_thread;

    trusty_thread->app = trusty_app;
    trusty_thread->entry = entry;
    trusty_thread->stack_start = stack_start;
    trusty_thread->stack_size = stack_size;
    trusty_thread->thread->tls[TLS_ENTRY_TRUSTY] = (uintptr_t)trusty_thread;

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

    list_for_every_entry(&trusty_app_list, app, trusty_app_t, node) {
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
static trusty_app_t* trusty_app_find_by_uuid_locked(uuid_t* uuid) {
    trusty_app_t* app;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));

    list_for_every_entry(&trusty_app_list, app, trusty_app_t, node) {
        if (!memcmp(&app->props.uuid, uuid, sizeof(uuid_t)))
            return app;
    }

    return NULL;
}

static status_t load_app_config_options(trusty_app_t* trusty_app,
                                        ELF_SHDR* shdr) {
    char* manifest_data;
    const char* port_name;
    uint32_t port_name_size;
    uint32_t port_flags;
    u_int *config_blob, config_blob_size;
    u_int i;
    struct manifest_port_entry* entry;

    /* have to at least have a valid UUID */
    if (shdr->sh_size < sizeof(uuid_t)) {
        dprintf(CRITICAL, "app %u manifest too small %" PRIuELF_Size "\n",
                trusty_app->app_id, shdr->sh_size);
        return ERR_NOT_VALID;
    }

    /* init default config options before parsing manifest */
    trusty_app->props.min_heap_size = DEFAULT_HEAP_SIZE;
    trusty_app->props.min_stack_size = DEFAULT_STACK_SIZE;
    trusty_app->props.mgmt_flags = DEFAULT_MGMT_FLAGS;

    manifest_data = (char*)(trusty_app->app_img->img_start + shdr->sh_offset);

    if (!address_range_within_img(manifest_data, shdr->sh_size,
                                  trusty_app->app_img)) {
        dprintf(CRITICAL, "app %u manifest data out of bounds\n",
                trusty_app->app_id);
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
    config_blob_size = (shdr->sh_size - sizeof(uuid_t));

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
            /* MAP_MEM takes 3 data values */
            if ((trusty_app->props.config_entry_cnt - i) < 4) {
                dprintf(CRITICAL, "app %u manifest missing MAP_MEM value\n",
                        trusty_app->app_id);
                return ERR_NOT_VALID;
            }
            trusty_app->props.map_io_mem_cnt++;
            i += 3;
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

static status_t init_brk(trusty_app_t* trusty_app, vaddr_t hint) {
    status_t status;
    uint arch_mmu_flags;
    vaddr_t start_brk;
    vaddr_t hint_page_end;
    size_t remaining;

    status = arch_mmu_query(&trusty_app->aspace->arch_aspace, hint, NULL,
                            &arch_mmu_flags);
    if (status != NO_ERROR) {
        dprintf(CRITICAL, "app %u heap hint page is not mapped %u\n",
                trusty_app->app_id, status);
        return ERR_NOT_VALID;
    }

    hint_page_end = round_up(hint, PAGE_SIZE);

    if (!(arch_mmu_flags & ARCH_MMU_FLAG_PERM_RO)) {
        start_brk = round_up(hint, CACHE_LINE);
        remaining = hint_page_end - start_brk;
    } else {
        start_brk = round_up(hint, PAGE_SIZE);
        remaining = 0;
    }

    if (remaining < trusty_app->props.min_heap_size) {
        status = vmm_alloc(
                trusty_app->aspace, "heap",
                trusty_app->props.min_heap_size - remaining,
                (void**)&hint_page_end, PAGE_SIZE_SHIFT,
                VMM_FLAG_VALLOC_SPECIFIC,
                ARCH_MMU_FLAG_PERM_USER | ARCH_MMU_FLAG_PERM_NO_EXECUTE);

        if (status != NO_ERROR) {
            dprintf(CRITICAL, "failed(%d) to create heap(0x%lx) for app %u\n",
                    status, hint_page_end, trusty_app->app_id);
            return ERR_NO_MEMORY;
        }

        ASSERT(hint_page_end == round_up(hint, PAGE_SIZE));
    }

    trusty_app->start_brk = start_brk;
    trusty_app->cur_brk = trusty_app->start_brk;
    trusty_app->end_brk =
            trusty_app->start_brk + trusty_app->props.min_heap_size;

    return NO_ERROR;
}

static status_t alloc_address_map(trusty_app_t* trusty_app) {
    ELF_EHDR* elf_hdr = (ELF_EHDR*)trusty_app->app_img->img_start;
    void* trusty_app_image;
    ELF_PHDR* prg_hdr;
    u_int i;
    status_t ret;
    vaddr_t start_code = ~0;
    vaddr_t start_data = 0;
    vaddr_t end_code = 0;
    vaddr_t end_data = 0;
    vaddr_t last_mem = 0;
    trusty_app_image = (void*)trusty_app->app_img->img_start;

    prg_hdr = (ELF_PHDR*)(trusty_app_image + elf_hdr->e_phoff);

    if (!address_range_within_img(prg_hdr, sizeof(ELF_PHDR) * elf_hdr->e_phnum,
                                  trusty_app->app_img)) {
        dprintf(CRITICAL, "ELF program headers table out of bounds\n");
        return ERR_NOT_VALID;
    }

    /* create mappings for PT_LOAD sections */
    for (i = 0; i < elf_hdr->e_phnum; i++, prg_hdr++) {
        vaddr_t first, last;

        LTRACEF("trusty_app %d: ELF type 0x%x"
                ", vaddr 0x%08" PRIxELF_Addr ", paddr 0x%08" PRIxELF_Addr
                ", rsize 0x%08" PRIxELF_Size ", msize 0x%08" PRIxELF_Size
                ", flags 0x%08x\n",
                trusty_app->app_id, prg_hdr->p_type, prg_hdr->p_vaddr,
                prg_hdr->p_paddr, prg_hdr->p_filesz, prg_hdr->p_memsz,
                prg_hdr->p_flags);

        if (prg_hdr->p_type != PT_LOAD)
            continue;

        /* skip PT_LOAD if it's below trusty_app start or above .bss */
        if ((prg_hdr->p_vaddr < TRUSTY_APP_START_ADDR) ||
            (prg_hdr->p_vaddr >= trusty_app->end_bss))
            continue;

        /* check for overlap into user stack range */
        vaddr_t stack_bot =
                TRUSTY_APP_STACK_TOP - trusty_app->props.min_stack_size;

        if (stack_bot < prg_hdr->p_vaddr + prg_hdr->p_memsz) {
            dprintf(CRITICAL,
                    "failed to load trusty_app: (overlaps user stack 0x%lx)\n",
                    stack_bot);
            return ERR_TOO_BIG;
        }

        vaddr_t vaddr = prg_hdr->p_vaddr;
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
                            (void**)&vaddr, PAGE_SIZE_SHIFT,
                            VMM_FLAG_VALLOC_SPECIFIC, arch_mmu_flags);

            if (ret != NO_ERROR) {
                dprintf(CRITICAL,
                        "failed(%d) to allocate data segment(0x%lx) %u for app %u\n",
                        ret, vaddr, i, trusty_app->app_id);
                return ret;
            }

            ASSERT(vaddr == prg_hdr->p_vaddr);

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
                    VMM_FLAG_VALLOC_SPECIFIC, arch_mmu_flags);
            if (ret != NO_ERROR) {
                dprintf(CRITICAL,
                        "failed(%d) to map RO segment(0x%lx) %u for app %u\n",
                        ret, vaddr, i, trusty_app->app_id);
                free(paddr_arr);
                return ret;
            }

            ASSERT(vaddr == prg_hdr->p_vaddr);
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

        /* start of code/data */
        first = prg_hdr->p_vaddr;
        if (first < start_code)
            start_code = first;
        if (start_data < first)
            start_data = first;

        /* end of code/data */
        last = prg_hdr->p_vaddr + prg_hdr->p_filesz;
        if ((prg_hdr->p_flags & PF_X) && end_code < last)
            end_code = last;
        if (end_data < last)
            end_data = last;

        /* hint for start of brk */
        last_mem = MAX(last_mem, prg_hdr->p_vaddr + prg_hdr->p_memsz);
    }

    ret = init_brk(trusty_app, last_mem);
    if (ret != NO_ERROR) {
        dprintf(CRITICAL,
                "failed to load trusty_app: trusty_app heap creation error\n");
        return ret;
    }

    dprintf(SPEW, "trusty_app %d: code: start 0x%08lx end 0x%08lx\n",
            trusty_app->app_id, start_code, end_code);
    dprintf(SPEW, "trusty_app %d: data: start 0x%08lx end 0x%08lx\n",
            trusty_app->app_id, start_data, end_data);
    dprintf(SPEW, "trusty_app %d: bss:                end 0x%08lx\n",
            trusty_app->app_id, trusty_app->end_bss);
    dprintf(SPEW, "trusty_app %d: brk:  start 0x%08lx end 0x%08lx\n",
            trusty_app->app_id, trusty_app->start_brk, trusty_app->end_brk);
    dprintf(SPEW, "trusty_app %d: entry 0x%08" PRIxELF_Addr "\n",
            trusty_app->app_id, elf_hdr->e_entry);

    return NO_ERROR;
}

static void trusty_app_destroy_locked(struct trusty_app* app) {
    status_t rc;
    struct manifest_port_entry* entry;
    struct manifest_port_entry* tmp_entry;

    DEBUG_ASSERT(is_mutex_held(&apps_lock));
    DEBUG_ASSERT(app->state == APP_NOT_RUNNING);
    DEBUG_ASSERT(!is_builtin(app));

    list_delete(&app->node);

    list_for_every_entry_safe(&app->props.port_entry_list, entry, tmp_entry,
                              struct manifest_port_entry, node) {
        list_delete(&entry->node);
        free(entry);
    }

    rc = vmm_free_region_etc(vmm_get_kernel_aspace(), app->app_img->img_start,
                             app->app_img->img_end - app->app_img->img_start,
                             0);

    ASSERT(rc == NO_ERROR);
    free(app->app_img);
    free(app);
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

    if (has_unload_pending(app)) {
        return ERR_NOT_FOUND;
    }

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
static status_t trusty_app_create(struct trusty_app_img* app_img,
                                  uint32_t flags) {
    ELF_EHDR* ehdr;
    ELF_SHDR* shdr;
    ELF_SHDR *bss_shdr, *manifest_shdr;
    char* shstbl;
    uint32_t shstbl_size;
    trusty_app_t* trusty_app;
    u_int i;
    status_t ret;
    struct manifest_port_entry* entry;
    struct manifest_port_entry* tmp_entry;
    bool connection_waiting;

    if (app_img->img_start & PAGE_MASK || app_img->img_end & PAGE_MASK) {
        dprintf(CRITICAL,
                "app image is not page aligned start 0x%lx end 0x%lx\n",
                app_img->img_start, app_img->img_end);
        return ERR_NOT_VALID;
    }

    dprintf(SPEW, "trusty_app: start %p size 0x%08lx end %p\n",
            (void*)app_img->img_start, app_img->img_end - app_img->img_start,
            (void*)app_img->img_end);

    trusty_app = (trusty_app_t*)calloc(1, sizeof(trusty_app_t));
    if (!trusty_app) {
        dprintf(CRITICAL,
                "trusty_app: failed to allocate memory for trusty app\n");
        return ERR_NO_MEMORY;
    }
    list_initialize(&trusty_app->props.port_entry_list);

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

    shdr = (ELF_SHDR*)((intptr_t)ehdr + ehdr->e_shoff);
    if (!address_range_within_img(shdr, sizeof(ELF_SHDR) * ehdr->e_shnum,
                                  app_img)) {
        dprintf(CRITICAL,
                "trusty_app_create: ELF section headers out of bounds\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        dprintf(CRITICAL,
                "trusty_app_create: ELF names table section header out of bounds\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    shstbl = (char*)((intptr_t)ehdr + shdr[ehdr->e_shstrndx].sh_offset);
    shstbl_size = shdr[ehdr->e_shstrndx].sh_size;
    if (!address_range_within_img(shstbl, shstbl_size, app_img)) {
        dprintf(CRITICAL,
                "trusty_app_create: ELF section names out of bounds\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    bss_shdr = manifest_shdr = NULL;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_NULL)
            continue;
        LTRACEF("trusty_app: sect %d"
                ", off 0x%08" PRIxELF_Off ", size 0x%08" PRIxELF_Size
                ", flags 0x%02" PRIxELF_Flags ", name %s\n",
                i, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_flags,
                shstbl + shdr[i].sh_name);

        /* track bss and manifest sections */
        if (compare_section_name(shdr + i, ".bss", shstbl, shstbl_size)) {
            bss_shdr = shdr + i;
            trusty_app->end_bss = bss_shdr->sh_addr + bss_shdr->sh_size;
        } else if (compare_section_name(shdr + i, ".trusty_app.manifest",
                                        shstbl, shstbl_size)) {
            manifest_shdr = shdr + i;
        }
    }

    /* we need these sections */
    if (!bss_shdr) {
        dprintf(CRITICAL, "bss section header not found\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    if (!manifest_shdr) {
        dprintf(CRITICAL, "manifest section header not found\n");
        ret = ERR_NOT_VALID;
        goto err_hdr;
    }

    trusty_app->flags |= flags;
    trusty_app->app_id = trusty_next_app_id++;
    trusty_app->app_img = app_img;
    trusty_app->state = APP_LOADING;

    mutex_acquire(&apps_lock);

    ret = load_app_config_options(trusty_app, manifest_shdr);
    if (ret == NO_ERROR) {
        list_add_tail(&trusty_app_list, &trusty_app->node);
    }

    mutex_release(&apps_lock);

    if (ret != NO_ERROR)
        goto err_load;

    /*
     * Call into ipc to check for waiting connections without the lock held.
     * This is safe since the app is still in APP_LOADING state.
     */
    connection_waiting = has_waiting_connection(trusty_app);

    mutex_acquire(&apps_lock);

    if (is_builtin(trusty_app) || has_unload_pending(trusty_app) ||
        (is_deferred_start(trusty_app) && !connection_waiting)) {
        trusty_app->state = APP_NOT_RUNNING;
    } else {
        trusty_app->state = APP_STARTING;
        event_signal(&app_mgr_event, false);
    }

    mutex_release(&apps_lock);

    return NO_ERROR;

err_load:
    dprintf(CRITICAL, "manifest processing failed(%d)\n", ret);
    list_for_every_entry_safe(&trusty_app->props.port_entry_list, entry,
                              tmp_entry, struct manifest_port_entry, node) {
        list_delete(&entry->node);
        free(entry);
    }
err_hdr:
    free(trusty_app);
    return ret;
}

status_t trusty_app_setup_mmio(trusty_app_t* trusty_app,
                               u_int mmio_id,
                               vaddr_t* vaddr,
                               uint32_t map_size) {
    status_t ret;
    u_int i;
    u_int id, offset, size;
    uint32_t port_name_size;

    /* Should only be called on the currently running app */
    DEBUG_ASSERT(trusty_app == current_trusty_app());

    /* step thru configuration blob looking for I/O mapping requests */
    for (i = 0; i < trusty_app->props.config_entry_cnt; i++) {
        switch (trusty_app->props.config_blob[i]) {
        case TRUSTY_APP_CONFIG_KEY_MAP_MEM:
            id = trusty_app->props.config_blob[++i];
            offset = trusty_app->props.config_blob[++i];
            size = round_up(trusty_app->props.config_blob[++i], PAGE_SIZE);

            if (id != mmio_id)
                continue;

            map_size = round_up(map_size, PAGE_SIZE);
            if (map_size > size)
                return ERR_INVALID_ARGS;
            ret = vmm_alloc_physical(
                    trusty_app->aspace, "mmio", map_size, (void**)vaddr,
                    PAGE_SIZE_SHIFT, offset, 0,
                    ARCH_MMU_FLAG_UNCACHED_DEVICE | ARCH_MMU_FLAG_PERM_USER);
            dprintf(SPEW, "mmio: vaddr 0x%lx, paddr 0x%x, ret %d\n", *vaddr,
                    offset, ret);
            return ret;
        case TRUSTY_APP_CONFIG_KEY_START_PORT:
            /* START_PORT takes 2 data values plus the aligned port name size */
            port_name_size = trusty_app->props.config_blob[i + 2];
            i += 2 + DIV_ROUND_UP(port_name_size, sizeof(uint32_t));
            break;
        case TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE:
        case TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE:
        case TRUSTY_APP_CONFIG_KEY_MGMT_FLAGS:
            i++;
            break;
        default:
            panic("unknown config key 0x%x at %p in config blob of app %d\n",
                  trusty_app->props.config_blob[i],
                  &trusty_app->props.config_blob[i], trusty_app->app_id);
        }
    }

    return ERR_NOT_FOUND;
}

static status_t trusty_app_start(trusty_app_t* trusty_app) {
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
    trusty_thread = trusty_thread_create(
            name, elf_hdr->e_entry, DEFAULT_PRIORITY, TRUSTY_APP_STACK_TOP,
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

    app = current_trusty_app();

    DEBUG_ASSERT(app->state == APP_RUNNING);

    LTRACEF("app %u exiting...\n", app->app_id);

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

    if (!has_unload_pending(app) &&
        (app->props.mgmt_flags & TRUSTY_APP_MGMT_FLAGS_RESTART_ON_EXIT ||
         has_connection)) {
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
    struct trusty_app* tmp;

    while (true) {
        LTRACEF("app manager waiting for events\n");
        event_wait(&app_mgr_event);

        mutex_acquire(&apps_lock);

        list_for_every_entry_safe(&trusty_app_list, app, tmp, struct trusty_app,
                                  node) {
            switch (app->state) {
            /*
             * This state is used to prevent the app from being destroyed while
             * it is still loading (i.e. detemrining if the next state should
             * be NOT_RUNNING or STARTING).
             */
            case APP_LOADING:
                break;
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
        if (trusty_app_create(app_img, APP_FLAGS_BUILTIN) != NO_ERROR)
            panic("Failed to create builtin apps\n");
    }
}

/* rather export trusty_app_list?  */
void trusty_app_forall(void (*fn)(trusty_app_t* ta, void* data), void* data) {
    trusty_app_t* ta;

    if (fn == NULL)
        return;

    mutex_acquire(&apps_lock);
    list_for_every_entry(&trusty_app_list, ta, trusty_app_t, node) fn(ta, data);
    mutex_release(&apps_lock);
}

static void start_apps(uint level) {
    trusty_app_t* trusty_app;

    mutex_acquire(&apps_lock);
    list_for_every_entry(&trusty_app_list, trusty_app, trusty_app_t, node) {
        if (is_deferred_start(trusty_app))
            continue;

        request_app_start_locked(trusty_app);
    }
    mutex_release(&apps_lock);
}

LK_INIT_HOOK(libtrusty_apps, start_apps, LK_INIT_LEVEL_APPS + 1);

#ifdef TEST_BUILD

static const uuid_t loader_uuids[] = {
        {0xc51f3873,
         0x7aec,
         0x447d,
         {0x96, 0xef, 0xa5, 0x97, 0x92, 0x57, 0x1b, 0x17}},
};

static bool is_loader(uuid_t* uuid) {
    for (size_t i = 0; i < countof(loader_uuids); i++) {
        if (!memcmp(uuid, &loader_uuids[i], sizeof(uuid_t))) {
            return true;
        }
    }

    return false;
}

long __SYSCALL sys_register_app(user_addr_t img_uaddr, uint32_t img_size) {
    int rc;
    struct trusty_app* caller;
    struct trusty_app_img* app_img;
    uint32_t aligned_size;

    caller = current_trusty_app();

    LTRACEF("app: %u  addr: %#" PRIxPTR_USER " size: %#x\n", caller->app_id,
            img_uaddr, img_size);

    if (!is_loader(&caller->props.uuid)) {
        dprintf(CRITICAL,
                "app %u is not allowed to register other applications\n",
                caller->app_id);
        PRINT_TRUSTY_APP_UUID(caller->app_id, &caller->props.uuid);
        return ERR_ACCESS_DENIED;
    }

    if (!img_size) {
        dprintf(CRITICAL, "Invalid image: zero size\n");
        return ERR_INVALID_ARGS;
    }

    app_img = calloc(1, sizeof(struct trusty_app_img));
    if (!app_img) {
        dprintf(CRITICAL, "Failed to allocate memory for app img metadata\n");
        return ERR_NO_MEMORY;
    }

    aligned_size = round_up(img_size, PAGE_SIZE);

    rc = vmm_alloc(vmm_get_kernel_aspace(), "app_img", aligned_size,
                   (void**)&app_img->img_start, PAGE_SIZE_SHIFT, 0,
                   ARCH_MMU_FLAG_CACHED);
    if (rc != NO_ERROR) {
        dprintf(CRITICAL,
                "Failed(%d) to allocate memory for app img. Size: %#x\n", rc,
                aligned_size);
        goto err_vmm;
    }

    rc = copy_from_user((void*)app_img->img_start, img_uaddr, img_size);
    if (rc != NO_ERROR) {
        dprintf(CRITICAL,
                "Failed(%d) to copy app img from userspace addr: %#" PRIxPTR_USER
                " size %#x\n",
                rc, img_uaddr, img_size);
        goto err_copy;
    }

    app_img->img_end = app_img->img_start + aligned_size;
    rc = trusty_app_create(app_img, 0);
    if (rc != NO_ERROR) {
        dprintf(CRITICAL, "Failed(%d) to register app\n", rc);
        goto err_create;
    }

    return NO_ERROR;

err_create:
err_copy:
    vmm_free_region_etc(vmm_get_kernel_aspace(), app_img->img_start,
                        aligned_size, 0);
err_vmm:
    free(app_img);
    return rc;
}

long __SYSCALL sys_unregister_app(user_addr_t app_uuid) {
    int rc;
    struct trusty_app* caller;
    struct trusty_app* target = NULL;
    uuid_t target_uuid;

    caller = current_trusty_app();

    if (!is_loader(&caller->props.uuid)) {
        dprintf(CRITICAL,
                "app %u is not allowed to unregister other applications\n",
                caller->app_id);
        PRINT_TRUSTY_APP_UUID(caller->app_id, &caller->props.uuid);
        return ERR_ACCESS_DENIED;
    }

    rc = copy_from_user(&target_uuid, app_uuid, sizeof(uuid_t));
    if (rc != NO_ERROR) {
        dprintf(CRITICAL,
                "Failed(%d) to copy uuid from userspace addr: %#" PRIxPTR_USER
                " size %#zx\n",
                rc, app_uuid, sizeof(uuid_t));
        return rc;
    }

    mutex_acquire(&apps_lock);
    target = trusty_app_find_by_uuid_locked(&target_uuid);
    if (!target) {
        rc = ERR_NOT_FOUND;
        goto out;
    }

    if (target->flags & APP_FLAGS_BUILTIN) {
        rc = ERR_NOT_ALLOWED;
        goto out;
    }

    if (target->state == APP_NOT_RUNNING) {
        trusty_app_destroy_locked(target);
    } else {
        target->flags |= APP_FLAGS_UNLOAD_PENDING;
        rc = ERR_BUSY;
    }

out:
    mutex_release(&apps_lock);

    return rc;
}

#else /* TEST_BUILD */

long __SYSCALL sys_register_app(user_addr_t img_uaddr, uint32_t img_size) {
    return ERR_NOT_SUPPORTED;
}

long __SYSCALL sys_unregister_app(user_addr_t app_uuid) {
    return ERR_NOT_SUPPORTED;
}

#endif /* TEST_BUILD */
