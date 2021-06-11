/*
 * Copyright (c) 2020, Google Inc. All rights reserved
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

#define LOCAL_TRACE 0

#include <err.h>
#include <interface/apploader/apploader.h>
#include <interface/apploader/apploader_secure.h>
#include <inttypes.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <lib/trusty/handle_set.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lib/trusty/memref.h>
#include <lk/err_ptr.h>
#include <lk/init.h>
#include <lk/trace.h>
#include <string.h>
#include <uapi/mm.h>

struct apploader_service {
    struct handle* port;
    struct handle* hset;
};

struct apploader_channel_ctx {
    struct handle_ref href;
    struct vmm_obj_slice vmm_obj_slice;
};

/* UUID: {081ba88f-f1ee-452e-b5e8-a7e9ef173a97} */
static const struct uuid apploader_user_uuid = {
        0x081ba88f,
        0xf1ee,
        0x452e,
        {0xb5, 0xe8, 0xa7, 0xe9, 0xef, 0x17, 0x3a, 0x97},
};

#if TEST_BUILD
/* UUID: {c549cb7c-f8dc-4063-8661-ef34fb3be6fc} */
static const struct uuid apploader_unittest_uuid = {
        0xc549cb7c,
        0xf8dc,
        0x4063,
        {0x86, 0x61, 0xef, 0x34, 0xfb, 0x3b, 0xe6, 0xfc},
};
#endif

struct apploader_secure_req {
    struct apploader_secure_header hdr;
    union {
        struct apploader_secure_get_memory_req get_memory_req;
        struct apploader_secure_load_app_req load_app_req;
    };
} __PACKED;

/*
 * Common structure covering all possible apploader messages, only used to
 * determine the maximum message size
 */
union apploader_longest_secure_msg {
    struct apploader_secure_req req;
    struct apploader_secure_resp resp;
} __PACKED;

static int apploader_service_translate_error(status_t rc) {
    switch (rc) {
    case ERR_NO_MEMORY:
        return APPLOADER_ERR_NO_MEMORY;
    case ERR_ALREADY_EXISTS:
        return APPLOADER_ERR_ALREADY_EXISTS;
    default:
        TRACEF("%s: unrecognized error (%d)\n", __func__, rc);
        return APPLOADER_ERR_INTERNAL;
    }
}

static int apploader_service_send_response(struct handle* chan,
                                           uint32_t cmd,
                                           uint32_t error,
                                           struct handle** handles,
                                           uint32_t num_handles) {
    struct apploader_secure_resp resp = {
            .hdr =
                    {
                            .cmd = cmd | APPLOADER_SECURE_RESP_BIT,
                    },
            .error = error,
    };
    struct iovec_kern resp_iov = {
            .iov_base = (void*)&resp,
            .iov_len = sizeof(resp),
    };
    struct ipc_msg_kern resp_msg = {
            .iov = &resp_iov,
            .num_iov = 1,
            .handles = handles,
            .num_handles = num_handles,
    };

    int rc = ipc_send_msg(chan, &resp_msg);
    if (rc < 0)
        return rc;

    if (rc != (int)sizeof(resp)) {
        return ERR_BAD_LEN;
    }

    return NO_ERROR;
}

static int apploader_service_handle_cmd_get_memory(
        struct apploader_channel_ctx* channel_ctx,
        struct apploader_secure_get_memory_req* req) {
    int rc;
    uint32_t resp_error;
    struct handle* chan = channel_ctx->href.handle;

    if (channel_ctx->vmm_obj_slice.obj) {
        TRACEF("%s: client already holds a memref\n", __func__);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_chan_has_memref;
    }

    if (!req->package_size) {
        TRACEF("%s: 0-sized GET_MEMORY request\n", __func__);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_zero_size;
    }

    uint64_t aligned_size = round_up(req->package_size, PAGE_SIZE);
    LTRACEF("Handling GET_MEMORY command, package size %" PRIu64
            " bytes, %" PRIu64 " aligned\n",
            req->package_size, aligned_size);

    struct vmm_obj* vmm_obj;
    struct obj_ref vmm_obj_ref = OBJ_REF_INITIAL_VALUE(vmm_obj_ref);
    rc = pmm_alloc(&vmm_obj, &vmm_obj_ref, aligned_size / PAGE_SIZE, 0, 0);
    if (rc != NO_ERROR) {
        TRACEF("%s: error (%d) allocating memory\n", __func__, rc);
        resp_error = apploader_service_translate_error(rc);
        goto err_alloc;
    }

    struct handle* memref_handle;
    uint32_t prot_flags = MMAP_FLAG_PROT_READ | MMAP_FLAG_PROT_WRITE;
    rc = memref_create_from_vmm_obj(vmm_obj, 0, aligned_size, prot_flags,
                                    &memref_handle);
    if (rc != NO_ERROR) {
        TRACEF("%s: error (%d) creating memref\n", __func__, rc);
        resp_error = apploader_service_translate_error(rc);
        goto err_memref_create;
    }

    rc = apploader_service_send_response(chan, APPLOADER_SECURE_CMD_GET_MEMORY,
                                         APPLOADER_NO_ERROR, &memref_handle, 1);
    if (rc < 0) {
        TRACEF("%s: error (%d) sending response\n", __func__, rc);
    } else {
        vmm_obj_slice_bind(&channel_ctx->vmm_obj_slice, vmm_obj, 0,
                           aligned_size);
    }

    handle_decref(memref_handle);
    vmm_obj_del_ref(vmm_obj, &vmm_obj_ref);

    return rc;

err_memref_create:
    vmm_obj_del_ref(vmm_obj, &vmm_obj_ref);
err_alloc:
err_zero_size:
err_chan_has_memref:
    return apploader_service_send_response(
            chan, APPLOADER_SECURE_CMD_GET_MEMORY, resp_error, NULL, 0);
}

static int apploader_service_handle_cmd_load_application(
        struct apploader_channel_ctx* channel_ctx,
        struct apploader_secure_load_app_req* req) {
    int rc;
    uint32_t resp_error;
    struct handle* chan = channel_ctx->href.handle;

    if (!channel_ctx->vmm_obj_slice.obj) {
        TRACEF("%s: invalid handle\n", __func__);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_invalid_handle;
    }

    if (!vmm_obj_has_only_ref(channel_ctx->vmm_obj_slice.obj,
                              &channel_ctx->vmm_obj_slice.obj_ref)) {
        TRACEF("%s: service not holding single reference to memref\n",
               __func__);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_invalid_refcount;
    }

    if (req->manifest_start >= req->manifest_end ||
        req->manifest_end > channel_ctx->vmm_obj_slice.size) {
        TRACEF("%s: received invalid manifest offsets: 0x%" PRIx64 "-0x%" PRIx64
               "\n",
               __func__, req->manifest_start, req->manifest_end);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_invalid_manifest_offsets;
    }

    if (req->img_start >= req->img_end ||
        req->img_end > channel_ctx->vmm_obj_slice.size) {
        TRACEF("%s: received invalid image offsets: 0x%" PRIx64 "-0x%" PRIx64
               "\n",
               __func__, req->img_start, req->img_end);
        resp_error = APPLOADER_ERR_INVALID_CMD;
        goto err_invalid_image_offsets;
    }

    LTRACEF("Handling LOAD_APPLICATION command, package size %zd bytes\n",
            channel_ctx->vmm_obj_slice.size);

    void* va;
    rc = vmm_alloc_obj(vmm_get_kernel_aspace(), "app package",
                       channel_ctx->vmm_obj_slice.obj, 0,
                       channel_ctx->vmm_obj_slice.size, &va, 0, 0,
                       ARCH_MMU_FLAG_PERM_NO_EXECUTE | ARCH_MMU_FLAG_PERM_RO);
    if (rc != NO_ERROR) {
        TRACEF("%s: error (%d) allocation memory for vmm object\n", __func__,
               rc);
        resp_error = apploader_service_translate_error(rc);
        goto err_alloc_app;
    }

    struct trusty_app_img* app_img = calloc(1, sizeof(struct trusty_app_img));
    if (!app_img) {
        TRACEF("%s: error (%d) allocating struct trusty_app_img\n", __func__,
               rc);
        resp_error = APPLOADER_ERR_NO_MEMORY;
        goto err_alloc_app_img;
    }

    if (__builtin_add_overflow((uintptr_t)va, req->manifest_start,
                               &app_img->manifest_start) ||
        __builtin_add_overflow((uintptr_t)va, req->manifest_end,
                               &app_img->manifest_end) ||
        __builtin_add_overflow((uintptr_t)va, req->img_start,
                               &app_img->img_start) ||
        __builtin_add_overflow((uintptr_t)va, req->img_end,
                               &app_img->img_end)) {
        TRACEF("%s: overflow when computing trusty_app pointers\n", __func__);
        resp_error = APPLOADER_ERR_LOADING_FAILED;
        goto err_trusty_app_overflow;
    }

    rc = trusty_app_create_and_start(app_img, APP_FLAGS_LOADABLE);
    if (rc < 0) {
        TRACEF("%s: error (%d) creating Trusty app\n", __func__, rc);
        if (rc == ERR_NOT_VALID) {
            resp_error = APPLOADER_ERR_LOADING_FAILED;
        } else {
            resp_error = apploader_service_translate_error(rc);
        }
        goto err_create_app;
    }

    /* Release the slice to prevent clients from loading the app twice */
    vmm_obj_slice_release(&channel_ctx->vmm_obj_slice);

    return apploader_service_send_response(
            chan, APPLOADER_SECURE_CMD_LOAD_APPLICATION, APPLOADER_NO_ERROR,
            NULL, 0);

err_create_app:
err_trusty_app_overflow:
    free(app_img);
err_alloc_app_img:
    vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)va);
err_alloc_app:
err_invalid_image_offsets:
err_invalid_manifest_offsets:
err_invalid_refcount:
    vmm_obj_slice_release(&channel_ctx->vmm_obj_slice);
err_invalid_handle:
    return apploader_service_send_response(
            chan, APPLOADER_SECURE_CMD_LOAD_APPLICATION, resp_error, NULL, 0);
}

static int apploader_service_read_request(struct handle* chan,
                                          struct apploader_secure_req* req) {
    int rc;
    struct ipc_msg_info msg_inf;
    rc = ipc_get_msg(chan, &msg_inf);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to get IPC message\n", __func__, rc);
        return rc;
    }

    if (msg_inf.len < sizeof(req->hdr) || msg_inf.len > sizeof(*req)) {
        TRACEF("%s: message is too short or too long (%zd)\n", __func__,
               msg_inf.len);
        rc = ERR_BAD_LEN;
        goto err;
    }

    struct iovec_kern iov = {
            .iov_base = (void*)req,
            .iov_len = sizeof(*req),
    };
    struct ipc_msg_kern msg = {
            .iov = &iov,
            .num_iov = 1,
            .handles = NULL,
            .num_handles = 0,
    };
    rc = ipc_read_msg(chan, msg_inf.id, 0, &msg);
    ASSERT(rc < 0 || (size_t)rc == msg_inf.len);

err:
    ipc_put_msg(chan, msg_inf.id);
    return rc;
}

static int apploader_service_handle_msg(
        struct apploader_channel_ctx* channel_ctx) {
    int rc;
    struct handle* chan = channel_ctx->href.handle;
    struct apploader_secure_req req;
    rc = apploader_service_read_request(chan, &req);
    if (rc < 0) {
        TRACEF("%s: failed (%d) to read apploader request\n", __func__, rc);
        return rc;
    }

    size_t cmd_len;
    switch (req.hdr.cmd) {
    case APPLOADER_SECURE_CMD_GET_MEMORY:
        /* Check the message length */
        cmd_len = sizeof(req.hdr) + sizeof(req.get_memory_req);
        if (rc != (int)cmd_len) {
            TRACEF("%s: expected to read %zu bytes, got %d\n", __func__,
                   cmd_len, rc);
            rc = apploader_service_send_response(
                    chan, req.hdr.cmd, APPLOADER_ERR_INVALID_CMD, NULL, 0);
            break;
        }

        rc = apploader_service_handle_cmd_get_memory(channel_ctx,
                                                     &req.get_memory_req);
        break;

    case APPLOADER_SECURE_CMD_LOAD_APPLICATION:
        /* Check the message length */
        cmd_len = sizeof(req.hdr) + sizeof(req.load_app_req);
        if (rc != (int)cmd_len) {
            TRACEF("%s: expected to read %zu bytes, got %d\n", __func__,
                   cmd_len, rc);
            rc = apploader_service_send_response(
                    chan, req.hdr.cmd, APPLOADER_ERR_INVALID_CMD, NULL, 0);
            break;
        }

        rc = apploader_service_handle_cmd_load_application(channel_ctx,
                                                           &req.load_app_req);
        break;

    default:
        TRACEF("%s: received unknown apploader service command: %" PRIu32 "\n",
               __func__, req.hdr.cmd);
        rc = apploader_service_send_response(
                chan, req.hdr.cmd, APPLOADER_ERR_UNKNOWN_CMD, NULL, 0);
        break;
    }

    if (rc < 0) {
        TRACEF("%s: failed to run command (%d)\n", __func__, rc);
    }

    return rc;
}

static void apploader_service_channel_close(
        struct apploader_channel_ctx* hctx) {
    handle_close(hctx->href.handle);
    vmm_obj_slice_release(&hctx->vmm_obj_slice);
    free(hctx);
}

static void apploader_service_handle_channel_event(struct handle_ref* event) {
    int rc;
    struct apploader_channel_ctx* channel_ctx = event->cookie;

    DEBUG_ASSERT(channel_ctx->href.handle == event->handle);

    if (event->emask & IPC_HANDLE_POLL_MSG) {
        rc = apploader_service_handle_msg(channel_ctx);

        if (rc != NO_ERROR) {
            TRACEF("%s: handle_msg failed (%d). Closing channel.\n", __func__,
                   rc);
            goto err;
        }
    }

    if (event->emask & IPC_HANDLE_POLL_HUP) {
        goto err;
    }
    return;

err:
    handle_set_detach_ref(&channel_ctx->href);
    apploader_service_channel_close(channel_ctx);
}

static void apploader_service_handle_port_event(struct apploader_service* ctx,
                                                struct handle_ref* event) {
    int rc;
    struct apploader_channel_ctx* channel_ctx;
    struct handle* channel;
    const struct uuid* peer_uuid;

    if (event->emask & IPC_HANDLE_POLL_READY) {
        rc = ipc_port_accept(event->handle, &channel, &peer_uuid);
        LTRACEF("accept returned %d\n", rc);

        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) to accept incoming connection\n", __func__,
                   rc);
            goto err_accept;
        }

        /*
         * Check peer UUID against the known apploader client.
         *
         * The unit test application is also allowed to connect in test builds,
         * since it tests both the user space client and this service from a
         * single set of unit tests.
         */
        if (memcmp(peer_uuid, &apploader_user_uuid, sizeof(struct uuid))
#if TEST_BUILD
            && memcmp(peer_uuid, &apploader_unittest_uuid, sizeof(struct uuid))
#endif
        ) {
            TRACEF("%s: received connection from unknown peer\n", __func__);
            goto err_bad_uuid;
        }

        channel_ctx = calloc(1, sizeof(struct apploader_channel_ctx));
        if (!channel_ctx) {
            TRACEF("%s: failed to allocate a apploader_channel_ctx\n",
                   __func__);
            goto err_alloc_channel_ctx;
        }
        vmm_obj_slice_init(&channel_ctx->vmm_obj_slice);

        /* to retrieve channel_ctx from a handle_set_wait() event */
        channel_ctx->href.cookie = channel_ctx;
        channel_ctx->href.handle = channel;
        channel_ctx->href.emask = ~0U;

        rc = handle_set_attach(ctx->hset, &channel_ctx->href);
        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) handle_set_attach()\n", __func__, rc);
            apploader_service_channel_close(channel_ctx);
            return;
        }
    }
    return;

err_alloc_channel_ctx:
err_bad_uuid:
    handle_close(channel);
err_accept:
    return;
}

static void apploader_service_loop(struct apploader_service* ctx) {
    int rc;
    struct handle_ref event;

    while (true) {
        rc = handle_set_wait(ctx->hset, &event, INFINITE_TIME);
        if (rc != NO_ERROR) {
            TRACEF("%s: handle_set_wait failed: %d\n", __func__, rc);
            break;
        }

        LTRACEF("%s: got handle set event rc=%d ev=%x handle=%p cookie=%p\n",
                __func__, rc, event.emask, event.handle, event.cookie);
        /* This only works for services with a single port, like apploader */
        if (event.handle == ctx->port) {
            LTRACEF("%s: handling port event\n", __func__);
            apploader_service_handle_port_event(ctx, &event);
        } else {
            LTRACEF("%s: handling channel event\n", __func__);
            apploader_service_handle_channel_event(&event);
        }
        handle_decref(event.handle);
    }
}

static int apploader_service_thread(void* arg) {
    int rc;
    struct apploader_service ctx;

    ctx.hset = handle_set_create();
    if (!ctx.hset) {
        TRACEF("%s: failed to create handle set\n", __func__);
        rc = ERR_NO_MEMORY;
        goto err_hset_create;
    }

    rc = ipc_port_create(&kernel_uuid, APPLOADER_SECURE_PORT, 1,
                         sizeof(union apploader_longest_secure_msg),
                         IPC_PORT_ALLOW_TA_CONNECT, &ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to create apploader port\n", __func__, rc);
        goto err_port_create;
    }

    rc = ipc_port_publish(ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to publish apploader port\n", __func__, rc);
        goto err_port_publish;
    }

    struct handle_ref port_href = {
            .handle = ctx.port,
            .emask = ~0U,
    };
    rc = handle_set_attach(ctx.hset, &port_href);
    if (rc < 0) {
        TRACEF("%s: failed (%d) handle_set_attach() port\n", __func__, rc);
        goto err_hset_add_port;
    }

    apploader_service_loop(&ctx);
    TRACEF("%s: apploader_service_loop() returned. apploader service exiting.\n",
           __func__);

    handle_set_detach_ref(&port_href);

err_hset_add_port:
err_port_publish:
    handle_close(ctx.port);
err_port_create:
    handle_close(ctx.hset);
err_hset_create:
    return rc;
}

static void apploader_service_init(uint level) {
    struct thread* thread =
            thread_create("apploader-service", apploader_service_thread, NULL,
                          DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    if (!thread) {
        TRACEF("%s: failed to create apploader-service thread\n", __func__);
        return;
    }
    thread_detach_and_resume(thread);
}

LK_INIT_HOOK(apploader, apploader_service_init, LK_INIT_LEVEL_APPS + 1);
