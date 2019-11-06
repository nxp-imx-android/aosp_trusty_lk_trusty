/*
 * Copyright (c) 2019, Google Inc. All rights reserved
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
#include <interface/smc/smc.h>
#include <kernel/thread.h>
#include <lib/trusty/handle_set.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lk/init.h>
#include <lk/trace.h>
#include <string.h>

#define LOCAL_TRACE (0)

struct smc_service {
    struct handle* port;
    struct handle* hset;
};

/* UUID: {4ae225ec-20f2-4264-9a3f-935f90a42ddc} */
static const struct uuid smc_service_uuid = {
        0x4ae225ec,
        0x20f2,
        0x4264,
        {0x9a, 0x3f, 0x93, 0x5f, 0x90, 0xa4, 0x2d, 0xdc},
};

/**
 * struct smc_regs - Struct representing input/output registers of an SMC
 * @r0-3: registers r0-3/x0-3 for 32/64 bit respectively
 */
struct smc_regs {
    ulong r0;
    ulong r1;
    ulong r2;
    ulong r3;
};

#if ARCH_ARM64
#define SMC_ARG0 "x0"
#define SMC_ARG1 "x1"
#define SMC_ARG2 "x2"
#define SMC_ARG3 "x3"
#define SMC_ARCH_EXTENSION ""
#define SMC_REGISTERS_TRASHED                                              \
    "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", \
            "x15", "x16", "x17"
#else
#define SMC_ARG0 "r0"
#define SMC_ARG1 "r1"
#define SMC_ARG2 "r2"
#define SMC_ARG3 "r3"
#define SMC_ARCH_EXTENSION ".arch_extension sec\n"
#define SMC_REGISTERS_TRASHED "ip"
#endif

/* Perform a secure manager call with up to 4 inputs and 4 outputs */
static struct smc_regs smc(struct smc_regs* regs) {
    register ulong _r0 __asm__(SMC_ARG0) = regs->r0;
    register ulong _r1 __asm__(SMC_ARG1) = regs->r1;
    register ulong _r2 __asm__(SMC_ARG2) = regs->r2;
    register ulong _r3 __asm__(SMC_ARG3) = regs->r3;
    __asm__ volatile(SMC_ARCH_EXTENSION "smc #0"
                     : "=r"(_r0), "=r"(_r1), "=r"(_r2), "=r"(_r3)
                     : "r"(_r0), "r"(_r1), "r"(_r2), "r"(_r3)
                     : SMC_REGISTERS_TRASHED);
    return (struct smc_regs){
            .r0 = _r0,
            .r1 = _r1,
            .r2 = _r2,
            .r3 = _r3,
    };
}

/* Read SMC service request from userspace client */
static int smc_read_request(struct handle* channel, struct smc_msg* msg) {
    int rc;
    struct ipc_msg_info msg_info;
    size_t msg_len = sizeof(struct smc_msg);

    rc = ipc_get_msg(channel, &msg_info);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to get message\n", __func__, rc);
        goto err;
    }

    struct iovec_kern iov = {
            .base = (void*)msg,
            .len = msg_len,
    };
    struct ipc_msg_kern ipc_msg = {
            .num_iov = 1,
            .iov = &iov,
            .num_handles = 0,
            .handles = NULL,
    };
    rc = ipc_read_msg(channel, msg_info.id, 0, &ipc_msg);
    if (rc != (int)msg_len) {
        TRACEF("%s: failed (%d) to read message. Expected to read %zu bytes.\n",
               __func__, rc, msg_len);
        rc = ERR_BAD_LEN;
    } else {
        rc = NO_ERROR;
    }
    ipc_put_msg(channel, msg_info.id);

err:
    return rc;
}

/* Send SMC service reply to userspace client */
static int smc_send_response(struct handle* channel, struct smc_msg* msg) {
    int rc;
    size_t msg_len = sizeof(struct smc_msg);
    struct iovec_kern iov = {
            .base = (void*)msg,
            .len = msg_len,
    };
    struct ipc_msg_kern ipc_msg = {
            .num_iov = 1,
            .iov = &iov,
            .num_handles = 0,
            .handles = NULL,
    };

    rc = ipc_send_msg(channel, &ipc_msg);
    if (rc != (int)msg_len) {
        TRACEF("%s: failed (%d) to send message. Expected to send %zu bytes.\n",
               __func__, rc, msg_len);
        rc = ERR_BAD_LEN;
    } else {
        rc = NO_ERROR;
    }
    return rc;
}

static int handle_msg(struct handle* channel) {
    int rc;

    struct smc_msg request;
    rc = smc_read_request(channel, &request);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to read SMC request\n", __func__, rc);
        goto err;
    }

    struct smc_regs args = {
            .r0 = (ulong)request.params[0],
            .r1 = (ulong)request.params[1],
            .r2 = (ulong)request.params[2],
            .r3 = (ulong)request.params[3],
    };
    struct smc_regs ret = smc(&args);

    struct smc_msg response = {
            .params[0] = ret.r0,
            .params[1] = ret.r1,
            .params[2] = ret.r2,
            .params[3] = ret.r3,
    };
    rc = smc_send_response(channel, &response);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to send response\n", __func__, rc);
    }

err:
    return rc;
}

/*
 * Adds a given handle to a given handle set. On success, returns pointer to
 * added handle_ref. Otherwise, returns NULL.
 */
static struct handle_ref* hset_add_handle(struct handle* hset,
                                          struct handle* h) {
    int rc;
    struct handle_ref* href;

    href = calloc(1, sizeof(struct handle_ref));
    if (!href) {
        TRACEF("%s: failed to allocate a handle_ref\n", __func__);
        goto err_href_alloc;
    }

    handle_incref(h);
    href->handle = h;
    href->emask = ~0U;

    /* to retrieve handle_ref from a handle_set_wait() event */
    href->cookie = href;

    rc = handle_set_attach(hset, href);
    if (rc < 0) {
        TRACEF("%s: failed (%d) handle_set_attach()\n", __func__, rc);
        goto err_hset_attach;
    }
    return href;

err_hset_attach:
    handle_decref(href->handle);
    free(href);
err_href_alloc:
    return NULL;
}

static void hset_remove_handle(struct handle_ref* href) {
    handle_set_detach_ref(href);
    handle_decref(href->handle);
    free(href);
}

static void handle_channel_event(struct handle_ref* event) {
    int rc;
    struct handle_ref* channel_ref = event->cookie;
    struct handle* channel = event->handle;

    DEBUG_ASSERT(channel_ref->handle == channel);

    if (event->emask & IPC_HANDLE_POLL_MSG) {
        rc = handle_msg(channel);

        if (rc != NO_ERROR) {
            TRACEF("%s: handle_msg failed (%d). Closing channel.\n", __func__,
                   rc);
            hset_remove_handle(channel_ref);
            return;
        }
    }

    if (event->emask & IPC_HANDLE_POLL_HUP) {
        hset_remove_handle(channel_ref);
    }
}

static void handle_port_event(struct smc_service* ctx,
                              struct handle_ref* event) {
    int rc;
    struct handle* channel;
    const struct uuid* dummy_uuid_ptr;

    if (event->emask & IPC_HANDLE_POLL_READY) {
        rc = ipc_port_accept(event->handle, &channel, &dummy_uuid_ptr);
        LTRACEF("accept returned %d\n", rc);

        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) to accept incoming connection\n", __func__,
                   rc);
            return;
        }

        hset_add_handle(ctx->hset, channel);
        handle_decref(channel);
    }
}

static void smc_service_loop(struct smc_service* ctx) {
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
        if (event.handle == ctx->port) {
            LTRACEF("%s: handling port event\n", __func__);
            handle_port_event(ctx, &event);
        } else {
            LTRACEF("%s: handling channel event\n", __func__);
            handle_channel_event(&event);
        }
        handle_decref(event.handle);
    }
}

static int smc_service_thread(void* arg) {
    int rc;
    struct handle_ref* port_href;
    struct smc_service ctx;

    ctx.hset = handle_set_create();
    if (!ctx.hset) {
        TRACEF("%s: failed to create handle set\n", __func__);
        rc = ERR_NO_MEMORY;
        goto err_hset_create;
    }

    rc = ipc_port_create(&smc_service_uuid, SMC_SERVICE_PORT, 1,
                         sizeof(struct smc_msg), IPC_PORT_ALLOW_TA_CONNECT,
                         &ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to create smc port\n", __func__, rc);
        goto err_port_create;
    }

    rc = ipc_port_publish(ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to publish smc port\n", __func__, rc);
        goto err_port_publish;
    }

    port_href = hset_add_handle(ctx.hset, ctx.port);
    if (!port_href) {
        TRACEF("%s: failed (%d) to and to handle set\n", __func__, rc);
        goto err_hset_add_handle;
    }

    smc_service_loop(&ctx);
    TRACEF("%s: smc_service_loop() returned. SMC service exiting.\n", __func__);

err_smc_service_loop:
    hset_remove_handle(port_href);
err_hset_add_handle:
err_port_publish:
    handle_close(ctx.port);
err_port_create:
    handle_close(ctx.hset);
err_hset_create:
    return rc;
}

static void smc_service_init(uint level) {
    struct thread* thread =
            thread_create("smc-service", smc_service_thread, NULL,
                          DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    if (!thread) {
        TRACEF("%s: failed to create smc-service thread\n", __func__);
        return;
    }
    thread_detach_and_resume(thread);
}

LK_INIT_HOOK(smc, smc_service_init, LK_INIT_LEVEL_APPS);
