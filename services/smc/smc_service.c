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
#include <services/smc/acl.h>
#include <string.h>

#define LOCAL_TRACE (0)

struct smc_service {
    struct handle* port;
    struct handle* hset;
};

struct smc_channel_ctx {
    struct handle* handle;
    struct handle_ref* href;
    struct smc_access_policy policy;
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
            .iov_base = (void*)msg,
            .iov_len = msg_len,
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
            .iov_base = (void*)msg,
            .iov_len = msg_len,
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

static int handle_msg(struct smc_channel_ctx* channel_ctx) {
    int rc;
    struct handle* channel = channel_ctx->handle;
    struct smc_msg request;
    uint32_t smc_nr;

    rc = smc_read_request(channel, &request);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to read SMC request\n", __func__, rc);
        goto err;
    }

    smc_nr = (uint32_t)request.params[0];
    rc = channel_ctx->policy.check_access(smc_nr);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) client not allowed to call SMC number %x\n",
               __func__, rc, smc_nr);
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
 * Adds a given channel to a given handle set. On success, returns pointer to
 * added handle_ref. Otherwise, returns NULL.
 */
static struct handle_ref* hset_add_channel(struct handle* hset,
                                           struct smc_channel_ctx* hctx) {
    int rc;
    struct handle_ref* href;

    href = calloc(1, sizeof(struct handle_ref));
    if (!href) {
        TRACEF("%s: failed to allocate a handle_ref\n", __func__);
        goto err_href_alloc;
    }

    handle_incref(hctx->handle);
    href->handle = hctx->handle;
    href->emask = ~0U;

    /* to retrieve handle_ref from a handle_set_wait() event */
    hctx->href = href;
    href->cookie = hctx;

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

static void hset_remove_channel(struct handle_ref* href) {
    handle_set_detach_ref(href);
    handle_decref(href->handle);
    free(href);
}

static void smc_channel_close(struct smc_channel_ctx* hctx) {
    handle_decref(hctx->handle);
    free(hctx);
}

static void handle_channel_event(struct handle_ref* event) {
    int rc;
    struct smc_channel_ctx* channel_ctx = event->cookie;

    DEBUG_ASSERT(channel_ctx->href->handle == event->handle);

    if (event->emask & IPC_HANDLE_POLL_MSG) {
        rc = handle_msg(channel_ctx);

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
    hset_remove_channel(channel_ctx->href);
    smc_channel_close(channel_ctx);
}

static void handle_port_event(struct smc_service* ctx,
                              struct handle_ref* event) {
    int rc;
    struct smc_channel_ctx* channel_ctx;
    struct handle* channel;
    const struct uuid* peer_uuid;

    if (event->emask & IPC_HANDLE_POLL_READY) {
        rc = ipc_port_accept(event->handle, &channel, &peer_uuid);
        LTRACEF("accept returned %d\n", rc);

        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) to accept incoming connection\n", __func__,
                   rc);
            goto err;
        }

        channel_ctx = calloc(1, sizeof(struct smc_channel_ctx));
        if (!channel_ctx) {
            TRACEF("%s: failed to allocate a smc_channel_ctx\n", __func__);
            goto err;
        }
        channel_ctx->handle = channel;
        smc_load_access_policy(peer_uuid, &channel_ctx->policy);

        if (!hset_add_channel(ctx->hset, channel_ctx)) {
            goto err_hset_add_channel;
        }
    }
    return;

err_hset_add_channel:
    smc_channel_close(channel_ctx);
err:
    return;
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

    rc = ipc_port_create(&kernel_uuid, SMC_SERVICE_PORT, 1,
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

    port_href = calloc(1, sizeof(struct handle_ref));
    if (!port_href) {
        TRACEF("%s: failed to allocate a port handle_ref\n", __func__);
        goto err_port_href_alloc;
    }
    port_href->handle = ctx.port;
    port_href->emask = ~0U;

    rc = handle_set_attach(ctx.hset, port_href);
    if (rc < 0) {
        TRACEF("%s: failed (%d) handle_set_attach() port\n", __func__, rc);
        goto err_hset_add_port;
    }

    smc_service_loop(&ctx);
    TRACEF("%s: smc_service_loop() returned. SMC service exiting.\n", __func__);

err_smc_service_loop:
    handle_set_detach_ref(port_href);
err_hset_add_port:
    free(port_href);
err_port_href_alloc:
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
