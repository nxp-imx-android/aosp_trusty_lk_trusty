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
#include <lib/ktipc/ktipc.h>
#include <lib/trusty/handle_set.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lk/init.h>
#include <lk/trace.h>
#include <services/smc/acl.h>
#include <string.h>

#define LOCAL_TRACE (0)

struct smc_channel_ctx {
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

static int smc_service_handle_msg(const struct ktipc_port* port,
                                  struct handle* channel,
                                  void* ctx) {
    struct smc_channel_ctx* channel_ctx = ctx;
    int rc;
    struct smc_msg request;
    uint32_t smc_nr;

    rc = ktipc_recv(channel, sizeof(request), &request, sizeof(request));
    if ((size_t)rc != sizeof(request)) {
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
    rc = ktipc_send(channel, &response, sizeof(response));
    if ((size_t)rc != sizeof(response)) {
        TRACEF("%s: failed (%d) to send response\n", __func__, rc);
    }

err:
    return rc;
}

static int smc_service_handle_connect(const struct ktipc_port* port,
                                      struct handle* chan,
                                      const struct uuid* peer_uuid,
                                      void** ctx_p) {
    struct smc_channel_ctx* channel_ctx = calloc(1, sizeof(*channel_ctx));
    if (!channel_ctx) {
        TRACEF("%s: failed to allocate smc_channel_ctx\n", __func__);
        return ERR_NO_MEMORY;
    }

    smc_load_access_policy(peer_uuid, &channel_ctx->policy);

    *ctx_p = channel_ctx;

    return NO_ERROR;
}

static void smc_service_handle_channel_cleanup(void* ctx) {
    struct smc_channel_ctx* channel_ctx = ctx;
    free(channel_ctx);
}

const static struct ktipc_srv_ops smc_service_ops = {
        .on_connect = smc_service_handle_connect,
        .on_message = smc_service_handle_msg,
        .on_channel_cleanup = smc_service_handle_channel_cleanup,
};

const static struct ktipc_port_acl smc_service_port_acl = {
        .flags = IPC_PORT_ALLOW_TA_CONNECT,
        .uuids = NULL,
        .uuid_num = 0,
        .extra_data = NULL,
};

const static struct ktipc_port smc_service_port = {
        .name = SMC_SERVICE_PORT,
        .uuid = &kernel_uuid,
        .msg_max_size = sizeof(struct smc_msg),
        .msg_queue_len = 1,
        .acl = &smc_service_port_acl,
        .priv = NULL,
};

static struct ktipc_server smc_ktipc_server =
        KTIPC_SERVER_INITIAL_VALUE(smc_ktipc_server, "smc_ktipc_server");

static void smc_service_init(uint level) {
    int rc;

    rc = ktipc_server_start(&smc_ktipc_server);
    if (rc < 0) {
        panic("Failed (%d) to start smc server\n", rc);
    }

    rc = ktipc_server_add_port(&smc_ktipc_server, &smc_service_port,
                               &smc_service_ops);
    if (rc < 0) {
        panic("Failed (%d) to create smc port\n", rc);
    }
}

LK_INIT_HOOK(smc, smc_service_init, LK_INIT_LEVEL_APPS);
