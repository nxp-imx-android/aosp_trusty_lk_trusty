/*
 * Copyright (c) 2021, Google Inc. All rights reserved
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

#define LOCAL_TRACE (2)

#include <bits.h>
#include <endian.h>
#include <err.h>
#include <interface/thread/thread.h>
#include <kernel/mp.h>
#include <kernel/thread.h>
#include <lib/trusty/handle.h>
#include <lib/trusty/handle_set.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/ipc_msg.h>
#include <lib/trusty/trusty_app.h>
#include <lk/init.h>
#include <lk/macros.h>
#include <lk/trace.h>
#include <string.h>
#include <uapi/err.h>
#include <uapi/mm.h>
#include <uapi/trusty_uuid.h>
#include "thread_service_policy.h"

struct cpu_bitmap {
    uint64_t __bits[DIV_ROUND_UP(SMP_MAX_CPUS, 8 * sizeof(uint64_t))];
};

struct thread_service {
    struct handle* port;
    struct handle* hset;
};

struct thread_service_chan_ctx {
    struct handle_ref href;
    const struct uuid* app_uuid;
    struct thread_service_policy_setaffinity policy_setaffinity;
};

struct thread_service_setaffinity_ctx {
    const struct thread_service_setaffinity_req* req;
    const struct uuid* setaffinity_uuid;
    int pinned_cpu;
    int result;
};

struct thread_service_getaffinity_ctx {
    const struct thread_service_chan_ctx* chan_ctx;
    const struct thread_service_getaffinity_req* req;
    struct thread_service_getaffinity_resp* resp;
    int pinned_cpu;
    int result;
};

struct thread_service_getpriority_ctx {
    const struct thread_service_chan_ctx* chan_ctx;
    const struct thread_service_getpriority_req* req;
    struct thread_service_getpriority_resp* resp;
    int priority;
    int result;
};

static bool equal_uuid(const struct uuid* a, const struct uuid* b) {
    return memcmp(a, b, sizeof(struct uuid)) == 0;
}

static inline void thread_service_pinned_to_cpu_set(
        int pinned_cpu,
        struct cpu_bitmap* cpu_set) {
    DEBUG_ASSERT(pinned_cpu < SMP_MAX_CPUS);
    DEBUG_ASSERT(pinned_cpu >= -1);
    STATIC_ASSERT(SMP_MAX_CPUS <= (sizeof(struct cpu_bitmap) * 8));
    STATIC_ASSERT(BYTE_ORDER == LITTLE_ENDIAN);
    memset(cpu_set, 0, sizeof(struct cpu_bitmap));
    if (pinned_cpu < 0) {
        /* cpu is not pinned, all active cpus are possible */
        for (int c = 0; c < SMP_MAX_CPUS; c++) {
            if (mp_is_cpu_active(c)) {
                bitmap_set((unsigned long*)cpu_set->__bits, c);
            }
        }
    } else {
        bitmap_set((unsigned long*)cpu_set->__bits, pinned_cpu);
    }
}

static inline int thread_service_cpu_set_to_pinned(
        const struct cpu_bitmap* cpu_set) {
    STATIC_ASSERT(SMP_MAX_CPUS <= (sizeof(struct cpu_bitmap) * 8));
    STATIC_ASSERT(BYTE_ORDER == LITTLE_ENDIAN);
    int pinned_cpu = ERR_INVALID_ARGS;
    bool reset_pinned_cpu = true;
    for (int c = 0; c < SMP_MAX_CPUS; c++) {
        if (bitmap_test((unsigned long*)cpu_set->__bits, c)) {
            /*
             * this is a stop-gap solution until the scheduler supports cpu
             * sets. for now, the lowest cpu id in the set is selected
             */
            if (pinned_cpu == ERR_INVALID_ARGS) {
                pinned_cpu = c;
            }
        } else {
            /*
             * to reset a pinned_cpu, cpu_set shall be a mask
             * with all active cpus selected.
             * so as soon as a cpu is active but its bit is not set,
             * reset is disabled
             */
            if (mp_is_cpu_active(c)) {
                reset_pinned_cpu = false;
            }
        }
    }
    if (reset_pinned_cpu) {
        return -1;  // reset value for pinned_cpu
    }
    DEBUG_ASSERT(pinned_cpu < SMP_MAX_CPUS);
    return pinned_cpu;
}

/**
 * thread_service_setaffinity_cb() - callback invoked by trusty_app_forall
 * @ta   pointer to the trusty application's structure &struct trusty_app
 * @data callback context pointer
 *
 * This callback is invoked while the apps lock is held, hence
 * allowing the thread's pointer to be safely accessed and thus
 * the pinned_cpu to be safely updated.
 */
static void thread_service_setaffinity_cb(struct trusty_app* ta, void* data) {
    struct thread_service_setaffinity_ctx* ctx = data;
    if (!equal_uuid(ctx->setaffinity_uuid, &(ta->props.uuid))) {
        return;
    }
    if (!ta->thread) {
        TRACEF("%s failed: app %d(%s) is not active (thread null)\n", __func__,
               ta->app_id, ta->props.app_name);
        return;
    }
    DEBUG_ASSERT(ta->thread->thread);
    int pinned_cpu = thread_pinned_cpu(ta->thread->thread);

    if (pinned_cpu != ctx->pinned_cpu) {
        if ((ctx->pinned_cpu > 0) && !mp_is_cpu_active(ctx->pinned_cpu)) {
            if (ctx->req->flags & THREAD_SERVICE_SETAFFINITY_FLAG_FORCE) {
                TRACEF("%s: app %d(%s), force pinning to inactive CPU: %d\n",
                       __func__, ta->app_id, ta->props.app_name,
                       ctx->pinned_cpu);
            } else {
                TRACEF("%s failed: app %d(%s) cannot pin to inactive CPU: %d\n",
                       __func__, ta->app_id, ta->props.app_name,
                       ctx->pinned_cpu);
                return;
            }
        }
        /*
         * note: ctx->pinned_cpu == -1 is valid
         * and is used to reset the cpu pinning
         */
        thread_set_pinned_cpu(ta->thread->thread, ctx->pinned_cpu);
        LTRACEF("%s: app %d(%s), pinned to CPU: %d\n", __func__, ta->app_id,
                ta->props.app_name, ctx->pinned_cpu);
    } else {
        if (ctx->pinned_cpu == -1) {
            LTRACEF("%s: app %d(%s), CPU already unpinned\n", __func__,
                    ta->app_id, ta->props.app_name);
        } else {
            LTRACEF("%s: app %d(%s), CPU already pinned to: %d\n", __func__,
                    ta->app_id, ta->props.app_name, ctx->pinned_cpu);
        }
    }
    ctx->result = NO_ERROR;
}

/**
 * thread_service_getaffinity_cb() - callback invoked by trusty_app_forall
 * @ta   pointer to the trusty application's structure &struct trusty_app
 * @data callback context pointer
 *
 * This callback is invoked while the apps lock is held, hence
 * allowing the thread's pointer to be safely accessed and thus
 * the pinned_cpu to be safely read.
 */
static void thread_service_getaffinity_cb(struct trusty_app* ta, void* data) {
    struct thread_service_getaffinity_ctx* ctx = data;
    if (!equal_uuid(ctx->chan_ctx->app_uuid, &(ta->props.uuid))) {
        return;
    }
    if (!ta->thread) {
        TRACEF("%s failed: app %d(%s) is not active (thread null)\n", __func__,
               ta->app_id, ta->props.app_name);
        return;
    }
    DEBUG_ASSERT(ta->thread->thread);
    int pinned_cpu = thread_pinned_cpu(ta->thread->thread);

    if (pinned_cpu >= 0) {
        DEBUG_ASSERT(pinned_cpu < SMP_MAX_CPUS);
    }
    ctx->pinned_cpu = pinned_cpu;
    ctx->result = NO_ERROR;
    LTRACEF("%s: app %d, %s pinned CPU: %u\n", __func__, ta->app_id,
            ta->props.app_name, pinned_cpu);
}

/**
 * thread_service_getpriority_cb() - callback invoked by trusty_app_forall
 * @ta   pointer to the trusty application's structure &struct trusty_app
 * @data callback context pointer
 *
 * This callback is invoked while the apps lock is held, hence
 * allowing the thread's pointer to be safely accessed and thus
 * the pinned_cpu to be safely read.
 */
static void thread_service_getpriority_cb(struct trusty_app* ta, void* data) {
    struct thread_service_getpriority_ctx* ctx = data;
    if (!equal_uuid(ctx->chan_ctx->app_uuid, &(ta->props.uuid))) {
        return;
    }
    if (!ta->thread) {
        TRACEF("%s failed: app %d(%s) is not active (thread null)\n", __func__,
               ta->app_id, ta->props.app_name);
        return;
    }
    DEBUG_ASSERT(ta->thread->thread);
    int priority = thread_current_priority(ta->thread->thread);

    ctx->priority = priority;
    ctx->result = NO_ERROR;
    TRACEF("%s: app %d, %s current_priority: %u\n", __func__, ta->app_id,
           ta->props.app_name, ctx->priority);
}

static inline int thread_service_setaffinity_check_flags(uint32_t flags) {
    uint32_t flags_unknown = flags;
    flags_unknown &= ~THREAD_SERVICE_SETAFFINITY_FLAG_FORCE;
    flags_unknown &= ~THREAD_SERVICE_SETAFFINITY_FLAG_PEER;
    if (flags_unknown) {
        TRACEF("%s: failed - flags (%x) are unknown\n", __func__,
               flags_unknown);
        return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

static int thread_service_setaffinity(
        const struct thread_service_setaffinity_req* req,
        const struct cpu_bitmap* cpu_set,
        const struct thread_service_chan_ctx* chan_ctx) {
    if (!req->cpu_set_elem_size) {
        TRACEF("%s: failed - cpu_set_elem_size shall be non 0, (%ul)\n",
               __func__, req->cpu_set_elem_size);
        return ERR_INVALID_ARGS;
    }
    if (!req->cpu_set_size) {
        TRACEF("%s: failed - cpu_set_size shall be non 0, (%ul)\n", __func__,
               req->cpu_set_size);
        return ERR_INVALID_ARGS;
    }
    if ((size_t)req->cpu_set_size > sizeof(struct cpu_bitmap)) {
        TRACEF("%s: failed - cpu_set_size (%zd) cannot be greater than the platform's cpu_bitmap (%zd)\n",
               __func__, (size_t)req->cpu_set_size,
               (size_t)sizeof(struct cpu_bitmap));
        return ERR_INVALID_ARGS;
    }
    int rc;
    rc = thread_service_setaffinity_check_flags(req->flags);
    if (rc) {
        return rc;
    }
    const struct uuid* peer_uuid = NULL;
    if (req->flags & THREAD_SERVICE_SETAFFINITY_FLAG_PEER) {
        // req->thread holds the peer index for now
        rc = chan_ctx->policy_setaffinity.get_peer_uuid(req->thread,
                                                        &peer_uuid);
        if (rc < 0) {
            TRACEF("%s: failed (%d) client not allowed to set affinity on peer\n",
                   __func__, rc);
            return rc;
        }
    } else {
        if (req->thread != 0) {
            TRACEF("%s: failed - thread (%lx) other than current app thread is not supported yet\n",
                   __func__, (unsigned long)req->thread);
            return ERR_INVALID_ARGS;
        }
    }

    struct thread_service_setaffinity_ctx ctx = {
            .setaffinity_uuid = peer_uuid ? peer_uuid : chan_ctx->app_uuid,
            .req = req,
            .result = ERR_INVALID_ARGS,
    };

    int pinned_req = thread_service_cpu_set_to_pinned(cpu_set);
    if (pinned_req == ERR_INVALID_ARGS) {
        TRACEF("%s: failed - cpu_set invalid (%016llx)\n", __func__,
               cpu_set->__bits[0]);
        return ERR_INVALID_ARGS;
    }
    if (pinned_req >= SMP_MAX_CPUS) {
        TRACEF("%s: failed - pinned cpu id (%u) greater than max id (%u)\n",
               __func__, pinned_req, SMP_MAX_CPUS - 1);
        return ERR_INVALID_ARGS;
    }
    ctx.pinned_cpu = pinned_req;
    trusty_app_forall(thread_service_setaffinity_cb, (void*)&ctx);
    LTRACEF("%s: thread_service_setaffinity result=%d\n", __func__, ctx.result);
    return ctx.result;
}

static int thread_service_getpriority(
        const struct thread_service_getpriority_req* req,
        struct thread_service_getpriority_resp* resp,
        const struct thread_service_chan_ctx* chan_ctx) {
    DEBUG_ASSERT(resp);
    DEBUG_ASSERT(req);
    /*
    if (req->thread != 0) {
        TRACEF("%s: failed - thread (%lx) other than current app thread is not
    supported yet\n",
               __func__, (unsigned long)req->thread);
        return ERR_INVALID_ARGS;
    }
    */

    resp->thread = req->thread;
    resp->reserved = 0;
    struct thread_service_getpriority_ctx ctx = {
            .chan_ctx = chan_ctx,
            .req = req,
            .resp = resp,
            .priority = ERR_INVALID_ARGS,
            .result = ERR_INVALID_ARGS,
    };
    trusty_app_forall(thread_service_getpriority_cb, (void*)&ctx);
    TRACEF("%s: After trusty_app_forall(), result=(%d), resp.priority=(%d), priority=(%d)\n",
           __func__, ctx.result, ctx.resp->current_priority, ctx.priority);
    if (!ctx.result) {
        resp->current_priority = ctx.priority;
    }
    return ctx.result;
}

static int thread_service_getaffinity(
        const struct thread_service_getaffinity_req* req,
        struct thread_service_getaffinity_resp* resp,
        struct cpu_bitmap* cpu_set,
        const struct thread_service_chan_ctx* chan_ctx) {
    DEBUG_ASSERT(resp);
    DEBUG_ASSERT(req);
    if (req->thread != 0) {
        TRACEF("%s: failed - thread (%lx) other than current app thread is not supported yet\n",
               __func__, (unsigned long)req->thread);
        return ERR_INVALID_ARGS;
    }
    if (!req->cpu_set_elem_size) {
        TRACEF("%s: failed - cpu_set_elem_size shall be non 0, (%ul)\n",
               __func__, req->cpu_set_elem_size);
        return ERR_INVALID_ARGS;
    }
    if ((size_t)req->cpu_set_size > sizeof(struct cpu_bitmap)) {
        TRACEF("%s: failed - cpu_set_size (%zd) cannot be greater than the platform's cpu_bitmap (%zd)\n",
               __func__, (size_t)req->cpu_set_size,
               (size_t)sizeof(struct cpu_bitmap));
        return ERR_INVALID_ARGS;
    }
    if (req->cpu_set_size < DIV_ROUND_UP(SMP_MAX_CPUS, 8)) {
        TRACEF("%s: failed - cpu_set_size (%zd) too small to hold the platform's max cpu count (%u)\n",
               __func__, (size_t)req->cpu_set_size, SMP_MAX_CPUS);
        return ERR_INVALID_ARGS;
    }

    resp->thread = req->thread;
    resp->reserved = 0;
    struct thread_service_getaffinity_ctx ctx = {
            .chan_ctx = chan_ctx,
            .req = req,
            .resp = resp,
            .pinned_cpu = ERR_INVALID_ARGS,
            .result = ERR_INVALID_ARGS,
    };
    trusty_app_forall(thread_service_getaffinity_cb, (void*)&ctx);
    if (!ctx.result && ctx.pinned_cpu >= -1) {
        thread_service_pinned_to_cpu_set(ctx.pinned_cpu, cpu_set);
    }
    return ctx.result;
}

static int thread_service_read_request(struct handle* channel,
                                       void* buf,
                                       size_t buf_size) {
    int rc;
    struct ipc_msg_info msg_info;

    rc = ipc_get_msg(channel, &msg_info);
    if (rc != NO_ERROR) {
        TRACEF("%s: failed (%d) to get message\n", __func__, rc);
        return rc;
    }

    struct iovec_kern iov = {
            .iov_base = buf,
            .iov_len = buf_size,
    };
    struct ipc_msg_kern ipc_msg = {
            .iov = &iov,
            .num_iov = 1,
            .handles = NULL,
            .num_handles = 0,
    };
    rc = ipc_read_msg(channel, msg_info.id, 0, &ipc_msg);
    if (rc < 0) {
        TRACEF("%s: failed (%d) to read message.\n", __func__, rc);
    }
    ipc_put_msg(channel, msg_info.id);
    return rc;
}

static int thread_service_send_response(struct handle* channel,
                                        void* buf,
                                        size_t buf_size) {
    int rc;
    struct iovec_kern iov = {
            .iov_base = buf,
            .iov_len = buf_size,
    };
    struct ipc_msg_kern ipc_msg = {
            .num_iov = 1,
            .iov = &iov,
            .num_handles = 0,
            .handles = NULL,
    };

    rc = ipc_send_msg(channel, &ipc_msg);
    if (rc < 0) {
        TRACEF("%s: failed (%d) to send message.\n", __func__, rc);
    }
    return rc;
}

static int thread_service_handle_msg(struct thread_service_chan_ctx* chan_ctx) {
    int rc;
    struct handle* channel = chan_ctx->href.handle;
    struct {
        struct thread_service_req hdr;
        union {
            struct thread_service_setaffinity_req setaffinity;
            struct thread_service_getaffinity_req getaffinity;
            struct thread_service_getpriority_req getpriority;
        };
        struct cpu_bitmap cpu_set;
    } req;
    STATIC_ASSERT(
            sizeof(req) ==
            sizeof(struct thread_service_req) +
                    MAX(MAX(sizeof(struct thread_service_setaffinity_req),
                            sizeof(struct thread_service_getaffinity_req)),
                        sizeof(struct thread_service_getpriority_req)) +
                    sizeof(struct cpu_bitmap));
    size_t req_payload_size;
    struct {
        struct thread_service_resp hdr;
        union {
            struct thread_service_get_cpu_set_size_resp getsize;
            struct thread_service_getaffinity_resp getaffinity;
            struct thread_service_getpriority_resp getpriority;
        };
        struct cpu_bitmap cpu_set;
    } resp = {};

    /*
    union {
            struct thread_service_get_cpu_set_size_resp getsize;
            struct thread_service_getaffinity_resp getaffinity;
            struct thread_service_getpriority_resp getpriority;
        } union_obj;

    TRACEF("%s: sizeof(resp)=(%lu),"
            "sizeof(union_obj)=(%lu), "
            "sizeof(struct thread_service_get_cpu_set_size_resp)=(%lu), "
            "sizeof(struct thread_service_getaffinity_resp)=(%lu), "
            "sizeof(struct thread_service_getpriority_resp)=(%lu), "
            "sizeof(struct cpu_bitmap)=(%lu)\n"
            "MAX(MAX(sizeof(struct
    thread_service_get_cpu_set_size_resp),sizeof(struct
    thread_service_getaffinity_resp)),sizeof(struct
    thread_service_getpriority_resp))=(%lu)\n",
           __func__, sizeof(resp),
           sizeof(union_obj),
           sizeof(struct thread_service_get_cpu_set_size_resp),
           sizeof(struct thread_service_getaffinity_resp),
           sizeof(struct thread_service_getpriority_resp),
           sizeof(struct cpu_bitmap),
           MAX(MAX(sizeof(struct thread_service_get_cpu_set_size_resp),
                            sizeof(struct thread_service_getaffinity_resp)),
                        sizeof(struct thread_service_getpriority_resp))
        );

    STATIC_ASSERT(
            sizeof(resp) ==
            sizeof(struct thread_service_resp) +
                    MAX(MAX(sizeof(struct thread_service_get_cpu_set_size_resp),
                            sizeof(struct thread_service_getaffinity_resp)),
                        sizeof(struct thread_service_getpriority_resp)) +
                    sizeof(struct cpu_bitmap));
    */
    size_t resp_payload_size = 0;
    /*
     * initialize cpu_set buffer to zero, allows to correctly support
     * the case where the client's cpu_set size is smaller than the platform's
     */
    memset(&req.cpu_set, 0, sizeof(struct cpu_bitmap));

    rc = thread_service_read_request(channel, &req, sizeof(req));
    if (rc < 0) {
        TRACEF("%s: failed (%d) to read request\n", __func__, rc);
        return rc;
    }
    if ((size_t)rc < sizeof(req.hdr)) {
        TRACEF("%s: request too short (%d)\n", __func__, rc);
        return ERR_BAD_LEN;
    }
    req_payload_size = rc - sizeof(req.hdr);
    if (req.hdr.reserved) {
        TRACEF("%s: bad request, reserved not 0, (%d)\n", __func__,
               req.hdr.reserved);
        return ERR_INVALID_ARGS;
    }

    switch (req.hdr.cmd) {
    case THREAD_SERVICE_CMD_GET_CPU_SET_SIZE: {
        if (req_payload_size != 0) {
            TRACEF("%s: bad get_cpu_set_size payload size (%zd)\n", __func__,
                   req_payload_size);
            rc = ERR_INVALID_ARGS;
            break;
        }
        rc = NO_ERROR;
        resp.getsize.reserved = 0;
        resp.getsize.cpu_set_size = sizeof(struct cpu_bitmap);
        resp_payload_size = sizeof(resp.getsize);
        break;
    }
    case THREAD_SERVICE_CMD_SETAFFINITY: {
        if (req_payload_size !=
            sizeof(req.setaffinity) + req.setaffinity.cpu_set_size) {
            TRACEF("%s: bad setaffinity payload size (%zd)\n", __func__,
                   req_payload_size);
            rc = ERR_INVALID_ARGS;
            break;
        }
        rc = thread_service_setaffinity(&req.setaffinity, &req.cpu_set,
                                        chan_ctx);
        break;
    }
    case THREAD_SERVICE_CMD_GETAFFINITY: {
        if (req_payload_size != sizeof(req.getaffinity)) {
            TRACEF("%s: bad getaffinity payload size (%zd)\n", __func__,
                   req_payload_size);
            rc = ERR_INVALID_ARGS;
            break;
        }
        rc = thread_service_getaffinity(&req.getaffinity, &resp.getaffinity,
                                        &resp.cpu_set, chan_ctx);
        if (!rc) {
            STATIC_ASSERT(sizeof(resp.getaffinity) == 8);
            resp_payload_size =
                    sizeof(resp.getaffinity) + req.getaffinity.cpu_set_size;
        }
        break;
    }
    case THREAD_SERVICE_CMD_GETPRIORITY: {
        if (req_payload_size != 0) {
            TRACEF("%s: bad getpriority payload size (%zd)\n", __func__,
                   req_payload_size);
            rc = ERR_INVALID_ARGS;
            break;
        }

        rc = thread_service_getpriority(&req.getpriority, &resp.getpriority,
                                        chan_ctx);
        if (!rc) {
            STATIC_ASSERT(sizeof(resp.getpriority) == (3 * 4));
            resp_payload_size = sizeof(resp.getpriority);
            TRACEF("%s: thread_service_getpriority returned priority(%d)\n", __func__,
                   resp.getpriority.current_priority);
        }
        break;
    }
    default:
        rc = ERR_CMD_UNKNOWN;
    }

    resp.hdr.cmd = req.hdr.cmd | THREAD_SERVICE_CMD_RESP_BIT;
    resp.hdr.result = rc;
    LTRACEF("sending response cmd (%08x) resp_paylod (%zd)\n", resp.hdr.cmd,
            resp_payload_size);
    rc = thread_service_send_response(channel, &resp,
                                      sizeof(resp.hdr) + resp_payload_size);
    if (rc < 0) {
        TRACEF("%s: failed (%d) to send response\n", __func__, rc);
        return rc;
    }
    if ((size_t)rc != sizeof(resp.hdr) + resp_payload_size) {
        TRACEF("%s: bad len (%d) from send_msg()\n", __func__, rc);
        return ERR_IO;
    }
    return NO_ERROR;
}

static void thread_service_remove_channel(
        struct thread_service_chan_ctx* chan_ctx) {
    handle_set_detach_ref(&chan_ctx->href);
    handle_close(chan_ctx->href.handle);
    free(chan_ctx);
}

static void thread_service_handle_channel_event(struct handle_ref* event) {
    int rc;
    struct thread_service_chan_ctx* chan_ctx = event->cookie;

    DEBUG_ASSERT(chan_ctx->href.handle == event->handle);

    if (event->emask & IPC_HANDLE_POLL_MSG) {
        rc = thread_service_handle_msg(chan_ctx);

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
    thread_service_remove_channel(chan_ctx);
}

static int thread_service_add_channel(
        struct handle* hset,
        struct handle* channel,
        struct thread_service_chan_ctx* chan_ctx) {
    int rc;

    /* to retrieve handle_ref from a handle_set_wait() event */
    chan_ctx->href.cookie = chan_ctx;
    chan_ctx->href.handle = channel;
    chan_ctx->href.emask = ~0U;

    rc = handle_set_attach(hset, &chan_ctx->href);
    if (rc < 0) {
        TRACEF("%s: failed (%d) handle_set_attach()\n", __func__, rc);
    }

    return rc;
}

static void thread_service_handle_port_event(struct thread_service* ctx,
                                             struct handle_ref* event) {
    int rc;
    struct handle* channel;
    struct thread_service_chan_ctx* chan_ctx;
    const struct uuid* app_uuid;

    if (event->emask & IPC_HANDLE_POLL_READY) {
        rc = ipc_port_accept(event->handle, &channel, &app_uuid);
        LTRACEF("accept returned %d\n", rc);

        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) to accept incoming connection\n", __func__,
                   rc);
            return;
        }

        chan_ctx = calloc(1, sizeof(struct thread_service_chan_ctx));
        if (!chan_ctx) {
            TRACEF("%s: failed to allocate a thread_service_chan_ctx\n",
                   __func__);
            goto close_channel;
        }
        chan_ctx->app_uuid = app_uuid;

        thread_service_policy_setaffinity_load(app_uuid,
                                               &chan_ctx->policy_setaffinity);

        DEBUG_ASSERT(chan_ctx->policy_setaffinity.get_peer_uuid);
        rc = thread_service_add_channel(ctx->hset, channel, chan_ctx);
        if (rc != NO_ERROR) {
            TRACEF("%s: failed (%d) to add channel\n", __func__, rc);
            goto free_chan_ctx;
        }
    }
    return;

free_chan_ctx:
    free(chan_ctx);
close_channel:
    handle_close(channel);
}

static void thread_service_loop(struct thread_service* ctx) {
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
            thread_service_handle_port_event(ctx, &event);
        } else {
            LTRACEF("%s: handling channel event\n", __func__);
            thread_service_handle_channel_event(&event);
        }
        handle_decref(event.handle);
    }
}

static int thread_service_thread(void* arg) {
    int rc;
    struct thread_service ctx;

    ctx.hset = handle_set_create();
    if (!ctx.hset) {
        TRACEF("%s: failed to create handle set\n", __func__);
        rc = ERR_NO_MEMORY;
        goto err_hset_create;
    }
    rc = ipc_port_create(
            &kernel_uuid, THREAD_SERVICE_PORT, 1,
            THREAD_SERVICE_MAX_MESSAGE_SIZE + sizeof(struct cpu_bitmap),
            IPC_PORT_ALLOW_TA_CONNECT, &ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to create thread-service port\n", __func__, rc);
        goto err_port_create;
    }

    rc = ipc_port_publish(ctx.port);
    if (rc) {
        TRACEF("%s: failed (%d) to publish thread-service port\n", __func__,
               rc);
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
    thread_service_loop(&ctx);
    TRACEF("%s: thread_service_loop() returned. thread-service service exiting.\n",
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

void thread_service_init(uint level) {
    struct thread* thread =
            thread_create("thread-service", thread_service_thread, NULL,
                          DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    if (!thread) {
        TRACEF("%s: failed to create thread-service thread\n", __func__);
        return;
    }
    thread_detach_and_resume(thread);
}

LK_INIT_HOOK(thread_service, thread_service_init, LK_INIT_LEVEL_APPS);
