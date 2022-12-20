/*
 * Copyright (c) 2022, Google, Inc. All rights reserved
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

#include <lib/shared/binder_discover/binder_discover.h>

#if defined(TRUSTY_USERSPACE)
#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <lib/tipc/tipc_srv.h>
#endif

int binder_discover_get_service(const char* port,
                                android::sp<android::IBinder>& ib) {
#if defined(TRUSTY_USERSPACE)
    android::sp<android::RpcSession> sess = android::RpcSession::make(
            android::RpcTransportCtxFactoryTipcTrusty::make());
    android::status_t status = sess->setupPreconnectedClient({}, [=]() {
        int srv_fd = connect(port, IPC_CONNECT_WAIT_FOR_PORT);
        return srv_fd >= 0 ? android::base::unique_fd(srv_fd)
                           : android::base::unique_fd();
    });
    if (status != android::OK) {
        return status;
    }
    ib = sess->getRootObject();
#else
    panic("out-of-process services are currently unsupported in the kernel\n");
#endif
    if (!ib) {
        return android::BAD_VALUE;
    }
    return android::OK;
}
