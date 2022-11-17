/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <binder/RpcServerTrusty.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <binder/ibinder.h>
#include <lk/macros.h>
#include <stdio.h>
#include <trusty_log.h>
#include <uapi/err.h>

#if defined(TRUSTY_USERSPACE)
#include <lib/tipc/tipc_srv.h>
#endif

using android::IBinder;

#define DEF_IFACE_CONTAINER(aidl_iface, iface) \
    struct iface##_container {                 \
        android::sp<aidl_iface> binder;        \
        struct iface cbinder;                  \
        std::atomic<uint32_t> ref_count;       \
    };

#define DEF_PARCELABLE_CONTAINER(parcel_type, parcel_struct) \
    struct parcel_struct##_container {                       \
        parcel_type* parcel;                                 \
        struct parcel_struct cparcel;                        \
        std::atomic<uint32_t> ref_count;                     \
    };

#define DEF_ADD_REF_IFACE(iface)                                               \
    void iface##_add_ref(struct iface* self) {                                 \
        auto container = containerof(self, struct iface##_container, cbinder); \
        container->ref_count.fetch_add(1, std::memory_order_relaxed);          \
    }

#define DEF_ADD_REF_PARCELABLE(parcel_struct)                                 \
    static void parcel_struct##_add_ref(struct parcel_struct* self) {         \
        auto container =                                                      \
                containerof(self, struct parcel_struct##_container, cparcel); \
        container->ref_count.fetch_add(1, std::memory_order_relaxed);         \
    }

#define DEF_RELEASE_IFACE(iface)                                            \
    void iface##_release(struct iface** pself) {                            \
        assert(pself != nullptr);                                           \
        assert(*pself != nullptr);                                          \
        auto container =                                                    \
                containerof(*pself, struct iface##_container, cbinder);     \
                                                                            \
        if (container->ref_count.fetch_sub(1, std::memory_order_release) == \
            1) {                                                            \
            std::atomic_thread_fence(std::memory_order_acquire);            \
            delete container;                                               \
        }                                                                   \
        *pself = nullptr;                                                   \
    }

#define DEF_RELEASE_PARCELABLE(parcel_struct)                                  \
    void parcel_struct##_release(struct parcel_struct** pself) {               \
        assert(pself != nullptr);                                              \
        assert(*pself != nullptr);                                             \
        auto container = containerof(*pself, struct parcel_struct##_container, \
                                     cparcel);                                 \
                                                                               \
        if (container->ref_count.fetch_sub(1, std::memory_order_release) ==    \
            1) {                                                               \
            std::atomic_thread_fence(std::memory_order_acquire);               \
            delete container->parcel;                                          \
            delete container;                                                  \
        }                                                                      \
        *pself = nullptr;                                                      \
    }

#define DEF_GET_CPP_IFACE(aidl, iface)                                         \
    android::sp<aidl>& iface##_to_##aidl(struct iface* self) {                 \
        auto container = containerof(self, struct iface##_container, cbinder); \
        return container->binder;                                              \
    }

#define DEF_GET_CPP_PARCELABLE(parcel_type, parcel_struct)                    \
    parcel_type* parcel_struct##_to_##parcel_type(                            \
            struct parcel_struct* self) {                                     \
        auto container =                                                      \
                containerof(self, struct parcel_struct##_container, cparcel); \
        return container->parcel;                                             \
    }

#define DEF_IFACE(aidl_iface, iface)        \
    DEF_IFACE_CONTAINER(aidl_iface, iface); \
    DEF_ADD_REF_IFACE(iface);               \
    DEF_RELEASE_IFACE(iface);               \
    DEF_GET_CPP_IFACE(aidl_iface, iface);

#define DEF_PARCELABLE(parcel_type, parcel)        \
    static inline parcel parcel##_builder();       \
    DEF_PARCELABLE_CONTAINER(parcel_type, parcel); \
    DEF_ADD_REF_PARCELABLE(parcel);                \
    DEF_RELEASE_PARCELABLE(parcel);                \
    DEF_GET_CPP_PARCELABLE(parcel_type, parcel)

// This empty struct must be defined here and not ibinder.h since this header
// can only be included by .cpp's which ensures that this type has a size of 1
// byte.  Binder client libraries that attempt to define interfaces as empty
// structs in headers included by .c's will get a compiler error triggered by
// -Wextern-c-compat. This limitation does not apply to structs with one or more
// members.
struct ibinder {};

DEF_IFACE_CONTAINER(IBinder, ibinder);
DEF_ADD_REF_IFACE(ibinder);
DEF_RELEASE_IFACE(ibinder);

static inline int binder_get_service(const char* port_name,
                                     android::sp<android::IBinder>& ib) {
#if defined(TRUSTY_USERSPACE)
    android::sp<android::RpcSession> sess = android::RpcSession::make(
            android::RpcTransportCtxFactoryTipcTrusty::make());
    android::status_t status = sess->setupPreconnectedClient({}, [=]() {
        int srv_fd = connect(port_name, IPC_CONNECT_WAIT_FOR_PORT);
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
