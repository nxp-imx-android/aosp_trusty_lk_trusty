/*
 * Copyright (c) 2013, Google, Inc. All rights reserved
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
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

#pragma once

#include <uapi/trusty_uuid.h>

/*
 * Layout of .trusty_app.manifest section in the trusted application is the
 * required UUID followed by an abitrary number of configuration options.
 */
typedef struct trusty_app_manifest {
    uuid_t uuid;
    uint32_t config_options[];
} trusty_app_manifest_t;

struct trusty_app_manifest_entry_port {
    uint32_t config_key;
    uint32_t port_flags;
    uint32_t port_name_size;
    char port_name[];
};

enum {
    TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE = 1,
    TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE = 2,
    TRUSTY_APP_CONFIG_KEY_MAP_MEM = 3,
    TRUSTY_APP_CONFIG_KEY_MGMT_FLAGS = 4,
    TRUSTY_APP_CONFIG_KEY_START_PORT = 5,
    TRUSTY_APP_CONFIG_KEY_PINNED_CPU = 6,
};

#define TRUSTY_APP_MGMT_FLAGS_NONE 0u
/* Restart the application on exit */
#define TRUSTY_APP_MGMT_FLAGS_RESTART_ON_EXIT (1u << 0)
/* Don't start the application at boot */
#define TRUSTY_APP_MGMT_FLAGS_DEFERRED_START (1u << 1)
/* Exit application if application crashes or exit with a non-0 exit code */
#define TRUSTY_APP_MGMT_FLAGS_NON_CRITICAL_APP (1u << 2)

#define TRUSTY_APP_PINNED_CPU_NONE (-1)
