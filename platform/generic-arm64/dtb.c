/*
 * Copyright (c) 2022 Google Inc. All rights reserved
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

#include <lib/dtb_embedded/dtb_embedded.h>
#include <lib/dtb_service/dtb_service.h>
#include <lib/ktipc/ktipc.h>
#include <lk/init.h>

#define DT_PORT "com.android.kernel.device_tree"
#define DTB_PORT "com.android.trusty.kernel.device_tree.blob"

static struct ktipc_server dtb_ktipc_server =
        KTIPC_SERVER_INITIAL_VALUE(dtb_ktipc_server, "dtb_ktipc_server");

static void platform_dtb_init(uint level) {
    int rc;
    rc = ktipc_server_start(&dtb_ktipc_server);
    if (rc < 0) {
        panic("Failed (%d) to start dtb server\n", rc);
    }

    size_t dtb_size = 0;
    const void* dtb = dtb_embedded_get(&dtb_size);
    if (!dtb || !dtb_size) {
        panic("No embedded device tree blob was found\n");
    }

    /*
     * TODO: If there are multiple dtbs, iterate through them to find the test
     * one
     */

    rc = dtb_service_add(dtb, dtb_size, DT_PORT, DTB_PORT, &dtb_ktipc_server);
    if (rc < 0) {
        panic("Failed (%d) to add dtb service to server\n", rc);
    }
}

LK_INIT_HOOK(platform_dtb, platform_dtb_init, LK_INIT_LEVEL_THREADING + 1);
