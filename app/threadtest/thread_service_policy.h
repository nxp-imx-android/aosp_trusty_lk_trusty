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
#pragma once

#include <interface/thread/thread.h>
#include <stdint.h>
#include <uapi/trusty_uuid.h>

struct thread_service_policy_ctx;

struct thread_service_policy_setaffinity {
    /*
     * get_peer_uuid - Get peer uuid at idx
     * @idx: peer idx
     * @peer_uuid: uuid
     * Return: 0 if successful, ERR_NOT_ALLOWED otherwise
     *
     * Retrieve the peer uuid for which cpu affinity shall be applied to.
     * Multiple peers can be supported via the idx argument.
     *
     */
    int (*get_peer_uuid)(uint32_t idx, const struct uuid** peer_uuid);
};

/*
 * thread_service_setaffinity_load_policy() - load client's permissions
 * to set cpu affinity
 * @uuid: uuid of the client whose permissions are being loaded
 * @policy: thread_service_setaffinity_policy to be filled out
 */
void thread_service_policy_setaffinity_load(
        const struct uuid* uuid,
        struct thread_service_policy_setaffinity* policy);
