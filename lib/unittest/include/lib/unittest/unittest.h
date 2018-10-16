/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <lib/trusty/ipc.h>
#include <lk/compiler.h>
#include <stdbool.h>

__BEGIN_CDECLS

/**
 * struct unittest - struct representing a kernel unit-test.
 * @port_name:  Port name.
 * @run_test:   Function to call when a client connects to @port_name.
 * @_href:      Private data used by library.
 */
struct unittest {
    const char* port_name;
    bool (*run_test)(struct unittest* test);
    struct handle_ref _href;
};

int unittest_printf(const char* fmt, ...);
int unittest_add(struct unittest* test);

__END_CDECLS
