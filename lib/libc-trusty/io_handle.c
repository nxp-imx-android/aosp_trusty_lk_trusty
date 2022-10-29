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

#include "stdio_impl.h"

#include <assert.h>
#include <debug.h>
#include <lib/io.h>
#include <trusty/io_handle.h>

io_handle_t* fd_io_handle(int fd) {
    if ((fd == stdout->fd) || (fd == stderr->fd)) {
        return &console_io;
    }

    return NULL;
}

io_handle_t* file_io_handle(FILE* file) {
    if (file == NULL) {
        return NULL;
    }

    return fd_io_handle(file->fd);
}
