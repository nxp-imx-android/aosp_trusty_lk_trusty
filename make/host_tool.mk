#
# Copyright (c) 2017, Google, Inc. All rights reserved
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

# args:
# HOST_TOOL_NAME : name of the host binary (required)
# HOST_SRCS : list of source files (required)
# HOST_INCLUDE_DIRS : list of include directories
# HOST_FLAGS : list of flags for the compiler
# HOST_LDFLAGS : list of flags for the compiler
# HOST_LIBS : list of libraries to link against

# Validate arguments.
ifeq ($(HOST_TOOL_NAME), )
$(error HOST_TOOL_NAME must be specified)
endif

ifeq ($(HOST_SRCS), )
$(error HOST_SRCS must be specified)
endif

HOST_CC := $(CLANG_BINDIR)/clang
# ASAN is not compatable with GDB.
HOST_SANITIZER_FLAGS := -fsanitize=address -fno-omit-frame-pointer

# We should use the prebuilt linker rather than the host linker
HOST_LDFLAGS += -B$(CLANG_BINDIR) -fuse-ld=lld

# When using clang, we need to always use the prebuilt libc++ library
# because we can't be sure what version of libstdc++ the host system
# has, or even if it exists at all.
ifneq ($(filter stdc++ c++,$(HOST_LIBS)),)
# Add the prebuilt libraries directory to the tool's rpath,
# so it can use those libraries, e.g., libc++.so
HOST_LIBCXX_PATH := $(CLANG_BINDIR)/../lib64/libc++.so
HOST_LIBCXX_CPPFLAGS := -stdlib=libc++ -isystem$(CLANG_BINDIR)/../include/c++/v1
HOST_LIBCXX_LDFLAGS := -L$(dir $(HOST_LIBCXX_PATH)) -stdlib=libc++ -Wl,-rpath,$(dir $(HOST_LIBCXX_PATH))
# Add relative path inside the SDK package to RPATH
HOST_LIBCXX_LDFLAGS += -Wl,-rpath,'$$ORIGIN/../toolchain/clang/lib64'
else
HOST_LIBCXX_CPPFLAGS :=
HOST_LIBCXX_LDFLAGS :=
endif

HOST_INCLUDE_DIRS += $(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES)

# Compile test sources.
GENERIC_CC := $(HOST_CC)
GENERIC_SRCS := $(HOST_SRCS)
GENERIC_OBJ_DIR := $(BUILDDIR)/host_tools/obj/$(HOST_TOOL_NAME)
GENERIC_FLAGS := $(HOST_FLAGS) -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror $(HOST_SANITIZER_FLAGS) $(addprefix -I, $(HOST_INCLUDE_DIRS))
GENERIC_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=199309 -Wno-missing-field-initializers
GENERIC_CPPFLAGS := -std=c++17 $(HOST_LIBCXX_CPPFLAGS)
include make/generic_compile.mk

# Link
HOST_TOOL_BIN := $(BUILDDIR)/host_tools/$(HOST_TOOL_NAME)
$(HOST_TOOL_BIN): CC := $(HOST_CC)
$(HOST_TOOL_BIN): LDFLAGS := -g $(HOST_SANITIZER_FLAGS) $(HOST_LDFLAGS) $(HOST_LIBCXX_LDFLAGS) $(addprefix -l, $(HOST_LIBS))
$(HOST_TOOL_BIN): $(GENERIC_OBJS)
	@echo linking $@
	@$(MKDIR)
	$(NOECHO)$(CC) $^ $(LDFLAGS) -o $@

EXTRA_BUILDDEPS += $(HOST_TOOL_BIN)

# Cleanup inputs
HOST_TOOL_NAME:=
HOST_SRCS :=
HOST_INCLUDE_DIRS :=
HOST_FLAGS :=
HOST_LDFLAGS :=
HOST_LIBS :=
# Cleanup internal
HOST_CC :=
HOST_SANITIZER_FLAGS :=
HOST_TOOL_BIN :=
HOST_OBJ_DIR :=
GENERIC_OBJS :=
