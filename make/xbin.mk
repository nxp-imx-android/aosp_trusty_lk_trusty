#
# Copyright (c) 2014-2015, Google, Inc. All rights reserved
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

# The following set of variables must can be passed to xbin.mk:
#
#     XBIN_NAME - an output file name (without extention)
#     XBIN_BUILDDIR - build directory
#     XBIN_TOP_MODULE - top module to compile
#     XBIN_ARCH - architecture to compile for
#     XBIN_TYPE - optional executable type
#     XBIN_LDFLAGS - extra linker flags (optional)
#     XBIN_SYMTAB_ENABLED - whether to build with .symtab or not (optional)
#

# check if all required variables are set or provide default

ifeq ($(XBIN_NAME), )
$(error XBIN_NAME must be specified)
endif

ifeq ($(XBIN_BUILDDIR), )
$(error XBIN_BUILDDIR must be specified)
endif

ifeq ($(XBIN_TOP_MODULE), )
$(error XBIN_TOP_MODULE must be specified)
endif

ifeq ($(XBIN_ARCH), )
$(error XBIN_ARCH must be specified)
endif

ifeq ($(XBIN_TYPE), )
XBIN_TYPE := XBIN
endif

ifeq ($(XBIN_ALIGNMENT), )
XBIN_ALIGNMENT := 1
else
XBIN_ALIGNMENT := $(XBIN_ALIGNMENT)
endif

ifeq ($(XBIN_SYMTAB_ENABLED),)
XBIN_SYMTAB_ENABLED := false
endif

# save global variables
SAVED_ARCH := $(ARCH)
SAVED_STANDARD_ARCH_NAME := $(STANDARD_ARCH_NAME)
SAVED_GLOBAL_OPTFLAGS := $(GLOBAL_OPTFLAGS)
SAVED_GLOBAL_COMPILEFLAGS := $(GLOBAL_COMPILEFLAGS)
SAVED_GLOBAL_CFLAGS := $(GLOBAL_CFLAGS)
SAVED_GLOBAL_CPPFLAGS := $(GLOBAL_CPPFLAGS)
SAVED_GLOBAL_ASMFLAGS := $(GLOBAL_ASMFLAGS)
SAVED_GLOBAL_INCLUDES := $(GLOBAL_INCLUDES)
SAVED_GLOBAL_DEFINES := $(GLOBAL_DEFINES)

SAVED_BUILDDIR := $(BUILDDIR)
SAVED_ALLMODULES := $(ALLMODULES)
SAVED_ALLMODULE_OBJS := $(ALLMODULE_OBJS)
SAVED_ALLOBJS := $(ALLOBJS)

# reset lk.bin variables
ARCH := $(XBIN_ARCH)
BUILDDIR := $(XBIN_BUILDDIR)
ALLMODULES :=
ALLMODULE_OBJS :=
ALLOBJS :=

# Re-derive the standard arch name.
$(eval $(call standard_name_for_arch,STANDARD_ARCH_NAME,$(ARCH),$(SUBARCH)))

# Override tools
include arch/$(ARCH)/toolchain.mk

XBIN_TOOLCHAIN_PREFIX := $(ARCH_$(ARCH)_TOOLCHAIN_PREFIX)

ifeq ($(call TOBOOL,$(CLANGBUILD)), true)
XBIN_CC := $(CCACHE) $(CLANG_BINDIR)/clang
else
XBIN_CC := $(CCACHE) $(XBIN_TOOLCHAIN_PREFIX)gcc
endif

# TODO: we could find the runtime like this.
# XBIN_LIBGCC := $(shell $(XBIN_CC) $(GLOBAL_COMPILEFLAGS) $(ARCH_$(ARCH)_COMPILEFLAGS) $(THUMBCFLAGS) --rtlib=compiler-rt -print-libgcc-file-name)
# However the compiler currently does not contain non-x86 prebuilts for the
# linux-gnu ABI. We could either get those prebuilts added to the toolchain or
# switch to the android ABI.
# Note there are two copies of compiler-rt in the toolchain - framework and NDK.
# We're using the NDK version because the path is more stable and the difference
# should not matter for this library. (The main difference is which version of
# libcxx they link against, and the builtins do not use C++.)
XBIN_LIBGCC := $(CLANG_BINDIR)/../runtimes_ndk_cxx/libclang_rt.builtins-$(STANDARD_ARCH_NAME)-android.a

XBIN_LD := $(CLANG_BINDIR)/ld.lld
XBIN_OBJCOPY := $(XBIN_TOOLCHAIN_PREFIX)objcopy
XBIN_OBJDUMP := $(XBIN_TOOLCHAIN_PREFIX)objdump
XBIN_STRIP := $(XBIN_TOOLCHAIN_PREFIX)strip

$(info XBIN_TOOLCHAIN_PREFIX = $(XBIN_TOOLCHAIN_PREFIX))
$(info XBIN_LIBGCC = $(XBIN_LIBGCC))

GLOBAL_CFLAGS := $(GLOBAL_CFLAGS)
GLOBAL_INCLUDES :=
GLOBAL_DEFINES := $(XBIN_TYPE)=1

# Include XBIN top module and handle all it's dependencies
include $(addsuffix /rules.mk,$(XBIN_TOP_MODULE))
include make/recurse.mk

# Add all XBIN specific defines
GLOBAL_DEFINES += \
	$(addsuffix =1,$(addprefix $(XBIN_TYPE)_WITH_,$(ALLMODULES)))

# XBIN build rules
XBIN_BIN := $(BUILDDIR)/$(XBIN_NAME).bin
XBIN_ELF := $(BUILDDIR)/$(XBIN_NAME).elf
XBIN_SYMS_ELF := $(BUILDDIR)/$(XBIN_NAME).syms.elf
XBIN_ALL_OBJS := $(ALLMODULE_OBJS)
XBIN_CONFIGHEADER := $(BUILDDIR)/config.h

# If ASLR is disabled, don't make PIEs, it burns space
ifneq ($(ASLR), false)
    # Generate PIE code to allow ASLR to be applied
    ifeq ($(XBIN_APP),true)
        GLOBAL_COMPILEFLAGS += -fPIC
        XBIN_LDFLAGS += -static -pie --no-dynamic-linker -z text -Bsymbolic
    endif
endif

ifneq ($(strip $(CONSTANTS)),)
GLOBAL_USER_INCLUDES += \
	$(BUILDDIR)/constants/include
endif

ifeq ($(HWASAN_ENABLED), true)
    ifeq ($(XBIN_APP),true)
        # TODO(b/148877030): Sanitize globals
        GLOBAL_COMPILEFLAGS += \
            -fsanitize-blacklist=trusty/user/base/lib/hwasan/exemptlist \
            -fsanitize=hwaddress \
            -mllvm -hwasan-with-tls=0 \
            -mllvm -hwasan-globals=0 \
            -mllvm -hwasan-use-short-granules=0 \

    endif
endif

# Set appropriate globals for all targets under $(BUILDDIR)
$(BUILDDIR)/%: CC := $(XBIN_CC)
$(BUILDDIR)/%: LD := $(XBIN_LD)
$(BUILDDIR)/%.o: GLOBAL_OPTFLAGS := $(GLOBAL_OPTFLAGS)
$(BUILDDIR)/%.o: GLOBAL_COMPILEFLAGS := $(GLOBAL_COMPILEFLAGS) -include $(XBIN_CONFIGHEADER)
$(BUILDDIR)/%.o: GLOBAL_CFLAGS   := $(GLOBAL_CFLAGS)
$(BUILDDIR)/%.o: GLOBAL_CPPFLAGS := $(GLOBAL_CPPFLAGS)
$(BUILDDIR)/%.o: GLOBAL_ASMFLAGS := $(GLOBAL_ASMFLAGS)
$(BUILDDIR)/%.o: GLOBAL_INCLUDES := $(addprefix -I,$(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES) $(GLOBAL_INCLUDES))
$(BUILDDIR)/%.o: ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
$(BUILDDIR)/%.o: ARCH_CFLAGS := $(ARCH_$(ARCH)_CFLAGS)
$(BUILDDIR)/%.o: THUMBCFLAGS := $(ARCH_$(ARCH)_THUMBCFLAGS)
$(BUILDDIR)/%.o: ARCH_CPPFLAGS := $(ARCH_$(ARCH)_CPPFLAGS)
$(BUILDDIR)/%.o: ARCH_ASMFLAGS := $(ARCH_$(ARCH)_ASMFLAGS)

# generate XBIN specific config.h
$(XBIN_CONFIGHEADER): GLOBAL_DEFINES := $(GLOBAL_DEFINES)
$(XBIN_CONFIGHEADER):
	@$(call MAKECONFIGHEADER,$@,GLOBAL_DEFINES)

$(ALLOBJS): $(XBIN_CONFIGHEADER)

# add it to global dependency list
GENERATED += $(XBIN_CONFIGHEADER)

# build manifest objects if manifest config json provided
# generate shared constants headers if constants provided
ifneq ($(strip $(MANIFEST)),)
XBIN_MANIFEST_COMPILER := trusty/user/base/tools/manifest_compiler.py
XBIN_MANIFEST_BIN := $(BUILDDIR)/$(XBIN_NAME).manifest
$(XBIN_MANIFEST_BIN): XBIN_MANIFEST_COMPILER := $(XBIN_MANIFEST_COMPILER)
$(XBIN_MANIFEST_BIN): CONSTANTS := $(CONSTANTS)
$(XBIN_MANIFEST_BIN): HEADER_DIR := $(BUILDDIR)/constants/include
$(XBIN_MANIFEST_BIN): $(MANIFEST) $(XBIN_MANIFEST_COMPILER) $(CONSTANTS)
	@$(MKDIR)
	@echo compiling $< to $@
	$(XBIN_MANIFEST_COMPILER) -i $< -o $@ $(addprefix -c,$(CONSTANTS)) --header-dir $(HEADER_DIR)

# The manifest binary is not actually a SRCDEP,
# but it is generated at the same time of header files that are.
# Since we do not know the name of the header files,
# add a dependency edge on a file created at the same time.
ifneq ($(strip $(CONSTANTS)),)
GLOBAL_SRCDEPS += $(XBIN_MANIFEST_BIN)
endif
endif

# Link XBIN elf
$(XBIN_SYMS_ELF): XBIN_LD := $(XBIN_LD)
$(XBIN_SYMS_ELF): XBIN_LIBGCC := $(XBIN_LIBGCC)
$(XBIN_SYMS_ELF): XBIN_LDFLAGS := $(XBIN_LDFLAGS)
$(XBIN_SYMS_ELF): XBIN_MEMBASE := $(XBIN_MEMBASE)
$(XBIN_SYMS_ELF): XBIN_ALL_OBJS := $(XBIN_ALL_OBJS)
$(XBIN_SYMS_ELF): $(XBIN_ALL_OBJS)
	@$(MKDIR)
	@echo linking $@
	$(NOECHO)$(XBIN_LD) $(XBIN_LDFLAGS) $(addprefix -Ttext ,$(XBIN_MEMBASE)) --start-group $(XBIN_ALL_OBJS) $(XBIN_LIBGCC) --end-group -o $@

ifeq ($(call TOBOOL,$(XBIN_SYMTAB_ENABLED)),true)
XBIN_STRIPFLAGS := --strip-debug
else
XBIN_STRIPFLAGS := -s
endif

# And strip it and pad with zeros to be page aligned
$(XBIN_ELF): XBIN_STRIP := $(XBIN_STRIP)
$(XBIN_ELF): XBIN_ALIGNMENT := $(XBIN_ALIGNMENT)
$(XBIN_ELF): XBIN_STRIPFLAGS := $(XBIN_STRIPFLAGS)
$(XBIN_ELF): $(XBIN_SYMS_ELF)
	@$(MKDIR)
	@echo stripping $<
	$(NOECHO)$(XBIN_STRIP) $(XBIN_STRIPFLAGS) $< -o $@
	@echo page aligning $<
	$(NOECHO)truncate -s %$(XBIN_ALIGNMENT) $@

# build XBIN binary
$(XBIN_BIN): XBIN_OBJCOPY := $(XBIN_OBJCOPY)
$(XBIN_BIN): $(XBIN_ELF)
	@echo generating image: $@
	$(NOECHO)$(XBIN_OBJCOPY) -O binary $< $@

# Also generate listings
all:: $(XBIN_BIN) $(XBIN_ELF) $(XBIN_ELF).lst $(XBIN_ELF).debug.lst

$(XBIN_ELF).lst: XBIN_OBJDUMP := $(XBIN_OBJDUMP)
$(XBIN_ELF).lst: $(XBIN_SYMS_ELF)
	@echo generating listing: $@
	$(NOECHO)$(XBIN_OBJDUMP) -d $< | $(CPPFILT) > $@

$(XBIN_ELF).debug.lst: XBIN_OBJDUMP := $(XBIN_OBJDUMP)
$(XBIN_ELF).debug.lst: $(XBIN_SYMS_ELF)
	@echo generating listing: $@
	$(NOECHO)$(XBIN_OBJDUMP) -S $< | $(CPPFILT) > $@

# restore LK variables
GLOBAL_OPTFLAGS := $(SAVED_GLOBAL_OPTFLAGS)
GLOBAL_COMPILEFLAGS := $(SAVED_GLOBAL_COMPILEFLAGS)
GLOBAL_CFLAGS   := $(SAVED_GLOBAL_CFLAGS)
GLOBAL_CPPFLAGS := $(SAVED_GLOBAL_CPPFLAGS)
GLOBAL_ASMFLAGS := $(SAVED_GLOBAL_ASMFLAGS)
GLOBAL_INCLUDES := $(SAVED_GLOBAL_INCLUDES)
GLOBAL_DEFINES  := $(SAVED_GLOBAL_DEFINES)

ARCH := $(SAVED_ARCH)
STANDARD_ARCH_NAME := $(SAVED_STANDARD_ARCH_NAME)
BUILDDIR := $(SAVED_BUILDDIR)
ALLMODULES := $(SAVED_ALLMODULES)
ALLMODULE_OBJS := $(SAVED_ALLMODULE_OBJS)
ALLOBJS := $(SAVED_ALLOBJS) $(ALLOBJS)

# Reset local variables
XBIN_NAME :=
XBIN_TYPE :=
XBIN_ARCH :=
XBIN_TOP_MODULE :=
XBIN_BUILDDIR :=
XBIN_ALIGNMENT :=
XBIN_SYMTAB_ENABLED :=

XBIN_BIN :=
XBIN_ELF :=
XBIN_SYMS_ELF :=
XBIN_ALL_OBJS :=
XBIN_CONFIGHEADER :=

XBIN_TOOLCHAIN_PREFIX :=
XBIN_CC :=
XBIN_LD :=
XBIN_OBJCOPY :=
XBIN_STRIP :=
XBIN_STRIPFLAGS :=

XBIN_LDFLAGS :=
XBIN_APP :=

MANIFEST :=
CONSTANTS :=
XBIN_MANIFEST_COMPILER :=
XBIN_MANIFEST_BIN :=
XBIN_MEMBASE :=
