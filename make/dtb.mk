#
# Copyright (c) 2022, Google, Inc. All rights reserved
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

# Build a devicetree blob module for Trusty
#
# This makefile generates a .dtb from a .dts specified by MODULE_DTS, then
# generates a .c that includes the .dtb with an .incbin directive and builds the
# generated source file with library.mk.
#
# args:
# MODULE : module name (required)
# MODULE_DTS : a .dts file (required)
# MODULE_DTC_FLAGS : flags passed to dtc invocation
# MODULE_DTS_INCLUDES : list of include directories used to preprocess the .dts
# MODULE_DT_SYM : an optional symbol name for the embedded dtb

MODULE_DTS_INCLUDES := $(foreach inc,$(MODULE_DTS_INCLUDES),$(addprefix -I,$(inc)))

MODULE_CPP_DTS := $(patsubst %.dts,$(BUILDDIR)/%.cpp.dts,$(MODULE_DTS))
MODULE_DTB := $(patsubst %.cpp.dts,%.dtb,$(MODULE_CPP_DTS))
MODULE_INCBIN_C := $(patsubst %.dtb,%.c,$(MODULE_DTB))

ifeq ($(MODULE_DT_SYM),)
# Generate a symbol name by taking the module name and replacing
# all non-alphanumeric characters in it with underscores
MODULE_DT_SYM := $(shell printf "$(basename $(MODULE_DTS))" | tr -c '[:alnum:]' '_')
endif

DTC_PREBUILT := prebuilts/misc/linux-x86/dtc/dtc

# Preprocess the .dts files
$(MODULE_CPP_DTS): MODULE_DTS_INCLUDES := $(MODULE_DTS_INCLUDES)
$(MODULE_CPP_DTS): $(MODULE_DTS)
	@$(MKDIR)
	$(NOECHO)$(CC) -E -nostdinc $(MODULE_DTS_INCLUDES) -undef -D__DTS__ \
		-x assembler-with-cpp -o $@ $<

# Compile each .dts into a .dtb
$(MODULE_DTB): MODULE_DTC_FLAGS := $(MODULE_DTC_FLAGS)
$(MODULE_DTB): DTC_PREBUILT := $(DTC_PREBUILT)
$(MODULE_DTB): $(MODULE_CPP_DTS)
	@$(MKDIR)
	$(NOECHO)$(DTC_PREBUILT) -O dtb -o $@ $(MODULE_DTC_FLAGS) --symbols $<

# Generate the .c that embeds the .dtb in the module
$(MODULE_INCBIN_C): MODULE_DTS := $(MODULE_DTS)
$(MODULE_INCBIN_C): MODULE_DT_SYM := $(MODULE_DT_SYM)
$(MODULE_INCBIN_C): MODULE_DTB := $(MODULE_DTB)
$(MODULE_INCBIN_C): $(MODULE_DTB)
	@$(MKDIR)
	$(NOECHO) printf "#include <lk/compiler.h>\n" > $@
	$(NOECHO) printf "INCBIN_ALIGNED(dtb_$(MODULE_DT_SYM), \
		dtb_$(MODULE_DT_SYM)_size, \"$(MODULE_DTB)\", \".dtb\", 8);\n" >> $@

# Add the generated .c to the module sources
MODULE_SRCS += \
	$(MODULE_INCBIN_C) \

include make/library.mk

MODULE_DTS :=
MODULE_DTC_FLAGS :=
MODULE_DTS_INCLUDES :=

MODULE_CPP_DTS :=
MODULE_DTB :=
MODULE_INCBIN_C :=

MODULE_DT_SYM :=

DTC_PREBUILT :=
