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
# defines a TRUSTY_EMBEDDED_DTB macro as the path to the .dtb and continues
# building the module with library.mk. TRUSTY_EMBEDDED_DTB may be used with
# either the INCBIN macro or the .incbin directive to embed the .dtb in the
# module.
#
# args:
# MODULE : module name (required)
# MODULE_DTS : a .dts file (required)
# MODULE_DTC_FLAGS : flags passed to dtc invocation
# MODULE_DTS_INCLUDES : list of include directories used to preprocess the .dts

MODULE_DTS_INCLUDES := $(foreach inc,$(MODULE_DTS_INCLUDES),$(addprefix -I,$(inc)))

MODULE_CPP_DTS := $(patsubst %.dts,$(BUILDDIR)/%.cpp.dts,$(MODULE_DTS))
MODULE_DTB := $(patsubst %.cpp.dts,%.dtb,$(MODULE_CPP_DTS))

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

# Ensure the .dtb is built before the module sources are compiled
MODULE_SRCDEPS += \
	$(MODULE_DTB) \

# Define TRUSTY_EMBEDDED_DTB for the module sources
MODULE_COMPILEFLAGS += \
	-DTRUSTY_EMBEDDED_DTB=\"$(MODULE_DTB)\"

include make/library.mk

MODULE_DTS :=
MODULE_DTC_FLAGS :=
MODULE_DTS_INCLUDES :=
DTC_PREBUILT :=
