#
# Copyright (c) 2014-2018, Google, Inc. All rights reserved
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

$(info Include Trusty user tasks support)

TRUSTY_APP_DIR := $(GET_LOCAL_DIR)

#
# Input variables
#
#   TRUSTY_BUILTIN_USER_TASKS  - list of compiled from source user tasks to be included into final image
#   TRUSTY_PREBUILT_USER_TASKS - list of precompiled user tasks to be included into final image
#   	These prebuilt task modules must include a manifest binary and app elf binary, e.g.:
#   		TRUSTY_PREBUILT_USER_TASKS += trusty/app/some_prebuilt_app
#
#			Add the following files from the pre-compiled app:
#			- trusty/app/some_prebuilt_app/some_prebuilt_app.elf
#			- trusty/app/some_prebuilt_app/some_prebuilt_app.manifest
#

# generate user task build rule: $(1): user task
define user-task-build-rule
$(eval XBIN_NAME := $(notdir $(1)))\
$(eval XBIN_TOP_MODULE := $(1))\
$(eval XBIN_TYPE := USER_TASK)\
$(eval XBIN_ARCH := $(TRUSTY_USER_ARCH))\
$(eval XBIN_BUILDDIR := $(BUILDDIR)/user_tasks/$(1))\
$(eval XBIN_LDFLAGS := $(BASE_XBIN_LDFLAGS))\
$(eval XBIN_ALIGNMENT := 4096)\
$(eval XBIN_APP := true)\
$(eval XBIN_SYMTAB_ENABLED := $(SYMTAB_ENABLED))\
$(eval include make/xbin.mk)
endef

# while compiling user space we allow FP support
SAVED_ALLOW_FP_USE := $(ALLOW_FP_USE)
ALLOW_FP_USE := true

SAVED_SCS_ENABLED = $(SCS_ENABLED)
# tell the arch-specific makefiles to set flags required for SCS if supported
SCS_ENABLED := $(call TOBOOL,$(USER_SCS_ENABLED))

# pull in common arch specific user task settings
BASE_XBIN_LDFLAGS := --gc-sections -z max-page-size=4096 -z separate-loadable-segments

include $(TRUSTY_APP_DIR)/arch/$(TRUSTY_USER_ARCH)/rules.mk

# generate list of all user tasks we need to build
# include the legacy TRUSTY_ALL_USER_TASKS variable for projects that still use
# it. This will be removed in the future and all projects should use
# TRUSTY_BUILTIN_USER_TASKS directly.
TRUSTY_BUILTIN_USER_TASKS := $(TRUSTY_BUILTIN_USER_TASKS) \
                             $(TRUSTY_ALL_USER_TASKS)

ALL_USER_TASKS := $(TRUSTY_BUILTIN_USER_TASKS) $(TRUSTY_LOADABLE_USER_TASKS)
# sort and remove duplicates
ALL_USER_TASKS := $(sort $(ALL_USER_TASKS))

#
# Generate build rules for each user task
#
$(foreach t,$(ALL_USER_TASKS),\
   $(call user-task-build-rule,$(t)))

# Add any prebuilt apps to the build.

PREBUILT_OBJECTS := $(foreach t,$(TRUSTY_PREBUILT_USER_TASKS),\
	$(t)/$(notdir $(t)).manifest $(t)/$(notdir $(t)).elf)
PREBUILT_OBJECTS_DEST := $(addprefix $(BUILDDIR)/user_tasks/,$(PREBUILT_OBJECTS))
$(PREBUILT_OBJECTS_DEST): $(BUILDDIR)/user_tasks/%: %
	$(MKDIR)
	cp $^ $(dir $@)/

TRUSTY_BUILTIN_USER_TASKS += $(TRUSTY_PREBUILT_USER_TASKS)

#
# Generate combined user task obj/bin if necessary
#
ifneq ($(strip $(TRUSTY_BUILTIN_USER_TASKS)),)

BUILTIN_TASK_MANIFESTS_BINARY := $(foreach t, $(TRUSTY_BUILTIN_USER_TASKS),\
   $(addsuffix /$(notdir $(t)).manifest, $(t)))
BUILTIN_TASK_MANIFESTS_BINARY := $(addprefix $(BUILDDIR)/user_tasks/, $(BUILTIN_TASK_MANIFESTS_BINARY))

BUILTIN_TASK_ELFS := $(foreach t, $(TRUSTY_BUILTIN_USER_TASKS),\
   $(addsuffix /$(notdir $(t)).elf, $(t)))

BUILTIN_TASK_ELFS := $(addprefix $(BUILDDIR)/user_tasks/, $(BUILTIN_TASK_ELFS))

BUILTIN_TASK_OBJS := $(patsubst %.elf,%.o,$(BUILTIN_TASK_ELFS))

$(BUILTIN_TASK_OBJS): CC := $(CC)
$(BUILTIN_TASK_OBJS): GLOBAL_COMPILEFLAGS := $(GLOBAL_COMPILEFLAGS)
$(BUILTIN_TASK_OBJS): ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
$(BUILTIN_TASK_OBJS): USER_TASK_OBJ_ASM:=$(TRUSTY_APP_DIR)/appobj.S
$(BUILTIN_TASK_OBJS): %.o: %.elf %.manifest $(USER_TASK_OBJ_ASM)
	@$(MKDIR)
	@echo converting $< to $@
	$(NOECHO)$(CC) -DUSER_TASK_ELF=\"$<\" -DMANIFEST_DATA=\"$(word 2,$^)\" $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) -c $(USER_TASK_OBJ_ASM) -o $@

EXTRA_OBJS += $(BUILTIN_TASK_OBJS)

endif

BASE_XBIN_LDFLAGS :=

ALLOW_FP_USE := $(SAVED_ALLOW_FP_USE)
SAVED_ALLOW_FP_USE :=

SCS_ENABLED := $(SAVED_SCS_ENABLED)
SAVED_SCS_ENABLED :=


