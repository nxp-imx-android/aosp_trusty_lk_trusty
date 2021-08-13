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

$(info Include Trusty user tasks support)

TRUSTY_APP_DIR := $(GET_LOCAL_DIR)

# generate trusty app or library build rules:
# $(1): path to app source dir (module name)
#
# Note: this function must be eval'd after calling it
#
# Other input variables, shared across all apps
# TRUSTY_APP_BASE_LDFLAGS: LDFLAGS for the app
# ARCH: Architecture of the app
# TRUSTY_APP_ALIGNMENT: Alignment of app image (defaults to 1)
# TRUSTY_APP_MEMBASE: App base address, if fixed
# TRUSTY_APP_SYMTAB_ENABLED: If true do not strip symbols from the
# 		resulting app binary
# TRUSTY_USERSPACE: Boolean indicating that the app should be built for the
# 		trusty userspace
#
define trusty-build-rule
# MODULE should be set to the parent module when including userspace_recurse.mk.
# In this case we are trying to build a top-level app or library, and need to
# isolate this build from the kernel build. In order to isolate the top level
# library (or app) module from the kernel build system, we save the kernel
# module flags (to a synthetic parent module, KERNEL), clear those flags, then
# include the library via DEPENDENCY_MODULE. After finishing with the rules for
# the library, we will restore the kernel flags from their saved values.
DEPENDENCY_MODULE := $(1)
MODULE := KERNEL
include make/userspace_recurse.mk
endef

TRUSTY_TOP_LEVEL_BUILDDIR := $(BUILDDIR)
TRUSTY_APP_BUILDDIR := $(BUILDDIR)/user_tasks
TRUSTY_LIBRARY_BUILDDIR := $(BUILDDIR)/lib

GLOBAL_USER_RUSTFLAGS += -L dependency=$(TRUSTY_LIBRARY_BUILDDIR)

GLOBAL_CRATE_COUNT := 0
RUST_ANALYZER_CRATES :=

# Save userspace-global variables so we can restore kernel state
TRUSTY_KERNEL_SAVED_ARCH := $(ARCH)
TRUSTY_KERNEL_SAVED_ALLOW_FP_USE := $(ALLOW_FP_USE)
TRUSTY_KERNEL_SAVED_SCS_ENABLED := $(SCS_ENABLED)

# while compiling user space we allow FP support
ALLOW_FP_USE := true

# tell the arch-specific makefiles to set flags required for SCS if supported
SCS_ENABLED := $(call TOBOOL,$(USER_SCS_ENABLED))

# Building trusty userspace
TRUSTY_USERSPACE := true

# Used by LTO, could be combined with TRUSTY_USERSPACE after this lands
USER_TASK_MODULE := true

ARCH := $(TRUSTY_USER_ARCH)
# Re-derive the standard arch name using the new arch.
$(eval $(call standard_name_for_arch,STANDARD_ARCH_NAME,$(ARCH),$(SUBARCH)))

# Override tools for the userspace arch
include arch/$(ARCH)/toolchain.mk

include $(TRUSTY_APP_DIR)/arch/$(TRUSTY_USER_ARCH)/rules.mk

# generate list of all user tasks we need to build
# include the legacy TRUSTY_ALL_USER_TASKS variable for projects that still use
# it. This will be removed in the future and all projects should use
# TRUSTY_BUILTIN_USER_TASKS directly.
TRUSTY_BUILTIN_USER_TASKS := $(TRUSTY_BUILTIN_USER_TASKS) \
                             $(TRUSTY_ALL_USER_TASKS) \
                             $(TRUSTY_USER_TESTS)

ALL_USER_TASKS := $(TRUSTY_BUILTIN_USER_TASKS) $(TRUSTY_LOADABLE_USER_TASKS)
# sort and remove duplicates
ALL_USER_TASKS := $(sort $(ALL_USER_TASKS))

TRUSTY_APP_BASE_LDFLAGS := $(GLOBAL_SHARED_LDFLAGS) -z max-page-size=4096 -z separate-loadable-segments
TRUSTY_APP_ALIGNMENT := 4096
TRUSTY_APP_MEMBASE :=
TRUSTY_APP_SYMTAB_ENABLED := $(SYMTAB_ENABLED)

#
# Generate build rules for each user task
#
$(foreach t,$(ALL_USER_TASKS),\
   $(eval $(call trusty-build-rule,$(t))))

# Add any prebuilt apps to the build.

PREBUILT_OBJECTS := $(foreach t,$(TRUSTY_PREBUILT_USER_TASKS),\
	$(t)/$(notdir $(t)).manifest $(t)/$(notdir $(t)).elf)
PREBUILT_OBJECTS_DEST := $(addprefix $(BUILDDIR)/user_tasks/,$(PREBUILT_OBJECTS))
$(PREBUILT_OBJECTS_DEST): $(BUILDDIR)/user_tasks/%: %
	$(MKDIR)
	cp $^ $(dir $@)/

TRUSTY_BUILTIN_USER_TASKS += $(TRUSTY_PREBUILT_USER_TASKS)

#
# Generate loadable application packages
#
define loadable-app-build-rule
$(eval APP_NAME := $(notdir $(1)))\
$(eval APP_TOP_MODULE := $(1))\
$(eval APP_BUILDDIR := $(BUILDDIR)/user_tasks/$(1))\
$(eval include make/loadable_app.mk)
endef

# Sort and remove duplicates
TRUSTY_LOADABLE_USER_TASKS := $(sort $(TRUSTY_LOADABLE_USER_TASKS))

#
# Generate build rules for each application
#
$(foreach t,$(TRUSTY_LOADABLE_USER_TASKS),\
   $(call loadable-app-build-rule,$(t)))

# Clear the list of loadable apps
LOADABLE_APP_LIST :=

# Sort and remove duplicates
TRUSTY_USER_TESTS := $(sort $(TRUSTY_USER_TESTS))

#
# Generate build rules for test application
#
$(foreach t,$(TRUSTY_USER_TESTS),\
   $(call loadable-app-build-rule,$(t)))

# At this point LOADABLE_APP_LIST only contains user tests
TRUSTY_LOADABLE_TEST_APPS := $(LOADABLE_APP_LIST)

ifneq ($(strip $(TRUSTY_LOADABLE_TEST_APPS)),)

TEST_PACKAGE_ZIP := $(BUILDDIR)/trusty_test_package.zip

$(TEST_PACKAGE_ZIP): BUILDDIR := $(BUILDDIR)
$(TEST_PACKAGE_ZIP): $(TRUSTY_LOADABLE_TEST_APPS)
	@$(MKDIR)
	@echo Creating Trusty test archive package
	@echo "$^"
	$(NOECHO)rm -f $@
	$(NOECHO)(cd $(BUILDDIR) && zip -q -u -r $@ $(subst $(BUILDDIR)/,,$^))

EXTRA_BUILDDEPS += $(TEST_PACKAGE_ZIP)

endif


#
# Build a rust-project.json for rust-analyzer
#
RUST_PROJECT_JSON := $(BUILDDIR)/rust-project.json
define RUST_PROJECT_JSON_CONTENTS :=
{
	"crates": [
		$(call STRIP_TRAILING_COMMA,$(RUST_ANALYZER_CRATES))
	]
}
endef
RUST_PROJECT_JSON_CONTENTS := $(subst $(NEWLINE),\n,$(RUST_PROJECT_JSON_CONTENTS))
.PHONY: $(RUST_PROJECT_JSON)
$(RUST_PROJECT_JSON): CONTENTS := $(RUST_PROJECT_JSON_CONTENTS)
$(RUST_PROJECT_JSON):
	@$(MKDIR)
	@echo Creating rust-project.json for rust-analyzer
	$(NOECHO)echo -e '$(CONTENTS)' > $@

EXTRA_BUILDDEPS += $(RUST_PROJECT_JSON)


# Restore kernel state
ARCH := $(TRUSTY_KERNEL_SAVED_ARCH)
ALLOW_FP_USE := $(TRUSTY_KERNEL_SAVED_ALLOW_FP_USE)
SCS_ENABLED := $(TRUSTY_KERNEL_SAVED_SCS_ENABLED)

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

# Reset app variables
TRUSTY_APP :=
TRUSTY_APP_NAME :=
TRUSTY_APP_BASE_LDFLAGS :=
TRUSTY_APP_ARCH :=
TRUSTY_APP_ALIGNMENT :=
TRUSTY_APP_MEMBASE :=
TRUSTY_APP_SYMTAB_ENABLED :=
TRUSTY_TOP_LEVEL_BUILDDIR :=
TRUSTY_USERSPACE :=
TRUSTY_USERSPACE_SAVED_ARCH :=
TRUSTY_USERSPACE_SAVED_ALLOW_FP_USE :=
TRUSTY_USERSPACE_SAVED_SCS_ENABLED :=
USER_TASK_MODULE :=
LOADABLE_APP_LIST :=
TRUSTY_LOADABLE_USER_TASKS :=
TEST_PACKAGE_ZIP :=
RUST_PROJECT_JSON :=
RUST_PROJECT_JSON_CONTENTS :=
RUST_ANALYZER_CRATES :=
GLOBAL_CRATE_COUNT :=
