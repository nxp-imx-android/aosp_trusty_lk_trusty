#
# Copyright (c) 2021, Google, Inc. All rights reserved
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

# The following set of variables must can be passed to trusty_app.mk:
#
#     APP_NAME - an output file name (without extension)
#     APP_TOP_MODULE - top module to compile
#     APP_BUILDDIR - build directory
#
# To sign the app with a different key than the default one from
# APPLOADER_SIGN_KEY_ID, set the following variable in rules.mk:
#     APPLOADER_SIGN_KEY_ID_FOR_$(MODULE)

# Build a loadable application
LOADABLE_APP_TOOL := $(BUILDDIR)/host_tools/apploader_package_tool

APP_ELF := $(APP_BUILDDIR)/$(APP_NAME).elf
APP_MANIFEST := $(APP_BUILDDIR)/$(APP_NAME).manifest

UNSIGNED_APP := $(APP_BUILDDIR)/$(APP_NAME).app.unsigned
LOADABLE_APP := $(APP_BUILDDIR)/$(APP_NAME).app

$(UNSIGNED_APP): LOADABLE_APP_TOOL := $(LOADABLE_APP_TOOL)
$(UNSIGNED_APP): $(APP_ELF) $(APP_MANIFEST) $(LOADABLE_APP_TOOL)
	@$(MKDIR)
	@echo building $@ from $<
	$(NOECHO)$(LOADABLE_APP_TOOL) -m build $@ $< $(word 2,$^)

# If we have an app-specific key identifier then use it,
# otherwise use the global default
ifneq ($(APPLOADER_SIGN_KEY_ID_FOR_$(APP_TOP_MODULE)),)
APP_SIGN_KEY_ID := $(APPLOADER_SIGN_KEY_ID_FOR_$(APP_TOP_MODULE))
else
APP_SIGN_KEY_ID := $(APPLOADER_SIGN_KEY_ID)
endif

ifneq ($(APP_SIGN_KEY_ID),)
APP_SIGN_KEY_FILE := $(APPLOADER_SIGN_PRIVATE_KEY_$(APP_SIGN_KEY_ID)_FILE)
endif

ifneq ($(APP_SIGN_KEY_FILE),)
$(LOADABLE_APP): LOADABLE_APP_TOOL := $(LOADABLE_APP_TOOL)
$(LOADABLE_APP): APP_SIGN_KEY_FILE := $(APP_SIGN_KEY_FILE)
$(LOADABLE_APP): APP_SIGN_KEY_ID := $(APP_SIGN_KEY_ID)
$(LOADABLE_APP): $(UNSIGNED_APP) $(APP_SIGN_KEY_FILE) $(LOADABLE_APP_TOOL)
	@$(MKDIR)
	@echo building $@ from $<
	$(NOECHO)$(LOADABLE_APP_TOOL) -m sign $@ $< \
		$(APP_SIGN_KEY_FILE) $(APP_SIGN_KEY_ID)
else
# If we don't have a signature file, just use the unsigned file as the output
# This is needed because modules that import loadable apps, e.g.,
# app-mgmt-test, need the app files to exist
# Note: apploader will refuse to load the unsigned application
$(LOADABLE_APP): $(UNSIGNED_APP)
	@$(MKDIR)
	@echo copying $< to $@
	@cp $< $@

$(warning Loadable application is not signed: $(LOADABLE_APP))
endif

GENERATED += $(LOADABLE_APP)
EXTRA_BUILDDEPS += $(LOADABLE_APP)

# Reset local variables
APP_NAME :=
APP_BUILDDIR :=
APP_TOP_MODULE :=

LOADABLE_APP_TOOL :=
APP_ELF :=
APP_MANIFEST :=

UNSIGNED_APP :=
LOADABLE_APP :=

APP_SIGN_KEY_ID :=
APP_SIGN_KEY_FILE :=
