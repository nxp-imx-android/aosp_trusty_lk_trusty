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

# Build a loadable application
LOADABLE_APP_TOOL := $(BUILDDIR)/host_tools/apploader_package_tool

APP_ELF := $(APP_BUILDDIR)/$(APP_NAME).elf
APP_MANIFEST := $(APP_BUILDDIR)/$(APP_NAME).manifest

LOADABLE_APP := $(APP_BUILDDIR)/$(APP_NAME).app

$(LOADABLE_APP): LOADABLE_APP_TOOL := $(LOADABLE_APP_TOOL)
$(LOADABLE_APP): $(APP_ELF) $(APP_MANIFEST) $(LOADABLE_APP_TOOL)
	@$(MKDIR)
	@echo building $@ from $<
	$(NOECHO)$(LOADABLE_APP_TOOL) -m build $@ $< $(word 2,$^)

GENERATED += $(LOADABLE_APP)
EXTRA_BUILDDEPS += $(LOADABLE_APP)

# Reset local variables
APP_NAME :=
APP_BUILDDIR :=
APP_TOP_MODULE :=

LOADABLE_APP_TOOL :=
APP_ELF :=
APP_MANIFEST :=
LOADABLE_APP :=
