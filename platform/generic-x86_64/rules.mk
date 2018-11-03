LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

CPU := generic

SMP_MAX_CPUS ?= 1

MODULE_DEPS += \
	lib/cbuf

MEMBASE := 0x00200000
MEMSIZE := 0x0fe00000

GLOBAL_DEFINES += \
	MEMBASE=$(MEMBASE) \
	MEMSIZE=$(MEMSIZE) \

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_DEPS += \
	dev/interrupt/x86_lapic \
	dev/timer/x86_generic \

include make/module.mk
