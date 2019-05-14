LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_DEFINES += \
	WITH_DPC_TEST=1 \

MODULE_DEPS += \
	external/lk/lib/dpc \
	trusty/kernel/lib/unittest \

MODULE_SRCS += \
	$(LOCAL_DIR)/dpctest.c \

include make/module.mk
