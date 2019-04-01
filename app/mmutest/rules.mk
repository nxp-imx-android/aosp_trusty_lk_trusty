LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_DEPS += \
	trusty/kernel/lib/unittest \

MODULE_SRCS += \
	$(LOCAL_DIR)/mmutest.c \
	$(LOCAL_DIR)/mmutest_$(ARCH).S \

include make/module.mk
