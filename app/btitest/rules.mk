LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_DEPS += \
	trusty/kernel/lib/unittest \

# Only build the test module if BTI is configured for some part of the system
ifeq (falsefalse,$(call TOBOOL,$(KERNEL_BTI_ENABLED))$(call TOBOOL,$(USER_BTI_ENABLED)))
MODULE_SRCS += \
	$(LOCAL_DIR)/btitest_stub.c
else
MODULE_SRCS += \
	$(LOCAL_DIR)/btitest.c \
	$(LOCAL_DIR)/btitest_arm64.S
endif

include make/module.mk
