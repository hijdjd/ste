TARGET := iphone:clang:16.5:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES = StarbucksSTE

THEOS_TC := $(THEOS)/toolchain/linux/iphone/bin

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = stehook
stehook_FILES = Tweak.x
stehook_CFLAGS = -fobjc-arc -Wno-unused-function -Wno-unused-variable
stehook_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
