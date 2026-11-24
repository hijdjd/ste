TARGET := iphone:clang:latest:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES = StarbucksSTE

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = stehook
stehook_FILES = Tweak.x
stehook_CFLAGS = -fobjc-arc
stehook_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
