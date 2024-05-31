.PHONY: all clean libs_aarch64 libs_x86_64

CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CARGO_CONFIG := .cargo/config.toml
OUT_DIR := static_libs
BUILD_DIR := $(OUT_DIR)/build

all: libs_aarch64 libs_x86_64 $(CARGO_CONFIG)

ifeq ($(ANDROID_NDK_ROOT),)
$(error ANDROID_NDK_ROOT variable is not defined)
endif

ANDROID_API_LEVEL ?= 30

NDK_BIN_PATH := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin

AARCH64_PREFIX := aarch64-linux-android
X86_64_PREFIX := x86_64-linux-android

export CC_aarch64_linux_android := $(NDK_BIN_PATH)/$(AARCH64_PREFIX)$(ANDROID_API_LEVEL)-clang
export CXX_aarch64_linux_android := $(NDK_BIN_PATH)/$(AARCH64_PREFIX)$(ANDROID_API_LEVEL)-clang++
export CC_x86_64_linux_android := $(NDK_BIN_PATH)/$(X86_64_PREFIX)$(ANDROID_API_LEVEL)-clang
export CXX_x86_64_linux_android := $(NDK_BIN_PATH)/$(X86_64_PREFIX)$(ANDROID_API_LEVEL)-clang++
export AR_NDK := $(NDK_BIN_PATH)/llvm-ar

export RUSTFLAGS_aarch64_linux_android := -L$(CURRENT_DIR)/$(OUT_DIR)/$(AARCH64_PREFIX)/lib
export RUSTFLAGS_x86_64_linux_android := -L$(CURRENT_DIR)/$(OUT_DIR)/$(X86_64_PREFIX)/lib

$(CARGO_CONFIG): .cargo/config_template.toml
	CURRENT_DIR=$(CURRENT_DIR) envsubst <$^ >$@

$(BUILD_DIR):
	mkdir -p $@

$(OUT_DIR):
	mkdir -p $@

libs_aarch64: Makefile_arch
	$(MAKE) -f $^ \
		CC=$(CC_aarch64_linux_android) \
		CXX=$(CXX_aarch64_linux_android) \
		BUILD_DIR=$(BUILD_DIR)/$(AARCH64_PREFIX) \
		OUT_DIR=$(OUT_DIR)/$(AARCH64_PREFIX) \
		HOST=$(AARCH64_PREFIX)

libs_x86_64: Makefile_arch
	$(MAKE) -f $^ \
		CC=$(CC_x86_64_linux_android) \
		CXX=$(CXX_x86_64_linux_android) \
		BUILD_DIR=$(BUILD_DIR)/$(X86_64_PREFIX) \
		OUT_DIR=$(OUT_DIR)/$(X86_64_PREFIX) \
		HOST=$(X86_64_PREFIX)

clean:
	rm -rf $(CARGO_CONFIG) $(OUT_DIR)
