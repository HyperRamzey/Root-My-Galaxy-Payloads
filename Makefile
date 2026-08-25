API ?= 35
TARGET ?= pa3q-S938NKSUACZF1
OUTDIR ?= build/$(TARGET)

APP_TARGET_CFLAGS :=
ifneq ($(filter dm2q-S916BXXSAFZG1 dm2q-S916NKSS8FZG1 f946b-F946BXXS7GZE5,$(TARGET)),)
APP_TARGET_CFLAGS := -DSLIDE_STACK_WRITER=1
endif

TARGET_HEADER := src/targets/$(TARGET)/target.h
TARGET_INCLUDE := targets/$(TARGET)/target.h
HOST_TAG := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(HOST_TAG),Linux)
  NDK_HOST := linux-x86_64
else ifeq ($(HOST_TAG),Darwin)
  NDK_HOST := darwin-x86_64
else
  NDK_HOST := windows-x86_64
endif
TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin/aarch64-linux-android$(API)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

PRELOAD := $(OUTDIR)/cve-2026-43499
APP_PRELOAD := $(OUTDIR)/cve-2026-43499-app.so
APP_RELEASE := $(OUTDIR)/cve-2026-43499-app.release.so
APP_RELEASE_SIZE := 104128
ROOT_HELPER := $(OUTDIR)/cve-2026-43499-root

PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

APP_PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide_app.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra -march=armv8-a+crc+crypto -mtune=cortex-a715 -flto=thin -ffunction-sections -fdata-sections -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden \
  -Wno-unused-parameter -Wno-sign-compare \
  -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"'

COMMON_LDFLAGS := -flto=thin -Wl,--gc-sections -Wl,-O3

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER)

release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread $(COMMON_LDFLAGS) -o $@

$(ROOT_HELPER): src/su_daemon.c | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie $(COMMON_CFLAGS) $< -ldl $(COMMON_LDFLAGS) -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 $(APP_TARGET_CFLAGS) -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread $(COMMON_LDFLAGS) -o $@

$(APP_RELEASE): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 $(APP_TARGET_CFLAGS) -fPIC -O2 -g0 \
	  -flto=thin \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' \
	  $(APP_PRELOAD_SRCS) -shared -pthread \
	  -flto=thin -Wl,--gc-sections -s -o $@
	@test $$(stat -c %s $@) -le $(APP_RELEASE_SIZE)
	truncate -s $(APP_RELEASE_SIZE) $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "APP_TARGET_CFLAGS=$(APP_TARGET_CFLAGS)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "APP_PRELOAD=$(APP_PRELOAD)"
	@echo "APP_RELEASE=$(APP_RELEASE)"
	@echo "ROOT_HELPER=$(ROOT_HELPER)"

clean:
	rm -rf $(OUTDIR)
