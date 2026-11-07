#syswarden-ebpf kernel side (BPF) build.

# Absolute paths, so the file works from any working directory
KERNEL_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

HOST_MACHINE := $(shell uname -m)
ifeq ($(HOST_MACHINE),x86_64)
HOST_ARCH := x86
else ifeq ($(HOST_MACHINE),aarch64)
HOST_ARCH := arm64
else
HOST_ARCH := $(HOST_MACHINE)
endif

BPF_TARGET_ARCH ?= $(HOST_ARCH)
CLANG       	?= clang
BPFTOOL     	?= bpftool
# BTF source for `make vmlinux`; defaults to the running kernel when it matches the target arch.
VMLINUX_BTF 	?= $(if $(filter $(BPF_TARGET_ARCH),$(HOST_ARCH)),/sys/kernel/btf/vmlinux)

SYSWARDEN_O := syswarden.bpf.o
BUILD_DIR   := $(KERNEL_DIR)/build
BPF_SRC     := $(KERNEL_DIR)/main.bpf.c
BPF_OBJ     := $(BUILD_DIR)/$(SYSWARDEN_O)
VMLINUX_H   := $(BUILD_DIR)/vmlinux_generated_$(BPF_TARGET_ARCH).h
BPF_HEADERS := $(shell find $(KERNEL_DIR) -path $(BUILD_DIR) -prune -o \( -name '*.h' -o -name '*.c' \) -print)

CLANG_FLAGS := -O2 -g -Wall -target bpf \
	-D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
	-I $(BUILD_DIR) -I $(KERNEL_DIR)/includes -I $(KERNEL_DIR)

.PHONY: all vmlinux clean distclean

all: $(BPF_OBJ)

# main.bpf.c includes the committed headers under includes/vmlinux/, not $(VMLINUX_H).
$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS) | $(BUILD_DIR)
	$(CLANG) $(CLANG_FLAGS) -c $(BPF_SRC) -o $@

$(VMLINUX_H): | $(BUILD_DIR)
	@test -n "$(VMLINUX_BTF)" || { echo "error: no BTF for $(BPF_TARGET_ARCH) on this $(HOST_ARCH) host: pass VMLINUX_BTF=<btf file>" >&2; exit 1; }
	@command -v $(BPFTOOL) >/dev/null || { echo "error: $(BPFTOOL) not found (install bpftool, e.g. linux-tools-$$(uname -r))" >&2; exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR):
	mkdir -p $@

vmlinux:
	rm -f $(VMLINUX_H)
	$(MAKE) $(VMLINUX_H)

clean:
	rm -f $(BPF_OBJ)

distclean:
	rm -rf $(BUILD_DIR)
