# Global build for the syswarden-ebpf project.

GO ?= go

# Outside go.work, like scripts/versionctl.
GO_ENV := GOWORK=off CGO_ENABLED=0

.PHONY: all bpf generate go clean distclean

all: bpf go

bpf:
	$(MAKE) -C bpf

# Regenerates the embedded BPF object (needs clang); the result is committed.
generate:
	GOWORK=off $(GO) generate ./...

go:
	$(GO_ENV) $(GO) build -o build/syswarden-ebpf .

clean:
	$(MAKE) -C bpf clean
	rm -f build/syswarden-ebpf

distclean:
	$(MAKE) -C bpf distclean
	rm -rf build
