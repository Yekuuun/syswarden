//go:build linux

// Package probe loads and attaches the syswarden BPF programs. The object is
// compiled from bpf/main.bpf.c by bpf2go and embedded, so no clang nor cgo at build.
package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 -cc clang -cflags "-O2 -g -Wall -Wno-missing-declarations -I../../bpf/includes -I../../bpf" syswarden ../../bpf/main.bpf.c
