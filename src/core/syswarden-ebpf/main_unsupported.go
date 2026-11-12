//go:build !linux

package main

import (
	"fmt"
	"os"
)

func execute() int {
	fmt.Fprintln(os.Stderr, "[SYSWARDEN-eBPF] Only supported on Linux")
	return 1
}
