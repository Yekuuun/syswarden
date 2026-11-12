//go:build linux

package main

import (
	"fmt"
	"os"
)

func execute() int {
	fmt.Fprintln(os.Stderr, "[SYSWARDEN-eBPF] Not implemented yet")
	return 1
}
