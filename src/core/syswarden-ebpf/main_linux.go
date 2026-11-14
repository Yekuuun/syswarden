//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/pipeline"
	"syswarden-ebpf/internal/status"
)

const usage = `usage: syswarden-ebpf <command> [flags]

commands:
  run      load the BPF programs and write events to the configured log
  status   print the state of the running daemon (exit 1 when not running)
`

func execute() int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch os.Args[1] {
	case "run":
		return runCommand(os.Args[2:])
	case "status":
		return statusCommand(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", os.Args[1], usage)
		return 2
	}
}

func runCommand(args []string) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := flags.String("config", config.DefaultPath, "configuration file")
	mode := flags.String("mode", "", "override the configured mode (full or summary)")
	statusPath := flags.String("status", status.DefaultPath, "status file")
	if code, done := parseFlags(flags, args); done {
		return code
	}

	cfg, found, err := config.Load(*configPath)
	if err != nil {
		log.Printf("[SYSWARDEN-eBPF] Refusing to start: %v", err)
		return 1
	}
	if !found {
		log.Printf("[SYSWARDEN-eBPF] %s not found, using defaults", *configPath)
	}
	if *mode != "" {
		cfg.Mode = config.Mode(*mode)
		if err := cfg.Validate(); err != nil {
			log.Printf("[SYSWARDEN-eBPF] Refusing to start: %v", err)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var stats pipeline.Stats
	err = pipeline.Run(ctx, cfg, &stats, *statusPath)
	log.Printf("[SYSWARDEN-eBPF] Stopped: received=%d written=%d queue_dropped=%d decode_errors=%d write_errors=%d ignored=%d aggregated=%d evicted=%d expired=%d",
		stats.Received.Load(), stats.Written.Load(), stats.QueueDropped.Load(), stats.DecodeErrors.Load(), stats.WriteErrors.Load(),
		stats.Ignored.Load(), stats.Aggregated.Load(), stats.Evicted.Load(), stats.Expired.Load())
	if err != nil {
		log.Printf("[SYSWARDEN-eBPF] %v", err)
		return 1
	}
	return 0
}

func statusCommand(args []string) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	statusPath := flags.String("status", status.DefaultPath, "status file")
	if code, done := parseFlags(flags, args); done {
		return code
	}

	snap, err := status.Read(*statusPath)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "syswarden-ebpf is not running (no %s)\n", *statusPath)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "syswarden-ebpf status: %v\n", err)
		return 1
	}

	out, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "syswarden-ebpf status: %v\n", err)
		return 1
	}
	fmt.Println(string(out))

	if err := snap.Check(time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "syswarden-ebpf is not running: %v\n", err)
		return 1
	}
	return 0
}

// parseFlags returns done when the command must stop with code.
func parseFlags(flags *flag.FlagSet, args []string) (code int, done bool) {
	flags.SetOutput(io.Discard)
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		flags.SetOutput(os.Stdout)
		flags.PrintDefaults()
		return 0, true
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SYSWARDEN-eBPF] %v\n", err)
		return 2, true
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "[SYSWARDEN-eBPF] unexpected arguments: %v\n", flags.Args())
		return 2, true
	}
	return 0, false
}
