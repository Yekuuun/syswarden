//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/pipeline"
)

const usage = `usage: syswarden-ebpf <command> [flags]

commands:
  run      load the BPF programs and write events to the configured log
`

func execute() int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch os.Args[1] {
	case "run":
		return runCommand(os.Args[2:])
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
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", config.DefaultPath, "configuration file")
	mode := flags.String("mode", "", "override the configured mode (full or summary)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.PrintDefaults()
			return 0
		}
		fmt.Fprintf(os.Stderr, "[SYSWARDEN-eBPF] %v\n", err)
		return 2
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
	err = pipeline.Run(ctx, cfg, &stats)
	log.Printf("[SYSWARDEN-eBPF] Stopped: received=%d written=%d queue_dropped=%d decode_errors=%d write_errors=%d ignored=%d aggregated=%d evicted=%d expired=%d",
		stats.Received.Load(), stats.Written.Load(), stats.QueueDropped.Load(), stats.DecodeErrors.Load(), stats.WriteErrors.Load(),
		stats.Ignored.Load(), stats.Aggregated.Load(), stats.Evicted.Load(), stats.Expired.Load())
	if err != nil {
		log.Printf("[SYSWARDEN-eBPF] %v", err)
		return 1
	}
	return 0
}
