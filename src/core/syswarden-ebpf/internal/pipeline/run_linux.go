//go:build linux

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/jsonlog"
	"syswarden-ebpf/internal/probe"
)

// Run loads, attaches and streams events until ctx is done, then stops in
// order: detach, drain the ringbuf, drain the queue, close files.
func Run(ctx context.Context, cfg config.Config, st *Stats) error {
	if cfg.Mode != config.ModeFull {
		return fmt.Errorf("mode %q is not available yet, run with --mode full", cfg.Mode)
	}

	out, err := jsonlog.Open(jsonlog.Options{Path: cfg.Output.Path, MaxBytes: cfg.Output.MaxBytes, Generations: cfg.Output.Generations})
	if err != nil {
		return err
	}
	defer closeLogged("output", out.Close)

	kcfg := probe.KernelConfig{SelfTGID: uint32(os.Getpid())}
	if cfg.Filter.IgnoreLoopback {
		kcfg.Flags |= probe.FlagIgnoreLoopback
	}
	p, err := probe.Load(kcfg)
	if err != nil {
		return err
	}
	defer closeLogged("probe", p.Close)

	rd, err := ringbuf.NewReader(p.Events())
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer closeLogged("ringbuf reader", rd.Close)

	queue := make(chan []byte, QueueSize)
	pumpErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pumpErr <- pump(ringbufSource{rd}, queue, st) }()
	go func() {
		defer wg.Done()
		writeFull(queue, out, monotonicToWall, st, newThrottledLog(10*time.Second, time.Now))
	}()

	var runErr error
	if runErr = p.Attach(); runErr == nil {
		logStatus(p.Status(), cfg)
		select {
		case <-ctx.Done():
			log.Println("[SYSWARDEN-eBPF] Shutting down gracefully...")
		case runErr = <-pumpErr:
			log.Printf("[SYSWARDEN-eBPF] Reader stopped, shutting down: %v", runErr)
		}
	}

	//stop new events first, then hand out what is left in the ringbuf.
	detachErr := p.Detach()
	if err := rd.Flush(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("[SYSWARDEN-eBPF] Cannot flush ringbuf: %v", err)
		_ = rd.Close()
	}
	wg.Wait()

	return errors.Join(runErr, detachErr)
}

// ringbufSource ends on Flush (ErrFlushed) or Close (ErrClosed).
type ringbufSource struct{ rd *ringbuf.Reader }

func (s ringbufSource) Read() ([]byte, error) {
	rec, err := s.rd.Read()
	if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
		return nil, errStop
	}
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

// monotonicToWall maps bpf_ktime_get_ns (CLOCK_MONOTONIC) to wall time. It
// is computed per event, so NTP steps and suspend are taken into account.
func monotonicToWall(monoNs uint64) time.Time {
	now := time.Now()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return now
	}
	current := uint64(ts.Nano())
	if monoNs > current {
		return now
	}
	return now.Add(-time.Duration(current - monoNs))
}

func logStatus(st probe.Status, cfg config.Config) {
	log.Printf("[SYSWARDEN-eBPF] Observing (mode=%s, output=%s, ignore_loopback=%v)", cfg.Mode, cfg.Output.Path, cfg.Filter.IgnoreLoopback)
	if st.LSM {
		log.Println("[SYSWARDEN-eBPF] Attached: tracepoint sock/inet_sock_set_state, lsm/socket_connect, lsm/socket_bind")
		return
	}
	log.Printf("[SYSWARDEN-eBPF] Attached: tracepoint sock/inet_sock_set_state only, LSM hooks skipped: %s", st.LSMReason)
}

func closeLogged(name string, closeFn func() error) {
	if err := closeFn(); err != nil {
		log.Printf("[SYSWARDEN-eBPF] Closing %s: %v", name, err)
	}
}
