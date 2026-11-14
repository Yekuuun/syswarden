//go:build linux

package pipeline

import (
	"os"
	"sync"
	"time"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/event"
	"syswarden-ebpf/internal/probe"
	"syswarden-ebpf/internal/status"
)

// publisher writes the status file. Its methods may run from the periodic
// goroutine and from Run, hence the mutex.
type publisher struct {
	mu       sync.Mutex
	path     string
	cfg      config.Config
	st       *Stats
	started  time.Time
	probe    *probe.Probe // nil once detached
	attached probe.Status
	kernel   status.Kernel // last read, kept after the maps are closed
	logf     throttledLog
}

func newPublisher(path string, cfg config.Config, st *Stats) *publisher {
	return &publisher{path: path, cfg: cfg, st: st, started: time.Now(), logf: newThrottledLog(time.Minute, time.Now)}
}

func (pb *publisher) attach(p *probe.Probe) {
	pb.mu.Lock()
	pb.probe, pb.attached = p, p.Status()
	pb.mu.Unlock()
	pb.publish(status.StateRunning, nil)
}

// detach reads the kernel counters one last time and forgets the probe.
func (pb *publisher) detach() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.refreshKernelLocked()
	pb.probe = nil
	pb.attached = probe.Status{LSMReason: pb.attached.LSMReason}
}

// every publishes "running" each interval until the returned stop is called.
func (pb *publisher) every(interval time.Duration) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pb.publish(status.StateRunning, nil)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

func (pb *publisher) publish(state string, runErr error) {
	pb.mu.Lock()
	pb.refreshKernelLocked()
	snap := pb.snapshotLocked(state, runErr, time.Now())
	pb.mu.Unlock()

	if err := status.Write(pb.path, snap); err != nil {
		pb.logf("cannot write status %s: %v", pb.path, err)
	}
}

func (pb *publisher) refreshKernelLocked() {
	if pb.probe == nil {
		return
	}
	full, filtered, err := pb.probe.KernelDrops()
	if err != nil {
		pb.logf("cannot read kernel counters: %v", err)
		return
	}
	pb.kernel = status.Kernel{RingbufFull: full, Filtered: filtered}
}

func (pb *publisher) snapshotLocked(state string, runErr error, now time.Time) status.Snapshot {
	snap := status.Snapshot{
		SchemaVersion:  status.SchemaVersion,
		State:          state,
		PID:            os.Getpid(),
		StartedAt:      pb.started.UTC(),
		UpdatedAt:      now.UTC(),
		EventSchema:    event.SchemaVersion,
		Mode:           string(pb.cfg.Mode),
		Output:         pb.cfg.Output.Path,
		IgnoreLoopback: pb.cfg.Filter.IgnoreLoopback,
		IgnoreRules:    len(pb.cfg.Ignore),
		Attached:       status.Attached{Tracepoint: pb.attached.Tracepoint, LSM: pb.attached.LSM, LSMReason: pb.attached.LSMReason},
		Kernel:         pb.kernel,
		Userspace:      pb.st.snapshot(),
	}
	if runErr != nil {
		snap.Error = runErr.Error()
	}
	return snap
}
