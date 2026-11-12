// Package pipeline moves ringbuf records to ebpf.json. The reading side never
// blocks on the writing side: a full queue drops and counts, so a slow disk
// can never make the kernel ringbuf overflow silently.
package pipeline

import (
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"syswarden-ebpf/internal/event"
)

// QueueSize bounds the records waiting between the reader and the writer.
const QueueSize = 4096

// errStop is returned by a source once it has nothing more to give.
var errStop = errors.New("source stopped")

// Stats are the userspace counters, read by `syswarden-ebpf status`.
type Stats struct {
	Received     atomic.Uint64 // records read from the ringbuf
	QueueDropped atomic.Uint64 // records lost because the writer lags
	DecodeErrors atomic.Uint64
	WriteErrors  atomic.Uint64
	Written      atomic.Uint64 // lines written to ebpf.json
}

// source yields raw ringbuf records until errStop.
type source interface {
	Read() ([]byte, error)
}

// sink receives one encoded JSON line at a time.
type sink interface {
	Write(line []byte) error
}

// wallClock converts a CLOCK_MONOTONIC timestamp to wall clock time.
type wallClock func(monoNs uint64) time.Time

// pump reads src into queue until errStop or a read error, then closes queue.
func pump(src source, queue chan<- []byte, st *Stats) error {
	defer close(queue)
	for {
		record, err := src.Read()
		if errors.Is(err, errStop) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read ringbuf: %w", err)
		}
		st.Received.Add(1)
		select {
		case queue <- record:
		default:
			st.QueueDropped.Add(1)
		}
	}
}

// writeFull writes every queued event as is (mode full), until queue closes.
func writeFull(queue <-chan []byte, out sink, clock wallClock, st *Stats, logf throttledLog) {
	for record := range queue {
		ev, err := event.Decode(record)
		if err != nil {
			st.DecodeErrors.Add(1)
			logf("dropping undecodable record: %v", err)
			continue
		}
		rec, err := event.NewRecord(ev, clock(ev.Header.MonoNs))
		if err != nil {
			st.DecodeErrors.Add(1)
			logf("dropping record: %v", err)
			continue
		}
		line, err := event.Encode(rec)
		if err == nil {
			err = out.Write(line)
		}
		if err != nil {
			st.WriteErrors.Add(1)
			logf("cannot write event: %v", err)
			continue
		}
		st.Written.Add(1)
	}
}

// throttledLog logs at most once per interval, so a broken disk does not
// flood the journal with one line per event.
type throttledLog func(format string, args ...any)

func newThrottledLog(interval time.Duration, now func() time.Time) throttledLog {
	var last time.Time
	var skipped int
	return func(format string, args ...any) {
		t := now()
		if !last.IsZero() && t.Sub(last) < interval {
			skipped++
			return
		}
		if skipped > 0 {
			log.Printf("[SYSWARDEN-eBPF] %d similar messages suppressed", skipped)
			skipped = 0
		}
		last = t
		log.Printf("[SYSWARDEN-eBPF] "+format, args...)
	}
}
