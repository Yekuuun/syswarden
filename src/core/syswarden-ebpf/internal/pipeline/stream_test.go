package pipeline

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"syswarden-ebpf/internal/event"
)

type sliceSource struct {
	records [][]byte
	err     error // returned once records are exhausted, errStop when nil
}

func (s *sliceSource) Read() ([]byte, error) {
	if len(s.records) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, errStop
	}
	r := s.records[0]
	s.records = s.records[1:]
	return r, nil
}

type memSink struct {
	mu    sync.Mutex
	lines []string
	err   error
}

func (m *memSink) Write(line []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.lines = append(m.lines, string(line))
	return nil
}

var fixedClock wallClock = func(uint64) time.Time { return time.Unix(0, 0) }

func silent(string, ...any) {}

// record builds a minimal valid lsm_bind record with the given comm.
func record(comm string) []byte {
	b := make([]byte, event.RecordSize)
	ne := binary.NativeEndian
	ne.PutUint16(b[0:], event.SchemaVersion)
	ne.PutUint16(b[2:], uint16(event.TypeLSMBind))
	ne.PutUint32(b[4:], event.RecordSize)
	copy(b[28:44], comm)
	b[44] = uint8(event.AttributionReliable)
	ne.PutUint16(b[48+8:], 2) //AF_INET
	return b
}

func TestFullModeWritesEveryEventInOrder(t *testing.T) {
	src := &sliceSource{records: [][]byte{record("a"), record("b"), record("c")}}
	queue := make(chan []byte, QueueSize)
	out := &memSink{}
	var st Stats

	if err := pump(src, queue, &st); err != nil {
		t.Fatal(err)
	}
	writeFull(queue, out, fixedClock, &st, silent)

	if len(out.lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(out.lines))
	}
	for i, comm := range []string{"a", "b", "c"} {
		if !strings.Contains(out.lines[i], `"comm":"`+comm+`"`) || !strings.HasSuffix(out.lines[i], "\n") {
			t.Fatalf("line %d: %s", i, out.lines[i])
		}
	}
	if st.Received.Load() != 3 || st.Written.Load() != 3 || st.QueueDropped.Load() != 0 {
		t.Fatalf("stats: received=%d written=%d dropped=%d", st.Received.Load(), st.Written.Load(), st.QueueDropped.Load())
	}
}

func TestPumpDropsInsteadOfBlockingOnFullQueue(t *testing.T) {
	records := make([][]byte, 10)
	for i := range records {
		records[i] = record("x")
	}
	queue := make(chan []byte, 4) //nobody reads it
	var st Stats

	done := make(chan error)
	go func() { done <- pump(&sliceSource{records: records}, queue, &st) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pump blocked on a full queue")
	}
	if st.Received.Load() != 10 || st.QueueDropped.Load() != 6 || len(queue) != 4 {
		t.Fatalf("received=%d dropped=%d queued=%d", st.Received.Load(), st.QueueDropped.Load(), len(queue))
	}
}

func TestPumpStopsOnReadError(t *testing.T) {
	boom := errors.New("epoll failed")
	queue := make(chan []byte, 1)
	var st Stats

	err := pump(&sliceSource{records: [][]byte{record("a")}, err: boom}, queue, &st)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want %v", err, boom)
	}
	if _, open := <-queue; !open {
		t.Fatal("queued record lost")
	}
	if _, open := <-queue; open {
		t.Fatal("queue must be closed after a read error")
	}
}

func TestWriteFullCountsBadRecordsAndKeepsGoing(t *testing.T) {
	bad := record("bad")
	bad[0] = 9 //schema version
	queue := make(chan []byte, 3)
	queue <- record("a")
	queue <- bad
	queue <- []byte{1, 2, 3}
	close(queue)

	out := &memSink{}
	var st Stats
	writeFull(queue, out, fixedClock, &st, silent)

	if len(out.lines) != 1 || st.Written.Load() != 1 || st.DecodeErrors.Load() != 2 {
		t.Fatalf("lines=%d written=%d decode_errors=%d", len(out.lines), st.Written.Load(), st.DecodeErrors.Load())
	}
}

func TestWriteFullCountsWriteErrors(t *testing.T) {
	queue := make(chan []byte, 2)
	queue <- record("a")
	queue <- record("b")
	close(queue)

	var st Stats
	writeFull(queue, &memSink{err: errors.New("disk full")}, fixedClock, &st, silent)

	if st.WriteErrors.Load() != 2 || st.Written.Load() != 0 {
		t.Fatalf("write_errors=%d written=%d", st.WriteErrors.Load(), st.Written.Load())
	}
}

func TestThrottledLogSuppressesBursts(t *testing.T) {
	var buf bytes.Buffer
	restore := captureLog(&buf)
	defer restore()

	now := time.Unix(100, 0)
	logf := newThrottledLog(10*time.Second, func() time.Time { return now })
	logf("first")
	logf("second")
	logf("third")
	now = now.Add(11 * time.Second)
	logf("fourth")

	got := buf.String()
	for _, want := range []string{"first", "2 similar messages suppressed", "fourth"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log %q must contain %q", got, want)
		}
	}
	if strings.Contains(got, "second") || strings.Contains(got, "third") {
		t.Fatalf("burst not suppressed: %q", got)
	}
}
