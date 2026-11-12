//go:build linux

package pipeline

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/status"
)

func TestPublisherReportsFailedStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	var st Stats
	st.Received.Add(5)
	st.Ignored.Add(2)

	pb := newPublisher(path, config.Defaults(), &st)
	pb.publish(status.StateStopped, errors.New("kernel BTF is required"))

	snap, err := status.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != status.StateStopped || snap.Error != "kernel BTF is required" || snap.Attached.Tracepoint {
		t.Fatalf("unexpected snapshot %+v", snap)
	}
	if snap.Mode != "summary" || snap.Userspace.Received != 5 || snap.Userspace.Ignored != 2 {
		t.Fatalf("settings or counters missing: %+v", snap)
	}
	if err := snap.Check(time.Now()); err == nil {
		t.Fatal("a stopped daemon must fail the check")
	}
}

func TestPublisherEvery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	pb := newPublisher(path, config.Defaults(), &Stats{})
	stop := pb.every(5 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	stop()

	snap, err := status.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State != status.StateRunning {
		t.Fatalf("state %s, want running", snap.State)
	}
}
