//go:build linux

package status

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syswarden-ebpf-status.json")
	want := running()
	want.Mode, want.Output = "summary", "/var/log/syswarden/ebpf.json"
	want.Attached = Attached{Tracepoint: true, LSMReason: "bpf is not in the active LSM list"}
	want.Kernel = Kernel{RingbufFull: 3, Filtered: 1200}
	want.Userspace = Userspace{Received: 10, Written: 8, Ignored: 2}

	for range 2 { //second write replaces the first
		if err := Write(path, want); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != fileMode {
		t.Fatalf("mode %o, want %o", info.Mode().Perm(), fileMode)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestReadRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := Write(target, running()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link); err == nil {
		t.Fatal("symlink must be refused")
	}
}
