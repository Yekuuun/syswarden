//go:build linux

package jsonlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func line(n int, fill byte) []byte {
	b := bytes.Repeat([]byte{fill}, n-1)
	return append(b, '\n')
}

func openTest(t *testing.T, maxBytes int64, generations int) (*Writer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "logs", "ebpf.json")
	w, err := Open(Options{Path: path, MaxBytes: maxBytes, Generations: generations})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, path
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustWrite(t *testing.T, w *Writer, record []byte) {
	t.Helper()
	if err := w.Write(record); err != nil {
		t.Fatal(err)
	}
}

func TestOpenCreatesPrivateLog(t *testing.T) {
	w, path := openTest(t, 64, 2)
	mustWrite(t, w, line(10, 'a'))

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != logMode {
		t.Fatalf("mode %v, want regular %o", info.Mode(), logMode)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm()&0027 != 0 {
		t.Fatalf("log directory must not be group writable nor world accessible: %v %v", dir.Mode(), err)
	}
}

func TestOpenAppendsToExistingLog(t *testing.T) {
	w, path := openTest(t, 64, 2)
	mustWrite(t, w, line(10, 'a'))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(Options{Path: path, MaxBytes: 64, Generations: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	mustWrite(t, again, line(10, 'b'))

	if got, want := read(t, path), string(line(10, 'a'))+string(line(10, 'b')); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRotationKeepsRecordsWholeAndBoundsGenerations(t *testing.T) {
	w, path := openTest(t, 25, 2)
	for _, fill := range []byte("abcdefg") {
		mustWrite(t, w, line(10, fill))
	}

	//25 bytes per file = 2 records of 10, so a, b | c, d | e, f | g.
	want := map[string]string{
		path:        string(line(10, 'g')),
		path + ".1": string(line(10, 'e')) + string(line(10, 'f')),
		path + ".2": string(line(10, 'c')) + string(line(10, 'd')),
	}
	for p, content := range want {
		if got := read(t, p); got != content {
			t.Fatalf("%s: got %q, want %q", filepath.Base(p), got, content)
		}
	}
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generation beyond the limit must not exist")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 3 {
		t.Fatalf("got %d files, want active + 2 generations", len(entries))
	}
}

func TestRecordExactlyAtLimitStartsNewFile(t *testing.T) {
	w, path := openTest(t, 20, 1)
	mustWrite(t, w, line(10, 'a'))
	mustWrite(t, w, line(10, 'b'))
	mustWrite(t, w, line(20, 'c'))

	if got := read(t, path); got != string(line(20, 'c')) {
		t.Fatalf("active: got %q", got)
	}
	if got := read(t, path+".1"); got != string(line(10, 'a'))+string(line(10, 'b')) {
		t.Fatalf("generation 1: got %q", got)
	}
}

func TestWriteRejectsInvalidRecords(t *testing.T) {
	w, path := openTest(t, 16, 1)
	cases := map[string]struct {
		record []byte
		want   error
	}{
		"empty":      {nil, ErrIncompleteRecord},
		"no newline": {[]byte("abc"), ErrIncompleteRecord},
		"over limit": {line(17, 'x'), ErrRecordTooLarge},
	}
	for name, tc := range cases {
		if err := w.Write(tc.record); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	if got := read(t, path); got != "" {
		t.Fatalf("rejected records must not be written, got %q", got)
	}
}

func TestWriteRecreatesLogRemovedFromOutside(t *testing.T) {
	w, path := openTest(t, 64, 1)
	mustWrite(t, w, line(10, 'a'))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, line(10, 'b'))

	if got := read(t, path); got != string(line(10, 'b')) {
		t.Fatalf("got %q", got)
	}
}

func TestOpenRefusesUnsafeActiveLog(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(dir, "hardlink.json")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "dir.json")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{symlink, hardlink, directory} {
		if w, err := Open(Options{Path: path, MaxBytes: 64, Generations: 1}); err == nil {
			_ = w.Close()
			t.Fatalf("%s: must be refused", filepath.Base(path))
		}
	}
}

func TestOpenRestoresPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ebpf.json")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	w, err := Open(Options{Path: path, MaxBytes: 64, Generations: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	info, _ := os.Stat(path)
	if info.Mode().Perm() != logMode {
		t.Fatalf("mode %o, want %o", info.Mode().Perm(), logMode)
	}
}

func TestOptionsValidation(t *testing.T) {
	cases := map[string]Options{
		"relative":      {Path: "ebpf.json", MaxBytes: 1, Generations: 1},
		"not canonical": {Path: "/var/log/../log/ebpf.json", MaxBytes: 1, Generations: 1},
		"root":          {Path: "/", MaxBytes: 1, Generations: 1},
		"zero size":     {Path: "/tmp/ebpf.json", MaxBytes: 0, Generations: 1},
		"no generation": {Path: "/tmp/ebpf.json", MaxBytes: 1, Generations: 0},
		"too many":      {Path: "/tmp/ebpf.json", MaxBytes: 1, Generations: maxGenerations + 1},
	}
	for name, opts := range cases {
		if _, err := Open(opts); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("%s: got %v, want ErrInvalidOptions", name, err)
		}
	}
}

func TestCloseIsIdempotentAndStopsWrites(t *testing.T) {
	w, _ := openTest(t, 64, 1)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(line(5, 'a')); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}
