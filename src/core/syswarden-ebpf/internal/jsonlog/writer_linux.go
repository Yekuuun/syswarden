//go:build linux

// Package jsonlog writes the ebpf.json JSONL log with bounded size-based
// rotation. File handling mirrors the core telemetry logger (logger.go):
// exclusive 0600 creation, no symlink following, identity checked writes.
package jsonlog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

const (
	logMode        = 0600
	dirMode        = 0750
	maxGenerations = 16
)

var (
	ErrInvalidOptions    = errors.New("invalid output options")
	ErrRecordTooLarge    = errors.New("record exceeds the rotation limit")
	ErrIncompleteRecord  = errors.New("record must be one newline terminated line")
	ErrClosed            = errors.New("writer is closed")
	errUnsafeActiveLog   = errors.New("active log is not a single-link regular file")
	errActiveLogReplaced = errors.New("active log changed while opening")
)

// Options bounds the disk usage to MaxBytes * (Generations + 1).
type Options struct {
	Path        string // absolute, canonical
	MaxBytes    int64  // per file
	Generations int    // rotated files kept as Path.1 .. Path.N
}

// Writer appends complete JSONL records. Safe for concurrent use.
type Writer struct {
	mu     sync.Mutex
	opts   Options
	file   *os.File // nil after a failed reopen, retried on next Write
	size   int64
	closed bool
}

func (o Options) validate() error {
	if !filepath.IsAbs(o.Path) || filepath.Clean(o.Path) != o.Path || filepath.Base(o.Path) == "/" {
		return fmt.Errorf("%w: path %q must be absolute and canonical", ErrInvalidOptions, o.Path)
	}
	if o.MaxBytes <= 0 {
		return fmt.Errorf("%w: max bytes must be positive", ErrInvalidOptions)
	}
	if o.Generations < 1 || o.Generations > maxGenerations {
		return fmt.Errorf("%w: generations must be in [1, %d]", ErrInvalidOptions, maxGenerations)
	}
	return nil
}

// Open opens or creates the active log. An existing log is appended to.
func Open(opts Options) (*Writer, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), dirMode); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	w := &Writer{opts: opts}
	if err := w.openActiveLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

// Write appends one record, rotating first when it would cross MaxBytes.
// A record is never split across two files.
func (w *Writer) Write(record []byte) error {
	n := int64(len(record))
	if n == 0 || record[n-1] != '\n' {
		return ErrIncompleteRecord
	}
	if n > w.opts.MaxBytes {
		return fmt.Errorf("%w: record=%d limit=%d", ErrRecordTooLarge, n, w.opts.MaxBytes)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrClosed
	}

	//moved or deleted from outside (manual cleanup, logrotate): start a fresh file.
	if w.file != nil && !w.stillActiveLocked() {
		_ = w.file.Close()
		w.file = nil
	}
	if w.file == nil {
		if err := w.openActiveLocked(); err != nil {
			return err
		}
	}

	if w.size > 0 && w.size+n > w.opts.MaxBytes {
		if err := w.rotateLocked(); err != nil {
			return fmt.Errorf("rotate %s: %w", w.opts.Path, err)
		}
	}

	written, err := w.file.Write(record)
	w.size += int64(written)
	if err != nil {
		return err
	}
	if written != len(record) {
		return io.ErrShortWrite
	}
	return nil
}

// Close syncs and closes the active log. Calling it twice is safe.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.closed = true
	if w.file == nil {
		return nil
	}
	syncErr := w.file.Sync()
	closeErr := w.file.Close()
	w.file = nil
	return errors.Join(syncErr, closeErr)
}

func (w *Writer) openActiveLocked() error {
	file, err := reopenLog(w.opts.Path)
	if errors.Is(err, os.ErrNotExist) {
		file, err = createLog(w.opts.Path)
		if err == nil {
			err = syncDir(w.opts.Path)
		}
	}
	if err != nil {
		if file != nil {
			_ = file.Close()
		}
		return fmt.Errorf("open %s: %w", w.opts.Path, err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect %s: %w", w.opts.Path, err)
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *Writer) stillActiveLocked() bool {
	opened, err := w.file.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(w.opts.Path)
	if err != nil {
		return false
	}
	return current.Mode().IsRegular() && os.SameFile(opened, current)
}

// rotateLocked shifts Path.i to Path.i+1, drops the oldest, then moves the
// active log to Path.1. If the new active log cannot be created, the old one
// is put back so writes go on.
func (w *Writer) rotateLocked() error {
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync active log: %w", err)
	}
	if err := w.file.Close(); err != nil {
		w.file = nil
		return errors.Join(fmt.Errorf("close active log: %w", err), w.openActiveLocked())
	}
	w.file = nil

	for i := w.opts.Generations; i >= 1; i-- {
		from := generationPath(w.opts.Path, i)
		if i == w.opts.Generations {
			if err := os.Remove(from); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.Join(fmt.Errorf("drop oldest generation: %w", err), w.openActiveLocked())
			}
			continue
		}
		if err := os.Rename(from, generationPath(w.opts.Path, i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("shift generation %d: %w", i, err), w.openActiveLocked())
		}
	}

	rotated := generationPath(w.opts.Path, 1)
	if err := os.Rename(w.opts.Path, rotated); err != nil {
		return errors.Join(fmt.Errorf("rename active log: %w", err), w.openActiveLocked())
	}

	file, err := createLog(w.opts.Path)
	if err != nil {
		rollbackErr := os.Rename(rotated, w.opts.Path)
		return errors.Join(fmt.Errorf("create active log: %w", err), rollbackErr, w.openActiveLocked())
	}
	w.file = file
	w.size = 0
	return syncDir(w.opts.Path)
}

func generationPath(path string, i int) string {
	return path + "." + strconv.Itoa(i)
}

func createLog(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, logMode) // #nosec G304 -- configured ebpf log path
	if err != nil {
		return nil, err
	}
	//umask may have cleared bits, the mode is checked by the core follower.
	if err := file.Chmod(logMode); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("set log mode: %w", err)
	}
	return file, nil
}

// reopenLog opens an existing log without following links and refuses a file
// the core follower would reject (other type, hard links, group/other write).
func reopenLog(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !singleLinkRegular(before) {
		return nil, errUnsafeActiveLog
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- regular leaf, identity checked below
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !singleLinkRegular(opened) || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errActiveLogReplaced
	}
	if opened.Mode().Perm() != logMode {
		if err := file.Chmod(logMode); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("restore log mode: %w", err)
		}
	}
	return file, nil
}

func singleLinkRegular(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && ok && st.Nlink == 1
}

func syncDir(path string) error {
	dir, err := os.Open(filepath.Dir(path)) // #nosec G304 -- directory of the configured ebpf log
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}
