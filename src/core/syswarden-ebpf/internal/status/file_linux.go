//go:build linux

package status

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const fileMode = 0640

// Write replaces path atomically: readers see the old or the new snapshot,
// never a partial one.
func Write(path string, s Snapshot) error {
	content, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	committed = true
	return nil
}

// Read loads path without following links.
func Read(path string) (Snapshot, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- status path
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("%s is not a regular file", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	return Decode(content)
}
