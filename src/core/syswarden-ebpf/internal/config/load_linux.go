//go:build linux

package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Load reads path with the same rules as the CLI configuration files
// (syswarden-cli/config/secure_path.go). A missing file yields the defaults
// and found = false.
func Load(path string) (cfg Config, found bool, err error) {
	content, err := readSecureFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Defaults(), false, nil
	}
	if err != nil {
		return Defaults(), false, err
	}
	cfg, err = Parse(content)
	return cfg, true, err
}

// readSecureFile refuses links, files writable or readable beyond owner and
// group (mode & 0037), files not owned by us, and a parent writable by others.
func readSecureFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("configuration path %q must be absolute and canonical", path)
	}

	dir, name := filepath.Split(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("configuration directory %s is not a directory or is writable by others", dir)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := checkFile(before, path); err != nil {
		return nil, err
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("configuration file %s changed while opening", path)
	}

	content, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxFileBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, path, maxFileBytes)
	}

	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("configuration file %s changed while reading", path)
	}
	return content, nil
}

func checkFile(info os.FileInfo, path string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("configuration file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0037 != 0 {
		return fmt.Errorf("configuration file %s has unsafe mode %#o", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("configuration file %s must be owned by uid %d", path, os.Geteuid())
	}
	return nil
}
