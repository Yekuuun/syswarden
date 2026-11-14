//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "ebpf.toml")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, found, err := Load(filepath.Join(privateDir(t), "ebpf.toml"))
	if err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if cfg.Mode != ModeSummary || !cfg.Filter.IgnoreLoopback {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestLoadAcceptsPrivateFile(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0640, 0400} {
		path := writeConfig(t, privateDir(t), `mode = "full"`, mode)
		cfg, found, err := Load(path)
		if err != nil || !found || cfg.Mode != ModeFull {
			t.Fatalf("mode %o: found=%v err=%v cfg=%+v", mode, found, err, cfg)
		}
	}
}

func TestLoadRefusesUnsafeFiles(t *testing.T) {
	t.Run("world readable", func(t *testing.T) {
		path := writeConfig(t, privateDir(t), "", 0644)
		if _, _, err := Load(path); err == nil {
			t.Fatal("0644 must be refused")
		}
	})
	t.Run("group writable", func(t *testing.T) {
		path := writeConfig(t, privateDir(t), "", 0660)
		if _, _, err := Load(path); err == nil {
			t.Fatal("0660 must be refused")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := privateDir(t)
		target := writeConfig(t, dir, "", 0600)
		link := filepath.Join(dir, "link.toml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(link); err == nil {
			t.Fatal("symlink must be refused")
		}
	})
	t.Run("open directory", func(t *testing.T) {
		dir := privateDir(t)
		path := writeConfig(t, dir, "", 0600)
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(path); err == nil {
			t.Fatal("world writable directory must be refused")
		}
	})
	t.Run("relative path", func(t *testing.T) {
		if _, _, err := Load("ebpf.toml"); err == nil {
			t.Fatal("relative path must be refused")
		}
	})
	t.Run("invalid content", func(t *testing.T) {
		path := writeConfig(t, privateDir(t), "[[ignore]]\ndport = 443", 0600)
		if _, found, err := Load(path); err == nil || !found {
			t.Fatalf("found=%v err=%v", found, err)
		}
	})
}
