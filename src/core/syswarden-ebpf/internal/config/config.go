// Package config loads and validates /etc/syswarden/ebpf.toml. Unknown keys
// are refused: a typo in a filter must not silently widen a blind spot.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

const (
	SchemaVersion = 1
	DefaultPath   = "/etc/syswarden/ebpf.toml"

	maxFileBytes   = 64 * 1024
	maxIgnoreRules = 64
	maxCommLen     = 15 // TASK_COMM_LEN - 1
	minLogBytes    = 64 * 1024
	maxLogBytes    = 1024 * 1024 * 1024
	maxGenerations = 16
	maxWindowSecs  = 3600
)

// Mode selects what reaches ebpf.json.
type Mode string

const (
	ModeSummary Mode = "summary" // one line per connection, repeats aggregated
	ModeFull    Mode = "full"    // every event, for debugging
)

var ErrInvalid = errors.New("invalid ebpf configuration")

// protectedPrefixes can never be ignored: cloud metadata endpoints are a
// classic credential theft target.
var protectedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::ffff:169.254.0.0/112"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

type Config struct {
	SchemaVersion int          `toml:"schema_version"`
	Mode          Mode         `toml:"mode"`
	Output        Output       `toml:"output"`
	Filter        Filter       `toml:"filter"`
	Summary       Summary      `toml:"summary"`
	Ignore        []IgnoreRule `toml:"ignore"`
}

type Output struct {
	Path        string `toml:"path"`
	MaxBytes    int64  `toml:"max_bytes"`
	Generations int    `toml:"generations"`
}

// Filter holds the kernel side filters, written to the ebpf_config map.
type Filter struct {
	IgnoreLoopback bool `toml:"ignore_loopback"`
}

type Summary struct {
	WindowSeconds int `toml:"window_seconds"`
}

// IgnoreRule drops matching connections in userspace. Every set field must
// match. A rule needs dst, or comm with dport: comm alone is spoofable and a
// port alone is where attackers hide (443, 53).
type IgnoreRule struct {
	Comm  string       `toml:"comm"`
	Dst   netip.Prefix `toml:"dst"`
	DPort uint16       `toml:"dport"`
	Proto string       `toml:"proto"` // "", "tcp" or "udp"
}

// Defaults is the configuration used when no file exists. config/ebpf.toml
// spells the same values out and a test keeps both in sync.
func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Mode:          ModeSummary,
		Output: Output{
			Path:        "/var/log/syswarden/ebpf.json",
			MaxBytes:    16 * 1024 * 1024,
			Generations: 3,
		},
		Filter:  Filter{IgnoreLoopback: true},
		Summary: Summary{WindowSeconds: 60},
	}
}

// Parse decodes content over the defaults, then validates the result.
func Parse(content []byte) (Config, error) {
	cfg := Defaults()
	if len(content) > maxFileBytes {
		return cfg, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalid, maxFileBytes)
	}

	decoder := toml.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate reports every problem at once, so one restart fixes them all.
func (c Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if c.SchemaVersion != SchemaVersion {
		fail("schema_version %d is not supported, want %d", c.SchemaVersion, SchemaVersion)
	}
	if c.Mode != ModeSummary && c.Mode != ModeFull {
		fail("mode %q must be %q or %q", c.Mode, ModeSummary, ModeFull)
	}

	p := c.Output.Path
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		fail("output.path %q must be absolute and canonical", p)
	}
	if c.Output.MaxBytes < minLogBytes || c.Output.MaxBytes > maxLogBytes {
		fail("output.max_bytes %d must be in [%d, %d]", c.Output.MaxBytes, minLogBytes, maxLogBytes)
	}
	if c.Output.Generations < 1 || c.Output.Generations > maxGenerations {
		fail("output.generations %d must be in [1, %d]", c.Output.Generations, maxGenerations)
	}
	if c.Summary.WindowSeconds < 1 || c.Summary.WindowSeconds > maxWindowSecs {
		fail("summary.window_seconds %d must be in [1, %d]", c.Summary.WindowSeconds, maxWindowSecs)
	}

	if len(c.Ignore) > maxIgnoreRules {
		fail("ignore has %d rules, at most %d allowed", len(c.Ignore), maxIgnoreRules)
	}
	for i, rule := range c.Ignore {
		if err := rule.validate(); err != nil {
			fail("ignore[%d]: %v", i, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(errs...))
	}
	return nil
}

func (r IgnoreRule) validate() error {
	hasDst := r.Dst.IsValid()

	if !hasDst && (r.Comm == "" || r.DPort == 0) {
		return errors.New("needs dst, or comm with dport (port or comm alone is refused)")
	}
	if r.Comm != "" && (len(r.Comm) > maxCommLen || strings.IndexFunc(r.Comm, notCommRune) >= 0) {
		return fmt.Errorf("comm %q must be 1 to %d printable characters", r.Comm, maxCommLen)
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("proto %q must be tcp or udp", r.Proto)
	}
	if !hasDst {
		return nil
	}

	if r.Dst.Bits() == 0 {
		return fmt.Errorf("dst %s covers every address", r.Dst)
	}
	if r.Dst != r.Dst.Masked() {
		return fmt.Errorf("dst %s has host bits set, use %s", r.Dst, r.Dst.Masked())
	}
	for _, protected := range protectedPrefixes {
		if r.Dst.Overlaps(protected) {
			return fmt.Errorf("dst %s overlaps protected %s (cloud metadata)", r.Dst, protected)
		}
	}
	return nil
}

func notCommRune(r rune) bool {
	return r > unicode.MaxASCII || !unicode.IsPrint(r)
}

// Target is what an ignore rule is matched against.
type Target struct {
	Comm         string
	CommReliable bool       // a comm seen in softirq is random, never matched
	Remote       netip.Addr // unmapped
	ServicePort  uint16     // remote port when outbound, local port when inbound
	Proto        string     // "tcp", "udp", ...
}

// Matches tells if every field set in r matches t.
func (r IgnoreRule) Matches(t Target) bool {
	if r.Comm != "" && (!t.CommReliable || r.Comm != t.Comm) {
		return false
	}
	if r.Dst.IsValid() && !r.Dst.Contains(t.Remote) {
		return false
	}
	if r.DPort != 0 && r.DPort != t.ServicePort {
		return false
	}
	return r.Proto == "" || r.Proto == t.Proto
}

// Ignored tells if any rule of c matches t.
func (c Config) Ignored(t Target) bool {
	for _, r := range c.Ignore {
		if r.Matches(t) {
			return true
		}
	}
	return false
}
