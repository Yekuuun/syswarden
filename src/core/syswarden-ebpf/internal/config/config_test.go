package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestExampleFileMatchesDefaults(t *testing.T) {
	content, err := os.ReadFile("../../config/ebpf.toml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(content)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, Defaults()) {
		t.Fatalf("config/ebpf.toml drifted from Defaults()\n got: %+v\nwant: %+v", cfg, Defaults())
	}
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseOverlaysDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
mode = "full"

[output]
generations = 5

[filter]
ignore_loopback = false

[[ignore]]
dst = "10.0.0.12/32"
dport = 62026

[[ignore]]
comm = "systemd-resolve"
dport = 53
proto = "udp"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	want.Mode = ModeFull
	want.Output.Generations = 5
	want.Filter.IgnoreLoopback = false
	want.Ignore = []IgnoreRule{
		{Dst: netip.MustParsePrefix("10.0.0.12/32"), DPort: 62026},
		{Comm: "systemd-resolve", DPort: 53, Proto: "udp"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("got %+v\nwant %+v", cfg, want)
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":    "verbose = true",
		"unknown nested": "[filter]\nignore_lo = true",
		"wrong type":     "mode = 1",
		"bad prefix":     "[[ignore]]\ndst = \"10.0.0.300/32\"",
		"syntax":         "mode = ",
		"too large":      "# " + strings.Repeat("x", maxFileBytes),
	}
	for name, content := range cases {
		if _, err := Parse([]byte(content)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestValidateRejectsOutOfRangeValues(t *testing.T) {
	cases := map[string]func(*Config){
		"schema":         func(c *Config) { c.SchemaVersion = 2 },
		"mode":           func(c *Config) { c.Mode = "verbose" },
		"relative path":  func(c *Config) { c.Output.Path = "ebpf.json" },
		"unclean path":   func(c *Config) { c.Output.Path = "/var/log/../log/ebpf.json" },
		"root path":      func(c *Config) { c.Output.Path = "/" },
		"small file":     func(c *Config) { c.Output.MaxBytes = minLogBytes - 1 },
		"huge file":      func(c *Config) { c.Output.MaxBytes = maxLogBytes + 1 },
		"no generation":  func(c *Config) { c.Output.Generations = 0 },
		"generations":    func(c *Config) { c.Output.Generations = maxGenerations + 1 },
		"no window":      func(c *Config) { c.Summary.WindowSeconds = 0 },
		"long window":    func(c *Config) { c.Summary.WindowSeconds = maxWindowSecs + 1 },
		"too many rules": func(c *Config) { c.Ignore = make([]IgnoreRule, maxIgnoreRules+1) },
	}
	for name, mutate := range cases {
		cfg := Defaults()
		mutate(&cfg)
		if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestIgnoreRules(t *testing.T) {
	prefix := netip.MustParsePrefix
	cases := []struct {
		name string
		rule IgnoreRule
		ok   bool
	}{
		{"dst only", IgnoreRule{Dst: prefix("10.0.0.0/8")}, true},
		{"dst and port", IgnoreRule{Dst: prefix("2001:db8::/32"), DPort: 443}, true},
		{"comm and port", IgnoreRule{Comm: "chronyd", DPort: 123, Proto: "udp"}, true},
		{"empty", IgnoreRule{}, false},
		{"port alone", IgnoreRule{DPort: 443}, false},
		{"comm alone", IgnoreRule{Comm: "curl"}, false},
		{"proto alone", IgnoreRule{Proto: "tcp"}, false},
		{"every v4", IgnoreRule{Dst: prefix("0.0.0.0/0")}, false},
		{"every v6", IgnoreRule{Dst: prefix("::/0")}, false},
		{"host bits", IgnoreRule{Dst: prefix("10.0.0.1/8")}, false},
		{"metadata host", IgnoreRule{Dst: prefix("169.254.169.254/32")}, false},
		{"metadata range", IgnoreRule{Dst: prefix("169.254.0.0/16")}, false},
		{"covers metadata", IgnoreRule{Dst: prefix("128.0.0.0/1")}, false},
		{"mapped metadata", IgnoreRule{Dst: prefix("::ffff:169.254.169.254/128")}, false},
		{"aws v6 metadata", IgnoreRule{Dst: prefix("fd00:ec2::/64")}, false},
		{"bad proto", IgnoreRule{Dst: prefix("10.0.0.0/8"), Proto: "icmp"}, false},
		{"long comm", IgnoreRule{Comm: strings.Repeat("a", maxCommLen+1), DPort: 1}, false},
		{"control comm", IgnoreRule{Comm: "bad\nname", DPort: 1}, false},
		{"non ascii comm", IgnoreRule{Comm: "nginxé", DPort: 1}, false},
	}
	for _, tc := range cases {
		if err := tc.rule.validate(); (err == nil) != tc.ok {
			t.Fatalf("%s: got %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = "verbose"
	cfg.Output.Generations = 0
	cfg.Ignore = []IgnoreRule{{DPort: 443}}

	err := cfg.Validate()
	for _, want := range []string{"mode", "output.generations", "ignore[0]"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error %v must mention %s", err, want)
		}
	}
}

func ExampleParse() {
	_, err := Parse([]byte("[[ignore]]\ndport = 443"))
	fmt.Println(err)
	// Output: invalid ebpf configuration: ignore[0]: needs dst, or comm with dport (port or comm alone is refused)
}

func TestIgnoreRuleMatches(t *testing.T) {
	prefix, addr := netip.MustParsePrefix, netip.MustParseAddr
	resolver := IgnoreRule{Comm: "systemd-resolve", DPort: 53, Proto: "udp"}
	peer := IgnoreRule{Dst: prefix("10.0.0.12/32"), DPort: 62026}

	cases := []struct {
		name   string
		rule   IgnoreRule
		target Target
		want   bool
	}{
		{"comm port proto", resolver, Target{Comm: "systemd-resolve", CommReliable: true, Remote: addr("1.1.1.1"), ServicePort: 53, Proto: "udp"}, true},
		{"unreliable comm", resolver, Target{Comm: "systemd-resolve", Remote: addr("1.1.1.1"), ServicePort: 53, Proto: "udp"}, false},
		{"other comm", resolver, Target{Comm: "curl", CommReliable: true, ServicePort: 53, Proto: "udp"}, false},
		{"other proto", resolver, Target{Comm: "systemd-resolve", CommReliable: true, ServicePort: 53, Proto: "tcp"}, false},
		{"peer any comm", peer, Target{Comm: "x", Remote: addr("10.0.0.12"), ServicePort: 62026, Proto: "tcp"}, true},
		{"peer other host", peer, Target{Remote: addr("10.0.0.13"), ServicePort: 62026, Proto: "tcp"}, false},
		{"peer other port", peer, Target{Remote: addr("10.0.0.12"), ServicePort: 22, Proto: "tcp"}, false},
		{"v4 rule v6 addr", peer, Target{Remote: addr("2001:db8::1"), ServicePort: 62026}, false},
	}
	for _, tc := range cases {
		if got := tc.rule.Matches(tc.target); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	cfg := Defaults()
	cfg.Ignore = []IgnoreRule{resolver, peer}
	if !cfg.Ignored(Target{Remote: addr("10.0.0.12"), ServicePort: 62026}) || cfg.Ignored(Target{Remote: addr("10.0.0.12")}) {
		t.Fatal("Ignored must match any rule and only those")
	}
}
