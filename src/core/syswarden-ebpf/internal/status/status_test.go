package status

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC)

func running() Snapshot {
	return Snapshot{SchemaVersion: SchemaVersion, State: StateRunning, PID: 42, StartedAt: now.Add(-time.Hour), UpdatedAt: now}
}

func TestCheck(t *testing.T) {
	stopped := running()
	stopped.State, stopped.Error = StateStopped, "load BPF objects: operation not permitted"

	cases := map[string]struct {
		snap Snapshot
		ok   bool
		has  string
	}{
		"fresh":        {running(), true, ""},
		"just in time": {func() Snapshot { s := running(); s.UpdatedAt = now.Add(-StaleAfter); return s }(), true, ""},
		"stale":        {func() Snapshot { s := running(); s.UpdatedAt = now.Add(-StaleAfter - time.Second); return s }(), false, "stale"},
		"stopped":      {stopped, false, "operation not permitted"},
	}
	for name, tc := range cases {
		err := tc.snap.Check(now)
		if (err == nil) != tc.ok || (tc.has != "" && !strings.Contains(err.Error(), tc.has)) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if err := cases["stale"].snap.Check(now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale must wrap ErrStale, got %v", err)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field": `{"schema_version":1,"state":"running","extra":true}`,
		"version":       `{"schema_version":2,"state":"running"}`,
		"not json":      `running`,
		"too large":     `{"schema_version":1,"output":"` + strings.Repeat("x", maxFileBytes) + `"}`,
	}
	for name, content := range cases {
		if _, err := Decode([]byte(content)); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
	}
}
