// Package status publishes the runtime state of syswarden-ebpf to a file read
// by `syswarden-ebpf status`. It holds counters and settings, no event data.
package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	SchemaVersion = 1
	DefaultPath   = "/run/syswarden-ebpf-status.json"

	// Interval between two writes while running. A snapshot older than
	// StaleAfter means the daemon died without writing "stopped".
	Interval   = 10 * time.Second
	StaleAfter = 3 * Interval

	StateRunning = "running"
	StateStopped = "stopped"

	maxFileBytes = 64 * 1024
)

var ErrStale = errors.New("status is stale")

type Snapshot struct {
	SchemaVersion  int       `json:"schema_version"`
	State          string    `json:"state"`
	PID            int       `json:"pid"`
	StartedAt      time.Time `json:"started_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	EventSchema    int       `json:"event_schema_version"`
	Mode           string    `json:"mode"`
	Output         string    `json:"output"`
	IgnoreLoopback bool      `json:"ignore_loopback"`
	IgnoreRules    int       `json:"ignore_rules"`
	Attached       Attached  `json:"attached"`
	Kernel         Kernel    `json:"kernel"`
	Userspace      Userspace `json:"userspace"`
	Error          string    `json:"error,omitempty"` // why the daemon stopped, when it failed
}

type Attached struct {
	Tracepoint bool   `json:"tracepoint"`
	LSM        bool   `json:"lsm"`
	LSMReason  string `json:"lsm_reason,omitempty"`
}

// Kernel counters, summed over CPUs from the drop_stats map.
type Kernel struct {
	RingbufFull uint64 `json:"ringbuf_full"`
	Filtered    uint64 `json:"filtered"`
}

type Userspace struct {
	Received     uint64 `json:"received"`
	Written      uint64 `json:"written"`
	QueueDropped uint64 `json:"queue_dropped"`
	DecodeErrors uint64 `json:"decode_errors"`
	WriteErrors  uint64 `json:"write_errors"`
	Ignored      uint64 `json:"ignored"`
	Aggregated   uint64 `json:"aggregated"`
	AggOverflow  uint64 `json:"agg_overflow"`
	Evicted      uint64 `json:"evicted"`
	Expired      uint64 `json:"expired"`
}

// Check tells if s describes a live daemon at now.
func (s Snapshot) Check(now time.Time) error {
	if s.State != StateRunning {
		if s.Error != "" {
			return fmt.Errorf("daemon %s: %s", s.State, s.Error)
		}
		return fmt.Errorf("daemon %s", s.State)
	}
	if age := now.Sub(s.UpdatedAt); age > StaleAfter {
		return fmt.Errorf("%w: last update %s ago", ErrStale, age.Truncate(time.Second))
	}
	return nil
}

// Decode parses a status file, refusing unknown fields and other versions.
func Decode(content []byte) (Snapshot, error) {
	var s Snapshot
	if len(content) > maxFileBytes {
		return s, fmt.Errorf("status exceeds %d bytes", maxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("decode status: %w", err)
	}
	if s.SchemaVersion != SchemaVersion {
		return s, fmt.Errorf("status schema_version %d is not supported", s.SchemaVersion)
	}
	return s, nil
}
