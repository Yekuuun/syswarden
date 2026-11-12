package event

import (
	"net/netip"
	"time"
)

// Flow outcomes.
const (
	OutcomeEstablished = "established" // TCP handshake done
	OutcomeFailed      = "failed"      // TCP connect closed from SYN_SENT
	OutcomeConnect     = "connect"     // connect() without handshake (UDP, ...)
)

// Flow directions.
const (
	DirectionOutbound = "outbound"
	DirectionInbound  = "inbound"
	DirectionUnknown  = "unknown"
)

const tcpSynSent = 2

// Process identifies the task behind a flow.
type Process struct {
	PID, TGID, UID uint32
	Comm           [16]byte
	Attribution    Attribution
}

// Process returns the task recorded in the header.
func (h Header) Process() Process {
	return Process{PID: h.PID, TGID: h.TGID, UID: h.UID, Comm: h.Comm, Attribution: h.Attribution}
}

// CommString returns the comm cut at its first NUL.
func (p Process) CommString() string { return commString(p.Comm) }

// Flow is a summary mode line. type "flow" is written on the first occurrence
// of a flow key in a window, "flow_repeat" at the end of the window when the
// key was seen again (count includes the first occurrence).
type Flow struct {
	SchemaVersion int    `json:"schema_version"`
	Type          string `json:"type"`
	Timestamp     string `json:"timestamp"`
	Outcome       string `json:"outcome"`
	Direction     string `json:"direction"`
	Family        string `json:"family"`
	Proto         string `json:"proto"`
	Local         string `json:"local"`
	LocalPort     uint16 `json:"local_port"`
	Remote        string `json:"remote"`
	RemotePort    uint16 `json:"remote_port"`
	PID           uint32 `json:"pid"`
	TGID          uint32 `json:"tgid"`
	UID           uint32 `json:"uid"`
	Comm          string `json:"comm"`
	Attribution   string `json:"attribution"`
	SockKey       string `json:"sock_key,omitempty"`
	Count         uint64 `json:"count,omitempty"`
	FirstSeen     string `json:"first_seen,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
}

// ConnFlow builds the flow of a tracepoint event. Flows are only built on
// handshake transitions, where the kernel knows the direction.
func ConnFlow(c *Conn, p Process, outcome string, wall time.Time) Flow {
	f := newFlow(p, outcome, wall)
	switch c.Direction {
	case DirActive:
		f.Direction = DirectionOutbound
	case DirPassive:
		f.Direction = DirectionInbound
	default:
		f.Direction = DirectionUnknown
	}
	f.Family, f.Proto = familyName(c.Family), protoName(c.Proto)
	f.Local, f.LocalPort = addrString(c.Family, c.SAddr), c.SPort
	f.Remote, f.RemotePort = addrString(c.Family, c.DAddr), c.DPort
	f.SockKey = sockKey(c.SockKey)
	return f
}

// SockFlow builds the outbound flow of a connect() that has no handshake.
func SockFlow(s *Sock, p Process, wall time.Time) Flow {
	f := newFlow(p, OutcomeConnect, wall)
	f.Direction = DirectionOutbound
	f.Family, f.Proto = familyName(s.Family), protoName(s.Proto)
	f.Local, f.LocalPort = addrString(s.Family, s.SAddr), s.SPort
	f.Remote, f.RemotePort = addrString(s.Family, s.DAddr), s.DPort
	f.SockKey = sockKey(s.SockKey)
	return f
}

// Repeat turns the first occurrence into its end of window summary.
func (f Flow) Repeat(count uint64, first, last, wall time.Time) Flow {
	f.Type = "flow_repeat"
	f.Timestamp = wall.UTC().Format(time.RFC3339Nano)
	f.SockKey = "" //differs on every occurrence
	f.Count = count
	f.FirstSeen = first.UTC().Format(time.RFC3339Nano)
	f.LastSeen = last.UTC().Format(time.RFC3339Nano)
	return f
}

func newFlow(p Process, outcome string, wall time.Time) Flow {
	return Flow{
		SchemaVersion: SchemaVersion,
		Type:          "flow",
		Timestamp:     wall.UTC().Format(time.RFC3339Nano),
		Outcome:       outcome,
		PID:           p.PID,
		TGID:          p.TGID,
		UID:           p.UID,
		Comm:          p.CommString(),
		Attribution:   attributionName(p.Attribution),
	}
}

// IsFailedConnect tells if a close comes straight from SYN_SENT.
func (c *Conn) IsFailedConnect() bool { return c.OldState == tcpSynSent }

// LocalAddr and RemoteAddr return unmapped addresses, so IPv4 rules also match
// v4-mapped traffic of IPv6 sockets.
func (c *Conn) LocalAddr() netip.Addr  { return addr(c.Family, c.SAddr) }
func (c *Conn) RemoteAddr() netip.Addr { return addr(c.Family, c.DAddr) }
func (s *Sock) LocalAddr() netip.Addr  { return addr(s.Family, s.SAddr) }
func (s *Sock) RemoteAddr() netip.Addr { return addr(s.Family, s.DAddr) }

func addr(family uint16, raw [16]byte) netip.Addr {
	if family == familyINET {
		return netip.AddrFrom4([4]byte(raw[:4]))
	}
	return netip.AddrFrom16(raw).Unmap()
}

// ProtoName exposes the proto naming used in every line.
func ProtoName(proto uint16) string { return protoName(proto) }

// EncodeFlow returns f as one JSON line, newline included.
func EncodeFlow(f Flow) ([]byte, error) { return encodeLine(f) }
