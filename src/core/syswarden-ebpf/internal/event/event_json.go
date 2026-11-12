package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// Record is the v1 JSON line written to ebpf.json. Ports are numbers, addresses
// text, sock_key a hex string (a uint64 does not fit a JSON number safely).
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	Type          string `json:"type"`
	Timestamp     string `json:"timestamp"`
	MonoNs        uint64 `json:"mono_ns"`
	PID           uint32 `json:"pid"`
	TGID          uint32 `json:"tgid"`
	UID           uint32 `json:"uid"`
	Comm          string `json:"comm"`
	Attribution   string `json:"attribution"`
	SockKey       string `json:"sock_key,omitempty"`
	Family        string `json:"family"`
	Proto         string `json:"proto"`
	SockType      string `json:"sock_type,omitempty"`
	Src           string `json:"src"`
	SPort         uint16 `json:"sport"`
	Dst           string `json:"dst,omitempty"`
	DPort         uint16 `json:"dport,omitempty"`
	OldState      string `json:"old_state,omitempty"`
	NewState      string `json:"new_state,omitempty"`
	Direction     string `json:"direction,omitempty"`
	Count         uint64 `json:"count,omitempty"`
	FirstSeen     string `json:"first_seen,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
}

// Repeat turns a record into its end of window summary (summary mode),
// type suffixed by "_repeat", count including the first occurrence.
func (r Record) Repeat(count uint64, first, last, wall time.Time) Record {
	r.Type += "_repeat"
	r.Timestamp = wall.UTC().Format(time.RFC3339Nano)
	r.SockKey = ""
	r.Count = count
	r.FirstSeen = first.UTC().Format(time.RFC3339Nano)
	r.LastSeen = last.UTC().Format(time.RFC3339Nano)
	return r
}

// NewRecord builds the JSON view of ev. wall is the wall clock time of the event,
// computed by the caller from MonoNs (the decoder stays clock free).
func NewRecord(ev Event, wall time.Time) (Record, error) {
	h := ev.Header
	rec := Record{
		SchemaVersion: int(h.SchemaVersion),
		Timestamp:     wall.UTC().Format(time.RFC3339Nano),
		MonoNs:        h.MonoNs,
		PID:           h.PID,
		TGID:          h.TGID,
		UID:           h.UID,
		Comm:          commString(h.Comm),
		Attribution:   attributionName(h.Attribution),
	}

	switch {
	case ev.Conn != nil:
		c := ev.Conn
		rec.Type = typeName(h.Type)
		rec.SockKey = sockKey(c.SockKey)
		rec.Family = familyName(c.Family)
		rec.Proto = protoName(c.Proto)
		rec.Src = addrString(c.Family, c.SAddr)
		rec.SPort = c.SPort
		rec.Dst = addrString(c.Family, c.DAddr)
		rec.DPort = c.DPort
		rec.OldState = tcpStateName(c.OldState)
		rec.NewState = tcpStateName(c.NewState)
		//kernel computes it from oldstate, only true on the open transition.
		if h.Type == TypeConnOpen {
			rec.Direction = directionName(c.Direction)
		}
	case ev.Sock != nil:
		s := ev.Sock
		rec.Type = typeName(h.Type)
		rec.SockKey = sockKey(s.SockKey)
		rec.Family = familyName(s.Family)
		rec.Proto = protoName(s.Proto)
		rec.SockType = sockTypeName(s.SockType)
		rec.Src = addrString(s.Family, s.SAddr)
		rec.SPort = s.SPort
		//bind has no remote side.
		if h.Type == TypeLSMConnect {
			rec.Dst = addrString(s.Family, s.DAddr)
			rec.DPort = s.DPort
		}
	default:
		return rec, fmt.Errorf("%w: no payload", ErrUnknownType)
	}

	return rec, nil
}

// Encode returns rec as one JSON line, newline included.
func Encode(rec Record) ([]byte, error) { return encodeLine(rec) }

func encodeLine(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func typeName(t Type) string {
	switch t {
	case TypeConnOpen:
		return "conn_open"
	case TypeConnClose:
		return "conn_close"
	case TypeLSMConnect:
		return "lsm_connect"
	case TypeLSMBind:
		return "lsm_bind"
	}
	return "unknown"
}

func attributionName(a Attribution) string {
	switch a {
	case AttributionReliable:
		return "reliable"
	case AttributionUnreliable:
		return "unreliable"
	}
	return "unknown"
}

func familyName(family uint16) string {
	if family == familyINET6 {
		return "ipv6"
	}
	return "ipv4"
}

// protoName keeps a string type for every value so consumers see one JSON type.
func protoName(proto uint16) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	case 136:
		return "udplite"
	}
	return strconv.Itoa(int(proto))
}

func sockTypeName(t uint16) string {
	switch t {
	case 1:
		return "stream"
	case 2:
		return "dgram"
	case 3:
		return "raw"
	case 5:
		return "seqpacket"
	}
	return strconv.Itoa(int(t))
}

// tcpStateName follows include/net/tcp_states.h.
func tcpStateName(state uint8) string {
	names := [...]string{
		1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
		7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
	}
	if int(state) < len(names) && names[state] != "" {
		return names[state]
	}
	return strconv.Itoa(int(state))
}

func directionName(d uint8) string {
	if d == 0 {
		return "active"
	}
	return "passive"
}

func sockKey(key uint64) string {
	return "0x" + strconv.FormatUint(key, 16)
}

func addrString(family uint16, raw [16]byte) string {
	if family == familyINET {
		return netip.AddrFrom4([4]byte(raw[:4])).String()
	}
	return netip.AddrFrom16(raw).String()
}

// commString cuts at the first NUL; invalid UTF-8 is replaced by json.Marshal.
func commString(comm [16]byte) string {
	if i := bytes.IndexByte(comm[:], 0); i >= 0 {
		return string(comm[:i])
	}
	return string(comm[:])
}
