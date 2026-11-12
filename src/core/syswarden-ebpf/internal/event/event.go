// Package event decodes the ringbuf records of the syswarden BPF programs.
// The layouts mirror bpf/data/bpf_events.h, frozen by its static asserts.
package event

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Schema v1 layout, see bpf/data/bpf_events.h.
const (
	SchemaVersion = 1

	HeaderSize    = 48
	PayloadSize   = 56
	RecordSize    = HeaderSize + PayloadSize
	payloadOffset = HeaderSize
)

// Type is the hdr.type of a record (EVENT_* in C).
type Type uint16

const (
	TypeConnOpen   Type = 1
	TypeConnClose  Type = 2
	TypeLSMConnect Type = 3
	TypeLSMBind    Type = 4
)

// Attribution tells if pid / comm really belong to the task behind the event (ATTR_* in C).
type Attribution uint8

const (
	AttributionReliable   Attribution = 1
	AttributionUnreliable Attribution = 2
)

// Direction of a conn event (DIR_* in C). Only known on the handshake
// transitions: a close from ESTABLISHED or FIN_WAIT is DirUnknown.
type Direction uint8

const (
	DirUnknown Direction = 0
	DirActive  Direction = 1
	DirPassive Direction = 2
)

// Address families, AF_INET_ / AF_INET6_ in C.
const (
	familyINET  = 2
	familyINET6 = 10
)

var (
	ErrRecordSize    = errors.New("record size mismatch")
	ErrSchemaVersion = errors.New("unsupported schema version")
	ErrUnknownType   = errors.New("unknown event type")
	ErrUnknownFamily = errors.New("unknown address family")
)

// Header mirrors event_hdr. Byte order is the host one, as written by the kernel.
type Header struct {
	SchemaVersion uint16
	Type          Type
	Size          uint32
	MonoNs        uint64 // bpf_ktime_get_ns, CLOCK_MONOTONIC
	PID           uint32
	TGID          uint32
	UID           uint32
	Comm          [16]byte
	Attribution   Attribution
	_             [3]byte
}

// Conn mirrors conn_event (tracepoint inet_sock_set_state).
type Conn struct {
	SockKey   uint64
	Family    uint16
	Proto     uint16
	SPort     uint16 // host order
	DPort     uint16 // host order
	SAddr     [16]byte
	DAddr     [16]byte
	OldState  uint8
	NewState  uint8
	Direction Direction
	_         [5]byte
}

// Sock mirrors sock_event (LSM socket_connect / socket_bind).
type Sock struct {
	SockKey  uint64
	Family   uint16
	Proto    uint16
	SockType uint16
	SPort    uint16 // host order
	DPort    uint16 // host order
	SAddr    [16]byte
	DAddr    [16]byte
	_        [6]byte
}

// Event is one decoded record: Conn is set for conn types, Sock for LSM types.
type Event struct {
	Header Header
	Conn   *Conn
	Sock   *Sock
}

// Decode parses one ringbuf record. It never trusts hdr.size nor hdr.type blindly.
func Decode(record []byte) (Event, error) {
	var ev Event

	if len(record) != RecordSize {
		return ev, fmt.Errorf("%w: got %d bytes, want %d", ErrRecordSize, len(record), RecordSize)
	}

	if _, err := binary.Decode(record[:HeaderSize], binary.NativeEndian, &ev.Header); err != nil {
		return ev, fmt.Errorf("decode header: %w", err)
	}

	if ev.Header.SchemaVersion != SchemaVersion {
		return ev, fmt.Errorf("%w: %d", ErrSchemaVersion, ev.Header.SchemaVersion)
	}

	if ev.Header.Size != RecordSize {
		return ev, fmt.Errorf("%w: header announces %d bytes", ErrRecordSize, ev.Header.Size)
	}

	payload := record[payloadOffset:]

	switch ev.Header.Type {
	case TypeConnOpen, TypeConnClose:
		ev.Conn = new(Conn)
		if _, err := binary.Decode(payload, binary.NativeEndian, ev.Conn); err != nil {
			return ev, fmt.Errorf("decode conn payload: %w", err)
		}
		return ev, checkFamily(ev.Conn.Family)
	case TypeLSMConnect, TypeLSMBind:
		ev.Sock = new(Sock)
		if _, err := binary.Decode(payload, binary.NativeEndian, ev.Sock); err != nil {
			return ev, fmt.Errorf("decode sock payload: %w", err)
		}
		return ev, checkFamily(ev.Sock.Family)
	default:
		return ev, fmt.Errorf("%w: %d", ErrUnknownType, ev.Header.Type)
	}
}

func checkFamily(family uint16) error {
	if family != familyINET && family != familyINET6 {
		return fmt.Errorf("%w: %d", ErrUnknownFamily, family)
	}
	return nil
}
