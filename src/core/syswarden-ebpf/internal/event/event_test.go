package event

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Offsets copied from bpf/data/bpf_events.h, not from the Go structs, so a
// layout drift on either side breaks these tests.
const (
	offSchema = 0
	offType   = 2
	offSize   = 4
	offMono   = 8
	offPID    = 16
	offTGID   = 20
	offUID    = 24
	offComm   = 28
	offAttr   = 44

	offConnKey    = 48 + 0
	offConnFamily = 48 + 8
	offConnProto  = 48 + 10
	offConnSPort  = 48 + 12
	offConnDPort  = 48 + 14
	offConnSAddr  = 48 + 16
	offConnDAddr  = 48 + 32
	offConnOld    = 48 + 48
	offConnNew    = 48 + 49
	offConnDir    = 48 + 50

	offSockKey    = 48 + 0
	offSockFamily = 48 + 8
	offSockProto  = 48 + 10
	offSockType   = 48 + 12
	offSockSPort  = 48 + 14
	offSockDPort  = 48 + 16
	offSockSAddr  = 48 + 18
	offSockDAddr  = 48 + 34
)

var ne = binary.NativeEndian

func header(typ Type, attr Attribution, comm string) []byte {
	b := make([]byte, RecordSize)
	ne.PutUint16(b[offSchema:], SchemaVersion)
	ne.PutUint16(b[offType:], uint16(typ))
	ne.PutUint32(b[offSize:], RecordSize)
	ne.PutUint64(b[offMono:], 123456789)
	ne.PutUint32(b[offPID:], 4242)
	ne.PutUint32(b[offTGID:], 4240)
	ne.PutUint32(b[offUID:], 1000)
	copy(b[offComm:offComm+16], comm)
	b[offAttr] = uint8(attr)
	return b
}

func connV4Record(typ Type, oldState, newState, dir uint8) []byte {
	b := header(typ, AttributionUnreliable, "curl")
	ne.PutUint64(b[offConnKey:], 0xffff888012345678)
	ne.PutUint16(b[offConnFamily:], familyINET)
	ne.PutUint16(b[offConnProto:], 6)
	ne.PutUint16(b[offConnSPort:], 51000)
	ne.PutUint16(b[offConnDPort:], 443)
	copy(b[offConnSAddr:], []byte{192, 168, 1, 10})
	copy(b[offConnDAddr:], []byte{93, 184, 216, 34})
	b[offConnOld] = oldState
	b[offConnNew] = newState
	b[offConnDir] = dir
	return b
}

func sockV6Record(typ Type) []byte {
	b := header(typ, AttributionReliable, "nc")
	ne.PutUint64(b[offSockKey:], 0xffff888087654321)
	ne.PutUint16(b[offSockFamily:], familyINET6)
	ne.PutUint16(b[offSockProto:], 17)
	ne.PutUint16(b[offSockType:], 2)
	ne.PutUint16(b[offSockSPort:], 0)
	ne.PutUint16(b[offSockDPort:], 53)
	b[offSockDAddr] = 0x20
	b[offSockDAddr+1] = 0x01
	b[offSockDAddr+2] = 0x0d
	b[offSockDAddr+3] = 0xb8
	b[offSockDAddr+15] = 0x01
	return b
}

func TestLayoutMatchesC(t *testing.T) {
	sizes := map[string][2]int{
		"Header": {binary.Size(Header{}), HeaderSize},
		"Conn":   {binary.Size(Conn{}), PayloadSize},
		"Sock":   {binary.Size(Sock{}), PayloadSize},
	}
	for name, s := range sizes {
		if s[0] != s[1] {
			t.Fatalf("%s: binary size %d, C size %d", name, s[0], s[1])
		}
	}
	if RecordSize != 104 {
		t.Fatalf("record size %d, want 104", RecordSize)
	}
}

func TestDecodeConn(t *testing.T) {
	ev, err := Decode(connV4Record(TypeConnOpen, 2, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sock != nil || ev.Conn == nil {
		t.Fatal("conn record must only fill Conn")
	}
	h, c := ev.Header, ev.Conn
	if h.Type != TypeConnOpen || h.MonoNs != 123456789 || h.PID != 4242 || h.TGID != 4240 || h.UID != 1000 || h.Attribution != AttributionUnreliable {
		t.Fatalf("header mismatch: %+v", h)
	}
	if c.SockKey != 0xffff888012345678 || c.Family != familyINET || c.Proto != 6 || c.SPort != 51000 || c.DPort != 443 {
		t.Fatalf("conn mismatch: %+v", c)
	}
	if c.SAddr[0] != 192 || c.DAddr[3] != 34 || c.OldState != 2 || c.NewState != 1 || c.Direction != 0 {
		t.Fatalf("conn addr/state mismatch: %+v", c)
	}
}

func TestDecodeSock(t *testing.T) {
	ev, err := Decode(sockV6Record(TypeLSMConnect))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Conn != nil || ev.Sock == nil {
		t.Fatal("sock record must only fill Sock")
	}
	s := ev.Sock
	if s.SockKey != 0xffff888087654321 || s.Family != familyINET6 || s.Proto != 17 || s.SockType != 2 || s.DPort != 53 || s.DAddr[15] != 1 {
		t.Fatalf("sock mismatch: %+v", s)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := connV4Record(TypeConnOpen, 2, 1, 0)
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	cases := map[string]struct {
		record []byte
		want   error
	}{
		"empty":          {nil, ErrRecordSize},
		"short":          {good[:RecordSize-1], ErrRecordSize},
		"long":           {append(append([]byte(nil), good...), 0), ErrRecordSize},
		"schema":         {mutate(func(b []byte) { ne.PutUint16(b[offSchema:], 2) }), ErrSchemaVersion},
		"announced size": {mutate(func(b []byte) { ne.PutUint32(b[offSize:], 96) }), ErrRecordSize},
		"type zero":      {mutate(func(b []byte) { ne.PutUint16(b[offType:], 0) }), ErrUnknownType},
		"type unknown":   {mutate(func(b []byte) { ne.PutUint16(b[offType:], 99) }), ErrUnknownType},
		"family":         {mutate(func(b []byte) { ne.PutUint16(b[offConnFamily:], 1) }), ErrUnknownFamily},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(tc.record); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
