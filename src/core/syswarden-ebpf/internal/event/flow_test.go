package event

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestFlowGolden(t *testing.T) {
	open, err := Decode(connV4Record(TypeConnOpen, 2, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	connect, err := Decode(sockV6Record(TypeLSMConnect))
	if err != nil {
		t.Fatal(err)
	}
	reliable := connect.Header.Process()
	later := wall.Add(42 * time.Second)

	cases := map[string]Flow{
		"flow_established_v4.json": ConnFlow(open.Conn, reliable, OutcomeEstablished, wall),
		"flow_connect_v6.json":     SockFlow(connect.Sock, reliable, wall),
		"flow_repeat_v4.json":      ConnFlow(open.Conn, reliable, OutcomeEstablished, wall).Repeat(7, wall, later, later),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			line, err := EncodeFlow(f)
			if err != nil {
				t.Fatal(err)
			}
			if want := fixture(t, name); !bytes.Equal(line, want) {
				t.Fatalf("json changed\n got: %s\nwant: %s", line, want)
			}
		})
	}
}

func TestFlowDirectionAndFailure(t *testing.T) {
	passive, _ := Decode(connV4Record(TypeConnOpen, 3, 1, 1))
	if f := ConnFlow(passive.Conn, passive.Header.Process(), OutcomeEstablished, wall); f.Direction != DirectionInbound {
		t.Fatalf("passive open must be inbound, got %s", f.Direction)
	}
	failed, _ := Decode(connV4Record(TypeConnClose, 2, 7, 0))
	if !failed.Conn.IsFailedConnect() {
		t.Fatal("close from SYN_SENT is a failed connect")
	}
	closed, _ := Decode(connV4Record(TypeConnClose, 4, 7, 1))
	if closed.Conn.IsFailedConnect() {
		t.Fatal("close from FIN_WAIT1 is not a failed connect")
	}
}

func TestAddrIsUnmapped(t *testing.T) {
	var raw [16]byte
	copy(raw[:], netip.MustParseAddr("::ffff:10.1.2.3").AsSlice())
	s := &Sock{Family: familyINET6, DAddr: raw}
	if got := s.RemoteAddr(); got != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("got %s, want unmapped 10.1.2.3", got)
	}
}
