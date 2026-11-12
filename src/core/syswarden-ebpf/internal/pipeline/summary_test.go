package pipeline

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/event"
)

var t0 = time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC)

// Offsets from bpf/data/bpf_events.h.
func hdr(typ event.Type, attr event.Attribution, comm string, pid uint32) []byte {
	b := make([]byte, event.RecordSize)
	ne := binary.NativeEndian
	ne.PutUint16(b[0:], event.SchemaVersion)
	ne.PutUint16(b[2:], uint16(typ))
	ne.PutUint32(b[4:], event.RecordSize)
	ne.PutUint32(b[16:], pid)
	ne.PutUint32(b[20:], pid)
	ne.PutUint32(b[24:], 1000)
	copy(b[28:44], comm)
	b[44] = uint8(attr)
	return b
}

type conn struct {
	key           uint64
	local, remote string
	lport, rport  uint16
	old, dir      uint8
}

func connRec(typ event.Type, comm string, c conn) event.Event {
	b := hdr(typ, event.AttributionUnreliable, comm, 0)
	ne := binary.NativeEndian
	ne.PutUint64(b[48:], c.key)
	ne.PutUint16(b[56:], 2)
	ne.PutUint16(b[58:], protoTCP)
	ne.PutUint16(b[60:], c.lport)
	ne.PutUint16(b[62:], c.rport)
	copy(b[64:], netip.MustParseAddr(c.local).AsSlice())
	copy(b[80:], netip.MustParseAddr(c.remote).AsSlice())
	b[96] = c.old
	b[97] = 1
	if typ == event.TypeConnClose {
		b[97] = 7
	}
	b[98] = c.dir
	return decode(b)
}

func sockRec(typ event.Type, comm string, pid uint32, key uint64, proto, lport, rport uint16, remote string) event.Event {
	b := hdr(typ, event.AttributionReliable, comm, pid)
	ne := binary.NativeEndian
	ne.PutUint64(b[48:], key)
	ne.PutUint16(b[56:], 2)
	ne.PutUint16(b[58:], proto)
	ne.PutUint16(b[60:], 1)
	ne.PutUint16(b[62:], lport)
	ne.PutUint16(b[64:], rport)
	if remote != "" {
		copy(b[82:], netip.MustParseAddr(remote).AsSlice())
	}
	return decode(b)
}

func decode(b []byte) event.Event {
	ev, err := event.Decode(b)
	if err != nil {
		panic(err)
	}
	return ev
}

type harness struct {
	t   *testing.T
	s   *summarizer
	out *memSink
	st  *Stats
}

func newHarness(t *testing.T, rules ...config.IgnoreRule) *harness {
	cfg := config.Defaults()
	cfg.Ignore = rules
	h := &harness{t: t, out: &memSink{}, st: &Stats{}}
	h.s = newSummarizer(cfg, h.out, h.st, silent)
	return h
}

func (h *harness) feed(at time.Duration, evs ...event.Event) {
	for _, ev := range evs {
		h.s.handle(ev, t0.Add(at))
	}
}

// lines decodes and empties what was written so far.
func (h *harness) lines() []map[string]any {
	h.t.Helper()
	var out []map[string]any
	for _, l := range h.out.lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, m)
	}
	h.out.lines = nil
	return out
}

func (h *harness) expect(n int) []map[string]any {
	h.t.Helper()
	got := h.lines()
	if len(got) != n {
		h.t.Fatalf("got %d lines, want %d: %v", len(got), n, got)
	}
	return got
}

func field(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Fatalf("%s = %v, want %v in %v", k, line[k], v, line)
		}
	}
}

var out443 = conn{key: 1, local: "192.168.1.10", remote: "93.184.216.34", lport: 51000, rport: 443, old: 2, dir: 0}

func TestOutboundTakesProcessFromConnect(t *testing.T) {
	h := newHarness(t)
	h.feed(0, sockRec(event.TypeLSMConnect, "curl", 77, 1, protoTCP, 0, 443, "93.184.216.34"))
	h.expect(0) //waits for the handshake

	h.feed(time.Second, connRec(event.TypeConnOpen, "swapper/3", out443))
	line := h.expect(1)[0]
	field(t, line, map[string]any{"type": "flow", "outcome": "established", "direction": "outbound", "comm": "curl",
		"attribution": "reliable", "pid": 77.0, "remote": "93.184.216.34", "remote_port": 443.0})

	closed := out443
	closed.old = 4
	h.feed(2*time.Second, connRec(event.TypeConnClose, "swapper/3", closed))
	h.expect(0)
	if h.s.pending.len() != 0 {
		t.Fatal("pending connect must be consumed by the open")
	}
}

func TestFailedConnect(t *testing.T) {
	h := newHarness(t)
	h.feed(0, sockRec(event.TypeLSMConnect, "nmap", 9, 1, protoTCP, 0, 443, "93.184.216.34"))
	h.feed(time.Second, connRec(event.TypeConnClose, "swapper/0", out443)) //old = SYN_SENT
	field(t, h.expect(1)[0], map[string]any{"outcome": "failed", "direction": "outbound", "comm": "nmap", "attribution": "reliable"})
}

func TestInboundTakesProcessFromBind(t *testing.T) {
	h := newHarness(t)
	h.feed(0, sockRec(event.TypeLSMBind, "nginx", 10, 50, protoTCP, 443, 0, ""))
	field(t, h.expect(1)[0], map[string]any{"type": "lsm_bind", "comm": "nginx", "sport": 443.0})

	in := conn{key: 2, local: "192.168.1.10", remote: "203.0.113.7", lport: 443, rport: 40000, old: 3, dir: 1}
	h.feed(time.Second, connRec(event.TypeConnOpen, "swapper/1", in))
	field(t, h.expect(1)[0], map[string]any{"direction": "inbound", "comm": "nginx", "attribution": "reliable",
		"local_port": 443.0, "remote": "203.0.113.7"})
}

func TestUDPConnectIsReportedAtOnce(t *testing.T) {
	h := newHarness(t)
	h.feed(0, sockRec(event.TypeLSMConnect, "dig", 5, 3, 17, 0, 53, "1.1.1.1"))
	field(t, h.expect(1)[0], map[string]any{"outcome": "connect", "proto": "udp", "comm": "dig", "remote_port": 53.0})
}

func TestRepeatsFoldIntoOneLinePerWindow(t *testing.T) {
	h := newHarness(t)
	for i := range 3 {
		c := out443
		c.key, c.lport = uint64(10+i), uint16(51000+i)
		h.feed(time.Duration(i)*time.Second, sockRec(event.TypeLSMConnect, "curl", 77, c.key, protoTCP, 0, 443, c.remote))
		h.feed(time.Duration(i)*time.Second, connRec(event.TypeConnOpen, "swapper/0", c))
	}
	h.expect(1)
	if h.st.Aggregated.Load() != 2 {
		t.Fatalf("aggregated=%d, want 2", h.st.Aggregated.Load())
	}

	h.s.flush(t0.Add(time.Minute))
	field(t, h.expect(1)[0], map[string]any{"type": "flow_repeat", "count": 3.0, "comm": "curl",
		"first_seen": "2026-11-12T18:00:00Z", "last_seen": "2026-11-12T18:00:02Z"})

	//new window: the next occurrence is written again.
	h.feed(2*time.Minute, sockRec(event.TypeLSMConnect, "curl", 77, 20, protoTCP, 0, 443, out443.remote))
	c := out443
	c.key = 20
	h.feed(2*time.Minute, connRec(event.TypeConnOpen, "swapper/0", c))
	h.expect(1)
	h.s.flush(t0.Add(3 * time.Minute))
	h.expect(0) //seen once, no repeat line
}

func TestUnreliableCommDoesNotSplitKeys(t *testing.T) {
	h := newHarness(t)
	for i, comm := range []string{"swapper/0", "kworker/1", "sshd"} {
		in := conn{key: uint64(i), local: "192.168.1.10", remote: "203.0.113.7", lport: 22, rport: uint16(40000 + i), old: 3, dir: 1}
		h.feed(0, connRec(event.TypeConnOpen, comm, in))
	}
	h.expect(1)
	h.s.flush(t0.Add(time.Minute))
	field(t, h.expect(1)[0], map[string]any{"type": "flow_repeat", "count": 3.0})
}

func TestIgnoreRules(t *testing.T) {
	h := newHarness(t,
		config.IgnoreRule{Dst: netip.MustParsePrefix("93.184.216.0/24"), DPort: 443},
		config.IgnoreRule{Comm: "sshd", DPort: 22},
	)
	h.feed(0, sockRec(event.TypeLSMConnect, "curl", 77, 1, protoTCP, 0, 443, out443.remote))
	h.feed(0, connRec(event.TypeConnOpen, "swapper/0", out443))
	h.expect(0)

	//comm "sshd" here comes from softirq: the comm rule must not hide it.
	in := conn{key: 2, local: "192.168.1.10", remote: "203.0.113.7", lport: 22, rport: 40000, old: 3, dir: 1}
	h.feed(0, connRec(event.TypeConnOpen, "sshd", in))
	h.expect(1)

	if h.st.Ignored.Load() != 1 {
		t.Fatalf("ignored=%d, want 1", h.st.Ignored.Load())
	}
}

func TestPendingConnectExpires(t *testing.T) {
	h := newHarness(t)
	h.feed(0, sockRec(event.TypeLSMConnect, "curl", 77, 1, protoTCP, 0, 443, out443.remote))
	h.s.flush(t0.Add(pendingTTL + time.Second))
	if h.st.Expired.Load() != 1 || h.s.pending.len() != 0 {
		t.Fatalf("expired=%d pending=%d", h.st.Expired.Load(), h.s.pending.len())
	}

	h.feed(pendingTTL+2*time.Second, connRec(event.TypeConnOpen, "swapper/0", out443))
	field(t, h.expect(1)[0], map[string]any{"attribution": "unreliable", "comm": "swapper/0"})
}

func TestWriteSummaryFlushesOnTickAndOnClose(t *testing.T) {
	h := newHarness(t)
	queue := make(chan []byte, 8)
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		writeSummary(queue, h.s, fixedClock, tick, func() time.Time { return t0 })
		close(done)
	}()

	rec := hdr(event.TypeLSMConnect, event.AttributionReliable, "dig", 5)
	binary.NativeEndian.PutUint16(rec[56:], 2)
	binary.NativeEndian.PutUint16(rec[58:], 17)
	queue <- rec
	queue <- rec
	tick <- t0 //flush: one repeat line
	queue <- rec
	close(queue) //final flush: seen once, no repeat
	<-done

	got := h.lines()
	if len(got) != 3 || got[0]["type"] != "flow" || got[1]["type"] != "flow_repeat" || got[2]["type"] != "flow" {
		t.Fatalf("got %v", got)
	}
}

func TestLRU(t *testing.T) {
	evicted := 0
	l := newLRU[int, string](2, func() { evicted++ })
	l.put(1, "a")
	l.put(2, "b")
	l.put(1, "a2") //refresh 1, 2 is now the oldest
	l.put(3, "c")
	if _, ok := l.get(2); ok || evicted != 1 {
		t.Fatalf("2 must be evicted, evicted=%d", evicted)
	}
	if v, ok := l.take(1); !ok || v != "a2" || l.len() != 1 {
		t.Fatalf("take(1) = %q %v, len %d", v, ok, l.len())
	}
	if n := l.pruneOldest(func(v string) bool { return v == "c" }); n != 1 || l.len() != 0 {
		t.Fatalf("pruned %d, len %d", n, l.len())
	}
}
