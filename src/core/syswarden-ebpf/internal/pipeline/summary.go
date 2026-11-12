package pipeline

import (
	"fmt"
	"net/netip"
	"time"

	"syswarden-ebpf/internal/config"
	"syswarden-ebpf/internal/event"
)

const (
	maxPending   = 65536 // TCP connects waiting for their handshake
	maxListeners = 4096  // bound ports, to attribute inbound connections
	maxAggKeys   = 65536 // distinct keys per window
	pendingTTL   = 5 * time.Minute

	protoTCP = 6
)

// pendingConnect keeps the reliable process of a TCP connect() until its
// handshake ends, since ESTABLISHED runs in softirq where current is random.
type pendingConnect struct {
	proc event.Process
	seen time.Time
}

// listenKey identifies a bound port. Family is left out: a dual stack socket
// bound in IPv6 also accepts IPv4 peers.
type listenKey struct {
	proto uint16
	port  uint16
}

// summarizer turns events into one line per connection and per bind, and
// folds repeats of the same key within a window into one *_repeat line.
type summarizer struct {
	cfg       config.Config
	pending   *lru[uint64, pendingConnect]
	listeners *lru[listenKey, event.Process]
	agg       map[string]*aggEntry
	out       sink
	st        *Stats
	logf      throttledLog
}

// aggEntry holds the first line of a key and how often it was seen since.
type aggEntry struct {
	repeat      func(count uint64, first, last, wall time.Time) ([]byte, error)
	count       uint64
	first, last time.Time
}

func newSummarizer(cfg config.Config, out sink, st *Stats, logf throttledLog) *summarizer {
	evicted := func() { st.Evicted.Add(1) }
	return &summarizer{
		cfg:       cfg,
		pending:   newLRU[uint64, pendingConnect](maxPending, evicted),
		listeners: newLRU[listenKey, event.Process](maxListeners, evicted),
		agg:       make(map[string]*aggEntry),
		out:       out,
		st:        st,
		logf:      logf,
	}
}

func (s *summarizer) handle(ev event.Event, wall time.Time) {
	switch ev.Header.Type {
	case event.TypeLSMBind:
		s.bind(ev, wall)
	case event.TypeLSMConnect:
		s.connect(ev, wall)
	case event.TypeConnOpen:
		s.open(ev, wall)
	case event.TypeConnClose:
		s.close(ev, wall)
	}
}

// bind records who owns a port, then reports the bind itself.
func (s *summarizer) bind(ev event.Event, wall time.Time) {
	sk, proc := ev.Sock, ev.Header.Process()
	if sk.SPort != 0 {
		s.listeners.put(listenKey{sk.Proto, sk.SPort}, proc)
	}

	rec, err := event.NewRecord(ev, wall)
	if err != nil {
		s.st.DecodeErrors.Add(1)
		return
	}
	key := fmt.Sprintf("bind|%d|%s|%s|%s|%d", proc.UID, rec.Comm, rec.Proto, rec.Src, rec.SPort)
	s.observe(key, wall, func() ([]byte, error) { return event.Encode(rec) },
		func(count uint64, first, last, now time.Time) ([]byte, error) {
			return event.Encode(rec.Repeat(count, first, last, now))
		})
}

// connect waits for the TCP handshake, other protocols are reported now.
func (s *summarizer) connect(ev event.Event, wall time.Time) {
	sk, proc := ev.Sock, ev.Header.Process()
	if sk.Proto == protoTCP {
		s.pending.put(sk.SockKey, pendingConnect{proc, wall})
		return
	}
	s.emitFlow(event.SockFlow(sk, proc, wall), proc, sk.RemoteAddr(), wall)
}

func (s *summarizer) open(ev event.Event, wall time.Time) {
	c := ev.Conn
	pending, hasPending := s.pending.take(c.SockKey)
	proc := ev.Header.Process()

	if c.Direction == event.DirActive && hasPending {
		proc = pending.proc
	}
	if c.Direction == event.DirPassive {
		if owner, ok := s.listeners.get(listenKey{c.Proto, c.SPort}); ok {
			proc = owner
		}
	}

	s.emitFlow(event.ConnFlow(c, proc, event.OutcomeEstablished, wall), proc, c.RemoteAddr(), wall)
}

// close only matters for a connect that never completed.
func (s *summarizer) close(ev event.Event, wall time.Time) {
	c := ev.Conn
	pending, hasPending := s.pending.take(c.SockKey)
	if !c.IsFailedConnect() {
		return
	}
	proc := ev.Header.Process()
	if hasPending {
		proc = pending.proc
	}
	s.emitFlow(event.ConnFlow(c, proc, event.OutcomeFailed, wall), proc, c.RemoteAddr(), wall)
}

// emitFlow drops ignored flows, then writes the first occurrence of its key.
func (s *summarizer) emitFlow(f event.Flow, proc event.Process, remote netip.Addr, wall time.Time) {
	reliable := proc.Attribution == event.AttributionReliable
	port := servicePort(f)

	if s.cfg.Ignored(config.Target{Comm: f.Comm, CommReliable: reliable, Remote: remote, ServicePort: port, Proto: f.Proto}) {
		s.st.Ignored.Add(1)
		return
	}

	//a random softirq comm would make every occurrence a new key.
	who := "?"
	if reliable {
		who = fmt.Sprintf("%d|%s", f.UID, f.Comm)
	}
	key := fmt.Sprintf("flow|%s|%s|%s|%s|%s|%d", f.Outcome, f.Direction, f.Proto, who, remote, port)
	s.observe(key, wall, func() ([]byte, error) { return event.EncodeFlow(f) },
		func(count uint64, first, last, now time.Time) ([]byte, error) {
			return event.EncodeFlow(f.Repeat(count, first, last, now))
		})
}

// observe writes line now on the first occurrence of key in the window, and
// only counts the next ones. Past maxAggKeys, lines are written untracked.
func (s *summarizer) observe(key string, wall time.Time, line func() ([]byte, error), repeat func(uint64, time.Time, time.Time, time.Time) ([]byte, error)) {
	if e, ok := s.agg[key]; ok {
		e.count++
		e.last = wall
		s.st.Aggregated.Add(1)
		return
	}
	if len(s.agg) < maxAggKeys {
		s.agg[key] = &aggEntry{repeat: repeat, count: 1, first: wall, last: wall}
	} else {
		s.st.AggOverflow.Add(1)
	}
	s.write(line())
}

// flush ends the window: one *_repeat line per key seen more than once, then
// pending connects older than pendingTTL are dropped.
func (s *summarizer) flush(wall time.Time) {
	for _, e := range s.agg {
		if e.count > 1 {
			s.write(e.repeat(e.count, e.first, e.last, wall))
		}
	}
	clear(s.agg)

	expired := s.pending.pruneOldest(func(p pendingConnect) bool { return wall.Sub(p.seen) > pendingTTL })
	s.st.Expired.Add(uint64(expired))
}

func (s *summarizer) write(line []byte, err error) {
	if err == nil {
		err = s.out.Write(line)
	}
	if err != nil {
		s.st.WriteErrors.Add(1)
		s.logf("cannot write summary line: %v", err)
		return
	}
	s.st.Written.Add(1)
}

// servicePort is the port that names the service: remote when outbound,
// local when inbound.
func servicePort(f event.Flow) uint16 {
	if f.Direction == event.DirectionInbound {
		return f.LocalPort
	}
	return f.RemotePort
}

// writeSummary runs the summarizer until queue closes, flushing every tick.
func writeSummary(queue <-chan []byte, s *summarizer, clock wallClock, tick <-chan time.Time, now func() time.Time) {
	for {
		select {
		case record, ok := <-queue:
			if !ok {
				s.flush(now())
				return
			}
			ev, err := event.Decode(record)
			if err != nil {
				s.st.DecodeErrors.Add(1)
				s.logf("dropping undecodable record: %v", err)
				continue
			}
			s.handle(ev, clock(ev.Header.MonoNs))
		case <-tick:
			s.flush(now())
		}
	}
}
