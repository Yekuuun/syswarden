//go:build linux

package probe

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestLSMListHasBPF(t *testing.T) {
	cases := map[string]bool{
		"lockdown,capability,landlock,yama,apparmor,bpf\n": true,
		"bpf":                          true,
		"capability,bpf,selinux":       true,
		"lockdown,capability,apparmor": false,
		"capability,bpfx,ebpf":         false,
		"":                             false,
	}
	for list, want := range cases {
		if got := lsmListHasBPF(list); got != want {
			t.Fatalf("%q: got %v, want %v", list, got, want)
		}
	}
}

func TestConfigValueMatchesC(t *testing.T) {
	//sizeof(ebpf_config_val) == 8, asserted in bpf/data/bpf_ringbuf.h.
	if size := binary.Size(syswardenEbpfConfigVal{}); size != 8 {
		t.Fatalf("config value size %d, want 8", size)
	}
}

// TestLoadAttach runs the verifier and attaches for real. It needs root:
// sudo env PATH=$PATH GOWORK=off go test -run TestLoadAttach -v ./internal/probe
func TestLoadAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	kcfg := KernelConfig{Flags: FlagIgnoreLoopback, SelfTGID: uint32(os.Getpid())}
	p, err := Load(kcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	var got syswardenEbpfConfigVal
	if err := p.maps.EbpfConfig.Lookup(uint32(0), &got); err != nil {
		t.Fatal(err)
	}
	if got.Flags != kcfg.Flags || got.SelfTgid != kcfg.SelfTGID {
		t.Fatalf("ebpf_config = %+v, want %+v", got, kcfg)
	}

	if err := p.Attach(); err != nil {
		t.Fatal(err)
	}
	st := p.Status()
	t.Logf("status: %+v, links: %d", st, len(p.links))
	if !st.Tracepoint || (st.LSM == (st.LSMReason != "")) {
		t.Fatalf("incoherent status %+v", st)
	}
	if err := p.Attach(); err == nil {
		t.Fatal("second Attach must fail")
	}
}
