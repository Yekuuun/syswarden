//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	lsmListPath = "/sys/kernel/security/lsm"
	btfPath     = "/sys/kernel/btf/vmlinux"
)

// FlagIgnoreLoopback mirrors CFG_IGNORE_LOOPBACK in bpf/data/bpf_ringbuf.h.
const FlagIgnoreLoopback uint32 = 1 << 0

// KernelConfig is written to the ebpf_config map before any attach.
type KernelConfig struct {
	Flags    uint32
	SelfTGID uint32 // filtered in syscall context only, see is_filtered()
}

// Status reports what is attached, for `syswarden-ebpf status`.
type Status struct {
	Tracepoint bool
	LSM        bool
	LSMReason  string // why LSM hooks are not attached, empty when they are
}

// Probe owns the loaded objects and their links. Load, open the ringbuf
// reader on Events, then Attach: events emitted before the reader exists
// would be lost.
type Probe struct {
	maps     syswardenMaps
	tp       *ebpf.Program
	lsm      *lsmPrograms
	links    []link.Link
	status   Status
	attached bool
}

type lsmPrograms struct {
	Bind    *ebpf.Program `ebpf:"lsm_socket_bind"`
	Connect *ebpf.Program `ebpf:"lsm_socket_connect"`
}

type tpObjects struct {
	syswardenMaps
	SockHandleSetState *ebpf.Program `ebpf:"sock_handle_set_state"`
}

type allObjects struct {
	tpObjects
	lsmPrograms
}

// Load loads the programs and maps and writes kcfg, without attaching. LSM
// programs are only loaded when the bpf LSM is active: on other kernels their
// attach target does not exist and the whole load would fail.
func Load(kcfg KernelConfig) (*Probe, error) {
	if _, err := os.Stat(btfPath); err != nil {
		return nil, fmt.Errorf("kernel BTF is required (%s): %w", btfPath, err)
	}
	//only needed before 5.11, where BPF memory is charged to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := loadSyswarden()
	if err != nil {
		return nil, fmt.Errorf("load embedded BPF spec: %w", err)
	}

	p := &Probe{status: Status{Tracepoint: true}}
	lsmOK, reason := lsmActive()

	if lsmOK {
		var objs allObjects
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			return nil, loadError(err)
		}
		p.maps, p.tp, p.lsm = objs.syswardenMaps, objs.SockHandleSetState, &objs.lsmPrograms
	} else {
		var objs tpObjects
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			return nil, loadError(err)
		}
		p.maps, p.tp = objs.syswardenMaps, objs.SockHandleSetState
		p.status.LSMReason = reason
	}

	val := syswardenEbpfConfigVal{Flags: kcfg.Flags, SelfTgid: kcfg.SelfTGID}
	if err := p.maps.EbpfConfig.Put(uint32(0), val); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("write ebpf_config: %w", err)
	}
	return p, nil
}

// Events is the ringbuf map, to open the reader on before Attach.
func (p *Probe) Events() *ebpf.Map { return p.maps.EbpfOutput }

// DropStats is the per-cpu drop counter map.
func (p *Probe) DropStats() *ebpf.Map { return p.maps.DropStats }

// Attach attaches the tracepoint, then the LSM hooks when loaded. Any failure
// detaches what was already attached.
func (p *Probe) Attach() error {
	if p.attached {
		return errors.New("already attached")
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", p.tp, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sock/inet_sock_set_state: %w", err)
	}
	p.links = append(p.links, tp)

	if p.lsm != nil {
		for name, prog := range map[string]*ebpf.Program{"socket_connect": p.lsm.Connect, "socket_bind": p.lsm.Bind} {
			l, err := link.AttachLSM(link.LSMOptions{Program: prog})
			if err != nil {
				p.detach()
				return fmt.Errorf("attach lsm/%s: %w", name, err)
			}
			p.links = append(p.links, l)
		}
		p.status.LSM = true
	}

	p.attached = true
	return nil
}

// Status returns what is currently attached.
func (p *Probe) Status() Status { return p.status }

// Close detaches every link, then releases programs and maps.
func (p *Probe) Close() error {
	errs := []error{p.detach()}
	if p.lsm != nil {
		errs = append(errs, p.lsm.Bind.Close(), p.lsm.Connect.Close())
	}
	if p.tp != nil {
		errs = append(errs, p.tp.Close())
	}
	errs = append(errs, p.maps.Close())
	return errors.Join(errs...)
}

func (p *Probe) detach() error {
	var errs []error
	//reverse order: LSM hooks go first, the tracepoint last.
	for _, l := range slices.Backward(p.links) {
		errs = append(errs, l.Close())
	}
	p.links = nil
	p.attached = false
	p.status.LSM = false
	return errors.Join(errs...)
}

// lsmActive tells if "bpf" is in the active LSM list, with the reason when not.
func lsmActive() (bool, string) {
	content, err := os.ReadFile(lsmListPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read %s: %v", lsmListPath, err)
	}
	if !lsmListHasBPF(string(content)) {
		return false, fmt.Sprintf("bpf is not in the active LSM list (%s), add lsm=...,bpf to the kernel command line", strings.TrimSpace(string(content)))
	}
	return true, ""
}

func lsmListHasBPF(list string) bool {
	return slices.Contains(strings.Split(strings.TrimSpace(list), ","), "bpf")
}

// loadError keeps the end of the verifier log, where the rejection reason is.
func loadError(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("BPF verifier rejected the program: %+v", ve)
	}
	return fmt.Errorf("load BPF objects: %w", err)
}
