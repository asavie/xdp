// +build  !armbe,!arm64be,!mips,!mips64,!mips64p32,!ppc64,!s390,!s390x,!sparc,!sparc64,!386,!amd64,!amd64p32,!arm,!arm64,!mipsle,!mips64le,!mips64p32le,!ppc64le,!riscv6

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type ipprotoSpecs struct {
	ProgramXdpSockProg *ebpf.ProgramSpec `ebpf:"xdp_sock_prog"`
	MapQidconfMap      *ebpf.MapSpec     `ebpf:"qidconf_map"`
	MapXsksMap         *ebpf.MapSpec     `ebpf:"xsks_map"`
	SectionRodata      *ebpf.MapSpec     `ebpf:".rodata"`
}

func newIpprotoSpecs() (*ipprotoSpecs, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (s *ipprotoSpecs) CollectionSpec() *ebpf.CollectionSpec {
	panic("unimplemented")
}

func (s *ipprotoSpecs) Load(opts *ebpf.CollectionOptions) (*ipprotoObjects, error) {
	panic("unimplemented")
}

func (s *ipprotoSpecs) Copy() *ipprotoSpecs {
	panic("unimplemented")
}

type ipprotoObjects struct {
	ProgramXdpSockProg *ebpf.Program `ebpf:"xdp_sock_prog"`
	MapQidconfMap      *ebpf.Map     `ebpf:"qidconf_map"`
	MapXsksMap         *ebpf.Map     `ebpf:"xsks_map"`
	SectionRodata      *ebpf.Map     `ebpf:".rodata"`
}

func (o *ipprotoObjects) Close() error {
	panic("unimplemented")
}
