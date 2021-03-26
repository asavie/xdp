// +build  !armbe,!arm64be,!mips,!mips64,!mips64p32,!ppc64,!s390,!s390x,!sparc,!sparc64,!386,!amd64,!amd64p32,!arm,!arm64,!mipsle,!mips64le,!mips64p32le,!ppc64le,!riscv6

package ebpf

import (
	"github.com/cilium/ebpf"
)

func loadIpproto() (*ebpf.CollectionSpec, error) {
	panic("unimplemented")
}

func loadIpprotoObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	panic("unimplemented")
}

type ipprotoSpecs struct {
	ipprotoProgramSpecs
	ipprotoMapSpecs
}

type ipprotoProgramSpecs struct {
	XdpSockProg *ebpf.ProgramSpec `ebpf:"xdp_sock_prog"`
}

type ipprotoMapSpecs struct {
	QidconfMap *ebpf.MapSpec `ebpf:"qidconf_map"`
	XsksMap    *ebpf.MapSpec `ebpf:"xsks_map"`
}

type ipprotoObjects struct {
	ipprotoPrograms
	ipprotoMaps
}

type ipprotoMaps struct {
	QidconfMap *ebpf.Map `ebpf:"qidconf_map"`
	XsksMap    *ebpf.Map `ebpf:"xsks_map"`
}

type ipprotoPrograms struct {
	XdpSockProg *ebpf.Program `ebpf:"xdp_sock_prog"`
}
