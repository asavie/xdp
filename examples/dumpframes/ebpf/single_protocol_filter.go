package ebpf

import (
	"fmt"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate $HOME/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3

// ipproto combines the ipprotoPrograms and ipprotoMaps structs into one type
// FIXME: this is a workaround, as loadIpprotoObjects with ipprotoObjects fails to `LoadAndAssign` the program / maps.
type ipproto struct {
	QidconfMap  *ebpf.Map     `ebpf:"qidconf_map"`
	XsksMap     *ebpf.Map     `ebpf:"xsks_map"`
	XdpSockProg *ebpf.Program `ebpf:"xdp_sock_prog"`
}

// NewIPProtoProgram returns an new eBPF that directs packets of the given ip protocol to to XDP sockets
func NewIPProtoProgram(protocol uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	spec, err := loadIpproto()
	if err != nil {
		return nil, err
	}

	if protocol >= 0 && protocol <= 255 {
		if err := spec.RewriteConstants(map[string]interface{}{"PROTO": uint8(protocol)}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("protocol must be between 0 and 255")
	}
	var program ipproto
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &xdp.Program{Program: program.XdpSockProg, Queues: program.QidconfMap, Sockets: program.XsksMap}
	return p, nil
}
