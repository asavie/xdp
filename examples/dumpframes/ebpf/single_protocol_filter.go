package ebpf

import (
	"fmt"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate $HOME/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3

// NewIPProtoProgram returns an new eBPF that directs packets of the given ip protocol to to XDP sockets
func NewIPProtoProgram(protocol uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	ss, err := newIpprotoSpecs()
	if err != nil {
		return nil, err
	}
	if protocol >= 0 && protocol <= 255 {
		if err := ss.CollectionSpec().RewriteConstants(map[string]interface{}{"PROTO": uint8(protocol)}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("protocol must be between 0 and 255")
	}
	so, err := ss.Load(options)
	if err != nil {
		return nil, err
	}
	program := &xdp.Program{Program: so.ProgramXdpSockProg, Queues: so.MapQidconfMap, Sockets: so.MapXsksMap}
	return program, nil
}
