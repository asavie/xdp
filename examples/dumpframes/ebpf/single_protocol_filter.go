package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate $HOME/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3

// NewIPProtoProgram returns a new eBPF and associated QidConf and XSK map that directs packets of the given IP protocol to to XDP sockets
func NewIPProtoProgram(protocol uint32, options *ebpf.CollectionOptions) (*ebpf.Program, *ebpf.Map, *ebpf.Map, error) {
	spec, err := loadIpproto()
	if err != nil {
		return nil, nil, nil, err
	}

	if protocol >= 0 && protocol <= 255 {
		if err := spec.RewriteConstants(map[string]interface{}{"PROTO": uint8(protocol)}); err != nil {
			return nil, nil, nil, err
		}
	} else {
		return nil, nil, nil, fmt.Errorf("protocol must be between 0 and 255")
	}
	var program ipprotoObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, nil, nil, err
	}

	return program.XdpSockProg, program.QidconfMap, program.XsksMap, nil
}
