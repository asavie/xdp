package xdp

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
)

// Program represents the necessary data structures for a simple XDP program that can filter traffic
// based on the attached rx queue.
type Program struct {
	Program *ebpf.Program
	Queues  *ebpf.Map
	Sockets *ebpf.Map
}

// Attach the XDP Program to an interface.
func (p *Program) Attach(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.Program)
}

// Detach the XDP Program from an interface.
func (p *Program) Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

// Register adds the socket file descriptor as the recipient for packets from the given queueID.
func (p *Program) Register(queueID int, fd int) error {
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return fmt.Errorf("failed to update xsksMap: %v", err)
	}

	if err := p.Queues.Put(uint32(queueID), uint32(1)); err != nil {
		return fmt.Errorf("failed to update qidconfMap: %v", err)
	}
	return nil
}

// Unregister removes any associated mapping to sockets for the given queueID.
func (p *Program) Unregister(queueID int) error {
	if err := p.Queues.Delete(uint32(queueID)); err != nil {
		return err
	}
	if err := p.Sockets.Delete(uint32(queueID)); err != nil {
		return err
	}
	return nil
}

// Close closes and frees the resources allocated for the Program.
func (p *Program) Close() error {
	allErrors := []error{}
	if p.Sockets != nil {
		if err := p.Sockets.Close(); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close xsksMap: %v", err))
		}
		p.Sockets = nil
	}

	if p.Queues != nil {
		if err := p.Queues.Close(); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close qidconfMap: %v", err))
		}
		p.Queues = nil
	}

	if p.Program != nil {
		if err := p.Program.Close(); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close XDP program: %v", err))
		}
		p.Program = nil
	}

	if len(allErrors) > 0 {
		return allErrors[0]
	}
	return nil
}

// NewProgram returns a translation of the default eBPF XDP program found in the
// xsk_load_xdp_prog() function in <linux>/tools/lib/bpf/xsk.c:
// https://github.com/torvalds/linux/blob/master/tools/lib/bpf/xsk.c#L259
func NewProgram(maxQueueEntries int) (*Program, error) {
	qidconfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "qidconf_map",
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(int32(0))),
		ValueSize:  uint32(unsafe.Sizeof(int32(0))),
		MaxEntries: uint32(maxQueueEntries),
		Flags:      0,
		InnerMap:   nil,
	})
	if err != nil {
		return nil, fmt.Errorf("ebpf.NewMap qidconf_map failed (try increasing RLIMIT_MEMLOCK): %v", err)
	}

	xsksMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    uint32(unsafe.Sizeof(int32(0))),
		ValueSize:  uint32(unsafe.Sizeof(int32(0))),
		MaxEntries: uint32(maxQueueEntries),
		Flags:      0,
		InnerMap:   nil,
	})
	if err != nil {
		return nil, fmt.Errorf("ebpf.NewMap xsks_map failed (try increasing RLIMIT_MEMLOCK): %v", err)
	}

	/*
		This is a translation of the default eBPF XDP program found in the
		xsk_load_xdp_prog() function in <linux>/tools/lib/bpf/xsk.c:
		https://github.com/torvalds/linux/blob/master/tools/lib/bpf/xsk.c#L259

		// This is the C-program:
		// SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
		// {
		//     int *qidconf, index = ctx->rx_queue_index;
		//
		//     // A set entry here means that the correspnding queue_id
		//     // has an active AF_XDP socket bound to it.
		//     qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
		//     if (!qidconf)
		//         return XDP_ABORTED;
		//
		//     if (*qidconf)
		//         return bpf_redirect_map(&xsks_map, index, 0);
		//
		//     return XDP_PASS;
		// }
		//
		struct bpf_insn prog[] = {
			// r1 = *(u32 *)(r1 + 16)
			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1, 16),   // 0
			// *(u32 *)(r10 - 4) = r1
			BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4),  // 1
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),           // 2
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),          // 3
			BPF_LD_MAP_FD(BPF_REG_1, xsk->qidconf_map_fd),  // 4 (2 instructions)
			BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),        // 5
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),            // 6
			BPF_MOV32_IMM(BPF_REG_0, 0),                    // 7
			// if r1 == 0 goto +8
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 8),          // 8
			BPF_MOV32_IMM(BPF_REG_0, 2),                    // 9
			// r1 = *(u32 *)(r1 + 0)
			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1, 0),    // 10
			// if r1 == 0 goto +5
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 5),          // 11
			// r2 = *(u32 *)(r10 - 4)
			BPF_LD_MAP_FD(BPF_REG_1, xsk->xsks_map_fd),     // 12 (2 instructions)
			BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, -4),  // 13
			BPF_MOV32_IMM(BPF_REG_3, 0),                    // 14
			BPF_EMIT_CALL(BPF_FUNC_redirect_map),           // 15
			// The jumps are to this instruction
			BPF_EXIT_INSN(),                                // 16
		};

		eBPF instructions:
		  0: code: 97 dst_reg: 1 src_reg: 1 off: 16 imm: 0   // 0
		  1: code: 99 dst_reg: 10 src_reg: 1 off: -4 imm: 0  // 1
		  2: code: 191 dst_reg: 2 src_reg: 10 off: 0 imm: 0  // 2
		  3: code: 7 dst_reg: 2 src_reg: 0 off: 0 imm: -4    // 3
		  4: code: 24 dst_reg: 1 src_reg: 1 off: 0 imm: 4    // 4 XXX use qidconfMap.FD as IMM
		  5: code: 0 dst_reg: 0 src_reg: 0 off: 0 imm: 0     //   part of the same instruction
		  6: code: 133 dst_reg: 0 src_reg: 0 off: 0 imm: 1   // 5
		  7: code: 191 dst_reg: 1 src_reg: 0 off: 0 imm: 0   // 6
		  8: code: 180 dst_reg: 0 src_reg: 0 off: 0 imm: 0   // 7
		  9: code: 21 dst_reg: 1 src_reg: 0 off: 8 imm: 0    // 8
		  10: code: 180 dst_reg: 0 src_reg: 0 off: 0 imm: 2  // 9
		  11: code: 97 dst_reg: 1 src_reg: 1 off: 0 imm: 0   // 10
		  12: code: 21 dst_reg: 1 src_reg: 0 off: 5 imm: 0   // 11
		  13: code: 24 dst_reg: 1 src_reg: 1 off: 0 imm: 5   // 12 XXX use xsksMap.FD as IMM
		  14: code: 0 dst_reg: 0 src_reg: 0 off: 0 imm: 0    //    part of the same instruction
		  15: code: 97 dst_reg: 2 src_reg: 10 off: -4 imm: 0 // 13
		  16: code: 180 dst_reg: 3 src_reg: 0 off: 0 imm: 0  // 14
		  17: code: 133 dst_reg: 0 src_reg: 0 off: 0 imm: 51 // 15
		  18: code: 149 dst_reg: 0 src_reg: 0 off: 0 imm: 0  // 16
	*/

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "xsk_ebpf",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			{OpCode: 97, Dst: 1, Src: 1, Offset: 16},                                  // 0: code: 97 dst_reg: 1 src_reg: 1 off: 16 imm: 0   // 0
			{OpCode: 99, Dst: 10, Src: 1, Offset: -4},                                 // 1: code: 99 dst_reg: 10 src_reg: 1 off: -4 imm: 0  // 1
			{OpCode: 191, Dst: 2, Src: 10},                                            // 2: code: 191 dst_reg: 2 src_reg: 10 off: 0 imm: 0  // 2
			{OpCode: 7, Dst: 2, Src: 0, Offset: 0, Constant: -4},                      // 3: code: 7 dst_reg: 2 src_reg: 0 off: 0 imm: -4    // 3
			{OpCode: 24, Dst: 1, Src: 1, Offset: 0, Constant: int64(qidconfMap.FD())}, // 4: code: 24 dst_reg: 1 src_reg: 1 off: 0 imm: 4    // 4 XXX use qidconfMap.FD as IMM
			//{ OpCode: 0 },                                                                 // 5: code: 0 dst_reg: 0 src_reg: 0 off: 0 imm: 0     //   part of the same instruction
			{OpCode: 133, Dst: 0, Src: 0, Constant: 1},                  // 6: code: 133 dst_reg: 0 src_reg: 0 off: 0 imm: 1   // 5
			{OpCode: 191, Dst: 1, Src: 0},                               // 7: code: 191 dst_reg: 1 src_reg: 0 off: 0 imm: 0   // 6
			{OpCode: 180, Dst: 0, Src: 0},                               // 8: code: 180 dst_reg: 0 src_reg: 0 off: 0 imm: 0   // 7
			{OpCode: 21, Dst: 1, Src: 0, Offset: 8},                     // 9: code: 21 dst_reg: 1 src_reg: 0 off: 8 imm: 0    // 8
			{OpCode: 180, Dst: 0, Src: 0, Constant: 2},                  // 10: code: 180 dst_reg: 0 src_reg: 0 off: 0 imm: 2  // 9
			{OpCode: 97, Dst: 1, Src: 1},                                // 11: code: 97 dst_reg: 1 src_reg: 1 off: 0 imm: 0   // 10
			{OpCode: 21, Dst: 1, Offset: 5},                             // 12: code: 21 dst_reg: 1 src_reg: 0 off: 5 imm: 0   // 11
			{OpCode: 24, Dst: 1, Src: 1, Constant: int64(xsksMap.FD())}, // 13: code: 24 dst_reg: 1 src_reg: 1 off: 0 imm: 5   // 12 XXX use xsksMap.FD as IMM
			//{ OpCode: 0 },                                                                 // 14: code: 0 dst_reg: 0 src_reg: 0 off: 0 imm: 0    //    part of the same instruction
			{OpCode: 97, Dst: 2, Src: 10, Offset: -4}, // 15: code: 97 dst_reg: 2 src_reg: 10 off: -4 imm: 0 // 13
			{OpCode: 180, Dst: 3},                     // 16: code: 180 dst_reg: 3 src_reg: 0 off: 0 imm: 0  // 14
			{OpCode: 133, Constant: 51},               // 17: code: 133 dst_reg: 0 src_reg: 0 off: 0 imm: 51 // 15
			{OpCode: 149},                             // 18: code: 149 dst_reg: 0 src_reg: 0 off: 0 imm: 0  // 16
		},
		License:       "LGPL-2.1 or BSD-2-Clause",
		KernelVersion: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("error: ebpf.NewProgram failed: %v", err)
	}

	return &Program{Program: program, Queues: qidconfMap, Sockets: xsksMap}, nil
}

// LoadProgram load a external XDP program, along with queue and socket map;
// fname is the BPF kernel program file (.o);
// funcname is the function name in the program file;
// qidmapname is the Queues map name;
// xskmapname is the Sockets map name;
func LoadProgram(fname, funcname, qidmapname, xskmapname string) (*Program, error) {
	prog := new(Program)
	col, err := ebpf.LoadCollection(fname)
	if err != nil {
		return nil, err
	}
	var ok bool
	if prog.Program, ok = col.Programs[funcname]; !ok {
		return nil, fmt.Errorf("%v doesn't contain a function named %v", fname, funcname)
	}
	if prog.Queues, ok = col.Maps[qidmapname]; !ok {
		return nil, fmt.Errorf("%v doesn't contain a queue map named %v", fname, qidmapname)
	}
	if prog.Sockets, ok = col.Maps[xskmapname]; !ok {
		return nil, fmt.Errorf("%v doesn't contain a socket map named %v", fname, xskmapname)
	}
	return prog, nil
}

// removeProgram removes an existing XDP program from the given network interface.
func removeProgram(Ifindex int) error {
	var link netlink.Link
	var err error
	link, err = netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	if !isXdpAttached(link) {
		return nil
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}
	for {
		link, err = netlink.LinkByIndex(Ifindex)
		if err != nil {
			return err
		}
		if !isXdpAttached(link) {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

// attachProgram attaches the given XDP program to the network interface.
func attachProgram(Ifindex int, program *ebpf.Program) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return err
	}
	return netlink.LinkSetXdpFdWithFlags(link, program.FD(), int(DefaultXdpFlags))
}
