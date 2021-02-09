// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
Package xdp allows to use XDP sockets from Go.

An XDP socket allows to get packets from a network interface driver into
a userspace process very fast, bypassing the Linux kernel's network
stack, see https://lwn.net/Articles/750845/ for more information.

NOTE:

* If your network link device supports multiple queues - you might
not see all of the incoming traffic because it might be e.g. load-balanced
between multiple queues. You can use the `ethtool -L` command to control the
load-balancing behaviour or even make it so that all of the incoming traffic
is put on a single queue.

* On recent versions of Linux kernel, the eBPF map memory counts towards the
"locked memory" user limit, so most likely you'll have to increase it. On
Fedora Linux, this can be done by running `ulimit -l <new-limit>` command, or
to make it permanent, by creating a file at
`/etc/security/limits.d/50-lockedmem.conf` with e.g. the following contents
(1MiB should be enough for this package):
	* - lockedmem 1048576
logging out and logging back in.
When you hit this limit, you'll get an error that looks like this:
	error: failed to create an XDP socket: ebpf.NewMap qidconf_map failed: map create: operation not permitted

Here is a minimal example of a program which receives network frames,
modifies their destination MAC address in-place to broadcast address and
transmits them back out the same network link:

	package main

	import (
		"os"
		"os/signal"
		"syscall"

		"github.com/asavie/xdp"
		"github.com/vishvananda/netlink"
	)

	func main() {
		const LinkName = "enp6s0"
		const QueueID = 0

		link, err := netlink.LinkByName(LinkName)
		if err != nil {
			panic(err)
		}

		program, err := xdp.NewProgram(QueueID + 1)
		if err != nil {
			panic(err)
		}
		if err := program.Attach(link.Attrs().Index); err != nil {
			panic(err)
		}

		xsk, err := xdp.NewSocket(link.Attrs().Index, QueueID, nil)
		if err != nil {
			panic(err)
		}

		if err := program.Register(QueueID, xsk.FD()); err != nil {
			panic(err)
		}

		// Remove the XDP BPF program on interrupt.
		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			program.Detach(link.Attrs().Index)
			os.Exit(1)
		}()

		for {
			xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots()))
			numRx, _, err := xsk.Poll(-1)
			if err != nil {
				panic(err)
			}
			rxDescs := xsk.Receive(numRx)
			for i := 0; i < len(rxDescs); i++ {
				// Set destination MAC address to
				// ff:ff:ff:ff:ff:ff
				frame := xsk.GetFrame(rxDescs[i])
				for i := 0; i < 6; i++ {
					frame[i] = byte(0xff)
				}
			}
			xsk.Transmit(rxDescs)
		}
	}
*/
package xdp

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// DefaultSocketOptions is the default SocketOptions used by an xdp.Socket created without specifying options.
var DefaultSocketOptions = SocketOptions{
	NumFrames:              128,
	FrameSize:              2048,
	FillRingNumDescs:       64,
	CompletionRingNumDescs: 64,
	RxRingNumDescs:         64,
	TxRingNumDescs:         64,
}

type umemRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []uint64
}

type rxTxRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []Desc
}

// A Socket is an implementation of the AF_XDP Linux socket type for reading packets from a device.
type Socket struct {
	fd             int
	umem           []byte
	fillRing       umemRing
	rxRing         rxTxRing
	txRing         rxTxRing
	completionRing umemRing
	qidconfMap     *ebpf.Map
	xsksMap        *ebpf.Map
	program        *ebpf.Program
	ifindex        int
	numTransmitted int
	numFilled      int
	freeDescs      []bool
	options        SocketOptions
	rxDescs        []Desc
	getDescs       []Desc
}

// SocketOptions are configuration settings used to bind an XDP socket.
type SocketOptions struct {
	NumFrames              int
	FrameSize              int
	FillRingNumDescs       int
	CompletionRingNumDescs int
	RxRingNumDescs         int
	TxRingNumDescs         int
}

// Desc represents an XDP Rx/Tx descriptor.
type Desc unix.XDPDesc

// Stats contains various counters of the XDP socket, such as numbers of
// sent/received frames.
type Stats struct {
	// Filled is the number of items consumed thus far by the Linux kernel
	// from the Fill ring queue.
	Filled uint64

	// Received is the number of items consumed thus far by the user of
	// this package from the Rx ring queue.
	Received uint64

	// Transmitted is the number of items consumed thus far by the Linux
	// kernel from the Tx ring queue.
	Transmitted uint64

	// Completed is the number of items consumed thus far by the user of
	// this package from the Completion ring queue.
	Completed uint64

	// KernelStats contains the in-kernel statistics of the corresponding
	// XDP socket, such as the number of invalid descriptors that were
	// submitted into Fill or Tx ring queues.
	KernelStats unix.XDPStatistics
}

// DefaultSocketFlags are the flags which are passed to bind(2) system call
// when the XDP socket is bound, possible values include unix.XDP_SHARED_UMEM,
// unix.XDP_COPY, unix.XDP_ZEROCOPY.
var DefaultSocketFlags uint16

// DefaultXdpFlags are the flags which are passed when the XDP program is
// attached to the network link, possible values include
// unix.XDP_FLAGS_DRV_MODE, unix.XDP_FLAGS_HW_MODE, unix.XDP_FLAGS_SKB_MODE,
// unix.XDP_FLAGS_UPDATE_IF_NOEXIST.
var DefaultXdpFlags uint32

func init() {
	DefaultSocketFlags = 0
	DefaultXdpFlags = 0
}

// NewSocket returns a new XDP socket attached to the network interface which
// has the given interface, and attached to the given queue on that network
// interface.
func NewSocket(Ifindex int, QueueID int, options *SocketOptions) (xsk *Socket, err error) {
	if options == nil {
		options = &DefaultSocketOptions
	}
	xsk = &Socket{fd: -1, ifindex: Ifindex, options: *options}

	xsk.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("syscall.Socket failed: %v", err)
	}

	xsk.umem, err = syscall.Mmap(-1, 0, options.NumFrames*options.FrameSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("syscall.Mmap failed: %v", err)
	}

	xdpUmemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&xsk.umem[0]))),
		Len:      uint64(len(xsk.umem)),
		Size:     uint32(options.FrameSize),
		Headroom: 0,
	}

	var errno syscall.Errno
	var rc uintptr

	rc, _, errno = unix.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&xdpUmemReg)),
		unsafe.Sizeof(xdpUmemReg), 0)
	if rc != 0 {
		xsk.Close()
		return nil, fmt.Errorf("unix.SetsockoptUint64 XDP_UMEM_REG failed: %v", errno)
	}

	err = syscall.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING,
		options.FillRingNumDescs)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("unix.SetsockoptUint64 XDP_UMEM_FILL_RING failed: %v", err)
	}

	err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING,
		options.CompletionRingNumDescs)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("unix.SetsockoptUint64 XDP_UMEM_COMPLETION_RING failed: %v", err)
	}

	var rxRing bool
	if options.RxRingNumDescs > 0 {
		err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_RX_RING,
			options.RxRingNumDescs)
		if err != nil {
			xsk.Close()
			return nil, fmt.Errorf("unix.SetsockoptUint64 XDP_RX_RING failed: %v", err)
		}
		rxRing = true
	}

	var txRing bool
	if options.TxRingNumDescs > 0 {
		err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_TX_RING,
			options.TxRingNumDescs)
		if err != nil {
			xsk.Close()
			return nil, fmt.Errorf("unix.SetsockoptUint64 XDP_TX_RING failed: %v", err)
		}
		txRing = true
	}

	if !(rxRing || txRing) {
		return nil, fmt.Errorf("RxRingNumDescs and TxRingNumDescs cannot both be set to zero")
	}

	var offsets unix.XDPMmapOffsets
	var vallen uint32
	vallen = uint32(unsafe.Sizeof(offsets))
	rc, _, errno = unix.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&vallen)), 0)
	if rc != 0 {
		xsk.Close()
		return nil, fmt.Errorf("unix.Syscall6 getsockopt XDP_MMAP_OFFSETS failed: %v", errno)
	}

	fillRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.Fr.Desc+uint64(options.FillRingNumDescs)*uint64(unsafe.Sizeof(uint64(0)))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("syscall.Mmap XDP_UMEM_PGOFF_FILL_RING failed: %v", err)
	}

	xsk.fillRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Producer)))
	xsk.fillRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Consumer)))
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&xsk.fillRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Desc)
	sh.Len = options.FillRingNumDescs
	sh.Cap = options.FillRingNumDescs

	completionRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.Cr.Desc+uint64(options.CompletionRingNumDescs)*uint64(unsafe.Sizeof(uint64(0)))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("syscall.Mmap XDP_UMEM_PGOFF_COMPLETION_RING failed: %v", err)
	}

	xsk.completionRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Producer)))
	xsk.completionRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Consumer)))
	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.completionRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Desc)
	sh.Len = options.CompletionRingNumDescs
	sh.Cap = options.CompletionRingNumDescs

	if rxRing {
		rxRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_PGOFF_RX_RING,
			int(offsets.Rx.Desc+uint64(options.RxRingNumDescs)*uint64(unsafe.Sizeof(Desc{}))),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			xsk.Close()
			return nil, fmt.Errorf("syscall.Mmap XDP_PGOFF_RX_RING failed: %v", err)
		}

		xsk.rxRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Producer)))
		xsk.rxRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Consumer)))
		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.rxRing.Descs))
		sh.Data = uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Desc)
		sh.Len = options.RxRingNumDescs
		sh.Cap = options.RxRingNumDescs

		xsk.rxDescs = make([]Desc, 0, options.RxRingNumDescs)
	}

	if txRing {
		txRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_PGOFF_TX_RING,
			int(offsets.Tx.Desc+uint64(options.TxRingNumDescs)*uint64(unsafe.Sizeof(Desc{}))),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			xsk.Close()
			return nil, fmt.Errorf("syscall.Mmap XDP_PGOFF_TX_RING failed: %v", err)
		}

		xsk.txRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Producer)))
		xsk.txRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Consumer)))
		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.txRing.Descs))
		sh.Data = uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Desc)
		sh.Len = options.TxRingNumDescs
		sh.Cap = options.TxRingNumDescs
	}

	sa := unix.SockaddrXDP{
		Flags:   DefaultSocketFlags,
		Ifindex: uint32(Ifindex),
		QueueID: uint32(QueueID),
	}
	if err = unix.Bind(xsk.fd, &sa); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("syscall.Bind SockaddrXDP failed: %v", err)
	}

	xsk.freeDescs = make([]bool, options.NumFrames)
	for i := 0; i < options.NumFrames; i++ {
		xsk.freeDescs[i] = true
	}
	xsk.getDescs = make([]Desc, 0, options.NumFrames)

	return xsk, nil
}

// Fill submits the given descriptors to be filled (i.e. to receive frames into)
// it returns how many descriptors where actually put onto Fill ring queue.
// The descriptors can be acquired either by calling the GetDescs() method or
// by calling Receive() method.
func (xsk *Socket) Fill(descs []Desc) int {
	numFreeSlots := xsk.NumFreeFillSlots()
	if numFreeSlots < len(descs) {
		descs = descs[:numFreeSlots]
	}

	prod := *xsk.fillRing.Producer
	for _, desc := range descs {
		xsk.fillRing.Descs[prod&uint32(xsk.options.FillRingNumDescs-1)] = desc.Addr
		prod++
		xsk.freeDescs[desc.Addr/uint64(xsk.options.FrameSize)] = false
	}
	//fencer.SFence()
	*xsk.fillRing.Producer = prod

	xsk.numFilled += len(descs)

	return len(descs)
}

// Receive returns the descriptors which were filled, i.e. into which frames
// were received into.
func (xsk *Socket) Receive(num int) []Desc {
	numAvailable := xsk.NumReceived()
	if num > int(numAvailable) {
		num = int(numAvailable)
	}

	descs := xsk.rxDescs[:0]
	cons := *xsk.rxRing.Consumer
	//fencer.LFence()
	for i := 0; i < num; i++ {
		descs = append(descs, xsk.rxRing.Descs[cons&uint32(xsk.options.RxRingNumDescs-1)])
		cons++
		xsk.freeDescs[descs[i].Addr/uint64(xsk.options.FrameSize)] = true
	}
	//fencer.MFence()
	*xsk.rxRing.Consumer = cons

	xsk.numFilled -= len(descs)

	return descs
}

// Transmit submits the given descriptors to be sent out, it returns how many
// descriptors were actually pushed onto the Tx ring queue.
// The descriptors can be acquired either by calling the GetDescs() method or
// by calling Receive() method.
func (xsk *Socket) Transmit(descs []Desc) (numSubmitted int) {
	numFreeSlots := xsk.NumFreeTxSlots()
	if len(descs) > numFreeSlots {
		descs = descs[:numFreeSlots]
	}

	prod := *xsk.txRing.Producer
	for _, desc := range descs {
		xsk.txRing.Descs[prod&uint32(xsk.options.TxRingNumDescs-1)] = desc
		prod++
		xsk.freeDescs[desc.Addr/uint64(xsk.options.FrameSize)] = false
	}
	//fencer.SFence()
	*xsk.txRing.Producer = prod

	xsk.numTransmitted += len(descs)

	numSubmitted = len(descs)

	var rc uintptr
	var errno syscall.Errno
	for {
		rc, _, errno = unix.Syscall6(syscall.SYS_SENDTO,
			uintptr(xsk.fd),
			0, 0,
			uintptr(unix.MSG_DONTWAIT),
			0, 0)
		if rc != 0 {
			switch errno {
			case unix.EINTR:
				// try again
			case unix.EAGAIN:
				return
			case unix.EBUSY: // "completed but not sent"
				return
			default:
				panic(fmt.Errorf("sendto failed with rc=%d and errno=%d", rc, errno))
			}
		} else {
			break
		}
	}

	return
}

// FD returns the file descriptor associated with this xdp.Socket which can be
// used e.g. to do polling.
func (xsk *Socket) FD() int {
	return xsk.fd
}

// Poll blocks until kernel informs us that it has either received
// or completed (i.e. actually sent) some frames that were previously submitted
// using Fill() or Transmit() methods.
// The numReceived return value can be used as the argument for subsequent
// Receive() method call.
func (xsk *Socket) Poll(timeout int) (numReceived int, numCompleted int, err error) {
	var events int16
	if xsk.numFilled > 0 {
		events |= unix.POLLIN
	}
	if xsk.numTransmitted > 0 {
		events |= unix.POLLOUT
	}
	if events == 0 {
		return
	}

	var pfds [1]unix.PollFd
	pfds[0].Fd = int32(xsk.fd)
	pfds[0].Events = events
	for err = unix.EINTR; err == unix.EINTR; {
		_, err = unix.Poll(pfds[:], timeout)
	}
	if err != nil {
		return 0, 0, err
	}

	numReceived = xsk.NumReceived()
	if numCompleted = xsk.NumCompleted(); numCompleted > 0 {
		xsk.Complete(numCompleted)
	}

	return
}

// GetDescs returns up to n descriptors which are not currently in use.
func (xsk *Socket) GetDescs(n int) []Desc {
	if n > len(xsk.freeDescs) {
		n = len(xsk.freeDescs)
	}
	descs := xsk.getDescs[:0]
	j := 0
	for i := 0; i < len(xsk.freeDescs) && j < n; i++ {
		if xsk.freeDescs[i] == true {
			descs = append(descs, Desc{
				Addr: uint64(i) * uint64(xsk.options.FrameSize),
				Len:  uint32(xsk.options.FrameSize),
			})
			j++
		}
	}
	return descs
}

// GetFrame returns the buffer containing the frame corresponding to the given
// descriptor. The returned byte slice points to the actual buffer of the
// corresponding frame, so modiyfing this slice modifies the frame contents.
func (xsk *Socket) GetFrame(d Desc) []byte {
	return xsk.umem[d.Addr : d.Addr+uint64(d.Len)]
}

// Close closes and frees the resources allocated by the Socket.
func (xsk *Socket) Close() error {
	allErrors := []error{}
	var err error

	if xsk.fd != -1 {
		if err = unix.Close(xsk.fd); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to close XDP socket: %v", err))
		}
		xsk.fd = -1

		var sh *reflect.SliceHeader

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.completionRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.txRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.rxRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.fillRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0
	}

	if xsk.umem != nil {
		if err := syscall.Munmap(xsk.umem); err != nil {
			allErrors = append(allErrors, fmt.Errorf("failed to unmap the UMEM: %v", err))
		}
		xsk.umem = nil
	}

	if len(allErrors) > 0 {
		return allErrors[0]
	}

	return nil
}

// Complete consumes up to n descriptors from the Completion ring queue to
// which the kernel produces when it has actually transmitted a descriptor it
// got from Tx ring queue.
// You should use this method if you are doing polling on the xdp.Socket file
// descriptor yourself, rather than using the Poll() method.
func (xsk *Socket) Complete(n int) {
	cons := *xsk.completionRing.Consumer
	//fencer.LFence()
	for i := 0; i < n; i++ {
		addr := xsk.completionRing.Descs[cons&uint32(xsk.options.CompletionRingNumDescs-1)]
		cons++
		xsk.freeDescs[addr/uint64(xsk.options.FrameSize)] = true
	}
	//fencer.MFence()
	*xsk.completionRing.Consumer = cons

	xsk.numTransmitted -= n
}

// NumFreeFillSlots returns how many free slots are available on the Fill ring
// queue, i.e. the queue to which we produce descriptors which should be filled
// by the kernel with incoming frames.
func (xsk *Socket) NumFreeFillSlots() int {
	prod := *xsk.fillRing.Producer
	cons := *xsk.fillRing.Consumer
	max := uint32(xsk.options.FillRingNumDescs)

	n := max - (prod - cons)
	if n > max {
		n = max
	}

	return int(n)
}

// NumFreeTxSlots returns how many free slots are available on the Tx ring
// queue, i.e. the queue to which we produce descriptors which should be
// transmitted by the kernel to the wire.
func (xsk *Socket) NumFreeTxSlots() int {
	prod := *xsk.txRing.Producer
	cons := *xsk.txRing.Consumer
	max := uint32(xsk.options.TxRingNumDescs)

	n := max - (prod - cons)
	if n > max {
		n = max
	}

	return int(n)
}

// NumReceived returns how many descriptors are there on the Rx ring queue
// which were produced by the kernel and which we have not yet consumed.
func (xsk *Socket) NumReceived() int {
	prod := *xsk.rxRing.Producer
	cons := *xsk.rxRing.Consumer
	max := uint32(xsk.options.RxRingNumDescs)

	n := prod - cons
	if n > max {
		n = max
	}

	return int(n)
}

// NumCompleted returns how many descriptors are there on the Completion ring
// queue which were produced by the kernel and which we have not yet consumed.
func (xsk *Socket) NumCompleted() int {
	prod := *xsk.completionRing.Producer
	cons := *xsk.completionRing.Consumer
	max := uint32(xsk.options.CompletionRingNumDescs)

	n := prod - cons
	if n > max {
		n = max
	}

	return int(n)
}

// NumFilled returns how many descriptors are there on the Fill ring
// queue which have not yet been consumed by the kernel.
// This method is useful if you're polling the xdp.Socket file descriptor
// yourself, rather than using the Poll() method - if it returns a number
// greater than zero it means you should set the unix.POLLIN flag.
func (xsk *Socket) NumFilled() int {
	return xsk.numFilled
}

// NumTransmitted returns how many descriptors are there on the Tx ring queue
// which have not yet been consumed by the kernel.
// Note that even after the descriptors are consumed by the kernel from the Tx
// ring queue, it doesn't mean that they have actually been sent out on the
// wire, that can be assumed only after the descriptors have been produced by
// the kernel to the Completion ring queue.
// This method is useful if you're polling the xdp.Socket file descriptor
// yourself, rather than using the Poll() method - if it returns a number
// greater than zero it means you should set the unix.POLLOUT flag.
func (xsk *Socket) NumTransmitted() int {
	return xsk.numTransmitted
}

// Stats returns various statistics for this XDP socket.
func (xsk *Socket) Stats() (Stats, error) {
	var stats Stats
	var size uint64

	stats.Filled = uint64(*xsk.fillRing.Consumer)
	stats.Received = uint64(*xsk.rxRing.Consumer)
	if xsk.txRing.Consumer != nil {
		stats.Transmitted = uint64(*xsk.txRing.Consumer)
	}
	if xsk.completionRing.Consumer != nil {
		stats.Completed = uint64(*xsk.completionRing.Consumer)
	}
	size = uint64(unsafe.Sizeof(stats.KernelStats))
	rc, _, errno := unix.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_STATISTICS,
		uintptr(unsafe.Pointer(&stats.KernelStats)),
		uintptr(unsafe.Pointer(&size)), 0)
	if rc != 0 {
		return stats, fmt.Errorf("getsockopt XDP_STATISTICS failed with errno %d", errno)
	}
	return stats, nil
}
