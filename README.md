xdp
===

[![GoDoc](https://godoc.org/github.com/asavie/xdp?status.svg)](https://godoc.org/github.com/asavie/xdp)

Package github.com/asavie/xdp allows one to use [XDP sockets](https://lwn.net/Articles/750845/) from the Go programming language.

Here is a minimal example of a program which receives network frames, modifies
their destination MAC address in-place to broadcast address and transmits them
back out the same network link:
```go
package main

import (
	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
)

func main() {
	const NetworkDevice = "enp3s0"
	const QueueID = 0

	link, err := netlink.LinkByName(NetworkDevice)
	if err != nil {
		panic(err)
	}

	xsk, err := xdp.NewSocket(link.Attrs().Index, QueueID)
	if err != nil {
		panic(err)
	}

	for {
		xsk.Fill(xsk.GetDescs(xsk.GetFreeFillSlots()))
		numRx, _, err := xsk.WaitForEvents(-1)
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
```
