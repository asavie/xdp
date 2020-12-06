// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
rebroadcast demonstrates how to receive and transmit network frames using
the github.com/asavie/xdp package, it receives frames on the given network
interface using an XDP socket, prints the received frames to stdout,
modifies their the destination MAC address to the broadcast address of
ff:ff:ff:ff:ff:ff in-line and sends the frames back out the same network
interface.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	var linkName string
	var queueID int

	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link on which rebroadcast should run on.")
	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Parse()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == linkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	// Create and initialize an XDP socket attached to our chosen network
	// link.
	xsk, err := xdp.NewSocket(Ifindex, queueID)
	if err != nil {
		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
		return
	}

	for numPkts := 0; ; numPkts++ {
		fmt.Printf(">>> ITERATION %d <<<\n", numPkts)

		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n))
		}

		// Wait for events: either receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue; or completion - meaning the
		// kernel finished sending one or more frames, previously
		// produced by us onto Tx ring queue, and has produced onto the
		// Completion ring queue.
		// Both events mean that some descriptors are not-in-use any
		// more and can be recycled.
		fmt.Printf("waiting for events...\n")
		numRx, numCompl, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}
		fmt.Printf("received: %d\ncompleted: %d\n", numRx, numCompl)

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)

			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				pktData := xsk.GetFrame(rxDescs[i])
				pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
				fmt.Printf("received frame %d:\nhexdump:\n%s\n\n%+v\n\n", i, hex.Dump(pktData[:]), pkt)

				// Set destination MAC address to
				// ff:ff:ff:ff:ff:ff, i.e. the broadcast
				// address.
				for i := 0; i < 6; i++ {
					pktData[i] = byte(0xff)
				}
			}

			// Send the modified frames back out.
			n := xsk.Transmit(rxDescs)
			fmt.Printf("sent: %d\n", n)
		}
	}
}
