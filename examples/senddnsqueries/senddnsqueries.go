/*
senddnsqueries pre-generates a frame with a DNS query and starts sending it in
and endless loop to given destination as fast as possible.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

// ...
var (
	NIC        string
	QueueID    int
	SrcMAC     string
	DstMAC     string
	SrcIP      string
	DstIP      string
	DomainName string
)

func main() {
	flag.StringVar(&NIC, "interface", "enp3s0", "Network interface to attach to.")
	flag.IntVar(&QueueID, "queue", 0, "The queue on the network interface to attach to.")
	flag.StringVar(&SrcMAC, "srcmac", "b2968175b211", "Source MAC address to use in sent frames.")
	flag.StringVar(&DstMAC, "dstmac", "ffffffffffff", "Destination MAC address to use in sent frames.")
	flag.StringVar(&SrcIP, "srcip", "192.168.111.1", "Source IP address to use in sent frames.")
	flag.StringVar(&DstIP, "dstip", "192.168.111.10", "Destination IP address to use in sent frames.")
	flag.StringVar(&DomainName, "domain", "asavie.com", "Domain name to use in the DNS query.")
	flag.Parse()

	// Initialize the XDP socket.

	link, err := netlink.LinkByName(NIC)
	if err != nil {
		panic(err)
	}

	xsk, err := xdp.NewSocket(link.Attrs().Index, QueueID)
	if err != nil {
		panic(err)
	}

	// Pre-generate a frame containing a DNS query.

	srcMAC, _ := hex.DecodeString(SrcMAC)
	dstMAC, _ := hex.DecodeString(DstMAC)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC),
		DstMAC:       net.HardwareAddr(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(SrcIP).To4(),
		DstIP:    net.ParseIP(DstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: 1234,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(DomainName), dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		panic(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	frameLen := len(buf.Bytes())

	// Fill all the frames in UMEM with the pre-generated DNS query frame.

	descs := xsk.GetDescs(math.MaxInt32)
	for i := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
	}

	// Start sending the pre-generated frame as quickly as possible in an
	// endless loop printing statistics of the number of sent frames and
	// the number of sent bytes every second.

	fmt.Printf("sending DNS queries from %v (%v) to %v (%v) for domain name %s...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC, DomainName)

	go func() {
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		var numPkts uint64
		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1) * time.Second)
			cur, err = xsk.Stats()
			if err != nil {
				panic(err)
			}
			numPkts = cur.Completed - prev.Completed
			fmt.Printf("%d packets/s (%d bytes/s)\n", numPkts, numPkts*uint64(frameLen))
			prev = cur
		}
	}()

	for {
		descs := xsk.GetDescs(xsk.NumFreeTxSlots())
		for i := range descs {
			descs[i].Len = uint32(frameLen)
		}
		xsk.Transmit(descs)

		_, _, err = xsk.Poll(1)
		if err != nil {
			panic(err)
		}
	}
}
