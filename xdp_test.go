package xdp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	ipproto "github.com/asavie/xdp/examples/dumpframes/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const ICPPROTO_UDP = 17

const queueID = 0

func TestXDPSocket(t *testing.T) {
	// borrow example/dumpframes ebpf for test
	filter, queues, sockets, err := ipproto.NewIPProtoProgram(uint32(ICPPROTO_UDP), nil)
	if err != nil {
		t.Fatalf("error: failed to create xdp program: %v", err)
	}
	program := &Program{Program: filter, Queues: queues, Sockets: sockets}
	defer program.Close()

	// use loopback interface
	// TODO: use flag / env var, or discover usable interface?
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("could not resolve interface: %v", err)
	}

	if err := program.Attach(iface.Index); err != nil {
		t.Fatalf("failed to attach xdp program to interface: %v", err)
	}
	defer program.Detach(iface.Index)

	xsk, err := NewSocket(iface.Index, queueID, &SocketOptions{
		NumFrames:              2048,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         2048,
		TxRingNumDescs:         2048,
	})
	if err != nil {
		t.Fatalf("failed to create an XDP socket: %v", err)
	}
	defer xsk.Close()
	if err := program.Register(queueID, xsk.FD()); err != nil {
		t.Fatalf("error: failed to register socket in BPF map: %v", err)
	}
	defer program.Unregister(queueID)

	// read packets via xdp socket
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	packets := []int{}
	go func() {
		drain(ctx, xsk, func(buf []byte) {
			packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
			udp := packet.Layer(layers.LayerTypeUDP)
			i, err := strconv.Atoi(string(udp.LayerPayload()))
			if err != nil {
				fmt.Println("malformed packet:", packet)
				return
			}
			packets = append(packets, i)
		})
		wg.Done()
	}()

	// start sending packets to localhost
	count := 1000
	if err := sendUDP(count); err != nil {
		t.Fatal(err)
	}
	cancel()  // stop reading the xdp socket
	wg.Wait() // drain goroutine is finished
	xsk.Close()

	// verify packet count matches sent payloads
	if len(packets) != count {
		t.Fatalf("expected packet count: %d; got: %d", count, len(packets))
	}

	// verify packets were received in order
	lastPacket := -1
	for _, p := range packets {
		if lastPacket+1 != p {
			t.Fatalf("expected packet: %d; got: %d", lastPacket+1, p)
		}
		lastPacket = p
	}
}

func sendUDP(count int) error {
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		if _, err := conn.WriteTo([]byte(fmt.Sprintf("%d", i)), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}); err != nil {
			fmt.Println("write err", err)
			return err
		}
	}
	return nil
}

func drain(ctx context.Context, xsk *Socket, packetHandler func([]byte)) error {
	for {
		// TODO: can we remove context ? if poll != -1, will this loop error if socket is closed?
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if n := xsk.NumFreeFillSlots(); n > 0 {
			xsk.Fill(xsk.GetDescs(n, true))
		}
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			return err
		}
		if numRx > 0 {
			rxDescs := xsk.Receive(numRx)
			for i := 0; i < len(rxDescs); i++ {
				pktData := xsk.GetFrame(rxDescs[i])
				packetHandler(pktData)
			}

		}
	}
}
