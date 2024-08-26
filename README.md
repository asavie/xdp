**The project is continued here:** https://github.com/slavc/xdp

https://github.com/asavie/xdp is now archived.

----

# xdp

[![Go Reference](https://pkg.go.dev/badge/github.com/asavie/xdp.svg)](https://pkg.go.dev/github.com/asavie/xdp)

Package github.com/asavie/xdp allows one to use [XDP sockets](https://lwn.net/Articles/750845/) from the Go programming language.

For usage examples, see the [documentation](https://pkg.go.dev/github.com/asavie/xdp) or the [examples/](https://github.com/asavie/xdp/tree/master/examples) directory.

## Performance

### examples/sendudp

With the default UDP payload size of 1400 bytes, running on Linux kernel
5.1.20, on a
[tg3](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/broadcom/tg3.c)
(so no native XDP support) gigabit NIC,
[sendudp.go](https://github.com/asavie/xdp/blob/master/examples/sendudp/sendudp.go)
does around 980 Mb/s, so practically line rate.

### examples/senddnsqueries

TL;DR: in the same environment, sending a pre-generated DNS query using an
ordinary UDP socket yields around 30 MiB/s whereas sending it using the
[senddnsqueries.go](https://github.com/asavie/xdp/blob/master/examples/senddnsqueries/senddnsqueries.go)
example program yields around 77 MiB/s.

Connecting a PC with Intel Core i7-7700 CPU running Linux kernel 5.0.17 and igb
driver to a laptop with Intel Core i7-5600U CPU running Linux kernel 5.0.9 with
e1000e with a cat 5E gigabit ethernet cable and using the following program
```go
package main

import (
	"net"

	"github.com/miekg/dns"
)

func main() {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn("asavie.com"), dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp", "192.168.111.10:53")
	if err != nil {
		panic(err)
	}

	for {
		_, err = conn.WriteTo(payload, dst)
		if err != nil {
			panic(err)
		}
	}
}
```
which uses an ordinary UDP socket to send a pre-generated DNS query from PC to
laptop as quickly as possible - I get about 30 MiB/s at laptop side.

Using the [senddnsqueries.go](https://github.com/asavie/xdp/blob/master/examples/senddnsqueries/senddnsqueries.go)
example program - I get about 77 MiB/s at laptop side.

