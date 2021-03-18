// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>


#define MAX_SOCKS 64

static volatile unsigned const char PROTO;
static volatile unsigned const char PROTO = IPPROTO_ICMP;

#define __bpf_constant_htons(x) ___constant_swab16(x)

//Ensure map references are available.
/*
        These will be initiated from go and 
        referenced in the end BPF opcodes by file descriptor
*/

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") qidconf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};


SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{

	int *qidconf, index = ctx->rx_queue_index;

	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;

	// redirect udp packets to an xdp socket; pass all other packets to the kernel
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) <= data_end) {
		struct iphdr *ip = data + sizeof(*eth);
		if ((void*)ip + sizeof(*ip) <= data_end) {
		if (ip->protocol == PROTO) {
				if (*qidconf)
					return bpf_redirect_map(&xsks_map, index, 0);
			}
		}
	}

	return XDP_PASS;
}

//Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
