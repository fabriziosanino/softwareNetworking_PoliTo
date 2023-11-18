#include <errno.h>	     /* Error codes */
#include <linux/bpf.h>	     /* Definition of struct __sk_buff, the parameter
			      * passed to our eBPF program
			      */
#include <linux/pkt_cls.h>   /* Definition of valid return codes for eBPF
			      * programs attached to the TC hook
			      * (e.g. TC_ACT_OK)
			      */
#include <linux/if_ether.h>  /* Definition of struct ethhdr */
//#include <linux/ip.h>	     /* Definition of struct iphdr */
//#include <linux/tcp.h>	     /* Definition of struct tcphdr */
#include <linux/udp.h>	     /* Definition of struct udphdr */
#include <bpf/bpf_endian.h>  /* Helpers to convert endiannes
			      * (e.g., bpf_ntohs())
			      */
#include <bpf/bpf_helpers.h> /* Other libbpf helpers (e.g., bpf_printk()) */

#include "network_monitor.h"

#include <stdint.h>
#include <string.h>

struct iphdr
{
	uint8_t lenver;	// header length + version
	uint8_t ip_tos;	// type of service
	uint16_t ip_len;	// total length
	uint16_t ip_id;	// identification
	uint16_t ip_off;	// fragment offset valid
	uint8_t ip_ttl;	// time to live
	uint8_t ip_p;		// protocol
	uint16_t ip_sum;	// checksum
	uint8_t ip_src[4]; // source address
	uint8_t ip_dst[4]; // destination address
};

struct tcphdr
{
	uint16_t src_port; // source port
	uint16_t dst_port; // destination port
};

/* Define a hash map with key of type __u16 (the size of the ethertype), value
 * of type struct l3proto_stats and a max size of 1024 elements
 */
/*struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u16);
	__type(value, struct l3proto_stats);
} l3protos_stats SEC(".maps");*/

/* Define a hash map with key of type struct ip_port (source ip, source port, destination ip, destination port), value
 * of type struct proto_stats and a max size of 1024 elements
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 150);
	__type(key, struct ip_port);
	__type(value, struct proto_stats);
} l3l4protos_stats SEC(".maps");

/* The main program that will be executed every time the hook is triggered.
 * The SEC("tc") macro provides a hint to libbpf to where the program will be
 * attached.
 * Programs attached to the TC hook receive as input a struct __sk_buff, that
 * contains metadata of the handled packet
 * (https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.hL6103)
 */
SEC("tc")
int tc_prog(struct __sk_buff *ctx)
{
	/* Retrieve pointers to the begin and end of the packet buffer */
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;

	/* Interpret the first part of the packet as an ethernet header */
	struct ethhdr *eth = data;

	/* Every time we access the packet buffer the eBPF verifier requires us
	 * to explicitly check that the address we are accessing doesn't exceed
	 * the buffer limits
	 */
	if (data + sizeof(*eth) > data_end) {
		/* The packet is malformed, the TC_ACT_SHOT return code
		 * instructs the kernel to drop it
		 */
		return TC_ACT_SHOT;
	}

	if(bpf_ntohs(eth->h_proto) == 0x800) {
		bpf_printk("IP PACKET\n");

		/* Interpret the second part of the packet as an ip header */
		struct iphdr *ip = data + sizeof(*eth);

		if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		{
			/* The packet is malformed, the TC_ACT_SHOT return code
			 * instructs the kernel to drop it
			 */
			return TC_ACT_SHOT;
		}

		uint8_t ip_len = 4 * (ip->lenver & 0X0F); // Shift to get only len value

		/* Interpret the third part of the packet as tcp header */
		struct tcphdr *tcp = data + sizeof(*eth) + ip_len + 2;

		if (data + sizeof(*eth) + ip_len + sizeof(*tcp) + 20 > data_end)
		{
			/* The packet is malformed, the TC_ACT_SHOT return code
			 * instructs the kernel to drop it
			 */
			return TC_ACT_SHOT;
		}

		/* Look for an existing entry in the hash map */
		struct ip_port key;
		memcpy(key.ip_src, ip->ip_src, sizeof(__u8) * 4);
		memcpy(key.ip_dst, ip->ip_dst, sizeof(__u8) * 4);
		key.port_src = tcp->src_port;
		key.port_dst = tcp->dst_port;
		key.protocol = ip->ip_p;

		struct proto_stats *val;
		val = bpf_map_lookup_elem(&l3l4protos_stats, &key);

		/* The value might be NULL if there is no element for the given key
		 * (i.e., this is the first packet we process with this key "ip_source, port_source, ...").
		 * The check on the validity of the pointer is MANDATORY even if we know
		 * that it cannot be NULL due to the program logic. Without the check
		 * the eBPF program would be rejected by the verifier at injection time,
		 * as in the case of packet boundary checks
		 */
		if (!val) {
			/* Preapare a new entry for the given ethertype */
			struct proto_stats new_val;
			new_val.pkts = 0;
			new_val.bytes = 0;


			/* The eBPF program can be executed concurrently on different
			* CPU cores, and another core might be creating/updating the
			* same entry in parallel. To prevent overwriting its values we
			* use the BPF_NOEXIST flag, that adds the entry only if it
			* doesn't already exist
			*/
			int rc = bpf_map_update_elem(&l3l4protos_stats, &key, &new_val, BPF_NOEXIST);
			if (rc != 0 && rc != -EEXIST) {
				/* The update failed (rc != 0), and it's not beacuse the
				* entry already existed (rc != -EEXIST). The map is
				* probably full. We let the packet proceed without
				* counting
				*/
				return TC_ACT_OK;
			}

			/* Retrieve a pointer to the newly inserted value */
			val = bpf_map_lookup_elem(&l3l4protos_stats, &key);
			if (!val) {
				/* This should never happen, however the check is
				* MANDATORY for the verifier to guarantee the safety
				* of the program
				*/
				return TC_ACT_OK;
			}

		}

		/* Since we are updating values concurrently on multiple cores we use
		 * the __sync_fetch_and_add() instruction that guarantees an atomic
		 * operation
		 */
		__sync_fetch_and_add(&val->pkts, 1);
		__sync_fetch_and_add(&val->bytes, (data_end - data));

		/* The bpf_trace_printk() helper can be used to print debug messages to
		 * the kernel trace pipe. The pipe is accessible reading the file
		 * /sys/kernel/debug/tracing/trace_pipe. The function bpf_printk() is a
		 * libbpf wrapper around the actual eBPF helper
		 */
		/*bpf_printk("Processed packet with l3proto 0x%04x\n",
			   bpf_ntohs(eth->h_proto));*/
	} else {
		bpf_printk("NO IP PACKET\n");
	}

	/* The TC_ACT_OK return code lets the packet proceed up in the network
	 * stack for ingress packets or out of a net device for egress ones
	 */
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";