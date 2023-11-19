#include <stdint.h>

/* The statistics we are gonna collect for each l3 protocol and store in the
 * eBPF map
 */
/* Part 3 - Delete old entries*/
struct proto_stats {
	unsigned long pkts;
	unsigned long bytes;
	uint64_t last_update;
};

/*
 * The hashmap key for l3l4protos_stats
 */
struct ip_port
{
	__u8 ip_src[4]; // source address
	__u16 port_src;	  // source port
	__u8 ip_dst[4]; // destination address
	__u16 port_dst;	  // destination port
	//__u8 protocol; // level4 protocol
};

struct iphdr
{
	uint8_t lenver;	   // header length + version
	uint8_t ip_tos;	   // type of service
	uint16_t ip_len;   // total length
	uint16_t ip_id;	   // identification
	uint16_t ip_off;   // fragment offset valid
	uint8_t ip_ttl;	   // time to live
	uint8_t ip_p;	   // protocol
	uint16_t ip_sum;   // checksum
	uint8_t ip_src[4]; // source address
	uint8_t ip_dst[4]; // destination address
};

struct tcphdr
{
	uint16_t src_port; // source port
	uint16_t dst_port; // destination port
};