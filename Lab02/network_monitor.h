/* The statistics we are gonna collect for each l3 protocol and store in the
 * eBPF map
 */
struct proto_stats {
	unsigned long pkts;
	unsigned long bytes;
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
	__u8 protocol; // level4 protocol
};