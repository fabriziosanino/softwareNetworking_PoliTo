#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "network_monitor.h"
#include "network_monitor.skel.h"

static volatile int stop = 0;

int time = 0;

static void handle_sigint(int signo)
{
	stop = 1;
}

static char *iptype_to_proto(__u16 iptype)
{
	switch (iptype) {
		case 1: return "ICMP";
		case 6: return "TCP";
		case 14: return "TELNET";
		default: return "Unknown";
	}
}

/* Scans all the entries in the given eBPF map and prints their value */
static int dump_l3l4protos_map(struct bpf_map *map)
{
	int err;
	struct ip_port key;

	time += 1;

	printf("# Source IP\t sport\t Destination IP\t dport\t protocol\t pkt\tbytes\ttime\n");

	/* This libbpf helper allows to iterate over all keys of an eBPF map.
	 * Refer to its definition in libbpf.h for more details on how it works
	 */
	err = bpf_map__get_next_key(map, NULL, &key, sizeof(key));
	while (!err) {
		struct proto_stats val;
		if (bpf_map__lookup_elem(map, &key, sizeof(key), &val,
					 sizeof(val), 0)) {
			fprintf(stderr, "Error reading key from map: "
				"%s\n", strerror(errno));
			return -1;
		}

		if ( (time * 1000000000000000) - val.last_update > 1){
			bpf_map__delete_elem(map, &key, sizeof(key), 0);
		} else {
			printf("%d.%d.%d.%d\t %d\t %d.%d.%d.%d\t %d\t %s\t\t %li\t%li\t%lu\n",
			key.ip_src[0], key.ip_src[1], key.ip_src[2], key.ip_src[3],
			bpf_ntohs(key.port_src),
			key.ip_dst[0], key.ip_dst[1], key.ip_dst[2], key.ip_dst[3],
			bpf_ntohs(key.port_dst),
			iptype_to_proto(key.protocol),
			val.pkts, val.bytes, val.last_update);
		}

		err = bpf_map__get_next_key(map, &key, &key, sizeof(key));
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return -1;
	}

	unsigned ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		fprintf(stderr, "Unable to find interface %s\n", argv[1]);
		return -1;
	}

	/* The following instruction load the eBPF object, parsing its ELF
	 * definition and identifying programs and maps, and then proceeds to
	 * load the program(s) in the kernel and create the corresponding maps.
	 * Internally it relies on multiple bpf() syscalls, one for each
	 * program/map. This step is where the verifier can reject the program
	 */
	struct network_monitor_bpf *skel;
	skel = network_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open eBPF skeleton\n");
		return 1;
	}

	/* Declare two TC hook points, in ingress and egress. libbpf provides
	 * macros to initialize its data structures. The following macros create
	 * two structures of type struct bpf_tc_hook with name tc_hook_ingress
	 * and tc_hook_egress and fields zeroed or initilized with the values we
	 * provide
	 */
	LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = ifindex,
		    .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = ifindex,
		    .attach_point = BPF_TC_EGRESS);

	/* The next function creates the hook point. TC hook points correspond
	 * to the clsact qdisc (Classify Action Queuing Discipline) of the TC
	 * subsystem. A single qdisc supports programs both in ingress and
	 * egress, so we only need to create it once (e.g., for the ingress)
	 */
	int err = bpf_tc_hook_create(&tc_hook_ingress);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %s\n",
			strerror(errno));
		goto cleanup;
	}

	/* Attach the eBPF program to the TC ingress hook. eBPF programs are
	 * attached in TC mode as ingress or egress classification filters. Each
	 * filter has a unique handle and a priority, which determines the order
	 * of execution in case there are multiple filters attached to the same
	 * side
	 */
	LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1,
		    .prog_fd = bpf_program__fd(skel->progs.tc_prog));
	err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
	if (err) {
		fprintf(stderr, "Failed to attach TC ingress: %s\n",
			strerror(errno));
		goto cleanup;
	}

	/* Attach the eBPF program to the TC egress hook */
	LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 2, .priority = 1,
		    .prog_fd = bpf_program__fd(skel->progs.tc_prog));
	err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
	if (err) {
		fprintf(stderr, "Failed to attach TC egress: %s\n",
			strerror(errno));
		goto cleanup;
	}

	if (signal(SIGINT, handle_sigint)) {
		fprintf(stderr, "Error setting signal handler: %s\n",
			strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run "
	       "`sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output "
	       "of the BPF program.\n\n");

	/* Wait for program to be stopped and dump statistics */
	while (!stop) {
		sleep(1);

		err = dump_l3l4protos_map(skel->maps.l3l4protos_stats);
		if (err)
			goto cleanup;

		printf("\n");
	}

cleanup:
	/* Remove the eBPF filters */
	bpf_tc_hook_destroy(&tc_hook_ingress);
	bpf_tc_hook_destroy(&tc_hook_egress);
	/* Unload eBPF programs and maps and destory auxiliary data
	 * structures
	 */
	network_monitor_bpf__destroy(skel);
	return 1;
}