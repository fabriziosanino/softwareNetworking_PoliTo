//Standard C include file for I/O functions
#include <stdio.h>

//Include files for libpcap functions
#include <pcap.h>

#include <string.h>

#define LINE_LEN 16

#define ETHLEN 14
#define IPLEN 20
#define TCPLEN 32

struct ether_header {
	u_int8_t ether_dhost[6]; //6 bytes destination address
	u_int8_t ether_shost[6]; //6 bytes source address
	u_int16_t ether_type;    //2 bytes ethertype
};

struct ip_header {
	u_int8_t lenver;	//header length + version
	u_int8_t ip_tos;	//type of service
	u_int16_t ip_len;	//total length
	u_int16_t ip_id;	//identification
	u_int16_t ip_off; 	//fragment offset valid
	u_int8_t ip_ttl;	//time to live
	u_int8_t ip_p;		//protocol
	u_int16_t ip_sum;	//checksum
	u_int8_t ip_src[4];	//source address
	u_int8_t ip_dst[4];	//destination address
};

struct tcp_header {
	u_int16_t src_port;	//source port
	u_int16_t dst_port;	//destination port
};

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv) {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = "enp1s0";
	
	/* Open the capture file */
	if((handle = pcap_open_live(device, BUFSIZ, 1, 10000, errbuf)) == NULL) {
		fprintf(stderr, "Could not open device %s: %s.\n\n", device, errbuf);
		return -1;
	}

	pcap_loop(handle, 0, dispatcher_handler, NULL);
	
	pcap_close(handle);
	return 0;
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct ether_header *eptr; //Pointer to the ether_header structure
	u_int16_t ethertype;       //Variable that keeps the ethertype in host-based format

	struct ip_header *ipptr;   //Pointer to the ip_header structure
	u_int8_t ip_len;	   //Variable that keeps the ip header length in host format

	struct tcp_header *tcpptr; //Pointer to the tcp_header structure
	u_int16_t src_port;	   //Variable to keeps the source port in host-based format
	u_int16_t dst_port;	   //Variable to keeps the destination port in host based format

	char http_header[800];     //Variable to keeps the http header

	char *start_pos;
	char *end_pos;
	char host_value[200];
	char *location = "Referer: ";	
	
	/* print pkt timestamp and pkt len */
	printf("%ld:%ld ", header->ts.tv_sec, header->ts.tv_usec);
	
	
	if(header->caplen > ETHLEN) {
		/* Parse FRAME */
		eptr = (struct ether_header *) pkt_data;
		/* Print on scree the MAC addresses of each packet */
		printf("%02x:%02x:%02x:%02x:%02x:%02x --> %02x:%02x:%02x:%02x:%02x:%02x", 
			eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2],
			eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5],
			eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2],
			eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);

		ethertype = ntohs(eptr->ether_type); // Converting ethertype from network to host byte order

		printf(" 0x%04x ", ethertype);

		if(ethertype == 0x800 && header->caplen > (ETHLEN + IPLEN)) {
			/* Parse PACKET */
			ipptr = (struct ip_header *) &pkt_data[ETHLEN];

			ip_len = (ntohs(ipptr->lenver) >> 4) & 0X0F;  //Shit to get only len value

			printf("%d.%d.%d.%d --> %d.%d.%d.%d", 
				ipptr->ip_src[0], ipptr->ip_src[1], ipptr->ip_src[2], ipptr->ip_src[3], 
				ipptr->ip_dst[0], ipptr->ip_dst[1], ipptr->ip_dst[2], ipptr->ip_dst[3]); 

			if(header->caplen > (ETHLEN + IPLEN + TCPLEN)) {
				/* Parse TRANSPORT */
				tcpptr = (struct tcp_header *) &pkt_data[ETHLEN + ip_len];

				src_port = ntohs(tcpptr->src_port);
				dst_port = ntohs(tcpptr->dst_port);

				printf(" %d -> %d", src_port, dst_port);

				if(dst_port == 80){
					/* Parse HTTP */
					memcpy(http_header, &pkt_data[ETHLEN + IPLEN + TCPLEN], 750);
					http_header[750] = '\0';
					
					if(strstr(http_header, "HTTP") != NULL) {
						start_pos = strstr(http_header, location);
						end_pos = strstr(start_pos, "\r\n");
						
						size_t length = end_pos - start_pos - strlen(location);
						if(length > 0 && start_pos > 0 && end_pos > start_pos){
							strncpy(host_value, start_pos + strlen(location), length);					


							printf(" %s", host_value);
						}
					}
				}
					
			}	
		}

		printf("\n");
	}
}