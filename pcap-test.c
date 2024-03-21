#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void printer(uint8_t* buffer, unsigned int num, char* delim){
	for(int i = 0; i < num; i++){ 
		if(num == 4) printf("%02d", buffer[i]); // ip addr
		else printf("%02x", buffer[i]); // max addr
		if(i == (num - 1)) break;
		printf("%s", delim);
	}
	printf("\n");
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen); // packet length

		/* Get Ethernet header */
		struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
		
		/* Get IP header */
		packet += sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;

		/* Get TCP header */
		packet += sizeof(struct libnet_ipv4_hdr);
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)packet;

		/* Get Data */
		packet += sizeof(struct libnet_tcp_hdr);
		uint8_t* data = (uint8_t*)packet;
		unsigned int datalen = header->caplen - (sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
		unsigned int maxlen = datalen > 20 ? 20 : datalen;

		uint16_t eth_type = ntohs(ethernet_hdr->ether_type);
		uint8_t protocol = ipv4_hdr->ip_p;

		/* Check Eth type */
		if(eth_type == ETHERTYPE_IP){
			/* Check Protocol */
			if(protocol == IPPROTO_TCP){
				/* print src & dst mac address */
				uint8_t* dst_addr = ethernet_hdr->ether_dhost;
				printf("Destination ethernet address\n");
				printer(dst_addr, ETHER_ADDR_LEN, ":");

				uint8_t* src_addr = ethernet_hdr->ether_shost;
				printf("Source ethernet address\n");
				printer(src_addr, ETHER_ADDR_LEN, ":");

				/* print src & dst ip */
				uint8_t* dst_ip = (uint8_t*)&ipv4_hdr->ip_dst;
				printf("Destination IP address\n");
				printer(dst_ip, sizeof(struct in_addr), ".");

				uint8_t* src_ip = (uint8_t*)&ipv4_hdr->ip_src;
				printf("Source IP address\n");
				printer(src_ip, sizeof(struct in_addr), ".");

				/* print src & dst port */
				uint16_t dst_port = ntohs(tcp_hdr->th_dport);
				printf("Destination port number : %d\n", dst_port);

				uint16_t src_port = ntohs(tcp_hdr->th_sport);
				printf("Source port number : %d\n", src_port);

				/* print Data(Max 20 bytes)*/
				printer(data, maxlen, " ");
				printf("\n");
			}
		}
	}

	pcap_close(pcap);
}
