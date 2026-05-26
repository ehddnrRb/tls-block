#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ETHER_ADDR_LEN 6

#define FIN  0x01
#define RST  0x04
#define ACK  0x10

void usage() {
	printf("syntax: tcp-block <interface> <pattern>\n");
	printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct {
	char* dev_;
	char* pattern_;
} Param;

Param param = {
	.dev_     = NULL,
	.pattern_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_     = argv[1];
	param->pattern_ = argv[2];
	return true;
}

// Ethernet header 먼저, 앞 4바이트
struct ethernet_hdr {
	uint8_t  dst_mac[ETHER_ADDR_LEN]; // destination mac addr 6 bytes
	uint8_t  src_mac[ETHER_ADDR_LEN]; // source mac addr 6 bytes
	uint16_t type;                    // type 2 bytes, IPv4 == 0x0800
};

// IPv4 Header 중간 20 bytes
struct ipv4_hdr {
	uint8_t  ver_ihl;  // version(4bit) + header length(4bit)
	uint8_t  ip_tos;
	uint16_t ip_len;   // total length
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t  ip_ttl;
	uint8_t  ip_p;     // protocol, TCP == 6
	uint16_t ip_cs;    // checksum
	uint32_t ip_scr;   // source ip address
	uint32_t ip_dst;   // destination ip address
};

// TCP Header 20바이트
struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t  dataoffset_reserved;
	uint8_t  flags;
	uint16_t win_size;
	uint16_t checksum;
	uint16_t urg_ptr;
};

uint16_t calc_checksum(const void* buf, int len) {
	const uint16_t* now = (const uint16_t*)buf;
	uint32_t sum = 0; // carry 발생 생각해서 32비트로 계산해야함.
	
    for (; len > 1; len -= 2) sum += *now++; // 16비트씩 더함

	if (len) sum += *(const uint8_t*)now; // len이 홀수일 때 마지막 바이트 더하기

	while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
	return (uint16_t)(~sum); // checksum == 1의 보수
}

void set_ip_checksum(struct ipv4_hdr* ip) {
	int hlen = (ip->ver_ihl & 0x0F) * 4;
	ip->ip_cs = 0;
	ip->ip_cs = calc_checksum(ip, hlen);
}

void set_tcp_checksum(const struct ipv4_hdr* ip, struct tcp_hdr* tcp, const uint8_t* payload, int plen) {
	tcp->checksum = 0;
	int tcp_len = (int)sizeof(struct tcp_hdr) + plen;
	uint8_t* buf = (uint8_t*)calloc(1, 12 + tcp_len);

    // 짭 IP header + TCP header + payload
	memcpy(buf + 0, &ip->ip_scr, 4);
	memcpy(buf + 4, &ip->ip_dst, 4);
	buf[8] = 0;
	buf[9] = ip->ip_p;
	uint16_t tl = htons((uint16_t)tcp_len);
	memcpy(buf + 10, &tl, 2);
	memcpy(buf + 12, tcp, sizeof(struct tcp_hdr));
	if (payload && plen > 0)
		memcpy(buf + 12 + sizeof(struct tcp_hdr), payload, plen);

	tcp->checksum = calc_checksum(buf, 12 + tcp_len);
	free(buf);
}

// 정방향: client → server 방향으로 RST 패킷 전송
void forward_rst(pcap_t* pcap, const struct ethernet_hdr* eth_hdr, const struct ipv4_hdr* ip_hdr, const struct tcp_hdr* tcp_hdr, int data_len) {
	int pkt_len = sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);
	uint8_t* pkt = (uint8_t*)calloc(1, pkt_len);

	struct ethernet_hdr* eth = (struct ethernet_hdr*)pkt;
	struct ipv4_hdr* ip  = (struct ipv4_hdr*)(pkt + sizeof(struct ethernet_hdr));
	struct tcp_hdr*  tcp = (struct tcp_hdr*)(pkt + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr));

	// Ethernet
	memcpy(eth->dst_mac, eth_hdr->dst_mac, ETHER_ADDR_LEN);
	memcpy(eth->src_mac, eth_hdr->src_mac, ETHER_ADDR_LEN);
	eth->type = htons(0x0800);

	// IPv4
	ip->ver_ihl = 0x45;
	ip->ip_tos  = 0;
	ip->ip_len  = htons(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
	ip->ip_id   = 0;
	ip->ip_off  = htons(0x4000);
	ip->ip_ttl  = 64;
	ip->ip_p    = IPPROTO_TCP;
	ip->ip_scr  = ip_hdr->ip_scr;
	ip->ip_dst  = ip_hdr->ip_dst;
	set_ip_checksum(ip);

	// TCP RST
	tcp->src_port            = tcp_hdr->src_port;
	tcp->dst_port            = tcp_hdr->dst_port;
	tcp->seq_num             = htonl(ntohl(tcp_hdr->seq_num) + data_len);
	tcp->ack_num             = tcp_hdr->ack_num;
	tcp->dataoffset_reserved = (uint8_t)((sizeof(struct tcp_hdr) / 4) << 4);
	tcp->flags               = RST | ACK;
	tcp->win_size            = 0;
	tcp->urg_ptr             = 0;
	set_tcp_checksum(ip, tcp, NULL, 0);

	if (pcap_sendpacket(pcap, pkt, pkt_len) != 0)
		fprintf(stderr, "pcap_sendpacket(RST) return error - %s\n", pcap_geterr(pcap));
	else
		printf("[+] RST(forward) sent\n");

	free(pkt);
}

// 역방향: server → client 방향으로 FIN+redirect 패킷 전송 (IP header를 알아서 넣기 위해 raw socket 사용)
void backward_fin(const struct ipv4_hdr* ip_hdr, const struct tcp_hdr* tcp_hdr, int data_len) {
	static const char redirect[] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	int redir_len = (int)strlen(redirect);
	int pkt_len   = (int)(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr)) + redir_len;

	uint8_t* pkt = (uint8_t*)calloc(1, pkt_len);
	struct ipv4_hdr* ip  = (struct ipv4_hdr*)pkt;
	struct tcp_hdr*  tcp = (struct tcp_hdr*)(pkt + sizeof(struct ipv4_hdr));
	uint8_t*         dat = pkt + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

	memcpy(dat, redirect, redir_len);

	// IPv4 (역방향: server → client)
	ip->ver_ihl = 0x45;
	ip->ip_tos  = 0;
	ip->ip_len  = htons((uint16_t)pkt_len);
	ip->ip_id   = 0;
	ip->ip_off  = htons(0x4000);
	ip->ip_ttl  = 64;
	ip->ip_p    = IPPROTO_TCP;
	ip->ip_scr  = ip_hdr->ip_dst;  // server IP
	ip->ip_dst  = ip_hdr->ip_scr;  // client IP
	set_ip_checksum(ip);

	// TCP FIN
	tcp->src_port            = tcp_hdr->dst_port;          // server port
	tcp->dst_port            = tcp_hdr->src_port;          // client port
	tcp->seq_num             = tcp_hdr->ack_num;            // server seq = client's ack
	tcp->ack_num             = htonl(ntohl(tcp_hdr->seq_num) + data_len);
	tcp->dataoffset_reserved = (uint8_t)((sizeof(struct tcp_hdr) / 4) << 4);
	tcp->flags               = FIN | ACK;
	tcp->win_size            = htons(65535);
	tcp->urg_ptr             = 0;
	set_tcp_checksum(ip, tcp, (const uint8_t*)redirect, redir_len);

	int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_fd < 0) {
		perror("socket(IPPROTO_RAW)");
		free(pkt);
		return;
	}

	int one = 1;
	setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)); // IP헤더를 직접 넣겠다고 알림.

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = ip_hdr->ip_scr;  // client IP

	if (sendto(raw_fd, pkt, pkt_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) // raw socket으로 패킷을 전송한다.
		perror("sendto(FIN)");
	else
		printf("[+] FIN+Redirect success!!\n");

	close(raw_fd);
	free(pkt);
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

	printf("[*] Listening on %s, blocking pattern: \"%s\"\n", param.dev_, param.pattern_);
	int pat_len = (int)strlen(param.pattern_);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// Ethernet
		const struct ethernet_hdr* eth_hdr = (const struct ethernet_hdr*)packet;
		uint16_t type_1 = ntohs(eth_hdr->type);
		if (type_1 != 0x0800) continue;

		// IPv4
		const u_char* ip_start = packet + sizeof(struct ethernet_hdr);
		const struct ipv4_hdr* ip_hdr = (const struct ipv4_hdr*)ip_start;
		uint8_t ip_hl  = ip_hdr->ver_ihl & 0x0F;
		uint8_t ip_len = ip_hl * 4;
		if (ip_hdr->ip_p != 6) continue;

		// TCP
		const struct tcp_hdr* tcp_hdr = (const struct tcp_hdr*)(ip_start + ip_len);
		uint8_t dataoffset = ((tcp_hdr->dataoffset_reserved & 0xF0) >> 4) * 4;

		// TCP Data
		const u_char* data = ip_start + ip_len + dataoffset;
		int data_len = ntohs(ip_hdr->ip_len) - ip_len - dataoffset;
		if (data_len <= 0 || data_len < pat_len) continue;

		// pattern 검색, 문자열 하나하나 대조
		bool found = false;
		for (int i = 0; i <= data_len - pat_len; i++) {
			if (memcmp(data + i, param.pattern_, pat_len) == 0) {
				found = true;
				break;
			}
		}
		if (!found) continue;

		printf("[*] Find block pattern: %s\n", param.pattern_);
		forward_rst(pcap, eth_hdr, ip_hdr, tcp_hdr, data_len);
		backward_fin(ip_hdr, tcp_hdr, data_len);
	}

	pcap_close(pcap);
}
