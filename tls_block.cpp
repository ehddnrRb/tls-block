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
#include <time.h>

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

// =============================================================================
// TCP Segmentation Reassembly
// Client Hello가 여러 TCP 패킷으로 쪼개져서 올 수 있어서
// 패킷 단위가 아니라 flow(연결) 단위로 데이터를 모아야 SNI를 꺼낼 수 있음
// flow는 (src_ip, dst_ip, src_port, dst_port) 4개로 식별
// =============================================================================
#define MAX_FLOWS    512        // 동시에 추적할 수 있는 flow 최대 개수
#define MAX_FLOW_BUF 16384      // 하나의 flow당 버퍼 크기 최대값.
#define FLOW_TIMEOUT 10         // 마지막 패킷 수신 후 10초 지나면 만료 처리

// flow를 식별하는 키 (TCP 5-tuple에서 protocol 제외)
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// flow별로 쌓아두는 데이터 엔트리
struct flow_entry {
    struct flow_key key;            // 어떤 연결인지 식별용
    uint8_t  buf[MAX_FLOW_BUF];    // 지금까지 모은 TCP 데이터 조각
    int      buf_len;               // 버퍼에 쌓인 바이트 수
    time_t   last_seen;             // 마지막으로 패킷 받은 시각
    bool     active;                // 이 슬롯이 사용 중인지 여부
};

// flow 테이블 전역 배열 (정적 할당, 최대 512개 동시 추적)
static struct flow_entry g_flows[MAX_FLOWS];

// 키에 해당하는 flow가 있으면 반환, 없으면 NULL
static struct flow_entry* find_flow(const struct flow_key* k) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!g_flows[i].active) continue; // 비어있는 슬롯은 건너뜀
        struct flow_key* fk = &g_flows[i].key;
        // 4개 필드 전부 일치해야 같은 flow
        if (fk->src_ip == k->src_ip && fk->dst_ip == k->dst_ip &&
            fk->src_port == k->src_port && fk->dst_port == k->dst_port)
            return &g_flows[i];
    }
    return NULL;
}

// 새 flow 슬롯 할당 - 비어있는 슬롯 우선, 없으면 가장 오래된 것 덮어씀
static struct flow_entry* alloc_flow(const struct flow_key* k) {
    time_t now = time(NULL);
    int slot = 0;
    time_t oldest = now + 1;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!g_flows[i].active) { slot = i; goto found; }
        // 활성 슬롯 중 가장 오래된 것 기록
        if (g_flows[i].last_seen < oldest) { oldest = g_flows[i].last_seen; slot = i; }
    }
found:
    // 슬롯 초기화
    g_flows[slot].key      = *k;
    g_flows[slot].buf_len  = 0;
    g_flows[slot].last_seen = now;
    g_flows[slot].active   = true;
    return &g_flows[slot];
}

// 10초 이상 패킷이 안 온 flow는 비활성화 
static void expire_flows(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_FLOWS; i++)
        if (g_flows[i].active && now - g_flows[i].last_seen > FLOW_TIMEOUT)
            g_flows[i].active = false;
}

// =============================================================================

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

bool extract_sni(const uint8_t* data, int data_len, char* out, int out_size){
	int p=0;
	if(data_len < 5) return false; 
	// TLS Record Header가 5바이트이므로, 최소 5이다!

	if (data[0] != 0x16) return false; // TLS Handshake(0x16)인지 확인.
	p=5;

	if(p+4 > data_len) return false; 
	// Handshake Header가 4바이트이므로 최소 9이다!
	if (data[p] != 0x01) return false; // ClientHello인지 확인할것.
	p+=4; // handshake header == 4바이트, 건너뛰기.

	p+=34; // client_version(2바이트) + random(32바이트)만큼 건너뛰기
	if(p >= data_len) return false;

	int session_id_len = data[p];
	p+=1+session_id_len; // session_id_len을 불러오고, 그만큼 + 1(session_id_len의 길이 = 1바이트)건너뛰기
	if(p + 2 > data_len) return false; // cipher_suites_len(2바이트) + 최소 2바이트의 cipher suite이므로, 최소 2이다
	
	int cipher_suites_len = (data[p] << 8) | data[p+1];
	p+=2+cipher_suites_len; // cipher_suites_len을 불러오고, 그만큼 + 2(cipher_suites_len의 길이 = 2바이트)건너뛰기
	if(p +1 > data_len) return false; // compression_methods_len(1바이트) + 최소 1바이트의 compression method이므로, 최소 1이다

	int compression_methods_len = data[p];
	p+=1+compression_methods_len; // compression_methods_len을 불러오고, 그만큼 + 1(compression_methods_len의 길이 = 1바이트)건너뛰기
	if(p + 2 > data_len) return false; // extensions읽기 시작(extension len 2바이트)

	int extension_total_len = (data[p] << 8) | data[p+1];
	p+=2; // extension_total_len의 길이 = 2바이트
	int extension_end = p + extension_total_len;
	if(extension_end > data_len) extension_end = data_len; 
	// extension_total_len이 실제 남은 데이터보다 길면, 남은 데이터까지만 읽도록 한다. -> 중간에 끊기는 상황을 가정함(TCP Segmentation)

	while(p+4 <= extension_end){
		int extension_type = (data[p] << 8) | data[p+1];
		int extension_len = (data[p+2] << 8) | data[p+3];
		p+=4; // extension_type(2바이트) + extension_len(2바이트)
		if (extension_type == 0x0000){ // SNI extension일 경우
			int sp = p;
			sp+=2; // server name list length
			if(sp + 3 > extension_end) return false; // server name type(1바이트) + server name length(2바이트) + 최소 1바이트의 server name이므로, 최소 3이다.

			int name_len = (data[sp+1] << 8) | data[sp+2];
			sp+=3; // server name type(1바이트) + server name length(2바이트)
			if(sp + name_len > extension_end) return false; // server name이 extension의 끝을 넘어가지 않는지 확인
			if(name_len >= out_size) name_len = out_size -1; // out 버퍼에 name_len이 들어가지 않을 때, 버퍼 크기에 맞게 name_len 조정
			memcpy(out, data + sp, name_len);
			out[name_len] = '\0';
			return true;
		}
		p += extension_len; // SNI extension이 아니면 extension의 길이만큼 건너뛰어야한다!
	}

	return false; // SNI extension이 없는 경우

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
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // lo로 라우팅 → IFB 우회, 로컬 TCP 스택 즉시 전달

	if (sendto(raw_fd, pkt, pkt_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) // raw socket으로 패킷을 전송한다.
		perror("sendto(FIN)");
	else
		printf("[+] FIN+Redirect success!!\n");

	close(raw_fd);
	free(pkt);
}

void backward_rst(const struct ipv4_hdr* ip_hdr, const struct tcp_hdr* tcp_hdr, int data_len) {
	int pkt_len = sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);
	uint8_t* pkt = (uint8_t*)calloc(1, pkt_len);
	struct ipv4_hdr* ip  = (struct ipv4_hdr*)pkt;
	struct tcp_hdr*  tcp = (struct tcp_hdr*)(pkt + sizeof(struct ipv4_hdr));

	// IPv4 (server -> client)
	ip->ver_ihl = 0x45;
	ip->ip_len = htons((uint16_t)pkt_len);
	ip->ip_off = htons(0x4000);
	ip->ip_ttl = 128;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_scr = ip_hdr->ip_dst; // server IP
	ip->ip_dst = ip_hdr->ip_scr; // client IP
	set_ip_checksum(ip);

	// TCP RST (server -> client)
	tcp->src_port = tcp_hdr->dst_port; // server port
	tcp->dst_port = tcp_hdr->src_port; // client port
	tcp->seq_num = tcp_hdr->ack_num; // server seq num == client ack num
	tcp->ack_num = htonl(ntohl(tcp_hdr->seq_num) + data_len);
	tcp->dataoffset_reserved = (uint8_t)((sizeof(struct tcp_hdr) / 4) << 4);
	tcp->flags = RST | ACK;
	tcp->win_size = 0;
	tcp->urg_ptr = 0;
	set_tcp_checksum(ip, tcp, NULL, 0);

	int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_fd < 0) {
		perror("socket(IPPROTO_RAW)");
		free(pkt);
		return;
	}

	int one=1;
	setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)); // IP헤더를 직접 넣겠다고 알림.

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // lo로 라우팅 → IFB 우회, 로컬 TCP 스택 즉시 
	// 사용 이유 :: lo를 통해 더 빠르게 backward rst를 클라이언트에게 전달할 수 있다.

	printf("[debug] backward seq=%u ack=%u win=%u\n",
		ntohl(tcp->seq_num), ntohl(tcp->ack_num), ntohs(tcp->win_size));
	printf("[debug] captured cli_seq=%u cli_ack=%u data_len=%d\n",
       ntohl(tcp_hdr->seq_num), ntohl(tcp_hdr->ack_num), data_len);

	if (sendto(raw_fd, pkt, pkt_len, 0, (struct sockaddr*)&sin, sizeof(sin)) < 0) // raw socket으로 패킷을 전송한다.
		perror("sendto(RST)");
	else
		printf("[+] RST(backward) sent\n");
	
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

	int pkt_count = 0;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// 1000 패킷마다 만료된 flow 정리
		if (++pkt_count % 1000 == 0) expire_flows();

		// Ethernet
		const struct ethernet_hdr* eth_hdr = (const struct ethernet_hdr*)packet;
		if (ntohs(eth_hdr->type) != 0x0800) continue;

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
		if (data_len <= 0) continue;

		// RST/FIN 오면 그 flow 추적 중단 (연결 끊긴 거니까 더 볼 필요 없음)
		if (tcp_hdr->flags & (RST | FIN )) {
			struct flow_key fkey = {
				ip_hdr->ip_scr, ip_hdr->ip_dst,
				tcp_hdr->src_port, tcp_hdr->dst_port
			};
			struct flow_entry* fe = find_flow(&fkey);
			if (fe) fe->active = false;
			continue;
		}

		// 현재 패킷의 flow 키 생성 (src_ip, dst_ip, src_port, dst_port)
		struct flow_key fkey = {
			ip_hdr->ip_scr, ip_hdr->ip_dst,
			tcp_hdr->src_port, tcp_hdr->dst_port
		};
		struct flow_entry* fe = find_flow(&fkey);

		if (!fe) {
			// 아직 추적 중이 아닌 flow인데, 첫 바이트가 0x16이면 TLS Handshake 시작
			// 0x16이 아니면 TLS가 아니니까 무시
			if (data[0] != 0x16) continue;
			fe = alloc_flow(&fkey); // 새 슬롯 할당해서 추적 시작
		}

		int space = MAX_FLOW_BUF - fe->buf_len;
		if (space > 0) {
			int copy = (data_len < space) ? data_len : space; // 버퍼 넘치지 않게 조절
			memcpy(fe->buf + fe->buf_len, data, copy);        // buf 끝에 이어붙임
			fe->buf_len += copy;
		}
		fe->last_seen = time(NULL); // 마지막 패킷 수신 시각 업데이트

		// 지금까지 모인 버퍼로 SNI 추출 시도
		char sni[256];
		if (!extract_sni(fe->buf, fe->buf_len, sni, sizeof(sni))) {
			// 단, 버퍼가 꽉 찼는데도 SNI 못 찾으면 이 flow는 포기
			if (fe->buf_len >= MAX_FLOW_BUF) fe->active = false;
			continue;
		}

		// SNI 패턴 매칭
		if (strstr(sni, param.pattern_) == NULL) {
			fe->active = false; // 차단 대상 아님, 추적 중단
			continue;
		}

		printf("[*] SNI Founded! Blocked SNI: %s\n", sni);
		fe->active = false; // 차단 이후 추적 stop

		// 양방향으로 RST 전송해서 TLS 연결 강제 종료
		forward_rst(pcap, eth_hdr, ip_hdr, tcp_hdr, data_len);  // client → server 방향
		backward_rst(ip_hdr, tcp_hdr, data_len);                 // server → client 방향
	}

	pcap_close(pcap);
}
