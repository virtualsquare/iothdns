#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iothdns.h>

struct iothdns_pkt *parse_pkt(struct iothdns_header *h, void *arg) {
	(void) arg;
	struct iothdns_pkt *pkt;
	if (strcmp(h->qname, "test.fake") == 0) {
		struct iothdns_rr rr = {h->qname, 1, 1, 600, 0};
		uint8_t addr[] = {10, 20, 30, 40};
		h->flags = 0x8500;
		pkt = iothdns_put_header(h);
		if (h->qtype == IOTHDNS_TYPE_A || h->qtype == IOTHDNS_TYPE_ANY) {
			iothdns_put_rr(IOTHDNS_TYPE_A, pkt, &rr);
			iothdns_put_a(pkt, addr);
		}
	} else {
		h->flags = 0x8503;
		pkt = iothdns_put_header(h);
	}
	return pkt;
}

int main(int argc, char *argv[]) {
	(void) argc;
	(void) argv;
	struct sockaddr_in sserv = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(53)};
	int s = ioth_msocket(NULL, AF_INET, SOCK_DGRAM, 0);
	ioth_bind(s, (struct sockaddr *)&sserv, sizeof(sserv));
	int t = ioth_msocket(NULL, AF_INET, SOCK_STREAM, 0);
	ioth_bind(t, (struct sockaddr *)&sserv, sizeof(sserv));
	ioth_listen(t, 5);

	struct pollfd pfd[] = {{s, POLLIN, 0}, {t, POLLIN, 0}};

	for (;;) {
		poll(pfd, 2, -1);
		if (pfd[0].revents)
			iothdns_udp_process_request(s, parse_pkt, NULL);
		if (pfd[1].revents) {
			int conn = ioth_accept(t, NULL, 0);
			iothdns_tcp_process_request(conn, parse_pkt, NULL);
			ioth_close(conn);
		}
	}
}
