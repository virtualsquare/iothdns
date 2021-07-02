#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iothdns.h>

int any_cb (int section, struct iothdns_rr *rr, struct iothdns_pkt *vpkt, void *arg) {
	(void) arg;
	char buf[IOTHDNS_MAXNAME];
	printf("section %d qtype %d %s\n", section, rr->type, rr->name);
	switch (rr->type) {
		case IOTHDNS_TYPE_CNAME:
			iothdns_get_name(vpkt, buf);
			printf("cname %s\n", buf);
			break;
		case IOTHDNS_TYPE_NS:
			iothdns_get_name(vpkt, buf);
			printf("name server %s\n", buf);
			break;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	struct iothdns *ns = iothdns_init_strcfg(NULL,
			"search v2.cs.unibo.it cs.unibo.it\n"
			"nameserver 8.8.8.8");
	char ipstr[INET6_ADDRSTRLEN];
	struct in_addr ipaddr[1];
	struct in6_addr ipaddr6[1];
	char *qname = (argc > 1) ? argv[1] : "";
	int rv = iothdns_lookup_a(ns, qname, ipaddr, 1);
	printf("%d %s\n", rv, inet_ntop(AF_INET, ipaddr, ipstr, INET6_ADDRSTRLEN));
	rv = iothdns_lookup_aaaa(ns, qname, ipaddr6, 1);
	printf("%d %s\n", rv, inet_ntop(AF_INET6, ipaddr6, ipstr, INET6_ADDRSTRLEN));
	rv = iothdns_lookup_cb_tcp(ns, qname, IOTHDNS_TYPE_ANY, any_cb, NULL);
	iothdns_fini(ns);
}

