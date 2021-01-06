#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iothdns.h>

int any_cb (int section, struct iothdns_rr *rr, void *arg) {
	printf("section %d qtype %d %s\n", section, rr->type, rr->name);
	return 0;
}

int main(int argc, char *argv[]) {
  struct iothdns *ns = iothdns_init_strcfg(NULL, 
			"search v2.cs.unibo.it cs.unibo.it\n"
			"nameserver 8.8.8.8");
  char ipstr[INET6_ADDRSTRLEN];
  struct in_addr ipaddr[1];
  struct in6_addr ipaddr6[1];
  int rv = iothdns_lookup_a(ns, argv[1], ipaddr, 1);
  printf("%d %s\n", rv, inet_ntop(AF_INET, ipaddr, ipstr, INET6_ADDRSTRLEN));
  rv = iothdns_lookup_aaaa(ns, argv[1], ipaddr6, 1);
  printf("%d %s\n", rv, inet_ntop(AF_INET6, ipaddr6, ipstr, INET6_ADDRSTRLEN));
  rv = iothdns_lookup_cb_tcp(ns, argv[1], IOTHDNS_TYPE_ANY, any_cb, NULL);

  iothdns_fini(ns);
}

