#ifndef IOTHDNS_GETHOST_H
#define IOTHDNS_GETHOST_H

/* iothdns_gethost maps a hostname string to its corresponding IP or IPv6 address
 * using a file following the syntax of hosts(5) */
int iothdns_gethost(char *hostfile, int af, const char *hostname, void *dst);

/* iothdns_gethost_rev maps an IP orIPv6 address to the corresponding hostname
 * using a file following the syntax of hosts(5) */
int iothdns_gethost_rev(char *hostfile, int af, void *addr, char *host, size_t hostlen);

#endif
