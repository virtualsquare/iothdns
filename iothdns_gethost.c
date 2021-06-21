/*
 *   iothdns.c: client and server utility functions for dns packets RFC 1035 (and updates)
 *   iothdns_getaddrinfo and ioth_getnameinfo: parse a file like hosts(5)
 *
 *   Copyright 2021 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 *   This library is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or (at
 *   your option) any later version.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <iothdns_gethost.h>

#define BLANKS " \t\n"
#define DIGITS "0123456789"
#define EXA DIGITS "abcdefABCDEF"
#define ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz"

struct hostparse {
	char *addr, *alias;
};

static inline void hostclear(struct hostparse *host) {
	host->addr = host->alias = NULL;
}

static int hostparseline(char *s, struct hostparse *host) {
	hostclear(host);
	s += strspn(s, BLANKS);
	if (*s == '#' || *s == 0) return 0;
	if (strchr(EXA ":", *s) == NULL) return -1;
	host->addr = s;
	s += strspn(s, EXA ".:");
	if (strchr(BLANKS, *s) == NULL) return -1;
	s += strspn(s, BLANKS);
	if (*s == '#') return 0;
	else if (strchr(ALPHA, *s) != NULL) {
		host->alias = s;
		return 0;
	} else
		return -1;
}

static int hostmatch(const char *hostname, char *s) {
	size_t hostnamelen = strlen(hostname); 
	if (s == NULL) return 0;
	while (*s != 0) {
		s += strspn(s, BLANKS);
		if (strchr(ALPHA DIGITS "-.", *s) == NULL) break;
		if (strncmp(hostname, s, hostnamelen) == 0 && 
				(s[hostnamelen] == 0 || strchr(BLANKS, s[hostnamelen])))
			return 1;
		s += strspn(s, ALPHA DIGITS "-.");
		if (strchr(BLANKS, *s) == NULL) break;
	}
	return 0;
}

/* iothdns_gethost maps a hostname string to its corresponding IP or IPv6 address
 * using a file following the syntax of hosts(5) */
int iothdns_gethost(char *hostfile, int af, const char *hostname, void *dst) {
	int retval = 0;
	FILE *f = fopen(hostfile, "r");
	if (f == NULL) return 0;
	char *line = NULL;
	size_t ll;
	while (getline(&line, &ll, f) > 0) {
		struct hostparse host;
		if (hostparseline(line, &host) == 0) {
			if (hostmatch(hostname, host.alias)) {
				size_t addrlen = strspn(host.addr, EXA ".:");
				char addr[addrlen + 1];
				snprintf(addr, addrlen + 1, "%s", host.addr);
				if (inet_pton(af, addr, dst) == 1) {
					retval = 1;
					break;
				}
			}
		}
	}
	fclose(f);
	if (line) free(line);
	return retval;
}

/* iothdns_gethost_rev maps an IP orIPv6 address to the corresponding hostname
 * using a file following the syntax of hosts(5) */
int iothdns_gethost_rev(char *hostfile, int af, void *addr, char *serv, size_t servlen) {
	int retval = 0;
	FILE *f = fopen(hostfile, "r");
	if (f == NULL) return 0;
	char *line = NULL;
	size_t ll;
	while (getline(&line, &ll, f) > 0) {
		struct hostparse host;
		if (hostparseline(line, &host) == 0) {
			if (host.addr) {
				unsigned char testaddr[sizeof(struct in6_addr)];
				char str[INET6_ADDRSTRLEN];
				snprintf(str, INET6_ADDRSTRLEN, "%.*s", (int) strspn(host.addr, EXA ".:"), host.addr);
				if (inet_pton(af, str, testaddr) == 1 &&
						memcmp(addr, testaddr,
							(af == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr))
						== 0) {
					retval = snprintf(serv, servlen, "%.*s",
							(int) strspn(host.alias, ALPHA DIGITS "-."), host.alias);
					break;
				}
			}
		}
	}
	fclose(f);
	if (line) free(line);
	return retval;
}
