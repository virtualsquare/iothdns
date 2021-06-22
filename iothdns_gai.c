/*
 *   iothdns.c: client and server utility functions for dns packets RFC 1035 (and updates)
 *   iothdns_getaddrinfo and ioth_getnameinfo implementation
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

#include <stdlib.h>
#include <limits.h>
#include <iothdns.h>
#include <iothdns_getserv.h>
#include <iothdns_gethost.h>
#include <arpa/inet.h>

#define DIGITS "0123456789"

static struct addrinfo default_hints = {
	.ai_flags = 0, // ck: glibc default is AI_V4MAPPED | AI_ADDRCONFIG
	.ai_family = AF_UNSPEC,
	.ai_socktype = 0,
	.ai_protocol = 0,
};

struct ioth_gaiport {
	int socktype;
	char *protocol;
	int port;
};

struct ioth_gaidata {
	const struct addrinfo *hints;
	struct ioth_gaiport *gaiport;
	char *canonname;
	struct addrinfo **next;
};

static int setprotocol(const struct addrinfo *hints, int socktype) {
	switch (socktype) {
		case SOCK_STREAM:
			switch (hints->ai_protocol) {
				case IPPROTO_TCP:
				case IPPROTO_SCTP:
					return hints->ai_protocol;
				default:
					return IPPROTO_TCP;
			}
		case SOCK_DGRAM:
			switch (hints->ai_protocol) {
				case IPPROTO_UDP:
				case IPPROTO_UDPLITE:
					return hints->ai_protocol;
				default:
					return IPPROTO_UDP;
			}
		case SOCK_RAW:
			return hints->ai_protocol;
		case SOCK_SEQPACKET:
			return IPPROTO_SCTP;
		default:
			return 0;
	}
}

static int ioth_gaiadd(struct ioth_gaidata *data,
		int af, void *addr, int socktype, int port) {
	size_t newlen = sizeof(struct addrinfo);
	switch (af) {
		case AF_INET: newlen += sizeof(struct sockaddr_in); break;
		case AF_INET6: newlen += sizeof(struct sockaddr_in6); break;
		default: return EAI_ADDRFAMILY;
	}
	int protocol = setprotocol(data->hints, socktype);
	struct addrinfo *new = calloc(1, newlen);
	if (new == NULL) return EAI_MEMORY;
	new->ai_addr = (void *) (new + 1);
	switch (af) {
		case AF_INET: {
										struct sockaddr_in *sin = (void *) (new + 1);
										sin->sin_family = AF_INET;
										sin->sin_port = htons(port);
										sin->sin_addr = *((struct in_addr *) addr);
										new->ai_addrlen = sizeof(*sin);
									}
									break;
		case AF_INET6: {
										 struct sockaddr_in6 *sin6 = (void *) (new + 1);
										 sin6->sin6_family = AF_INET;
										 sin6->sin6_port = htons(port);
										 sin6->sin6_addr = *((struct in6_addr *) addr);
										 new->ai_addrlen = sizeof(*sin6);
									 }
									 break;
	}
	new->ai_family = af;
	new->ai_socktype = socktype;
	new->ai_protocol = protocol;
	new->ai_canonname = (data->canonname == NULL) ? NULL : strdup(data->canonname);
	data->canonname = NULL;
	*data->next = new;
	data->next = &(new->ai_next);
	return 0;
}

static inline int ioth_af_ok(const struct addrinfo *hints, int af) {
	return (hints->ai_family == af || hints->ai_family == AF_UNSPEC ||
			(hints->ai_family == AF_INET6 && af == AF_INET && (hints->ai_flags & AI_V4MAPPED)));
}

static int _ioth_gaiaddport(struct ioth_gaidata *data,
		int af, void *addr) {
	struct ioth_gaiport *gaiport = data->gaiport;
	if (ioth_af_ok(data->hints, af)) {
		for (int i = 0; gaiport[i].socktype != 0; i++)
			if (gaiport[i].port >= 0) {
				int retval;
				retval = ioth_gaiadd(data, af, addr, gaiport[i].socktype, gaiport[i].port);
				if (retval != 0) return retval;
			}
	}
	return 0;
}

static int ioth_gaiaddport(struct ioth_gaidata *data,
		int af, void *addr) {
	if (af == AF_INET && (data->hints->ai_flags & AI_V4MAPPED) ) {
		unsigned char *v4 = addr;
		unsigned char v4mapped[sizeof(struct in6_addr)] = {
			[10]=0xff,0xff,v4[0],v4[1],v4[2],v4[3]};
		return _ioth_gaiaddport(data, AF_INET6, v4mapped);
	}
	else
		return _ioth_gaiaddport(data, af, addr);
}

static int lookup_cb_cname(int section, struct iothdns_rr *rr, struct iothdns_pkt *pkt, void *arg) {
	struct ioth_gaidata *data = arg;
	if (section == IOTHDNS_SEC_ANSWER && rr->type == IOTHDNS_TYPE_CNAME) {
		char buf[IOTHDNS_MAXNAME];
		iothdns_get_name(pkt, buf);
		// Canonname is dynamically allocaed. It is copied in the first addrinfo or freed */
		data->canonname = strdup(buf);
	}
	return 0;
}

static int lookup_cb_a(int section, struct iothdns_rr *rr, struct iothdns_pkt *pkt, void *arg) {
	if (section == IOTHDNS_SEC_ANSWER && rr->type == IOTHDNS_TYPE_A) {
		unsigned char buf[sizeof(struct in_addr)];
		iothdns_get_a(pkt, buf);
		ioth_gaiaddport(arg, AF_INET, buf);
	}
	return 0;
}

static int lookup_cb_aaaa (int section, struct iothdns_rr *rr, struct iothdns_pkt *pkt, void *arg) {
	if (section == IOTHDNS_SEC_ANSWER && rr->type == IOTHDNS_TYPE_AAAA) {
		unsigned char buf[sizeof(struct in6_addr)];
		iothdns_get_aaaa(pkt, buf);
		ioth_gaiaddport(arg, AF_INET6, buf);
	}
	return 0;
}

int iothdns_getaddrinfo(struct iothdns *iothdns,
		const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res) {
	if (node == NULL && service == NULL)
		return EAI_NONAME;
	if (hints == NULL)
		hints = &default_hints;
	/* PHASE 1: get the port # and socktype availability */
	struct ioth_gaiport gaiport[] = {
		{SOCK_STREAM, "tcp", 0},
		{SOCK_DGRAM, "udp", 0},
		{SOCK_RAW, NULL, 0},
		{0, NULL, 0}};
	struct ioth_gaidata gaidata = {
		.hints = hints,
		.gaiport = gaiport,
		.canonname = NULL,
		.next = res,
	};
	/* the user requires a specific socktype */
	if (hints->ai_socktype != 0)
		for (int i = 0; gaiport[i].socktype != 0; i++)
			if (hints->ai_socktype != gaiport[i].socktype)
				gaiport[i].port = -1;
	/* parse service */
	if (service != NULL) {
		if (service[strspn(service, DIGITS)] == 0) {
			/* numeric service */
			int port = strtoll(service, NULL, 10);
			for (int i = 0; gaiport[i].socktype != 0; i++)
				if (gaiport[i].port == 0)
					gaiport[i].port = port;
		} else if ((hints->ai_flags & AI_NUMERICSERV) == 0){
			/* search in "services" file */
			char services_path[PATH_MAX];
			if (iothdns_getpath(iothdns, IOTHDNS_SERVICES, services_path, PATH_MAX) > 0) {
				for (int i = 0; gaiport[i].socktype != 0; i++)
					if (gaiport[i].port == 0)
						gaiport[i].port = iothdns_getservice(services_path, service, gaiport[i].protocol);
			}
		}
	}

	/* PHASE 2: get ip addr */
	unsigned char buf[sizeof(struct in6_addr)];
	/* Node is NULL => ANY if AI_PASSIVE otherwise localhost */
	if(node == NULL) {
		if(hints->ai_flags & AI_PASSIVE) {
			inet_pton(AF_INET, "0.0.0.0", buf);
			ioth_gaiaddport(&gaidata, AF_INET, buf);
			inet_pton(AF_INET6, "::", buf);
			ioth_gaiaddport(&gaidata, AF_INET6, buf);
		} else {
			inet_pton(AF_INET6, "::1", buf);
			ioth_gaiaddport(&gaidata, AF_INET6, buf);
			inet_pton(AF_INET, "127.0.0.1", buf);
			ioth_gaiaddport(&gaidata, AF_INET, buf);
		}
	} else if(inet_pton(AF_INET, node, buf) == 1)
		/* it is a numeric IPv4 addess */
		ioth_gaiaddport(&gaidata, AF_INET, buf);
	else if (inet_pton(AF_INET6, node, buf) == 1)
		/* it is a numeric IPv6 addess */
		ioth_gaiaddport(&gaidata, AF_INET6, buf);
	else if ((hints->ai_flags & AI_NUMERICHOST) == 0) {
		/* canonname is always via DNS */
		if (hints->ai_flags & AI_CANONNAME)
			iothdns_lookup_cb(iothdns, (char *) node, IOTHDNS_TYPE_CNAME,
					lookup_cb_cname, &gaidata);
		/* search in the "hosts" file */
		char hosts_path[PATH_MAX];
		if (iothdns_getpath(iothdns, IOTHDNS_HOSTS, hosts_path, PATH_MAX) > 0) {
			if (ioth_af_ok(hints, AF_INET)) {
				if (iothdns_gethost(hosts_path, AF_INET, node, buf))
					ioth_gaiaddport(&gaidata, AF_INET, buf);
			}
			if (ioth_af_ok(hints, AF_INET6)) {
				if (iothdns_gethost(hosts_path, AF_INET6, node, buf))
					ioth_gaiaddport(&gaidata, AF_INET6, buf);
			}
		}
		if (*res == NULL) {
			/* search in the DNS */
			if (hints->ai_family == AF_INET6 &&
					(hints->ai_flags & AI_V4MAPPED) && !(hints->ai_flags & AI_ALL)) {
				/* if no matching IPv6 addresses could be found, then return IPv4-mapped IPv6 addresses */
				/* AI_ALL is ignored if AI_V4MAPPED is not also specified */
				iothdns_lookup_cb(iothdns, node, IOTHDNS_TYPE_AAAA, lookup_cb_aaaa, &gaidata);
				if (*res == NULL)
					iothdns_lookup_cb(iothdns, node, IOTHDNS_TYPE_A, lookup_cb_a, &gaidata);
			} else {
				if (ioth_af_ok(hints, AF_INET))
					iothdns_lookup_cb(iothdns, node, IOTHDNS_TYPE_A, lookup_cb_a, &gaidata);
				if (ioth_af_ok(hints, AF_INET6))
					iothdns_lookup_cb(iothdns, node, IOTHDNS_TYPE_AAAA, lookup_cb_aaaa, &gaidata);
			}
		}
		if (gaidata.canonname != NULL) free(gaidata.canonname);
	}
	return 0;
}

void iothdns_freeaddrinfo(struct addrinfo *res) {
	while (res != NULL) {
		struct addrinfo *next = res->ai_next;
		if (res->ai_canonname != NULL) free(res->ai_canonname);
		free(res);
		res = next;
	}
}

struct ioth_rev_data {
	char *host;
	socklen_t hostlen;
	int retval;
};

static int lookup_cb_ptr(int section, struct iothdns_rr *rr, struct iothdns_pkt *pkt, void *arg) {
	struct ioth_rev_data *data = arg;
	if (section == IOTHDNS_SEC_ANSWER && rr->type == IOTHDNS_TYPE_PTR) {
		char buf[IOTHDNS_MAXNAME];
		iothdns_get_name(pkt, buf);
		data->retval = snprintf(data->host, data->hostlen, "%s", buf);
	}
	return 0;
}

static int ioth_dns_rev(struct iothdns *dns, int af, void *addr, char *host, socklen_t hostlen) {
	unsigned char *byte = addr;
	struct ioth_rev_data data = {host, hostlen, 0};
	int revqlen = 74;
	char revq[revqlen];
	if (af == AF_INET) {
		snprintf(revq, revqlen, "%d.%d.%d.%d.in-addr.arpa", byte[3], byte[2], byte[1], byte[0]);
	}
	if (af == AF_INET6) {
		char *s = revq;
		for(int i = 0; i < 16; i++) {
			s += sprintf(s, "%x.%x.", byte[15 - i] & 0xf, byte[15 - i] >> 4);
			sprintf(s, "ip6.arpa");
		}
	}
	iothdns_lookup_cb(dns, revq, IOTHDNS_TYPE_PTR,
			lookup_cb_ptr, &data);
	return data.retval;
}

int iothdns_getnameinfo(struct iothdns *iothdns,
		const struct sockaddr *addr, socklen_t addrlen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen, int flags) {
	void *addrx;
	int port;
	/* check consistency */
	int af = addr->sa_family;
	/* retrieve addr pointer and port */
	switch (af) {
		case AF_INET:
			if (addrlen < sizeof(struct sockaddr_in)) return EAI_FAMILY;
			addrx = &((struct sockaddr_in *) addr)->sin_addr;
			port = ntohs(((struct sockaddr_in *) addr)->sin_port);
			break;
		case AF_INET6:
			if (addrlen < sizeof(struct sockaddr_in6)) return EAI_FAMILY;
			addrx = &((struct sockaddr_in6 *) addr)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
			break;
		default: return EAI_FAMILY;
	}
	/* get service name if required */
	if (serv != NULL && servlen > 0) {
		char services_path[PATH_MAX];
		if (iothdns_getpath(iothdns, IOTHDNS_SERVICES, services_path, PATH_MAX) > 0) {
			socklen_t rv = iothdns_getservice_rev(services_path, port,
					(flags & NI_DGRAM) ? "udp": "tcp",
					serv, servlen, flags & NI_NUMERICSERV);
			if (rv >= servlen) return EAI_OVERFLOW;
		}
	}
	/* get host name if required */
	if (host != NULL && hostlen > 0) {
		socklen_t rv = 0;
		if (! flags & NI_NUMERICHOST) {
			/* try via the "hosts" file */
			char hosts_path[PATH_MAX];
			if (iothdns_getpath(iothdns, IOTHDNS_HOSTS, hosts_path, PATH_MAX) > 0) {
				rv = iothdns_gethost_rev(hosts_path, af, addrx, host, hostlen);
				if (rv >= hostlen) return EAI_OVERFLOW;
			}
			if (rv == 0) {
				/* try via DNS */
				rv = ioth_dns_rev(iothdns, af, addrx, host, hostlen);
				if (rv >= hostlen) return EAI_OVERFLOW;
			}
			if((flags & NI_NAMEREQD) && rv == 0)
				return EAI_NONAME;
		}
		if (rv == 0) {
			char buf[INET6_ADDRSTRLEN];
			if (inet_ntop(af, addrx, buf, INET6_ADDRSTRLEN) == NULL)
				return EAI_FAIL;
			rv = snprintf(host, hostlen, "%s", buf);
			if (rv >= hostlen) return EAI_OVERFLOW;
		}
	}
	return 0;
}

const char *iothdns_gai_strerror(int errcode) {
	return gai_strerror(errcode);
}
