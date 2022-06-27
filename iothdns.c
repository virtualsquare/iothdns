/*
 *   iothdns.c: client and server utility functions for dns packets RFC 1035 (and updates)
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <iothdns.h>

/* sockaddr_storage wastes memory */
#ifdef WASTE_MEMORY_FOR_SOCKADDR_SORAGE
#define sockaddr_in46 sockaddr_storage
#define sin46_family ss_family
#else
#define sockaddr_in46 sockaddr_in6
#define sin46_family sin6_family
#endif

struct iothdns {
	struct ioth *stack;
	pthread_mutex_t mutex;
	struct sockaddr_in46 sockaddr[IOTHDNS_MAXNS];
	char *search;
	char *paths[IOTHDNS_PATH_SIZE];
};

static char *iothdns_default_paths[IOTHDNS_PATH_SIZE] = {
	IOTHDNS_DEFAULT_HOSTS,
	IOTHDNS_DEFAULT_SERVICES
};

/* common function to initialize/update iothdns */
#define NSTAG "nameserver"
#define NSTAGLEN (sizeof(NSTAG) - 1)
#define SEARCHTAG "search "
#define SEARCHTAGLEN (sizeof(SEARCHTAG) - 1)
static struct iothdns *_iothdns_init_f(struct iothdns *iothdns, struct ioth *stack, FILE *fconfig) {
	/* create a new iothdns (init) or clean previous configurations */
	if (iothdns == NULL) {
		iothdns = calloc(1, sizeof(*iothdns));
		if (iothdns) {
			iothdns->stack = stack;
			pthread_mutex_init(&iothdns->mutex, NULL);
			pthread_mutex_lock(&iothdns->mutex);
		}
	} else {
		pthread_mutex_lock(&iothdns->mutex);
		for (int nsno = 0; nsno < IOTHDNS_MAXNS; nsno++)
			iothdns->sockaddr[nsno].sin46_family = PF_UNSPEC;
		if (iothdns->search != NULL) {
			free(iothdns->search);
			iothdns->search = NULL;
		}
	}
	if (iothdns) {
		/* parse the resolv.conf syntax */
		char *line = NULL;
		size_t linelen = 0;
		ssize_t len;
		int nsno = 0;
		while ((len = getline(&line, &linelen, fconfig)) >= 0) {
			size_t thislinelen = strlen(line);
			/* comment line */
			if (line[0] == '#' || line[0] == ';')
				continue;
			/* strip traling '\n' */
			if (line[thislinelen - 1] == '\n')
				line[--thislinelen] = 0;
			/* add a nameserver address up to IOTHDNS_MAXNS */
			if (nsno < IOTHDNS_MAXNS && strncmp(line, NSTAG, NSTAGLEN) == 0) {
				char straddr[len - NSTAGLEN];
				if (sscanf(line + NSTAGLEN, "%s", straddr) == 1) {
					uint8_t addr[sizeof(struct in6_addr)];
					if (inet_pton(AF_INET6, straddr, addr) == 1) {
						struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) (&iothdns->sockaddr[nsno++]);
						sin6->sin6_family = AF_INET6;
						sin6->sin6_port = htons(IOTHDNS_DEFAULT_PORT);
						sin6->sin6_addr = *((struct in6_addr *) addr);
					}
					if (inet_pton(AF_INET, straddr, addr) == 1) {
						struct sockaddr_in *sin = (struct sockaddr_in *) (&iothdns->sockaddr[nsno++]);
						sin->sin_family = AF_INET;
						sin->sin_port = htons(IOTHDNS_DEFAULT_PORT);
						sin->sin_addr = *((struct in_addr *) addr);
					}
				}
			}
			/* Search list for host-name lookup */
			if (strncmp(line, SEARCHTAG, SEARCHTAGLEN) == 0) {
				/* If there are multiple search directives, only the search list from the last instance is used */
				if (iothdns->search != NULL) {
					free(iothdns->search);
					iothdns->search = NULL;
				}
				iothdns->search = strdup(line + SEARCHTAGLEN);
			}
		}
		if (line != NULL)
			free(line);
		pthread_mutex_unlock(&iothdns->mutex);
	}
	return iothdns;
}

/* helper functions to handle file or string configuration */
static struct iothdns *iothdns_init_update(struct iothdns *iothdns,
		struct ioth *stack, char *path_config) {
	char *path = (path_config == NULL) ? IOTHDNS_DEFAULT_RESOLV_CONF : path_config;
	FILE *f = fopen(path, "r");
	if (f) {
		struct iothdns *new = _iothdns_init_f(iothdns, stack, f);
		fclose(f);
		return new;
	} else
		return NULL;
}

static struct iothdns *iothdns_init_update_strcfg(struct iothdns *iothdns,
		struct ioth *stack, char *config) {
	if (config == NULL)
		return iothdns_init_update(iothdns, stack, NULL);
	else {
		FILE *f = fmemopen(config, strlen(config), "r");
		if (f) {
			struct iothdns *new = _iothdns_init_f(iothdns, stack, f);
			fclose(f);
			return new;
		} else
			return NULL;
	}
}

struct iothdns *iothdns_init(struct ioth *stack, char *path_config) {
	return iothdns_init_update(NULL, stack, path_config);
}

struct iothdns *iothdns_init_strcfg(struct ioth *stack, char *config) {
	return iothdns_init_update_strcfg(NULL, stack, config);
}

int iothdns_update(struct iothdns *iothdns, char *path_config) {
	return iothdns_init_update(iothdns, NULL, path_config) == NULL ? -1 : 0;
}

int iothdns_update_strcfg(struct iothdns *iothdns, char *config) {
	return iothdns_init_update_strcfg(iothdns, NULL, config) == NULL ? -1 : 0;
}

int iothdns_add_nameserver(struct iothdns *iothdns, int af, void *in46_addr) {
	int rv = 0;
	int nsno = 0;
	pthread_mutex_lock(&iothdns->mutex);
	for (int nsno = 0; nsno < IOTHDNS_MAXNS; nsno++)
		if (iothdns->sockaddr[nsno].sin46_family == PF_UNSPEC)
			break;
	if (nsno < IOTHDNS_MAXNS) {
		if (af == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) (&iothdns->sockaddr[nsno]);
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(IOTHDNS_DEFAULT_PORT);
			sin6->sin6_addr = *((struct in6_addr *) in46_addr);
		} else if (af == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *) (&iothdns->sockaddr[nsno]);
			sin->sin_family = AF_INET;
			sin->sin_port = htons(IOTHDNS_DEFAULT_PORT);
			sin->sin_addr = *((struct in_addr *) in46_addr);
		} else {
			rv = -1;
			errno = EAFNOSUPPORT;
		}
	} else {
		rv = -1;
		errno = ENOSPC;
	}
	pthread_mutex_unlock(&iothdns->mutex);
	return rv;
}

void iothdns_setpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *newvalue) {
	pthread_mutex_lock(&iothdns->mutex);
	if (iothdns->paths[pathtag] != NULL) free(iothdns->paths[pathtag]);
	if (newvalue == NULL)
		iothdns->paths[pathtag] = NULL;
	else
		iothdns->paths[pathtag] = strdup(newvalue);
	pthread_mutex_unlock(&iothdns->mutex);
}

int iothdns_getpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *buf, size_t size) {
	pthread_mutex_lock(&iothdns->mutex);
	char *value = iothdns->paths[pathtag];
	if (value == NULL) value = iothdns_default_paths[pathtag];
	int retvalue = snprintf(buf, size, "%s", value);
	pthread_mutex_unlock(&iothdns->mutex);
	return retvalue;
}

void iothdns_fini(struct iothdns *iothdns) {
	pthread_mutex_lock(&iothdns->mutex);
	if (iothdns->search != NULL) free(iothdns->search);
	for (int i = 0; i < IOTHDNS_PATH_SIZE; i++) {
		if (iothdns->paths[i] != NULL)
			free(iothdns->paths[i]);
	}
	pthread_mutex_unlock(&iothdns->mutex);
	free(iothdns);
}

/* dialog function prototype **for clients**
	 dialog = open socket + connect + send + recv reply (or timeout) + close */
typedef size_t dialog_function_t(struct ioth *stack,
		const struct sockaddr_in46 *addr,
		void *reqbuf, size_t reqbuflen,
		void *repbuf, size_t repbuflen);

/* UDP dialog */
static size_t udp_client_dialog(struct ioth *stack,
		const struct sockaddr_in46 *addr,
		void *reqbuf, size_t reqbuflen,
		void *repbuf, size_t repbuflen) {
	int s = ioth_msocket(stack, addr->sin46_family, SOCK_DGRAM, 0);
	struct pollfd pfd[] = {{s, POLLIN, 0}};
	ioth_connect(s, (struct sockaddr *) addr, sizeof(struct sockaddr_in46));
	ioth_write(s, reqbuf, reqbuflen);
	if (poll(pfd, 1, IOTHDNS_TIMEOUT_MS) == 0) {
		ioth_close(s);
		return 0;
	}
	size_t len = ioth_read(s, repbuf, repbuflen);
	ioth_close(s);
	return len;
}

/* TCP dialog */
static size_t tcp_get_pkt(int s,
		void *repbuf, size_t repbuflen) {
	struct pollfd pfd[] = {{s, POLLIN, 0}};
	if (poll(pfd, 1, IOTHDNS_TIMEOUT_MS) == 0) {
		ioth_close(s);
		return 0;
	}
	uint8_t tcpheader[2];
	size_t len =  ioth_read(s, tcpheader, sizeof(tcpheader));
	if (len < sizeof(tcpheader))
		return errno = EBADMSG, -1;
	size_t pktlen = tcpheader[0] << 8 | tcpheader[1];
	if (pktlen > repbuflen)
		return errno = EBADMSG, -1;
	struct iovec iov_rdd[] = {{repbuf, pktlen}};
	for (;;) {
		if (poll(pfd, 1, IOTHDNS_TIMEOUT_MS) == 0)
			return 0;
		len = ioth_readv(s, iov_rdd, 1);
		if (len <= 0)
			return errno = EBADMSG, -1;
		iov_rdd->iov_base = ((uint8_t *) iov_rdd->iov_base) + len;
		iov_rdd->iov_len -= len;
		if (iov_rdd->iov_len <= 0)
			break;
	}
	return pktlen;
}

static size_t tcp_client_dialog(struct ioth *stack,
		const struct sockaddr_in46 *addr,
		void *reqbuf, size_t reqbuflen,
		void *repbuf, size_t repbuflen) {
	int s = ioth_msocket(stack, addr->sin46_family, SOCK_STREAM, 0);
	uint8_t tcpheader[2] = {reqbuflen >> 8, reqbuflen};
	struct iovec iov_wr[] = {{tcpheader, sizeof(tcpheader)}, {reqbuf, reqbuflen}};
	ioth_connect(s, (struct sockaddr *) addr, sizeof(struct sockaddr_in46));
	ioth_writev(s, iov_wr, 2);
	size_t len = tcp_get_pkt(s, repbuf, repbuflen);
	ioth_close(s);
	return len;
}

/* client: lookup helper #2.
	 try all the ns servers */
static struct iothdns_pkt *__iothdns_lookup(struct iothdns *iothdns,
		dialog_function_t *dialog_function,
		const char *name, int type,
		uint8_t *outbuf, size_t outbuflen) {
	uint16_t id = random();
	int dnsno;
	for (dnsno = 0; dnsno < IOTHDNS_MAXNS; dnsno++) {
		if (iothdns->sockaddr[dnsno].sin46_family != 0) {
			//printf("%d %d\n", dnsno, iothdns->sockaddr[dnsno].sin46_family);
			struct iothdns_header h = {id, IOTHDNS_QUERY | IOTHDNS_RD, name, type, IOTHDNS_CLASS_IN};
			struct iothdns_pkt *pkt = iothdns_put_header(&h);
			size_t len = dialog_function(iothdns->stack,
					&iothdns->sockaddr[dnsno],
					iothdns_buf(pkt), iothdns_buflen(pkt),
					outbuf, outbuflen);
			char qname[IOTHDNS_MAXNAME];
			iothdns_free(pkt);
			pkt = iothdns_get_header(&h, outbuf, len, qname);
			if (pkt != NULL && len > 0 && h.id == id && strcmp(h.qname, name) == 0 &&
					h.qtype == type && IOTHDNS_IS_RESPONSE(h.flags)) {
				switch (IOTHDNS_GET_RCODE(h.flags)) {
					case IOTHDNS_RCODE_OK:
						return pkt;
					case IOTHDNS_RCODE_ENOENT:
						free(pkt);
						return errno = ENOENT, NULL;
				}
			}
			if (pkt != NULL)
				iothdns_free(pkt);
		}
	}
	return NULL;
}

/* client: lookup helper #1.
	 mutex for concurrent updates.
	 if the name is just a hostname call the helper #2 trying to complete the fqdn using each item of the
	 search list.
	 otherwise call the helper #2 here above */
static struct iothdns_pkt *_iothdns_lookup(struct iothdns *iothdns,
		dialog_function_t *dialog_function,
		const char *name, int type,
		uint8_t *outbuf, size_t outbuflen) {
	struct iothdns_pkt *retval;
	pthread_mutex_lock(&iothdns->mutex);
	if (*name != '\0' && strchr(name, '.') == NULL && iothdns->search != NULL) {
		char qname[IOTHDNS_MAXNAME];	
		retval = NULL;
		for (char *scan = iothdns->search;
				*scan != '\0' && retval == NULL; scan++) {
			if (*scan == ' ') continue;
			int len = strchrnul(scan, ' ') - scan;
			snprintf(qname, IOTHDNS_MAXNAME, "%s.%.*s",
					name, len, scan);
			//printf("SEARCH! %s\n", qname);
			retval = __iothdns_lookup(iothdns, dialog_function, qname, type,
					outbuf, outbuflen);
			scan += len - 1;
		}
	} else {
		retval = __iothdns_lookup(iothdns, dialog_function, name, type,
				outbuf, outbuflen);
	}
	pthread_mutex_unlock(&iothdns->mutex);
	return retval;
}

/* prototype for lookup functions */
typedef struct iothdns_pkt *iothdns_lookup_f_t(struct iothdns *iothdns,
		const char *name, int type,
		uint8_t *outbuf, size_t outbuflen);

/* lookup via UDP */
static struct iothdns_pkt *iothdns_udp_lookup(struct iothdns *iothdns,
		const char *name, int type,
		uint8_t *outbuf, size_t outbuflen) {
	return _iothdns_lookup(iothdns, udp_client_dialog,
			name, type, outbuf, outbuflen);
}

/* lookup via TCP */
static struct iothdns_pkt *iothdns_tcp_lookup(struct iothdns *iothdns,
		const char *name, int type,
		uint8_t *outbuf, size_t outbuflen) {
	return _iothdns_lookup(iothdns, tcp_client_dialog,
			name, type, outbuf, outbuflen);
}

/* helper function to support numeric a/aaaa queries via inet_pton */
static int iothdns_lookup_pton(int af, const char *src, void *dst, int n) {
	if (n == 0) {
		uint8_t tmpbuf[sizeof(struct in6_addr)];
		return inet_pton(af, src, tmpbuf);
	} else
		return inet_pton(af, src, dst);
}

/* lookup IPv4 addresses */
int iothdns_lookup_a(struct iothdns *iothdns, const char *name, struct in_addr *a, int n) {
	int retval = iothdns_lookup_pton(AF_INET, name, a, n);
	// query the dns only when it is not a numerical address v4 or v6
	if (retval == 0 && iothdns_lookup_pton(AF_INET6, name, NULL, 0) == 0) {
		uint8_t buf[IOTHDNS_UDP_MAXBUF];
		struct iothdns_pkt *pkt = iothdns_udp_lookup(iothdns, name, IOTHDNS_TYPE_A, buf, IOTHDNS_UDP_MAXBUF);
		struct iothdns_rr rr;
		char rname[IOTHDNS_MAXNAME];
		int section;
		if (pkt == NULL)
			return -1;
		while ((section = iothdns_get_rr(pkt, &rr, rname)) != 0) {
			if (section == IOTHDNS_SEC_ANSWER && rr.type == IOTHDNS_TYPE_A) {
				if (retval < n)
					iothdns_get_a(pkt, a + retval);
				retval++;
			}
		}
		iothdns_free(pkt);
	}
	return retval;
}

/* lookup IPv6 addresses */
int iothdns_lookup_aaaa(struct iothdns *iothdns, const char *name, struct in6_addr *aaaa, int n) {
	int retval = iothdns_lookup_pton(AF_INET6, name, aaaa, n);
	// query the dns only when it is not a numerical address v4 or v6
	if (retval == 0 && iothdns_lookup_pton(AF_INET, name, NULL, 0) == 0) {
		uint8_t buf[IOTHDNS_UDP_MAXBUF];
		struct iothdns_pkt *pkt = iothdns_udp_lookup(iothdns, name, IOTHDNS_TYPE_AAAA, buf, IOTHDNS_UDP_MAXBUF);
		struct iothdns_rr rr;
		char rname[IOTHDNS_MAXNAME];
		int section;
		if (pkt == NULL)
			return -1;
		while ((section = iothdns_get_rr(pkt, &rr, rname)) != 0) {
			if (section == IOTHDNS_SEC_ANSWER && rr.type == IOTHDNS_TYPE_AAAA) {
				if (retval < n)
					iothdns_get_aaaa(pkt, aaaa + retval);
				retval++;
			}
		}
		iothdns_free(pkt);
	}
	return retval;
}

/* lookup IPv6 addresses + IPv4 compat (e.g. ::ffff:1.2.3.4) */
#define v4v6compat(X) \
	(struct in6_addr) {.s6_addr32[2] = htonl(0xffff), .s6_addr32[3] = (X).s_addr}
int iothdns_lookup_aaaa_compat(struct iothdns *iothdns, const char *name, struct in6_addr *aaaa, int n) {
	int n6 = iothdns_lookup_aaaa(iothdns, name, aaaa, n);
	if (n6 < 0)
		return n6;
	int nmax4 = n - n6;
	if (nmax4 > 0) {
		struct in_addr a4[nmax4];
		int n4 = iothdns_lookup_a(iothdns, name, a4, nmax4);
		if (n4 < 0)
			return n6;
		if (n4 < nmax4) nmax4 = n4;
		for (int i = 0; i < nmax4; i++)
			aaaa[n6 + i] = v4v6compat(a4[i]);
		return n6 + n4;
	} else
		return n6 + iothdns_lookup_a(iothdns, name, NULL, 0);
}

static int _iothdns_lookup_cb(struct iothdns *iothdns, const char *name, int qtype,
		lookup_cb_t *lookup_cb, void *arg,
		iothdns_lookup_f_t *iothdns_lookup_f, size_t outbuflen) {
	int retval = 0;
	uint8_t buf[outbuflen];
	struct iothdns_rr rr;
	char rname[IOTHDNS_MAXNAME];
	int section;
	struct iothdns_pkt *pkt = iothdns_lookup_f(iothdns, name, qtype, buf, outbuflen);
	if (pkt == NULL)
		return -1;
	while (retval == 0 && (section = iothdns_get_rr(pkt, &rr, rname)) != 0) {
		retval = lookup_cb(section, &rr, pkt, arg);
	}
	iothdns_free(pkt);
	return retval;
}

/* general purpose lookup function: it calls 'lookup_cb' for each resource record */
int iothdns_lookup_cb(struct iothdns *iothdns, const char *name, int qtype,
		lookup_cb_t *lookup_cb, void *arg) {
	return _iothdns_lookup_cb(iothdns, name, qtype, lookup_cb, arg, iothdns_udp_lookup, IOTHDNS_UDP_MAXBUF);
}

int iothdns_lookup_cb_tcp(struct iothdns *iothdns, const char *name, int qtype,
		lookup_cb_t *lookup_cb, void *arg) {
	return _iothdns_lookup_cb(iothdns, name, qtype, lookup_cb, arg, iothdns_tcp_lookup, IOTHDNS_TCP_MAXBUF);
}

/* **server side** process a UDP message */
int iothdns_udp_process_request(int fd,
		parse_request_t *parse_request, void *arg) {
	char buf[IOTHDNS_UDP_MAXBUF];
	struct sockaddr_in46 from;
	socklen_t fromlen = sizeof(from);
	size_t len = ioth_recvfrom(fd, buf, IOTHDNS_UDP_MAXBUF, 0, (struct sockaddr *) &from, &fromlen);
	if (len <= 0)
		return len;
	struct iothdns_header h;
	char qname[IOTHDNS_MAXNAME];	
	struct iothdns_pkt *pkt = iothdns_get_header(&h, buf, len, qname);
	iothdns_free(pkt);
	if (pkt != NULL && IOTHDNS_IS_QUERY(h.flags)) {
		pkt = parse_request(&h, arg);
		ioth_sendto(fd, iothdns_buf(pkt), iothdns_buflen(pkt), 0, (struct sockaddr *) &from, fromlen);
	}
	return len;
}

/* **server side** process a TCP message */
int iothdns_tcp_process_request(int fd,
		parse_request_t *parse_request, void *arg) {
	char buf[IOTHDNS_TCP_MAXBUF];
	size_t len = tcp_get_pkt(fd, buf, IOTHDNS_TCP_MAXBUF);
	if (len <= 0)
		return len;
	struct iothdns_header h;
	char qname[IOTHDNS_MAXNAME];
	struct iothdns_pkt *pkt = iothdns_get_header(&h, buf, len, qname);
	iothdns_free(pkt);
	if (pkt != NULL && IOTHDNS_IS_QUERY(h.flags)) {
		pkt = parse_request(&h, arg);
		len = iothdns_buflen(pkt);
		uint8_t tcpheader[2] = {len >> 8, len};
		struct iovec iov_wr[] = {{tcpheader, sizeof(tcpheader)}, {iothdns_buf(pkt), len}};
		ioth_writev(fd, iov_wr, 2);
	}
	return len;
}

__attribute__((constructor))
	static void init(void) {
		unsigned int seed;
		if (getrandom(&seed, sizeof(seed), 0) == 0)
			srand(seed);
		else
			srand(time(NULL) ^ getpid());
	}
