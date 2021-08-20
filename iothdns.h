#ifndef IOTHDNS_H
#define IOTHDNS_H
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ioth.h>

#define IOTHDNS_DEFAULT_PORT 53
#define IOTHDNS_MAXNS 3
#define IOTHDNS_TIMEOUT_MS 1000
#define IOTHDNS_DEFAULT_RESOLV_CONF "/etc/resolv.conf"
#define IOTHDNS_DEFAULT_HOSTS       "/etc/hosts"
#define IOTHDNS_DEFAULT_SERVICES    "/etc/services"

struct iothdns;
struct iothdns_pkt;

/* init/update configuration */
/* configure the resolver: NS addresses and search path.
 * the configuration file (iothdns_init/iothdns_update)
 * or string (iothdns_init_strcfg, iothdns_update_strcfg)
 * follow the syntax of resolv.conf(5) */

struct iothdns *iothdns_init(struct ioth *stack, char *path_config);
struct iothdns *iothdns_init_strcfg(struct ioth *stack, char *config);
int iothdns_update(struct iothdns *iothdns, char *path_config);
int iothdns_update_strcfg(struct iothdns *iothdns, char *config);

/* add a nameserver: af is the addr family AF_INET6 or AF_INET;
 * the last arg is a pointer to struct in_addr or struct in6_addr. */
int iothdns_add_nameserver(struct iothdns *iothdns, int af, void *in46_addr);

/* provide alternative files to "/etc/hosts" or "/etc/services" for
 * iothdns_getaddrinfo and iothdns_getnameinfo */

enum iothdns_pathtag {IOTHDNS_HOSTS, IOTHDNS_SERVICES, // real tags
	IOTHDNS_PATH_SIZE}; // count of enum elements

void iothdns_setpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *newvalue);
int iothdns_getpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *buf, size_t size);

void iothdns_fini(struct iothdns *iothdns);

/* --------------- client side ----------------- */

/* lookup IPv4 addresses */
int iothdns_lookup_a(struct iothdns *iothdns, const char *name, struct in_addr *a, int n);

/* lookup IPv6 addresses */
int iothdns_lookup_aaaa(struct iothdns *iothdns, const char *name, struct in6_addr *aaaa, int n);

/* iothdns getaddrinfo (see getaddrinfo(3)) */
int iothdns_getaddrinfo(struct iothdns *iothdns,
		const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res);

void iothdns_freeaddrinfo(struct addrinfo *res);

const char *iothdns_gai_strerror(int errcode);

/* iothdns getnameinfo (see getnameinfo(3)) */
int iothdns_getnameinfo(struct iothdns *iothdns,
		const struct sockaddr *addr, socklen_t addrlen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen, int flags);


/* general purpose lookup functions: 'lookup_cb' is a callback for each resource record */
struct iothdns_rr;
typedef int lookup_cb_t(int section, struct iothdns_rr *rr, struct iothdns_pkt *vpkt, void *arg);
int iothdns_lookup_cb(struct iothdns *iothdns, const char *name, int qtype,
		lookup_cb_t *lookup_cb, void *arg);
int iothdns_lookup_cb_tcp(struct iothdns *iothdns, const char *name, int qtype,
		lookup_cb_t *lookup_cb, void *arg);

/* --------------- server side ----------------- */

struct iothdns_header;
/* this callback gets called once for each query.
 * It returns the iothdns_pkt to be sent back as the reply */
typedef struct iothdns_pkt *parse_request_t(struct iothdns_header *h, void *arg);

/* fd is a UDP (SOCK_DGRAM) socket: read from the socket parse the request,
 * call the callback for each query, send back the reply.
 * arg is an opaque argument passed as is to the callback function */
int iothdns_udp_process_request(int fd, parse_request_t *parse_request, void *arg);

/* it is like the previous function except that fd is a TCP (SOCK_STREAM) socket.
 * (each messsage -- query or reply -- has a prepending length field. */
int iothdns_tcp_process_request(int fd, parse_request_t *parse_request, void *arg);

/* --------------- packet compose/parse ----------------- */

struct iothdns_header {
	uint16_t id;
	uint16_t flags;
	const char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct iothdns_rr {
	const char *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
};

/* COMPOSE MODE */
/* iothdns_put_header creates a iothdns_pkt including the header and the
 * query resource record */
struct iothdns_pkt *iothdns_put_header(struct iothdns_header *h);

/* iothdns_put_rr adds a resource record */
/* WARNING: RRs must be added in non-decreasing sorting of sections.
 * a RR whose section is smaller than the section of the previous RR is silently discarded */
/* rdlength is automatically computed */
void iothdns_put_rr(int section, struct iothdns_pkt *vpkt, struct iothdns_rr *rr);

/* add data to the last resource record */
void iothdns_put_int8(struct iothdns_pkt *vpkt, uint8_t data);
void iothdns_put_int16(struct iothdns_pkt *vpkt, uint16_t data);
void iothdns_put_int32(struct iothdns_pkt *vpkt, uint32_t data);
void iothdns_put_data(struct iothdns_pkt *vpkt, void *data, uint16_t len);
void iothdns_put_name(struct iothdns_pkt *vpkt, const char *name);
void iothdns_put_name_uncompressed(struct iothdns_pkt *vpkt, const char *name);
void iothdns_put_string(struct iothdns_pkt *vpkt, char *string);
void iothdns_put_a(struct iothdns_pkt *vpkt, void *addr_ipv4);
void iothdns_put_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6);

/* PARSE MODE */
/* iothdns_get_header parses the header and the query of the packed stored in buf.
 * qnamebuf is a temporary buffer (whose length is IOTHDNS_MAXNAME) to store the queryname */
struct iothdns_pkt *iothdns_get_header(struct iothdns_header *h, void *buf, size_t bufsize, char *qnamebuf);

/* iothdns_get_rr parses the next resource record */
/* namebuf is a temporary buffer (whose length is IOTHDNS_MAXNAME) to store the name of this RR */
/* It is not necessary to parse the arguments of the current RR.
 * Just call again iothdns_get_rr again if the arguments are not significant/needed. */
int iothdns_get_rr(struct iothdns_pkt *vpkt, struct iothdns_rr *rr, char *namebuf);

/* parse argument data of the current resource record */
uint8_t iothdns_get_int8(struct iothdns_pkt *vpkt);
uint16_t iothdns_get_int16(struct iothdns_pkt *vpkt);
uint32_t iothdns_get_int32(struct iothdns_pkt *vpkt);
void *iothdns_get_data(struct iothdns_pkt *vpkt, void *data, uint16_t len);
char *iothdns_get_name(struct iothdns_pkt *vpkt, char *name);
char *iothdns_get_string(struct iothdns_pkt *vpkt, char *name);
void *iothdns_get_a(struct iothdns_pkt *vpkt, void *addr_ipv4);
void *iothdns_get_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6);


/* BOTH COMPOSE/PARSE MODES */

/* iothdns_buf retrurns the address of the packet buffer of vpkt*/
void *iothdns_buf(struct iothdns_pkt *vpkt);
/* iothdns_buflen retruns the length of iothdns_buf */
size_t iothdns_buflen(struct iothdns_pkt *vpkt);
/* delete vpkt and free all the dynamically allocated memory */
void iothdns_free(struct iothdns_pkt *vpkt);

/* REWRITE HEADER */
/* in place rewrite id and flags (for forwarders or non-caching proxies) */
void iothdns_retrieve_header(struct iothdns_pkt *vpkt, uint16_t *id, uint16_t *flags);
void iothdns_rewrite_header(struct iothdns_pkt *vpkt, uint16_t id, uint16_t flags);

/* MACRO & CONSTANTS */

#define IOTHDNS_MAXNAME 256
#define IOTHDNS_MAXSTRING 255
#define IOTHDNS_UDP_MAXBUF 512
#define IOTHDNS_TCP_MAXBUF 65536

#define IOTHDNS_SECTIONS 4
#define IOTHDNS_SEC_QUERY 0
#define IOTHDNS_SEC_ANSWER 1
#define IOTHDNS_SEC_AUTH 2
#define IOTHDNS_SEC_ADDITIONAL 3

#define IOTHDNS_QUERY    0x0000
#define IOTHDNS_RESPONSE 0x8000
#define IOTHDNS_QR_MASK  0x8000
#define IOTHDNS_IS_QUERY(x)    (((x) & IOTHDNS_QR_MASK) == IOTHDNS_QUERY)
#define IOTHDNS_IS_RESPONSE(x) (((x) & IOTHDNS_QR_MASK) == IOTHDNS_RESPONSE)
#define IOTHDNS_OP_MASK   0x7800

#define IOTHDNS_AA        0x0400
#define IOTHDNS_TRUNC     0x0200
#define IOTHDNS_RD        0x0100
#define IOTHDNS_RA        0x0080
#define IOTHDNS_Z         0x0040
#define IOTHDNS_AD        0x0020
#define IOTHDNS_CD        0x0010

#define IOTHDNS_RCODE_MASK 0x000F
#define IOTHDNS_GET_RCODE(x) ((x) & IOTHDNS_RCODE_MASK)
#define IOTHDNS_RCODE_OK     0
#define IOTHDNS_RCODE_EFMT   1
#define IOTHDNS_RCODE_EFAIL  2
#define IOTHDNS_RCODE_ENOENT 3
#define IOTHDNS_RCODE_ENOSUP 4
#define IOTHDNS_RCODE_EPERM  5

#define IOTHDNS_CLASS_IN     1
#define IOTHDNS_CLASS_ANY  255

#define IOTHDNS_TYPE_A       1
#define IOTHDNS_TYPE_NS      2
/* ... */
#define IOTHDNS_TYPE_CNAME   5
#define IOTHDNS_TYPE_SOA     6
#define IOTHDNS_TYPE_NULL   10
#define IOTHDNS_TYPE_PTR    12
#define IOTHDNS_TYPE_MX     15
#define IOTHDNS_TYPE_TXT    16
#define IOTHDNS_TYPE_AAAA   28
#define IOTHDNS_TYPE_ANY   255

#endif
