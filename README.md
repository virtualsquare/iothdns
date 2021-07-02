# iothdns

## Name Resolution support library for the Internet of Threads.

The domain name resolution functions provided by the C library use the TCP-IP stack implemented in the Linux kernel.
They are thus unsuitable to support user level implemented stacks like those provided by [`libioth`](https://github.com/virtualsquare/libioth).

This library provides support for:

 * Client programs that need to query DNS servers
 * DNS servers, forwarders, filters that need to parse DNS queries, compose and send back appropriate replies

## Compile and Install

Pre-requisites: [`libioth`](https://github.com/virtualsquare/libioth) (and [`iothconf`](https://github.com/virtualsquare/iothconf) only for some examples, not for the library itself)

`iothdns` uses cmake. The standard building/installing procedure is:

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

An uninstaller is provided for your convenience. In the build directory run:
```
sudo make uninstall
```


## The API

### ioth configuration

The library must be initialized.The functions `iothdns_init` and `iothdns_init_strcfg` allow the user to choose
the _ioth_ stack to use and to set the configuration parameters using the same syntax of `resolv.conf(5)`. The configuration can be provided as a pathname of a file (`iothdns_init`) or as a string (`iothdns_init_strcfg`).

```C
struct iothdns *iothdns_init(struct ioth *stack, char *path_config);
struct iothdns *iothdns_init_strcfg(struct ioth *stack, char *config);
int iothdns_update(struct iothdns *iothdns, char *path_config);
int iothdns_update_strcfg(struct iothdns *iothdns, char *config);

void iothdns_fini(struct iothdns *iothdns);
```

(`iothdns_init` uses `/etc/resolv.conf` if  `path_config` is NULL).
`iothdns_init` and `iothdns_init_strcfg` return a _iothdns descriptor_ used in many function of this API.
In case of error `NULL` is returned and `errno` provides a description of the error.

`iothdns_fini` closes the _iothdns descriptor_ and deallocates its data structures.

`iothdns_update` and `iothdns_update_strcfg` update the DNS resolution configuration. These functions return 0 in case
of success and -1 in case of error (using `errno` to identify the error encountered).

```C
enum iothdns_pathtag {IOTHDNS_HOSTS, IOTHDNS_SERVICES, ...};
void iothdns_setpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *newvalue);
int iothdns_getpath(struct iothdns *iothdns, enum iothdns_pathtag pathtag, char *buf, size_t size);
```

The domain name resolution functions provided by the C library use some system provided files like `/etc/hosts` and `/etc/services`. `iothdns` allows users to redefine files to be used instead of the system provided ones.

### ioth configuration examples

#### define `dd` to use the kernel stack and /etc/resolv.conf
```C
#include <iothdns.h>
struct iothdns *dd = iothdns_init(NULL, NULL);
...
iothdns_fini(dd);
```
#### define `dd` to use the kernel stack but a different configuration provided as a string
```C
#include <iothdns.h>
struct iothdns *dd = iothdns_init_strcfg(NULL,
  "search my.domain.org\n"
  "nameserver 80.80.80.80");
...
iothdns_fini(dd);
```

#### `dd` uses a `vdestack` user level stack, whose virtual interface `vde0` is connected to the VDE net `vxvde://234.0.0.1`.&nbsp;&nbsp; `vde0`'s IP address is 10.0.0.53/24, default gateway is 10.0.0.1. DNS is 1.1.1.1 (this example needs [`iothconf`](https://github.com/virtualsquare/iothconf))
```C
#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>
struct ioth *stack = ioth_newstack("vdestack", "vxvde://234.0.0.1");
ioth_config(stack, "eth,ip=10.0.0.53/24,gw=10.0.0.1");
struct iothdns *dd = iothdns_init_strcfg(stack, "nameserver 1.1.1.1");
...
iothdns_fini(dd);
```
#### user provided hosts/services files
```C
iothdns_setpath(IOTHDNS_HOSTS, "~/.myetc/hosts");
iothdns_setpath(IOTHDNS_SERVICES, "~/.myetc/services");
```

### high level API: client queries

`iothdns_getaddrinfo` and `iothdns_getnameinfo` are the `iothdns` counterparts of
`getaddrinfo(3)` and `getnameinfo(3)`. The only difference in the functions' signature is the heading _iothdns descriptor_.

```C
int iothdns_getaddrinfo(struct iothdns *iothdns,
    const char *node, const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res);

void iothdns_freeaddrinfo(struct addrinfo *res);

const char *iothdns_gai_strerror(int errcode);

int iothdns_getnameinfo(struct iothdns *iothdns,
    const struct sockaddr *addr, socklen_t addrlen,
    char *host, socklen_t hostlen,
    char *serv, socklen_t servlen, int flags);
```
Note: the implementation supports the most common usages, not all the special cases of `getaddrinfo(3)` and `getnameinfo(3)` are supported yet.

### mid level API: client queries

`hashdns` provides some functions to query for IPv4 or IPv6 addresses.

```C
int iothdns_lookup_a(struct iothdns *iothdns, const char *name, struct in_addr *a, int n);
int iothdns_lookup_aaaa(struct iothdns *iothdns, const char *name, struct in6_addr *aaaa, int n);
```

where `iothdns` is the _iothdns descriptor_, `name` is the name of the host to query for, `a` or `aaaa` is the pointer to a buffer for one more IP (v4 or v6) addresses, _n_ is the number of addresses that `a` or `aaaa` can  host.
The return value is:

 * __-1__: in case of error (e.g. `errno` is `ENOENT` in case of a non-existent name)
 * __0__: if the name is valid but there is not an IP address defined for it
 * __> 0__: the return value is the number of IP addresses defined for the queried name. the heading _n_ addresses are stored in the `a` or `aaaa` buffer (if the returned value is greater than `n` the remaining addresses are dropped).

### low level API: client side

The structure of DNS protocol messages is defined by RFC 1035.
Each message is composed by a header and 4 sections. Each section includes a sequence of resource records (RR):
```
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

```
All sections can be empty except the `Question` which (in practice) always contains one element.

```
typedef int lookup_cb_t(int section, struct iothdns_rr *rr, struct iothdns_pkt *vpkt, void *arg);
int iothdns_lookup_cb(struct iothdns *iothdns, const char *name, int qtype,
    lookup_cb_t *lookup_cb, void *arg);
int iothdns_lookup_cb_tcp(struct iothdns *iothdns, const char *name, int qtype,
    lookup_cb_t *lookup_cb, void *arg);
```
These functions support general purpose queries. `iothdns_lookup_cb` and `iothdns_lookup_cb_tcp` perform a query using UDP or TCP respectively. If a server returns a reply message the callback function `lookup_cb` is called once for each RR in the Answer, Authority and Additional sections.
The section number and the header of the resource record are passed to `lookup_cb` as arguments, specific payloads can be parsed using the packet parsing `iothdns_get...` functions on the `vpkt` parameter (see below).
If the callback function returns 0 the scan continues otherwise terminates.

### low level API: server side

```C
typedef struct iothdns_pkt *parse_request_t(struct iothdns_header *h, void *arg);
int iothdns_udp_process_request(int fd, parse_request_t *parse_request, void *arg);
int iothdns_tcp_process_request(int fd, parse_request_t *parse_request, void *arg);
```

`iothdns_udp_process_request` and `iothdns_tcp_process_request` read the data available on the
socket `fd` and call the callback `parse_request` for each query, then it send back the reply.
The callback argument `h` includes all the data from the DNS query header and question section.
The return value  of `parse_request` is the message to be sent back as the reply, this message is created
using the packet composing `iothdns_put...` functions (see below).

### very low level API: parsing RFC1035 messages

```C
struct iothdns_pkt *iothdns_get_header(struct iothdns_header *h, void *buf, size_t bufsize, char *qnamebuf);
int iothdns_get_rr(struct iothdns_pkt *vpkt, struct iothdns_rr *rr, char *namebuf);
uint8_t iothdns_get_int8(struct iothdns_pkt *vpkt);
uint16_t iothdns_get_int16(struct iothdns_pkt *vpkt);
uint32_t iothdns_get_int32(struct iothdns_pkt *vpkt);
void *iothdns_get_data(struct iothdns_pkt *vpkt, void *data, uint16_t len);
char *iothdns_get_name(struct iothdns_pkt *vpkt, char *name);
char *iothdns_get_string(struct iothdns_pkt *vpkt, char *name);
void *iothdns_get_a(struct iothdns_pkt *vpkt, void *addr_ipv4);
void *iothdns_get_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6);
void iothdns_free(struct iothdns_pkt *vpkt);
```
`iothdns_get_header` parses the header and question section of the message.
`qnamebuf` is a temporary buffer (whose length is `IOTHDNS_MAXNAME`) to store the query name.
`iothdns_get_header` returns a handler that can be used to get the other RRs (`iothdns_get_rr`) and the resource records' arguments (by the other `iothdns_get...` functions).
All the names returned in `iothdns_get_header`, `iothdns_get_rr` and `iothdns_get_name` are strings containing fully qualified domain names. The parsing of the compression defined in section 4.1.4 of RFC1035 is automatic.

### very low level API: composing RFC1035 messages
```C
struct iothdns_pkt *iothdns_put_header(struct iothdns_header *h);
void iothdns_put_rr(int section, struct iothdns_pkt *vpkt, struct iothdns_rr *rr);
void iothdns_put_int8(struct iothdns_pkt *vpkt, uint8_t data);
void iothdns_put_int16(struct iothdns_pkt *vpkt, uint16_t data);
void iothdns_put_int32(struct iothdns_pkt *vpkt, uint32_t data);
void iothdns_put_data(struct iothdns_pkt *vpkt, void *data, uint16_t len);
void iothdns_put_name(struct iothdns_pkt *vpkt, const char *name);
void iothdns_put_name_uncompressed(struct iothdns_pkt *vpkt, const char *name);
void iothdns_put_string(struct iothdns_pkt *vpkt, char *string);
void iothdns_put_a(struct iothdns_pkt *vpkt, void *addr_ipv4);
void iothdns_put_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6);
void *iothdns_buf(struct iothdns_pkt *vpkt);
size_t iothdns_buflen(struct iothdns_pkt *vpkt);
void iothdns_free(struct iothdns_pkt *vpkt);
```

`iothdns_put_header` creates a message containing the header and the question section from the fields of `h`.
It returns a handler that can be used to add all the other RRs (`iothdns_put_rr`) and the resource records' arguments (by the other `iothdns_put...`functions).
The length of the entire message as well as the length of each resource record are automatically computed and inserted in the correspodnent fields of the message. Moreover all the names added by `iothdns_put_header`, `iothdns_put_rr` and `iothdns_put_name` are automatically compressed using the method defined RFC1035, section 4.1.4.
The functions `iothdns_buf` and `iothdns_buflen` have been designed to be used in functions like `send(2)`, `sendto(2)` or `write(2)` to send the composed message to the other end (to the server if it is a query, to the client if it is a reply).

## Some tutorial examples

### Simple Query:

[`test_query.c`](https://raw.githubusercontent.com/virtualsquare/iothdns/master/test/test_query.c) is a simple example: it uses the networking stack of the kernel but it redefines the configuration data. It tests `iothdns_lookup_a`, `iothdns_lookup_aaaa` and `iothdns_lookup_cb_tcp`.

```sh
$ gcc -o test_query test_query.c -lhashdns
$ ./test_query mad.cs.unibo.it
1 130.136.5.6
1 2001:760:2e00:f005:226:b9ff:fe77:51b
section 1 qtype 5 mad.cs.unibo.it
cname maddalena.cs.unibo.it
```

### A query using a user level stack

[`test_iothq.c`](https://raw.githubusercontent.com/virtualsquare/iothdns/master/test/test_iothq.c) is an evolution of the previous example. It uses a user level implementation of a stack. This example needs [`iothconf`](https://github.com/virtualsquare/iothconf).

In the following usage example `test_iothq` uses a vdestack connected to a slirp emulator. The interface address is provided via dhcp.
```sh
$ gcc -o test_iothq test_iothq.c -liothdns -liothconf -lioth
$ ./test_iothq mad.cs.unibo.it vdestack slirp:// eth,dhcp
1 130.136.5.6
1 2001:760:2e00:f005:226:b9ff:fe77:51b
section 1 qtype 5 mad.cs.unibo.it
cname maddalena.cs.unibo.it
```

### A minimal DNS server

[`test_server.c`](https://github.com/virtualsquare/iothdns/blob/master/test/test_server.c) implements a minimal DNS server able to provide an A record (10.20.30.40) for the query `test.fake`.
The server returns a _name error_ for all the other queries. This server processes both UDP and TCP incoming queries.

The following usage example is based on [vdens](https://github.com/rd235/vdens).
```sh
t$ gcc -o test_server test_server.c -liothdns -lioth
$ vdens
$# ip link set lo up
$# ./test_server &
[1] 705
$# host test.fake 127.0.0.1
Using domain server:
Name: 127.0.0.1
Address: 127.0.0.1#53
Aliases:

test.fake has address 10.20.30.40
$# klll %1
[1]+  Terminated              ./test_server
$# exit
$
```

### getaddrinfo and getnameinfo

[`test_gai.c`](https://github.com/virtualsquare/iothdns/blob/master/test/test_gai.c) tests the iothdns implementation of getaddrinfo and getnameinfo.

The following command line interaction shows the usage banner of `test_gai` and some run.
Each query is tested with and without '-x', i.e. comparing `iothdns_get*info` with glibc's `get*info`.

```bash
t$ gcc -o test_gai test_gai.c -liothdns
$ ./test_gai
Usage: ./test_gai [options] host port
        -r --rev
        -R resolvconf_file     --resolvconf resolvconf_file
        -x --native
        -4 --ipv4
        -6 --ipv6
        -d --dgram
        -s --stream
        -m --v4mapped
        -a --all
        -p --passive
        -c --canonname
        -n --numerichost
        -N --numericserv
        -e --errnoname
$ ./test_gai mad.cs.unibo.it domain
IPv4 SOCK_STREAM addr: 130.136.5.6 port 53 proto 6
IPv4 SOCK_DGRAM addr: 130.136.5.6 port 53 proto 17
IPv6 SOCK_STREAM addr: 2001:760:2e00:f005:226:b9ff:fe77:51b port 53 proto 6
IPv6 SOCK_DGRAM addr: 2001:760:2e00:f005:226:b9ff:fe77:51b port 53 proto 17
$ ./test_gai -x mad.cs.unibo.it domain
IPv4 SOCK_STREAM addr: 130.136.5.6 port 53 proto 6
IPv4 SOCK_DGRAM addr: 130.136.5.6 port 53 proto 17
IPv6 SOCK_STREAM addr: 2001:760:2e00:f005:226:b9ff:fe77:51b port 53 proto 6
IPv6 SOCK_DGRAM addr: 2001:760:2e00:f005:226:b9ff:fe77:51b port 53 proto 17
$ ./test_gai multiip.v2.cs.unibo.it ssh
IPv4 SOCK_STREAM addr: 130.136.200.90 port 22 proto 6
IPv4 SOCK_STREAM addr: 130.136.200.92 port 22 proto 6
IPv4 SOCK_STREAM addr: 130.136.200.91 port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5a port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5c port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5b port 22 proto 6
$ ./test_gai -x multiip.v2.cs.unibo.it ssh
IPv4 SOCK_STREAM addr: 130.136.200.90 port 22 proto 6
IPv4 SOCK_STREAM addr: 130.136.200.91 port 22 proto 6
IPv4 SOCK_STREAM addr: 130.136.200.92 port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5c port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5a port 22 proto 6
IPv6 SOCK_STREAM addr: 2001:760:2e00:ff00::5b port 22 proto 6
$ ./test_gai -r 130.136.5.6 22
host=maddalena.cs.unibo.it, serv=ssh
$ ./test_gai -rx 130.136.5.6 22
host=maddalena.cs.unibo.it, serv=ssh
```
