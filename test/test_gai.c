#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <iothdns.h>

static char *sst(int socktype) {
	switch (socktype) {
		case SOCK_STREAM: return "SOCK_STREAM";
		case SOCK_DGRAM: return "SOCK_DGRAM";
		case SOCK_RAW: return "SOCK_RAW";
		case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
		default: return"SOCK_UNKNOWN";
	}
}

static void usage(char *progname) {
	fprintf(stderr, "Usage: options host port\n", progname);
    exit(EXIT_FAILURE);
}

	int
main(int argc, char *argv[])
{
	static struct addrinfo hints;
	static char *shortopts = "rx46dsmapcnNeR:";
	static struct option longopts[] = {
		{"rev", no_argument, 0, 'r'},
		{"resolvconf", required_argument, 0, 'R'},
		{"native", no_argument, 0, 'x'},
		{"ipv4", no_argument, 0, '4'},
		{"ipv6", no_argument, 0, '6'},
		{"dgram", no_argument, 0, 'd'},
		{"stream", no_argument, 0, 's'},
		{"v4mapped", no_argument, 0, 'm'},
		{"all", no_argument, 0, 'a'},
		{"passive", no_argument, 0, 'p'},
		{"canonname", no_argument, 0, 'c'},
		{"numerichost", no_argument, 0, 'n'},
		{"numericserv", no_argument, 0, 'N'},
		{"errnoname", no_argument, 0, 'e'},
		{0, 0, 0, 0}};
	static char *default_ns =
		"search v2.cs.unibo.it cs.unibo.it\n"
		"nameserver 8.8.8.8";
	char *resolvconf = NULL;
	int rev = 0;
	int opt = 0;
	int native = 0;
	int revflags = 0;
	
	while((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) > 0) {
		switch(opt) {
			case 'r': rev = 1; break;
			case 'R': resolvconf = optarg; break;
			case 'x': native = 1; break;
			case '4': hints.ai_family = AF_INET; break;
			case '6': hints.ai_family = AF_INET6; break;
			case 'd': hints.ai_socktype = SOCK_DGRAM; revflags |= NI_DGRAM; break;
			case 's': hints.ai_socktype = SOCK_STREAM; break;
			case 'm': hints.ai_flags |= AI_V4MAPPED; break;
			case 'a': hints.ai_flags |= AI_ALL; break;
			case 'p': hints.ai_flags |= AI_PASSIVE; break;
			case 'c': hints.ai_flags |= AI_CANONNAME; break;
			case 'n': hints.ai_flags |= AI_NUMERICHOST; revflags |= NI_NUMERICHOST; break;
			case 'N': hints.ai_flags |= AI_NUMERICSERV; revflags |= NI_NUMERICSERV; break;
			case 'e': revflags |= NI_NAMEREQD; break;
			default: usage(argv[0]);
		}
	}

	if (argc - optind != 2)
		usage(argv[0]);

	char *hostarg = argv[optind];
	char *portarg = argv[optind + 1];

	if (hostarg[0] == 0) hostarg = NULL;
	if (portarg[0] == 0) portarg = NULL;

	struct iothdns *ns = NULL;
	if (native == 0) {
		if (resolvconf)
			ns	= iothdns_init(NULL, resolvconf);
		else
			ns	= iothdns_init_strcfg(NULL, default_ns);
	}

	if (rev) {
		static struct sockaddr_storage addr;

		int port = atoi(portarg);

		unsigned char testaddr[sizeof(struct in6_addr)];

		if (inet_pton(AF_INET, hostarg, testaddr) == 1) {
			struct sockaddr_in *s = (void *) &addr;
			s->sin_family = AF_INET;
			s->sin_port = htons(port);
			memcpy(&s->sin_addr, testaddr, sizeof(s->sin_addr));
		}
		if (inet_pton(AF_INET6, hostarg, testaddr) == 1) {
			struct sockaddr_in6 *s = (void *) &addr;
			s->sin6_family = AF_INET6;
			s->sin6_port = htons(port);
			memcpy(&s->sin6_addr, testaddr, sizeof(s->sin6_addr));
		}

		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
		int s;

		if (ns == NULL)
			s = getnameinfo((void *) &addr, sizeof(addr), hbuf, sizeof(hbuf), sbuf,
          sizeof(sbuf), revflags);
		else
			s = iothdns_getnameinfo(ns, (void *) &addr, sizeof(addr), hbuf, sizeof(hbuf), sbuf,
          sizeof(sbuf), revflags);

		if (s == 0)
			printf("host=%s, serv=%s\n", hbuf, sbuf);
	} else {
		struct addrinfo *result, *rp;
		int s;

		/* Obtain address(es) matching host/port */
		if (ns == NULL) 
			s = getaddrinfo(hostarg, portarg, &hints, &result);
		else
			s = iothdns_getaddrinfo(ns, hostarg, portarg, &hints, &result);
		if (s != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
			exit(EXIT_FAILURE);
		}

		/* getaddrinfo() returns a list of address structures.
			 Try each address until we successfully connect(2).
			 If socket(2) (or connect(2)) fails, we (close the socket
			 and) try the next address. */

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			char str[INET6_ADDRSTRLEN];
			struct sockaddr_in *s4 = (void *) rp->ai_addr;
			struct sockaddr_in6 *s6 = (void *) rp->ai_addr;
			switch(rp->ai_family) {
				case AF_INET:
					printf("IPv4 %s addr: %s port %d proto %d\n",
							sst(rp->ai_socktype),
							inet_ntop(rp->ai_family, &s4->sin_addr, str, INET6_ADDRSTRLEN),
							ntohs(s4->sin_port), rp->ai_protocol);
					if (rp->ai_canonname) printf("canon %s\n", rp->ai_canonname);
					break;
				case AF_INET6:
					printf("IPv6 %s addr: %s port %d proto %d\n",
							sst(rp->ai_socktype),
							inet_ntop(rp->ai_family, &s6->sin6_addr, str, INET6_ADDRSTRLEN),
							ntohs(s6->sin6_port), rp->ai_protocol);
					if (rp->ai_canonname) printf("canon %s\n", rp->ai_canonname);
					break;
				default:
					printf("unknown family\n");
			}
		}

		freeaddrinfo(result);           /* No longer needed */

		exit(EXIT_SUCCESS);
	}
}
