#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <iothdns.h>

#define BUF_SIZE 500

static char *sst(int socktype) {
	switch (socktype) {
		case SOCK_STREAM: return "SOCK_STREAM";
		case SOCK_DGRAM: return "SOCK_DGRAM";
		case SOCK_RAW: return "SOCK_RAW";
		case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
		default: return"SOCK_UNKNOWN";
	}
}

	int
main(int argc, char *argv[])
{
	struct iothdns *ns = iothdns_init_strcfg(NULL,
			"search v2.cs.unibo.it cs.unibo.it\n"
			"nameserver 8.8.8.8");

	 if (argc < 3) {
    fprintf(stderr, "Usage: %s host port [rev]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

	if (argc > 3) {
		static struct sockaddr_storage addr;

		int port = atoi(argv[2]);

		unsigned char testaddr[sizeof(struct in6_addr)];

		if (inet_pton(AF_INET, argv[1], testaddr) == 1) {
			struct sockaddr_in *s = (void *) &addr;
			s->sin_family = AF_INET;
			s->sin_port = htons(port);
			memcpy(&s->sin_addr, testaddr, sizeof(s->sin_addr));
		}
		if (inet_pton(AF_INET6, argv[1], testaddr) == 1) {
			struct sockaddr_in6 *s = (void *) &addr;
			s->sin6_family = AF_INET6;
			s->sin6_port = htons(port);
			memcpy(&s->sin6_addr, testaddr, sizeof(s->sin6_addr));
		}

		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

		if (iothdns_getnameinfo(ns, (void *) &addr, sizeof(addr), hbuf, sizeof(hbuf), sbuf,
					sizeof(sbuf), 0) == 0)
			printf("host=%s, serv=%s\n", hbuf, sbuf);
	} else {
		struct addrinfo hints;
		struct addrinfo *result, *rp;
		int s;

		/* Obtain address(es) matching host/port */

		memset(&hints, 0, sizeof(hints));
		//hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
		hints.ai_family = AF_INET6;    /* Allow IPv4 or IPv6 */
		//hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
		hints.ai_socktype = 0;
		hints.ai_flags = 0;
		hints.ai_flags |= AI_V4MAPPED;
		hints.ai_flags |= AI_ALL;
		//hints.ai_flags |= AI_PASSIVE;
		hints.ai_flags |= AI_CANONNAME;

		hints.ai_protocol = 0;          /* Any protocol */

		if (*argv[1] == 0) argv[1] = NULL;
		if (*argv[2] == 0) argv[2] = NULL;
		s = iothdns_getaddrinfo(ns, argv[1], argv[2], &hints, &result);
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
