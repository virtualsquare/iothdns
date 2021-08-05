/*
 *   iothdns.c: client and server utility functions for dns packets RFC 1035 (and updates)
 *   iothdns_getaddrinfo and ioth_getnameinfo: parse a file link services(5)
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
#include <iothdns_getserv.h>

#define BLANKS " \t\n"
#define DIGITS "0123456789"
#define ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz"

struct gsparse {
	char *name, *port, *proto, *alias;
};

static inline void gsclear(struct gsparse *gs) {
	gs->name = gs->port = gs->proto = gs->alias = NULL;
}

/* parse a line:
 * addign each element of gs to the first char of each field */
static int gsparseline(char *s, struct gsparse *gs) {
	gsclear(gs);
	s += strspn(s, BLANKS);
	if (*s == '#' || *s == 0) return 0;
	if (strchr(ALPHA, *s) == NULL) return -1;
	gs->name = s;
	s += strspn(s, ALPHA DIGITS "-_");
	if (strchr(BLANKS, *s) == NULL) return -1;
	s += strspn(s, BLANKS);
	if (strchr(DIGITS, *s) == NULL) return -1;
	gs->port = s;
	s += strspn(s, DIGITS);
	if (strchr("/", *s) == NULL) return -1;
	s++;
	if (strchr(ALPHA, *s) == NULL) return -1;
	gs->proto = s;
	s += strspn(s, ALPHA);
	if (*s == '#') return 0;
	if (strchr(BLANKS, *s) == NULL) return -1;
	s += strspn(s, BLANKS);
	if (*s == '#') return 0;
	else if (strchr(ALPHA, *s) != NULL) {
		gs->alias = s;
		return 0;
	} else
		return -1;
}

/* word matching:
 * s can contain multiple blank separated words
 * gsmatch returns 1 id sample matches one of them. */
static int gsmatch(const char *sample, char *s) {
	size_t samplelen = strlen(sample);
	if (s == NULL) return 0;
	while (*s != 0) {
		s += strspn(s, BLANKS);
		if (strchr(ALPHA DIGITS "-_", *s) == NULL) break;
		if (strncmp(sample, s, samplelen) == 0 &&
				(s[samplelen] == 0 || strchr(BLANKS, s[samplelen])))
			return 1;
		s += strspn(s, ALPHA DIGITS "-_");
		if (strchr(BLANKS, *s) == NULL) break;
	}
	return 0;
}

/* iothdns_getservice maps a service string to its corresponding port #
 * using a file following the syntax of services(5) */
int iothdns_getservice(const char *servicefile, const char *servicename, const char *protocol) {
	int retval = -1;
	if (protocol == NULL) return -1;
	size_t protolen = strlen(protocol);
	FILE *f = fopen(servicefile, "r");
	if (f == NULL) return -1;
	char *line = NULL;
	size_t ll;
	while (getline(&line, &ll, f) > 0) {
		struct gsparse gs;
		if (gsparseline(line, &gs) == 0) {
			if (gsmatch(servicename, gs.name) || gsmatch(servicename, gs.alias))
			{
				char *proto = gs.proto;
				if (strncmp(protocol, proto, protolen) == 0 &&
						(proto[protolen] == 0 || strchr(BLANKS, proto[protolen]))) {
					retval = strtoul(gs.port, NULL, 10);
					break;
				}
			}
		}
	}
	fclose(f);
	return retval;
}

/* iothdns_getservice_rev maps a port number to its corresponding service string
 * using a file following the syntax of services(5) */
int iothdns_getservice_rev(const char *servicefile, int port, const char *protocol,
		char *serv, size_t servlen, int numeric) {
	if (protocol == NULL) return -1;
	if (serv == NULL) return -1;
	size_t retval = snprintf(serv, servlen, "%d", port);
	if (retval >= servlen || numeric)
		return retval;
	size_t protolen = strlen(protocol);
	FILE *f = fopen(servicefile, "r");
	if (f == NULL) return -1;
	char *line = NULL;
	size_t ll;
	while (getline(&line, &ll, f) > 0) {
		struct gsparse gs;
		if (gsparseline(line, &gs) == 0) {
			if (gs.name != NULL) {
				char *proto = gs.proto;
				if (strncmp(serv, gs.port, retval) == 0 && gs.port[retval] == '/' &&
						strncmp(protocol, proto, protolen) == 0 &&
						(proto[protolen] == 0 || strchr(BLANKS, proto[protolen]))) {
					retval = snprintf(serv, servlen, "%.*s",
							(int) strspn(gs.name, ALPHA DIGITS "-_"), gs.name);
					break;
				}
			}
		}
	}
	fclose(f);
	return retval;
}
