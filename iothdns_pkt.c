/*
 *   iothdns_pkt.c: compose & parse dns packets RFC 1035 (and updates)
 *
 *   Copyright 2017-2021 Renzo Davoli - Virtual Square Team
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
#include <volatilestream.h>
#include <iothdns.h>
#include <name2dns.h>

struct iothdns_pkt {
	struct volstream *vols;
	FILE *f;
	int count[IOTHDNS_SECTIONS];
	union {
		struct { // WRONLY: compose packet
			struct name_compr *nc;
			int maxsec;
			long rdlength_pos;
		};
		struct { // RDONLY: parse packets
			void *buf;
			size_t bufsize;
			long nextrr;
		};
	};
};

void iothdns_put_int8(struct iothdns_pkt *vpkt, uint8_t data) {
	fputc(data, vpkt->f);
}

void iothdns_put_int16(struct iothdns_pkt *vpkt, uint16_t data) {
	fputc(data >> 8, vpkt->f);
	fputc(data, vpkt->f);
}

void iothdns_put_int32(struct iothdns_pkt *vpkt, uint32_t data) {
	fputc(data >> 24, vpkt->f);
	fputc(data >> 16, vpkt->f);
	fputc(data >> 8, vpkt->f);
	fputc(data, vpkt->f);
}

void iothdns_put_data(struct iothdns_pkt *vpkt, void *data, uint16_t len) {
	fwrite(data, len, 1, vpkt->f);
}

void iothdns_put_name(struct iothdns_pkt *vpkt, const char *name) {
	char dnsname[IOTHDNS_MAXNAME];
	int len = name2dns(name, dnsname, ftell(vpkt->f), &vpkt->nc);
	if (len > 0)
		iothdns_put_data(vpkt, dnsname, len);
}

void iothdns_put_name_uncompressed(struct iothdns_pkt *vpkt, const char *name) {
	char dnsname[IOTHDNS_MAXNAME];
	int len = name2dns(name, dnsname, 0, NULL);
	if (len > 0)
		iothdns_put_data(vpkt, dnsname, len);
}

void iothdns_put_string(struct iothdns_pkt *vpkt, char *string) {
	int len = strlen(string);
	if (len > IOTHDNS_MAXSTRING) len = IOTHDNS_MAXSTRING;
	iothdns_put_int8(vpkt, len);
	iothdns_put_data(vpkt, string, len);
}

void iothdns_put_a(struct iothdns_pkt *vpkt, void *addr_ipv4) {
	iothdns_put_data(vpkt, addr_ipv4, 4);
}

void iothdns_put_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6) {
	iothdns_put_data(vpkt, addr_ipv6, 16);
}

struct iothdns_pkt *iothdns_put_header(struct iothdns_header *h) {
	struct iothdns_pkt *new = calloc(1, sizeof(*new));
	new->f = volstream_openv(&new->vols);
	if (new->f == NULL)
		goto err;
	iothdns_put_int16(new, h->id);
	iothdns_put_int16(new, h->flags);
	iothdns_put_int16(new, 0); // QDCOUNT QUERY
	iothdns_put_int16(new, 0); // ANCOUNT ANSWER
	iothdns_put_int16(new, 0); // NSCOUNT AUTH
	iothdns_put_int16(new, 0); // ARCOUNT ADDITIONAL
	if (h->qname != NULL) {
		iothdns_put_name(new, h->qname);
		iothdns_put_int16(new, h->qtype);
		iothdns_put_int16(new, h->qclass);
		new->count[IOTHDNS_SEC_QUERY] = 1;
	};
	return new;
err:
	free(new);
	return NULL;
}

static void backpatch_rdlength(struct iothdns_pkt *vpkt) {
	if (vpkt->rdlength_pos > 0) {
		long pos = ftell(vpkt->f);
		fseek(vpkt->f, vpkt->rdlength_pos, SEEK_SET);
		iothdns_put_int16(vpkt, pos - vpkt->rdlength_pos - sizeof(uint16_t));
		fseek(vpkt->f, pos, SEEK_SET);
	}
	vpkt->rdlength_pos = 0;
}

void iothdns_put_rr(int section, struct iothdns_pkt *vpkt, struct iothdns_rr *rr) {
	if (section < IOTHDNS_SECTIONS && section >= vpkt->maxsec) {
		vpkt->maxsec = section;
		vpkt->count[section]++;
		backpatch_rdlength(vpkt);
		iothdns_put_name(vpkt, rr->name);
		iothdns_put_int16(vpkt, rr->type);
		iothdns_put_int16(vpkt, rr->class);
		iothdns_put_int32(vpkt, rr->ttl);
		vpkt->rdlength_pos = ftell(vpkt->f);
		iothdns_put_int16(vpkt, 0); // RDLENGTH
	}
}

static void iothdns_put_flush(struct iothdns_pkt *vpkt) {
	backpatch_rdlength(vpkt);
	fseek(vpkt->f, 2 * sizeof(uint16_t), SEEK_SET);
	iothdns_put_int16(vpkt, vpkt->count[IOTHDNS_SEC_QUERY]);
	iothdns_put_int16(vpkt, vpkt->count[IOTHDNS_SEC_ANSWER]);
	iothdns_put_int16(vpkt, vpkt->count[IOTHDNS_SEC_AUTH]);
	iothdns_put_int16(vpkt, vpkt->count[IOTHDNS_SEC_ADDITIONAL]);
	fseek(vpkt->f, 0, SEEK_END);
	fflush(vpkt->f);
}

uint8_t iothdns_get_int8(struct iothdns_pkt *vpkt) {
	int byte = fgetc(vpkt->f);
	return (byte > 0) ? byte : 0;
}

uint16_t iothdns_get_int16(struct iothdns_pkt *vpkt) {
	return (iothdns_get_int8(vpkt) << 8) | iothdns_get_int8(vpkt);
}

uint32_t iothdns_get_int32(struct iothdns_pkt *vpkt) {
	return (iothdns_get_int8(vpkt) << 24) | (iothdns_get_int8(vpkt) << 16) |
		(iothdns_get_int8(vpkt) << 8) | iothdns_get_int8(vpkt);
}

void *iothdns_get_data(struct iothdns_pkt *vpkt, void *data, uint16_t len) {
	size_t retval = fread(data, len, 1, vpkt->f);
	(void) retval;
	return data;
}

char *iothdns_get_name(struct iothdns_pkt *vpkt, char *name) {
	uint8_t len;
	if (name == NULL) {
		while((len = iothdns_get_int8(vpkt)) != 0) {
			if ((len & 0xc0) == 0xc0) {
				iothdns_get_int8(vpkt);
				break;
			}
			fseek(vpkt->f, len, SEEK_CUR);
		}
	} else {
		int index = 0;
		int limit = -1;
		while ((len = iothdns_get_int8(vpkt)) != 0 && index < IOTHDNS_MAXNAME - 1) {
			if ((len & 0xc0) == 0xc0) {
				int newpos = ((len & 0x3f) << 8) | iothdns_get_int8(vpkt);
				if (limit < 0) limit = ftell(vpkt->f);
				if (fseek(vpkt->f, newpos, SEEK_SET) < 0)
					break;
			} else {
				int i;
				if (index > 0)
					name[index++] = '.';
				for (i = 0; i < len && index < IOTHDNS_MAXNAME - 1; i++)
					name[index++] = iothdns_get_int8(vpkt);
			}
		}
		name[index] = 0;
		if (limit >= 0) fseek(vpkt->f, limit, SEEK_SET);
	}
	return name;
}

char *iothdns_get_string(struct iothdns_pkt *vpkt, char *name) {
	uint8_t len = iothdns_get_int8(vpkt);
	if (name == NULL) {
		fseek(vpkt->f, len, SEEK_CUR);
	} else {
		int index;
		for (index = 0; index < len; index++)
			name[index] = iothdns_get_int8(vpkt);
		name[index] = 0;
	}
	return name;
}

void *iothdns_get_a(struct iothdns_pkt *vpkt, void *addr_ipv4) {
	iothdns_get_data(vpkt, addr_ipv4, 4);
	return addr_ipv4;
}

void *iothdns_get_aaaa(struct iothdns_pkt *vpkt, void *addr_ipv6) {
	iothdns_get_data(vpkt, addr_ipv6, 16);
	return addr_ipv6;
}

struct iothdns_pkt *iothdns_get_header(struct iothdns_header *h, void *buf, size_t size, char *qnamebuf) {
	struct iothdns_pkt *new = calloc(1, sizeof(*new));
	new->f = fmemopen(buf, size, "r");
	if (new->f == NULL)
		goto err;
	h->id = iothdns_get_int16(new);
	h->flags = iothdns_get_int16(new);
	new->count[IOTHDNS_SEC_QUERY] = iothdns_get_int16(new);
	new->count[IOTHDNS_SEC_ANSWER] = iothdns_get_int16(new);
	new->count[IOTHDNS_SEC_AUTH] = iothdns_get_int16(new);
	new->count[IOTHDNS_SEC_ADDITIONAL] = iothdns_get_int16(new);
	if (new->count[IOTHDNS_SEC_QUERY] > 0) {
		h->qname = iothdns_get_name(new, qnamebuf);
		h->qtype = iothdns_get_int16(new);
		h->qclass = iothdns_get_int16(new);
		new->count[IOTHDNS_SEC_QUERY] = 0;
	}
	new->buf = buf;
	new->bufsize = size;
	new->nextrr = ftell(new->f);
	return new;
err:
	free(new);
	return NULL;
}

static int vdne_get_section(struct iothdns_pkt *vpkt) {
	int section;
	for (section = 1; section < IOTHDNS_SECTIONS; section++) {
		if (vpkt->count[section] > 0)
			break;
	}
	if (section == IOTHDNS_SECTIONS)
		return 0;
	else
		return vpkt->count[section]--, section;
}

int iothdns_get_rr(struct iothdns_pkt *vpkt, struct iothdns_rr *rr, char *namebuf) {
	int section = vdne_get_section(vpkt);
	fseek(vpkt->f, vpkt->nextrr, SEEK_SET);
	rr->name = iothdns_get_name(vpkt, namebuf);
	rr->type = iothdns_get_int16(vpkt);
	rr->class = iothdns_get_int16(vpkt);
	rr->ttl = iothdns_get_int32(vpkt);
	rr->rdlength = iothdns_get_int16(vpkt);
	vpkt->nextrr = ftell(vpkt->f) + rr->rdlength;
	return section;
}

void *iothdns_buf(struct iothdns_pkt *vpkt) {
	if (vpkt->vols == NULL) {
		return vpkt->buf;
	} else {
		iothdns_put_flush(vpkt);
		return volstream_getbuf(vpkt->vols);
	}
}

size_t iothdns_buflen(struct iothdns_pkt *vpkt) {
	if (vpkt->vols == NULL) {
		return vpkt->bufsize;
	} else {
		iothdns_put_flush(vpkt);
		return volstream_getsize(vpkt->vols);
	}
}

void iothdns_free(struct iothdns_pkt *vpkt) {
	if (vpkt->vols != NULL)
		name_compr_free(vpkt->nc);
	fclose(vpkt->f);
	free(vpkt);
}

void iothdns_rewrite_header(void *buf, size_t bufsize, uint16_t id, uint16_t flags) {
	FILE *f = fmemopen(buf, bufsize, "r+");
	fputc(id >> 8, f);
	fputc(id, f);
	fputc(flags >> 8, f);
	fputc(flags, f);
	fclose(f);
}
