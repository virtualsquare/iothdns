#ifndef NAME_DNS_H
#define NAME_DNS_H
struct name_compr;

/* convert a name in DNS format (compression is enabled if compr_head != NULL)
	 host.domain.org. -> \004host\006domain\003org\000.
	 conversion is correct whether or not there is the final dot.
	 returns the length in byte of the converted string */
unsigned int name2dns(const char *name, char *out, short pos, struct name_compr **compr_head);

/* de-allocate the name list for dns message compression */
void name_compr_free(struct name_compr *compr_head);
#endif
