/*   
 *   name_utils.c: name to string coversions 
 *   (as described in sections 3.1 and 4.1.4 of rfc 1035)
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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <name2dns.h>

struct name_compr {
	struct name_compr *next;
	short pos;
	short len;
	char name[];
};

/* add a name and its postition in the packet buffer to the list of previous names for compression */
static void name_compr_addname(struct name_compr **head, char *name, int namelen, short pos) {
	struct name_compr **scan;
	for (scan = head; *scan != NULL; scan = &((*scan)->next))
		;
	struct name_compr *new = malloc(sizeof(*new) + namelen + 1);
	if (new) {
		new->next = NULL;
		new->pos = pos;
		new->len = namelen;
		strcpy(new->name, name);
		*scan = new;
		//printf("added_new %s %d\n", new->name, new->pos);
	}
}

/* search in the list of previous names
	 complete or partial match is supported. */
static short name_compr_search(struct name_compr *head, char *name) {
	int namelen = strlen(name);
	struct name_compr *scan;
	for (scan = head; scan != NULL; scan = scan->next) {
		int lendiff = scan->len - namelen;
		//printf("CMP %d %s %s\n", lendiff, scan->name, name );
		if (lendiff == 0 && strcasecmp(scan->name, name) == 0)
			return scan->pos;
		else if (lendiff > 0 && scan->name[lendiff - 1] == '.'
				&& strcasecmp(scan->name + lendiff, name) == 0)
			return scan->pos + lendiff;
	}
	return 0;
}

/* this hidden function makes the actual conversion:
	 at each label of the domain name it checks if the 'tail' of the domain
	 name appears somewhere before.
	 If it does, it generates the compression pattern otherwise it converts
	 the label in dns format (length+chars) */
static unsigned int lname2dns(char *name, char *out, struct name_compr *compr_head) {
	unsigned int len = 0;
	while (*name) {
		unsigned short oldpos;
		char *itemlen = out++;
		if ((oldpos = name_compr_search(compr_head, name)) != 0 &&
				oldpos < 0xc000) {
			*itemlen = 0xc0 | (oldpos >> 8);
			*out =oldpos & 0xff;
			return len + 2;
		}
		//printf("name %s\n",name);
		while (*name !=0 && *name != '.')
			*out++ = *name++;
		if (*name == '.') name++;
		*itemlen = out - itemlen - 1;
		len += (*itemlen) + 1;
		//printf("itemlen %u\n",*itemlen);
	}
	*out=0;
	return len + 1;
}

/* convert a name in DNS format (using compression if compr_head != NULL):
	 host.domain.org. -> \004host\006domain\003org\000.
	 conversion is correct whether or not there is the final dot.
	 returns the length in byte of the converted string */
/* out must have at least the same size of name, i.e. strlen(name) + 1 */
unsigned int name2dns(const char *name, char *out, short pos, struct name_compr **compr_head) {
	int namelen = strlen(name);
	if (namelen == 0)
		return out[0] = 0, 1;
	else {
		int len;
		if (name[namelen - 1] == '.') namelen--;
		char lname[namelen + 1];
		sprintf(lname, "%*.*s", namelen, namelen, name);
		if (compr_head) {
			len = lname2dns(lname, out, *compr_head);
			if ((out[0] & 0xc00) != 0xc00) 
				name_compr_addname(compr_head, lname, namelen, pos);
		} else
			len = lname2dns(lname, out, NULL);
		return len;
	}
}

void name_compr_free(struct name_compr *compr_head) {
	struct name_compr *next;
	for (; compr_head != NULL; compr_head = next) {
		next = compr_head->next;
		free(compr_head);
	}
}
