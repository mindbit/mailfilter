/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter.
 *
 * mailfilter is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * mailfilter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "mod_dkim.h"

#define DKIM_MAXHOSTNAMELEN	256
#define MAXPACKET		8192
#define BUFRSZ			1024

static int mod_dkim_dns_get_key(void)
{
	int len, qdcount, n, type, ancount, rdlength = 0, c;
	char dname[DKIM_MAXHOSTNAMELEN + 1];
	unsigned char answer[MAXPACKET];
	unsigned char buf[BUFRSZ + 1];
	unsigned char *cp, *eom, *eob, *p, *txtfound = NULL;
	HEADER hdr;

	snprintf(dname, sizeof(dname) - 1, "%s.%s.%s",
			"20120113", "_domainkey", "gmail.com");

	len = res_query(&dname[0], C_IN, T_TXT, &answer[0], sizeof(answer));
	if (len == -1) {
		printf("res_query() failed!\n");
		return len;
	}

	printf("DNS answer len: %d\n", len);

	memcpy(&hdr, &answer, sizeof(hdr));
	cp = &answer[0] + HFIXEDSZ;
	eom = &answer[0] + len;

	if (hdr.rcode != NOERROR) {
		printf("'%s' response error %d\n", dname, hdr.rcode);
		return -1;
	}

	/* Get the answer count */
	ancount = ntohs(hdr.ancount);
	if (ancount == 0) {
		printf("'%s' answer count is 0\n", dname);
		return -1;
	}

	printf("qdcount = %d\n", ntohs(hdr.qdcount));
	printf("ancount = %d\n", ancount);

	/* Skip over the Question section of the message */
	for (qdcount = ntohs(hdr.qdcount); qdcount > 0; qdcount--) {
		/* skip domain name */
		if ((n = dn_expand(&answer[0], eom, cp, dname, sizeof(dname))) < 0) {
			printf("'%s', reply corrupt\n", dname);
			return -1;
		}
		cp += n;

		if (cp + 2 * INT16SZ > eom) {
			printf("'%s', reply corrupt\n", dname);
			return -1;
		}

		/* skip type, class */
		cp += 2 * INT16SZ;
	}

	/* Extract the data from the first TXT reply */
	while (--ancount >= 0 && cp < eom) {
		/* skip domain name */
		if ((n = dn_expand(&answer[0], eom, cp,
						dname, sizeof(dname))) < 0) {
			printf("'%s': reply corrupt\n", dname);
			return -1;
		}
		cp += n;

		GETSHORT(type, cp);	/* get type */
		cp += INT16SZ; 		/* skip class */
		cp += INT32SZ; 		/* skip ttl */
		GETSHORT(n, cp);	/* get data length */

		if (type == T_TXT) {
			if (txtfound) {
				printf("multiple DNS replies for '%s'\n", dname);
				return -1;
			}
			txtfound = cp;
			rdlength = n;
		}
		cp += n;
	}


	if (!txtfound) {
		printf("'%s': no TXT record found in reply\n", dname);
		return -1;
	}

	cp = txtfound;

	if (cp + rdlength > eom) {
		printf("'%s': reply corrupt\n", dname);
		return -1;
	}

	/* extract the payload */
	memset(buf, 0, sizeof(buf));
	p = buf;
	eob = buf + sizeof(buf) - 1;
	while (rdlength > 0 && p < eob) {
		c = *cp++;
		rdlength--;
		while (c > 0 && p < eob) {
			*p++ = *cp++;
			c--;
			rdlength--;
		}
	}

	printf("after decoding buf = '%s'\n", buf);

	return 0;
}

static void mod_dkim_parse_signature(char *hdr)
{
	char *p, *end, *sep;

	hdr = strdup(hdr);
	printf("%s: '%s'\n", __func__, hdr);

	p = hdr;

	do {
		end = strchr(p, ';');
		sep = strchr(p, '=');

		*sep++ = 0;
		string_remove_whitespace(p);
		printf("key = '%s' ", p);

		if (end)
			*end++ = 0;

		string_remove_whitespace(sep);
		printf("value = '%s'\n", sep);
		p = end;
	} while (end);
	free(hdr);
}

static int mod_dkim_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct im_header *hdr;

	hdr = im_header_find(ctx, "dkim-signature");
	if (!hdr)
		return SCHS_OK;

	printf("DKIM-Signature header found!\n");
	mod_dkim_parse_signature(hdr->value);
	//mod_dkim_dns_get_key();

	return SCHS_OK;
}

void mod_dkim_init(void)
{
	smtp_cmd_register("BODY", mod_dkim_hdlr_body, 50, 0);
}
