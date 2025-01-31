/* SPDX-License-Identifier: GPLv2 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <jsapi.h>

#include "mod_dkim.h"

#define DKIM_MAXHOSTNAMELEN	256
#define MAXPACKET		8192
#define BUFRSZ			1024

#if 0

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
	struct list_head lh;
	struct kv_pair *entry;

	hdr = strdup(hdr);

	printf("%s: '%s'\n", __func__, hdr);

	INIT_LIST_HEAD(&lh);
	string_kv_split(hdr, ';', &lh);

	list_for_each_entry(entry, &lh, lh) {
		string_remove_whitespace(entry->value);
		printf("key = '%s', value = '%s'\n", entry->key, entry->value);
	}

	free(hdr);
}

static int mod_dkim_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct im_header *hdr;

	hdr = im_header_find(ctx, "dkim-signature");
	if (!hdr)
		return 0;

	printf("DKIM-Signature header found!\n");
	mod_dkim_parse_signature(hdr->value);
	mod_dkim_dns_get_key();

	return 0;
}

void mod_dkim_init(void)
{
}

#endif
