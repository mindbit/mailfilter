/*
 * Copyright (C) 2016 Mindbit SRL
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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <jsmisc.h>

#include "mailfilter.h"

static int parse_t_a(duk_context *ctx, const ns_msg *hdl, const ns_rr *rr)
{
	char addr[16];

	if (ns_rr_rdlen(*rr) != 4)
		return 0;

	if (!inet_ntop(AF_INET, ns_rr_rdata(*rr), addr, sizeof(addr)))
		return 0;

	duk_push_string(ctx, addr);
	duk_put_prop_string(ctx, -2, "data");

	return 0;
}

static int parse_name(duk_context *ctx, const ns_msg *hdl, const ns_rr *rr)
{
	char name[MAXDNAME];
	const unsigned char *base = ns_msg_base(*hdl), *end = ns_msg_end(*hdl);

	if (ns_name_uncompress(base, end, ns_rr_rdata(*rr), name, sizeof(name)) < 0)
		return 0;

	duk_push_string(ctx, name);
	duk_put_prop_string(ctx, -2, "data");

	return 0;
}

/*
 * Parse a single answer section. The topmost element on the Duktape stack is an
 * array object that the resource records will be stored in.
 */
static int parse_section(duk_context *ctx, ns_msg *hdl, ns_sect sect)
{
	static const struct {
		ns_type type;
		int (*func)(duk_context *, const ns_msg *, const ns_rr *);
	} pmap[] = {
		{ns_t_a,	parse_t_a},
		{ns_t_cname,	parse_name},
		{ns_t_ns,	parse_name},
	};

	int rrnum, i;
	ns_rr rr;

	for (rrnum = 0; rrnum < ns_msg_count(*hdl, sect); rrnum++) {
		if (ns_parserr(hdl, sect, rrnum, &rr) < 0)
			return js_ret_error(ctx, "ns_parserr: %s", strerror(errno));

		duk_push_object(ctx);
		duk_push_string(ctx, ns_rr_name(rr));
		duk_put_prop_string(ctx, -2, "name");
		duk_push_int(ctx, ns_rr_type(rr));
		duk_put_prop_string(ctx, -2, "type");

		for (i = 0; i < ARRAY_SIZE(pmap); i++)
			if (pmap[i].type == ns_rr_type(rr)) {
				pmap[i].func(ctx, hdl, &rr);
				break;
			}

		duk_put_prop_index(ctx, -2, rrnum);
	}

	return 0;
}

static int Dns_revAddr(duk_context *ctx)
{
	int argc = duk_get_top(ctx);
	const char *addr, *domain = NULL;
	char *rev = NULL;
	unsigned char buf[sizeof(struct in6_addr)];
	size_t len;

	if (argc < 1)
		return js_ret_errno(ctx, EINVAL);

	addr = duk_to_string(ctx, 0);

	if (argc >= 2)
		domain = duk_to_string(ctx, 1);

	if (inet_pton(AF_INET, addr, buf)) {
		if (!domain)
			domain = "in-addr.arpa";

		len = 17 + strlen(domain);
		rev = malloc(len);
		if (!rev)
			return js_ret_errno(ctx, ENOMEM);

		snprintf(rev, len, "%hhu.%hhu.%hhu.%hhu.%s",
				buf[3], buf[2], buf[1], buf[0], domain);
	} else if (inet_pton(AF_INET6, addr, buf)) {
		int i;

		if (!domain)
			domain = "ip6.arpa";

		len = 65 + strlen(domain);
		rev = malloc(len);
		if (!rev)
			return js_ret_errno(ctx, ENOMEM);

		for (i = 15; i >= 0; i--)
			sprintf(&rev[(15 - i) * 4], "%hhx.%hhx.",
					buf[i] % 16, buf[i] / 16);
		strcpy(&rev[64], domain);
	}

	if (rev) {
		duk_push_string(ctx, rev);
		free(rev);
	} else
		duk_push_null(ctx);

	return 1;
}

static int Dns_query(duk_context *ctx)
{
	static const struct {
		ns_sect sect;
		const char *prop;
	} smap[] = {
		{ns_s_qd,	"question"},
		{ns_s_an,	"answer"},
		{ns_s_ns,	"ns"},
		{ns_s_ar,	"additional"},
	};

	const char *domain;
	int32_t type;
	struct __res_state rs;
	unsigned char rsp[NS_PACKETSZ];
	int rlen;
	ns_msg hdl;
	int i;

	if (res_ninit(&rs))
		return js_ret_error(ctx, "res_ninit: %s", hstrerror(h_errno));

	domain = duk_to_string(ctx, 0);
	type = duk_to_int32(ctx, 1);
	rlen = res_nquery(&rs, domain, ns_c_in, type, rsp, sizeof(rsp));

	if (rlen < 0) {
		duk_push_int(ctx, h_errno);
		return 1;
	}

	if (ns_initparse(rsp, rlen, &hdl))
		return js_ret_error(ctx, "ns_initparse: %s", strerror(errno));

	duk_push_object(ctx);
	for (i = 0; i < ARRAY_SIZE(smap); i++) {
		duk_push_array(ctx);
		parse_section(ctx, &hdl, smap[i].sect);
		duk_put_prop_string(ctx, -2, smap[i].prop);
	}

	return 1;
}

static const duk_number_list_entry Dns_props[] = {
	// h_errno
	{"HOST_NOT_FOUND",	HOST_NOT_FOUND},
	{"TRY_AGAIN",		TRY_AGAIN},
	{"NO_RECOVERY",		NO_RECOVERY},
	{"NO_DATA",		NO_DATA},
	// ns_type
	{"t_invalid",		ns_t_invalid},
	{"t_a",			ns_t_a},
	{"t_ns",		ns_t_ns},
	{"t_md",		ns_t_md},
	{"t_mf",		ns_t_mf},
	{"t_cname",		ns_t_cname},
	{"t_soa",		ns_t_soa},
	{"t_mb",		ns_t_mb},
	{"t_mg",		ns_t_mg},
	{"t_mr",		ns_t_mr},
	{"t_null",		ns_t_null},
	{"t_wks",		ns_t_wks},
	{"t_ptr",		ns_t_ptr},
	{"t_hinfo",		ns_t_hinfo},
	{"t_minfo",		ns_t_minfo},
	{"t_mx",		ns_t_mx},
	{"t_txt",		ns_t_txt},
	{"t_rp",		ns_t_rp},
	{"t_afsdb",		ns_t_afsdb},
	{"t_x25",		ns_t_x25},
	{"t_isdn",		ns_t_isdn},
	{"t_rt",		ns_t_rt},
	{"t_nsap",		ns_t_nsap},
	{"t_nsap_ptr",		ns_t_nsap_ptr},
	{"t_sig",		ns_t_sig},
	{"t_key",		ns_t_key},
	{"t_px",		ns_t_px},
	{"t_gpos",		ns_t_gpos},
	{"t_aaaa",		ns_t_aaaa},
	{"t_loc",		ns_t_loc},
	{"t_nxt",		ns_t_nxt},
	{"t_eid",		ns_t_eid},
	{"t_nimloc",		ns_t_nimloc},
	{"t_srv",		ns_t_srv},
	{"t_atma",		ns_t_atma},
	{"t_naptr",		ns_t_naptr},
	{"t_kx",		ns_t_kx},
	{"t_cert",		ns_t_cert},
	{"t_a6",		ns_t_a6},
	{"t_dname",		ns_t_dname},
	{"t_sink",		ns_t_sink},
	{"t_opt",		ns_t_opt},
	{"t_apl",		ns_t_apl},
	{"t_ds",		ns_t_ds},
	{"t_sshfp",		ns_t_sshfp},
	{"t_ipseckey",		ns_t_ipseckey},
	{"t_rrsig",		ns_t_rrsig},
	{"t_nsec",		ns_t_nsec},
	{"t_dnskey",		ns_t_dnskey},
	{"t_dhcid",		ns_t_dhcid},
	{"t_nsec3",		ns_t_nsec3},
	{"t_nsec3param",	ns_t_nsec3param},
	{"t_tlsa",		ns_t_tlsa},
	{"t_smimea",		ns_t_smimea},
	{"t_hip",		ns_t_hip},
	{"t_ninfo",		ns_t_ninfo},
	{"t_rkey",		ns_t_rkey},
	{"t_talink",		ns_t_talink},
	{"t_cds",		ns_t_cds},
	{"t_cdnskey",		ns_t_cdnskey},
	{"t_openpgpkey",	ns_t_openpgpkey},
	{"t_csync",		ns_t_csync},
	{"t_spf",		ns_t_spf},
	{"t_uinfo",		ns_t_uinfo},
	{"t_uid",		ns_t_uid},
	{"t_gid",		ns_t_gid},
	{"t_unspec",		ns_t_unspec},
	{"t_nid",		ns_t_nid},
	{"t_l32",		ns_t_l32},
	{"t_l64",		ns_t_l64},
	{"t_lp",		ns_t_lp},
	{"t_eui48",		ns_t_eui48},
	{"t_eui64",		ns_t_eui64},
	{"t_tkey",		ns_t_tkey},
	{"t_tsig",		ns_t_tsig},
	{"t_ixfr",		ns_t_ixfr},
	{"t_axfr",		ns_t_axfr},
	{"t_mailb",		ns_t_mailb},
	{"t_maila",		ns_t_maila},
	{"t_any",		ns_t_any},
	{"t_uri",		ns_t_uri},
	{"t_caa",		ns_t_caa},
	{"t_avc",		ns_t_avc},
	{"t_ta",		ns_t_ta},
	{"t_dlv",		ns_t_dlv},
	{NULL,			0.0}
};

static duk_function_list_entry Dns_functions[] = {
	{"revAddr",	Dns_revAddr, 	DUK_VARARGS},
	{"query",	Dns_query,	2},
	{NULL,		NULL,		0}
};

duk_bool_t js_dns_init(duk_context *ctx)
{
	duk_push_object(ctx);
	duk_put_number_list(ctx, -1, Dns_props);
	duk_put_function_list(ctx, -1, Dns_functions);
	duk_put_global_string(ctx, "Dns");

	return 1;
}
