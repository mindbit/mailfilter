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

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "smtp_client.h"

int smtp_client_response(bfd_t *stream, smtp_client_callback_t callback, void *priv)
{
	char buf[SMTP_COMMAND_MAX + 1];
	long int code;
	char *p, sep;

	do {
		int n = 0;
		ssize_t len;

		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((len = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) <= 0)
				return SMTP_READ_ERROR;
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[len] = '\0';

		if (len < 4 || n > 1)
			return SMTP_PARSE_ERROR;
		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return SMTP_PARSE_ERROR;
		if (code < 100 || code > 999)
			return SMTP_INVALID_CODE;

		if (buf[len - 1] == '\n')
			buf[--len] = '\0';
		if (buf[len - 1] == '\r')
			buf[--len] = '\0';

		if (callback != NULL && callback(code, &buf[0] + 4, sep == ' ', priv))
			return code;
	} while (sep == '-');

	return code;
}

int smtp_put_path(bfd_t *stream, struct smtp_path *path)
{
	struct smtp_domain *domain;

	if (bfd_putc(stream, '<') < 0)
		return 1;

	list_for_each_entry(domain, &path->domains, lh) {
		if (bfd_putc(stream, '@') < 0)
			return 1;
		if (bfd_puts(stream, domain->domain) < 0)
			return 1;
		if (bfd_putc(stream, ':') < 0)
			return 1;
	}

	if (path->mailbox.local != EMPTY_STRING) {
		if (bfd_puts(stream, path->mailbox.local) < 0)
			return 1;
		if (bfd_putc(stream, '@') < 0)
			return 1;
		if (bfd_puts(stream, path->mailbox.domain.domain) < 0)
			return 1;
	}

	if (bfd_putc(stream, '>') < 0)
		return 1;

	return 0;
}

int smtp_put_path_cmd(bfd_t *stream, const char *cmd, struct smtp_path *path)
{
	if (bfd_puts(stream, cmd) < 0)
		return 1;
	if (bfd_putc(stream, ':') < 0)
		return 1;
	if (smtp_put_path(stream, path))
		return 1;
	if (bfd_puts(stream, "\r\n") < 0)
		return 1;
	if (bfd_flush(stream) < 0)
		return 1;
	return 0;
}

int smtp_c_mail(bfd_t *stream, struct smtp_path *path)
{
	return smtp_put_path_cmd(stream, "MAIL FROM", path);
}

int smtp_c_rcpt(bfd_t *stream, struct smtp_path *path)
{
	return smtp_put_path_cmd(stream, "RCPT TO", path);
}

int smtp_client_command(bfd_t *stream, const char *cmd, const char *arg)
{
	if (bfd_puts(stream, cmd) < 0)
		return 1;
	if (arg != NULL) {
		if (bfd_putc(stream, ' ') < 0)
			return 1;
		if (bfd_puts(stream, arg) < 0)
			return 1;
	}
	if (bfd_puts(stream, "\r\n") < 0)
		return 1;
	if (bfd_flush(stream) < 0)
		return 1;
	return 0;
}

int smtp_copy_from_file(bfd_t *out, bfd_t *in)
{
	const uint32_t DOTLINE_MAGIC	= 0x0d0a2e;	/* <CR><LF>"." */
	const uint32_t DOTLINE_MASK		= 0xffffff;
	const uint32_t CRLF_MAGIC		= 0x0d0a;	/* <CR><LF> */
	const uint32_t CRLF_MASK		= 0xffff;
	uint32_t buf = 0;
	int fill = 0, needcrlf = 1;
	int c;

	while ((c = bfd_getc(in)) >= 0) {
		if (++fill > 4) {
			if (bfd_putc(out, buf >> 24) < 0)
				return 1;
			fill = 4;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if (bfd_putc(out, (buf >> ((fill - 1) * 8)) & 0xff) < 0)
			return 1;
		buf = (buf << 8) | '.';
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8) {
		if (fill == 8 && (buf & CRLF_MASK) == CRLF_MAGIC)
			needcrlf = 0;
		if (bfd_putc(out, (buf >> fill) & 0xff) < 0)
			return 1;
	}

	/* send termination marker */
	if (needcrlf && bfd_puts(out, "\r\n") < 0)
		return 1;
	if (bfd_puts(out, ".\r\n") < 0)
		return 1;

	return 0;
}
