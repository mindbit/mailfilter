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

#define _GNU_SOURCE
#include <string.h>

#include "smtp.h"
#include "string_tools.h"

const char *white = "\r\n\t ";

char *smtp_path_to_string(struct smtp_path *path)
{
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	struct smtp_domain *domain;

	if (string_buffer_append_char(&sb, '<'))
		goto out_err;

	list_for_each_entry(domain, &path->domains, lh) {
		if (string_buffer_append_char(&sb, '@'))
			goto out_err;
		if (string_buffer_append_string(&sb, domain->domain))
			goto out_err;
		if (string_buffer_append_char(&sb, ':'))
			goto out_err;
	}

	if (path->mailbox.local != EMPTY_STRING) {
		if (string_buffer_append_string(&sb, path->mailbox.local))
			goto out_err;
		if (string_buffer_append_char(&sb, '@'))
			goto out_err;
		if (string_buffer_append_string(&sb, path->mailbox.domain.domain))
			goto out_err;
	}

	if (string_buffer_append_char(&sb, '>'))
		goto out_err;
	return sb.s;

out_err:
	string_buffer_cleanup(&sb);
	return NULL;
}

int smtp_path_parse(struct smtp_path *path, const char *arg, char **trailing)
{
	enum {
		S_INIT,
		S_SEPARATOR,
		S_DOMAIN,
		S_MBOX_LOCAL,
		S_MBOX_DOMAIN,
		S_FINAL
	} state = S_INIT;
	const char *token = NULL;
	struct smtp_domain *domain;

	while (*arg != '\0') {
		switch (state) {
		case S_INIT:
			if (*arg != '<')
				return 1;
			state = S_SEPARATOR;
			arg++;
			continue;
		case S_SEPARATOR:
			if (strchr(white, *arg) != NULL) {
				arg++;
				continue;
			}
			if (*arg == '@') {
				state = S_DOMAIN;
				token = ++arg;
				continue;
			}
			if (*arg == '>') {
				path->mailbox.local = EMPTY_STRING;
				arg++;
				state = S_FINAL;
				continue;
			}
			token = arg;
			state = S_MBOX_LOCAL;
			continue;
		case S_DOMAIN:
			if (*arg == ',' || *arg == ':') {
				if (token == arg)
					return 1;
				domain = malloc(sizeof(struct smtp_domain));
				if (domain == NULL)
					return 2; // FIXME in cadrul apelant trebuie sa dau alt mesaj de eroare decat syntax err
				if ((domain->domain = strndup(token, arg - token)) == NULL) {
					free(domain);
					return 2; // FIXME
				}
				list_add_tail(&domain->lh, &path->domains);
			}
			if (*arg == ',') {
				++arg;
				state = S_SEPARATOR;
				continue;
			}
			if (*arg == ':') {
				token = ++arg;
				state = S_MBOX_LOCAL;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_LOCAL:
			if (*arg == '@') {
				if (token == arg)
					return 1;
				if ((path->mailbox.local = strndup(token, arg - token)) == NULL)
					return 2; // FIXME
				state = S_MBOX_DOMAIN;
				token = ++arg;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_DOMAIN:
			if (*arg == '>') {
				if (token == arg)
					return 1;
				if ((path->mailbox.domain.domain = strndup(token, arg - token)) == NULL)
					return 2; // FIXME
				state = S_FINAL;
			}
			arg++;
			continue;
		case S_FINAL:
			if (trailing) {
				*trailing = arg;
				return 0;
			}
			if (strchr(white, *(arg++)) == NULL)
				return 1;
			continue;
		}
	}

	return state == S_FINAL ? 0 : 1;
}
