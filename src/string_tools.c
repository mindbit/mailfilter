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

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "string_tools.h"

int __string_buffer_enlarge(struct string_buffer *sb, size_t chunk)
{
	void *s = realloc(sb->s, sb->size + chunk);

	if (s == NULL)
		return ENOMEM;

	memset(s + sb->size, 0, chunk);
	sb->s = s;
	sb->size += chunk;

	return 0;
}

int expr_expand(const char *expr, struct string_buffer *sb, const char *keys, expr_expand_callback_t cbk, void *priv, size_t *offset)
{
	enum {
		S_EXPECT_KEY,
		S_EXPECT_KEY_ESCAPE,
		S_EXPECT_BRACKET,
		S_TOKEN,
		S_TOKEN_ESCAPE
	} state = S_EXPECT_KEY;
	char key = '\0';
	const char *token = NULL;
	char *p = (char *)expr;
	int err = 0, bracket = 0;

	if (keys == NULL)
		keys = "$";

	while (*p) {
		switch (state) {
		case S_EXPECT_KEY:
			if (*p == '\\') {
				state = S_EXPECT_KEY_ESCAPE;
				break;
			}
			if (strchr(keys, *p) == NULL) {
				string_buffer_append_char(sb, *p);
				break;
			}
			key = *p;
			state = S_EXPECT_BRACKET;
			break;
		case S_EXPECT_KEY_ESCAPE:
			string_buffer_append_char(sb, *p);
			state = S_EXPECT_KEY;
			break;
		case S_EXPECT_BRACKET:
			if (*p != '{') {
				err = -1;
				break;
			}
			token = p + 1;
			bracket++; /* should be 1 */
			break;
		case S_TOKEN:
			if (*p == '\\') {
				state = S_TOKEN_ESCAPE;
				break;
			}
			if (*p == '{') {
				bracket++;
				break;
			}
			if (*p != '}')
				break;
			if (--bracket)
				break;
			if ((err = cbk(sb, key, token, p - token, priv)))
				break;
			state = S_EXPECT_KEY;
			break;
		case S_TOKEN_ESCAPE:
			string_buffer_append_char(sb, *p);
			state = S_TOKEN;
			break;
		}

		if (err)
			break;

		p++;
	}

	if (state != S_EXPECT_KEY && !err)
		err = -2;

	if (err && offset != NULL)
		*offset = p - expr;

	return err;
}
