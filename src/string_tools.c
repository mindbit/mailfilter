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
#include <ctype.h>

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

int string_kv_split(char *str, char delim, struct list_head *lh)
{
	struct kv_pair *pair;
	char *p, *tmp, *end, *sep;

	if (!lh)
		return -EINVAL;

	p = str;

	do {
		while (*p && isspace(*p))
			p++;

		end = strchr(p, delim);
		sep = strchr(p, '=');

		tmp = sep - 1;
		while (isspace(*tmp))
			*tmp-- = 0;

		*sep++ = 0;
		while (isspace(*sep))
			*sep++ = 0;

		if (end)
			*end++ = 0;

		pair = malloc(sizeof(*pair));
		if (!pair)
			return -ENOMEM;

		pair->key = p;
		pair->value = sep;
		list_add_tail(&pair->lh, lh);

		p = end;
	} while (end);

	return 0;
}

void string_remove_whitespace(char *str)
{
	char *p, *curr;

	for (p = curr = str; *curr; curr++) {
		if (!isspace(*curr))
			*p++ = *curr;
	}
	memset(p, 0, curr - p);
}

void string_remove_beginning_whitespace(char *str)
{
	char *p, *curr;
	int ok = 1;

	for (p = curr = str; *curr; curr++) {
		if (ok && isspace(*curr))
			continue;
		ok = 0;
		*p++ = *curr;
	}
	memset(p, 0, curr - p);
}
