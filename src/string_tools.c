/* SPDX-License-Identifier: GPLv2 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include "string_tools.h"
#include "mailfilter.h"

/**
 * @return	0 on success; POSIX error code on error
 */
int __string_buffer_enlarge(struct string_buffer *sb, size_t chunk)
{
	void *s = realloc(sb->s, sb->size + chunk);

	if (s == NULL)
		return ENOMEM;

	sb->s = s;
	sb->size += chunk;

	return 0;
}

/**
 * @return	0 on success; POSIX error code on error
 */
int string_buffer_append_char(struct string_buffer *sb, char c)
{
	int err;

	/* we add 1 to reserve an extra byte for the null terminator */
	if (sb->cur + 1 >= sb->size && (err = string_buffer_enlarge(sb)))
		return err;

	sb->s[sb->cur++] = c;
	sb->s[sb->cur] = '\0';

	return 0;
}

/**
 * @return	0 on success; POSIX error code on error
 */
int string_buffer_append_string(struct string_buffer *sb, const char *s)
{
	size_t len = strlen(s);

	if (sb->cur + len >= sb->size) {
		int err = __string_buffer_enlarge(sb,
			  ROUND_UP(sb->cur + len + 1 - sb->size, sb->chunk));
		if (err)
			return err;
	}

	strcpy(sb->s + sb->cur, s);
	sb->cur += len;

	return 0;
}

int string_buffer_append_strings(struct string_buffer *sb, ...)
{
	va_list ap;
	const char *s;
	int ret;

	va_start(ap, sb);
	for (s = va_arg(ap, const char *); s; s = va_arg(ap, const char *))
		if ((ret = string_buffer_append_string(sb, s)))
			break;
	va_end(ap);
	return ret;
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
