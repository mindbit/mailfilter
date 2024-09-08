/* SPDX-License-Identifier: GPLv2 */

#ifndef _STRING_TOOLS_H
#define _STRING_TOOLS_H

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <list.h>

/* ------------------------- String Buffer ------------------------- */

/* A few basic rules about string buffers:
 *   - sb->s is NULL after string_buffer_init() and is initialized
 *     after the first append operation;
 *   - sb->s can be explicitly initialized using string_buffer_enlarge()
 *   - if sb->s is not NULL, then it points to a null-terminated string
 */
struct string_buffer {
	char *s;
	size_t size;
	size_t cur;
	size_t chunk;
};

#define STRING_BUFFER_CHUNK 256

#define __STRING_BUFFER_INITIALIZER(__chunk) { .chunk = __chunk }
#define STRING_BUFFER_INITIALIZER __STRING_BUFFER_INITIALIZER(STRING_BUFFER_CHUNK)

static inline void __string_buffer_init(struct string_buffer *sb, size_t chunk)
{
	memset(sb, 0, sizeof(*sb));
	sb->chunk = chunk;
}

static inline void string_buffer_cleanup(struct string_buffer *sb)
{
	free(sb->s);
	sb->s = NULL;
}

#define __STRING_BUFFER_INIT(__sb, __chunk...) __string_buffer_init(__sb, __chunk)
#define string_buffer_init(__sb, __chunk...) __STRING_BUFFER_INIT(__sb, ##__chunk, STRING_BUFFER_CHUNK)

int __string_buffer_enlarge(struct string_buffer *sb, size_t chunk);
#define string_buffer_enlarge(sb) __string_buffer_enlarge((sb), (sb)->chunk)

static inline void string_buffer_reset(struct string_buffer *sb)
{
	sb->cur = 0;
	if (sb->s)
		sb->s[0] = '\0';
}

int string_buffer_append_char(struct string_buffer *sb, char c);
int string_buffer_append_string(struct string_buffer *sb, const char *s);
int string_buffer_append_strings(struct string_buffer *sb, ...);

/* ------------------ Generic string functionality ---------------- */

struct kv_pair {
	char *key;
	char *value;
	struct list_head lh;
};

/*
 * Parses a string in the form "key1=value1<sep> key2=value2<sep>, ..."
 * and adds kv_pair elements to the linked list lh. The function also skips
 * whitespace between key,value pairs. The list contains pointers to places
 * inside the original string and also alters the original string by
 * replacing the "=", ";" and whitespace with the null character.
 *
 * The caller must free up the storage for the list elements once he no
 * longer uses them.
 */
int string_kv_split(char *str, char delim, struct list_head *lh);

/*
 * Removes all whitespace from a string by altering the original string
 * No additional storage is allocated so the user must be careful to pass
 * a copy of the original string if they need to preserve the original.
 */
void string_remove_whitespace(char *str);

static inline const char *ltrim(const char *str)
{
	while (*str && isspace(*str))
		str++;

	return str;
}

#endif
