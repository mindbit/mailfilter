#ifndef _STRING_TOOLS_H
#define _STRING_TOOLS_H

#include <string.h>
#include <stdlib.h>

/* ------------------------- String Buffer ------------------------- */

/* A few basic rules about string buffers:
 *   - sb->s is NULL after string_buffer_init() and is initialized
 *     after the first append operation;
 *   - sb->s can be explicitly initialized using string_buffer_enlarge()
 *   - if sb->s is not NULL, then it points to a null-terminated string
 */
struct string_buffer {
	char *s;
	size_t size, cur, chunk;
};

#define STRING_BUFFER_CHUNK 256

#define __STRING_BUFFER_INITIALIZER(__chunk) {\
	.s = NULL,\
	.size = 0,\
	.cur = 0,\
	.chunk = __chunk\
}

#define STRING_BUFFER_INITIALIZER __STRING_BUFFER_INITIALIZER(STRING_BUFFER_CHUNK)

static inline void __string_buffer_init(struct string_buffer *sb, size_t chunk)
{
	memset(sb, 0, sizeof(struct string_buffer));
	sb->chunk = chunk;
}

static inline void string_buffer_cleanup(struct string_buffer *sb)
{
	if (sb->s != NULL)
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

static inline int string_buffer_append_char(struct string_buffer *sb, char c)
{
	int err;

	/* we add 1 to keep an extra byte for the null terminator */
	if (sb->cur + 1 >= sb->size && (err = string_buffer_enlarge(sb)))
		return err;

	sb->s[sb->cur++] = c;
	/* we don't need to add a '\0' because string_buffer_enlarge()
	 * zeroes the newly allocated memory for us */

	return 0;
}

static inline int string_buffer_append_string(struct string_buffer *sb, const char *s)
{
	size_t len = strlen(s);
	int err;

	if (sb->cur + len >= sb->size && (err = __string_buffer_enlarge(sb, sb->chunk * ((sb->chunk + sb->cur + len - sb->size) / sb->chunk))))
		return err;

	strcpy(sb->s + sb->cur, s);
	sb->cur += len;

	return 0;
}

/* ------------------ Generic expression expansion ---------------- */

typedef int (*expr_expand_callback_t)(struct string_buffer *sb, char key, const char *token, size_t tklen, void *priv);

int expr_expand(const char *expr, struct string_buffer *sb, const char *keys, expr_expand_callback_t cbk, void *priv, size_t *offset);

#endif
