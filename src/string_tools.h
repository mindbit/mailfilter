#ifndef _STRING_TOOLS_H
#define _STRING_TOOLS_H

/* ------------------------- String Buffer ------------------------- */

struct string_buffer {
	char *s;
	size_t size, cur, chunk;
};

int string_buffer_append_char(struct string_buffer *sb, char c);
int string_buffer_append_string(struct string_buffer *sb, char *s);

#define STRING_BUFFER_CHUNK 256

void string_buffer_init(struct string_buffer *sb);

int __string_buffer_enlarge(struct string_buffer *sb, size_t chunk);
#define string_buffer_enlarge(sb) __string_buffer_enlarge((sb), (sb)->chunk)

/* ------------------ Generic expression expansion ---------------- */

typedef int (*expr_expand_callback_t)(struct string_buffer *sb, char key, const char *token, size_t tklen, void *priv);

int expr_expand(const char *expr, struct string_buffer *sb, const char *keys, expr_expand_callback_t cbk, void *priv, size_t *offset);

#endif
