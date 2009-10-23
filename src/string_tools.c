#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "string_tools.h"

void string_buffer_init(struct string_buffer *sb)
{
	memset(sb, 0, sizeof(struct string_buffer));
	sb->chunk = STRING_BUFFER_CHUNK;
}

int __string_buffer_enlarge(struct string_buffer *sb, size_t chunk)
{
	void *s = realloc(sb->s, sb->size + chunk);

	if (s == NULL)
		return ENOMEM;

	sb->s = s;
	sb->size += chunk;

	return 0;
}

int string_buffer_append_char(struct string_buffer *sb, char c)
{
	int err;

	if (sb->cur >= sb->size && (err = string_buffer_enlarge(sb)))
		return err;

	sb->s[sb->cur++] = c;

	return 0;
}

int expr_expand(const char *expr, struct string_buffer *sb, const char *keys, expr_expand_callback_t cbk, void *priv, size_t *offset)
{
	enum {
		S_EXPECT_KEY,
		S_EXPECT_BRACKET,
		S_TOKEN
	} state = S_EXPECT_KEY;
	char key = '\0';
	const char *token = NULL;
	char *p = (char *)expr;
	int err = 0;

	if (keys == NULL)
		keys = "$";

	while (*p) {
		switch (state) {
		case S_EXPECT_KEY:
			if (strchr(keys, *p) == NULL) {
				string_buffer_append_char(sb, *p);
				break;
			}
			key = *p;
			state = S_EXPECT_BRACKET;
			break;
		case S_EXPECT_BRACKET:
			if (*p == key) {
				string_buffer_append_char(sb, *p);
				break;
			}
			if (*p != '{') {
				err = -1;
				break;
			}
			token = p + 1;
			break;
		case S_TOKEN:
			if (*p != '}')
				break;
			if ((err = cbk(sb, key, token, p - token, priv)))
				break;
			state = S_EXPECT_KEY;
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
