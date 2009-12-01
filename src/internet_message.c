#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "internet_message.h"

static const char *white = "\t ";

int im_header_alloc(struct im_header_context *ctx)
{
	struct im_header *hdr = malloc(sizeof(struct im_header));

	if (hdr == NULL)
		return -ENOMEM;

	if ((hdr->name = strdup(ctx->sb.s)) == NULL) {
		free(hdr);
		return -ENOMEM;
	}
	string_buffer_reset(&ctx->sb);

	hdr->value = NULL;
	INIT_LIST_HEAD(&hdr->folding);
	list_add_tail(&hdr->lh, ctx->hdrs);
	return 0;
}

int im_header_set_value(struct im_header_context *ctx)
{
	if ((list_entry(ctx->hdrs->prev, struct im_header, lh)->value = strdup(ctx->sb.s)) == NULL)
		return -ENOMEM;
	string_buffer_reset(&ctx->sb);
	return 0;
}

int im_header_add_fold(struct im_header_context *ctx)
{
	struct im_header_folding *fold = malloc(sizeof(struct im_header_folding));

	if (fold == NULL)
		return -ENOMEM;

	fold->offset = ctx->sb.cur;
	fold->original = NULL;

	list_add_tail(&fold->lh, &list_entry(ctx->hdrs->prev, struct im_header, lh)->folding);
	return 0;
}

int im_header_feed(struct im_header_context *ctx, char c)
{
	switch (ctx->state) {
	case IM_H_NAME1:
		if (strchr(white, c)) {
			if (list_empty(ctx->hdrs))
				return IM_PARSE_ERROR;
			if (im_header_add_fold(ctx))
				return IM_OUT_OF_MEM;
			if (ctx->curr_size++ >= ctx->max_size)
				return IM_OVERRUN;
			if (string_buffer_append_char(&ctx->sb, ' '))
				return IM_OUT_OF_MEM;
			ctx->state = IM_H_FOLD;
			return IM_OK;
		}
		if (!list_empty(ctx->hdrs) && im_header_set_value(ctx))
			return IM_OUT_OF_MEM;
		if (c == '\n') {
			return IM_COMPLETE;
		}
		if (c == '\r') {
			ctx->state = IM_H_FIN;
			return IM_OK;
		}
		/* Intentionally fall back to IM_H_NAME2 */
	case IM_H_NAME2:
		if (c == ':') {
			if (im_header_alloc(ctx))
				return IM_OUT_OF_MEM;
			ctx->state = IM_H_VAL1;
			return IM_OK;
		}
		if (ctx->curr_size++ >= ctx->max_size)
			return IM_OVERRUN;
		if (string_buffer_append_char(&ctx->sb, c))
			return IM_OUT_OF_MEM;
		/* This piece of code is also part of IM_H_NAME1, so set state */
		ctx->state = IM_H_NAME2;
		return IM_OK;
	case IM_H_FOLD:
		if (strchr(white, c)) {
			// TODO append to original folding
			return IM_OK;
		}
		/* Intentionally fall back to IM_H_VAL1 */
	case IM_H_VAL1:
		if (strchr(white, c))
			return IM_OK;
		/* Intentionally fall back to IM_H_VAL2 */
	case IM_H_VAL2:
		if (c == '\n') {
			ctx->state = IM_H_NAME1;
			return IM_OK;
		}
		if (c == '\r') {
			ctx->state = IM_H_VAL3;
			return IM_OK;
		}
		if (ctx->curr_size++ >= ctx->max_size)
			return IM_OVERRUN;
		if (string_buffer_append_char(&ctx->sb, c))
			return IM_OUT_OF_MEM;
		/* This piece of code is also part of IM_H_VAL1, so set state */
		ctx->state = IM_H_VAL2;
		return IM_OK;
	case IM_H_VAL3:
		if (c != '\n')
			return IM_PARSE_ERROR;
		ctx->state = IM_H_NAME1;
		return IM_OK;
	case IM_H_FIN:
		if (c != '\n')
			return IM_PARSE_ERROR;
		return IM_COMPLETE;
	}

	return IM_WTF;
}

int __im_header_write(struct im_header *hdr, FILE *f)
{
	char *s = hdr->value;
	struct im_header_folding *folding;
	size_t prev_offset = 0;

	if (hdr->name && fputs(hdr->name, f) == EOF)
		return 1;

	if (fputs(": ", f) == EOF)
		return 1;

	if (!s)
		return 0;

	list_for_each_entry(folding, &hdr->folding, lh) {
		size_t offset = folding->offset + 1;

		if (!fwrite(s, folding->offset - prev_offset, 1, f))
			return 1;
		s += offset - prev_offset;
		prev_offset = offset;
		if (fputs("\r\n\t", f) == EOF)
			return 1;
		/* FIXME replace \r\n\t sequence with folding->original when
		 * it is implemented by im_header_feed() */
	}

	if (fputs(s, f) == EOF)
		return 1;

	return 0;
}

int im_header_write(struct list_head *lh, FILE *f)
{
	struct im_header *hdr;
	int err;

	list_for_each_entry(hdr, lh, lh) {
		if ((err = __im_header_write(hdr, f)))
			return err;
		if (fputs("\r\n", f) == EOF)
			return 1;
	}

	return 0;
}

void im_header_dump(struct list_head *lh)
{
	struct im_header *hdr;
	int n = 1;

	list_for_each_entry(hdr, lh, lh) {
		printf("Nam %d: %s\n", n, hdr->name);
		printf("Val %d: %s\n", n, hdr->value);
		n++;
	}
}
