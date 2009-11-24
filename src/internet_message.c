#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <string.h>
#include <errno.h>

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

	hdr->name = NULL;
	INIT_LIST_HEAD(&hdr->folding);
	list_add_tail(&hdr->lh, &ctx->hdrs);
	return 0;
}

int im_header_set_value(struct im_header_context *ctx)
{
	if ((list_entry(ctx->hdrs.prev, struct im_header, lh)->value = strdup(ctx->sb.s)) == NULL)
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

	list_add_tail(&fold->lh, &list_entry(ctx->hdrs.prev, struct im_header, lh)->folding);
	return 0;
}

int im_header_feed(struct im_header_context *ctx, char c)
{
	switch (ctx->state) {
	case IM_H_NAME1:
		if (strchr(white, c)) {
			if (list_empty(&ctx->hdrs))
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
		if (!list_empty(&ctx->hdrs) && im_header_set_value(ctx))
			return IM_OUT_OF_MEM;
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
