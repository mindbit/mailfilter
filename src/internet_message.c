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

#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>

#include "internet_message.h"
#include "smtp_server.h"
#include "js_main.h"

int add_new_header(jsval *header); // FIXME defined in js_main.c

static const char *tab_space = "\t ";

/* ==================== header parsing functions ==================== */

/*
 * Allocate a new header and initialize the name with the contents of the
 * context string buffer.
 */
static int im_header_alloc_ctx(struct im_header_context *ctx)
{
	ctx->curhdr = new_header_instance(ctx->sb.s);
	string_buffer_reset(&ctx->sb);

	return JSVAL_IS_NULL(ctx->curhdr) ? 1 : 0;
}


/*
 * Set the value of the "current" (currently being parsed) header to the
 * contents of the context string buffer.
 */
static int im_header_set_value_ctx(struct im_header_context *ctx)
{
	int ret = add_part_to_header(&ctx->curhdr, ctx->sb.s);
	add_new_header(&ctx->curhdr);
	ctx->curhdr = JSVAL_NULL;
	string_buffer_reset(&ctx->sb);
	return ret;
}

/*
 * Add a folding to the "current" (currently being parsed) header. The
 * folding position is the current position in the context string buffer.
 */
static int im_header_add_fold_ctx(struct im_header_context *ctx)
{
	add_part_to_header(&ctx->curhdr, ctx->sb.s);
	string_buffer_reset(&ctx->sb);
	return 0;
}

/*
 * Feed a single character to the header parsing state machine.
 */
int im_header_feed(struct im_header_context *ctx, char c)
{
	switch (ctx->state) {
	case IM_H_NAME1:
		if (strchr(tab_space, c)) {
			if (JSVAL_IS_NULL(ctx->curhdr))
				return IM_PARSE_ERROR;
			if (im_header_add_fold_ctx(ctx))
				return IM_OUT_OF_MEM;
			if (ctx->curr_size++ >= ctx->max_size)
				return IM_OVERRUN;
			if (string_buffer_append_char(&ctx->sb, c))
				return IM_OUT_OF_MEM;
			ctx->state = IM_H_FOLD;
			return IM_OK;
		}
		if (!JSVAL_IS_NULL(ctx->curhdr) && im_header_set_value_ctx(ctx)) {
			return IM_OUT_OF_MEM;
		}

		if (c == '\n') {
			return IM_COMPLETE;
		}
		if (c == '\r') {
			ctx->state = IM_H_FIN;
			printf("fin=%s\n", ctx->sb.s);
			return IM_OK;
		}
		/* Intentionally fall back to IM_H_NAME2 */
	case IM_H_NAME2:
		if (c == ':') {
			if (im_header_alloc_ctx(ctx))
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
		if (strchr(tab_space, c)) {
			string_buffer_append_char(&ctx->sb, c);
			return IM_OK;
		}
		/* Intentionally fall back to IM_H_VAL1 */
	case IM_H_VAL1:
		if (strchr(tab_space, c))
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
