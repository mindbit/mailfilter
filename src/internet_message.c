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

static const char *tab_space = "\t ";

struct im_header *im_header_alloc(const char *name)
{
	struct im_header *hdr = malloc(sizeof(struct im_header));

	if (hdr == NULL)
		return NULL;

	if (name == NULL)
		hdr->name = NULL;
	else
		if ((hdr->name = strdup(name)) == NULL) {
			free(hdr);
			return NULL;
		}

	hdr->value = NULL;
	INIT_LIST_HEAD(&hdr->folding);
	return hdr;
}

struct im_header *im_header_find(struct smtp_server_context *ctx, const char *name)
{
	struct im_header *hdr;

	list_for_each_entry(hdr, &ctx->hdrs, lh) {
		if (!strcasecmp(hdr->name, name))
			return hdr;
	}

	return NULL;
}

void im_header_unfold(struct im_header *hdr)
{
	struct im_header_folding *fold, *tmp;

	list_for_each_entry_safe(fold, tmp, &hdr->folding, lh) {
		list_del(&fold->lh);
		if (fold->original)
			free(fold->original);
		free(fold);
	}
}

struct im_header_folding *im_header_add_fold(struct im_header *hdr, size_t offset)
{
	struct im_header_folding *fold = malloc(sizeof(struct im_header_folding));

	if (fold == NULL)
		return NULL;

	fold->offset = offset;
	fold->original = NULL;

	list_add_tail(&fold->lh, &hdr->folding);
	return fold;
}

int im_header_refold(struct im_header *hdr, int width)
{
	size_t len = strlen(hdr->name) + 2;
	char *p1 = hdr->value;
	char *p2 = p1;

	im_header_unfold(hdr);

	do {
		int count = 0;
		do {
			len += p2 - p1;
			p1 = p2;
			if ((p2 = strchr(p1, ' ')) == NULL)
				return 0;
			p2++;
			count++;
		} while (len + p2 - p1 < width);
		if (count > 1)
			im_header_add_fold(hdr, p1 - 1 - hdr->value);
		else
			im_header_add_fold(hdr, p2 - 1 - hdr->value);
		len = 8;
	} while (1);
}

/* ==================== header parsing functions ==================== */

/*
 * Allocate a new header and initialize the name with the contents of the
 * context string buffer.
 */
static jsval im_header_alloc_ctx(struct im_header_context *ctx)
{
	jsval header = new_header_instance(ctx->sb.s);
	string_buffer_reset(&ctx->sb);

	return header;
}


/*
 * Set the value of the "current" (currently being parsed) header to the
 * contents of the context string buffer.
 */
static int im_header_set_value_ctx(struct im_header_context *ctx, jsval *header)
{
	int ret = add_part_to_header(header, ctx->sb.s);

	add_new_header(header);

	string_buffer_reset(&ctx->sb);
	return ret;
}

/*
 * Add a folding to the "current" (currently being parsed) header. The
 * folding position is the current position in the context string buffer.
 */
static int im_header_add_fold_ctx(struct im_header_context *ctx, jsval *header)
{
	add_part_to_header(header, ctx->sb.s);
	string_buffer_reset(&ctx->sb);
	return 0;
}

/*
 * Feed a single character to the header parsing state machine.
 */
int im_header_feed(struct im_header_context *ctx, char c)
{
	jsval header;

	switch (ctx->state) {
	case IM_H_NAME1:
		if (strchr(tab_space, c)) {
			if (im_header_add_fold_ctx(ctx, &header))
				return IM_OUT_OF_MEM;
			if (ctx->curr_size++ >= ctx->max_size)
				return IM_OVERRUN;
			if (string_buffer_append_char(&ctx->sb, c))
				return IM_OUT_OF_MEM;
			ctx->state = IM_H_FOLD;
			return IM_OK;
		}
		if (ctx->start && im_header_set_value_ctx(ctx, &header)) {
			return IM_OUT_OF_MEM;
		}

		ctx->start = 1;

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
			header = im_header_alloc_ctx(ctx);
			if (JSVAL_IS_NULL(header))
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

int __im_header_write(struct im_header *hdr, bfd_t *f)
{
	char *s = hdr->value;
	struct im_header_folding *folding;
	size_t prev_offset = 0;

	if (hdr->name && bfd_puts(f, hdr->name) < 0)
		return 1;

	if (bfd_puts(f, ": ") < 0)
		return 1;

	if (!s)
		return 0;

	list_for_each_entry(folding, &hdr->folding, lh) {
		size_t offset = folding->offset + 1;

		if (bfd_write_full(f, s, folding->offset - prev_offset) < 0)
			return 1;
		s += offset - prev_offset;
		prev_offset = offset;
		if (bfd_puts(f, "\r\n\t") < 0)
			return 1;
		/* FIXME replace \r\n\t sequence with folding->original when
		 * it is implemented by im_header_feed() */
	}

	if (bfd_puts(f, s) < 0)
		return 1;

	return 0;
}

int im_header_write(struct list_head *lh, bfd_t *f)
{
	struct im_header *hdr;
	int err;

	list_for_each_entry(hdr, lh, lh) {
		if ((err = __im_header_write(hdr, f)))
			return err;
		if (bfd_puts(f, "\r\n") < 0)
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

void im_header_free(struct im_header *hdr)
{
	struct im_header_folding *folding, *folding_aux;

	if (hdr->name != NULL)
		free(hdr->name);
	if (hdr->value != NULL)
		free(hdr->value);
	list_for_each_entry_safe(folding, folding_aux, &hdr->folding, lh) {
		free(folding);
	}
	free(hdr);
}
