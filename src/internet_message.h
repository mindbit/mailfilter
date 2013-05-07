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

#ifndef _INTERNET_MESSAGE_H
#define _INTERNET_MESSAGE_H

/* Data structures and functions to parse, manipulate and reassemble
 * internet message headers, according to RFC 2822 */

#include "list.h"
#include "string_tools.h"
#include "bfd.h"

/**
 * A single header: name-value pair.
 */
struct im_header {
	struct list_head lh;
	char *name;
	char *value;
	struct list_head folding;
};

/**
 * Folding offsets for a single header.
 */
struct im_header_folding {
	struct list_head lh;
	size_t offset;
	char *original;
};

/**
 * Context for message header parser.
 */
struct im_header_context {
	enum {
		IM_H_NAME1,
		IM_H_NAME2,
		IM_H_VAL1,
		IM_H_VAL2,
		IM_H_VAL3,
		IM_H_FOLD,
		IM_H_FIN
	} state;
	struct list_head *hdrs;
	size_t max_size, curr_size;
	struct string_buffer sb;
};

#define IM_HEADER_CONTEXT_INITIALIZER {\
	.state = IM_H_NAME1,\
	.hdrs = NULL,\
	.max_size = 0,\
	.curr_size = 0,\
	.sb = STRING_BUFFER_INITIALIZER\
}

enum {
	IM_OK,
	IM_COMPLETE,
	IM_OVERRUN,
	IM_OUT_OF_MEM,
	IM_PARSE_ERROR,
	IM_WTF
};

struct im_header *im_header_alloc(const char *name);
int im_header_feed(struct im_header_context *ctx, char c);
void im_header_dump(struct list_head *lh);
void im_header_unfold(struct im_header *hdr);
int im_header_refold(struct im_header *hdr, int width);
int im_header_write(struct list_head *lh, bfd_t *f);
void im_header_free(struct im_header *hdr);

#endif
