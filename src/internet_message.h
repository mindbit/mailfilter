#ifndef _INTERNET_MESSAGE_H
#define _INTERNET_MESSAGE_H

/* Data structures and functions to parse, manipulate and reassemble
 * internet message headers, according to RFC 2822 */

#include "list.h"
#include "string_tools.h"

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
	struct list_head hdrs;
	size_t max_size, curr_size;
	struct string_buffer sb;
};

enum {
	IM_OK,
	IM_COMPLETE,
	IM_OVERRUN,
	IM_OUT_OF_MEM,
	IM_PARSE_ERROR,
	IM_WTF
};

#endif
