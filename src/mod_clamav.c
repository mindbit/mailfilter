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
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "smtp_server.h"
#include "string_tools.h"

static uint64_t key;
static const char *module = "clamav";

#include "pexec.h"

int mod_clamav_send_headers(struct smtp_server_context *ctx, bfd_t *fw)
{
	return im_header_write(&ctx->hdrs, fw);
}

int mod_clamav_result(struct smtp_server_context *ctx, bfd_t *fr, int status)
{
	if (WEXITSTATUS(status) > 1) {
		mod_log(LOG_ERR, "clamdscan failed with error\n");
		return 0;
	}

	if (!WEXITSTATUS(status)) {
		mod_log(LOG_INFO, "message passed\n");
		return 0;
	}

	ctx->code = 550;

	do {
		struct string_buffer sb;
		char c;
		int i;

		string_buffer_init(&sb);
		/* first line of output is "stream: " followed
		 * by the virus name followed by " FOUND"; first
		 * skip "stream: " */
		for (i = 0; i < 8; i++)
			if (bfd_getc(fr) < 0)
				break;
		/* copy virus name */
		while ((c = bfd_getc(fr)) >= 0 && c != ' ')
			string_buffer_append_char(&sb, c);
		if (sb.s == NULL)
			break;
		if (asprintf(&ctx->message, "This message appears to be infected with the %s virus", sb.s) == -1)
			ctx->message = NULL;
	} while (0);
	if (ctx->message == NULL)
		ctx->message = strdup("This message appears to contain viruses");
	return 0;
}

int mod_clamav_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	const char *argv[] = {"/usr/bin/clamdscan", "-", NULL};

	return pexec_hdlr_body(ctx, argv, mod_clamav_send_headers, mod_clamav_result);
}

void mod_clamav_init(void)
{
}
