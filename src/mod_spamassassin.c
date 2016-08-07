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

/* FIXME this needs to become a config option */
#define BYPASS_AUTH 1

/* FIXME this needs to become a config option */
#define BYPASS_SIZE_TRESHOLD 500000

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <jsapi.h>

#include "smtp_server.h"

static uint64_t key;
static const char *module = "spamassassin";

#include "pexec.h"

int mod_spamassassin_send_headers(struct smtp_server_context *ctx, bfd_t *fw)
{
	return im_header_write(&ctx->hdrs, fw);
}

int mod_spamassassin_result(struct smtp_server_context *ctx, bfd_t *fr, int status)
{
	float score = 0, treshold = 0;
	char buf[100];
	ssize_t len;

	if ((len = bfd_read_line(fr, buf, sizeof(buf) - 1)) >= 0) {
		buf[len] = '\0';
		sscanf(buf, "%f/%f", &score, &treshold);
	}

	if (WEXITSTATUS(status) > 1) {
		mod_log(LOG_ERR, "spamc failed with error\n");
		return 0;
	}

	if (!WEXITSTATUS(status)) {
		mod_log(LOG_INFO, "message passed\n");
		return 0;
	}

	ctx->code = 550;
	ctx->message = strdup("This message appears to be spam");
	mod_log(LOG_INFO, "message rejected\n");
	return 0;
}

int mod_spamassassin_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	const char *argv[] = {"/usr/bin/spamc", "-c", "-x", NULL};

	if (BYPASS_AUTH && ctx->auth_user) {
		mod_log(LOG_INFO, "bypassed authenticated user\n");
		return 0;
	}

	if (ctx->body.size >= BYPASS_SIZE_TRESHOLD) {
		mod_log(LOG_INFO, "bypassed large message (size=%d, treshold=%d)\n", ctx->body.size, BYPASS_SIZE_TRESHOLD);
		return 0;
	}

	return pexec_hdlr_body(ctx, argv, mod_spamassassin_send_headers, mod_spamassassin_result);
}

void mod_spamassassin_init(void)
{
}
