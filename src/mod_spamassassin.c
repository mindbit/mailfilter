#define _XOPEN_SOURCE 500

/* FIXME this needs to become a config option */
#define BYPASS_AUTH 1

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

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
		return SCHS_BREAK;
	}

	if (!WEXITSTATUS(status)) {
		mod_log(LOG_INFO, "message passed\n");
		return SCHS_IGNORE;
	}

	ctx->code = 550;
	ctx->message = strdup("This message appears to be spam");
	mod_log(LOG_INFO, "message rejected\n");
	return SCHS_BREAK;
}

int mod_spamassassin_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	const char *argv[] = {"/usr/bin/spamc", "-c", "-x", NULL};

	if (BYPASS_AUTH && ctx->auth_user) {
		mod_log(LOG_INFO, "bypassed authenticated user\n");
		return SCHS_IGNORE;
	}

	return pexec_hdlr_body(ctx, argv, mod_spamassassin_send_headers, mod_spamassassin_result);
}

void mod_spamassassin_init(void)
{
	smtp_cmd_register("BODY", mod_spamassassin_hdlr_body, 50, 0);
}
