#define _XOPEN_SOURCE 500
#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <limits.h>

#include "smtp_server.h"

static uint64_t key;
static const char *module = "spamassassin";

#include "pexec.h"

static int write_received_hdr(struct smtp_server_context *ctx, FILE *fw)
{
	char *remote_addr = inet_ntoa(ctx->addr.sin_addr);
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[32];
	char remote_host[NI_MAXHOST];
	char my_hostname[HOST_NAME_MAX];
	char *rcpt;
	int ret;

	getnameinfo(&ctx->addr, sizeof(ctx->addr), remote_host, sizeof(remote_host), NULL, 0, 0);
	gethostname(my_hostname, sizeof(my_hostname));
	strftime(ts, sizeof(ts), "%a, %d %b %Y %H:%M:%S %z", tm);
	rcpt = smtp_path_to_string(list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	ret = fprintf(fw,
			"Received: from %s (%s [%s]) by\r\n"
			"\t%s (8.14.2/8.14.2) with SMTP id abcdef123456 for\r\n"
			"\t%s; %s\r\n",
			ctx->identity ? ctx->identity: remote_addr,
			remote_host, remote_addr, my_hostname,
			rcpt, ts
			) < 0;
	free(rcpt);

	return ret;
}

int mod_spamassassin_send_headers(struct smtp_server_context *ctx, FILE *fw)
{
	struct im_header *hdr;
	int err, whdr = 1;

	/* Fabricate an additional "Received" header so that spamassassin
	 * can see the real sender ip address */

	list_for_each_entry(hdr, &ctx->hdrs, lh) {
		if (whdr && !strcasecmp(hdr->name, "received")) {
			whdr = 0;
			if ((err = write_received_hdr(ctx, fw)))
				return err;
		}
		if ((err = __im_header_write(hdr, fw)))
			return err;
		if (fputs("\r\n", fw) == EOF)
			return 1;
	}

	return whdr ? write_received_hdr(ctx, fw) : 0;
}

int mod_spamassassin_result(struct smtp_server_context *ctx, FILE *fr, int status)
{
	float score = 0, treshold = 0;
	fscanf(fr, "%f/%f", &score, &treshold);

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

int mod_spamassassin_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	const char *argv[] = {"/usr/bin/spamc", "-c", "-x", NULL};

	return pexec_hdlr_body(ctx, argv, mod_spamassassin_send_headers, mod_spamassassin_result);
}

void mod_spamassassin_init(void)
{
	smtp_cmd_register("BODY", mod_spamassassin_hdlr_body, 50, 0);
}
