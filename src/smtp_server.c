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
#define _BSD_SOURCE

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <limits.h>

#include "js/js.h"

#include "smtp_server.h"
#include "smtp.h"
#include "base64.h"

//static uint64_t key;
static const char *module = "server";

// map SMTP commands to handlers
static struct smtp_cmd_hdlr smtp_cmd_hdlrs[PREPROCESS_HDLRS_LEN] = {
	DEFINE_SMTP_CMD_HDLR(init),
	DEFINE_SMTP_CMD_HDLR(auth),
	DEFINE_SMTP_CMD_HDLR(alou),
	DEFINE_SMTP_CMD_HDLR(alop),
	DEFINE_SMTP_CMD_HDLR(aplp),
	DEFINE_SMTP_CMD_HDLR(ehlo),
	DEFINE_SMTP_CMD_HDLR(data),
	DEFINE_SMTP_CMD_HDLR(mail),
	DEFINE_SMTP_CMD_HDLR(rcpt),
	DEFINE_SMTP_CMD_HDLR(rset),
	DEFINE_SMTP_CMD_HDLR(quit)
};

struct smtp_cmd_tree cmd_tree;

int smtp_cmd_register(const char *cmd, smtp_cmd_hdlr_t hdlr, int prio, int invokable)
{
	struct smtp_cmd_tree *node = &cmd_tree, *aux;
	struct smtp_cmd_hdlr_list *hlink;
	struct list_head *p;
	const char *c;

	for (c = cmd; *c != '\0'; c++) {
		assert_log(*c >= 'A' && *c <= 'Z', &config);
		if (node->next[*c - 'A'] != NULL) {
			node = node->next[*c - 'A'];
			continue;
		}
		aux = malloc(sizeof(struct smtp_cmd_tree));
		assert_log(aux != NULL, &config);
		memset(aux, 0, sizeof(struct smtp_cmd_tree));
		INIT_LIST_HEAD(&aux->hdlrs);
		node->next[*c - 'A'] = aux;
		node = aux;
	}

	list_for_each(p, &node->hdlrs) {
		if (list_entry(p, struct smtp_cmd_hdlr_list, lh)->prio > prio)
			break;
	}

	hlink = malloc(sizeof(struct smtp_cmd_hdlr_list));
	assert_log(hlink != NULL, &config);
	hlink->hdlr = hdlr;
	hlink->prio = prio;
	hlink->invokable = invokable;

	list_add_tail(&hlink->lh, p);
	return 0;
}

struct smtp_cmd_tree *smtp_cmd_lookup(const char *cmd)
{
	struct smtp_cmd_tree *node = &cmd_tree;

	while (*cmd != '\0' && node != NULL) {
		char c = *cmd;
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';
		if (c < 'A' || c > 'Z')
			return NULL;
		node = node->next[c - 'A'];
		cmd++;
	}

	return node;
}

int smtp_server_response(bfd_t *f, int code, const char *message)
{
	char *buf = (char *)message, *c;

	while ((c = index(buf, '\n'))) {
		*c = 0;
		log(&config, LOG_DEBUG, "[%s] <<< %d-%s", module, code, buf);
		bfd_printf(f, "%d-%s\r\n", code, buf);
		*c = '\n';
		buf = c + 1;
	}

	log(&config, LOG_DEBUG, "[%s] <<< %d %s", module, code, buf);
	if (bfd_printf(f, "%d %s\r\n", code, buf) >= 0) {
		bfd_flush(f);
		return 0;
	}

	return -1;
}

int smtp_server_process(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	int disconnect = 1;
	int hdlr_idx;
	int code;

	struct smtp_cmd_hdlr_list *hlink;
	struct smtp_cmd_hdlr *cmd_hdlr;
	char *message;

	code = 0;
	message = NULL;
	hdlr_idx = smtp_get_hdlr_idx(cmd);

	if (hdlr_idx != -1) {
		/* Get the structure with specific handler */
		cmd_hdlr = &smtp_cmd_hdlrs[hdlr_idx];

		/* Call the handler */
		disconnect = !cmd_hdlr->smtp_preprocess_hdlr(ctx, cmd, arg, stream);

		if (ctx->code) {
			code = ctx->code;
			message = ctx->message;
		} else {
			code = 451;
			message = strdup("Internal server error");
		}
	} else {
		code = 500;
		message = strdup("Command not implemented");
	}

	smtp_server_response(stream, code, message);

	if (message) {
		free(message);
	}

	return disconnect;
}

int smtp_get_hdlr_idx(const char *cmd) {
	int i;
	char cmd_lower[4];

	if (cmd == NULL) {
		return -1;
	}

	for (i = 0; i < 4; i++) {
		cmd_lower[i] = tolower((unsigned char) cmd[i]);
	}

	for (i = 0; i < PREPROCESS_HDLRS_LEN; i++) {
		if (strcmp(smtp_cmd_hdlrs[i].cmd_name, cmd_lower) == 0) {
			return i;
		}
	}

	return -1;
}

int __smtp_server_run(struct smtp_server_context *ctx, bfd_t *stream)
{
	int continue_session = 1;
	char buf[SMTP_COMMAND_MAX + 1];

	/* Command handling loop */
	do {
		char *c = &buf[0];
		char tmp;
		size_t i, n = 0;
		ssize_t sz;

		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) < 0) {
				mod_log(LOG_ERR, "Socket read error (%s). Aborting", strerror(errno));
				return -1;
			}
			if (!sz) {
				mod_log(LOG_ERR, "Lost connection to client");
				return -1;
			}
			n++;
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[sz] = '\0';

		/* Log received command (without the trailing '\n') */
		for (c += strlen(c) - 1; c >= &buf[0] && (*c == '\n' || *c == '\r'); c--);
		tmp = *++c;
		*c = '\0';
		mod_log(LOG_DEBUG, ">>> %s", &buf[0]);
		*c = tmp;
		c = &buf[0];

		/* reject oversized commands */
		if (n > 1) {
			smtp_server_response(stream, 421, "Command too long");
			return -1;
		}

		/* Parse SMTP command */
		c += strspn(c, white);
		n = strcspn(c, white);

		/* Prepare argument */
		if (c[n] != '\0') {
			c[n] = '\0';
			n++;
		}

		continue_session = smtp_server_process(ctx, c, c + n, stream);
	} while (continue_session);

	return 0;
}

void smtp_path_init(struct smtp_path *path)
{
	memset(path, 0, sizeof(struct smtp_path));
	INIT_LIST_HEAD(&path->domains);
	INIT_LIST_HEAD(&path->mailbox.domain.lh);
}

void smtp_path_cleanup(struct smtp_path *path)
{
	struct smtp_domain *pos, *n;

	if (path->mailbox.local != NULL && path->mailbox.local != EMPTY_STRING)
		free(path->mailbox.local);
	if (path->mailbox.domain.domain != NULL)
		free(path->mailbox.domain.domain);
	list_for_each_entry_safe(pos, n, &path->domains, lh) {
		free(pos->domain);
		free(pos);
	}

	//FIXME ctx->hdrs
}

void smtp_server_context_init(struct smtp_server_context *ctx)
{
	int i;

	memset(ctx, 0, sizeof(struct smtp_server_context));
	smtp_path_init(&ctx->rpath);
	INIT_LIST_HEAD(&ctx->fpath);

	for (i = 0; i < SMTP_PRIV_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ctx->priv_hash[i]);

	INIT_LIST_HEAD(&ctx->hdrs);
}

/**
 * Free resources and prepare for another SMTP transaction.
 *
 * This function is not only used at the end of the SMTP session, but
 * also by the default RSET handler.
 *
 * Besides closing all resources, this also leaves the context ready for
 * another SMTP session.
 */
void smtp_server_context_cleanup(struct smtp_server_context *ctx)
{
	struct smtp_path *path, *path_aux;
	struct im_header *hdr, *hdr_aux;

	smtp_path_cleanup(&ctx->rpath);
	smtp_path_init(&ctx->rpath);

	list_for_each_entry_safe(path, path_aux, &ctx->fpath, mailbox.domain.lh) {
		smtp_path_cleanup(path);
		free(path);
	}
	INIT_LIST_HEAD(&ctx->fpath);

	list_for_each_entry_safe(hdr, hdr_aux, &ctx->hdrs, lh) {
		im_header_free(hdr);
	}
	INIT_LIST_HEAD(&ctx->hdrs);

	if (ctx->body.stream != NULL)
		bfd_close(ctx->body.stream);
	ctx->body.stream = NULL;

	if (ctx->body.path[0] != '\0')
		unlink(ctx->body.path);
	ctx->body.path[0] = '\0';
}

int smtp_server_run(struct smtp_server_context *ctx, bfd_t *stream)
{
	int ret;
	int hdlr_idx;

	/* Handle initial greeting */
	if (!smtp_server_process(ctx, "INIT", NULL, stream) || !ctx->code)
		return 0;

	ret = __smtp_server_run(ctx, stream);

	/* Give all modules the chance to clean up (possibly after a broken
	 * connection */

	smtp_server_context_cleanup(ctx);

	return ret;
}

int smtp_path_parse_cmd(struct smtp_path *path, const char *arg, const char *word)
{
	char *trailing = arg;

	/* Look for passed-in word */
	arg += strspn(arg, white);
	if (strncasecmp(arg, word, strlen(word)))
		return 1;
	arg += strlen(word);

	/* Look for colon */
	arg += strspn(arg, white);
	if (*(arg++) != ':')
		return 1;

	/* Parse actual path */
	arg += strspn(arg, white);
	if (smtp_path_parse(path, arg, &trailing)) {
		smtp_path_cleanup(path);
		return 1;
	}
	if (trailing == arg)
		return 0;

	arg = trailing + strspn(trailing, white);
	if (*arg == '\0')
		return 0;
	// FIXME handle extra params, such as "SIZE=nnn"

	return 0;
}

int smtp_auth_login_parse_user(struct smtp_server_context *ctx, const char *arg)
{
	ctx->code = 334;
	if (arg) {
		ctx->auth_user = base64_dec(arg, strlen(arg), NULL);
		if (!ctx->auth_user) {
			ctx->code = 501;
			ctx->message = strdup("Cannot decode AUTH parameter");
			return SCHS_BREAK;
		}
		ctx->node = smtp_cmd_lookup("ALOP");
		ctx->message = base64_enc("Password:", strlen("Password:"));
	}
	else {
		ctx->node = smtp_cmd_lookup("ALOU");
		ctx->message = base64_enc("Username:", strlen("Username:"));
	}
	return SCHS_CHAIN;
}

int smtp_auth_login_parse_pw(struct smtp_server_context *ctx, const char *arg)
{
	ctx->auth_pw = base64_dec(arg, strlen(arg), NULL);
	if (!ctx->auth_pw) {
		ctx->code = 501;
		ctx->message = strdup("Cannot decode AUTH parameter");
		return SCHS_BREAK;
	}
	ctx->code = 250;
	return SCHS_OK;
}

int smtp_auth_plain_parse(struct smtp_server_context *ctx, const char *arg)
{
	char *auth_info, *p;
	int len;

	ctx->node = smtp_cmd_lookup("APLP");

	/* Parse (user, pw) from arg = base64(\0username\0password) */
	if (arg) {
		auth_info = base64_dec(arg, strlen(arg), &len);
		if (!auth_info) {
			ctx->code = 501;
			ctx->message = strdup("Cannot decode AUTH parameter");
			return SCHS_BREAK;
		}
		ctx->auth_user = strdup(auth_info + 1);
		p = auth_info + strlen(auth_info + 1) + 2;
		assert_mod_log(p - auth_info < len);
		ctx->auth_pw = strdup(p);
		free(auth_info);
		return SCHS_CHAIN;
	}

	/* Request the base64 encoded authentication string */
	ctx->code = 334;
	ctx->message = NULL;
	return SCHS_CHAIN;
}

int smtp_auth_unknown_parse(struct smtp_server_context *ctx, const char *arg)
{
	ctx->code = 504;
	ctx->message = strdup("AUTH mechanism not available");
	return SCHS_BREAK;
}

int smtp_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	ctx->code = 220;
	ctx->message = strdup("Mindbit Mail Filter");
	return SCHS_OK;
}

int smtp_hdlr_auth(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct {
		const char *name;
		int (*parse)(struct smtp_server_context *ctx, const char *arg);
	} auth_types[] = {
		{ "LOGIN", smtp_auth_login_parse_user },
		{ "PLAIN", smtp_auth_plain_parse },
		{ NULL, NULL },
	};
	char *c, tmp;
	int i;

	if (ctx->auth_user) {
		ctx->code = 503;
		ctx->message = strdup("Already Authenticated");
		return SCHS_OK;
	}

	c = strrchr(arg, ' ');
	if (c) {
		tmp = *c;
		*c = 0;
		ctx->auth_type = strdup(arg);
		*c = tmp;
		c++;
	}
	else {
		c = arg;
		c[strcspn(c, "\r\n")] = 0;
		ctx->auth_type = strdup(arg);
		c = NULL;
	}

	for (i = 0; auth_types[i].name; i++)
		if (!strcasecmp(ctx->auth_type, auth_types[i].name))
			return auth_types[i].parse(ctx, c);
	return smtp_auth_unknown_parse(ctx, c);
}

int smtp_hdlr_alou(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	assert_mod_log(!ctx->auth_user);

	if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) < 0)
		return SCHS_BREAK;
	buf[sz] = '\0';

	if (!strcmp(buf, "*\r\n")) {
		ctx->code = 501;
		ctx->message = strdup("AUTH aborted");
		return SCHS_BREAK;
	}

	return smtp_auth_login_parse_user(ctx, buf);
}

int smtp_hdlr_alop(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	assert_mod_log(!ctx->auth_pw);

	if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) < 0)
		return SCHS_BREAK;
	buf[sz] = '\0';

	if (!strcmp(buf, "*\r\n")) {
		ctx->code = 501;
		ctx->message = strdup("AUTH aborted");
		return SCHS_BREAK;
	}

	return smtp_auth_login_parse_pw(ctx, buf);
}

int smtp_hdlr_aplp(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	if (!ctx->auth_user) {
		if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) < 0)
			return SCHS_BREAK;
		buf[sz] = '\0';

		return smtp_auth_plain_parse(ctx, buf);
	}
	return SCHS_OK;
}

int smtp_hdlr_ehlo(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char *domain;

	/* We must break the rules and modify arg to strip the terminating newline. Otherwise
	 * the server to which we're proxying gets confused, since it expects the \r\n line
	 * ending. smtp_client_command already appends this.
	 */
	domain = (char *)arg;
	domain[strcspn(domain, "\r\n")] = '\0';

	/* Store client identity in the server's context */
	ctx->identity = strdup(domain);
	ctx->code = 250;
	ctx->message = strdup("AUTH LOGIN PLAIN\nHELP");

	return SCHS_OK;
}

int smtp_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	if (ctx->rpath.mailbox.local != NULL) {
		ctx->code = 503;
		ctx->message = strdup("Sender already specified");
		return SCHS_BREAK;
	}

	if (smtp_path_parse_cmd(&ctx->rpath, arg, "FROM")) {
		smtp_path_init(&ctx->rpath);
		ctx->code = 501;
		ctx->message = strdup("Syntax error");
		return SCHS_BREAK;
	}

	ctx->code = 250;
	ctx->message = strdup("Envelope sender ok");
	return SCHS_OK;
}

int smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct smtp_path *path;

	if (ctx->rpath.mailbox.local == NULL) {
		ctx->code = 503;
		ctx->message = strdup("Must specify envelope sender first");
		return SCHS_BREAK;
	}

	path = malloc(sizeof(struct smtp_path));
	if (path == NULL)
		return SCHS_BREAK;
	smtp_path_init(path);

	if (smtp_path_parse_cmd(path, arg, "TO")) {
		free(path);
		ctx->code = 501;
		ctx->message = strdup("Syntax error");
		return SCHS_BREAK;
	}

	list_add_tail(&path->mailbox.domain.lh, &ctx->fpath);
	ctx->code = 250;
	ctx->message = strdup("Recipient ok");

	return SCHS_OK;
}

int smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	int fd;

	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	if (list_empty(&ctx->fpath)) {
		ctx->code = 503;
		ctx->message = strdup("Must specify recipient(s) first");
		return SCHS_BREAK;
	}

	/* prepare temporary file to store message body */
	sprintf(ctx->body.path, "/tmp/mailfilter.XXXXXX"); // FIXME sNprintf; cale in loc de /tmp;
	if ((fd = mkstemp(ctx->body.path)) == -1) {
		ctx->body.path[0] = '\0';
		return SCHS_BREAK;
	}
	if ((ctx->body.stream = bfd_alloc(fd)) == NULL) {
		close(fd);
		unlink(ctx->body.path);
		ctx->body.path[0] = '\0';
		return SCHS_BREAK;
	}

	/* prepare response */
	smtp_server_response(stream, 354, "Go ahead");

	// Parse the BODY content of DATA
	struct im_header_context im_hdr_ctx = IM_HEADER_CONTEXT_INITIALIZER;
	struct stat stat;

	assert_mod_log(ctx->body.stream != NULL);

	im_hdr_ctx.max_size = 65536; // FIXME use proper value
	im_hdr_ctx.hdrs = &ctx->hdrs;
	//sleep(10);
	switch (smtp_copy_to_file(ctx->body.stream, stream, &im_hdr_ctx)) {
		case 0:
			insert_received_hdr(ctx);
			ctx->code = 250;
			ctx->message = strdup("Mail successfully received");
			break;
		case IM_PARSE_ERROR:
			ctx->code = 500;
			ctx->message = strdup("Could not parse message headers");
			return SCHS_ABORT;
		case IM_OVERRUN:
			ctx->code = 552;
			ctx->message = strdup("Message header size exceeds safety limits");
			return SCHS_ABORT;
		default:
			ctx->code = 452;
			ctx->message = strdup("Insufficient system storage");
			return SCHS_ABORT;
	}

	if (bfd_flush(ctx->body.stream) || fstat(ctx->body.stream->fd, &stat) == -1) {
		ctx->code = 452;
		ctx->message = strdup("Insufficient system storage");
		return SCHS_ABORT;
	}
	ctx->body.size = stat.st_size;

	//printf("path: %s\n", ctx->body.path); sleep(10);
	//im_header_write(&ctx->hdrs, stdout);

	// If no error until now, call the JS handler
	jsval ret = call_js_handler(cmd);

	// Get code and message from returned by JS handler
	ctx->code = js_get_code(ret);
	ctx->message = js_get_message(ret);

	return js_get_disconnect(ret);
}

int smtp_copy_to_file(bfd_t *out, bfd_t *in, struct im_header_context *im_hdr_ctx)
{
	const uint64_t DOTLINE_MAGIC	= 0x0d0a2e0000;	/* <CR><LF>"."<*> */
	const uint64_t DOTLINE_MASK		= 0xffffff0000;
	const uint64_t CRLF_MAGIC		= 0x0000000d0a; /* <CR><LF> */
	const uint64_t CRLF_MASK		= 0x000000ffff;
	uint64_t buf = 0;
	int fill = 0;
	int im_state = IM_OK;
	int c;

	while ((c = bfd_getc(in)) >= 0) {
		if (im_hdr_ctx && im_state == IM_OK) {
			im_state = im_header_feed(im_hdr_ctx, c);
			continue;
		}
		if (++fill > 8) {
			if (bfd_putc(out, buf >> 56) < 0)
				return -EIO;
			fill = 8;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if ((buf & CRLF_MASK) == CRLF_MAGIC) {
			/* we found the EOF sequence (<CR><LF>"."<CR><LF>) */
			assert_log(fill >= 5, &config);
			/* discard the (terminating) "."<CR><LF> */
			buf >>= 24;
			fill -= 3;
			break;
		}
		/* flush buffer up to the dot; otherwise we get false-positives for
		 * a line consisting of (only) two dots */
		assert_log(fill >= 5, &config);
		while (fill > 3)
			if (bfd_putc(out, (buf >> (--fill * 8)) & 0xff) < 0)
				return -EIO;
		buf &= CRLF_MASK;
		fill = 2;
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8)
		if (bfd_putc(out, (buf >> fill) & 0xff) < 0)
			return -EIO;

	return im_state == IM_OK || im_state == IM_COMPLETE ? 0 : im_state;
}

static struct im_header *create_received_hdr(struct smtp_server_context *ctx)
{
	char *remote_addr = inet_ntoa(ctx->addr.sin_addr);
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[32];
	char remote_host[NI_MAXHOST];
	char my_hostname[HOST_NAME_MAX];
	int rev = 0;
	//char *rcpt;
	struct im_header *hdr = im_header_alloc("Received");

	if (hdr == NULL)
		return NULL;

	if (!getnameinfo((struct sockaddr *)&ctx->addr, sizeof(ctx->addr), remote_host, sizeof(remote_host), NULL, 0, 0))
		rev = strcmp(remote_host, remote_addr);
	gethostname(my_hostname, sizeof(my_hostname));
	strftime(ts, sizeof(ts), "%a, %d %b %Y %H:%M:%S %z", tm);
	//rcpt = smtp_path_to_string(list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	asprintf(&hdr->value,
			"from %s (%s%s[%s]) by %s (8.14.2/8.14.2) with SMTP id %s; %s",
			ctx->identity ? ctx->identity: (rev ? remote_host : remote_addr),
			rev ? remote_host : "", rev ? " " : "",
			remote_addr, my_hostname, "abcdef123456", ts);
	//free(rcpt);

	return hdr;
}

/*
 * Generate an additional "Received" header
 */
int insert_received_hdr(struct smtp_server_context *ctx)
{
	struct im_header *hdr;
	struct list_head *lh = ctx->hdrs.next;

	hdr = im_header_find(ctx, "received");
	if (hdr)
		lh = &hdr->lh;

	if ((hdr = create_received_hdr(ctx)) == NULL)
		return -ENOMEM;

	im_header_refold(hdr, 78);
	list_add_tail(&hdr->lh, lh);
	return 0;
}

int smtp_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	ctx->code = 221;
	ctx->message = strdup("closing connection");
	return SCHS_QUIT;
}

int smtp_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	smtp_server_context_cleanup(ctx);
	ctx->code = 250;
	ctx->message = strdup("State reset complete");
	return SCHS_OK;
}

void smtp_server_init(void)
{
	// TODO urmatoarele trebuie sa se intample din config
	mod_proxy_init();
	//mod_spamassassin_init();
	//mod_clamav_init();
	//mod_log_sql_init();
}

int smtp_priv_register(struct smtp_server_context *ctx, uint64_t key, void *priv)
{
	struct smtp_priv_hash *h;

	h = malloc(sizeof(struct smtp_priv_hash));
	if (h == NULL)
		return -ENOMEM;

	h->key = key;
	h->priv = priv;
	list_add_tail(&h->lh, &ctx->priv_hash[smtp_priv_bucket(key)]);

	return 0;
}

void *smtp_priv_lookup(struct smtp_server_context *ctx, uint64_t key)
{
	struct smtp_priv_hash *h;
	int i = smtp_priv_bucket(key);

	list_for_each_entry(h, &ctx->priv_hash[i], lh)
		if (h->key == key)
			return h->priv;

	return NULL;
}

int smtp_priv_unregister(struct smtp_server_context *ctx, uint64_t key)
{
	struct smtp_priv_hash *h;
	int i = smtp_priv_bucket(key);

	list_for_each_entry(h, &ctx->priv_hash[i], lh)
		if (h->key == key) {
			list_del(&h->lh);
			free(h);
			return 0;
		}

	return -ESRCH;
}
