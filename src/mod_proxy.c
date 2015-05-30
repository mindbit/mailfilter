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
#define _BSD_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "mod_proxy.h"
#include "smtp_client.h"
#include "base64.h"

static uint64_t key;
static const char *module = "proxy";

static const char *proxy_host = "127.0.0.1";
static const int proxy_port = 25;

int copy_response_callback(int code, const char *message, int last, void *priv)
{
	struct smtp_server_context *ctx = priv;

	ctx->code = code;
	ctx->message = strdup(message);

	return 0;
}

int mod_proxy_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv;
	int sock, err, ret = SCHS_ABORT;
	struct sockaddr_in peer;

	priv = malloc(sizeof(struct mod_proxy_priv));
	assert_mod_log(priv != NULL);
	memset(priv, 0, sizeof(struct mod_proxy_priv));

	if (smtp_priv_register(ctx, key, priv) < 0)
		goto out_err;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		goto out_err;

	peer.sin_family = AF_INET;
	peer.sin_port = htons(proxy_port);
	inet_aton(proxy_host, &peer.sin_addr); // FIXME: we should use getaddrinfo()

	if (connect(sock, (struct sockaddr *)&peer, sizeof(struct sockaddr_in)) == -1) {
		mod_log(LOG_ERR, "could not connect to %s, port %d\n", proxy_host, proxy_port);
		goto out_err;
	}
	mod_log(LOG_DEBUG, "connected to %s, port %d\n", proxy_host, proxy_port);

	priv->sock = bfd_alloc(sock);
	if (!priv->sock)
		goto out_err;

	if ((err = smtp_client_response(priv->sock, copy_response_callback, ctx)) < 0) {
		mod_log(LOG_ERR, "error %d reading initial greeting\n", err);
		goto out_err;
	}

	return SCHS_OK;
out_err:
	if (sock != -1)
		close(sock);
	smtp_priv_unregister(ctx, key);
	free(priv);
	return ret;
}

int mod_proxy_hdlr_helo(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char *domain;

	assert_mod_log(priv);

	/* We must break the rules and modify arg to strip the terminating newline. Otherwise
	 * the server to which we're proxying gets confused, since it expects the \r\n line
	 * ending. smtp_client_command already appends this.
	 */
	domain = (char *)arg;
	domain[strcspn(domain, "\r\n")] = '\0';
	smtp_client_command(priv->sock, cmd, domain);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_ehlo(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char buf[SMTP_COMMAND_MAX + 1], sep;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	ssize_t sz;

	assert_mod_log(priv);

	/* send the EHLO command to the real SMTP server */
	smtp_client_command(priv->sock, cmd, ctx->identity);
	/* read the real SMTP server response */
	do {
		if ((sz = bfd_read_line(priv->sock, buf, SMTP_COMMAND_MAX)) <= 0)
			goto out_err;
		buf[sz] = '\0';
		if (strlen(buf) < 4)
			goto out_err;
		if ((sep = buf[3]) != '-')
			break;
		buf[strcspn(buf, "\r\n")] = '\0';
		if (string_buffer_append_string(&sb, &buf[4]))
			goto out_err;
		if (string_buffer_append_char(&sb, '\n'))
			goto out_err;
	} while (1);

	buf[strcspn(buf, "\r\n")] = '\0';
	buf[3] = '\0';
	ctx->code = strtol(buf, NULL, 10);
	if (string_buffer_append_string(&sb, &buf[4]))
		goto out_err;
	ctx->message = sb.s;

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;

out_err:
	string_buffer_cleanup(&sb);
	return SCHS_BREAK;
}

int mod_proxy_auth_send_one(struct smtp_server_context *ctx, const char *cmd) {
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char buf[SMTP_COMMAND_MAX + 1], sep;
	ssize_t sz;

	assert_mod_log(priv);

	/* Send command to the real stmp server */
	if (smtp_client_command(priv->sock, cmd, NULL))
		return SCHS_BREAK;

	/* read back the smtp server response */
	if ((sz = bfd_read_line(priv->sock, buf, SMTP_COMMAND_MAX)) < 0)
		return SCHS_BREAK;
	buf[sz] = '\0';

	if (strlen(buf) < 4)
		return SCHS_BREAK;

	/* parse the response code */
	sep = buf[3];
	buf[3] = '\0';
	ctx->code = strtol(buf, NULL, 10);
	buf[3] = sep;

	if (ctx->code != 334) {
		buf[strcspn(buf, "\r\n")] = '\0';
		ctx->message = strdup(&buf[4]);
		return SCHS_BREAK;
	}

	return SCHS_OK;
}

int mod_proxy_hdlr_alop(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char buf[SMTP_COMMAND_MAX + 1], *user64, *pw64;
	int err;

	/* AUTH LOGIN base64(username) */
	user64 = base64_enc(ctx->auth_user, strlen(ctx->auth_user));
	if (!user64)
		return SCHS_BREAK;

	err = sprintf(buf, "AUTH LOGIN %s", user64);
	assert_mod_log(err < SMTP_COMMAND_MAX + 1);
	free(user64);

	err = mod_proxy_auth_send_one(ctx, buf);
	if (err != SCHS_OK)
		return err;

	/* base64(password) */
	pw64 = base64_enc(ctx->auth_pw, strlen(ctx->auth_pw));
	if (!pw64)
		return SCHS_BREAK;

	err = mod_proxy_auth_send_one(ctx, pw64);
	free(pw64);
	if (err != SCHS_OK)
		return err;

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_aplp(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	char buf[SMTP_COMMAND_MAX + 1], *auth64;
	int err;

	/* FIXME: should we brutally abort, or gracefully signal an internal server error? */
	assert_mod_log(ctx->auth_user);
	assert_mod_log(ctx->auth_pw);
	assert_mod_log(2 + strlen(ctx->auth_user) + strlen(ctx->auth_pw) < SMTP_COMMAND_MAX + 1);

	memset(buf, 0, sizeof(buf));
	memcpy(&buf[1], ctx->auth_user, strlen(ctx->auth_user));
	memcpy(&buf[2 + strlen(ctx->auth_user)], ctx->auth_pw, strlen(ctx->auth_pw));

	/* AUTH PLAIN base64(buf) */
	auth64 = base64_enc(buf, 2 + strlen(ctx->auth_user) + strlen(ctx->auth_pw));
	if (!auth64)
		return SCHS_BREAK;

	err = sprintf(buf, "AUTH PLAIN %s", auth64);
	assert_mod_log(err < SMTP_COMMAND_MAX + 1);
	free(auth64);

	err = mod_proxy_auth_send_one(ctx, buf);
	if (err != SCHS_OK)
		return err;

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_c_mail(priv->sock, &ctx->rpath);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	if (list_empty(&ctx->fpath))
		return SCHS_BREAK;

	smtp_c_rcpt(priv->sock, list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "QUIT", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	/* We have no handler for DATA. Instead, we use this handler to send
	 * both stages (DATA and message body) to the origin server.
	 *
	 * Once we send "DATA" to the origin server, there is no way to
	 * cancel message delivery. But it is only in the BODY stage that we
	 * know for sure if the message can be delivered (for instance the
	 * message can be rejected by antivir modules upon message body
	 * inspection).
	 *
	 * So we don't send anything to the origin server in the DATA stage,
	 * and then we send both stages when we reach the BODY stage.
	 */
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "DATA", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	if (ctx->code < 300 || ctx->code > 399) {
		return SCHS_BREAK;
	}

	free(ctx->message);
	ctx->code = 0;
	ctx->message = NULL;

	if (im_header_write(&ctx->hdrs, priv->sock))
		goto out_err;

	if (bfd_puts(priv->sock, "\r\n") < 0)
		goto out_err;

	bfd_seek(ctx->body.stream, 0, SEEK_SET);
	if (smtp_copy_from_file(priv->sock, ctx->body.stream))
		goto out_err;
	bfd_flush(priv->sock);

	smtp_client_response(priv->sock, copy_response_callback, ctx);
	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
out_err:
	/* leave code to 0 (fall back to the default Internal Server
	 * Error message); update transaction state just to set the module */
	return SCHS_BREAK;
}

int mod_proxy_hdlr_term(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_priv_unregister(ctx, key);
	free(priv);

	return SCHS_IGNORE;
}

int mod_proxy_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "RSET", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

/* void __attribute__((constructor)) my_init() */

void mod_proxy_init(void)
{
	key = smtp_priv_key(module);
}

