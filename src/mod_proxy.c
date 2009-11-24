#define _XOPEN_SOURCE 500
#define _BSD_SOURCE

#include <assert.h>
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

static uint64_t key;
static const char *module = "proxy";

int copy_response_callback(int code, const char *message, int last, void *priv)
{
	struct smtp_server_context *ctx = priv;

	ctx->code = code;
	ctx->message = strdup(message);

	return 0;
}

int mod_proxy_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv;
	int sock, err = SCHS_ABORT;
	struct sockaddr_in peer;

	priv = malloc(sizeof(struct mod_proxy_priv));
	assert(priv != NULL);
	memset(priv, 0, sizeof(struct mod_proxy_priv));

	if (smtp_priv_register(ctx, key, priv) < 0)
		goto out_err;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		goto out_err;

	peer.sin_family = AF_INET;
	peer.sin_port = htons(25);
	inet_aton("127.0.0.1", &peer.sin_addr);

	if (connect(sock, (struct sockaddr *)&peer, sizeof(struct sockaddr_in)) == -1)
		goto out_err;

	priv->sock = fdopen(sock, "r+");
	if (!priv->sock)
		goto out_err;

	if (smtp_client_response(priv->sock, copy_response_callback, ctx) < 0)
		goto out_err;

	return SCHS_OK;
out_err:
	if (sock != -1)
		close(sock);
	smtp_priv_unregister(ctx, key);
	free(priv);
	return err;
}

int mod_proxy_hdlr_helo(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char *domain;

	assert(priv);

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

int mod_proxy_hdlr_ehlo(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char buf[SMTP_COMMAND_MAX + 1], *domain, *p, sep;

	assert(priv);

	/* We must break the rules and modify arg to strip the terminating newline. Otherwise
	 * the server to which we're proxying gets confused, since it expects the \r\n line
	 * ending. smtp_client_command already appends this.
	 */
	domain = (char *)arg;
	domain[strcspn(domain, "\r\n")] = '\0';

	/* send the EHLO command to the real SMTP server */
	smtp_client_command(priv->sock, cmd, domain);
	/* proxy the SMTP server output to our client */
	do {
		if (fgets(buf, sizeof(buf), priv->sock) == NULL)
			return SCHS_BREAK;
		if (strlen(buf) < 4)
			return SCHS_BREAK;
		if ((sep = buf[3]) != '-')
			break;
		fprintf(stream, "%s", buf);
	} while (1);
	fflush(stream);

	buf[strcspn(buf, "\r\n")] = '\0';
	buf[3] = '\0';
	ctx->code = strtol(buf, &p, 10);
	ctx->message = strdup(&buf[4]);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_auth(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);
	char buf[SMTP_COMMAND_MAX + 1], *p, sep;

	assert(priv);

	sprintf(buf, "%s %s", cmd, arg);

	do {
		/* proxy command to smtp server */
		if (fputs(buf, priv->sock) == EOF)
			return SCHS_BREAK;
		/* read back the smtp server response */
		if (fgets(buf, sizeof(buf), priv->sock) == NULL)
			return SCHS_BREAK;
		if (strlen(buf) < 4)
			return SCHS_BREAK;
		/* parse the response code and loop while it's 334 */
		sep = buf[3];
		buf[3] = '\0';
		ctx->code = strtol(buf, &p, 10);
		buf[3] = sep;
		if (ctx->code != 334)
			break;
		/* send the smtp server's response to the client */
		if (fputs(buf, stream) == EOF)
			return SCHS_BREAK;
		/* read next command from client */
		if (fgets(buf, sizeof(buf), stream) == NULL)
			return SCHS_BREAK;
	} while (1);

	buf[strcspn(buf, "\r\n")] = '\0';
	ctx->message = strdup(&buf[4]);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_c_mail(priv->sock, &ctx->rpath);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	if (list_empty(&ctx->fpath))
		return SCHS_BREAK;

	smtp_c_rcpt(priv->sock, list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "QUIT", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
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
		smtp_set_transaction_state(ctx, module, 0, NULL);
		return SCHS_BREAK;
	}

	free(ctx->message);
	ctx->code = 0;
	ctx->message = NULL;

	rewind(ctx->body.stream);
	if (smtp_copy_from_file(priv->sock, ctx->body.stream)) {
		/* leave code to 0 (fall back to the default Internal Server
		 * Error message); update transaction state just to set the module */
		smtp_set_transaction_state(ctx, module, 0, NULL);
		return SCHS_BREAK;
	}
	fflush(priv->sock);

	smtp_client_response(priv->sock, copy_response_callback, ctx);
	smtp_set_transaction_state(ctx, module, 0, NULL);
	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_proxy_hdlr_term(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_priv_unregister(ctx, key);
	free(priv);

	return SCHS_IGNORE;
}

/* void __attribute__((constructor)) my_init() */

void mod_proxy_init(void)
{
	key = smtp_priv_key(module);
	smtp_cmd_register("INIT", mod_proxy_hdlr_init, 100, 0);
	smtp_cmd_register("HELO", mod_proxy_hdlr_helo, 100, 1);
	smtp_cmd_register("EHLO", mod_proxy_hdlr_ehlo, 100, 1);
	smtp_cmd_register("AUTH", mod_proxy_hdlr_auth, 100, 1);
	smtp_cmd_register("MAIL", mod_proxy_hdlr_mail, 100, 1);
	smtp_cmd_register("RCPT", mod_proxy_hdlr_rcpt, 100, 1);
	smtp_cmd_register("QUIT", mod_proxy_hdlr_quit, 100, 1);
	smtp_cmd_register("BODY", mod_proxy_hdlr_body, 100, 0);
	smtp_cmd_register("TERM", mod_proxy_hdlr_term, 100, 0);
}

