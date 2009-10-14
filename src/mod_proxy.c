#define _XOPEN_SOURCE 500
#define _BSD_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>

#include "mod_proxy.h"
#include "smtp_client.h"

static uint64_t key;

void mod_proxy_priv_init(struct mod_proxy_priv *priv)
{
	memset(priv, 0, sizeof(struct mod_proxy_priv));
}

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
	int sock;
	struct sockaddr_in peer;

	priv = malloc(sizeof(struct mod_proxy_priv));
	// FIXME check for NULL
	mod_proxy_priv_init(priv);

	smtp_priv_register(ctx, key, priv);
	// FIXME check ret val

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		return SCHS_ABORT;

	peer.sin_family = AF_INET;
	peer.sin_port = htons(25);
	inet_aton("127.0.0.1", &peer.sin_addr);

	if (connect(sock, (struct sockaddr *)&peer, sizeof(struct sockaddr_in)) == -1)
		return SCHS_ABORT;

	priv->sock = fdopen(sock, "r+");
	// FIXME check NULL

	if (smtp_client_response(priv->sock, copy_response_callback, ctx) < 0)
		return SCHS_ABORT;

	return SCHS_OK;
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
	struct mod_proxy_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "DATA", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	if (ctx->code < 300 || ctx->code > 399)
		return SCHS_BREAK;

	free(ctx->message);
	ctx->code = 0;
	ctx->message = NULL;

	rewind(ctx->body.stream);
	if (smtp_copy_from_file(priv->sock, ctx->body.stream)) {
		/* leave code to 0 (fall back to the default Internal Server
		 * Error message) */
		return SCHS_BREAK;
	}
	fflush(priv->sock);

	smtp_client_response(priv->sock, copy_response_callback, ctx);
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
	key = smtp_priv_key("proxy");
	smtp_cmd_register("INIT", mod_proxy_hdlr_init, 100, 0);
	smtp_cmd_register("MAIL", mod_proxy_hdlr_mail, 100, 1);
	smtp_cmd_register("RCPT", mod_proxy_hdlr_rcpt, 100, 1);
	smtp_cmd_register("QUIT", mod_proxy_hdlr_quit, 100, 1);
	smtp_cmd_register("BODY", mod_proxy_hdlr_body, 100, 0);
	smtp_cmd_register("TERM", mod_proxy_hdlr_term, 100, 0);
}

