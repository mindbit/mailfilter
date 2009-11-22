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

static uint64_t key;
static const char *module = "log_sql";

enum {
	PSTMT_CREATE_TRANSACTION,
	PSTMT_GET_TRANSACTION_ID,
	PSTMT_UPDATE_SENDER
};


static const char *prepared_statements[] = {
	[PSTMT_CREATE_TRANSACTION] =
		"INSERT INTO smtp_transactions(remote_addr, remote_port, time) VALUES ($1::inet, $2::integer, NOW())",
	[PSTMT_GET_TRANSACTION_ID] =
		"SELECT currval('smtp_transactions_smtp_transaction_id_seq')",
	[PSTMT_UPDATE_SENDER] =
		"UPDATE smtp_transactions SET envelope_sender=$1 WHERE smtp_transaction_id=$2::integer"
};

#include "mod_log_sql.h"
#include "smtp_client.h"
#include "pgsql_tools.h"

int mod_log_sql_new_transaction(struct smtp_server_context *ctx)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	PGresult *res;
	char remote_port[6];
	char *remote[] = {
		inet_ntoa(ctx->addr.sin_addr),
		&remote_port[0]
	};

	snprintf(remote_port, sizeof(remote_port), "%hu", ntohs(ctx->addr.sin_port));
	if ((res = _PQexecPrepared(ctx, priv->conn, PSTMT_CREATE_TRANSACTION, 2, (const char * const *)remote, NULL, NULL, 0)) == NULL)
		return -1;
	PQclear(res);

	/* It is safe to use currval() on associated sequence, since the value
	 * retrieved is stored separately (by the pgsql backend) for each session */
	if ((res = _PQexecPrepared(ctx, priv->conn, PSTMT_GET_TRANSACTION_ID, 0, NULL, NULL, NULL, 0)) == NULL)
		return -1;

	priv->smtp_transaction_id = atoll(PQgetvalue(res, 0, 0));
	/* FIXME verificam ca avem macar 1 rand rezultat */
	PQclear(res);

	mod_log(LOG_DEBUG, "New transaction id is %d\n", priv->smtp_transaction_id);
	return 0;
}

int mod_log_sql_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv;
	char *stmt;

	priv = malloc(sizeof(struct mod_log_sql_priv));
	assert(priv != NULL);
	memset(priv, 0, sizeof(struct mod_log_sql_priv));

	if (smtp_priv_register(ctx, key, priv) < 0)
		goto out_err;

	mod_log(LOG_DEBUG, "Using connect string %s\n", ctx->cfg->dbconn);

	priv->conn = PQconnectdb(ctx->cfg->dbconn);
	assert(priv->conn);
	if (PQstatus(priv->conn) != CONNECTION_OK) {
		mod_log(LOG_ERR, "Could not connect to database: %s\n", PQerrorMessage(priv->conn));
		goto out_err;
	}

	mod_log(LOG_INFO, "Database initialization complete\n");

	if (mod_log_sql_new_transaction(ctx))
		goto out_err;

	ctx->code = -1;
	return SCHS_OK;
out_err:
	if (priv->conn != NULL)
		PQfinish(priv->conn);
	smtp_priv_unregister(ctx, key);
	free(priv);
	return SCHS_ABORT;
}

/*
int mod_log_sql_hdlr_helo(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	char *domain;

	assert(priv);

	domain = (char *)arg;
	domain[strcspn(domain, "\r\n")] = '\0';
	smtp_client_command(priv->sock, cmd, domain);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}
*/

int mod_log_sql_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	char id[20];
	char *params[2] = {
		smtp_path_to_string(&ctx->rpath),
		&id[0]
	};
	PGresult *res;

	snprintf(id, sizeof(id), "%lld", priv->smtp_transaction_id);
	if ((res = _PQexecPrepared(ctx, priv->conn, PSTMT_UPDATE_SENDER, 2, (const char * const *)params, NULL, NULL, 0)) == NULL)
		return SCHS_BREAK;
	PQclear(res);

	ctx->code = -1;
	return SCHS_OK;
}

/*
int mod_log_sql_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	if (list_empty(&ctx->fpath))
		return SCHS_BREAK;

	smtp_c_rcpt(priv->sock, list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_log_sql_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_client_command(priv->sock, "QUIT", NULL);
	smtp_client_response(priv->sock, copy_response_callback, ctx);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}
*/

int mod_log_sql_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_log_sql_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	return ctx->code >= 200 && ctx->code <= 299 ? SCHS_OK : SCHS_BREAK;
}

int mod_log_sql_hdlr_term(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	smtp_priv_unregister(ctx, key);
	free(priv);

	return SCHS_IGNORE;
}

/* void __attribute__((constructor)) my_init() */

void mod_log_sql_init(void)
{
	key = smtp_priv_key(module);
	smtp_cmd_register("INIT", mod_log_sql_hdlr_init, 10, 0);
	/*
	smtp_cmd_register("HELO", mod_log_sql_hdlr_helo, 100, 1);
	*/
	smtp_cmd_register("MAIL", mod_log_sql_hdlr_mail, 100, 1);
	/*
	smtp_cmd_register("RCPT", mod_log_sql_hdlr_rcpt, 100, 1);
	smtp_cmd_register("QUIT", mod_log_sql_hdlr_quit, 100, 1);
	*/
	smtp_cmd_register("RSET", mod_log_sql_hdlr_rset, 1000, 1);
	smtp_cmd_register("BODY", mod_log_sql_hdlr_body, 1000, 0);
	smtp_cmd_register("TERM", mod_log_sql_hdlr_term, 1000, 0);
}

