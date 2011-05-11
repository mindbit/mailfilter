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

static uint64_t key;
static const char *module = "log_sql";

enum {
	PSTMT_CREATE_TRANSACTION,
	PSTMT_GET_TRANSACTION_ID,
	PSTMT_UPDATE_SENDER,
	PSTMT_ADD_RECIPIENT,
	PSTMT_UPDATE_TRANSACTION_STATE,
	PSTMT_UPDATE_SIZE,
};


static const char *prepared_statements[] = {
	[PSTMT_CREATE_TRANSACTION] =
		"INSERT INTO smtp_transactions(remote_addr, remote_port, time) VALUES ($1::inet, $2::integer, NOW())",
	[PSTMT_GET_TRANSACTION_ID] =
		"SELECT currval('smtp_transactions_smtp_transaction_id_seq')",
	[PSTMT_UPDATE_SENDER] =
		"UPDATE smtp_transactions SET envelope_sender=$1 WHERE smtp_transaction_id=$2::integer",
	[PSTMT_ADD_RECIPIENT] =
		"INSERT INTO smtp_transaction_recipients(smtp_transaction_id, recipient) VALUES($1::integer, $2)",
	[PSTMT_UPDATE_TRANSACTION_STATE] =
		"UPDATE smtp_transactions SET smtp_status_code=$1::integer, smtp_status_message=$2, module=$3 WHERE smtp_transaction_id=$4::integer",
	[PSTMT_UPDATE_SIZE] =
		"UPDATE smtp_transactions SET size=$1::integer WHERE smtp_transaction_id=$2::integer"
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

int mod_log_sql_end_transaction(struct smtp_server_context *ctx)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	uint64_t my_transaction_id = priv->smtp_transaction_id;
	char id[20], code[10];
	const char * params[4] = {
		&code[0],
		ctx->transaction.state.message,
		ctx->transaction.module,
		&id[0]
	};
	PGresult *res;

	if (!my_transaction_id)
		return 0;

	priv->smtp_transaction_id = 0;
	snprintf(id, sizeof(id), "%lld", (long long)my_transaction_id);
	snprintf(code, sizeof(code), "%d", ctx->transaction.state.code);

	res = _PQexecPrepared(ctx, priv->conn, PSTMT_UPDATE_TRANSACTION_STATE, 4, (const char * const *)params, NULL, NULL, 0);

	if (res == NULL)
		return -1;

	PQclear(res);

	return 0;
}

int mod_log_sql_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_log_sql_priv *priv;

	priv = malloc(sizeof(struct mod_log_sql_priv));
	assert_mod_log(priv != NULL);
	memset(priv, 0, sizeof(struct mod_log_sql_priv));

	if (smtp_priv_register(ctx, key, priv) < 0)
		goto out_err;

	mod_log(LOG_DEBUG, "Using connect string %s\n", ctx->cfg->dbconn);

	priv->conn = PQconnectdb(ctx->cfg->dbconn);
	assert_mod_log(priv->conn);
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

int mod_log_sql_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	char id[20];
	char *params[2] = {
		smtp_path_to_string(&ctx->rpath),
		&id[0]
	};
	PGresult *res;

	snprintf(id, sizeof(id), "%lld", (long long)priv->smtp_transaction_id);
	res = _PQexecPrepared(ctx, priv->conn, PSTMT_UPDATE_SENDER, 2, (const char * const *)params, NULL, NULL, 0);
	free(params[0]);

	if (res == NULL)
		return SCHS_BREAK;

	PQclear(res);
	ctx->code = -1;
	return SCHS_OK;
}

int mod_log_sql_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	char id[20];
	char *params[2] = {&id[0], NULL};
	PGresult *res;

	if (list_empty(&ctx->fpath))
		return SCHS_BREAK;

	snprintf(id, sizeof(id), "%lld", (long long)priv->smtp_transaction_id);
	params[1] = smtp_path_to_string(list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	res = _PQexecPrepared(ctx, priv->conn, PSTMT_ADD_RECIPIENT, 2, (const char * const *)params, NULL, NULL, 0);
	free(params[1]);

	if (res == NULL)
		return SCHS_BREAK;

	PQclear(res);
	ctx->code = -1;
	return SCHS_OK;
}

int mod_log_sql_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	if (mod_log_sql_end_transaction(ctx))
		return SCHS_BREAK;

	ctx->code = -1;
	return SCHS_OK;
}

int mod_log_sql_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	if (mod_log_sql_end_transaction(ctx))
		return SCHS_BREAK;

	if (mod_log_sql_new_transaction(ctx))
		return SCHS_BREAK;

	ctx->code = -1;
	return SCHS_OK;
}

int mod_log_sql_hdlr_term(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);

	mod_log_sql_end_transaction(ctx);

	PQfinish(priv->conn);

	smtp_priv_unregister(ctx, key);
	free(priv);

	return SCHS_IGNORE;
}

int mod_log_sql_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, bfd_t *stream)
{
	struct mod_log_sql_priv *priv = smtp_priv_lookup(ctx, key);
	char id[20], size[20];
	char * params[2] = {
		&size[0],
		&id[0]
	};
	PGresult *res;

	assert_mod_log(priv);

	if (!priv->smtp_transaction_id)
		return SCHS_BREAK;

	snprintf(id, sizeof(id), "%lld", (long long)priv->smtp_transaction_id);
	snprintf(size, sizeof(size), "%ld", ctx->body.size);

	res = _PQexecPrepared(ctx, priv->conn, PSTMT_UPDATE_SIZE, 2, (const char * const *)params, NULL, NULL, 0);
	if (res == NULL)
		return SCHS_BREAK;
	PQclear(res);

	/* use previous code and message */
	ctx->code = -1;

	return SCHS_OK;
}

/* void __attribute__((constructor)) my_init() */

void mod_log_sql_init(void)
{
	key = smtp_priv_key(module);
	smtp_cmd_register("INIT", mod_log_sql_hdlr_init, 10, 0);
	smtp_cmd_register("MAIL", mod_log_sql_hdlr_mail, 1000, 1);
	smtp_cmd_register("RCPT", mod_log_sql_hdlr_rcpt, 1000, 1);
	smtp_cmd_register("QUIT", mod_log_sql_hdlr_quit, 1000, 1);
	smtp_cmd_register("RSET", mod_log_sql_hdlr_rset, -10, 1);
	smtp_cmd_register("TERM", mod_log_sql_hdlr_term, 1000, 0);
	smtp_cmd_register("BODY", mod_log_sql_hdlr_body, 1000, 0);
}

