#ifndef _PGSQL_TOOLS_H
#define _PGSQL_TOOLS_H

#include <stdint.h>

static uint64_t prepared_mask = 0;

#define _PQexecPrepared(ctx, conn, id, nParams, paramValues, paramLengths, paramFormats, resultFormat) \
	__PQexecPrepared(ctx, conn, #id, id, nParams, paramValues, paramLengths, paramFormats, resultFormat)

static __inline__ PGresult *__PQexecPrepared(struct smtp_server_context *ctx, PGconn *conn, const char *stmt, int stmt_id,
		int nParams, const char * const *paramValues, const int *paramLengths,
		const int *paramFormats, int resultFormat)
{
	PGresult *res;
	uint64_t mask = ((uint64_t)1) << stmt_id;

	if (!(prepared_mask & mask)) {
		res = PQprepare(conn, stmt, prepared_statements[stmt_id], 0, NULL);
		mod_log(LOG_DEBUG, "Preparing statement '%s': '%s'\n", stmt, prepared_statements[stmt_id]);
		if (res == NULL) {
			mod_log(LOG_ERR, "PQprepare(%s) failed: %s\n", stmt, PQerrorMessage(conn));
			return NULL;
		}
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			mod_log(LOG_ERR, "PQprepare(%s) failed(%d): %s\n", stmt, PQresultStatus(res), PQerrorMessage(conn));
			PQclear(res);
			return NULL;
		}
		PQclear(res);
		prepared_mask |= mask;
	}
	res = PQexecPrepared(conn, stmt, nParams, paramValues, paramLengths, paramFormats, resultFormat);
	if (res == NULL) {
		mod_log(LOG_ERR, "PQexecPrepared(%s) failed: %s\n", prepared_statements[stmt_id], PQerrorMessage(conn));
		return NULL;
	}
	if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
		mod_log(LOG_ERR, "PQexecPrepared(%s) failed(%d): %s\n", prepared_statements[stmt_id], PQresultStatus(res), PQerrorMessage(conn));
		PQclear(res);
		return NULL;
	}
	return res;
}

#endif
