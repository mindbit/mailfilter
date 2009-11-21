#ifndef _MOD_LOG_SQL_H
#define _MOD_LOG_SQL_H

#include <stdint.h>
#include <libpq-fe.h>

#include "smtp_server.h"

struct mod_log_sql_priv {
	PGconn *conn;
	uint64_t smtp_transaction_id;
};

#endif
