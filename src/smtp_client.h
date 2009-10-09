#ifndef _SMTP_CLIENT_H
#define _SMTP_CLIENT_H

#include "smtp.h"

typedef int (*smtp_client_callback_t)(int code, const char *message, int last, void *priv);
enum {
	SMTP_READ_ERROR		= -1,
	SMTP_PARSE_ERROR	= -2,
	SMTP_INVALID_CODE	= -3
};
int smtp_client_response(FILE *stream, smtp_client_callback_t callback, void *priv);
int smtp_client_command(FILE *stream, const char *cmd, const char *arg);
#endif
