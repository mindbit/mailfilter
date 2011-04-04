#ifndef _SMTP_CLIENT_H
#define _SMTP_CLIENT_H

#include "smtp.h"
#include "bfd.h"

typedef int (*smtp_client_callback_t)(int code, const char *message, int last, void *priv);
enum {
	SMTP_READ_ERROR		= -1,
	SMTP_PARSE_ERROR	= -2,
	SMTP_INVALID_CODE	= -3
};
int smtp_client_response(bfd_t *stream, smtp_client_callback_t callback, void *priv);
int smtp_client_command(bfd_t *stream, const char *cmd, const char *arg);
int smtp_copy_from_file(bfd_t *out, bfd_t *in);
int smtp_put_path(bfd_t *stream, struct smtp_path *path);
int smtp_put_path_cmd(bfd_t *stream, const char *cmd, struct smtp_path *path);
int smtp_c_mail(bfd_t *stream, struct smtp_path *path);
int smtp_c_rcpt(bfd_t *stream, struct smtp_path *path);
#endif
