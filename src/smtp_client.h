/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter, a free SIP server.
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
