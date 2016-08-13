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

#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include <stdio.h>
#include <linux/limits.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include "smtp.h"
#include "internet_message.h"

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Remote end address */
	struct sockaddr_in addr;

	/* Client identity specified in EHLO command */
	char *identity;

	/* Authentication details. NULL if no user authenticated */
	char *auth_user, *auth_pw, *auth_type;

	/* Envelope sender (aka reverse-path as per RFC821). .mailbox.local
	 * is NULL if "MAIL" was not issued. */
	struct smtp_path rpath;

	/* List of recipients (aka forward-path as per RFC821). Mailbox list
	 * is empty if "RCPT" was not issued. Elements are chained by the
	 * .mailbox.domain.lh component. */
	struct list_head fpath;

	struct list_head hdrs;

	/* Message body */
	struct {
		/* Path to tmp file or empty string if "DATA" was not issued */
		char path[PATH_MAX];

		/* Stream of tmp file or NULL if "DATA" was not issued */
		bfd_t *stream;

		/* Size of message body (without headers) */
		off_t size;
	} body;

	/* SMTP status code to send back to client */
	int code;

	/* SMTP message to send back to client */
	char *message;
};

extern void smtp_server_main(struct smtp_server_context *ctx, int client_sock_fd);
extern void smtp_server_context_init(struct smtp_server_context *ctx);

#endif
