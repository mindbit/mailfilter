#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include <stdio.h>
#include <linux/limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include "list.h"

#define SMTP_COMMAND_MAX 512

struct smtp_domain {
	const char *domain;
	struct list_head lh;
};

struct smtp_mailbox {
	const char *local;
	struct smtp_domain domain;
};

struct smtp_path {
	struct smtp_mailbox mailbox;
	struct list_head domains;
};

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Authenticated username or empty string if no user authenticated */
	char auth[10]; // FIXME 10

	/* Envelope sender (aka reverse-path as per RFC821). .mailbox.local
	 * is NULL if "MAIL" was not issued. */
	struct smtp_path rpath;

	/* List of recipients (aka forward-path as per RFC821). Mailbox list
	 * is empty if "RCPT" was not issued. Elements are chained by the
	 * .mailbox.domain.lh component. */
	struct list_head fpath;

	/* Path to temporary file or empty string if "DATA" was not issued */
	char data[PATH_MAX];

	/* Remote end address */
	struct sockaddr_in addr;

	/* SMTP status code to send back to client */
	int code;

	/* SMTP message to send back to client */
	char *message;
};

/**
 * SMTP command handler prototype.
 *
 * cmd
 *		The (SMTP) command that is being handled.
 * 
 * in
 * 		Communication socket stream.
 *
 * priv
 * 		Private data passed back to the command handler, as passed to
 * 		smtp_cmd_register() on handler registration.
 */
typedef int (*smtp_cmd_hdlr_t)(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream);

struct smtp_cmd_hdlr_list {
	smtp_cmd_hdlr_t hdlr;
	int prio;
	struct list_head lh;
};

/**
 * SMTP command tree node.
 *
 * User by generic command parser to find out what handler to call for
 * each SMTP command.
 */
struct smtp_cmd_tree {
	struct smtp_cmd_tree *next[26];
	smtp_cmd_hdlr_t hdlr;
	struct list_head hdlrs;
};

enum smtp_cmd_hdlr_status {
	/* Status OK, continue handler chain for current command */
	SCHS_OK		= 0,

	/* Status not OK, skip remaining handlers for current command */
	SCHS_BREAK	= 1,

	/* Send response to client and abort session (close connection) */
	SCHS_ABORT	= 2,

	/* Allow remaining handlers to finish, but close session afterwards */
	SCHS_QUIT	= 3
};

extern int smtp_cmd_register(const char *cmd, smtp_cmd_hdlr_t hdlr, int prio);
extern int smtp_server_init(void);
extern int smtp_server_run(struct smtp_server_context *ctx, FILE *f);
extern void smtp_server_context_init(struct smtp_server_context *ctx);

#endif
