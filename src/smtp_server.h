#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include <stdio.h>
#include <linux/limits.h>

#define SMTP_COMMAND_MAX 512

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
typedef int (*smtp_cmd_handler_t)(const char *cmd, FILE *in, void *priv, char **argv);

/**
 * SMTP command tree node.
 *
 * User by generic command parser to find out what handler to call for
 * each SMTP command.
 */
struct smtp_cmd_tree {
	struct smtp_cmd_tree *next[26];
	smtp_cmd_handler_t handler;
	void *priv;
};

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Authenticated username or empty string if no user authenticated */
	char auth[10]; // FIXME 10

	/* Envelope sender or empty string if "MAIL" was not issued */
	char mail[10]; // FIXME 10

	/* List of recipient addresses (empty if "RCPT" was not issued) */
	// FIXME "list" rcpt

	/* Path to temporary file or empty string if "DATA" was not issued */
	char data[PATH_MAX];
};


extern int smtp_cmd_register(const char *cmd, smtp_cmd_handler_t handler, void *priv);
extern int smtp_server_run(FILE *f);

#endif
