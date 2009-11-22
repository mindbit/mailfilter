#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include <stdio.h>
#include <linux/limits.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include "smtp.h"
#include "logging.h"

struct smtp_server_context;

/**
 * SMTP command handler prototype.
 *
 * FIXME: this help is innacurate ...
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

	/* Whether this handler is called on *user* command invokation.
	 * Other type of invokation is "implicit" (by the engine, for
	 * SCHS_CHAIN return code of command handlers). */
	int invokable;
	struct list_head lh;
};

/**
 * SMTP command tree node.
 *
 * Used by generic command parser to find out what handler to call for
 * each SMTP command.
 */
struct smtp_cmd_tree {
	struct smtp_cmd_tree *next[26];
	struct list_head hdlrs;
};

#define SMTP_PRIV_HASH_SIZE 16

struct smtp_priv_hash {
	uint64_t key;
	void *priv;
	struct list_head lh;
};

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Server configuration */
	struct config *cfg;

	/* Remote end address */
	struct sockaddr_in addr;

	/* Command tree node that is currently being run */
	struct smtp_cmd_tree *node;

	/* Authenticated username or empty string if no user authenticated */
	char auth[10]; // FIXME 10

	/* Envelope sender (aka reverse-path as per RFC821). .mailbox.local
	 * is NULL if "MAIL" was not issued. */
	struct smtp_path rpath;

	/* List of recipients (aka forward-path as per RFC821). Mailbox list
	 * is empty if "RCPT" was not issued. Elements are chained by the
	 * .mailbox.domain.lh component. */
	struct list_head fpath;

	/* Message body */
	struct {
		/* Path to tmp file or empty string if "DATA" was not issued */
		char path[PATH_MAX];

		/* Stream of tmp file or NULL if "DATA" was not issued */
		FILE *stream;
	} body;

	/* SMTP status code to send back to client */
	int code, prev_code;

	/* SMTP message to send back to client */
	char *message, *prev_message;

	/* Hash of per-module private data */
	struct list_head priv_hash[SMTP_PRIV_HASH_SIZE];
};

enum smtp_cmd_hdlr_status {
	/* Status OK, continue handler chain for current command */
	SCHS_OK		= 0,

	/* Status not OK, skip remaining handlers for current command */
	SCHS_BREAK	= 1,

	/* Send response to client and abort session (close connection) */
	SCHS_ABORT	= 2,

	/* Allow remaining handlers to finish, but close session afterwards */
	SCHS_QUIT	= 3,

	/* Re-enter handler processing chain */
	SCHS_CHAIN	= 4,

	/* Same as OK, but ignore the handler not having set any response code */
	SCHS_IGNORE	= 5
};

extern int smtp_cmd_register(const char *cmd, smtp_cmd_hdlr_t hdlr, int prio, int invokable);
extern void smtp_server_init(void);
extern int smtp_server_run(struct smtp_server_context *ctx, FILE *stream);
extern void smtp_server_context_init(struct smtp_server_context *ctx);
extern int smtp_priv_register(struct smtp_server_context *ctx, uint64_t key, void *priv);
extern void *smtp_priv_lookup(struct smtp_server_context *ctx, uint64_t key);
extern int smtp_priv_unregister(struct smtp_server_context *ctx, uint64_t key);

static inline int smtp_priv_bucket(uint64_t key)
{
	int i, ret = 0;

	for (i = 0; i < 8; i++) {
		ret += key & 0xff;
		key >>= 8;
	}

	return ret % SMTP_PRIV_HASH_SIZE;
}

static inline uint64_t smtp_priv_key(const char *str)
{
	uint64_t ret = 0;
	int i = 0;

	while (*str != '\0') {
		if (++i > 8)
			return ret;
		ret = (ret << 8) | *(unsigned char *)(str++);
	}

	return ret;
}

#endif
