#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "smtp_server.h"

struct smtp_cmd_tree cmd_tree;
const char *white = "\r\n\t ";

int smtp_cmd_register(const char *cmd, smtp_cmd_hdlr_t hdlr, int prio)
{
	struct smtp_cmd_tree *node = &cmd_tree, *aux;
	struct smtp_cmd_hdlr_list *hlink;
	struct list_head *p;
	const char *c;

	for (c = cmd; c != NULL && *c != '\0'; c++) {
		assert(*c >= 'A' && *c <= 'Z');
		if (node->next[*c - 'A'] != NULL) {
			node = node->next[*c - 'A'];
			continue;
		}
		aux = malloc(sizeof(struct smtp_cmd_tree));
		assert(aux != NULL);
		memset(aux, 0, sizeof(struct smtp_cmd_tree));
		INIT_LIST_HEAD(&aux->hdlrs);
		node->next[*c - 'A'] = aux;
		node = aux;
	}

	list_for_each(p, &node->hdlrs) {
		if (list_entry(p, struct smtp_cmd_hdlr_list, lh)->prio > prio)
			break;
	}

	hlink = malloc(sizeof(struct smtp_cmd_hdlr_list));
	assert(hlink != NULL);
	hlink->hdlr = hdlr;
	hlink->prio = prio;

	list_add_tail(&hlink->lh, p);
	return 0;
}

int smtp_server_response(FILE *f, int code, const char *message)
{
	if (fprintf(f, "%d %s\r\n", code, message) >= 0) {
		fflush(f);
		return 0;
	}

	return -1;
}

int smtp_server_run(struct smtp_server_context *ctx, FILE *f)
{
	int continue_session = 1;
	struct smtp_cmd_hdlr_list *hlink;
	char buf[SMTP_COMMAND_MAX + 1];

	/* Worst case for argv: all arguments are one character long. Even
	 * so, since command is not stored in argv, there are N / 2 - 1
	 * arguments, leaving the last position for the terminating NULL */
	char *argv[SMTP_COMMAND_MAX / 2];

	smtp_server_context_init(ctx);
	list_for_each_entry(hlink, &cmd_tree.hdlrs, lh) {
		int schs;

		if (ctx->message != NULL)
			free(ctx->message);
		schs = hlink->hdlr(ctx, buf, f, argv);
		if (schs == SCHS_ABORT)
			continue_session = 0;
		if (schs != SCHS_OK)
			break;
	}

	if (ctx->code) {
		smtp_server_response(f, ctx->code, ctx->message);
		free(ctx->message);
	} else {
		smtp_server_response(f, 400, "Internal server error"); // FIXME: 400
		continue_session = 0;
	}
	if (!continue_session)
		return 0;

	do {
		int oversized = 0;
		struct smtp_cmd_tree *node = &cmd_tree;
		char *c = &buf[0];
		size_t i, n;
		int argc = 0;

		buf[SMTP_COMMAND_MAX] = '\0';
		if (fgets(buf, sizeof(buf), f) == NULL)
			return -1;

		/* Handle oversized commands */
		do {
			if (buf[SMTP_COMMAND_MAX] == '\0')
				break;
			oversized = 1;
			buf[SMTP_COMMAND_MAX] = '\0';
		} while (fgets(buf, sizeof(buf), f) != NULL);
		if (oversized) {
			smtp_server_response(f, 421, "Command too long");
			return -1;
		}

		/* Parse SMTP command */
		c += strspn(c, white);
		n = strcspn(c, white);
		for (i = 0; i < n; i++) {
			if (c[i] >= 'a' && c[i] <= 'z')
				c[i] -= 'a' - 'A';
			if (c[i] < 'A' || c[i] > 'Z')
				break;
			if (node->next[c[i] - 'A'] == NULL)
				break;
			node = node->next[c[i] - 'A'];
		}
		if (i < n || !n || list_empty(&node->hdlrs)) {
			smtp_server_response(f, 500, "Command not implemented");
			continue;
		}

		/* Parse arguments */
		while (c[n] != '\0') {
			c[n] = '\0';
			c += n + 1;
			c += strspn(c, white);
			if (*c == '\0')
				break;
			n = strcspn(c, white);
			argv[argc++] = c;
		}
		argv[argc] = NULL;

		/* Invoke all command handlers */
		ctx->code = 0;
		ctx->message = NULL;
		list_for_each_entry(hlink, &node->hdlrs, lh) {
			int schs;

			if (ctx->message != NULL)
				free(ctx->message);
			schs = hlink->hdlr(ctx, buf, f, argv);
			if (schs == SCHS_ABORT || schs == SCHS_QUIT)
				continue_session = 0;
			if (schs == SCHS_BREAK || schs == SCHS_ABORT)
				break;
		}

		if (ctx->code) {
			smtp_server_response(f, ctx->code, ctx->message);
			free(ctx->message);
		} else
			smtp_server_response(f, 400, "Internal server error"); // FIXME: 400
	} while (continue_session);

	return 0;
}

int smtp_hdlr_init(struct smtp_server_context *ctx, const char *cmd, FILE *in, char **argv)
{
	ctx->code = 220;
	ctx->message = strdup("Mindbit Mail Filter");
	return SCHS_OK;
}

int smtp_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, FILE *in, char **argv)
{
	// TODO copiere envelope sender in smtp_server_context
	return SCHS_OK;
}

int smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, FILE *in, char **argv)
{
	// TODO verificare existenta envelope sender; populare lista recipients in smtp_server_context
	return SCHS_OK;
}

int smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, FILE *in, char **argv)
{
	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	return SCHS_OK;
}

int smtp_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, FILE *in, char **argv)
{
	ctx->code = 221;
	ctx->message = strdup("closing connection");
	return SCHS_QUIT;
}

int smtp_server_init(void)
{
	memset(&cmd_tree, 0, sizeof(struct smtp_cmd_tree));
	INIT_LIST_HEAD(&cmd_tree.hdlrs);
	smtp_cmd_register(NULL, smtp_hdlr_init, 0);
	smtp_cmd_register("MAIL", smtp_hdlr_mail, 0);
	smtp_cmd_register("RCPT", smtp_hdlr_rcpt, 0);
	smtp_cmd_register("DATA", smtp_hdlr_data, 0);
	smtp_cmd_register("QUIT", smtp_hdlr_quit, 0);
}

int smtp_server_context_init(struct smtp_server_context *ctx)
{
	memset(ctx, 0, sizeof(struct smtp_server_context));
}
