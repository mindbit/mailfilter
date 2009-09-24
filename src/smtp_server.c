#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "smtp_server.h"

struct smtp_cmd_tree cmd_tree;
const char *white = "\r\n\t ";
const char *EMPTY_STRING = "";

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

	smtp_server_context_init(ctx);

	/* Handle initial greeting */
	list_for_each_entry(hlink, &cmd_tree.hdlrs, lh) {
		int schs;

		if (ctx->message != NULL)
			free(ctx->message);
		schs = hlink->hdlr(ctx, NULL, NULL, f);
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

	/* Command handling loop */
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

		/* Prepare argument */
		if (c[n] != '\0') {
			c[n] = '\0';
			n++;
		}

		/* Invoke all command handlers */
		ctx->code = 0;
		ctx->message = NULL;
		list_for_each_entry(hlink, &node->hdlrs, lh) {
			int schs;

			if (ctx->message != NULL)
				free(ctx->message);
			schs = hlink->hdlr(ctx, c, c + n, f);
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

void smtp_path_init(struct smtp_path *path)
{
	memset(path, 0, sizeof(struct smtp_path));
	INIT_LIST_HEAD(&path->domains);
	INIT_LIST_HEAD(&path->mailbox.domain.lh);
}

void smtp_path_cleanup(struct smtp_path *path)
{
	struct smtp_domain *pos, *n;

	if (path->mailbox.local != NULL && path->mailbox.local != EMPTY_STRING)
		free(path->mailbox.local);
	if (path->mailbox.domain.domain != NULL)
		free(path->mailbox.domain.domain);
	list_for_each_entry_safe(pos, n, &path->domains, lh) {
		free(pos->domain);
		free(pos);
	}
}

void smtp_server_context_init(struct smtp_server_context *ctx)
{
	memset(ctx, 0, sizeof(struct smtp_server_context));
	smtp_path_init(&ctx->rpath);
	INIT_LIST_HEAD(&ctx->fpath);
}

void smtp_server_context_cleanup(struct smtp_server_context *ctx)
{
	struct smtp_path *path, *path_aux;
	smtp_path_cleanup(&ctx->rpath);
	list_for_each_entry_safe(path, path_aux, &ctx->fpath, mailbox.domain.lh) {
		smtp_path_cleanup(path);
		free(path);
	}
}

int __smtp_path_parse(struct smtp_path *path, const char *arg)
{
	enum {
		S_INIT,
		S_SEPARATOR,
		S_DOMAIN,
		S_MBOX_LOCAL,
		S_MBOX_DOMAIN,
		S_FINAL
	} state = S_INIT;
	const char *token = NULL;
	struct smtp_domain *domain;

	while (*arg != '\0') {
		switch (state) {
		case S_INIT:
			if (*arg != '<')
				return 1;
			state = S_SEPARATOR;
			arg++;
			continue;
		case S_SEPARATOR:
			if (strchr(white, *arg) != NULL) {
				arg++;
				continue;
			}
			if (*arg == '@') {
				state = S_DOMAIN;
				token = ++arg;
				continue;
			}
			if (*arg == '>') {
				path->mailbox.local = EMPTY_STRING;
				arg++;
				state = S_FINAL;
				continue;
			}
			token = arg;
			state = S_MBOX_LOCAL;
			continue;
		case S_DOMAIN:
			if (*arg == ',' || *arg == ':') {
				if (token == arg)
					return 1;
				domain = malloc(sizeof(struct smtp_domain));
				if (domain == NULL)
					return 2; // FIXME in cadrul apelant dau alt mesaj de eroare decat syntax err
				if ((domain->domain = strndup(token, arg - token)) == NULL)
					return 2; // FIXME
				list_add_tail(&domain->lh, &path->domains);
			}
			if (*arg == ',') {
				++arg;
				state = S_SEPARATOR;
				continue;
			}
			if (*arg == ':') {
				token = ++arg;
				state = S_MBOX_LOCAL;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_LOCAL:
			if (*arg == '@') {
				if (token == arg)
					return 1;
				if ((path->mailbox.local = strndup(token, arg - token)) == NULL)
					return 2; // FIXME
				state = S_MBOX_DOMAIN;
				token = ++arg;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_DOMAIN:
			if (*arg == '>') {
				if (token == arg)
					return 1;
				if ((path->mailbox.domain.domain = strndup(token, arg - token)) == NULL)
					return 2; // FIXME
				state = S_FINAL;
			}
			arg++;
			continue;
		case S_FINAL:
			if (strchr(white, *(arg++)) == NULL)
				return 1;
			continue;
		}
	}

	return state == S_FINAL ? 0 : 1;
}

int smtp_path_parse(struct smtp_path *path, const char *arg, const char *word)
{
	/* Look for passed-in word */
	arg += strspn(arg, white);
	if (strncasecmp(arg, word, strlen(word)))
		return 1;
	arg += strlen(word);

	/* Look for colon */
	arg += strspn(arg, white);
	if (*(arg++) != ':')
		return 1;

	/* Parse actual path */
	arg += strspn(arg, white);
	if (__smtp_path_parse(path, arg)) {
		smtp_path_cleanup(path);
		return 1;
	}

	return 0;
}

int smtp_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	ctx->code = 220;
	ctx->message = strdup("Mindbit Mail Filter");
	return SCHS_OK;
}

int smtp_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct smtp_path path;

	if (ctx->rpath.mailbox.local != NULL) {
		ctx->code = 503;
		ctx->message = strdup("Sender already specified");
		return SCHS_BREAK;
	}

	smtp_path_init(&path);
	if (smtp_path_parse(&path, arg, "FROM")) {
		ctx->code = 501;
		ctx->message = strdup("Syntax error");
		return SCHS_BREAK;
	}

	memcpy(&ctx->rpath, &path, sizeof(struct smtp_path));

	fprintf(stream, "l='%s' d='%s'\n", path.mailbox.local, path.mailbox.domain.domain);

	ctx->code = 250;
	ctx->message = strdup("Ok");
	return SCHS_OK;
}

int smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	// TODO verificare existenta envelope sender; populare lista recipients in smtp_server_context
	return SCHS_OK;
}

int smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	return SCHS_OK;
}

int smtp_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	ctx->code = 221;
	ctx->message = strdup("closing connection");
	return SCHS_QUIT;
}

int smtp_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	smtp_server_context_cleanup(ctx);
	smtp_server_context_init(ctx);
	ctx->code = 250;
	ctx->message = strdup("State reset complete");
	return SCHS_OK;
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
	smtp_cmd_register("RSET", smtp_hdlr_rset, 0);
}
