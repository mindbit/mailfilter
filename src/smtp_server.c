#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "smtp_server.h"

struct smtp_cmd_tree cmd_tree;
const char *white = "\r\n\t ";

int smtp_cmd_register(const char *cmd, smtp_cmd_hdlr_t hdlr, int prio, int invokable)
{
	struct smtp_cmd_tree *node = &cmd_tree, *aux;
	struct smtp_cmd_hdlr_list *hlink;
	struct list_head *p;
	const char *c;

	for (c = cmd; *c != '\0'; c++) {
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
	hlink->invokable = invokable;

	list_add_tail(&hlink->lh, p);
	return 0;
}

struct smtp_cmd_tree *smtp_cmd_lookup(const char *cmd)
{
	struct smtp_cmd_tree *node = &cmd_tree;

	while (*cmd != '\0' && node != NULL) {
		char c = *cmd;
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';
		if (c < 'A' || c > 'Z')
			return NULL;
		node = node->next[c - 'A'];
		cmd++;
	}

	return node;
}

int smtp_server_response(FILE *f, int code, const char *message)
{
	if (fprintf(f, "%d %s\r\n", code, message) >= 0) {
		fflush(f);
		return 0;
	}

	return -1;
}

int smtp_server_process(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	int schs, continue_session = 1;
	struct smtp_cmd_hdlr_list *hlink;

	do {
		/* Save ctx->node to local var, since it can be changed by a
		 * command handler *while* we are walking the handler list */
		struct smtp_cmd_tree *node = ctx->node;

		ctx->code = 0;
		ctx->message = NULL;
		list_for_each_entry(hlink, &node->hdlrs, lh) {

			if (ctx->message != NULL) {
				free(ctx->message);
				ctx->message = NULL;
			}
			schs = hlink->hdlr(ctx, cmd, arg, stream);
			if (schs == SCHS_ABORT || schs == SCHS_QUIT)
				continue_session = 0;
			if (schs == SCHS_BREAK || schs == SCHS_ABORT)
				break;
		}

		if (ctx->code) {
			smtp_server_response(stream, ctx->code, ctx->message);
			free(ctx->message);
		} else if (schs != SCHS_CHAIN && schs != SCHS_IGNORE)
			smtp_server_response(stream, 451, "Internal server error");
	} while (schs == SCHS_CHAIN);

	return continue_session;
}

int __smtp_server_run(struct smtp_server_context *ctx, FILE *stream)
{
	int continue_session;
	char buf[SMTP_COMMAND_MAX + 1];

	/* Command handling loop */
	do {
		int oversized = 0;
		char *c = &buf[0];
		size_t i, n;

		buf[SMTP_COMMAND_MAX] = '\n';
		if (fgets(buf, sizeof(buf), stream) == NULL)
			return -1;

		/* Handle oversized commands */
		while (buf[SMTP_COMMAND_MAX] != '\n') {
			oversized = 1;
			buf[SMTP_COMMAND_MAX] = '\n';
			if (fgets(buf, sizeof(buf), stream) == NULL)
				return -1;
		}
		if (oversized) {
			smtp_server_response(stream, 421, "Command too long");
			return -1;
		}

		/* Parse SMTP command */
		c += strspn(c, white);
		n = strcspn(c, white);
		ctx->node = &cmd_tree;
		for (i = 0; i < n; i++) {
			if (c[i] >= 'a' && c[i] <= 'z')
				c[i] -= 'a' - 'A';
			if (c[i] < 'A' || c[i] > 'Z')
				break;
			if (ctx->node->next[c[i] - 'A'] == NULL)
				break;
			ctx->node = ctx->node->next[c[i] - 'A'];
		}
		if (i < n || !n || list_empty(&ctx->node->hdlrs)) {
			smtp_server_response(stream, 500, "Command not implemented");
			continue;
		}

		/* Prepare argument */
		if (c[n] != '\0') {
			c[n] = '\0';
			n++;
		}

		/* Invoke all command handlers */
		continue_session = smtp_server_process(ctx, c, c + n, stream);
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
	int i;

	memset(ctx, 0, sizeof(struct smtp_server_context));
	smtp_path_init(&ctx->rpath);
	INIT_LIST_HEAD(&ctx->fpath);

	for (i = 0; i < SMTP_PRIV_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ctx->priv_hash[i]);
}

void smtp_server_context_cleanup(struct smtp_server_context *ctx)
{
	struct smtp_path *path, *path_aux;
	smtp_path_cleanup(&ctx->rpath);
	list_for_each_entry_safe(path, path_aux, &ctx->fpath, mailbox.domain.lh) {
		smtp_path_cleanup(path);
		free(path);
	}
	if (ctx->body.stream != NULL)
		fclose(ctx->body.stream);
	if (ctx->body.path[0] != '\0')
		unlink(ctx->body.path);
}

int smtp_server_run(struct smtp_server_context *ctx, FILE *stream)
{
	int ret;

	smtp_server_context_init(ctx);

	/* Handle initial greeting */
	if ((ctx->node = smtp_cmd_lookup("INIT")) != NULL) {
		if (!smtp_server_process(ctx, NULL, NULL, stream) || !ctx->code)
			return 0;
	}

	ret = __smtp_server_run(ctx, stream);

	/* Give all modules the chance to clean up (possibly after a broken
	 * connection */
	if ((ctx->node = smtp_cmd_lookup("TERM")) != NULL) {
		if (!smtp_server_process(ctx, NULL, NULL, stream) || !ctx->code)
			return 0;
	}
	smtp_server_context_cleanup(ctx);

	return ret;
}

int smtp_path_parse(struct smtp_path *path, const char *arg)
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
					return 2; // FIXME in cadrul apelant trebuie sa dau alt mesaj de eroare decat syntax err
				if ((domain->domain = strndup(token, arg - token)) == NULL) {
					free(domain);
					return 2; // FIXME
				}
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

int smtp_path_parse_cmd(struct smtp_path *path, const char *arg, const char *word)
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
	if (smtp_path_parse(path, arg)) {
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
	if (ctx->rpath.mailbox.local != NULL) {
		ctx->code = 503;
		ctx->message = strdup("Sender already specified");
		return SCHS_BREAK;
	}

	if (smtp_path_parse_cmd(&ctx->rpath, arg, "FROM")) {
		smtp_path_init(&ctx->rpath);
		ctx->code = 501;
		ctx->message = strdup("Syntax error");
		return SCHS_BREAK;
	}

	ctx->code = 250;
	ctx->message = strdup("Envelope sender ok");
	return SCHS_OK;
}

int smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct smtp_path *path;

	if (ctx->rpath.mailbox.local == NULL) {
		ctx->code = 503;
		ctx->message = strdup("Must specify envelope sender first");
		return SCHS_BREAK;
	}

	path = malloc(sizeof(struct smtp_path));
	if (path == NULL)
		return SCHS_BREAK;
	smtp_path_init(path);

	if (smtp_path_parse_cmd(path, arg, "TO")) {
		free(path);
		ctx->code = 501;
		ctx->message = strdup("Syntax error");
		return SCHS_BREAK;
	}

	list_add_tail(&path->mailbox.domain.lh, &ctx->fpath);
	ctx->code = 250;
	ctx->message = strdup("Recipient ok");

	return SCHS_OK;
}

int smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	int fd;

	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	if (list_empty(&ctx->fpath)) {
		ctx->code = 503;
		ctx->message = strdup("Must specify recipient(s) first");
		return SCHS_BREAK;
	}

	/* prepare temporary file to store message body */
	sprintf(ctx->body.path, "/tmp/mailfilter.XXXXXX"); // FIXME sNprintf; cale in loc de /tmp;
	if ((fd = mkstemp(ctx->body.path)) == -1) {
		ctx->body.path[0] = '\0';
		return SCHS_BREAK;
	}
	if ((ctx->body.stream = fdopen(fd, "r+")) == NULL) {
		close(fd);
		unlink(ctx->body.path);
		ctx->body.path[0] = '\0';
		return SCHS_BREAK;
	}

	/* prepare response */
	ctx->code = 354;
	ctx->message = strdup("Go ahead");
	ctx->node = smtp_cmd_lookup("BODY");
	return SCHS_CHAIN;
}

int smtp_copy_to_file(FILE *out, FILE *in)
{
	const uint64_t DOTLINE_MAGIC	= 0x0d0a2e0000;	/* <CR><LF>"."<*> */
	const uint64_t DOTLINE_MASK		= 0xffffff0000;
	const uint64_t CRLF_MAGIC		= 0x0000000d0a; /* <CR><LF> */
	const uint64_t CRLF_MASK		= 0x000000ffff;
	uint64_t buf = 0;
	int fill = 0;
	int c;

	while ((c = getc_unlocked(in)) != EOF) {
		if (++fill > 8) {
			if (putc_unlocked(buf >> 56, out) == EOF)
				return 1;
			fill = 8;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if ((buf & CRLF_MASK) == CRLF_MAGIC) {
			/* we found the EOF sequence (<CR><LF>"."<CR><LF>) */
			assert(fill >= 5);
			/* discard the (terminating) "."<CR><LF> */
			buf >>= 24;
			fill -= 3;
			break;
		}
		/* strip the dot at beginning of line */
		assert(fill >= 5);
		buf = ((buf >> 8) & ~CRLF_MASK) | (buf & CRLF_MASK);
		fill--;
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8)
		if (putc_unlocked((buf >> fill) & 0xff, out) == EOF)
			return 1;

	return 0;
}

int smtp_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	assert(ctx->body.stream != NULL);
	smtp_copy_to_file(ctx->body.stream, stream);
	fflush(ctx->body.stream);
	ctx->code = 250;
	ctx->message = strdup("Mail successfully received");
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
	ctx->code = 250;
	ctx->message = strdup("State reset complete");
	return SCHS_OK;
}

void smtp_server_init(void)
{
	memset(&cmd_tree, 0, sizeof(struct smtp_cmd_tree));
	INIT_LIST_HEAD(&cmd_tree.hdlrs);
	smtp_cmd_register("INIT", smtp_hdlr_init, 0, 0);
	smtp_cmd_register("MAIL", smtp_hdlr_mail, 0, 1);
	smtp_cmd_register("RCPT", smtp_hdlr_rcpt, 0, 1);
	smtp_cmd_register("DATA", smtp_hdlr_data, 0, 1);
	smtp_cmd_register("BODY", smtp_hdlr_body, 0, 0);
	smtp_cmd_register("QUIT", smtp_hdlr_quit, 0, 1);
	smtp_cmd_register("RSET", smtp_hdlr_rset, 0, 1);

	// TODO urmatoarele trebuie sa se intample din config
	mod_proxy_init();
	mod_spamassassin_init();
	mod_clamav_init();
}

int smtp_priv_register(struct smtp_server_context *ctx, uint64_t key, void *priv)
{
	struct smtp_priv_hash *h;

	h = malloc(sizeof(struct smtp_priv_hash));
	if (h == NULL)
		return -ENOMEM;

	h->key = key;
	h->priv = priv;
	list_add_tail(&h->lh, &ctx->priv_hash[smtp_priv_bucket(key)]);

	return 0;
}

void *smtp_priv_lookup(struct smtp_server_context *ctx, uint64_t key)
{
	struct smtp_priv_hash *h;
	int i = smtp_priv_bucket(key);

	list_for_each_entry(h, &ctx->priv_hash[i], lh)
		if (h->key == key)
			return h->priv;

	return NULL;
}

int smtp_priv_unregister(struct smtp_server_context *ctx, uint64_t key)
{
	struct smtp_priv_hash *h;
	int i = smtp_priv_bucket(key);

	list_for_each_entry(h, &ctx->priv_hash[i], lh)
		if (h->key == key) {
			list_del(&h->lh);
			free(h);
			return 0;
		}

	return -ESRCH;
}

