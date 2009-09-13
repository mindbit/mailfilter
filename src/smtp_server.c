#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "smtp_server.h"

struct smtp_cmd_tree cmd_tree;
const char *white = "\r\n\t ";

int smtp_cmd_register(const char *cmd, smtp_cmd_handler_t handler, void *priv)
{
	struct smtp_cmd_tree *node = &cmd_tree, *aux;
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
		node->next[*c - 'A'] = aux;
		node = aux;
	}

	if (node->handler != NULL)
		return -1;

	node->handler = handler;
	node->priv = priv;

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

int smtp_server_run(FILE *f)
{
	char buf[SMTP_COMMAND_MAX + 1];

	/* Worst case for argv: all arguments are one character long. Even
	 * so, since command is not stored in argv, there are N / 2 - 1
	 * arguments, leaving the last position for the terminating NULL */
	char *argv[SMTP_COMMAND_MAX / 2];

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
		if (i < n) {
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

		if (node->handler(buf, f, node->priv, argv))
			break;
	} while (1);

	return 0;
}

int smtp_hdlr_mail(const char *cmd, FILE *in, void *priv, char **argv)
{
	// TODO copiere envelope sender in smtp_server_context
	return 0;
}

int smtp_hdlr_rcpt(const char *cmd, FILE *in, void *priv, char **argv)
{
	// TODO verificare existenta envelope sender; populare lista recipients in smtp_server_context
	return 0;
}

int smtp_hdlr_data(const char *cmd, FILE *in, void *priv, char **argv)
{
	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	return 0;
}

int smtp_hdlr_quit(const char *cmd, FILE *in, void *priv, char **argv)
{
	// TODO apelare hooks
	return 0;
}

int smtp_server_init(void)
{
	smtp_cmd_register("MAIL", smtp_hdlr_mail, NULL);
	smtp_cmd_register("RCPT", smtp_hdlr_rcpt, NULL);
	smtp_cmd_register("DATA", smtp_hdlr_data, NULL);
	smtp_cmd_register("QUIT", smtp_hdlr_quit, NULL);

	// TODO init smtp_server_context
}
