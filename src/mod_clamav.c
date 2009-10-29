#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "smtp_server.h"
#include "string_tools.h"

static inline void clamdscan(struct smtp_server_context *ctx, int pipe_fd)
{
	const char *path = "/usr/bin/clamdscan";
	int i, null_fd;
	struct rlimit rl = {0};

	getrlimit(RLIMIT_NOFILE, &rl);
	switch (rl.rlim_max) {
	case -1:
		//syslog(LOG_ERR, "getrlimit");
		exit(100);
	case 0:
		//syslog(LOG_ERR, "Max number of open file descriptors is 0!");
		exit(100);
	}
	for (i = 0; i < rl.rlim_max; i++) {
		if (i == pipe_fd)
			continue;
		close(i);
	}

	null_fd = open("/dev/null", 0);
	dup2(pipe_fd, 1);
	dup2(null_fd, 2);

	execl(path, path, ctx->body.path, NULL);
	exit(100);
}

int mod_clamav_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	int status, p[2];
	pid_t pid;
	FILE *pipe_stream = NULL;
	int ret = SCHS_BREAK;

	if (pipe(p))
		return SCHS_BREAK;

	switch ((pid = fork())) {
	case -1:
		break;
	case 0:
		/* child */
		clamdscan(ctx, p[1]);
		break;
	default:
		/* parent */
		do {
			waitpid(pid, &status, 0);
			// FIXME check for interrupted syscall (and retval)
		} while (!WIFEXITED(status));

		if (WEXITSTATUS(status) == 100) {
			/* we failed to execl() the clamdscan binary */
			break;
		}

		if (WEXITSTATUS(status) > 1) {
			/* clamdscan failed with error */
			break;
		}

		if (!WEXITSTATUS(status)) {
			ret = SCHS_IGNORE;
			break;
		}

		ctx->code = 550;

		do {
			struct string_buffer sb;
			char c;
			int i;

			string_buffer_init(&sb);
			if ((pipe_stream = fdopen(p[0], "r")) == NULL)
				break;
			/* first line of output is the file path followed by ": " followed
			 * by the virus name followed by " FOUND" */
			for (i = strlen(ctx->body.path) + 2; i; i--)
				if (getc_unlocked(pipe_stream) == EOF)
					break;
			while ((c = getc_unlocked(pipe_stream)) != EOF && c != ' ')
				string_buffer_append_char(&sb, c);
			if (sb.s == NULL)
				break;
			if (asprintf(&ctx->message, "This message appears to be infected with the %s virus", sb.s) == -1)
				ctx->message = NULL;
		} while (0);
		if (ctx->message == NULL)
			ctx->message = strdup("This message appears to contain viruses");
	}

	if (pipe_stream == NULL)
		close(p[0]);
	else
		fclose(pipe_stream);
	close(p[1]);
	return ret;
}

void mod_clamav_init(void)
{
	smtp_cmd_register("BODY", mod_clamav_hdlr_body, 60, 0);
}
