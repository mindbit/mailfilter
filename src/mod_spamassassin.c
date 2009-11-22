#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "smtp_server.h"

static uint64_t key;
static const char *module = "spamassassin";

static inline void spamc(struct smtp_server_context *ctx, int pipe_fd)
{
	const char *path = "/usr/bin/spamc";
	int i, body_fd, err_fd;
	struct rlimit rl = {0};

	/* close all open file descriptors */
	body_fd = fileno(ctx->body.stream);
	// FIXME if body_fd == -1
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
		if (i == pipe_fd || i == body_fd)
			continue;
		close(i);
	}

	lseek(body_fd, 0, SEEK_SET);
	dup2(body_fd, 0);
	dup2(pipe_fd, 1);
	err_fd = open("/dev/null", 0);

	// FIXME chiar avem nevoie de asta? teoretic ar trebui sa primim 2
	if (err_fd != 2)
		dup2(err_fd, 2);

	execl(path, path, "-c", "-x", NULL);
	exit(100);
}

int mod_spamassassin_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	int status, p[2];
	pid_t pid;
	float score = 0, treshold = 0;
	FILE *pipe_stream = NULL;
	int ret = SCHS_BREAK;

	if (pipe(p)) {
		smtp_set_transaction_state(ctx, module, 0, NULL);
		return SCHS_BREAK;
	}

	switch ((pid = fork())) {
	case -1:
		break;
	case 0:
		/* child */
		spamc(ctx, p[1]);
		break;
	default:
		/* parent */
		do {
			waitpid(pid, &status, 0);
			// FIXME check for interrupted syscall (and retval)
		} while (!WIFEXITED(status));

		if (WEXITSTATUS(status) == 100) {
			/* we failed to execl() the spamc binary */
			break;
		}

		if ((pipe_stream = fdopen(p[0], "r")) != NULL)
			fscanf(pipe_stream, "%f/%f", &score, &treshold);

		if (WEXITSTATUS(status) > 1) {
			/* spamc failed with error */
			break;
		}

		if (!WEXITSTATUS(status)) {
			ret = SCHS_IGNORE;
			break;
		}

		ctx->code = 550;
		ctx->message = strdup("This message appears to be spam");
	}

	if (pipe_stream == NULL)
		close(p[0]);
	else
		fclose(pipe_stream);
	close(p[1]);
	smtp_set_transaction_state(ctx, module, 0, NULL);
	return ret;
}

void mod_spamassassin_init(void)
{
	smtp_cmd_register("BODY", mod_spamassassin_hdlr_body, 50, 0);
}
