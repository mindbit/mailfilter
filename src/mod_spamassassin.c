#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "smtp_server.h"

static uint64_t key;
static const char *module = "spamassassin";

static inline int spamc(struct smtp_server_context *ctx, int fd_in, int fd_out)
{
	const char *path = "/usr/bin/spamc";
	int i, fd_err;
	struct rlimit rl = {0};

	/* close all open file descriptors */
	getrlimit(RLIMIT_NOFILE, &rl);
	switch (rl.rlim_max) {
	case -1:
		//syslog(LOG_ERR, "getrlimit");
		return 100;
	case 0:
		//syslog(LOG_ERR, "Max number of open file descriptors is 0!");
		return 100;
	}
	for (i = 0; i < rl.rlim_max; i++) {
		if (i == fd_in || i == fd_out)
			continue;
		close(i);
	}

	dup2(fd_in, 0);
	dup2(fd_out, 1);
	fd_err = open("/dev/null", 0);

	// FIXME chiar avem nevoie de asta? teoretic ar trebui sa primim 2
	if (fd_err != 2)
		dup2(fd_err, 2);

	execl(path, path, "-c", "-x", NULL);
	return 127;
}

int mod_spamassassin_hdlr_body(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	int status = 0, pr[2] = {-1, -1}, pw[2] = {-1, -1};
	pid_t pid;
	float score = 0, treshold = 0;
	FILE *fr = NULL, *fw = NULL;
	int ret = SCHS_BREAK;

	if (pipe(pr))
		goto out_clean;
	if (pipe(pw))
		goto out_clean;
	if ((fr = fdopen(pr[0], "r")) == NULL)
		goto out_clean;
	if ((fw = fdopen(pw[1], "w")) == NULL)
		goto out_clean;

	switch ((pid = fork())) {
	case -1:
		mod_log(LOG_ERR, "could not spawn child process\n");
		goto out_clean;
	case 0:
		/* child */
		status = spamc(ctx, pw[0], pr[1]);
		/* spamc() should not return; if it does, something went wrong */
		exit(status);
	}

	/* parent */
	if (im_header_write(&ctx->hdrs, fw)) {
		mod_log(LOG_ERR, "could not copy message headers\n");
		goto out_err;
	}

	if (fputs("\r\n", fw) == EOF) {
		mod_log(LOG_ERR, "could not copy message header delimiter\n");
		goto out_err;
	}

	fseek(ctx->body.stream, 0, SEEK_SET);
	if (stream_copy(ctx->body.stream, fw)) {
		mod_log(LOG_ERR, "could not copy message body\n");
		goto out_err;
	}

	/* close pipe and prevent it from being closed again at cleanup */
	fclose(fw);
	fw = NULL;
	pw[0] = -1;

	do {
		waitpid(pid, &status, 0);
		// FIXME check for interrupted syscall (and retval)
	} while (!WIFEXITED(status));

	if (WEXITSTATUS(status) >= 100) {
		/* we failed to execl() the spamc binary */
		goto out_err;
	}

	fscanf(fr, "%f/%f", &score, &treshold);

	if (WEXITSTATUS(status) > 1) {
		mod_log(LOG_ERR, "spamc failed with error\n");
		goto out_clean;
	}

	if (!WEXITSTATUS(status)) {
		ret = SCHS_IGNORE;
		mod_log(LOG_INFO, "message passed\n");
		goto out_clean;
	}

	ctx->code = 550;
	ctx->message = strdup("This message appears to be spam");
	mod_log(LOG_INFO, "message rejected\n");

	goto out_clean;

out_err:
	/* first check if waitpid() has already been called, since we may get
	 * here after all data was sent to child process */
	if (!WIFEXITED(status))
		waitpid(pid, &status, WNOHANG);
	if (WIFEXITED(status)) {
		switch (WEXITSTATUS(status)) {
		case 127:
			mod_log(LOG_ERR, "execl() failed\n");
			break;
		default:
			mod_log(LOG_ERR, "early child initialization failed\n");
		}
		goto out_clean;
	}
	/* cleanup when child process seems to be dead */
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);

out_clean:
	if (fr != NULL) {
		fclose(fr);
		pr[0] = -1;
	}
	if (fw != NULL) {
		fclose(fw);
		pw[1] = -1;
	}
	if (pr[0] != -1)
		close(pr[0]);
	if (pr[1] != -1)
		close(pr[1]);
	if (pw[0] != -1)
		close(pw[0]);
	if (pw[1] != -1)
		close(pw[1]);
	smtp_set_transaction_state(ctx, module, 0, NULL);
	return ret;
}

void mod_spamassassin_init(void)
{
	smtp_cmd_register("BODY", mod_spamassassin_hdlr_body, 50, 0);
}
