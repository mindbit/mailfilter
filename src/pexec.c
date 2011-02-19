#define _POSIX_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "pexec.h"
#include "stdio.h"

int pexec(char * const *argv, int fd_in, int fd_out)
{
	int i, fd_err;
	struct rlimit rl = {0};

	/* close all open file descriptors */
	getrlimit(RLIMIT_NOFILE, &rl);
	if (rl.rlim_max <= 0)
		return 127;
	for (i = 0; i < rl.rlim_max; i++) {
		if (i == fd_in || i == fd_out)
			continue;
		close(i);
	}

	dup2(fd_in, 0);
	dup2(fd_out, 1);
	fd_err = open("/dev/null", 0);

	// FIXME do we really need this? we should have fd_err == 2 anyway
	if (fd_err != 2)
		dup2(fd_err, 2);

	execv(argv[0], argv);
	return 127;
}

int __pexec_hdlr_body(struct smtp_server_context *ctx, const char *module, char * const *argv,
		pexec_send_headers_t pexec_send_headers, pexec_result_t pexec_result)
{
	int status = 0, pr[2] = {-1, -1}, pw[2] = {-1, -1};
	pid_t pid;
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
		status = pexec(argv, pw[0], pr[1]);
		/* pexec() should not return; if it does, something went wrong */
		exit(status);
	}

	/* parent */
	if (pexec_send_headers(ctx, fw)) {
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

	if (WEXITSTATUS(status) >= 127) {
		/* we failed to execl() the spamc binary */
		goto out_err;
	}

	ret = pexec_result(ctx, fr, status);
	goto out_clean;

out_err:
	/* first check if waitpid() has already been called, since we may get
	 * here after all data was sent to child process */
	if (!WIFEXITED(status))
		waitpid(pid, &status, WNOHANG);
	if (WIFEXITED(status)) {
		mod_log(LOG_ERR, "execv(%s) failed\n", argv[0]);
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
