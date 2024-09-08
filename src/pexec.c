/* SPDX-License-Identifier: GPLv2 */

#define _POSIX_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <jsmisc.h>

#include "pexec.h"
#include "bfd.h"

static inline int std_fd(int fd)
{
	return fd >= 0 && fd <= 2;
}

static inline int dup_opt(int fd)
{
	return fd < 0 ? open("/dev/null", 0) : dup(fd);
}


int pexec_fd_execv(char * const *argv, int fd_in, int fd_out, int fd_err)
{
	int i;
	struct rlimit rl = {0};

	if (std_fd(fd_in) || std_fd(fd_out) || std_fd(fd_err))
		return EINVAL;

	/* close all open file descriptors */
	errno = EINVAL;
	getrlimit(RLIMIT_NOFILE, &rl);
	if (rl.rlim_max <= 0)
		return errno;
	for (i = 0; i < rl.rlim_max; i++)
		if (i != fd_in && i != fd_out && i != fd_err)
			close(i);

	if (dup(fd_in) < 0)
		return errno;

	if (dup_opt(fd_out) < 0)
		return errno;

	if (dup_opt(fd_err) < 0)
		return errno;

	execv(argv[0], argv);
	return errno;
}

JSBool pexec_put_msg(JSContext *cx, char * const *argv, jsval hdrs, jsval path,
		struct string_buffer *out, int *status)
{
	int status = 0, pr[2] = {-1, -1}, pw[2] = {-1, -1};
	pid_t pid;
	bfd_t *istream, ostream;
	int ret = 0;

	istream = smtp_body_open_read(cx, path);
	if (!istream)
		goto out_clean;
	if (pipe(pr))
		goto out_clean;
	if (pipe(pw))
		goto out_clean;
	bfd_init(&ostream, pw[1]);
	// ((fr = bfd_alloc(pr[0])) == NULL)

	switch ((pid = fork())) {
	case -1:
		JS_Log(JS_LOG_ERR, "could not spawn child process\n");
		goto out_clean;
	case 0:
		/* child; pipe ends that we're not interested in (the ones used
		 * by the parent) will be implicitly closed by pexec_fd_execv()
		 * because it closes everything but our own pipe ends. */
		pexec_fd_execv(argv, pw[0], pr[1], -1);
		/* pexec() should not return; if it does, something went wrong */
		exit(127);
	}

	/* parent; close pipe ends that are meant for the child, so that we
	 * detect (get read/write error) when the other pipe end has closed. */
	close(pr[1]);
	pr[1] = -1;
	close(pw[0]);
	pw[0] = -1;

	status = smtp_copy_from_file(&ostream, istream, JSVAL_TO_OBJECT(hdrs), 0);

	close(body_stream->fd);
	free(body_stream);

	if (status != EIO)
		bfd_flush(client_stream);

	return !status;

	if (pexec_send_headers(ctx, fw)) {
		JS_Log(JS_LOG_ERR, "could not copy message headers\n");
		goto out_err;
	}

	if (bfd_puts(fw, "\r\n") < 0) {
		JS_Log(JS_LOG_ERR, "could not copy message header delimiter\n");
		goto out_err;
	}

	bfd_seek(ctx->body.stream, 0, SEEK_SET);
	if (bfd_copy(ctx->body.stream, fw)) {
		JS_Log(JS_LOG_ERR, "could not copy message body\n");
		goto out_err;
	}

	/* close pipe and prevent it from being closed again at cleanup */
	bfd_close(fw);
	fw = NULL;
	pw[0] = -1;

	/* FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
	 * We have a severe race condition: if the child process
	 * writes enough data to fill the pipe buffer, it will
	 * block in write() and will never exit. On the other hand,
	 * we first wait for the child to finish and then read from
	 * the pipe, so this is a deadlock.
	 *
	 * We cannot close our read pipe, because the child might
	 * die by SIGPIPE. Instead we need to read (and discard
	 * the data) until the child closes its own end.
	 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME */
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
		JS_Log(JS_LOG_ERR, "execv(%s) failed\n", argv[0]);
		goto out_clean;
	}
	/* cleanup when child process seems to be dead */
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);

out_clean:
	if (fr != NULL) {
		bfd_close(fr);
		pr[0] = -1;
	}
	if (fw != NULL) {
		bfd_close(fw);
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
	return ret;
}
