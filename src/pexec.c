/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter.
 *
 * mailfilter is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * mailfilter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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
#include "bfd.h"

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
	bfd_t *fr = NULL, *fw = NULL;
	int ret = SCHS_BREAK;

	if (pipe(pr))
		goto out_clean;
	if (pipe(pw))
		goto out_clean;
	if ((fr = bfd_alloc(pr[0])) == NULL)
		goto out_clean;
	if ((fw = bfd_alloc(pw[1])) == NULL)
		goto out_clean;

	switch ((pid = fork())) {
	case -1:
		mod_log(LOG_ERR, "could not spawn child process\n");
		goto out_clean;
	case 0:
		/* child; pipe ends that we're not interested in (the ones used
		 * by the parent) will be implicitly closed by pexec() because
		 * it closes everything but our own pipe ends. */
		status = pexec(argv, pw[0], pr[1]);
		/* pexec() should not return; if it does, something went wrong */
		exit(status);
	}

	/* parent; close pipe ends that are meant for the child, so that we
	 * detect (get read/write error) when the other pipe end has closed. */
	close(pr[1]);
	pr[1] = -1;
	close(pw[0]);
	pw[0] = -1;

	if (pexec_send_headers(ctx, fw)) {
		mod_log(LOG_ERR, "could not copy message headers\n");
		goto out_err;
	}

	if (bfd_puts(fw, "\r\n") < 0) {
		mod_log(LOG_ERR, "could not copy message header delimiter\n");
		goto out_err;
	}

	bfd_seek(ctx->body.stream, 0, SEEK_SET);
	if (bfd_copy(ctx->body.stream, fw)) {
		mod_log(LOG_ERR, "could not copy message body\n");
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
		mod_log(LOG_ERR, "execv(%s) failed\n", argv[0]);
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
