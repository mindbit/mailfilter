/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter, a free SIP server.
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

#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "js/js.h"
#include "smtp_server.h"

// FIXME this is used by assert_log() in places where we have no other
// reference to the main config
struct config __main_config;

/* Forks, closes all file descriptors and redirects stdin/stdout to /dev/null */
void daemonize(void)
{
	struct rlimit rl = {0};
	int fd = -1;
	int i;

	switch (fork()) {
	case -1:
		//syslog(LOG_ERR, "Prefork stage 1: %m");
		exit(1);
	case 0: /* child */
		break;
	default: /* parent */
		exit(0);
	}

	rl.rlim_max = 0;
	getrlimit(RLIMIT_NOFILE, &rl);
	switch (rl.rlim_max) {
	case -1: /* oops! */
		//syslog(LOG_ERR, "getrlimit");
		exit(1);
	case 0:
		//syslog(LOG_ERR, "Max number of open file descriptors is 0!");
		exit(1);
	}
	for (i = 0; i < rl.rlim_max; i++)
		close(i);
	if (setsid() == -1) {
		//syslog(LOG_ERR, "setsid failed");
		exit(1);
	}
	switch (fork()) {
	case -1:
		//syslog(LOG_ERR, "Prefork stage 2: %m");
		exit(1);
	case 0: /* child */
		break;
	default: /* parent */
		exit(0);
	}

	chdir("/");
	umask(0);
	fd = open("/dev/null", O_RDWR);
	dup(fd);
	dup(fd);
}

static void show_help(const char *argv0)
{
	fprintf(stderr,
			"Usage: %s <options>\n"
			"\n"
			"Valid options:\n"
			"  -c <path>       Read configuration file from <path>\n"
			"  -d              Do not fork to background; log everything to stderr\n"
			"  -h              Show this help\n"
			"\n",
			argv0);
}

static void chld_sigaction(int sig, siginfo_t *info, void *_ucontext)
{
	int status;

#if 0
	printf("SIGCHLD: signo=%d errno=%d code=%d pid=%d\n",
			info->si_signo, info->si_errno, info->si_code, info->si_pid);
#endif
	waitpid(info->si_pid, &status, WNOHANG);
}

/* TODO redesign model procese:
 * - reciclam workerii
 * - procesul parinte functioneaza ca multiplexor de date
 *   - fiecare worker are un set de pipe-uri cu procesul principal
 *   - la o conexiune noua, daca avem un worker disponibil, asignam workerul si punem conexiunea intr-o lista
 *   - procesul parinte supravegheaza cu select() toate fd-urile active
 *   - datele primite pe socket se copiaza in pipe si invers
 * - probleme
 *   - pipe-urile sunt unidirectionale => in worker trebuie modificat FILE * stream cu o pereche
 *   - stream-urile fac buffer; pot sa am probleme cu buffer pe input atunci cand un worker serveste o noua conexiune
 */
int main(int argc, char **argv)
{
	int sock, on = 1, status, opt;
	struct sockaddr_in servaddr;

	struct sigaction sigchld_act = {
		.sa_sigaction = chld_sigaction,
		.sa_flags = SA_SIGINFO | SA_NOCLDSTOP
	};

	while ((opt = getopt(argc, argv, "hdc:")) != -1) {
		switch (opt) {
		case 'c':
			config.path = strdup(optarg);
			break;
		case 'd':
			config.daemon = 0;
			break;
		case 'h':
			show_help(argv[0]);
			return 0;
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	/* Intialize JavaScript engine */
	status = js_init(config.path);
	assert_log(status != -1, &config);

	smtp_server_init();

	sock = socket(PF_INET, SOCK_STREAM, 0);
	assert_log(sock != -1, &config);

	status = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	assert_log(status != -1, &config);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(8025);

	status = bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
	assert_log(status != -1, &config);

	status = listen(sock, 20);
	assert_log(status != -1, &config);

	sigaction(SIGCHLD, &sigchld_act, NULL);

	log(&config, LOG_INFO, "mailfilter 0.1 startup complete; ready to accept connections\n");

	do {
		socklen_t addrlen = sizeof(struct sockaddr_in);
		struct smtp_server_context ctx;
		bfd_t *client_sock_stream;
		int client_sock_fd;
		char *remote_addr;

		smtp_server_context_init(&ctx);
		client_sock_fd = accept(sock, (struct sockaddr *)&ctx.addr, &addrlen);
		if (client_sock_fd < 0) {
			continue; // FIXME busy loop daca avem o problema recurenta
		}
		remote_addr = inet_ntoa(ctx.addr.sin_addr);

		switch (fork()) {
		case -1:
			assert_log(0, config); // FIXME
			break;
		case 0:
			//printf("pid: %d sleeping\n", getpid()); fflush(stdout); sleep(8);

			/* __pexec_hdlr_body() always calls waitpid() for child processes,
			 * so we reinstall the default signal handler */
			signal(SIGCHLD, SIG_DFL);

			/* Ignore SIGPIPE, because we don't want to die if the chid closes
			 * while we're writing to the pipe. Instead, reads/writes will fail
			 * with -1 (and errno set to EPIPE), and __pexec_hdlr_body() will
			 * properly recover from the error. */
			signal(SIGPIPE, SIG_IGN);

			client_sock_stream = bfd_alloc(client_sock_fd);
			assert_log(client_sock_stream != NULL, config);
			log(&config, LOG_INFO, "New connection from %s", remote_addr);
			ctx.cfg = &config;
			smtp_server_run(&ctx, client_sock_stream);
			bfd_close(client_sock_stream);
			log(&config, LOG_INFO, "Closed connection to %s", remote_addr);
			js_stop();
			exit(EXIT_SUCCESS);
		default:
			close(client_sock_fd);
			// FIXME append child to list for graceful shutdown
		}
	} while (1);

	return 0;
}
