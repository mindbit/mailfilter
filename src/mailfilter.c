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

#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "js/js.h"
#include "smtp_server.h"

/* Array of server sockets */
int fds[256], fds_len;

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

static int get_socket_for_address(char *ip, char *port)
{
	int sockfd, status, yes = 1;
	struct addrinfo hints, *servinfo, *p;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	status = getaddrinfo(ip, port, &hints, &servinfo);
	if (status) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd < 0) {
			perror("socket");
			continue;
		}

		status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int));
		if (status < 0) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		status = bind(sockfd, p->ai_addr, p->ai_addrlen);
		if (status < 0) {
			close(sockfd);
			perror("bind");
			continue;
		}

		status = listen(sockfd, 20);
		if (status < 0) {
			close(sockfd);
			perror("listen");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "failed to bind to %s:%s\n", ip, port);
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

static int create_sockets(void)
{
	JSObject *global, *smtpserver, *listen_address, *array;
	jsval server_val, prop_val, array_elem;

	JSString *array_elem_obj;
	char *ip, *port;

	int i;
	jsuint array_len;

	/* Get "global" object */
	global = JS_GetGlobalForScopeChain(js_context);

	if (!JS_GetProperty(js_context, global, "smtpServer", &server_val))
		return -1;
	smtpserver = JSVAL_TO_OBJECT(server_val);

	if (!JS_GetProperty(js_context, smtpserver, "listenAddress", &prop_val))
		return -1;

	/* Check if assigned value is not primitive */
	if (JSVAL_IS_PRIMITIVE(prop_val))
		return JS_FALSE;

	/* Check if object is an array */
	listen_address = JSVAL_TO_OBJECT(prop_val);
	if (!listen_address || !JS_IsArrayObject(js_context, listen_address))
		return JS_FALSE;

	/* Get number of elements in array */
	if (!JS_GetArrayLength(js_context, listen_address, &array_len))
		return JS_FALSE;

	/* Handle each of the array elements */
	for (i = 0; i < array_len; i++) {
		if (!JS_GetElement(js_context, listen_address, i, &array_elem))
			return JS_FALSE;

		/* Check if assigned value is not primitive */
		if (JSVAL_IS_PRIMITIVE(array_elem))
			return JS_FALSE;

		/* Check if object is an array */
		array = JSVAL_TO_OBJECT(array_elem);
		if (!array || !JS_IsArrayObject(js_context, array))
			return JS_FALSE;

		/* Get number of elements in array */
		if (!JS_GetArrayLength(js_context, array, &array_len))
			return JS_FALSE;

		/* Get IP address (1st element of array) */
		if (array_len >= 1) {
			if (!JS_GetElement(js_context, array, 0, &array_elem))
				return JS_FALSE;

			if (!JSVAL_IS_STRING(array_elem))
				return JS_FALSE;

			array_elem_obj = JSVAL_TO_STRING(array_elem);
			if (!array_elem_obj)
				return JS_FALSE;

			ip = JS_EncodeString(js_context, array_elem_obj);
		}

		/* Get Port number (2nd element of array) */
		if (array_len >= 2) {
			if (!JS_GetElement(js_context, array, 1, &array_elem))
				return JS_FALSE;

			if (!JSVAL_IS_STRING(array_elem))
				return JS_FALSE;

			array_elem_obj = JSVAL_TO_STRING(array_elem);
			if (!array_elem_obj)
				return JS_FALSE;

			port = JS_EncodeString(js_context, array_elem_obj);
		}

		fds[i] = get_socket_for_address(ip, port);
		log(&config, LOG_INFO, "Listening on %s:%s\n", ip, port);
		fds_len++;

		JS_free(js_context, ip);
		JS_free(js_context, port);

		/*
		 * TODO: For now, handle only the first element of the
		 * "listenAddress" property.
		 */
		break;
	}

	return 0;
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
	int status, opt;

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

	/* Start listening on addresses and ports given in the JS config */
	if (create_sockets() < 0) {
		fprintf(stderr, "Error setting up sockets.\n");
		exit(EXIT_FAILURE);
	}

	sigaction(SIGCHLD, &sigchld_act, NULL);

	log(&config, LOG_INFO, "mailfilter 0.1 startup complete; ready to accept connections\n");

	do {
		socklen_t addrlen = sizeof(struct sockaddr_in);
		struct smtp_server_context ctx;
		bfd_t *client_sock_stream;
		int client_sock_fd;
		char *remote_addr;

		smtp_server_context_init(&ctx);

		/* TODO: Using only socket fds[0], for now */
		client_sock_fd = accept(fds[0], (struct sockaddr *)&ctx.addr, &addrlen);
		if (client_sock_fd < 0) {
			continue; // FIXME busy loop daca avem o problema recurenta
		}
		remote_addr = inet_ntoa(ctx.addr.sin_addr);

		switch (fork()) {
		case -1:
			assert_log(0, &config); // FIXME
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
			assert_log(client_sock_stream != NULL, &config);
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
