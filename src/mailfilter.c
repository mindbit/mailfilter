#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>

#include "smtp_server.h"

/* Forks, closes all file descriptors and redirects stdin/stdout to /dev/null */
void daemonize(void) {
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

	/*
	 * Server configuration initializer.
	 */
	struct config config = {
		.path = "/etc/mailfilter.conf",
		.daemon = 1,
		.logging_type = LOGGING_TYPE_STDERR,
		.logging_level = LOG_INFO,
		.logging_facility = LOG_DAEMON,
		.dbconn = NULL,
	};
	struct config newcfg;

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

	if (config_parse(&config, &newcfg))
		return 1;

	config = newcfg;

	smtp_server_init();

	sock = socket(PF_INET, SOCK_STREAM, 0);
	assert(sock != -1);

	status = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	assert(status != -1);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(8025);

	status = bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
	assert(status != -1);

	status = listen(sock, 20);
	assert(status != -1);

	log(&config, LOG_INFO, "mailfilter 0.1 startup complete; ready to accept connections\n");

	do {
		socklen_t addrlen = sizeof(struct sockaddr_in);
		struct smtp_server_context ctx;
		FILE *client_sock_stream;
		int client_sock_fd;

		client_sock_fd = accept(sock, (struct sockaddr *)&ctx.addr, &addrlen);
		if (client_sock_fd < 0) {
			continue; // FIXME busy loop daca avem o problema recurenta
		}

		switch (fork()) {
		case -1:
			assert(0); // FIXME
			break;
		case 0:
			client_sock_stream = fdopen(client_sock_fd, "r+");
			assert(client_sock_stream != NULL);
			ctx.cfg = &config;
			smtp_server_run(&ctx, client_sock_stream);
			fclose(client_sock_stream);
			exit(EXIT_SUCCESS);
		default:
			close(client_sock_fd);
			// FIXME append child to list for graceful shutdown
		}
	} while (1);

	return 0;
}
