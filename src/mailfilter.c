/* SPDX-License-Identifier: GPLv2 */

#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "mailfilter.h"
#include "config.h"
#include "js_sys.h"
#include "js_smtp.h"
#include "js_dns.h"
#include "smtp_server.h"

#include "mod_spf.h"
#include "mod_extscan.h"

// FIXME
#define assert_log(...)
#define assert_mod_log(...)

const char *white = "\r\n\t ";
const char *tab_space = "\t ";

// FIXME will be retrieved by dlsym() when loadable module support is available
duk_bool_t mod_spf_init(duk_context *ctx);

static SSL_CTX *ssl_init(const char *chain_path, const char *key_path)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		log_ssl_errors();
		return NULL;
	}

	if (SSL_CTX_use_certificate_chain_file(ctx, chain_path) != 1) {
		log_ssl_errors();
		goto out_free;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
		log_ssl_errors();
		goto out_free;
	}

	return ctx;

out_free:
	SSL_CTX_free(ctx);
	return NULL;
}

static int drop_privs(uid_t uid, gid_t gid)
{
	/* See SEI CERT C rule POS36-C */

	if (geteuid() != 0)
		return EPERM;

	if (setgroups(0, NULL) == -1)
		return errno;

	if (setgid(gid) == -1)
		return errno;

	if (setuid(uid) == -1)
		return errno;

	return 0;
}

static void js_fatal(void *udata, const char *msg) {
	(void) udata;  /* ignored in this case, silence warning */

	/* Note that 'msg' may be NULL. */
	fprintf(stderr, "*** FATAL ERROR: %s\n", (msg ? msg : "no message"));
	fflush(stderr);
	abort();
}

static duk_context *js_init(const char *filename)
{
	duk_context *ctx = NULL, *ret = NULL;
	//jsval sys;

	int fd = -1;
	void *buf = MAP_FAILED;
	off_t len = 0;

	ctx = duk_create_heap(NULL, NULL, NULL, NULL, js_fatal);
	if (!ctx)
		return ctx;

	/* Initialize global objects */

	if (!js_sys_init(ctx))
		goto out_clean;

	if (!duk_get_global_string(ctx, "Sys"))
		goto out_clean;
	if (!js_misc_init(ctx, -1))
		goto out_clean;
	duk_pop(ctx);

	if (!js_smtp_init(ctx))
		goto out_clean;

	if (!js_dns_init(ctx))
		goto out_clean;

#if HAVE_LIBSPF2
	mod_spf_init(ctx);
#endif
	mod_extscan_init(ctx);

	/* Read the file into memory */

	fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		perror(filename);
		goto out_clean;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t) -1) {
		perror("lseek");
		goto out_clean;
	}

	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		goto out_clean;
	}

	/* Run script */

	duk_push_lstring(ctx, buf, len);
	duk_push_string(ctx, filename);
	if (duk_pcompile(ctx, 0)) {
		js_log_error(ctx, -1);
		goto out_clean;
	}

	if (duk_pcall(ctx, 0)) {
		js_log_error(ctx, -1);
		goto out_clean;
	}
	duk_pop(ctx); /* ignore result */

	ret = ctx;

	// FIXME maybe parse the debugProtocol property, which should
	// be in smtpServer instead of engine

out_clean:
	if (ctx && !ret)
		duk_destroy_heap(ctx);

	if (buf != MAP_FAILED)
		munmap(buf, len);

	close(fd);

	return ret;
}

/* Array of server sockets */
int fds[256], fds_len; // FIXME don't define these globally

static void show_help(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s <options>\n"
		"\n"
		"Valid options:\n"
		"  -c <path>      Read configuration file from <path>\n"
		"  -d             Debug mode (do not fork worker processes)\n"
		"  -g <group>     Run as specified group name\n"
		"  -h             Show this help\n"
		"  -k <path>      Read SSL key from PEM file at <path>\n"
		"  -s <path>      Read SSL certificate chain from PEM file at <path>\n"
		"  -u <user>      Run as specified user name\n"
		"\n",
		argv0);
}

static void chld_sigaction(int sig, siginfo_t *info, void *_ucontext)
{
	pid_t pid __attribute__((unused));
	int status;

	/*
	 * If multiple child processes exit at about the same time, the signal
	 * handler is called only once. Repeatedly wait for *any* child process
	 * that has exited (not just the one in info->si_pid), until there are
	 * no more child processes.
	 */
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

static int get_socket_for_address(const char *host, unsigned short port)
{
	int sockfd = -1, status, yes = 1;
	struct addrinfo *addrinfo, *p, hints = {
		.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char pstr[20];

	snprintf(pstr, sizeof(pstr), "%hu", port);
	status = getaddrinfo(host, pstr, &hints, &addrinfo);
	if (status) {
		js_log(LOG_NOTICE, "getaddrinfo: %s\n", gai_strerror(status));
		return -ENOLINK;
	}

	for (p = addrinfo; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd < 0) {
			js_log(LOG_NOTICE, "socket: %s\n", strerror(errno));
			continue;
		}

		status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int));
		if (status < 0) {
			js_log(LOG_NOTICE, "setsockopt: %s\n", strerror(errno));
			close(sockfd);
			continue;
		}

		status = bind(sockfd, p->ai_addr, p->ai_addrlen);
		if (status < 0) {
			js_log(LOG_NOTICE, "bind: %s\n", strerror(errno));
			close(sockfd);
			continue;
		}

		if (listen(sockfd, 20) == 0)
			break;

		js_log(LOG_NOTICE, "listen: %s\n", strerror(errno));
		close(sockfd);
	}

	freeaddrinfo(addrinfo);

	if (!p) {
		js_log(LOG_ERR, "cannot bind to %s:%s\n", host, pstr);
		return -ENOLINK;
	}

	return sockfd;
}

static int create_sockets(duk_context *ctx)
{
	duk_size_t i, n;

	/* Get global SmtpServer object */
	if (!duk_get_global_string(ctx, "SmtpServer"))
		return EINVAL;

	/* Get SmtpServer.listenAddress and check it's an array */
	if (!duk_get_prop_string(ctx, -1, "listenAddress"))
		return EINVAL;
	if (!duk_is_array(ctx, -1))
		return EINVAL;

	/* Iterate over SmtpServer.listenAddress */
	n = duk_get_length(ctx, -1);
	for (i = 0; i < n; i++) {
		const char *host;
		int port, sock;

		duk_get_prop_index(ctx, -1, i);

		/*
		 * Each element of SmtpServer.listenAddress is a 2 element
		 * array. Make sure this is what we get.
		 */
		if (!duk_is_array(ctx, -1) || duk_get_length(ctx, -1) < 2) {
			duk_pop_3(ctx);
			return EINVAL;
		}

		/* Get IP address (1st element of array) */
		duk_get_prop_index(ctx, -1, 0);
		host = duk_safe_to_string(ctx, -1);
		duk_pop(ctx);

		/* Get Port number (2nd element of array) */
		duk_get_prop_index(ctx, -1, 1);
		port = duk_to_int(ctx, -1);
		duk_pop(ctx);

		if ((sock = get_socket_for_address(host, port)) < 0) {
			duk_pop_3(ctx);
			return -sock;
		}

		fds[fds_len++] = sock;
		js_log(LOG_INFO, "Listening on %s:%d\n", host, port);
		duk_pop(ctx);
		// FIXME for now, handle only the first element of "listenAddress"
		break;
	}

	duk_pop_2(ctx);
	return 0;
}

int connect_to_address(duk_context *ctx, const char *host, unsigned short port)
{
	int sockfd = -1, status;
	struct addrinfo *addrinfo, *p, hints = {
		.ai_flags = AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char pstr[20];

	snprintf(pstr, sizeof(pstr), "%hu", port);
	status = getaddrinfo(host, pstr, &hints, &addrinfo);
	if (status) {
		js_log(LOG_NOTICE, "getaddrinfo: %s\n", gai_strerror(status));
		return -ENOLINK;
	}

	for (p = addrinfo; p; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd < 0) {
			js_log(LOG_NOTICE, "socket: %s\n", strerror(errno));
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0)
			break;

		js_log(LOG_NOTICE, "connect: %s\n", strerror(errno));
		close(sockfd);
	}

	freeaddrinfo(addrinfo);

	if (!p) {
		js_log(LOG_ERR, "cannot connect to %s:%s\n", host, pstr);
		return -ENOLINK;
	}

	return sockfd;
}

int ssl_print_errors_cb(const char *str, size_t len, void *u)
{
	const struct log_metadata *m = u;

	if (m->func)
		js_log_impl(m->prio, "[%s %s:%d] %*s",
			    m->func, m->file, m->line, (int)len, str);
	else
		js_log_impl(m->prio, "[%s:%d] %*s",
			    m->file, m->line, (int)len, str);

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
	int opt, debug = 0, err;
	const char *config_path = "config.js";
	const char *ssl_chain_path = NULL;
	const char *ssl_key_path = NULL;
	duk_context *dctx;
	SSL_CTX *sctx = NULL;
	struct group *group;
	struct passwd *passwd;
	gid_t gid = 0;
	uid_t uid = 0;

	struct sigaction sigchld_act = {
		.sa_sigaction = chld_sigaction,
		.sa_flags = SA_SIGINFO | SA_NOCLDSTOP
	};

	while ((opt = getopt(argc, argv, "c:dg:hk:s:u:")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'g':
			group = getgrnam(optarg);
			if (!group || !group->gr_gid) {
				fprintf(stderr, "Invalid group '%s': %s\n", optarg,
					strerror(!passwd && !errno ? ENOENT : errno));
				return EXIT_FAILURE;
			}
			gid = group->gr_gid;
			break;
		case 'h':
			show_help(argv[0]);
			return EXIT_SUCCESS;
		case 'k':
			ssl_key_path = optarg;
			break;
		case 's':
			ssl_chain_path = optarg;
			break;
		case 'u':
			passwd = getpwnam(optarg);
			if (!passwd || !passwd->pw_uid) {
				fprintf(stderr, "Invalid user '%s': %s\n", optarg,
					strerror(!passwd && !errno ? ENOENT : errno));
				return EXIT_FAILURE;
			}
			uid = passwd->pw_uid;
			break;
		default:
			show_help(argv[0]);
			return EXIT_FAILURE;
		}
	}

	js_log(LOG_INFO, "%s\n", VERSION_STR);

	if (ssl_key_path && ssl_chain_path) {
		sctx = ssl_init(ssl_chain_path, ssl_key_path);
		if (sctx)
			js_log(LOG_INFO, "STARTTLS support initialized\n");
		else
			js_log(LOG_NOTICE, "STARTTLS support unavailable\n");
	} else
		js_log(LOG_NOTICE, "STARTTLS support not configured\n");

	if ((uid || gid) && (err = drop_privs(uid, gid))) {
		js_log(LOG_ERR, "Error dropping privileges: %s\n", strerror(err));
		return EXIT_FAILURE;
	}

	/* Intialize JavaScript engine */
	if (!(dctx = js_init(config_path)))
		goto out;

	/* Start listening on addresses and ports given in the JS config */
	if (create_sockets(dctx)) {
		js_log(LOG_ERR, "Error setting up listening sockets\n");
		goto out;
	}

	/* Ignore SIGPIPE, because we don't want to die if the other end of
	 * a socket has been closed and we attempt to write. Ignore the
	 * signal, and writes will fail with -1 (and errno set to EPIPE).
	 * Write failures are properly handled throughout the code base. */
	signal(SIGPIPE, SIG_IGN);

	/* Make sure child processes are reaped and do not become zombies. */
	sigaction(SIGCHLD, &sigchld_act, NULL);

	js_log(LOG_INFO, "startup complete; ready to accept connections\n");

	do {
		struct sockaddr_in peer;
		socklen_t addrlen = sizeof(peer);
		int client_sock_fd;

		// FIXME using only socket fds[0] for now
		client_sock_fd = accept(fds[0], (struct sockaddr *)&peer, &addrlen);
		if (client_sock_fd < 0) {
			continue; // FIXME busy loop daca avem o problema recurenta
		}

		if (debug) {
			smtp_server_main(dctx, sctx, client_sock_fd, &peer);
			continue;
		}

		switch (fork()) {
		case -1:
			assert_log(0, &config); // FIXME
			break;
		case 0:
			signal(SIGCHLD, SIG_DFL);

			smtp_server_main(dctx, sctx, client_sock_fd, &peer);
			SSL_CTX_free(sctx);
			duk_destroy_heap(dctx);
			exit(EXIT_SUCCESS);
		default:
			close(client_sock_fd);
			// FIXME append child to list for graceful shutdown
		}
	} while (1);

out:
	SSL_CTX_free(sctx);
	duk_destroy_heap(dctx);
	return EXIT_FAILURE;
}
