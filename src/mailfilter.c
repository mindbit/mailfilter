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
#define _POSIX_C_SOURCE 201112L

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
#include <sys/mman.h>

#include <jsmisc.h>

#include "config.h"
#include "js_sys.h"
#include "js_smtp.h"
#include "smtp_server.h"

// FIXME
#define assert_log(...)
#define assert_mod_log(...)

const char *white = "\r\n\t ";
const char *tab_space = "\t ";

JSContext *js_context; // FIXME make static
static JSRuntime *js_runtime;

// FIXME will be retrieved by dlsym() when loadable module support is available
JSBool mod_spf_init(JSContext *cx, JSObject *global);

static int js_init(const char *filename)
{
	JSObject *global;
	jsval sys;

	int fd;
	void *buf;
	off_t len;

	/* The class of the global object. */
	static JSClass global_class = {
		"global", JSCLASS_GLOBAL_FLAGS, JS_PropertyStub,
		JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
		JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub,
		NULL, JSCLASS_NO_OPTIONAL_MEMBERS
	};

	/*
	 * Create a JS runtime. Each runtime has an owner thread, which is
	 * by default the current thread at the time when the runtime is
	 * created. Note that mailfilter is NOT multi-threaded.
	 */
	js_runtime = JS_NewRuntime(8 * 1024 * 1024);
	if (js_runtime == NULL)
		return -1;
	/* Create a context. You always need a context per runtime. */
	js_context = JS_NewContext(js_runtime, 8192);
	if (js_context == NULL)
		return -1;
	JS_SetOptions(js_context, JSOPTION_VAROBJFIX | JSOPTION_METHODJIT);
	JS_SetVersion(js_context, JSVERSION_LATEST);
	JS_MiscSetErrorReporter(js_context);

	/*
	 * Create the global object in a new compartment.
	 * You always need a global object per context.
	 */
	global = JS_NewGlobalObject(js_context, &global_class, NULL);
	if (global == NULL)
		return -1;

	/*
	 * Populate the global object with the standard JavaScript
	 * function and object classes, such as Object, Array, Date.
	 */
	if (!JS_InitStandardClasses(js_context, global))
		return -1;

	/* Read the file into memory */
	fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		perror(filename);
		return -1;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t) -1) {
		close(fd);
		perror("lseek");
		return -1;
	}

	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		perror("mmap");
		return -1;
	}

	/* Initialize global objects */
	if (js_sys_init(js_context, global))
		return -1;
	if (!JS_GetProperty(js_context, global, "Sys", &sys))
		return -1;
	if (!JS_MiscInit(js_context, JSVAL_TO_OBJECT(sys)))
		return -1;
	if (!js_smtp_init(js_context, global))
		return -1;

	// FIXME will be called by Sys.loadModule() when supported
	mod_spf_init(js_context, global);

	/* Run script */
	JS_EvaluateScript(js_context, global, buf, len, filename, 0, NULL);

	// FIXME maybe parse the debugProtocol property, which should
	// be in smtpServer instead of engine
#if 0
	/* Evaluate the changes caused by the script */
	if (js_engine_parse(js_context, global))
		return -1;
#endif

	return 0;
}

void js_stop(void)
{
	/* Clean things up and shut down SpiderMonkey. */
	JS_DestroyContext(js_context);
	JS_DestroyRuntime(js_runtime);
	JS_ShutDown();
}

/* Array of server sockets */
int fds[256], fds_len; // FIXME don't define these globally

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
			"  -d              Debug mode (do not fork worker processes)\n"
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

static int get_socket_for_address(char *ip, unsigned short port)
{
	int sockfd = -1, status, yes = 1;
	struct addrinfo *servinfo, *p, hints = {
		.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char pstr[20];

	snprintf(pstr, sizeof(pstr), "%hu", port);
	status = getaddrinfo(ip, pstr, &hints, &servinfo);
	if (status) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd < 0) {
			perror("socket"); // FIXME log the error
			continue;
		}

		status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int));
		if (status < 0) {
			perror("setsockopt"); // FIXME log the error
			close(sockfd);
			continue;
		}

		status = bind(sockfd, p->ai_addr, p->ai_addrlen);
		if (status < 0) {
			perror("bind"); // FIXME log the error
			close(sockfd);
			continue;
		}

		status = listen(sockfd, 20);
		if (status < 0) {
			perror("listen"); // FIXME log the error
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "failed to bind to %s:%s\n", ip, pstr); // FIXME log the error
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

static int create_sockets(void)
{
	JSObject *global, *smtpserver, *listen_address, *array;
	jsval server_val, prop_val, array_elem;

	JSString *array_elem_obj;
	char *ip;
	int32_t port;

	int i;
	uint32_t array_len;

	/* Get "global" object */
	global = JS_GetGlobalForScopeChain(js_context);

	if (!JS_GetProperty(js_context, global, "SmtpServer", &server_val))
		return -1;
	// FIXME smtpserver is NULL if property was not found
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

		if (array_len < 2)
			return JS_FALSE;

		/* Get IP address (1st element of array) */
		if (!JS_GetElement(js_context, array, 0, &array_elem))
			return JS_FALSE;

		if (!JSVAL_IS_STRING(array_elem))
			return JS_FALSE;

		array_elem_obj = JSVAL_TO_STRING(array_elem);
		if (!array_elem_obj)
			return JS_FALSE;

		ip = JS_EncodeString(js_context, array_elem_obj);

		/* Get Port number (2nd element of array) */
		if (!JS_GetElement(js_context, array, 1, &array_elem))
			return JS_FALSE;

		if (!JS_ValueToInt32(js_context, array_elem, &port))
			return JS_FALSE;

		if ((fds[fds_len++] = get_socket_for_address(ip, port)) < 0)
			return JS_FALSE;
		JS_Log(JS_LOG_INFO, "Listening on %s:%d\n", ip, (int)port);

		JS_free(js_context, ip);

		 // FIXME for now, handle only the first element of "listenAddress"
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
	int opt, debug = 0;
	char *config_path = "config.js";

	struct sigaction sigchld_act = {
		.sa_sigaction = chld_sigaction,
		.sa_flags = SA_SIGINFO | SA_NOCLDSTOP
	};

	while ((opt = getopt(argc, argv, "hdc:")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			show_help(argv[0]);
			return 0;
		default:
			show_help(argv[0]);
			return 1;
		}
	}

	JS_Log(JS_LOG_INFO, "%s\n", VERSION_STR);

	/* Intialize JavaScript engine */
	if (js_init(config_path))
		goto out;

	/* Start listening on addresses and ports given in the JS config */
	if (create_sockets() < 0) {
		fprintf(stderr, "Error setting up sockets.\n");
		exit(EXIT_FAILURE);
	}

	sigaction(SIGCHLD, &sigchld_act, NULL);

	JS_Log(JS_LOG_INFO, "startup complete; ready to accept connections\n");

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
			smtp_server_main(client_sock_fd, &peer);
			continue;
		}

		switch (fork()) {
		case -1:
			assert_log(0, &config); // FIXME
			break;
		case 0:
			/* __pexec_hdlr_body() always calls waitpid() for child processes,
			 * so we reinstall the default signal handler */
			signal(SIGCHLD, SIG_DFL);

			/* Ignore SIGPIPE, because we don't want to die if the chid closes
			 * while we're writing to the pipe. Instead, reads/writes will fail
			 * with -1 (and errno set to EPIPE), and __pexec_hdlr_body() will
			 * properly recover from the error. */
			signal(SIGPIPE, SIG_IGN);

			smtp_server_main(client_sock_fd, &peer);
			// js_stop();
			/*
			 * FIXME handle fork() vs. mozjs multithreading properly
			 *
			 * Calling js_stop() here blocks the process:
			 *
			 * #0  0x00007f996e2c53df in pthread_cond_destroy@@GLIBC_2.3.2 () from /lib64/libpthread.so.0
			 * #1  0x00007f996dc969f9 in PR_DestroyCondVar () from /lib64/libnspr4.so
			 * #2  0x00007f996efa1973 in js::SourceCompressorThread::finish (this=0x7f996f804c78) at /usr/src/debug/mozjs17.0.0/js/src/jsscript.cpp:896
			 * #3  0x00007f996eeb168d in JSRuntime::~JSRuntime (this=0x7f996f804010, __in_chrg=<value optimized out>) at /usr/src/debug/mozjs17.0.0/js/src/jsapi.cpp:954
			 * #4  0x00007f996eeb1966 in delete_<JSRuntime> (rt=0x7f996f804010) at dist/include/js/Utility.h:616
			 * #5  JS_Finish (rt=0x7f996f804010) at /usr/src/debug/mozjs17.0.0/js/src/jsapi.cpp:1079
			 * #6  0x00000000004032a8 in js_stop () at mailfilter.c:157
			 * #7  0x0000000000403d65 in main (argc=3, argv=0x7fffc9be3fb8) at mailfilter.c:475
			 *
			 */
			exit(EXIT_SUCCESS);
		default:
			close(client_sock_fd);
			// FIXME append child to list for graceful shutdown
		}
	} while (1);

out:
	js_stop();
	return 1;
}
