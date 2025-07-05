/* SPDX-License-Identifier: GPLv2 */

#ifndef _MAILFILTER_H
#define _MAILFILTER_H

#include <openssl/err.h>
#include <jsmisc.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define ROUND_UP(n, d) ({							\
	typeof(d) _d = (d);							\
	(((n) + _d - 1) / _d) * d;						\
})

#define SMTP_COMMAND_MAX 512

extern const char *white;
extern const char *tab_space;

struct log_metadata {
	int prio;
	const char *func;
	const char *file;
	int line;
};

int connect_to_address(duk_context *ctx, const char *host, unsigned short port);

int ssl_print_errors_cb(const char *str, size_t len, void *u);
#define __log_ssl_errors(prio, func, file, line) ERR_print_errors_cb( \
	ssl_print_errors_cb, (void *)&(const struct log_metadata){prio, func, file, line})
#ifdef JS_DEBUG
#define _log_ssl_errors(x, prio...) __log_ssl_errors(prio, __func__, __FILE__, __LINE__)
#else
#define _log_ssl_errors(x, prio...) __log_ssl_errors(prio, NULL, __FILE__, __LINE__)
#endif
#define log_ssl_errors(prio...) _log_ssl_errors(x, ##prio, LOG_ERR)

#endif
