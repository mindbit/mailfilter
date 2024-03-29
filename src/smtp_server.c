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
#define _POSIX_C_SOURCE 201112L /* mkstemp */
#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <limits.h>

#include <jsmisc.h>

#include "mailfilter.h"
#include "js_smtp.h"
#include "smtp_server.h"
#include "string_tools.h"
#include "base64.h"

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Client stream (buffered file descriptor) */
	bfd_t stream;

	/* Duktape context */
	duk_context *dcx;

	/* JavaScript instance of SmtpServer */
	duk_idx_t js_srv_idx;
};

struct smtp_response {
	/* SMTP status code to send back to client */
	int code;

	/* SMTP message to send back to client */
	char *message;
};

struct esmtp_cap {
	const char *verb;
	int (*cb)(const char *verb, char *param);
};

// FIXME
#define assert_log(...)
#define assert_mod_log(...)

//static uint64_t key;

/**
 * @brief SMTP command handler prototype
 */
typedef int (*smtp_cmd_hdlr_t)(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp);

/**
 * @brief SMTP command handler table element
 */
struct smtp_cmd_hdlr {
	const char *name;
	smtp_cmd_hdlr_t hdlr;
};

/**
 * @brief SMTP command handler table
 *
 * Map SMTP commands to handlers
 */
static struct smtp_cmd_hdlr smtp_cmd_table[];

#define DEF_SMTP_RSP(name, _code, _message) \
	static const struct smtp_response smtp_rsp_##name = {\
		.code		= _code, \
		.message	= _message, \
	}

DEF_SMTP_RSP(bye,		221, "Closing connection");
DEF_SMTP_RSP(ok,		250, "OK");
DEF_SMTP_RSP(go_ahead,		354, "Go ahead");
DEF_SMTP_RSP(int_err,		451, "Internal server error");
DEF_SMTP_RSP(no_space,		452, "Insufficient system storage");
DEF_SMTP_RSP(not_impl,		500, "Command not implemented");
DEF_SMTP_RSP(cmd_too_long,	500, "Command too long");
DEF_SMTP_RSP(bad_syntax,	500, "Bad syntax");
DEF_SMTP_RSP(invalid_hdrs,	500, "Could not parse message headers");
DEF_SMTP_RSP(syntax_error,	501, "Syntax error");
DEF_SMTP_RSP(hostname_req,	501, "Hostname required");
DEF_SMTP_RSP(sndr_specified,	503, "Sender already specified");
DEF_SMTP_RSP(no_sndr,		503, "Must specify sender first");
DEF_SMTP_RSP(no_recipients,	503, "Must specify recipient(s) first");
DEF_SMTP_RSP(hdrs_too_big,	552, "Message header too long");

struct esmtp_cap esmtp_cap_table[] = {
	{"PIPELINING",		NULL},
	{"SIZE",		NULL},
	{NULL,			NULL}
};

static inline int smtp_successful(const struct smtp_response *rsp)
{
	return rsp->code >= 200 && rsp->code < 400;
}

/**
 * @return	0 on success;
 *		ENOMEM on error
 */
static int smtp_response_copy(struct smtp_response *dst, const struct smtp_response *src)
{
	dst->code = src->code;
	dst->message = strdup(src->message);
	return dst->message ? 0 : ENOMEM;
}

/**
 * @return	0 on success;
 *		EIO on socket error
 */
static int smtp_server_response(bfd_t *f, const struct smtp_response *rsp)
{
	static const int log_len = 50;
	char *h, *t;

	for (h = rsp->message; (t = strchr(h, '\n')); h = t + 1) {
		js_log(JS_LOG_DEBUG, "<<< %d-%.*s\n", rsp->code, MIN(log_len, t - h), h);

		bfd_printf(f, "%d-", rsp->code);
		bfd_write_full(f, h, t - h);
		bfd_printf(f, "\r\n");
	}

	js_log(JS_LOG_DEBUG, "<<< %d %.*s\n", rsp->code, log_len, h);
	if (bfd_printf(f, "%d %s\r\n", rsp->code, h) >= 0) {
		bfd_flush(f);
		return 0;
	}

	return EIO;
}

/**
 * @return	0 on success;
 *		EIO on socket error
 *
 * Duktape stack:
 *	Input:	...
 *	Output:	...
 */
static int smtp_server_handle_cmd(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	int idx, status;
	struct smtp_response rsp;

	for (idx = 0; smtp_cmd_table[idx].name; idx++)
		if (!strcasecmp(smtp_cmd_table[idx].name, cmd))
			break;

	if (!smtp_cmd_table[idx].hdlr)
		return smtp_server_response(&ctx->stream, &smtp_rsp_not_impl);

	status = smtp_cmd_table[idx].hdlr(ctx, cmd, arg, &rsp);
	if (status == EIO)
		return status;
	if (status)
		return smtp_server_response(&ctx->stream, &smtp_rsp_int_err);

	status = smtp_server_response(&ctx->stream, &rsp);
	free(rsp.message);

	return status;
}

/**
 * @brief	Read line from buffered file descriptor and trim "\r\n"
 *
 * If the line in the input stream is longer than the supplied buffer,
 * subsequent reads are performed in the same buffer and older data is
 * overwritten.
 *
 * The resulting string in the buffer is always null-terminated.
 *
 * @param[in]	stream The input buffered file descriptor
 * @param[in]	buf Buffer to store data that is read from the file
 * @param[in]	size Buffer size
 * @param[out]	size String length after "\r\n" was trimmed and
 *		excluding the null-terminator
 *
 * @return	Positive value: successful read; indicates how many
 *		lines were written to the buffer.
 *		0: no data could be read from the stream (e.g. socket
 *		closed).
 *		-1: socket read error (errno is set).
 */
static int smtp_server_read_line(bfd_t *stream, char *buf, size_t *size)
{
	ssize_t len;
	int writes = 0;

	if (!stream || !buf || !size || *size < 2) {
		errno = EINVAL;
		return -1;
	}

	do {
		buf[*size - 2] = '\n';
		len = bfd_read_line(stream, buf, *size - 1);

		if (len <= 0)
			return len;

		writes++;
	} while (buf[*size - 2] != '\n');

	/* Add null termination and strip \r\n sequence */
	do {
		buf[len--] = '\0';
	} while (len >= 0 && (buf[len] == '\r' || buf[len] == '\n'));

	*size = len + 1;
	return writes;
}

/**
 * @brief 	Read and handle a single SMTP command from the client
 * @return	0 on success;
 *		EIO on socket error
 *
 * Duktape stack:
 *	Input:	...
 *	Output:	...
 */
static int smtp_server_hdle_one(struct smtp_server_context *ctx)
{
	char buf[SMTP_COMMAND_MAX];
	size_t n = sizeof(buf);
	char *c = &buf[0];
	int status;

	status = smtp_server_read_line(&ctx->stream, buf, &n);

	if (status < 0) {
		js_log(JS_LOG_ERR, "Socket read error (%s)\n", strerror(errno));
		return EIO;
	}

	if (!status) {
		js_log(JS_LOG_ERR, "Lost connection to client\n");
		return EIO;
	}

	/* Log received command */
	js_log(JS_LOG_DEBUG, ">>> %s\n", &buf[0]);

	/* reject oversized commands */
	if (status > 1)
		return smtp_server_response(&ctx->stream, &smtp_rsp_cmd_too_long);

	if (!n)
		return smtp_server_response(&ctx->stream, &smtp_rsp_bad_syntax);

	/* Parse SMTP command */
	c += strspn(c, white);
	if (*c == '\0')
		return smtp_server_response(&ctx->stream, &smtp_rsp_bad_syntax);

	n = strcspn(c, white);

	/* Prepare argument */
	if (c[n] != '\0') {
		c[n++] = '\0';
		n += strspn(c + n, white);
	}

	return smtp_server_handle_cmd(ctx, c, c + n);
}

/**
 * @return	0 on success;
 *		EINVAL on error
 *
 * Duktape stack:
 *	Input:	... | arg1 | arg2 | ... | argN
 *		nargs arguments are passed to JS handler
 *	Output:	...
 *
 * Upon successful return, the caller owns rsp->message and must free it.
 */
static int call_js_handler(struct smtp_server_context *ctx, const char *cmd, duk_idx_t nargs, struct smtp_response *rsp)
{
	char handler_name[10] = "smtp";
	int code, i;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	char *message;
	const char *str;

	for (i = 4; i < sizeof(handler_name) - 1 && *cmd; i++)
		handler_name[i] = tolower(*(cmd++));
	handler_name[4] = toupper(handler_name[4]);
	handler_name[i] = '\0';

	/* Call the given function */
	duk_push_string(ctx->dcx, handler_name);
	duk_insert(ctx->dcx, -(nargs + 1));
	if (duk_pcall_prop(ctx->dcx, ctx->js_srv_idx, nargs)) {
		js_log_error(ctx->dcx, -1);
		duk_pop(ctx->dcx);
		js_log(JS_LOG_ERR, "failed calling '%s'\n", handler_name);
		return EINVAL;
	}

	if (!rsp) {
		duk_pop(ctx->dcx);
		return 0;
	}

	/* Sanity check on return type */
	if (!duk_is_object(ctx->dcx, -1)) {
		js_log(JS_LOG_ERR, "%s: retval not an object\n", handler_name);
		duk_pop(ctx->dcx);
		return EINVAL;
	}

	/* Extract "code" field */
	if (!duk_get_prop_string(ctx->dcx, -1, "code")) {
		js_log(JS_LOG_ERR, "%s: retval missing code\n", handler_name);
		duk_pop_2(ctx->dcx);
		return EINVAL;
	}
	code = duk_get_int(ctx->dcx, -1);
	duk_pop(ctx->dcx);

	/* Extract "message" field */
	if (!duk_get_prop_string(ctx->dcx, -1, "message")) {
		js_log(JS_LOG_ERR, "%s: retval missing message\n", handler_name);
		duk_pop_2(ctx->dcx);
		return EINVAL;
	}
	if (!duk_is_array(ctx->dcx, -1)) {
		str = duk_safe_to_string(ctx->dcx, -1);
		if (!strlen(str)) {
			js_log(JS_LOG_ERR, "%s: retval empty message\n", handler_name);
			duk_pop_2(ctx->dcx);
			return EINVAL;
		}
		message = strdup(str);
	} else {
		/* Extract array elements and append to string buffer */
		duk_size_t i, n = duk_get_length(ctx->dcx, -1);

		for (i = 0; i < n; i++) {
			if (sb.cur && string_buffer_append_char(&sb, '\n'))
				break;

			duk_get_prop_index(ctx->dcx, -1, i);
			str = duk_safe_to_string(ctx->dcx, -1);

			if (string_buffer_append_string(&sb, str))
				i = n;

			duk_pop(ctx->dcx);
		}

		if (!sb.cur) {
			js_log(JS_LOG_ERR, "%s: retval empty message\n", handler_name);
			duk_pop_2(ctx->dcx);
			string_buffer_cleanup(&sb);
			return EINVAL;
		}

		message = sb.s;
	}
	duk_pop(ctx->dcx);

	/* Extract "disconnect" field */
	if (!duk_get_prop_string(ctx->dcx, -1, PR_DISCONNECT)) {
		js_log(JS_LOG_ERR, "%s: retval missing disconnect\n", handler_name);
		duk_pop_2(ctx->dcx);
		free(message);
		return EINVAL;
	}
	duk_to_boolean(ctx->dcx, -1);
	duk_put_prop_string(ctx->dcx, ctx->js_srv_idx, PR_DISCONNECT);

	duk_pop(ctx->dcx); /* JS handler return value */
	rsp->code = code;
	rsp->message = message;

	return 0;
}

static duk_bool_t smtp_server_get_disconnect(struct smtp_server_context *ctx)
{
	duk_bool_t ret = 0;

	if (duk_get_prop_string(ctx->dcx, ctx->js_srv_idx, PR_DISCONNECT))
		ret = duk_to_boolean(ctx->dcx, -1);
	else
		js_log(JS_LOG_WARNING, "Cannot get disconnect flag\n");

	duk_pop(ctx->dcx);
	return ret;
}

/**
 *
 * Duktape stack:
 *	Input:	...
 *	Output:	...
 */
void smtp_server_main(duk_context *dcx, int client_sock_fd, const struct sockaddr_in *peer)
{
	int status;
	char *remote_addr = NULL;
	struct smtp_server_context ctx = { .dcx = dcx };
	struct smtp_response rsp;

	remote_addr = inet_ntoa(peer->sin_addr);
	bfd_init(&ctx.stream, client_sock_fd);
	js_log(JS_LOG_INFO, "New connection from %s\n", remote_addr);

	/* Create SmtpServer instance */
	if (!duk_get_global_string(dcx, "SmtpServer"))
		goto out_close;

	duk_push_string(dcx, remote_addr);
	duk_push_int(dcx, ntohs(peer->sin_port));
	if (duk_pnew(dcx, 2)) {
		js_log_error(dcx, -1);
		goto out_clean;
	}
	ctx.js_srv_idx = duk_get_top_index(dcx);

	/* Handle initial greeting */
	if (call_js_handler(&ctx, "INIT", 0, &rsp)) {
		smtp_server_response(&ctx.stream, &smtp_rsp_int_err);
		goto out_clean;
	}

	smtp_server_response(&ctx.stream, &rsp);
	free(rsp.message);

	if (smtp_server_get_disconnect(&ctx))
		goto out_clean;

	do {
		status = smtp_server_hdle_one(&ctx);
	} while (!status && !smtp_server_get_disconnect(&ctx));

	/* Give all modules the chance to clean up (possibly after a broken
	 * connection) */
	duk_push_string(dcx, "cleanup");
	if (!duk_pcall_prop(dcx, ctx.js_srv_idx, 0))
		js_log_error(dcx, -1);
	duk_pop(dcx);

out_clean:
	duk_pop(dcx); /* SmtpServer instance (or error) */
out_close:
	bfd_close(&ctx.stream);
	js_log(JS_LOG_INFO, "Closed connection to %s\n", remote_addr);
}

/**
 * @return 0 on failure, 1 on success
 *
 * Duktape stack:
 *	Input:	...
 *	Output:	...						[failure]
 *		... | Object					[success]
 *		Object is a SmtpPath instance
 */
static duk_bool_t smtp_path_parse_cmd(struct smtp_server_context *ctx, const char *arg, const char *word, char **trail)
{
	/* Look for passed-in word */
	arg += strspn(arg, white);
	if (strncasecmp(arg, word, strlen(word)))
		return 0;
	arg += strlen(word);

	/* Look for colon */
	arg += strspn(arg, white);
	if (*(arg++) != ':')
		return 0;

	/* Parse actual path */
	arg += strspn(arg, white);

	/* Create SmtpPath instance */
	if (!duk_get_global_string(ctx->dcx, "SmtpPath")) {
		duk_pop(ctx->dcx);
		return 0;
	}
	if (duk_pnew(ctx->dcx, 0)) {
		js_log_error(ctx->dcx, -1);
		duk_pop(ctx->dcx);
		return 0;
	}

	/* Invoke the parse() method */
	duk_push_string(ctx->dcx, "parse");
	duk_push_string(ctx->dcx, arg);
	if (duk_pcall_prop(ctx->dcx, -3, 1)) {
		js_log_error(ctx->dcx, -1);
		duk_pop_2(ctx->dcx);
		return 0;
	}

	if (duk_is_null(ctx->dcx, -1)) {
		duk_pop_2(ctx->dcx);
		return 0;
	}

	if (trail)
		*trail = strdup(duk_safe_to_string(ctx->dcx, -1));

	duk_pop(ctx->dcx);
	return 1;
}

// TODO fix auth handling
#if 0
int smtp_auth_login_parse_user(struct smtp_server_context *ctx, const char *arg)
{
	ctx->code = 334;
	if (arg) {
		ctx->auth_user = base64_dec(arg, strlen(arg), NULL);
		if (!ctx->auth_user) {
			ctx->code = 501;
			ctx->message = strdup("Cannot decode AUTH parameter");
			return 0;
		}
		ctx->message = base64_enc("Password:", strlen("Password:"));
	}
	else {
		ctx->message = base64_enc("Username:", strlen("Username:"));
	}
	return 0;
}

int smtp_auth_login_parse_pw(struct smtp_server_context *ctx, const char *arg)
{
	ctx->auth_pw = base64_dec(arg, strlen(arg), NULL);
	if (!ctx->auth_pw) {
		ctx->code = 501;
		ctx->message = strdup("Cannot decode AUTH parameter");
		return 0;
	}
	ctx->code = 250;
	return 0;
}

int smtp_auth_plain_parse(struct smtp_server_context *ctx, const char *arg)
{
	char *auth_info, *p;
	int len;

	/* Parse (user, pw) from arg = base64(\0username\0password) */
	if (arg) {
		auth_info = base64_dec(arg, strlen(arg), &len);
		if (!auth_info) {
			ctx->code = 501;
			ctx->message = strdup("Cannot decode AUTH parameter");
			return 0;
		}
		ctx->auth_user = strdup(auth_info + 1);
		p = auth_info + strlen(auth_info + 1) + 2;
		assert_mod_log(p - auth_info < len);
		ctx->auth_pw = strdup(p);
		free(auth_info);
		return 0;
	}

	/* Request the base64 encoded authentication string */
	ctx->code = 334;
	ctx->message = NULL;
	return 0;
}

int smtp_auth_unknown_parse(struct smtp_server_context *ctx, const char *arg)
{
	ctx->code = 504;
	ctx->message = strdup("AUTH mechanism not available");
	return 0;
}

int smtp_hdlr_auth(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	struct {
		const char *name;
		int (*parse)(struct smtp_server_context *ctx, const char *arg);
	} auth_types[] = {
		{ "LOGIN", smtp_auth_login_parse_user },
		{ "PLAIN", smtp_auth_plain_parse },
		{ NULL, NULL },
	};
	char *c, tmp;
	int i;

	if (ctx->auth_user) {
		ctx->code = 503;
		ctx->message = strdup("Already Authenticated");
		return 0;
	}

	c = strrchr(arg, ' ');
	if (c) {
		tmp = *c;
		*c = 0;
		ctx->auth_type = strdup(arg);
		*c = tmp;
		c++;
	}
	else {
		c = arg;
		c[strcspn(c, "\r\n")] = 0;
		ctx->auth_type = strdup(arg);
		c = NULL;
	}

	for (i = 0; auth_types[i].name; i++)
		if (!strcasecmp(ctx->auth_type, auth_types[i].name))
			return auth_types[i].parse(ctx, c);
	return smtp_auth_unknown_parse(ctx, c);
}

int smtp_hdlr_alou(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	assert_mod_log(!ctx->auth_user);

	if ((sz = bfd_read_line(ctx->stream, buf, SMTP_COMMAND_MAX)) < 0)
		return 0;
	buf[sz] = '\0';

	if (!strcmp(buf, "*\r\n")) {
		ctx->code = 501;
		ctx->message = strdup("AUTH aborted");
		return 0;
	}

	return smtp_auth_login_parse_user(ctx, buf);
}

int smtp_hdlr_alop(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	assert_mod_log(!ctx->auth_pw);

	if ((sz = bfd_read_line(ctx->stream, buf, SMTP_COMMAND_MAX)) < 0)
		return 1;
	buf[sz] = '\0';

	if (!strcmp(buf, "*\r\n")) {
		ctx->code = 501;
		ctx->message = strdup("AUTH aborted");
		return 0;
	}

	return smtp_auth_login_parse_pw(ctx, buf);
}

int smtp_hdlr_aplp(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	char buf[SMTP_COMMAND_MAX + 1];
	ssize_t sz;

	if (!ctx->auth_user) {
		if ((sz = bfd_read_line(ctx->stream, buf, SMTP_COMMAND_MAX)) < 0)
			return 0;
		buf[sz] = '\0';

		return smtp_auth_plain_parse(ctx, buf);
	}
	return 0;
}
#endif

/**
 * @return	0 on success;
 *		EINVAL on JS error;
 *		ENOMEM
 */
int smtp_hdlr_helo(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	size_t alen = strcspn(arg, white);
	const char *proto = "ESMTP";
	int status;

	if (*arg == '\0')
		return smtp_response_copy(rsp, &smtp_rsp_hostname_req);

	/* Call JS handler - note: arg is always consumed */
	duk_push_lstring(ctx->dcx, arg, alen);
	status = call_js_handler(ctx, cmd, 1, rsp);
	if (status || !smtp_successful(rsp))
		return status;

	/* Set <SmtpServer>.hostname */
	duk_push_lstring(ctx->dcx, arg, alen);
	duk_put_prop_string(ctx->dcx, ctx->js_srv_idx, PR_HOSTNAME);

	/* Note: cmd is "EHLO" when we are called by smtp_hdlr_ehlo() */
	if (strcasecmp(cmd, "EHLO"))
		proto++;

	/* Set <SmtpServer>.proto */
	duk_push_string(ctx->dcx, proto);
	duk_put_prop_string(ctx->dcx, ctx->js_srv_idx, PR_PROTO);

	/* Reset SMTP transaction state: RFC5321 - 4.1.1.1 */
	if (!js_init_envelope(ctx->dcx, ctx->js_srv_idx)) {
		free(rsp->message);
		return EINVAL;
	}

	return 0;
}

/**
 * @return	0 on success;
 *		EINVAL on JS error
 */
int smtp_hdlr_ehlo(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	char *src, *dst = NULL, *next;

	int status = smtp_hdlr_helo(ctx, cmd, arg, rsp);
	if (status || !smtp_successful(rsp))
		return status;

	/* filter SMTP extensions; see RFC 5321 - section 4.1.1.1 */
	src = rsp->message;
	do {
		char *param;
		struct esmtp_cap *cap;

		next = strchr(src, '\n');

		/* skip ehlo-greet */
		if (src == rsp->message) {
			src = dst = next;
			continue;
		}

		if (next)
			*next = '\0';

		param = strchr(src, ' ');
		if (param)
			*param++ = '\0';

		for (cap = &esmtp_cap_table[0]; cap->verb; cap++) {
			if (strcasecmp(src, cap->verb))
				continue;
			if (!cap->cb || cap->cb(cap->verb, param))
				break;
		}

		if (cap->verb) {
			*dst++ = '\n';
			strcpy(dst, cap->verb);
			dst += strlen(cap->verb);

			if (param) {
				*dst++ = ' ';
				strcpy(dst, param);
				dst += strlen(param);
			}
		}

		src = next;
	} while (src++);

	if (dst)
		*dst = '\0';

	return status;
}

/**
 * @return	0 on success;
 *		EINVAL on JS error;
 *		ENOMEM
 */
int smtp_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	int status;

	duk_get_prop_string(ctx->dcx, ctx->js_srv_idx, PR_SENDER);
	status = duk_is_null_or_undefined(ctx->dcx, -1);
	duk_pop(ctx->dcx);
	if (!status)
		return smtp_response_copy(rsp, &smtp_rsp_sndr_specified);

	if (!smtp_path_parse_cmd(ctx, arg, "FROM", NULL))
		return smtp_response_copy(rsp, &smtp_rsp_syntax_error);

	// FIXME check for trailing characters

	duk_dup_top(ctx->dcx);
	status = call_js_handler(ctx, cmd, 1, rsp);
	if (status || !smtp_successful(rsp)) {
		duk_pop(ctx->dcx);
		return status;
	}

	duk_put_prop_string(ctx->dcx, ctx->js_srv_idx, PR_SENDER);
	return 0;
}

/**
 * @return	0 on success;
 *		EINVAL on JS error;
 *		ENOMEM
 */
int smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	int status;

	duk_get_prop_string(ctx->dcx, ctx->js_srv_idx, PR_SENDER);
	status = duk_is_null_or_undefined(ctx->dcx, -1);
	duk_pop(ctx->dcx);
	if (status)
		return smtp_response_copy(rsp, &smtp_rsp_no_sndr);

	if (!smtp_path_parse_cmd(ctx, arg, "TO", NULL))
		return smtp_response_copy(rsp, &smtp_rsp_syntax_error);

	// FIXME check for trailing characters
	// FIXME check for null (or broken) recipient (e.g. "rcpt to:<>")
	// before calling JS handler

	duk_dup_top(ctx->dcx);
	status = call_js_handler(ctx, cmd, 1, rsp);
	if (status || !smtp_successful(rsp)) {
		duk_pop(ctx->dcx);
		return status;
	}

	if (!duk_get_prop_string(ctx->dcx, ctx->js_srv_idx, PR_RECIPIENTS)) {
		duk_pop_2(ctx->dcx);
		free(rsp->message);
		return EINVAL;
	}

	duk_insert(ctx->dcx, -2);
	if (!js_append_array_element(ctx->dcx, -2)) {
		duk_pop_2(ctx->dcx);
		free(rsp->message);
		return EINVAL;
	}

	duk_pop(ctx->dcx);
	return 0;
}

/**
 * @return	0 on success;
 *		EIO on socket error;
 *		EINVAL on JS error;
 *		ENOMEM
 */
int smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	duk_size_t len;
	char path[] = "/tmp/mailfilter.XXXXXX";
	int fd, status = EIO;
	bfd_t bstream;

	if (!duk_get_prop_string(ctx->dcx, ctx->js_srv_idx, PR_RECIPIENTS)) {
		duk_pop(ctx->dcx);
		return EINVAL;
	}

	if (!duk_is_array(ctx->dcx, -1)) {
		duk_pop(ctx->dcx);
		return EINVAL;
	}

	len = duk_get_length(ctx->dcx, -1);
	duk_pop(ctx->dcx);
	if (!len)
		return smtp_response_copy(rsp, &smtp_rsp_no_recipients);

	duk_push_array(ctx->dcx); // headers

	/* prepare temporary file to store message body */
	if ((fd = mkstemp(path)) == -1)
		return EINVAL;

	bfd_init(&bstream, fd);

	if (!smtp_server_response(&ctx->stream, &smtp_rsp_go_ahead))
		status = smtp_copy_to_file(ctx->dcx, &bstream, &ctx->stream);

	if (bfd_close(&bstream) && !status)
		status = EINVAL;

	switch (status) {
	case 0:
		break;
	case EIO:
		goto out_error;
	case EAGAIN:
	case EPROTO:
		status = smtp_response_copy(rsp, &smtp_rsp_invalid_hdrs);
		goto out_error;
	case EOVERFLOW:
		status = smtp_response_copy(rsp, &smtp_rsp_hdrs_too_big);
		goto out_error;
	default:
		status = smtp_response_copy(rsp, &smtp_rsp_no_space);
		goto out_error;
	}

	duk_push_string(ctx->dcx, path);
	status = call_js_handler(ctx, cmd, 2, rsp);
	goto out_clean;

out_error:
	/*
	 * At this point we have consumed the envelope (sender and
	 * recipients), but we have an error. Call the JS handler with
	 * NULL arguments to give the JS side a chance to clean up the
	 * transaction state (e.g. RSET the client connection).
	 */
	duk_pop(ctx->dcx); // headers
	duk_push_null(ctx->dcx);
	duk_push_null(ctx->dcx);
	call_js_handler(ctx, cmd, 2, NULL);

out_clean:
	if (!js_init_envelope(ctx->dcx, ctx->js_srv_idx)) {
		if (!status)
			free(rsp->message);
		if (status != EIO)
			status = EINVAL;
	}

	unlink(path);
	return status;
}

/**
 * @return	0 on success;
 *		EINVAL on JS error
 */
int smtp_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	int status = call_js_handler(ctx, cmd, 0, rsp);

	if (status || !smtp_successful(rsp))
		return status;

	if (!js_init_envelope(ctx->dcx, ctx->js_srv_idx)) {
		free(rsp->message);
		status = EINVAL;
	}

	return status;
}

/**
 * @return	0 on success;
 *		ENOMEM
 */
int smtp_hdlr_noop(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	return smtp_response_copy(rsp, &smtp_rsp_ok);
}

/**
 * @return	0 on success;
 *		ENOMEM
 */
int smtp_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	duk_push_true(ctx->dcx);
	duk_put_prop_string(ctx->dcx, ctx->js_srv_idx, PR_DISCONNECT);

	return smtp_response_copy(rsp, &smtp_rsp_bye);
}

#define SMTP_CMD_HDLR_INIT(name) {#name, smtp_hdlr_##name}

static struct smtp_cmd_hdlr smtp_cmd_table[] = {
#if 0
	SMTP_CMD_HDLR_INIT(auth),
#endif
	SMTP_CMD_HDLR_INIT(ehlo),
	SMTP_CMD_HDLR_INIT(helo),
	SMTP_CMD_HDLR_INIT(data),
	SMTP_CMD_HDLR_INIT(mail),
	SMTP_CMD_HDLR_INIT(rcpt),
	SMTP_CMD_HDLR_INIT(rset),
	SMTP_CMD_HDLR_INIT(noop),
	SMTP_CMD_HDLR_INIT(quit),
	{NULL, NULL}
};
