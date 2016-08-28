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
#include "js_main.h"
#include "internet_message.h"
#include "smtp_server.h"
#include "smtp.h"
#include "base64.h"

/**
 * SMTP server context.
 */
struct smtp_server_context {
	/* Client stream (buffered file descriptor) */
	bfd_t *stream;

	/* JavaScript instance of SmtpServer */
	JSObject *js_srv;

	/* Flag indicating whether the connection should be closed */
	int disconnect;

	/* Client identity specified in EHLO command */
	char *identity;

	/* Authentication details. NULL if no user authenticated */
	char *auth_user, *auth_pw, *auth_type;

	/* Envelope sender (aka reverse-path as per RFC821). .mailbox.local
	 * is NULL if "MAIL" was not issued. */
	struct smtp_path rpath;

	/* List of recipients (aka forward-path as per RFC821). Mailbox list
	 * is empty if "RCPT" was not issued. Elements are chained by the
	 * .mailbox.domain.lh component. */
	struct list_head fpath;

	struct list_head hdrs;

	/* Message body */
	struct {
		/* Path to tmp file or empty string if "DATA" was not issued */
		char path[PATH_MAX];

		/* Stream of tmp file or NULL if "DATA" was not issued */
		bfd_t *stream;

		/* Size of message body (without headers) */
		off_t size;
	} body;
};

struct smtp_response {
	/* SMTP status code to send back to client */
	int code;

	/* SMTP message to send back to client */
	char *message;
};

typedef enum {
	SMTP_SUCCESS,	/* Handler completed successfully */
	SMTP_COM_ERR,	/* I/O error on client socket; close session */
	SMTP_INT_ERR,	/* Internal error; reply 451 to client */
} smtp_status_t;

// FIXME
#define assert_log(...)
#define assert_mod_log(...)

//static uint64_t key;

/**
 * @brief SMTP command handler prototype
 */
typedef smtp_status_t (*smtp_cmd_hdlr_t)(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp);

/**
 * @brief SMTP command handler table element
 */
struct smtp_cmd_hdlr {
	const char *name;
	smtp_cmd_hdlr_t hdlr;
};

extern JSContext *js_context; // FIXME pass through arguments

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
DEF_SMTP_RSP(no_recipients,	503, "Must specify recipient(s) first");
DEF_SMTP_RSP(hdrs_too_big,	552, "Message header too long");

static inline int smtp_successful(const struct smtp_response *rsp)
{
	return rsp->code >= 200 && rsp->code < 400;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on error
 */
static smtp_status_t smtp_response_copy(struct smtp_response *dst, const struct smtp_response *src)
{
	dst->code = src->code;
	dst->message = strdup(src->message);
	return dst->message ? SMTP_SUCCESS : SMTP_INT_ERR;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_COM_ERR on socket error
 */
static smtp_status_t smtp_server_response(bfd_t *f, const struct smtp_response *rsp)
{
	static const int sz = 200;
	char buf[sz + 4];
	char *h, *t;

	strcpy(&buf[sz], "...");
	for (h = rsp->message; (t = strchr(h, '\n')); h = t + 1) {
		if (t - h < sz) {
			strncpy(buf, h, t - h);
			buf[t - h] = '\0';
		} else
			strncpy(buf, h, sz);
		JS_Log(JS_LOG_DEBUG, "<<< %d-%s\n", rsp->code, buf);

		bfd_printf(f, "%d-", rsp->code);
		bfd_write_full(f, h, t - h);
		bfd_printf(f, "\r\n");
	}

	JS_Log(JS_LOG_DEBUG, "<<< %d %s\n", rsp->code, h);
	if (bfd_printf(f, "%d %s\r\n", rsp->code, h) >= 0) {
		bfd_flush(f);
		return SMTP_SUCCESS;
	}

	return SMTP_COM_ERR;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_COM_ERR on socket error
 */
static int smtp_server_handle_cmd(struct smtp_server_context *ctx, const char *cmd, const char *arg)
{
	int idx;
	smtp_status_t status;
	struct smtp_response rsp;

	for (idx = 0; smtp_cmd_table[idx].name; idx++)
		if (!strcasecmp(smtp_cmd_table[idx].name, cmd))
			break;

	if (!smtp_cmd_table[idx].hdlr)
		return smtp_server_response(ctx->stream, &smtp_rsp_not_impl);

	status = smtp_cmd_table[idx].hdlr(ctx, cmd, arg, &rsp);
	if (status == SMTP_COM_ERR)
		return status;
	if (status == SMTP_INT_ERR)
		return smtp_server_response(ctx->stream, &smtp_rsp_int_err);

	status = smtp_server_response(ctx->stream, &rsp);
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
 *		-1: socket read error.
 */
static int smtp_server_read_line(bfd_t *stream, char *buf, size_t *size)
{
	ssize_t len;
	int writes = 0;

	if (!stream || !buf || !size || *size < 2)
		return -EINVAL;

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
 * @return	SMTP_SUCCESS on success;
 *		SMTP_COM_ERR on socket error
 */
static smtp_status_t smtp_server_read_and_handle(struct smtp_server_context *ctx)
{
	char buf[SMTP_COMMAND_MAX];
	size_t n = sizeof(buf);
	char *c = &buf[0];
	int status;

	status = smtp_server_read_line(ctx->stream, buf, &n);

	if (status < 0) {
		JS_Log(JS_LOG_ERR, "Socket read error (%s)\n", strerror(errno));
		return SMTP_COM_ERR;
	}

	if (!status) {
		JS_Log(JS_LOG_ERR, "Lost connection to client\n");
		errno = ECONNABORTED;
		return SMTP_COM_ERR;
	}

	/* Log received command */
	JS_Log(JS_LOG_DEBUG, ">>> %s\n", &buf[0]);

	/* reject oversized commands */
	if (status > 1)
		return smtp_server_response(ctx->stream, &smtp_rsp_cmd_too_long);

	if (!n)
		return smtp_server_response(ctx->stream, &smtp_rsp_bad_syntax);

	/* Parse SMTP command */
	c += strspn(c, white);
	if (*c == '\0')
		return smtp_server_response(ctx->stream, &smtp_rsp_bad_syntax);

	n = strcspn(c, white);

	/* Prepare argument */
	if (c[n] != '\0') {
		c[n++] = '\0';
		n += strspn(c + n, white);
	}

	return smtp_server_handle_cmd(ctx, c, c + n);
}

static int smtp_copy_to_file(bfd_t *out, bfd_t *in, struct im_header_context *im_hdr_ctx)
{
	const uint64_t DOTLINE_MAGIC	= 0x0d0a2e0000;	/* <CR><LF>"."<*> */
	const uint64_t DOTLINE_MASK	= 0xffffff0000;
	const uint64_t CRLF_MAGIC	= 0x0000000d0a; /* <CR><LF> */
	const uint64_t CRLF_MASK	= 0x000000ffff;
	uint64_t buf = 0;
	int fill = 0;
	int im_state = IM_OK;
	int c;

	while ((c = bfd_getc(in)) >= 0) {
		if (im_state == IM_OK) {
			im_state = im_header_feed(im_hdr_ctx, c);
			continue;
		}
		if (++fill > 8) {
			if (bfd_putc(out, buf >> 56) < 0)
				return -EIO;
			fill = 8;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if ((buf & CRLF_MASK) == CRLF_MAGIC) {
			/* we found the EOF sequence (<CR><LF>"."<CR><LF>) */
			assert_log(fill >= 5, &config);
			/* discard the (terminating) "."<CR><LF> */
			buf >>= 24;
			fill -= 3;
			break;
		}
		/* flush buffer up to the dot; otherwise we get false-positives for
		 * a line consisting of (only) two dots */
		assert_log(fill >= 5, &config);
		while (fill > 3)
			if (bfd_putc(out, (buf >> (--fill * 8)) & 0xff) < 0)
				return -EIO;
		buf &= CRLF_MASK;
		fill = 2;
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8)
		if (bfd_putc(out, (buf >> fill) & 0xff) < 0)
			return -EIO;

	return im_state == IM_OK || im_state == IM_COMPLETE ? 0 : im_state;
}

void smtp_path_init(struct smtp_path *path)
{
	memset(path, 0, sizeof(struct smtp_path));
	INIT_LIST_HEAD(&path->domains);
	INIT_LIST_HEAD(&path->mailbox.domain.lh);
}

void smtp_path_cleanup(struct smtp_path *path)
{
	// TODO remove when everything is ported to JS
#if 0
	struct smtp_domain *pos, *n;

	if (path->mailbox.local != NULL && path->mailbox.local != EMPTY_STRING)
		free(path->mailbox.local);
	if (path->mailbox.domain.domain != NULL)
		free(path->mailbox.domain.domain);
	list_for_each_entry_safe(pos, n, &path->domains, lh) {
		free(pos->domain);
		free(pos);
	}
#endif
}

void smtp_server_context_init(struct smtp_server_context *ctx)
{
	memset(ctx, 0, sizeof(struct smtp_server_context));
	smtp_path_init(&ctx->rpath);
	INIT_LIST_HEAD(&ctx->fpath);
	INIT_LIST_HEAD(&ctx->hdrs);
}

/**
 * Free resources and prepare for another SMTP transaction.
 *
 * This function is not only used at the end of the SMTP session, but
 * also by the default RSET handler.
 *
 * Besides closing all resources, this also leaves the context ready for
 * another SMTP session.
 */
void smtp_server_context_cleanup(struct smtp_server_context *ctx)
{
	struct smtp_path *path, *path_aux;
	struct im_header *hdr, *hdr_aux;

	smtp_path_cleanup(&ctx->rpath);
	smtp_path_init(&ctx->rpath);

	list_for_each_entry_safe(path, path_aux, &ctx->fpath, mailbox.domain.lh) {
		smtp_path_cleanup(path);
		free(path);
	}
	INIT_LIST_HEAD(&ctx->fpath);

	list_for_each_entry_safe(hdr, hdr_aux, &ctx->hdrs, lh) {
		im_header_free(hdr);
	}
	INIT_LIST_HEAD(&ctx->hdrs);

	if (ctx->body.stream != NULL)
		bfd_close(ctx->body.stream);
	ctx->body.stream = NULL;

	if (ctx->body.path[0] != '\0')
		unlink(ctx->body.path);
	ctx->body.path[0] = '\0';
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on error
 */
static smtp_status_t call_js_handler(struct smtp_server_context *ctx, const char *cmd, unsigned argc, jsval *argv, struct smtp_response *rsp)
{
	char handler_name[10] = "smtp";
	int i;
	jsval v = JSVAL_NULL, rval;
	uint32_t len;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;

	for (i = 4; i < sizeof(handler_name) - 1 && *cmd; i++)
		handler_name[i] = tolower(*(cmd++));
	handler_name[4] = toupper(handler_name[4]);
	handler_name[i] = '\0';

	/* Call the given function */
	if (!JS_CallFunctionName(js_context, ctx->js_srv, handler_name,
				argc, argv, &rval)) {
		JS_Log(JS_LOG_ERR, "failed calling '%s'", handler_name);
		return SMTP_INT_ERR;
	}

	/* Sanity check on return type */
	if (JS_TypeOfValue(js_context, rval) != JSTYPE_OBJECT) {
		JS_Log(JS_LOG_ERR, "handler '%s' invalid rval", handler_name);
		return SMTP_INT_ERR;
	}

	/* Extract "disconnect" field */
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(rval), "disconnect", &v))
		return SMTP_INT_ERR;
	ctx->disconnect = JSVAL_TO_BOOLEAN(v);

	if (!rsp)
		return SMTP_SUCCESS;

	/* Extract "code" field */
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(rval), "code", &v))
		return SMTP_INT_ERR;
	rsp->code = JSVAL_TO_INT(v);

	/* Extract "messages" field */

	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(rval), "messages", &v))
		return SMTP_INT_ERR;

	if (JS_TypeOfValue(js_context, v) == JSTYPE_STRING) {
		JSString *js_str = JSVAL_TO_STRING(v);
		rsp->message = JS_EncodeStringLoose(js_context, js_str);
		return rsp->message ? SMTP_SUCCESS : SMTP_INT_ERR;
	}

	/* Sanity checks for array object */

	if (JS_TypeOfValue(js_context, v) != JSTYPE_OBJECT)
		return SMTP_INT_ERR;

	if (!JS_IsArrayObject(js_context, JSVAL_TO_OBJECT(v)))
		return SMTP_INT_ERR;

	if (!JS_GetArrayLength(js_context, JSVAL_TO_OBJECT(v), &len))
		return SMTP_INT_ERR;

	/* Extract array elements and append to string buffer */

	for (i = 0; i < (int)len; i++) {
		jsval msg;
		char *c_str;
		JSString *js_str;

		if (!JS_GetElement(js_context, JSVAL_TO_OBJECT(v), i, &msg))
			continue;

		js_str = JSVAL_TO_STRING(msg);
		if (!js_str)
			continue;

		c_str = JS_EncodeString(js_context, js_str);
		if (!c_str)
			continue;

		if (sb.cur && string_buffer_append_char(&sb, '\n')) {
			JS_free(js_context, c_str);
			break;
		}

		if (string_buffer_append_string(&sb, c_str)) {
			JS_free(js_context, c_str);
			break;
		}

		JS_free(js_context, c_str);
	}

	if (sb.cur) {
		rsp->message = sb.s;
		return SMTP_SUCCESS;
	}

	string_buffer_cleanup(&sb);
	return SMTP_INT_ERR;
}

void smtp_server_main(int client_sock_fd, const struct sockaddr_in *peer)
{
	int status;
	char *remote_addr = NULL;
	jsval v;
	struct smtp_server_context ctx;
	struct smtp_response rsp;

	smtp_server_context_init(&ctx);
	remote_addr = inet_ntoa(peer->sin_addr);
	ctx.stream = bfd_alloc(client_sock_fd); // FIXME check if successful
	JS_Log(JS_LOG_INFO, "New connection from %s\n", remote_addr);

	/* Create SmtpServer instance */
	if (!JS_GetProperty(js_context, JS_GetGlobalForScopeChain(js_context), "SmtpServer", &v))
		goto out_clean;
	ctx.js_srv = JS_New(js_context, JSVAL_TO_OBJECT(v), 0, NULL);
	if (!ctx.js_srv)
		goto out_clean;
	JS_AddObjectRoot(js_context, &ctx.js_srv);

	/* Handle initial greeting */
	if (call_js_handler(&ctx, "INIT", 0, NULL, &rsp)) {
		smtp_server_response(ctx.stream, &smtp_rsp_int_err);
		goto out_clean;
	}

	smtp_server_response(ctx.stream, &rsp);
	free(rsp.message);

	if (ctx.disconnect)
		goto out_clean;

	do {
		status = smtp_server_read_and_handle(&ctx);
	} while (!status && !ctx.disconnect);

	/* Give all modules the chance to clean up (possibly after a broken
	 * connection */
	call_js_handler(&ctx, "CLNP", 0, NULL, NULL);

	smtp_server_context_cleanup(&ctx);

out_clean:
	JS_RemoveObjectRoot(js_context, &ctx.js_srv);
	bfd_close(ctx.stream);
	JS_Log(JS_LOG_INFO, "Closed connection to %s\n", remote_addr);
}

static JSObject *smtp_path_parse_cmd(const char *arg, const char *word, char **trail)
{
	jsval v, rval;
	JSObject *path;
	JSString *str;

	/* Look for passed-in word */
	arg += strspn(arg, white);
	if (strncasecmp(arg, word, strlen(word)))
		return NULL;
	arg += strlen(word);

	/* Look for colon */
	arg += strspn(arg, white);
	if (*(arg++) != ':')
		return NULL;

	/* Parse actual path */
	arg += strspn(arg, white);

	if (!JS_GetProperty(js_context, JS_GetGlobalForScopeChain(js_context), "SmtpPath", &v))
		return NULL;
	path = JS_New(js_context, JSVAL_TO_OBJECT(v), 0, NULL);

	str = JS_NewStringCopyZ(js_context, arg);
	if (!str)
		return NULL;

	v = STRING_TO_JSVAL(str);
	if (!JS_CallFunctionName(js_context, path, "parse", 1, &v, &rval))
		return NULL;

	if (JSVAL_IS_NULL(rval))
		return NULL;

	if (!trail)
		return path;

	*trail = NULL;
	if (!JS_GetProperty(js_context, JSVAL_TO_OBJECT(rval), "trail", &v))
		return path;

	str = JSVAL_TO_STRING(v);
	if (str)
		*trail = JS_EncodeStringLoose(js_context, str);

	return path;
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
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_helo(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	JSString *hostname;
	smtp_status_t status;
	jsval js_arg;

	if (*arg == '\0')
		return smtp_response_copy(rsp, &smtp_rsp_hostname_req);

	hostname = JS_NewStringCopyN(js_context, arg, strcspn(arg, white));
	if (!hostname)
		return SMTP_INT_ERR;

	js_arg = STRING_TO_JSVAL(hostname);
	status = call_js_handler(ctx, cmd, 1, &js_arg, rsp);
	if (status != SMTP_SUCCESS || !smtp_successful(rsp))
		return status;

	if (!JS_DefineProperty(js_context, ctx->js_srv, "hostname", js_arg, NULL, NULL, JSPROP_ENUMERATE))
		return SMTP_INT_ERR;

	// FIXME reset SMTP transaction state (clear envelope sender, etc.)

	return SMTP_SUCCESS;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_ehlo(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	smtp_status_t status = smtp_hdlr_helo(ctx, cmd, arg, rsp);
	if (status != SMTP_SUCCESS)
		return status;

	// FIXME validate/filter ESMTP capabilities before returning
	return status;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_mail(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	jsval v;
	JSBool jstat;
	JSObject *path;
	smtp_status_t status;

	jstat = JS_GetProperty(js_context, ctx->js_srv, "envelopeSender", &v);
	if (jstat && !JSVAL_IS_NULL(v))
		return smtp_response_copy(rsp, &smtp_rsp_sndr_specified);

	path = smtp_path_parse_cmd(arg, "FROM", NULL);
	// FIXME check for trailing characters
	if (!path)
		return smtp_response_copy(rsp, &smtp_rsp_syntax_error);

	v = OBJECT_TO_JSVAL(path);
	status = call_js_handler(ctx, cmd, 1, &v, rsp);
	if (status != SMTP_SUCCESS || !smtp_successful(rsp))
		return status;

	if (!JS_DefineProperty(js_context, ctx->js_srv, "envelopeSender", v, NULL, NULL, JSPROP_ENUMERATE))
		return SMTP_INT_ERR;

	return SMTP_SUCCESS;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_rcpt(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
#if 0
	struct smtp_path *path;

	path = malloc(sizeof(struct smtp_path));
	if (path == NULL)
		return SMTP_INT_ERR;
	smtp_path_init(path);

	jsval smtpPath = smtp_path_parse_cmd(arg, "TO");

	if (JSVAL_IS_NULL(smtpPath)) {
		free(path);
		return smtp_response_copy(rsp, &smtp_rsp_syntax_error);
	}

	add_recipient(&smtpPath);
	list_add_tail(&path->mailbox.domain.lh, &ctx->fpath);
#endif
	return call_js_handler(ctx, cmd, 0, NULL, rsp);
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_COM_ERR on socket error;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_data(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	int fd;

	// TODO verificare existenta envelope sender si recipienti; salvare mail in temporar; copiere path temp in smtp_server_context
	if (list_empty(&ctx->fpath))
		return smtp_response_copy(rsp, &smtp_rsp_no_recipients);

	/* prepare temporary file to store message body */
	sprintf(ctx->body.path, "/tmp/mailfilter.XXXXXX"); // FIXME sNprintf; cale in loc de /tmp;
	if ((fd = mkstemp(ctx->body.path)) == -1) {
		ctx->body.path[0] = '\0';
		return SMTP_INT_ERR;
	}

	if ((ctx->body.stream = bfd_alloc(fd)) == NULL) {
		close(fd);
		unlink(ctx->body.path);
		ctx->body.path[0] = '\0';
		return SMTP_INT_ERR;
	}

	/* prepare response */
	if (smtp_server_response(ctx->stream, &smtp_rsp_go_ahead))
		return SMTP_COM_ERR;

	// Parse the BODY content of DATA
	struct im_header_context im_hdr_ctx = IM_HEADER_CONTEXT_INITIALIZER;
	struct stat stat;

	assert_mod_log(ctx->body.stream != NULL);

	im_hdr_ctx.max_size = 65536; // FIXME use proper value
	im_hdr_ctx.hdrs = &ctx->hdrs;
	//sleep(10);
	switch (smtp_copy_to_file(ctx->body.stream, ctx->stream, &im_hdr_ctx)) {
		case 0:
			break;
		case IM_PARSE_ERROR:
			return smtp_response_copy(rsp, &smtp_rsp_invalid_hdrs);
		case IM_OVERRUN:
			return smtp_response_copy(rsp, &smtp_rsp_hdrs_too_big);
		default:
			return smtp_response_copy(rsp, &smtp_rsp_no_space);
	}

	// Add the file bfd stream to smtpClient.bodyStream
	if (add_body_stream(ctx->body.stream))
		return SMTP_INT_ERR;

	if (bfd_flush(ctx->body.stream) || fstat(ctx->body.stream->fd, &stat) == -1)
		return smtp_response_copy(rsp, &smtp_rsp_no_space);
	ctx->body.size = stat.st_size;

	//printf("path: %s\n", ctx->body.path); sleep(10);
	//im_header_write(&ctx->hdrs, stdout);

	return call_js_handler(ctx, cmd, 0, NULL, rsp);
}

static struct im_header *create_received_hdr(struct smtp_server_context *ctx)
{
	char *remote_addr = "10.0.0.1"; // FIXME inet_ntoa(ctx->addr.sin_addr);
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[32];
	char remote_host[NI_MAXHOST];
	char my_hostname[HOST_NAME_MAX];
	int rev = 0;
	//char *rcpt;
	struct im_header *hdr = im_header_alloc("Received");

	if (hdr == NULL)
		return NULL;

#if 0
	if (!getnameinfo((struct sockaddr *)&ctx->addr, sizeof(ctx->addr), remote_host, sizeof(remote_host), NULL, 0, 0))
		rev = strcmp(remote_host, remote_addr);
#endif
	gethostname(my_hostname, sizeof(my_hostname));
	strftime(ts, sizeof(ts), "%a, %d %b %Y %H:%M:%S %z", tm);
	//rcpt = smtp_path_to_string(list_entry(ctx->fpath.prev, struct smtp_path, mailbox.domain.lh));
	asprintf(&hdr->value,
			"from %s (%s%s[%s]) by %s (8.14.2/8.14.2) with SMTP id %s; %s",
			ctx->identity ? ctx->identity: (rev ? remote_host : remote_addr),
			rev ? remote_host : "", rev ? " " : "",
			remote_addr, my_hostname, "abcdef123456", ts);
	//free(rcpt);

	return hdr;
}

/*
 * Generate an additional "Received" header
 */
int insert_received_hdr(struct smtp_server_context *ctx)
{
	struct im_header *hdr;
	struct list_head *lh = ctx->hdrs.next;

	hdr = im_header_find(ctx, "received");
	if (hdr)
		lh = &hdr->lh;

	if ((hdr = create_received_hdr(ctx)) == NULL)
		return -ENOMEM;

	im_header_refold(hdr, 78);
	list_add_tail(&hdr->lh, lh);
	return 0;
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_quit(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	ctx->disconnect = 1;

	if (!JS_DefineProperty(js_context, ctx->js_srv, "quitAsserted", BOOLEAN_TO_JSVAL(JS_TRUE), NULL, NULL, JSPROP_ENUMERATE))
		JS_Log(JS_LOG_WARNING, "failed to set quitAsserted\n");

	return smtp_response_copy(rsp, &smtp_rsp_bye);
}

/**
 * @return	SMTP_SUCCESS on success;
 *		SMTP_INT_ERR on JS error
 */
smtp_status_t smtp_hdlr_rset(struct smtp_server_context *ctx, const char *cmd, const char *arg, struct smtp_response *rsp)
{
	// FIXME cleanup envelope sender, recipients, etc
	smtp_server_context_cleanup(ctx);
	return call_js_handler(ctx, cmd, 0, NULL, rsp);
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
	SMTP_CMD_HDLR_INIT(quit),
	{NULL, NULL}
};
