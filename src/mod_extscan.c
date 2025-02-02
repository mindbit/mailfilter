/* SPDX-License-Identifier: GPLv2 */

/*
 * Interface to external scanners using TCP sockets. Currently Apache
 * SpamAssassin and ClamAV are supported.
 *
 * There are some advantages to connecting directly to the external
 * scanners instead of running the dedicated clients (e.g. spamc and
 * clamdscan) as child processes:
 *  - Avoid the overhead of running an external program and copying the
 *    message again from stdin to the scanner socket.
 *  - Direct access to the scanner protocol provides more flexibility.
 */

#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "mailfilter.h"
#include "js_smtp.h"
#include "js_sys.h"

#define SPAMD_MAX_RESPONSE_SIZE 16384

struct extscan_context {
	duk_context *dcx;
	const char *host;
	int port;
	const char *user;
	int max_message_len;
	struct string_buffer hdr;
	bfd_t *body_stream;
	bfd_t *sock_stream;
	size_t message_size;
	char *rbuf;
};

struct extscan_field {
	const char *name;
	char type;
};

#define EXTSCAN_CONTEXT_INITIALIZER(ctx) {					\
	.dcx = ctx,								\
	.hdr = STRING_BUFFER_INITIALIZER,					\
}

static void extscan_context_cleanup(struct extscan_context *ecx)
{
	free(ecx->rbuf);
	string_buffer_cleanup(&ecx->hdr);
	bfd_free(ecx->body_stream);
	bfd_free(ecx->sock_stream);
}

#define extscan_ret_errno(ecx, err) ({						\
	typeof(err) _err = (err);						\
	extscan_context_cleanup(ecx);						\
	js_ret_errno((ecx)->dcx, _err);						\
})

enum extscan_flags {
	FL_USER = 1,
};

static void extscan_construct(duk_context *ctx, int default_port, enum extscan_flags fl)
{
	duk_push_this(ctx);

	// Add host
	duk_dup(ctx, 0);
	duk_to_string(ctx, -1);
	duk_put_prop_string(ctx, -2, "host");

	// Add port
	if (duk_is_undefined(ctx, 1))
		duk_push_int(ctx, default_port);
	else {
		duk_dup(ctx, 1);
		duk_to_int(ctx, -1);
	}
	duk_put_prop_string(ctx, -2, "port");

	// Add user
	if ((fl && FL_USER)) {
		if (duk_is_undefined(ctx, 2))
			js_sys_get_prop(ctx, "user");
		else {
			duk_dup(ctx, 2);
			duk_to_string(ctx, -1);
		}
		duk_put_prop_string(ctx, -2, "user");
	}

	duk_pop(ctx);
}

static void extscan_get_props(struct extscan_context *ecx, enum extscan_flags fl)
{
	duk_idx_t this;

	duk_push_this(ecx->dcx);
	this = duk_normalize_index(ecx->dcx, -1);

	// Get host
	duk_get_prop_string(ecx->dcx, this, "host");
	ecx->host = duk_get_string(ecx->dcx, -1);
	if (!ecx->host)
		js_report_error(ecx->dcx, "Invalid host");

	// Get port
	duk_get_prop_string(ecx->dcx, this, "port");
	ecx->port = duk_get_int(ecx->dcx, -1);
	if (!ecx->port)
		js_report_error(ecx->dcx, "Invalid port");

	// Get user
	if ((fl & FL_USER)) {
		duk_get_prop_string(ecx->dcx, this, "user");
		ecx->user = duk_get_string(ecx->dcx, -1);
		if (!ecx->user)
			js_report_error(ecx->dcx, "Invalid user");
	}

	// Get max message length; the property is defined in the prototype
	// but allow individual objects to override it
	duk_get_prop_string(ecx->dcx, this, "MAX_MESSAGE_LEN");
	ecx->max_message_len = duk_get_int(ecx->dcx, -1);
}

static int extscan_prepare(struct extscan_context *ecx)
{
	int err;
	struct stat body_stat;

	// Extract headers and append to string buffer. We cannot use
	// smtp_copy_from_file() because we need to calculate the total
	// header size to send the correct Content-length value to spamd.
	if ((err = smtp_headers_to_string(ecx->dcx, &ecx->hdr, 0)))
		return extscan_ret_errno(ecx, err);

	// Prepare message body stream
	if (!(ecx->body_stream = smtp_body_open_read(ecx->dcx, 1)))
		return extscan_ret_errno(ecx, ENOMEM);

	if (fstat(bfd_get_fd(ecx->body_stream), &body_stat))
		return extscan_ret_errno(ecx, errno);

	ecx->message_size = ecx->hdr.cur + body_stat.st_size;

	return ecx->message_size > ecx->max_message_len;
}

static int extscan_connect(struct extscan_context *ecx)
{
	int sockfd;

	sockfd = connect_to_address(ecx->dcx, ecx->host, ecx->port);
	if (sockfd < 0)
		return extscan_ret_errno(ecx, -sockfd);

	ecx->sock_stream = bfd_alloc(sockfd);
	if (!ecx->sock_stream) {
		close(sockfd);
		return extscan_ret_errno(ecx, ENOMEM);
	}

	return 0;
}

static int extscan_send_hdr_body(struct extscan_context *ecx)
{
	int err;

	if ((err = bfd_puts(ecx->sock_stream, ecx->hdr.s)))
		return extscan_ret_errno(ecx, err);

	if ((err = bfd_copy(ecx->body_stream, ecx->sock_stream)))
		return extscan_ret_errno(ecx, err);

	if ((err = bfd_flush(ecx->sock_stream)))
		return extscan_ret_errno(ecx, err);

	return 0;
}

static int extscan_parse_fields(struct extscan_context *ecx, char *buf, char delim,
				const struct extscan_field *fields)
{
	int i;

	for (i = 0; fields[i].name; i++) {
		char *p = strchr(buf, delim);
		int d;
		double f;

		if (!p)
			return extscan_ret_errno(ecx, EPROTO);
		*p = '\0';
		switch (fields[i].type) {
		case 's':
			duk_push_string(ecx->dcx, buf);
			break;
		case 'd':
			if (sscanf(buf, "%d", &d) != 1)
				return extscan_ret_errno(ecx, EPROTO);
			duk_push_int(ecx->dcx, d);
			break;
		case 'f':
			if (sscanf(buf, "%lf", &f) != 1)
				return extscan_ret_errno(ecx, EPROTO);
			duk_push_number(ecx->dcx, f);
			break;
		}
		duk_put_prop_string(ecx->dcx, -2, fields[i].name);
		buf = p + 1;
	}

	return 0;
}

/* {{{ SpamAssassin */

/*
 * Interface to the Apache SpamAssassin spam filter
 *
 * The spamd protocol is similar to HTTP and described in spamd/PROTOCOL
 * in the SpamAssassin source code. The assumption is that spamd responds
 * with the report format defined in extras/spamassassin_user_prefs. This
 * file should be installed as ~/.spamassassin/user_prefs in the home
 * directory of the user that Mailfilter runs as. The list of supported
 * report tags can be found in lib/Mail/SpamAssassin/PerMsgStatus.pm, and
 * the tags are documented in lib/Mail/SpamAssassin/Conf.pm in the
 * SpamAssassin source code.
 */

static int SpamAssassin_construct(duk_context *ctx)
{
	extscan_construct(ctx, 783, FL_USER);
	return 0;
}

static int SpamAssassin_scan(duk_context *ctx)
{
	struct extscan_context ecx = EXTSCAN_CONTEXT_INITIALIZER(ctx);
	int err, len, clen = 0, i;
	bool spam = false;
	double score = 0, required = 0;
	const struct extscan_field fields[] = {
		{"hostname",		's'},
		{"version",		's'},
		{"subversion",		's'},
		{"rulesversion",	's'},
		{"bayes",		'f'},
		{"testsscores",		's'},
		{ /* sentinel */ }
	};

	extscan_get_props(&ecx, FL_USER);

	if (extscan_prepare(&ecx)) {
		duk_push_null(ctx);
		extscan_context_cleanup(&ecx);
		return 1;
	}

	// Prepare connection to spamd
	extscan_connect(&ecx);

	// Send request line and headers to spamd
	if ((err = bfd_printf(ecx.sock_stream,
		"REPORT SPAMC/1.5\r\n"
		"User: %s\r\n"
		"Content-length: %zu\r\n"
		"\r\n",
		ecx.user, ecx.message_size)))
		return extscan_ret_errno(&ecx, err);

	// Send message headers and body to spamd
	extscan_send_hdr_body(&ecx);

	// Read and parse status line and headers from spamd
	for (i = 0;; i++) {
		char hdr[50], scr[sizeof(hdr)];

		if ((len = bfd_read_line(ecx.sock_stream, hdr, sizeof(hdr))) < 0)
			return extscan_ret_errno(&ecx, len ? -len : EIO);

		if (len < 2 || strncmp(&hdr[len - 2], "\r\n", 2))
			return extscan_ret_errno(&ecx, EPROTO);

		hdr[len -= 2] = '\0';
		if (!len)
			break;

		if (!i) {
			if (sscanf(hdr, "SPAMD/%[0-9.] %d %s", scr, (int *)scr, scr) != 3 ||
			    strcmp(scr, "EX_OK"))
				return extscan_ret_errno(&ecx, EPROTO);
			continue;
		}

		if (sscanf(hdr, "Content-length: %d", &clen) == 1)
			continue;

		if (sscanf(hdr, "Spam: %s ; %lf / %lf", scr, &score, &required) == 3) {
			if (strcmp(scr, "True") == 0)
				spam = true;
			else if (strcmp(scr, "False") != 0)
				return extscan_ret_errno(&ecx, EPROTO);
		}
	}

	if (!clen || clen >= SPAMD_MAX_RESPONSE_SIZE)
		return extscan_ret_errno(&ecx, EPROTO);

	ecx.rbuf = malloc(clen + 1);
	if (!ecx.rbuf)
		return extscan_ret_errno(&ecx, ENOMEM);

	// Read and parse response from spamd
	if ((err = bfd_read_full(ecx.sock_stream, ecx.rbuf, clen)))
		return extscan_ret_errno(&ecx, err);
	ecx.rbuf[clen] = '\0';

	duk_push_object(ctx);
	duk_push_boolean(ctx, spam);
	duk_put_prop_string(ctx, -2, "spam");
	duk_push_number(ctx, score);
	duk_put_prop_string(ctx, -2, "score");
	duk_push_number(ctx, required);
	duk_put_prop_string(ctx, -2, "required");
	extscan_parse_fields(&ecx, ecx.rbuf, '\n', fields);

	extscan_context_cleanup(&ecx);
	return 1;
}

static const duk_number_list_entry SpamAssassin_props[] = {
	{"MAX_MESSAGE_LEN",	2 * 1024 * 1024},
	{NULL,			0.0}
};


static const duk_function_list_entry SpamAssassin_functions[] = {
	{"scan",		SpamAssassin_scan,		2},
	{NULL,			NULL,				0}
};

/* }}} SpamAssassin */

duk_bool_t mod_extscan_init(duk_context *ctx)
{
	duk_push_c_function(ctx, SpamAssassin_construct, 3);
	duk_push_object(ctx);
	duk_put_number_list(ctx, -1, SpamAssassin_props);
	duk_put_function_list(ctx, -1, SpamAssassin_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SpamAssassin");

	return 1;
}

// vim: foldmethod=marker
