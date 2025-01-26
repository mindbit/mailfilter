/* SPDX-License-Identifier: GPLv2 */

/*
 * Interface to the Apache SpamAssassin spam filter
 *
 * The implementation in this module connects directly to spamd over a
 * TCP socket and does not use spamc. There are some advantages:
 *  - Avoid the overhead of running an external program and copying the
 *    message again from stdin to the spamd socket inside spamc.
 *  - Avoid parsing the response twice (here and inside spamc).
 *  - Direct access to the spamd protocol headers.
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

#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "mailfilter.h"
#include "js_smtp.h"
#include "js_sys.h"

#define SPAMD_MAX_RESPONSE_SIZE 16384

/* {{{ SpamAssassin */

static int SpamAssassin_construct(duk_context *ctx)
{
	duk_push_this(ctx);

	// Add host
	duk_dup(ctx, 0);
	duk_to_string(ctx, -1);
	duk_put_prop_string(ctx, -2, "host");

	// Add port
	if (duk_is_undefined(ctx, 1))
		duk_push_int(ctx, 783);
	else {
		duk_dup(ctx, 1);
		duk_to_int(ctx, -1);
	}
	duk_put_prop_string(ctx, -2, "port");

	// Add user
	if (duk_is_undefined(ctx, 2))
		js_sys_get_prop(ctx, "user");
	else {
		duk_dup(ctx, 2);
		duk_to_string(ctx, -1);
	}
	duk_put_prop_string(ctx, -2, "user");

	duk_pop(ctx);

	return 0;
}

static int SpamAssassin_scan(duk_context *ctx)
{
	const char *host, *user;
	int port, err, sockfd = -1, len, clen = 0, i;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	bfd_t *body_stream, *sock_stream = NULL;
	struct stat body_stat;
	bool spam = false;
	double score = 0, required = 0;
	char *buf = NULL, *tok;
	const struct {
		const char *name;
		char type;
	} fields[] = {
		{"hostname",		's'},
		{"version",		's'},
		{"subversion",		's'},
		{"rulesversion",	's'},
		{"bayes",		'f'},
		{"testsscores",		's'},
	};


	duk_push_this(ctx);

	// Get host
	duk_get_prop_string(ctx, -1, "host");
	host = duk_get_string(ctx, -1);

	// Get port
	duk_get_prop_string(ctx, -2, "port");
	port = duk_get_int(ctx, -1);

	// Get user
	duk_get_prop_string(ctx, -3, "user");
	user = duk_get_string(ctx, -1);

	if (!host || !port)
		return js_ret_error(ctx, "Invalid host or port %s:%d", host, port);

	// Extract headers and append to string buffer. We cannot use
	// smtp_copy_from_file() because we need to calculate the total
	// header size to send the correct Content-length value to spamd.
	if ((err = smtp_headers_to_string(ctx, &sb, 0)))
		return js_ret_errno(ctx, err);

	// Prepare message body stream
	body_stream = smtp_body_open_read(ctx, 1);
	if (!body_stream) {
		err = ENOMEM;
		goto out_clean;
	}

	if (fstat(bfd_get_fd(body_stream), &body_stat)) {
		err = errno;
		goto out_clean;
	}

	// Prepare connection to spamd
	sockfd = connect_to_address(ctx, host, port);
	if (sockfd < 0) {
		err = -sockfd;
		goto out_clean;
	}

	sock_stream = bfd_alloc(sockfd);
	if (!sock_stream) {
		close(sockfd);
		err = ENOMEM;
		goto out_clean;
	}

	// Send request line and headers to spamd
	if ((err = bfd_printf(sock_stream,
		"REPORT SPAMC/1.5\r\n"
		"User: %s\r\n"
		"Content-length: %zu\r\n"
		"\r\n%s",
		user,
		sb.cur + body_stat.st_size,
		sb.s)))
		goto out_clean;

	// Send message body to spamd
	if ((err = bfd_copy(body_stream, sock_stream)))
		goto out_clean;
	if ((err = bfd_flush(sock_stream)))
		goto out_clean;

	// Read and parse status line and headers from spamd
	for (i = 0;; i++) {
		char hdr[50], scr[sizeof(hdr)];

		if ((len = bfd_read_line(sock_stream, hdr, sizeof(hdr))) < 0) {
			err = len ? -len : EIO;
			goto out_clean;
		}

		if (len < 2 || strncmp(&hdr[len - 2], "\r\n", 2)) {
			err = EPROTO;
			goto out_clean;
		}

		hdr[len -= 2] = '\0';
		if (!len)
			break;

		if (!i) {
			if (sscanf(hdr, "SPAMD/%[0-9.] %d %s", scr, (int *)scr, scr) != 3 ||
			    strcmp(scr, "EX_OK")) {
				err = EPROTO;
				goto out_clean;
			}
			continue;
		}

		if (sscanf(hdr, "Content-length: %d", &clen) == 1)
			continue;

		if (sscanf(hdr, "Spam: %s ; %lf / %lf", scr, &score, &required) == 3) {
			if (strcmp(scr, "True") == 0)
				spam = true;
			else if (strcmp(scr, "False") != 0) {
				err = EPROTO;
				goto out_clean;
			}
		}
	}

	if (!clen || clen >= SPAMD_MAX_RESPONSE_SIZE) {
		err = EPROTO;
		goto out_clean;
	}

	buf = malloc(clen + 1);
	if (!buf) {
		err = ENOMEM;
		goto out_clean;
	}

	// Read and parse response from spamd
	if ((err = bfd_read_full(sock_stream, buf, clen)))
		goto out_clean;
	buf[clen] = '\0';

	duk_push_object(ctx);
	duk_push_boolean(ctx, spam);
	duk_put_prop_string(ctx, -2, "spam");
	duk_push_number(ctx, score);
	duk_put_prop_string(ctx, -2, "score");
	duk_push_number(ctx, required);
	duk_put_prop_string(ctx, -2, "required");

	for (i = 0, tok = buf; i < ARRAY_SIZE(fields); i++) {
		char *p = strchr(tok, '\n');
		int d;
		double f;

		if (!p) {
			err = EPROTO;
			goto out_clean;
		}
		*p = '\0';
		switch (fields[i].type) {
		case 's':
			duk_push_string(ctx, tok);
			break;
		case 'd':
			if (sscanf(tok, "%d", &d) != 1) {
				err = EPROTO;
				goto out_clean;
			}
			duk_push_int(ctx, d);
			break;
		case 'f':
			if (sscanf(tok, "%lf", &f) != 1) {
				err = EPROTO;
				goto out_clean;
			}
			duk_push_number(ctx, f);
			break;
		}
		duk_put_prop_string(ctx, -2, fields[i].name);
		tok = p + 1;
	}

out_clean:
	free(buf);
	string_buffer_cleanup(&sb);
	bfd_free(body_stream);
	bfd_free(sock_stream);
	return err ? js_ret_errno(ctx, err) : 1;
}

static const duk_function_list_entry SpamAssassin_functions[] = {
	{"scan",		SpamAssassin_scan,		2},
	{NULL,			NULL,				0}
};

/* }}} SpamAssassin */

duk_bool_t mod_spamassassin_init(duk_context *ctx)
{
	duk_push_c_function(ctx, SpamAssassin_construct, 3);
	duk_push_object(ctx);
	duk_put_function_list(ctx, -1, SpamAssassin_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SpamAssassin");

	return 1;
}

// vim: foldmethod=marker
