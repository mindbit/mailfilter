#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include <jsmisc.h>

#include "mailfilter.h"
#include "js_smtp.h"
#include "string_tools.h"

/**
 * Context for message header parser.
 */
struct im_header_context {
	enum {
		IM_H_NAME1,
		IM_H_NAME2,
		IM_H_VAL1,
		IM_H_VAL2,
		IM_H_VAL3,
		IM_H_FOLD,
		IM_H_FIN
	} state;
	duk_context *dcx;
	duk_bool_t hdr;
	size_t max_size, curr_size;
	struct string_buffer sb;
};

#define IM_HEADER_CONTEXT_INITIALIZER {\
	.state = IM_H_NAME1,\
	.hdr = 0,\
	.max_size = 0,\
	.curr_size = 0,\
	.sb = STRING_BUFFER_INITIALIZER\
}

/**
 * Append a header part to a SmtpHeader instance.
 *
 * Duktape stack:
 *	Input:	... | Object
 *	Output:	... | Object
 *		Object is a SmtpHeader instance.
 */
static duk_bool_t header_add_part(duk_context *ctx, const char *str)
{
	duk_bool_t ret;

	if (!duk_get_prop_string(ctx, -1, "parts")) {
		duk_pop(ctx);
		return 0;
	}

	duk_push_string(ctx, str);
	ret = js_append_array_element(ctx, -2);
	duk_pop(ctx); /* SmtpHeader.parts */

	return ret;
}

/**
 * Allocate a new SmtpHeader object and initialize the name property with the
 * given string.
 *
 * Duktape stack:
 *	Input:	...
 *	Output:	...						[failure]
 *	Output:	... | Object					[success]
 *		Object is a SmtpHeader instance.
 */
static duk_bool_t header_alloc(duk_context *ctx, const char *name)
{
	if (!duk_get_global_string(ctx, "SmtpHeader")) {
		duk_pop(ctx);
		return 0;
	}

	duk_push_string(ctx, name);
	if (duk_pnew(ctx, 1)) {
		js_log_error(ctx, -1);
		duk_pop(ctx);
		return 0;
	}

	return 1;
}

/**
 * Add a folding to the "current" (currently being parsed) header. The
 * folding position is the current position in the context string buffer.
 *
 * Duktape stack:
 *	Input:	... | Object
 *	Output:	... | Object
 *		Object is a SmtpHeader instance.
 */
static duk_bool_t im_header_add_fold_ctx(struct im_header_context *ctx)
{
	if (!header_add_part(ctx->dcx, ctx->sb.s))
		return 0;

	string_buffer_reset(&ctx->sb);
	return 1;
}

/**
 * Add the contents of the string buffer to the current header and push
 * the header object to the array of header objects.
 *
 * Duktape stack:
 *	Input:	... | Array | Object
 *	Output:	... | Array | Object				[failure]
 *	Output:	... | Array					[success]
 *		Object is a SmtpHeader instance.
 */
static duk_bool_t im_header_set_value_ctx(struct im_header_context *ctx)
{
	if (!im_header_add_fold_ctx(ctx))
		return 0;

	if (!js_append_array_element(ctx->dcx, -2))
		return 0;

	ctx->hdr = 0;
	return 1;
}

/*
 * Feed a single character to the header parsing state machine.
 *
 * @return	0		header parsing complete (found \r\n\r\n);
 *		EAGAIN		ready to accept a new character;
 *		EOVERFLOW	header exceeded context max_size;
 *		EINVAL		internal error; JS API error or something;
 *		ENOMEM
 *		EPROTO		header syntax error
 */
static int im_header_feed(struct im_header_context *ctx, char c)
{
	switch (ctx->state) {
	case IM_H_NAME1:
		/*
		 * Expect a new header (the name part). But we can also get
		 * white space (which means the previous header is a multiline
		 * header) or the \r\n sequence (which marks the end of the
		 * header section).
		 */
		if (strchr(tab_space, c)) {
			if (!ctx->hdr)
				return EPROTO;
			if (!im_header_add_fold_ctx(ctx))
				return EINVAL;
			if (ctx->curr_size++ >= ctx->max_size)
				return EOVERFLOW;
			if (string_buffer_append_char(&ctx->sb, c))
				return ENOMEM;
			ctx->state = IM_H_FOLD;
			return EAGAIN;
		}
		if (ctx->hdr && !im_header_set_value_ctx(ctx))
			return EINVAL;

		if (c == '\n') {
			return 0;
		}
		if (c == '\r') {
			ctx->state = IM_H_FIN;
			return EAGAIN;
		}
		/* Intentionally fall through to IM_H_NAME2 */
	case IM_H_NAME2:
		/*
		 * Expect a regular character that is part of the header name.
		 * We can also get the ':' delimiter, which marks the end of
		 * the header name.
		 */
		if (c == ':') {
			if (!header_alloc(ctx->dcx, ctx->sb.s))
				return EINVAL;
			string_buffer_reset(&ctx->sb);
			ctx->hdr = 1;
			ctx->state = IM_H_VAL1;
			return EAGAIN;
		}
		if (ctx->curr_size++ >= ctx->max_size)
			return EOVERFLOW;
		if (string_buffer_append_char(&ctx->sb, c))
			return ENOMEM;
		/* This piece of code is also part of IM_H_NAME1, so set state */
		ctx->state = IM_H_NAME2;
		return EAGAIN;
	case IM_H_FOLD:
		/*
		 * Expect whitespace that is at the beginning of the line in a
		 * multi-line header. Only the first whitespace character marks
		 * a multi-line header - the following whitespace characters
		 * (if present) are considered part of the header value.
		 */
		if (strchr(tab_space, c)) {
			if (string_buffer_append_char(&ctx->sb, c))
				return ENOMEM;
			return EAGAIN;
		}
		/* Intentionally fall through to IM_H_VAL1 */
	case IM_H_VAL1:
		/*
		 * Expect initial whitespace before the header value. Skip all
		 * whitespace, then fall through to the next state.
		 */
		if (strchr(tab_space, c))
			return EAGAIN;
		/* Intentionally fall through to IM_H_VAL2 */
	case IM_H_VAL2:
		/* Expect any character that can be part of the header value
		 * and append it to the buffer. We can also get the \r\n
		 * sequence, which means we either advance to the next header
		 * or continue this header on the next line, depending on the
		 * first character on the next line.
		 */
		if (c == '\n') {
			ctx->state = IM_H_NAME1;
			return EAGAIN;
		}
		if (c == '\r') {
			ctx->state = IM_H_VAL3;
			return EAGAIN;
		}
		if (ctx->curr_size++ >= ctx->max_size)
			return EOVERFLOW;
		if (string_buffer_append_char(&ctx->sb, c))
			return ENOMEM;
		/* This piece of code is also part of IM_H_VAL1, so set state */
		ctx->state = IM_H_VAL2;
		return EAGAIN;
	case IM_H_VAL3:
		/*
		 * Expect the '\n' character at the end of a header line. At
		 * this point we have already seen '\r', so '\n' is the only
		 * legal character.
		 */
		if (c != '\n')
			return EPROTO;
		ctx->state = IM_H_NAME1;
		return EAGAIN;
	case IM_H_FIN:
		/*
		 * Expect the '\n' character at the end of an empty line. At
		 * this point we have already seen '\r', so '\n' is the only
		 * legal character. This sequence marks the end of the
		 * header section.
		 */
		if (c != '\n')
			return EPROTO;
		return 0;
	}

	return EINVAL;
}

/**
 * Copy a RFC5322 formatted Internet Message from a socket to a temporary file.
 *
 * Headers are parsed into SmtpHeader objects that are stored on the heap.
 * Only the message body is copied to the temporary file.
 *
 * Duktape stack:
 *	Input:	... | Array
 *	Output:	... | Array
 *
 * Note: New SmtpHeader instances are created as headers are parsed. The
 *       instances are added to the Array at the top of the stack.
 *
 * @return	0		parsing complete, no errors;
 *		EIO
 *		EOVERFLOW	header exceeded context max_size;
 *		EINVAL		internal error; JS API error or something;
 *		ENOMEM
 *		EPROTO		header syntax error
 */
int smtp_copy_to_file(duk_context *ctx, bfd_t *out, bfd_t *in)
{
	/* "<CR><LF>.<CR><LF>" pattern and mask */
	const unsigned long long TERMSEQ_PTRN = 0x0d0a2e0d0aULL;
	const unsigned long long TERMSEQ_MASK = 0xffffffffffULL;
	/* "<CR><LF>.<any><any>" pattern and mask */
	const unsigned long long CRLFDOT_PTRN = 0x0d0a2e0000ULL;
	const unsigned long long CRLFDOT_MASK = 0xffffff0000ULL;
	/* length (in bytes) of the above patterns */
	const int PTRN_LEN = 5;
	/*
	 * <CR><LF> after DATA is considered when matching against the
	 * terminating sequence <CR><LF>.<CR><LF> - RFC5321 - 4.1.1.4.
	 */
	unsigned long long buf = 0x0d0aULL; /* <CR><LF> */
	/*
	 * Set fill to 0 because we want to discard the initial
	 * <CR><LF> that we initialize buf with.
	 */
	int fill = 0;

	int im_state = EAGAIN, ret = EINVAL;
	struct im_header_context im_hdr_ctx = IM_HEADER_CONTEXT_INITIALIZER;
	int c;

	im_hdr_ctx.dcx = ctx;
	im_hdr_ctx.max_size = 65536; // FIXME use proper value
	while ((c = bfd_getc(in)) >= 0) {
		buf = (buf << 8) | c;

		if (++fill > PTRN_LEN) {
			if (bfd_putc(out, (buf >> (PTRN_LEN * 8)) & 0xff))
				break;
			fill = PTRN_LEN;
		}

		/* double-dot conversion: test for "<CR><LF>." and discard dot */
		if ((buf & CRLFDOT_MASK) == CRLFDOT_PTRN && fill == PTRN_LEN) {
			if (bfd_putc(out, 0x0d) || bfd_putc(out, 0x0a))
				break;
			fill = 2;
		}

		if ((buf & TERMSEQ_MASK) == TERMSEQ_PTRN) {
			ret = 0;
			break;
		}

		if (im_state == EAGAIN) {
			im_state = im_header_feed(&im_hdr_ctx, c);
			fill = 0;
		}
	}

	string_buffer_cleanup(&im_hdr_ctx.sb);

	if (c < 0)
		return EIO;

	if (ret)
		return ret;

	return im_state;
}

/**
 * Copy a RFC5322 formatted Internet Message from a temporary file to a socket.
 *
 * Headers are taken from SmtpHeader objects that are stored on the heap.
 * Only the message body is copied from the temporary file.
 *
 * Duktape stack:
 *	Input:	... | Array
 *	Output:	... | Array
 *
 * @param[in] dotconv Dot conversion flag. If set, a line comprising of a
 *            single dot in the input stream is converted to double dot
 *            before writing to the output stream. Additionally, a line
 *            comprising of a single dot is written to the output stream
 *            at the end. This is useful when sending a message to an
 *            SMTP server.
 */
int smtp_copy_from_file(duk_context *ctx, bfd_t *out, bfd_t *in, int dotconv)
{
	const unsigned long CRLFDOT_PTRN = 0x0d0a2e;
	const unsigned long CRLFDOT_MASK = 0xffffff;
	const unsigned int PTRN_LEN = 3;
	const unsigned long CRLF_PTRN = 0x0d0a;
	const unsigned long CRLF_MASK = 0xffff;
	unsigned long buf = 0;
	duk_size_t i, len;
	int c, fill = 0, add_crlf = 1;

	/* send headers */
	len = duk_get_length(ctx, -1);
	for (i = 0; i < len; i++) {
		if (!duk_get_prop_index(ctx, -1, i)) {
			duk_pop(ctx);
			return EINVAL;
		}

		duk_push_string(ctx, "toString");
		if (duk_pcall_prop(ctx, -2, 0)) {
			js_log_error(ctx, -1);
			duk_pop_2(ctx);
			return EINVAL;
		}

		if (bfd_puts(out, duk_safe_to_string(ctx, -1))) {
			duk_pop_2(ctx);
			return EIO;
		}
		duk_pop_2(ctx);

		if (bfd_puts(out, "\r\n"))
			return EIO;
	}

	/* send header delimiter */
	if (bfd_puts(out, "\r\n"))
		return EIO;

	/* send body */
	while ((c = bfd_getc(in)) >= 0) {
		do {
			buf = (buf << 8) | c;
			if (++fill > PTRN_LEN) {
				if (bfd_putc(out, buf >> (PTRN_LEN * 8)))
					return EIO;
				fill = PTRN_LEN;
			}
			c = '.';
		} while (dotconv && (buf & CRLFDOT_MASK) == CRLFDOT_PTRN);
	}

	/* flush remaining buffer */
	while (fill) {
		if (fill == 2 && (buf & CRLF_MASK) == CRLF_PTRN)
			add_crlf = 0;
		if (bfd_putc(out, (buf >> (--fill * 8)) & 0xff))
			return EIO;
	}

	/* send termination marker */
	if (add_crlf && bfd_puts(out, "\r\n"))
		return EIO;
	if (dotconv && bfd_puts(out, ".\r\n"))
		return EIO;

	return 0;
}

bfd_t *smtp_body_open_read(duk_context *ctx, duk_idx_t obj_idx)
{
	const char *path = duk_safe_to_string(ctx, obj_idx);
	int fd;
	bfd_t *stream;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		js_report_error(ctx, "File %s cannot be opened: %d", path, errno);
		return NULL;
	}

	stream = bfd_alloc(fd);
	if (!stream)
		close(fd);

	return stream;
}

duk_bool_t smtp_create_response(duk_context *ctx, int code, const char *message, int disconnect)
{
	if (!duk_get_global_string(ctx, "SmtpResponse")) {
		js_log(JS_LOG_ERR, "SmtpResponse is not defined\n");
		duk_pop(ctx);
		return 0;
	}

	duk_push_int(ctx, code);
	duk_push_string(ctx, message);
	duk_push_boolean(ctx, disconnect);

	if (duk_pnew(ctx, 3)) {
		js_log_error(ctx, -1);
		duk_pop(ctx);
		return 0;
	}

	return 1;
}

duk_bool_t js_init_envelope(duk_context *ctx, duk_idx_t obj_idx)
{
	obj_idx = duk_normalize_index(ctx, obj_idx);

	duk_push_null(ctx);
	duk_put_prop_string(ctx, obj_idx, PR_SENDER);

	duk_push_array(ctx);
	duk_put_prop_string(ctx, obj_idx, PR_RECIPIENTS);

	return 1;
}

/* {{{ SmtpPath */

static int SmtpPath_construct(duk_context *ctx)
{
	duk_push_this(ctx);

	// Add domains property
	duk_push_array(ctx);
	duk_put_prop_string(ctx, -2, "domains");

	// Add mailbox property
	duk_push_object(ctx);
	duk_push_null(ctx);
	duk_put_prop_string(ctx, -2, "local");
	duk_push_null(ctx);
	duk_put_prop_string(ctx, -2, "domain");
	duk_put_prop_string(ctx, -2, "mailbox");

	duk_pop(ctx);

	return 0;
}

static int SmtpPath_parse(duk_context *ctx)
{
	enum {
		S_INIT,
		S_SEPARATOR,
		S_DOMAIN,
		S_MBOX_LOCAL,
		S_MBOX_DOMAIN,
		S_FINAL
	} state = S_INIT;
	const char *arg, *token = NULL;
	duk_idx_t self, domains, mailbox, local, domain;
	duk_uarridx_t idx = 0;

	/* Check arguments; prepare parsed data placeholders */
	arg = duk_to_string(ctx, 0);
	duk_push_this(ctx);
	self = duk_get_top_index(ctx);
	domains = duk_push_array(ctx);
	mailbox = duk_push_object(ctx);
	duk_push_null(ctx);
	local = duk_get_top_index(ctx);
	duk_push_null(ctx);
	domain = duk_get_top_index(ctx);

	/* Parsing state machine */
	while (*arg != '\0') {
		switch (state) {
		case S_INIT:
			if (*arg != '<')
				break;
			state = S_SEPARATOR;
			arg++;
			continue;
		case S_SEPARATOR:
			if (strchr(white, *arg) != NULL) {
				arg++;
				continue;
			}
			if (*arg == '@') {
				state = S_DOMAIN;
				token = ++arg;
				continue;
			}
			if (*arg == '>') {
				arg++;
				state = S_FINAL;
				continue;
			}
			token = arg;
			state = S_MBOX_LOCAL;
			continue;
		case S_DOMAIN:
			if (*arg == ',' || *arg == ':') {
				if (token == arg)
					break;
				duk_push_lstring(ctx, token, arg - token);
				duk_put_prop_index(ctx, domains, idx++);
			}
			if (*arg == ',') {
				++arg;
				state = S_SEPARATOR;
				continue;
			}
			if (*arg == ':') {
				token = ++arg;
				state = S_MBOX_LOCAL;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_LOCAL:
			if (*arg == '@') {
				if (token == arg)
					break;

				duk_push_lstring(ctx, token, arg - token);
				duk_replace(ctx, local);
				state = S_MBOX_DOMAIN;
				token = ++arg;
				continue;
			}
			arg++;
			continue;
		case S_MBOX_DOMAIN:
			if (*arg == '>') {
				if (token == arg)
					break;

				duk_push_lstring(ctx, token, arg - token);
				duk_replace(ctx, domain);
				state = S_FINAL;
			}
			arg++;
			continue;
		case S_FINAL:
			break;
		}
		break;
	}

	if (state != S_FINAL) {
		duk_pop_n(ctx, 5);
		duk_push_null(ctx);
		return 0;
	}

	/* Parsing successful; save parsed data to object and return */
	duk_put_prop_string(ctx, mailbox, "domain");
	duk_put_prop_string(ctx, mailbox, "local");
	duk_put_prop_string(ctx, self, "mailbox");
	duk_put_prop_string(ctx, self, "domains");
	duk_pop(ctx); // self (aka this)
	duk_push_string(ctx, arg);

	return 0;
}

static int SmtpPath_toString(duk_context *ctx)
{
	duk_idx_t self, domains, mailbox, local, domain;
	int domains_len, i = 0;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	char c;

	duk_push_this(ctx);
	self = duk_get_top_index(ctx);

	if (!duk_get_prop_string(ctx, self, "domains"))
		return js_ret_errno(ctx, EINVAL);
	domains = duk_get_top_index(ctx);

	if (!duk_get_prop_string(ctx, self, "mailbox") || duk_is_null(ctx, -1))
		return js_ret_errno(ctx, EINVAL);
	mailbox = duk_get_top_index(ctx);

	if (!duk_get_prop_string(ctx, mailbox, "local"))
		return js_ret_errno(ctx, EINVAL);
	local = duk_get_top_index(ctx);

	if (!duk_get_prop_string(ctx, mailbox, "domain"))
		return js_ret_errno(ctx, EINVAL);
	domain = duk_get_top_index(ctx);

	domains_len = duk_get_length(ctx, domains);

	if (string_buffer_append_char(&sb, '<'))
		goto out_clean;

	while (i < domains_len) {
		if (!duk_get_prop_index(ctx, domains, i))
			goto out_clean;

		if (string_buffer_append_char(&sb, '@'))
			goto out_clean;

		if (string_buffer_append_string(&sb, duk_to_string(ctx, -1)))
			goto out_clean;

		c = ++i < domains_len ? ',' : ':';
		if (string_buffer_append_char(&sb, c))
			goto out_clean;
	}

	if (!duk_is_null(ctx, local)) {
		if (string_buffer_append_string(&sb, duk_to_string(ctx, local)))
			goto out_clean;
	}

	if (!duk_is_null(ctx, domain)) {
		if (string_buffer_append_char(&sb, '@'))
			goto out_clean;

		if (string_buffer_append_string(&sb, duk_to_string(ctx, domain)))
			goto out_clean;
	}

	if (string_buffer_append_char(&sb, '>'))
		goto out_clean;

	duk_pop_n(ctx, 5);
	duk_push_string(ctx, sb.s);
	string_buffer_cleanup(&sb);

	return 1;

out_clean:
	string_buffer_cleanup(&sb);
	return js_report_errno(ctx, ENOMEM);
}

static const duk_function_list_entry SmtpPath_functions[] = {
	{"parse",		SmtpPath_parse,			1},
	{"toString",		SmtpPath_toString,		0},
	{NULL,			NULL,				0}
};

/* }}} SmtpPath */

/* {{{ SmtpHeader */

static int SmtpHeader_construct(duk_context *ctx)
{
	duk_idx_t argc = duk_get_top(ctx);

	if (argc < 1)
		return js_ret_errno(ctx, EINVAL);

	duk_push_this(ctx);

	// Set name property
	duk_dup(ctx, 0);
	duk_to_string(ctx, -1);
	duk_put_prop_string(ctx, -2, "name");

	// Add parts property
	if (argc >= 2 && duk_is_object(ctx, 1)) {
		duk_dup(ctx, 1);
		goto out_ret;
	}

	duk_push_array(ctx);

	if (argc >= 2) {
		// Add message to messages array
		duk_dup(ctx, 1);
		duk_to_string(ctx, -1);
		duk_put_prop_index(ctx, -2, 0);
	}

out_ret:
	duk_put_prop_string(ctx, -2, "parts");

	return 0;
}

/*
 * Get the canonical value of the header by left trimming each part and
 * concatenating the parts. The object is not modified.
 */
static int SmtpHeader_getValue(duk_context *ctx)
{
	duk_size_t len, i;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	int err;

	duk_push_this(ctx);

	if (!duk_get_prop_string(ctx, -1, "parts")) {
		duk_pop_2(ctx);
		return js_ret_errno(ctx, EINVAL);
	}

	// Get number of parts
	len = duk_get_length(ctx, -1);

	for (i = 0; i < len; i++) {
		if (i && (err = string_buffer_append_char(&sb, ' ')))
			goto out_ret;

		duk_get_prop_index(ctx, -1, i);
		err = string_buffer_append_string(&sb,
			ltrim(duk_to_string(ctx, -1)));
		duk_pop(ctx);
		if (err)
			goto out_ret;
	}

	duk_pop_2(ctx);
	duk_push_string(ctx, sb.s ? sb.s : "");
	string_buffer_cleanup(&sb);

	return 1;

out_ret:
	duk_pop_2(ctx);
	string_buffer_cleanup(&sb);

	return js_ret_errno(ctx, err);
}

/*
 * Get a string representation of the entire header, including folding. The
 * result contains the header name, followed by ": ", followed by all value
 * parts with their existing leading whitespace and concatenated by "\r\n".
 */
static int SmtpHeader_toString(duk_context *ctx)
{
	duk_size_t len, i;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	int err = EINVAL;

	duk_push_this(ctx);

	// Get name
	if (!duk_get_prop_string(ctx, -1, "name"))
		goto out_ret;

	if ((err = string_buffer_append_string(&sb, duk_get_string(ctx, -1))))
		goto out_ret;
	if ((err = string_buffer_append_string(&sb, ": ")))
		goto out_ret;

	duk_pop(ctx);

	// Get parts
	if (!duk_get_prop_string(ctx, -1, "parts")) {
		err = EINVAL;
		goto out_ret;
	}

	// Get number of parts
	len = duk_get_length(ctx, -1);

	for (i = 0; i < len; i++) {
		if (i && (err = string_buffer_append_string(&sb, "\r\n")))
			goto out_ret;

		duk_get_prop_index(ctx, -1, i);
		err = string_buffer_append_string(&sb,
			duk_to_string(ctx, -1));
		duk_pop(ctx);
		if (err)
			goto out_ret;
	}

	duk_pop_2(ctx);
	duk_push_string(ctx, sb.s);
	string_buffer_cleanup(&sb);

	return 1;

out_ret:
	duk_pop_2(ctx);
	string_buffer_cleanup(&sb);

	return js_ret_errno(ctx, err);
}

static int SmtpHeader_refold(duk_context *ctx)
{
	int hdridx = 0, err;
	const int width = duk_get_int(ctx, 0);
	char *value, *part, *ptr, *end;

	// Get canonical value
	if ((err = SmtpHeader_getValue(ctx)) < 0)
		return err;
	if (!(value = strdup(duk_get_string(ctx, -1))))
		return js_ret_errno(ctx, ENOMEM);
	duk_pop(ctx);

	// Prepare new header parts
	duk_push_this(ctx);
	duk_push_array(ctx);

	for (part = value; *part; part = end + !!*end) {
		// Find the longest substring that starts at [part], ends with
		// either ' ' or '\0' and is shorter than [width]. If there is
		// no ' ' within the first [width] characters, take everything
		// up to the first ' ' (or the end of string if no ' ' exists).
		for (end = NULL, ptr = part; *ptr; end = ptr, ptr += !!*ptr) {
			ptr = strchr(ptr, ' ') ?: strchr(ptr, '\0');
			if (ptr - part > width)
				break;
		}
		if (!end) // the first substring is longer than width
			end = ptr;
		if (hdridx)
			*--part = '\t';
		duk_push_lstring(ctx, part, end - part);
		duk_put_prop_index(ctx, -1, hdridx++);
	}
	free(value);

	duk_put_prop_string(ctx, -2, "parts");
	duk_pop(ctx);

	return 0;
}

static const duk_function_list_entry SmtpHeader_functions[] = {
	{"getValue",		SmtpHeader_getValue,		0},
	{"toString",		SmtpHeader_toString,		0},
	{"refold",		SmtpHeader_refold,		0},
	{NULL,			NULL,				0}
};

/* }}} SmtpHeader */

/* {{{ SmtpResponse */

static int SmtpResponse_construct(duk_context *ctx)
{
	duk_idx_t argc = duk_get_top(ctx);
	duk_bool_t disconnect = 0;

	if (argc < 2)
		return DUK_RET_ERROR;

	duk_push_this(ctx);

	// Add code property
	duk_dup(ctx, 0);
	duk_to_int(ctx, -1);
	duk_put_prop_string(ctx, -2, "code");

	// Add message property
	duk_dup(ctx, 1);
	if (!duk_is_array(ctx, -1))
		duk_to_string(ctx, -1);
	// FIXME if it's an array, coerce each element to string
	duk_put_prop_string(ctx, -2, "message");

	// Add disconnect property
	if (argc >= 3)
		disconnect = duk_get_boolean(ctx, 2);
	duk_push_boolean(ctx, disconnect);
	duk_put_prop_string(ctx, -2, "disconnect");

	duk_pop(ctx);

	return 0;
}

/* }}} SmtpResponse */

static int connect_to_address(duk_context *ctx, const char *host, unsigned short port)
{
	int sockfd;
	struct sockaddr_in serv_addr = {AF_INET};
	struct hostent *server;

	// FIXME use getaddrinfo; handle ipv6
	server = gethostbyname(host);
	if (!server) {
		// TODO throw exc
		return -1;
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		// TODO throw exc
		return -1;
	}

	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, sizeof(in_addr_t));
	serv_addr.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		close(sockfd);
		return js_report_error(ctx, "Cannot connect to %s:%hu!", host, port);
	}

	return sockfd;
}

/* {{{ SmtpClient */

static int __SmtpClient_closeStream(duk_context *ctx)
{
	bfd_t *stream = NULL;

	duk_push_this(ctx);
	if (duk_get_prop_string(ctx, -1, "stream"))
		stream = duk_get_pointer(ctx, -1);
	duk_del_prop_string(ctx, -2, "stream");
	duk_pop_2(ctx);

	if (stream)
		bfd_free(stream);

	return 0;
}

static int SmtpClient_construct(duk_context *ctx)
{
	duk_push_this(ctx);

	// Add host
	duk_dup(ctx, 0);
	duk_to_string(ctx, -1);
	duk_put_prop_string(ctx, -2, "host");

	// Add port
	duk_dup(ctx, 1);
	duk_to_int(ctx, -1);
	duk_put_prop_string(ctx, -2, "port");

	duk_pop(ctx);

	return 0;
}

static int SmtpClient_finalize(duk_context *ctx)
{
	return __SmtpClient_closeStream(ctx);
}

static int SmtpClient_connect(duk_context *ctx)
{
	const char *host;
	int port;
	int sockfd;
	bfd_t *stream;

	duk_push_this(ctx);

	// Get host
	duk_get_prop_string(ctx, -1, "host");
	host = duk_get_string(ctx, -1);

	// Get port
	duk_get_prop_string(ctx, -2, "port");
	port = duk_get_int(ctx, -1);

	if (!host || !port)
		js_report_error(ctx, "Invalid host or port %s:%d", host, port);

	sockfd = connect_to_address(ctx, host, port);
	// FIXME connect_to_address may fail; check return value and bail out

	stream = bfd_alloc(sockfd);
	// FIXME bfd_alloc can fail

	// FIXME client may already be connected; don't leak previous connection
	duk_push_pointer(ctx, stream);
	duk_put_prop_string(ctx, -4, "stream");

	duk_pop_3(ctx);

	return 0;
}

static int SmtpClient_disconnect(duk_context *ctx)
{
	return __SmtpClient_closeStream(ctx);
}

static int SmtpClient_readResponse(duk_context *ctx)
{
	int code, lines_count;
	char buf[SMTP_COMMAND_MAX + 1], *p, sep;
	ssize_t sz;
	bfd_t *stream = NULL;

	duk_push_this(ctx);
	if (duk_get_prop_string(ctx, -1, "stream"))
		stream = duk_get_pointer(ctx, -1);
	duk_pop_2(ctx);
	if (!stream)
		return js_ret_errno(ctx, ENOTCONN);

	duk_push_array(ctx);

	lines_count = 0;
	do {
		sz = 0;
		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) <= 0)
				return js_ret_errno(ctx, EIO);
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[sz] = '\0';

		if (sz < 4)
			return js_ret_errno(ctx, EPROTO);

		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return js_ret_errno(ctx, EPROTO);
		if (code < 100 || code > 999)
			return js_ret_errno(ctx, EPROTO);

		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		if (buf[sz - 1] == '\r')
			buf[--sz] = '\0';

		//add response
		duk_push_string(ctx, buf + 4);
		duk_put_prop_index(ctx, -2, lines_count++);
	} while (sep == '-');

	if (!duk_get_global_string(ctx, "SmtpResponse"))
		return js_ret_error(ctx, "SmtpResponse is not defined");
	duk_insert(ctx, -2);

	duk_push_int(ctx, code);
	duk_insert(ctx, -2);

	duk_push_boolean(ctx, 0);
	duk_new(ctx, 3);

	return 1;
}

/*
 * The corresponding JS function takes 2 arguments:
 *  - SMTP verb (mandatory)
 *  - parameters to the SMTP verb (optional)
 *
 * We use a fixed number of two arguments when we bind the native C function,
 * and rely on the fact that Duktape pads missing arguments with undefined to
 * determine if the second argument was specified at call time. As a bonus, this
 * also handles the case when a wrapper function has two arguments and always
 * passes the second argument, but the wrapper itself is called with only one
 * argument.
 */
static int SmtpClient_sendCommand(duk_context *ctx)
{
	bfd_t *stream = NULL;
	const char *str;

	duk_push_this(ctx);
	if (duk_get_prop_string(ctx, -1, "stream"))
		stream = duk_get_pointer(ctx, -1);
	duk_pop_2(ctx);
	if (!stream)
		return js_ret_errno(ctx, ENOTCONN);

	str = duk_to_string(ctx, 0);

	if (bfd_puts(stream, str))
		return js_ret_errno(ctx, EIO);

	if (duk_is_undefined(ctx, 1))
		goto out_flush;

	str = duk_to_string(ctx, 1);

	if (bfd_putc(stream, ' '))
		return js_ret_errno(ctx, EIO);

	if (bfd_puts(stream, str))
		return js_ret_errno(ctx, EIO);

out_flush:
	if (bfd_puts(stream, "\r\n"))
		return js_ret_errno(ctx, EIO);

	if (bfd_flush(stream))
		return js_ret_errno(ctx, EIO);

	return 0;
}

static int SmtpClient_sendMessage(duk_context *ctx)
{
	int status;
	bfd_t *client_stream = NULL, *body_stream;

	duk_push_this(ctx);
	if (duk_get_prop_string(ctx, -1, "stream"))
		client_stream = duk_get_pointer(ctx, -1);
	duk_pop_2(ctx);
	if (!client_stream)
		return js_ret_errno(ctx, ENOTCONN);

	body_stream = smtp_body_open_read(ctx, 1);
	if (!body_stream)
		return js_ret_errno(ctx, ENOMEM);

	// Duktape guarantees that exactly 2 elements are on the stack at
	// function entry, since we use a fixed number of arguments.
	// Remove the 2nd argument and leave the first at the stack top.
	duk_pop(ctx);
	status = smtp_copy_from_file(ctx, client_stream, body_stream, 1);

	bfd_free(body_stream);

	if (status != EIO) {
		int err = bfd_flush(client_stream);
		status = err ? err : status;
	}

	if (status)
		return js_ret_errno(ctx, status);

	return 0;
}

static const duk_function_list_entry SmtpClient_functions[] = {
	{"connect",		SmtpClient_connect,		0},
	{"disconnect",		SmtpClient_disconnect,		0},
	{"readResponse",	SmtpClient_readResponse,	0},
	{"sendCommand",		SmtpClient_sendCommand,		2},
	{"sendMessage",		SmtpClient_sendMessage,		2},
	{NULL,			NULL,				0}
};

/* }}} SmtpClient */

/* {{{ SmtpServer */

static int SmtpServer_construct(duk_context *ctx)
{
	duk_push_this(ctx);

	// Set address
	duk_dup(ctx, 0);
	duk_to_string(ctx, -1);
	duk_put_prop_string(ctx, -2, PR_REMOTE_ADDR);

	// Set port
	duk_dup(ctx, 1);
	duk_to_int(ctx, -1);
	duk_put_prop_string(ctx, -2, PR_REMOTE_PORT);

	// Define and set session properties

	duk_push_null(ctx);
	duk_put_prop_string(ctx, -2, PR_CLIENTNAME);

	if (!js_init_envelope(ctx, -1))
		return js_ret_errno(ctx, ENOMEM);

	duk_push_boolean(ctx, 0);
	duk_put_prop_string(ctx, -2, PR_DISCONNECT);

	duk_push_string(ctx, "SMTP");
	duk_put_prop_string(ctx, -2, PR_PROTO);

	return 0;
}

static int SmtpServer_cleanup(duk_context *ctx)
{
	return 0;
}

static int SmtpServer_receivedHeader(duk_context *ctx)
{
	duk_idx_t argc = duk_get_top(ctx);
	duk_idx_t self;
	const char *fname, *lhost, *proto, *addr, *str;
	struct sockaddr_in addr4 = {AF_INET};
	char phost[NI_MAXHOST];
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	int err;
	const char *myid = "Mailfilter"; // TODO take from config
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[40];

	duk_push_this(ctx);
	self = duk_get_top_index(ctx);

	if (!duk_get_prop_string(ctx, self, PR_CLIENTNAME))
		return js_ret_errno(ctx, EINVAL);
	fname = duk_to_string(ctx, -1);

	if (!duk_get_prop_string(ctx, self, PR_HOSTNAME))
		return js_ret_errno(ctx, EINVAL);
	lhost = duk_to_string(ctx, -1);

	if (!duk_get_prop_string(ctx, self, PR_PROTO))
		return js_ret_errno(ctx, EINVAL);
	proto = duk_to_string(ctx, -1);

	if (!duk_get_prop_string(ctx, self, PR_REMOTE_ADDR))
		return js_ret_errno(ctx, EINVAL);
	addr = duk_to_string(ctx, -1);

	// TODO add IPv6 support
	inet_pton(AF_INET, addr, &addr4.sin_addr); // FIXME check return value
	if (getnameinfo((struct sockaddr *)&addr4, sizeof(addr4), phost, sizeof(phost), NULL, 0, NI_NAMEREQD))
		strcpy(phost, "unknown");

	if (!header_alloc(ctx, "Received"))
		return js_ret_errno(ctx, ENOMEM);

	err = string_buffer_append_strings(&sb, "from ", fname ? fname :
			"unknown", " (", phost, " [", addr, "])", NULL);
	if (err)
		goto out_clean;
	if (!header_add_part(ctx, sb.s))
		goto out_clean;

	string_buffer_reset(&sb);
	err = string_buffer_append_strings(&sb, "\tby ", lhost, " (",
			myid, ") with ", proto, NULL);
	if (err)
		goto out_clean;

	/* Add opt-info "ID" (if supplied as parameter #1) */
	if (argc >= 1) {
		str = duk_to_string(ctx, 0);
		if (string_buffer_append_strings(&sb, " id ", str, NULL))
			goto out_clean;
	}

	/* Add opt-info "for" (if supplied as parameter #2) */
	if (argc >= 2) {
		if (!header_add_part(ctx, sb.s))
			goto out_clean;
		string_buffer_reset(&sb);
		str = duk_to_string(ctx, 1);
		if (string_buffer_append_strings(&sb, "\tfor ", str, NULL))
			goto out_clean;
	}

	err = string_buffer_append_char(&sb, ';');
	if (err)
		goto out_clean;

	if (!header_add_part(ctx, sb.s))
		goto out_clean;

	strftime(ts, sizeof(ts), "%a, %e %b %Y %H:%M:%S %z (%Z)", tm);
	string_buffer_reset(&sb);
	err = string_buffer_append_strings(&sb, "\t", ts, NULL);
	if (err)
		goto out_clean;
	if (!header_add_part(ctx, sb.s))
		goto out_clean;

	string_buffer_cleanup(&sb);

	return 1;

out_clean:
	string_buffer_cleanup(&sb);
	return js_ret_errno(ctx, ENOMEM);
}

#define DEFINE_HANDLER_STUB(name) \
	static int SmtpServer_smtp##name (duk_context *ctx) { \
		duk_bool_t rc = smtp_create_response(ctx, 250, "def" #name, 0); \
		return rc ? 1 : DUK_RET_ERROR; \
	}

DEFINE_HANDLER_STUB(Init);
DEFINE_HANDLER_STUB(Auth);
DEFINE_HANDLER_STUB(Ehlo);
DEFINE_HANDLER_STUB(Helo);
DEFINE_HANDLER_STUB(Data);
DEFINE_HANDLER_STUB(Mail);
DEFINE_HANDLER_STUB(Rcpt);
DEFINE_HANDLER_STUB(Rset);
DEFINE_HANDLER_STUB(Body);
DEFINE_HANDLER_STUB(StartTls);

static const duk_function_list_entry SmtpServer_functions[] = {
	{"smtpInit",		SmtpServer_smtpInit,		0},
	{"smtpAuth",		SmtpServer_smtpAuth,		0},
	{"smtpEhlo",		SmtpServer_smtpEhlo,		0},
	{"smtpHelo",		SmtpServer_smtpHelo,		0},
	{"smtpData",		SmtpServer_smtpData,		0},
	{"smtpMail",		SmtpServer_smtpMail,		0},
	{"smtpRcpt",		SmtpServer_smtpRcpt,		0},
	{"smtpRset",		SmtpServer_smtpRset,		0},
	{"smtpBody",		SmtpServer_smtpBody,		0},
	{"smtpStartTls",	SmtpServer_smtpStartTls,	0},
	{"cleanup",		SmtpServer_cleanup,		0},
	{"receivedHeader",	SmtpServer_receivedHeader,	0},
	{NULL,			NULL,				0}
};

/* }}} SmtpServer */

/**
 * @return 1 on success, throws error on failure
 */
duk_bool_t js_smtp_init(duk_context *ctx)
{
	char hostname[HOST_NAME_MAX] = "localhost";

	gethostname(hostname, sizeof(hostname));

	duk_push_c_function(ctx, SmtpPath_construct, 0);
	duk_push_object(ctx);
	duk_put_function_list(ctx, -1, SmtpPath_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SmtpPath");

	duk_push_c_function(ctx, SmtpHeader_construct, DUK_VARARGS);
	duk_push_object(ctx);
	duk_put_function_list(ctx, -1, SmtpHeader_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SmtpHeader");

	duk_push_c_function(ctx, SmtpResponse_construct, DUK_VARARGS);
	duk_put_global_string(ctx, "SmtpResponse");

	duk_push_c_function(ctx, SmtpClient_construct, 2);
	duk_push_object(ctx);
	duk_push_c_function(ctx, SmtpClient_finalize, 2);
	duk_set_finalizer(ctx, -2);
	duk_put_function_list(ctx, -1, SmtpClient_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SmtpClient");

	duk_push_c_function(ctx, SmtpServer_construct, 2);
	duk_push_object(ctx);
	duk_put_function_list(ctx, -1, SmtpServer_functions);
	duk_push_string(ctx, hostname);
	duk_put_prop_string(ctx, -2, PR_HOSTNAME);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SmtpServer");

	return 1;
}

// vim: foldmethod=marker
