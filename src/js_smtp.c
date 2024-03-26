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
			if (bfd_putc(out, (buf >> (PTRN_LEN * 8)) & 0xff) < 0)
				break;
			fill = PTRN_LEN;
		}

		/* double-dot conversion: test for "<CR><LF>." and discard dot */
		if ((buf & CRLFDOT_MASK) == CRLFDOT_PTRN && fill == PTRN_LEN) {
			if (bfd_putc(out, 0x0d) < 0 || bfd_putc(out, 0x0a) < 0)
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

		if (bfd_puts(out, duk_safe_to_string(ctx, -1)) < 0) {
			duk_pop_2(ctx);
			return EIO;
		}
		duk_pop_2(ctx);

		if (bfd_puts(out, "\r\n") < 0)
			return EIO;
	}

	/* send header delimiter */
	if (bfd_puts(out, "\r\n") < 0)
		return EIO;

	/* send body */
	while ((c = bfd_getc(in)) >= 0) {
		do {
			buf = (buf << 8) | c;
			if (++fill > PTRN_LEN) {
				if (bfd_putc(out, buf >> (PTRN_LEN * 8)) < 0)
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
		if (bfd_putc(out, (buf >> (--fill * 8)) & 0xff) < 0)
			return EIO;
	}

	/* send termination marker */
	if (add_crlf && bfd_puts(out, "\r\n") < 0)
		return EIO;
	if (dotconv && bfd_puts(out, ".\r\n") < 0)
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
		// FIXME raise JS error
		//JS_ReportError(js_context, "File %s cannot be opened: %d", path, errno);
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
#if 0

/* {{{ SmtpPath */

static JSClass SmtpPath_class = {
	"SmtpPath", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpPath_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *domains, *mailbox, *obj;

	obj = JS_NewObjectForConstructor(cx, &SmtpPath_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add domains property
	domains = JS_NewArrayObject(cx, 0, NULL);
	if (!domains)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	// Add mailbox property
	mailbox = JS_NewObject(cx, NULL, NULL, NULL);
	if (!mailbox)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, mailbox, "local", JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, mailbox, "domain", JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static JSBool SmtpPath_parse(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	enum {
		S_INIT,
		S_SEPARATOR,
		S_DOMAIN,
		S_MBOX_LOCAL,
		S_MBOX_DOMAIN,
		S_FINAL
	} state = S_INIT;
	JSBool ret = JS_TRUE;
	char *c_str = NULL, *arg, *token = NULL;
	JSString *js_str, *local = NULL, *domain = NULL, *trail = NULL;
	JSObject *domains, *mailbox;
	uint32_t idx = 0;

	/* Check arguments; prepare parsed data placeholders */
	JS_SET_RVAL(cx, vp, JSVAL_NULL);

	if (!argc || !self)
		goto out_ret;

	js_str = JSVAL_TO_STRING(JS_ARGV(cx, vp)[0]);
	if (!js_str)
		goto out_ret;

	c_str = JS_EncodeString(cx, js_str);
	if (!c_str)
		goto out_ret;

	ret = JS_FALSE;

	domains = JS_NewArrayObject(cx, 0, NULL);
	if (!domains)
		goto out_ret;

	/* Parsing state machine */
	arg = c_str;
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
				js_str = JS_NewStringCopyN(cx, token, arg - token);
				if (!js_str)
					goto out_ret;
				if (!JS_DefineElement(cx, domains, idx++, STRING_TO_JSVAL(js_str), NULL, NULL, 0))
					goto out_ret;
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

				local = JS_NewStringCopyN(cx, token, arg - token);
				if (!local)
					goto out_ret;

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

				domain = JS_NewStringCopyN(cx, token, arg - token);
				if (!domain)
					goto out_ret;

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
		ret = JS_TRUE;
		goto out_ret;
	}

	/* Parsing successful; save parsed data to object and return */

	if (!JS_DefineProperty(cx, self, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	// Add mailbox property
	mailbox = JS_NewObject(cx, NULL, NULL, NULL);
	if (!mailbox)
		goto out_ret;

	if (!JS_DefineProperty(cx, mailbox, "local", JS_StringToJsval(local), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	if (!JS_DefineProperty(cx, mailbox, "domain", JS_StringToJsval(domain), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	if (!JS_DefineProperty(cx, self, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	trail = JS_NewStringCopyZ(cx, arg);
	JS_SET_RVAL(cx, vp, JS_StringToJsval(trail));
	ret = JS_TRUE;

out_ret:
	JS_free(cx, c_str);
	return ret;
}

static JSBool SmtpPath_toString(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval domain, local, domains, mailbox, v;
	uint32_t domains_len, i = 0;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	char c, *str = NULL;
	JSBool ret = JS_FALSE;

	if (!JS_GetProperty(cx, self, "domains", &domains))
		return JS_RetErrno(cx, EINVAL);

	if (!JS_GetProperty(cx, self, "mailbox", &mailbox) || JSVAL_IS_NULL(mailbox))
		return JS_RetErrno(cx, EINVAL);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "local", &local))
		return JS_RetErrno(cx, EINVAL);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "domain", &domain))
		return JS_RetErrno(cx, EINVAL);

	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(domains), &domains_len))
		return JS_RetErrno(cx, EINVAL);

	if (string_buffer_append_char(&sb, '<'))
		goto out_clean;

	while (i < domains_len) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(domains), i, &v))
			goto out_clean;

		if (string_buffer_append_char(&sb, '@'))
			goto out_clean;

		JS_free(cx, str);
		str = JS_EncodeString(cx, JSVAL_TO_STRING(v));
		if (string_buffer_append_string(&sb, str))
			goto out_clean;

		c = ++i < domains_len ? ',' : ':';
		if (string_buffer_append_char(&sb, c))
			goto out_clean;
	}

	if (!JSVAL_IS_NULL(local)) {
		JS_free(cx, str);
		str = JS_EncodeString(cx, JSVAL_TO_STRING(local));
		if (string_buffer_append_string(&sb, str))
			goto out_clean;
	}

	if (!JSVAL_IS_NULL(domain)) {
		if (string_buffer_append_char(&sb, '@'))
			goto out_clean;

		JS_free(cx, str);
		str = JS_EncodeString(cx, JSVAL_TO_STRING(domain));
		if (string_buffer_append_string(&sb, str))
			goto out_clean;
	}

	if (string_buffer_append_char(&sb, '>'))
		goto out_clean;

	// FIXME avoid extra copy with JS_NewUCString; but arg is jschar!
	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_NewStringCopyZ(cx, sb.s)));
	ret = JS_TRUE;

out_clean:
	string_buffer_cleanup(&sb);
	JS_free(cx, str);
	if (!ret)
		JS_ReportErrno(cx, ENOMEM);
	return ret;
}

static JSFunctionSpec SmtpPath_functions[] = {
	JS_FS("parse", SmtpPath_parse, 1, 0),
	JS_FS("toString", SmtpPath_toString, 0, 0),
	JS_FS_END
};

/* }}} SmtpPath */

/* {{{ SmtpHeader */

static JSClass SmtpHeader_class = {
	"SmtpHeader", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpHeader_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval name, parts;
	JSObject *obj, *pr;

	name = JS_ARGV(cx, vp)[0];
	parts = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpHeader_class, vp);
	if (!obj)
		return JS_FALSE;

	// Set name property
	if (!JS_SetProperty(js_context, obj, "name", &name))
		return JS_FALSE;

	// Add parts property
	if (argc >= 2 && JS_TypeOfValue(cx, parts) == JSTYPE_OBJECT) {
		if (!JS_SetProperty(js_context, obj, "parts", &parts))
			return JS_FALSE;
		goto out_ret;
	}

	pr = JS_NewArrayObject(js_context, 0, NULL);
	if (!pr)
		return JS_FALSE;

	if (argc >= 2 && JS_TypeOfValue(cx, parts) == JSTYPE_STRING) {
		// Add message to messages array
		if (!JS_SetElement(js_context, pr, 0, &parts))
			return JS_FALSE;
		goto out_ret;
	}

	if (argc >= 2)
		return JS_FALSE;

out_ret:
	parts = OBJECT_TO_JSVAL(pr);

	if (!JS_SetProperty(js_context, obj, "parts", &parts))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static JSBool SmtpHeader_getValue(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval parts, rval;

	uint32_t parts_len, header_len;
	int i;
	char *c_str, *header_no_wsp;

	// Get parts
	if (!JS_GetProperty(cx, self, "parts", &parts)) {
		return JS_FALSE;
	}

	// Get number of parts
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(parts), &parts_len)) {
		return -1;
	}

	if (parts_len == 0) {
		JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, "")));

		return JS_TRUE;
	}

	header_len = 0;

	for (i = 0; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &rval)) {
			return -1;
		}
		header_len += JS_GetStringLength(JSVAL_TO_STRING(rval));
	}

	header_len += 3 * ((int) parts_len - 1);

	c_str = malloc(header_len + 1);

	if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), 0, &rval)) {
		return -1;
	}

	// Remove beginning whitespace chars
	header_no_wsp = JS_EncodeString(cx, JSVAL_TO_STRING(rval));
	string_remove_beginning_whitespace(header_no_wsp);

	strcpy(c_str, header_no_wsp);
	strcat(c_str, " ");

	free(header_no_wsp);

	for (i = 1; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &rval)) {
			return -1;
		}

		// Remove beginning whitespace chars
		header_no_wsp = JS_EncodeString(cx, JSVAL_TO_STRING(rval));
		string_remove_beginning_whitespace(header_no_wsp);

		strcat(c_str, header_no_wsp);
		free(header_no_wsp);

		if (i < (int) (parts_len - 1)) {
			strcat(c_str, " ");
		}
	}

	strcat(c_str, "\0");

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));

	free(c_str);

	return JS_TRUE;
}

static JSBool SmtpHeader_toString(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval rval, name, parts, part;
	uint32_t parts_len;
	int i;

	// Get name
	if (!JS_GetProperty(cx, self, "name", &name)) {
		return JS_FALSE;
	}

	// Get parts
	if (!JS_GetProperty(cx, self, "parts", &parts)) {
		return JS_FALSE;
	}

	// Get number of parts
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(parts), &parts_len)) {
		return -1;
	}

	rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(name), JS_InternString(cx, ": ")));

	for (i = 0; i < (int) parts_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(parts), i, &part)) {
			return -1;
		}

		rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(rval), JSVAL_TO_STRING(part)));

		if (i < (int) parts_len - 1) {
			rval = STRING_TO_JSVAL(JS_ConcatStrings(cx, JSVAL_TO_STRING(rval), JS_InternString(cx, "\r\n")));
		}
	}

	JS_SET_RVAL(cx, vp, rval);
	return JS_TRUE;
}

static JSBool SmtpHeader_refold(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval name, value, parts;
	int width, len;
	char /* *c_name, */ *c_value, *p1, *p2, *p3, *c_part;

	width = JSVAL_TO_INT(JS_ARGV(cx, vp)[0]);

	// Get name
	if (!JS_GetProperty(cx, self, "name", &name)) {
		return JS_FALSE;
	}

	// Get value
	if (SmtpHeader_getValue(cx, argc, vp)) {
		value = *vp;
	}

	// Delete header parts
	if (!JS_GetProperty(cx, self, "parts", &parts))
		return JS_FALSE;
	if (!JS_SetArrayLength(cx, JSVAL_TO_OBJECT(parts), 0))
		return JS_FALSE;

	//c_name = JS_EncodeString(cx, JSVAL_TO_STRING(name));
	c_value = JS_EncodeString(cx, JSVAL_TO_STRING(value));

	p1 = c_value;
	p2 = p1;
	p3 = c_value;
	len = 0;

	do {
		int count = 0;
		do {
			len += p2 - p1;
			p1 = p2;

			if ((p2 = strchr(p1, ' ')) == NULL) {
				c_part = malloc(strlen(c_value) + 2);
				c_part[0] = '\t';
				strncpy(c_part + 1, c_value, strlen(c_value) + 1);
				header_add_part(js_context, self, c_part);
				free(c_part);
				free(p3);
				return JS_TRUE;
			}
			p2++;
			count++;
		} while (len + p2 - p1 < width);

		// Add tab, then header, then null terminator
		c_part = malloc(len + 1);
		c_part[0] = '\t';
		strncpy(c_part + 1, c_value, len - 1);
		c_part[len] = '\0';

		// Add this new part to header.parts
		header_add_part(js_context, self, c_part);
		c_value += len;
		free(c_part);

		len = 0;
	} while (1);

	return JS_TRUE;
}

static JSFunctionSpec SmtpHeader_functions[] = {
	JS_FS("getValue", SmtpHeader_getValue, 0, 0),
	JS_FS("toString", SmtpHeader_toString, 0, 0),
	JS_FS("refold", SmtpHeader_refold, 0, 0),
	JS_FS_END
};

/* }}} SmtpHeader */

#endif

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

#if 0

static int connect_to_address(char *host, unsigned short port)
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
		JS_ReportError(js_context, "Cannot connect to %s:%hu!", host, port);
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/* {{{ SmtpClient */

static void SmtpClient_finalize(JSFreeOp *fop, JSObject *obj);
static JSClass SmtpClient_class = {
	"SmtpClient", JSCLASS_HAS_PRIVATE, JS_PropertyStub,
	JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
	JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub,
	SmtpClient_finalize, JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpClient_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj;
	jsval host, port;

	host = JS_ARGV(cx, vp)[0];
	port = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpClient_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add host
	if (!JS_SetProperty(cx, obj, "host", &host))
		return JS_FALSE;

	// Add port
	if (!JS_SetProperty(cx, obj, "port", &port))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static void SmtpClient_finalize(JSFreeOp *fop, JSObject *obj)
{
	bfd_t *stream = (bfd_t *)JS_GetPrivate(obj);

	if (stream) {
		bfd_close(stream);
		free(stream);
	}
}

static JSBool SmtpClient_connect(JSContext *cx, unsigned argc, jsval *vp) {
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval host, port;
	char *c_host;
	int sockfd;
	int32_t num;
	bfd_t *stream;

	// Get host
	if (!JS_GetProperty(cx, self, "host", &host)) {
		return JS_FALSE;
	}

	// Get port
	if (!JS_GetProperty(cx, self, "port", &port))
		return JS_FALSE;
	if (!JS_ValueToInt32(cx, port, &num))
		return JS_FALSE;

	c_host = JS_EncodeString(cx, JSVAL_TO_STRING(host));

	sockfd = connect_to_address(c_host, num);
	// FIXME connect_to_address may fail; check return value and bail out

	stream = bfd_alloc(sockfd);
	// FIXME bfd_alloc can fail

	// FIXME client may already be connected; don't leak previous connection
	JS_SetPrivate(self, stream);

	JS_free(cx, c_host);

	return JS_TRUE;
}

static JSBool SmtpClient_disconnect(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	bfd_t *stream = JS_GetPrivate(self);

	if (!stream)
		return JS_FALSE;

	bfd_close(stream);
	free(stream);
	JS_SetPrivate(self, NULL);

	return JS_TRUE;
}

static JSBool SmtpClient_readResponse(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval content, response;
	jsval js_code, js_messages, js_disconnect;
	JSObject *messages_obj, *global;

	int code, lines_count;
	char buf[SMTP_COMMAND_MAX + 1], *p, sep;
	ssize_t sz;
	bfd_t *stream;

	stream = (bfd_t *)JS_GetPrivate(self);
	if (!stream)
		return JS_RetErrno(cx, ENOTCONN);

	global = JS_GetGlobalForScopeChain(cx);
	messages_obj = JS_NewArrayObject(cx, 0, 0);

	lines_count = 0;
	do {
		sz = 0;
		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((sz = bfd_read_line(stream, buf, SMTP_COMMAND_MAX)) <= 0)
				return JS_RetErrno(cx, EIO);
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[sz] = '\0';

		if (sz < 4)
			return JS_RetErrno(cx, EPROTO);

		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return JS_RetErrno(cx, EPROTO);
		if (code < 100 || code > 999)
			return JS_RetErrno(cx, EPROTO);

		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		if (buf[sz - 1] == '\r')
			buf[--sz] = '\0';

		//add response
		content = STRING_TO_JSVAL(JS_InternString(cx, buf + 4));
		if (!JS_SetElement(cx, messages_obj, lines_count++, &content))
			return JS_RetErrno(cx, EFAULT);
	} while (sep == '-');

	js_code = INT_TO_JSVAL(code);
	js_messages = OBJECT_TO_JSVAL(messages_obj);
	js_disconnect = JSVAL_FALSE;
	jsval argv[] = {js_code, js_messages, js_disconnect};

	JS_CallFunctionName(cx, global, "SmtpResponse",
				3, argv, &response);

	JS_SET_RVAL(cx, vp, response);
	return JS_TRUE;
}

static JSBool SmtpClient_sendCommand(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	bfd_t *stream = (bfd_t *)JS_GetPrivate(self);
	char *str;
	int status;

	if (!stream)
		return JS_RetErrno(cx, ENOTCONN);

	if (!argc)
		return JS_RetErrno(cx, EINVAL);

	str = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[0]);
	if (!str)
		return JS_RetErrno(cx, EINVAL);

	status = bfd_puts(stream, str);
	JS_free(cx, str);
	if (status < 0)
		return JS_RetErrno(cx, EIO);

	if (argc <= 1 || JSVAL_IS_VOID(JS_ARGV(cx, vp)[1]))
		goto out_flush;

	if (bfd_putc(stream, ' ') < 0)
		return JS_RetErrno(cx, EIO);

	str = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[1]);
	if (!str)
		return JS_RetErrno(cx, EINVAL);

	status = bfd_puts(stream, str);
	JS_free(cx, str);
	if (status < 0)
		return JS_RetErrno(cx, EIO);

out_flush:
	if (bfd_puts(stream, "\r\n") < 0)
		return JS_RetErrno(cx, EIO);

	if (bfd_flush(stream) < 0)
		return JS_RetErrno(cx, EIO);

	return JS_TRUE;
}

static JSBool SmtpClient_sendMessage(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	int status;
	jsval hdrs, path;
	bfd_t *client_stream, *body_stream;

	if (argc < 2)
		return JS_FALSE;

	hdrs = JS_ARGV(cx, vp)[0];
	path = JS_ARGV(cx, vp)[1];

	client_stream = (bfd_t *)JS_GetPrivate(self);
	if (!client_stream)
		return JS_FALSE;

	body_stream = smtp_body_open_read(cx, path);
	if (!body_stream)
		return JS_FALSE;

	status = smtp_copy_from_file(client_stream, body_stream, JSVAL_TO_OBJECT(hdrs), 1);

	close(body_stream->fd);
	free(body_stream);

	if (status != EIO)
		bfd_flush(client_stream);

	return !status;
}

static JSFunctionSpec SmtpClient_functions[] = {
	JS_FS("connect", SmtpClient_connect, 0, 0),
	JS_FS("disconnect", SmtpClient_disconnect, 0, 0),
	JS_FS("readResponse", SmtpClient_readResponse, 0, 0),
	JS_FS("sendCommand", SmtpClient_sendCommand, 2, 0),
	JS_FS("sendMessage", SmtpClient_sendMessage, 2, 0),
	JS_FS_END
};

/* }}} SmtpClient */

/* {{{ SmtpServer */

static JSClass SmtpServer_class = {
	"SmtpServer", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};
#endif

static int SmtpServer_construct(duk_context *ctx)
{
#if 0
	JSObject *obj;
	JSString *str;

	obj = JS_NewObjectForConstructor(cx, &SmtpServer_class, vp);
	if (!obj)
		return JS_FALSE;

	// FIXME verify argument count
	if (!JS_DefineProperty(cx, obj, PR_REMOTE_ADDR, JS_ARGV(cx, vp)[0], NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;
	if (!JS_DefineProperty(cx, obj, PR_REMOTE_PORT, JS_ARGV(cx, vp)[1], NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	// Define and set session properties
	if (!JS_DefineProperty(cx, obj, PR_HOSTNAME, JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	if (!js_init_envelope(cx, obj))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, PR_DISCONNECT, BOOLEAN_TO_JSVAL(JS_FALSE), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	str = JS_NewStringCopyZ(cx, "SMTP");
	if (!str)
		return JS_FALSE;
	if (!JS_DefineProperty(cx, obj, PR_PROTO, STRING_TO_JSVAL(str), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
#endif
	return 0;
}

#if 0
static JSBool SmtpServer_cleanup(JSContext *cx, unsigned argc, jsval *vp)
{
	return JS_TRUE;
}

static JSBool SmtpServer_receivedHeader(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	jsval v;
	char *fname = NULL, *proto = NULL, *addr = NULL;
	JSBool ret = JS_FALSE;
	struct sockaddr_in addr4 = {AF_INET};
	char phost[NI_MAXHOST], lhost[HOST_NAME_MAX];
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	JSObject *hdr;
	int err;
	const char *myid = "mailfilter"; // FIXME take from config; should be similar to EHLO id
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char ts[40];
	char *s = NULL;

	if (!JS_GetProperty(cx, self, PR_HOSTNAME, &v))
		goto out_clean;
	fname = JS_EncodeStringValue(cx, v);

	if (!JS_GetProperty(cx, self, PR_PROTO, &v))
		goto out_clean;
	proto = JS_EncodeStringValue(cx, v);

	if (!JS_GetProperty(cx, self, PR_REMOTE_ADDR, &v))
		goto out_clean;
	addr = JS_EncodeStringValue(cx, v);

	// TODO add IPv6 support
	inet_pton(AF_INET, addr, &addr4.sin_addr); // FIXME check return value
	if (getnameinfo((struct sockaddr *)&addr4, sizeof(addr4), phost, sizeof(phost), NULL, 0, NI_NAMEREQD))
		strcpy(phost, "unknown");

	if (gethostname(lhost, sizeof(lhost)))
		goto out_clean;

	hdr = header_alloc(cx, "Received");
	if (!hdr)
		goto out_clean;

	err = string_buffer_append_strings(&sb, "from ", fname ? fname :
			"unknown", " (", phost, " [", addr, "])", NULL);
	if (err)
		goto out_clean;
	if (!header_add_part(cx, hdr, sb.s))
		goto out_clean;

	string_buffer_reset(&sb);
	err = string_buffer_append_strings(&sb, "\tby ", lhost, " (",
			myid, ") with ", proto, NULL);
	if (err)
		goto out_clean;

	/* Add opt-info "ID" (if supplied as parameter #1) */
	if (argc >= 1 && (s = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[0]))) {
		if (string_buffer_append_strings(&sb, " id ", s, NULL))
			goto out_clean;
		JS_free(cx, s);
		s = NULL;
	}

	/* Add opt-info "for" (if supplied as parameter #2) */
	if (argc >= 2 && (s = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[1]))) {
		if (!header_add_part(cx, hdr, sb.s))
			goto out_clean;
		string_buffer_reset(&sb);
		if (string_buffer_append_strings(&sb, "\tfor ", s, NULL))
			goto out_clean;
		JS_free(cx, s);
		s = NULL;
	}

	err = string_buffer_append_char(&sb, ';');
	if (err)
		goto out_clean;

	if (!header_add_part(cx, hdr, sb.s))
		goto out_clean;

	strftime(ts, sizeof(ts), "%a, %e %b %Y %H:%M:%S %z (%Z)", tm);
	string_buffer_reset(&sb);
	err = string_buffer_append_strings(&sb, "\t", ts, NULL);
	if (err)
		goto out_clean;
	if (!header_add_part(cx, hdr, sb.s))
		goto out_clean;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(hdr));
	ret = JS_TRUE;

out_clean:
	string_buffer_cleanup(&sb);
	JS_free(cx, fname);
	JS_free(cx, proto);
	JS_free(cx, addr);
	JS_free(cx, s);
	return ret;
}

#define DEFINE_HANDLER_STUB(name) \
	static JSBool smtp##name (JSContext *cx, unsigned argc, jsval *vp) { \
		jsval rval = smtp_create_response(cx, 250, "def" #name, 0); \
		JS_SET_RVAL(cx, vp, rval); \
		return JS_TRUE; \
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

static JSFunctionSpec SmtpServer_functions[] = {
	JS_FS("smtpInit", smtpInit, 0, 0),
	JS_FS("smtpAuth", smtpAuth, 0, 0),
	JS_FS("smtpEhlo", smtpEhlo, 0, 0),
	JS_FS("smtpHelo", smtpHelo, 0, 0),
	JS_FS("smtpData", smtpData, 0, 0),
	JS_FS("smtpMail", smtpMail, 0, 0),
	JS_FS("smtpRcpt", smtpRcpt, 0, 0),
	JS_FS("smtpRset", smtpRset, 0, 0),
	JS_FS("smtpBody", smtpBody, 0, 0),
	JS_FS("cleanup", SmtpServer_cleanup, 0, 0),
	JS_FS("receivedHeader", SmtpServer_receivedHeader, 0, 0),
	JS_FS_END
};

/* }}} SmtpServer */

#endif
/**
 * @return 1 on success, throws error on failure
 */
duk_bool_t js_smtp_init(duk_context *ctx)
{
#if 0
	if (!JS_InitClass(cx, global, NULL, &SmtpPath_class, SmtpPath_construct, 1, NULL, SmtpPath_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpHeader_class, SmtpHeader_construct, 1, NULL, SmtpHeader_functions, NULL, NULL))
		return JS_FALSE;
#endif

	duk_push_c_function(ctx, SmtpResponse_construct, DUK_VARARGS);
	duk_put_global_string(ctx, "SmtpResponse");

#if 0
	if (!JS_InitClass(cx, global, NULL, &SmtpClient_class, SmtpClient_construct, 1, NULL, SmtpClient_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpServer_class, SmtpServer_construct, 1, NULL, SmtpServer_functions, NULL, NULL))
		return JS_FALSE;
#endif
	duk_push_c_function(ctx, SmtpServer_construct, 2);
	duk_push_object(ctx);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SmtpServer");

	return 1;
}

// vim: foldmethod=marker
