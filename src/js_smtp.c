#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <jsmisc.h>

#include "mailfilter.h"
#include "js_smtp.h"
#include "string_tools.h"

extern JSContext *js_context; // FIXME pass through arguments

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
	JSObject *curhdr;
	JSObject *hdrs;
	size_t max_size, curr_size;
	struct string_buffer sb;
};

#define IM_HEADER_CONTEXT_INITIALIZER {\
	.state = IM_H_NAME1,\
	.curhdr = NULL,\
	.hdrs = NULL,\
	.max_size = 0,\
	.curr_size = 0,\
	.sb = STRING_BUFFER_INITIALIZER\
}

static int add_part_to_header(JSObject *hdr, const char *c_str)
{
	jsval parts;
	JSString *js_str;

	if (!JS_GetProperty(js_context, hdr, "parts", &parts))
		return -1;

	js_str = JS_NewStringCopyZ(js_context, c_str);
	if (!js_str)
		return -1;

	if (!JS_AppendArrayElement(js_context, JSVAL_TO_OBJECT(parts), STRING_TO_JSVAL(js_str), NULL, NULL, 0))
		return -1;

	return 0;
}

/**
 * Allocate a new header and initialize the name with the contents of the
 * context string buffer.
 *
 * @return 0 on success, -1 on error
 */
static int im_header_alloc_ctx(struct im_header_context *ctx)
{
	jsval ctor, argv;
	JSObject *global, *curhdr;
	JSString *name;

	name = JS_NewStringCopyZ(js_context, ctx->sb.s);
	if (!name)
		return -1;

	global = JS_GetGlobalForScopeChain(js_context);
	if (!JS_GetProperty(js_context, global, "SmtpHeader", &ctor))
		return -1;

	argv = STRING_TO_JSVAL(name);
	curhdr = JS_New(js_context, JSVAL_TO_OBJECT(ctor), 1, &argv);
	if (!curhdr)
		return -1;

	ctx->curhdr = curhdr;
	string_buffer_reset(&ctx->sb);
	return 0;
}

/**
 * Add a folding to the "current" (currently being parsed) header. The
 * folding position is the current position in the context string buffer.
 */
static int im_header_add_fold_ctx(struct im_header_context *ctx)
{
	if (add_part_to_header(ctx->curhdr, ctx->sb.s))
		return -1;

	string_buffer_reset(&ctx->sb);
	return 0;
}

/**
 * Set the value of the "current" (currently being parsed) header to the
 * contents of the context string buffer.
 *
 * @return 0 on success, -1 on error
 */
static int im_header_set_value_ctx(struct im_header_context *ctx)
{
	if (im_header_add_fold_ctx(ctx))
		return -1;

	if (!JS_AppendArrayElement(js_context, ctx->hdrs, OBJECT_TO_JSVAL(ctx->curhdr), NULL, NULL, 0))
		return -1;

	ctx->curhdr = NULL;
	return 0;
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
		if (strchr(tab_space, c)) {
			if (!ctx->curhdr)
				return EPROTO;
			if (im_header_add_fold_ctx(ctx))
				return EINVAL;
			if (ctx->curr_size++ >= ctx->max_size)
				return EOVERFLOW;
			if (string_buffer_append_char(&ctx->sb, c))
				return ENOMEM;
			ctx->state = IM_H_FOLD;
			return EAGAIN;
		}
		if (ctx->curhdr && im_header_set_value_ctx(ctx))
			return EINVAL;

		if (c == '\n') {
			return 0;
		}
		if (c == '\r') {
			ctx->state = IM_H_FIN;
			return EAGAIN;
		}
		/* Intentionally fall back to IM_H_NAME2 */
	case IM_H_NAME2:
		if (c == ':') {
			if (im_header_alloc_ctx(ctx))
				return EINVAL;
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
		if (strchr(tab_space, c)) {
			if (string_buffer_append_char(&ctx->sb, c))
				return ENOMEM;
			return EAGAIN;
		}
		/* Intentionally fall back to IM_H_VAL1 */
	case IM_H_VAL1:
		if (strchr(tab_space, c))
			return EAGAIN;
		/* Intentionally fall back to IM_H_VAL2 */
	case IM_H_VAL2:
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
		if (c != '\n')
			return EPROTO;
		ctx->state = IM_H_NAME1;
		return EAGAIN;
	case IM_H_FIN:
		if (c != '\n')
			return EPROTO;
		return 0;
	}

	return EINVAL;
}

int smtp_copy_to_file(bfd_t *out, bfd_t *in, JSObject *hdrs)
{
	const uint64_t DOTLINE_MAGIC	= 0x0d0a2e0000;	/* <CR><LF>"."<*> */
	const uint64_t DOTLINE_MASK	= 0xffffff0000;
	const uint64_t CRLF_MAGIC	= 0x0000000d0a; /* <CR><LF> */
	const uint64_t CRLF_MASK	= 0x000000ffff;
	uint64_t buf = 0;
	int fill = 0;
	int im_state = EAGAIN, ret = EIO;
	int c;
	struct im_header_context im_hdr_ctx = IM_HEADER_CONTEXT_INITIALIZER;

	im_hdr_ctx.max_size = 65536; // FIXME use proper value
	im_hdr_ctx.hdrs = hdrs;
	while ((c = bfd_getc(in)) >= 0) {
		if (im_state == EAGAIN) {
			im_state = im_header_feed(&im_hdr_ctx, c);
			continue;
		}
		if (++fill > 8) {
			if (bfd_putc(out, buf >> 56) < 0)
				goto out_clean;
			fill = 8;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if ((buf & CRLF_MASK) == CRLF_MAGIC) {
			/* we found the EOF sequence (<CR><LF>"."<CR><LF>) */
			if (fill < 5) {
				ret = EINVAL;
				goto out_clean;
			}
			/* discard the (terminating) "."<CR><LF> */
			buf >>= 24;
			fill -= 3;
			break;
		}
		/* flush buffer up to the dot; otherwise we get false-positives for
		 * a line consisting of (only) two dots */
		if (fill < 5) {
			ret = EINVAL;
			goto out_clean;
		}
		while (fill > 3)
			if (bfd_putc(out, (buf >> (--fill * 8)) & 0xff) < 0)
				goto out_clean;
		buf &= CRLF_MASK;
		fill = 2;
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8)
		if (bfd_putc(out, (buf >> fill) & 0xff) < 0)
			goto out_clean;

	ret = im_state == EAGAIN ? 0 : im_state;

out_clean:
	string_buffer_cleanup(&im_hdr_ctx.sb);
	return ret;
}

/**
 * @param[in] dotconv Dot conversion flag. If set, a line comprising of a
 *            single dot in the input stream is converted to double dot
 *            before writing to the output stream. Additionally, a line
 *            comprising of a single dot is written to the output stream
 *            at the end. This is useful when sending a message to an
 *            SMTP server.
 */
int smtp_copy_from_file(bfd_t *out, bfd_t *in, JSObject *hdrs, int dotconv)
{
	const uint32_t DOTLINE_MAGIC	= 0x0d0a2e;	/* <CR><LF>"." */
	const uint32_t DOTLINE_MASK	= 0xffffff;
	const uint32_t CRLF_MAGIC	= 0x0d0a;	/* <CR><LF> */
	const uint32_t CRLF_MASK	= 0xffff;
	uint32_t buf = 0, hdrs_len;
	int fill = 0, needcrlf = 1;
	int c, i;
	jsval v;

	// FIXME handle dotline properly

	// Send headers
	if (!JS_GetArrayLength(js_context, hdrs, &hdrs_len))
		return JS_FALSE;

	for (i = 0; i < (int)hdrs_len; i++) {
		char *hdr;

		if (!JS_GetElement(js_context, hdrs, i, &v))
			return 1;

		JS_CallFunctionName(js_context, JSVAL_TO_OBJECT(v), "toString",
				0, NULL, &v);

		hdr = JS_EncodeString(js_context, JSVAL_TO_STRING(v));

		if (bfd_puts(out, hdr) < 0) {
			JS_free(js_context, hdr);
			return 1;
		}
		JS_free(js_context, hdr);

		if (bfd_puts(out, "\r\n") < 0)
			return 1;
	}

	// Send body
	while ((c = bfd_getc(in)) >= 0) {
		if (++fill > 4) {
			if (bfd_putc(out, buf >> 24) < 0)
				return 1;
			fill = 4;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if (bfd_putc(out, (buf >> ((fill - 1) * 8)) & 0xff) < 0)
			return 1;
		buf = (buf << 8) | '.';
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8) {
		if (fill == 8 && (buf & CRLF_MASK) == CRLF_MAGIC)
			needcrlf = 0;
		if (bfd_putc(out, (buf >> fill) & 0xff) < 0)
			return 1;
	}

	/* send termination marker */
	if (needcrlf && bfd_puts(out, "\r\n") < 0)
		return 1;
	if (bfd_puts(out, ".\r\n") < 0)
		return 1;

	return 0;
}

bfd_t *smtp_body_open_read(JSContext *cx, jsval path)
{
	char *pstr = JS_EncodeStringValue(cx, path);
	int fd;
	bfd_t *stream;

	if (!pstr)
		return NULL;

	fd = open(pstr, O_RDONLY);
	if (fd == -1) {
		JS_ReportError(js_context, "File %s cannot be opened: %d", pstr, errno);
		JS_free(cx, pstr);
		return NULL;
	}
	JS_free(cx, pstr);

	stream = bfd_alloc(fd);
	if (!stream)
		close(fd);

	return stream;
}

jsval smtp_create_response(JSContext *cx, int code, const char *message, int disconnect)
{
	jsval ctor, argv[3];
	JSString *str;
	JSObject *global, *ret;

	str = JS_NewStringCopyZ(cx, message);
	if (!str)
		return JSVAL_NULL;

	argv[0] = INT_TO_JSVAL(code);
	argv[1] = STRING_TO_JSVAL(str);
	argv[2] = BOOLEAN_TO_JSVAL(disconnect ? JS_TRUE: JS_FALSE);

	global = JS_GetGlobalForScopeChain(cx);
	if (!JS_GetProperty(js_context, global, "SmtpResponse", &ctor))
		return JSVAL_NULL;

	ret = JS_New(cx, JSVAL_TO_OBJECT(ctor), 3, argv);
	return OBJECT_TO_JSVAL(ret);
}

JSBool js_init_envelope(JSContext *cx, JSObject *obj)
{
	JSObject *recipients;

	if (!JS_DefineProperty(cx, obj, PR_SENDER, JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	recipients = JS_NewArrayObject(cx, 0, NULL);
	if (!recipients)
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, PR_RECIPIENTS, OBJECT_TO_JSVAL(recipients), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	return JS_TRUE;
}

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
	JSObject *domains, *mailbox, *rval;
	JSObject *this = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	uint32_t idx = 0;

	/* Check arguments; prepare parsed data placeholders */
	JS_SET_RVAL(cx, vp, JSVAL_NULL);

	if (!argc || !this)
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
			trail = JS_NewStringCopyZ(cx, arg);
			/* no break */
		}
		break;
	}

	if (state != S_FINAL) {
		ret = JS_TRUE;
		goto out_ret;
	}

	/* Parsing successful; save parsed data to object and return */

	rval = JS_NewObject(cx, NULL, NULL, NULL);
	if (!rval)
		goto out_ret;
	if (!JS_DefineProperty(cx, this, "trail", JS_StringToJsval(trail), NULL, NULL, JSPROP_ENUMERATE))
		goto out_ret;

	if (!JS_DefineProperty(cx, this, "domains", OBJECT_TO_JSVAL(domains), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	// Add mailbox property
	mailbox = JS_NewObject(cx, NULL, NULL, NULL);
	if (!mailbox)
		goto out_ret;

	if (!JS_DefineProperty(cx, mailbox, "local", JS_StringToJsval(local), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	if (!JS_DefineProperty(cx, mailbox, "domain", JS_StringToJsval(domain), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	if (!JS_DefineProperty(cx, this, "mailbox", OBJECT_TO_JSVAL(mailbox), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		goto out_ret;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(rval));
	ret = JS_TRUE;

out_ret:
	JS_free(cx, c_str);
	return ret;
}

static JSBool SmtpPath_toString(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval domain, local, domains, smtpPath, mailbox, rval;
	int str_len, i;
	uint32_t domains_len;

	smtpPath = JS_THIS(cx, vp);

	// Get domains
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpPath), "domains", &domains)) {
		return JS_FALSE;
	}

	// Get mailbox
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpPath), "mailbox", &mailbox)) {
		return JS_FALSE;
	}

	// Get mailbox.local
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "local", &local)) {
		return JS_FALSE;
	}
	// Get mailbox.domain
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(mailbox), "domain", &domain)) {
		return JS_FALSE;
	}

	// +1 for "@"
	str_len = JS_GetStringLength(JSVAL_TO_STRING(local))
			+ JS_GetStringLength(JSVAL_TO_STRING(domain))
			+ 1;

	// Get number of domains
	if (!JS_GetArrayLength(cx, JSVAL_TO_OBJECT(domains), &domains_len)) {
		return -1;
	}

	for (i = 0; i < (int) domains_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(domains), i, &rval)) {
			return -1;
		}

		str_len += JS_GetStringLength(JSVAL_TO_STRING(rval));
	}

	// Add space for "@" * domains_len and "," * (domains_len - 1)
	str_len += 2 * domains_len - 1;

	// Add space for "<", ">" and ":"
	str_len += 3;

	char *c_str = malloc(str_len + 1);

	strcpy(c_str, "<");

	for (i = 0; i < domains_len; i++) {
		if (!JS_GetElement(cx, JSVAL_TO_OBJECT(domains), i, &rval)) {
			return -1;
		}

		strcat(c_str, "@");
		strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(rval)));

		if (domains_len != 1 && i < domains_len - 1) {
			strcat(c_str, ",");
		}
	}

	if (domains_len > 0) {
		strcat(c_str, ":");
	}

	// FIXME if (mailbox is not null)
	strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(local)));

	strcat(c_str, "@");

	strcat(c_str, JS_EncodeString(cx, JSVAL_TO_STRING(domain)));
	// FIXME endif

	strcat(c_str, ">");

	strcat(c_str, "\0");

	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(JS_InternString(cx, c_str)));

	free(c_str);

	return JS_TRUE;
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
	jsval parts, rval;
	jsval header;

	uint32_t parts_len, header_len;
	int i;
	char *c_str, *header_no_wsp;

	// Get header
	header = JS_THIS(cx, vp);

	// Get parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts)) {
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
	jsval rval, name, parts, part;
	uint32_t parts_len;
	int i;

	jsval header = JS_THIS(cx, vp);
	// Get name
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "name", &name)) {
		return JS_FALSE;
	}

	// Get parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts)) {
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
	jsval name, value, parts, header;
	int width, len;
	char /* *c_name, */ *c_value, *p1, *p2, *p3, *c_part;

	width = JSVAL_TO_INT(JS_ARGV(cx, vp)[0]);
	header = JS_THIS(cx, vp);

	// Get name
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "name", &name)) {
		return JS_FALSE;
	}

	// Get value
	if (SmtpHeader_getValue(cx, argc, vp)) {
		value = *vp;
	}

	// Delete header parts
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(header), "parts", &parts))
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
				add_part_to_header(JSVAL_TO_OBJECT(header), c_part);
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
		add_part_to_header(JSVAL_TO_OBJECT(header), c_part);
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

/* {{{ SmtpResponse */

static JSClass SmtpResponse_class = {
	"SmtpResponse", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SmtpResponse_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval code, messages, disconnect;
	jsval aux;
	JSObject *obj, *messages_arr;

	code = JS_ARGV(cx, vp)[0];
	messages = JS_ARGV(cx, vp)[1];
	disconnect = JS_ARGV(cx, vp)[2];

	obj = JS_NewObjectForConstructor(cx, &SmtpResponse_class, vp);
	if (!obj)
		return JS_FALSE;

	// Add code property
	if (!JS_SetProperty(cx, obj, "code", &code))
		return JS_FALSE;

	// Add messages property
	switch(JS_TypeOfValue(cx, messages)) {
	case JSTYPE_STRING:
		// Create the messages array property
		messages_arr = JS_NewArrayObject(cx, 0, NULL);

		if (!messages_arr)
			return JS_FALSE;

		// Add message to messages array
		if (!JS_SetElement(cx, messages_arr, 0, &messages))
			return JS_FALSE;

		// Copy the messages to the property
		aux = OBJECT_TO_JSVAL(messages_arr);
		if (!JS_SetProperty(cx, obj, "messages", &aux))
			return JS_FALSE;

		break;
	case JSTYPE_OBJECT:
		// Copy the messages to the property
		if (!JS_SetProperty(cx, obj, "messages", &messages))
			return JS_FALSE;

		break;
	default:
		return JS_FALSE;
	}

	// Add disconnect property
	if (!JS_SetProperty(cx, obj, "disconnect", &disconnect))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

/* }}} SmtpResponse */

static int connect_to_address(char *ip, char *port)
{
	int sockfd, portno;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	portno = atoi(port);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		// throw exc
		printf("sock failed\n");
		return -1;
	}

	server = gethostbyname(ip);

	if (!server) {
		// throw exc
		printf("server failed\n");
	}

	bzero((char*) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;

	bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		JS_ReportError(js_context, "Cannot connect to %s:%s!", ip, port);
		return -1;
	}

	return sockfd;
}

/* {{{ SmtpClient */

static JSClass SmtpClient_class = {
	"SmtpClient", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
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

static JSBool SmtpClient_connect(JSContext *cx, unsigned argc, jsval *vp) {
	jsval host, port, client, clientStream;
	char *c_host, *c_port;
	int sockfd;
	bfd_t *client_stream;

	client = JS_THIS(cx, vp);

	// Get host
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(client), "host", &host)) {
		return JS_FALSE;
	}

	// Get port
	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(client), "port", &port)) {
		return JS_FALSE;
	}

	c_host = JS_EncodeString(cx, JSVAL_TO_STRING(host));
	c_port = JS_EncodeString(cx, JSVAL_TO_STRING(port));

	sockfd = connect_to_address(c_host, c_port);

	client_stream = bfd_alloc(sockfd);
	clientStream = PRIVATE_TO_JSVAL(client_stream);

	if (!JS_SetProperty(cx, JSVAL_TO_OBJECT(client), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	free(c_host);
	free(c_port);

	return JS_TRUE;
}

static JSBool SmtpClient_readResponse(JSContext *cx, unsigned argc, jsval *vp) {
	jsval smtpClient, content, response, clientStream;
	jsval js_code, js_messages, js_disconnect;
	JSObject *messages_obj, *global;

	int code, lines_count;
	char buf[SMTP_COMMAND_MAX + 1], *p, sep;
	ssize_t sz;
	bfd_t *client_stream;

	global = JS_GetGlobalForScopeChain(cx);
	smtpClient = JS_THIS(cx, vp);
	messages_obj = JS_NewArrayObject(cx, 0, 0);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "clientStream", &clientStream)) {
		return JS_FALSE;
	}

	client_stream = JSVAL_TO_PRIVATE(clientStream);

	lines_count = 0;
	do {
		sz = 0;
		do {
			buf[SMTP_COMMAND_MAX] = '\n';
			if ((sz = bfd_read_line(client_stream, buf, SMTP_COMMAND_MAX)) <= 0)
				return JS_FALSE;
		} while (buf[SMTP_COMMAND_MAX] != '\n');
		buf[sz] = '\0';

		if (sz < 4)
			return JS_FALSE;

		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return JS_FALSE;
		if (code < 100 || code > 999)
			return JS_FALSE;

		if (buf[sz - 1] == '\n')
			buf[--sz] = '\0';
		if (buf[sz - 1] == '\r')
			buf[--sz] = '\0';

		//add response
		content = STRING_TO_JSVAL(JS_InternString(cx, buf + 4));
		if (!JS_SetElement(cx, messages_obj, lines_count++, &content)) {
			return -1;
		}
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

static JSBool SmtpClient_sendCommand(JSContext *cx, unsigned argc, jsval *vp) {
	jsval command, arg = JSVAL_NULL, smtpClient, clientStream;
	char *str;
	bfd_t *client_stream;
	// FIXME don't use "sb"; write directly to stream because it's
	// buffered anyway
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;

	command = JS_ARGV(cx, vp)[0];

	if (argc > 1)
		arg = JS_ARGV(cx, vp)[1];

	smtpClient = JS_THIS(cx, vp);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(smtpClient), "clientStream", &clientStream))
		return JS_FALSE;
	client_stream = JSVAL_TO_PRIVATE(clientStream);

	// Add command name
	if (!JSVAL_IS_STRING(command))
		return JS_FALSE;
	str = JS_EncodeString(cx, JSVAL_TO_STRING(command));
	if (string_buffer_append_string(&sb, str))
		goto out_err_free;
	JS_free(cx, str);

	if (string_buffer_append_char(&sb, ' '))
		goto out_err;

	if (JSVAL_IS_STRING(arg)) {
		str = JS_EncodeString(cx, JSVAL_TO_STRING(arg));
		if (str && string_buffer_append_string(&sb, str))
			goto out_err_free;
		JS_free(cx, str);
	}

	if (string_buffer_append_string(&sb, "\r\n"))
		goto out_err;

	if (bfd_puts(client_stream, sb.s) < 0) {
		goto out_err;
	}

	bfd_flush(client_stream);
	string_buffer_cleanup(&sb);

	return JS_TRUE;

out_err_free:
	JS_free(cx, str);
out_err:
	string_buffer_cleanup(&sb);
	bfd_close(client_stream);
	free(client_stream);
	return JS_FALSE;
}

static JSBool SmtpClient_sendMessage(JSContext *cx, unsigned argc, jsval *vp) {
	JSBool ret;
	jsval hdrs, path, self, v;
	bfd_t *client_stream, *body_stream;

	if (argc < 2)
		return JS_FALSE;

	hdrs = JS_ARGV(cx, vp)[0];
	path = JS_ARGV(cx, vp)[1];
	self = JS_THIS(cx, vp);

	if (!JS_GetProperty(cx, JSVAL_TO_OBJECT(self), "clientStream", &v))
		return JS_FALSE;
	client_stream = JSVAL_TO_PRIVATE(v);

	body_stream = smtp_body_open_read(cx, path);
	if (!body_stream)
		return JS_FALSE;

	ret = !smtp_copy_from_file(client_stream, body_stream, JSVAL_TO_OBJECT(hdrs), 1);

	close(body_stream->fd);
	free(body_stream);

	if (ret)
		bfd_flush(client_stream);

	return ret;
}

static JSFunctionSpec SmtpClient_functions[] = {
	JS_FS("connect", SmtpClient_connect, 2, 0),
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

static JSBool SmtpServer_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj;
	//jsval host, port, client;

	//host = JS_ARGV(cx, vp)[0];
	//port = JS_ARGV(cx, vp)[1];

	obj = JS_NewObjectForConstructor(cx, &SmtpServer_class, vp);
	if (!obj)
		return JS_FALSE;

	// Define and set session properties
	if (!JS_DefineProperty(cx, obj, PR_HOSTNAME, JSVAL_NULL, NULL, NULL, JSPROP_ENUMERATE))
		return JS_FALSE;

	if (!js_init_envelope(cx, obj))
		return JS_FALSE;

	if (!JS_DefineProperty(cx, obj, PR_DISCONNECT, BOOLEAN_TO_JSVAL(JS_FALSE), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
		return JS_FALSE;

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
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
DEFINE_HANDLER_STUB(Clnp);

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
	JS_FS("smtpClnp", smtpClnp, 0, 0),
	JS_FS_END
};

/* }}} SmtpServer */

JSBool js_smtp_init(JSContext *cx, JSObject *global)
{
	if (!JS_InitClass(cx, global, NULL, &SmtpPath_class, SmtpPath_construct, 1, NULL, SmtpPath_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpHeader_class, SmtpHeader_construct, 1, NULL, SmtpHeader_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpResponse_class, SmtpResponse_construct, 1, NULL, NULL, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpClient_class, SmtpClient_construct, 1, NULL, SmtpClient_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SmtpServer_class, SmtpServer_construct, 1, NULL, SmtpServer_functions, NULL, NULL))
		return JS_FALSE;

	return JS_TRUE;
}

// vim: foldmethod=marker
