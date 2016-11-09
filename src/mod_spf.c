#include <arpa/inet.h>
#include <sys/types.h>
#include <spf2/spf.h>
#include <jsmisc.h>
#include <errno.h>

#include "mailfilter.h"

#define sr_js_int_prop(func, rp) \
	INT_TO_JSVAL(SPF_response_##func(rp)), \
	NULL, NULL, JSPROP_ENUMERATE

#define sr_js_str_prop(cx, func, rp) \
	STRING_TO_JSVAL(JS_NewStringCopyZ(cx, SPF_response_get_##func(rp))), \
	NULL, NULL, JSPROP_ENUMERATE

static JSObject *build_spf_response(JSContext *cx, SPF_errcode_t status, SPF_response_t *rp)
{
	JSObject *global = JS_GetGlobalForScopeChain(cx);
	JSObject *obj;
	jsval ctor;

	if (!JS_GetProperty(cx, global, "SpfResponse", &ctor))
		return NULL;

	obj = JS_New(cx, JSVAL_TO_OBJECT(ctor), 0, NULL);
	if (!obj)
		return NULL;

	if (!JS_DefineProperty(cx, obj, "status", INT_TO_JSVAL(status), NULL, NULL, JSPROP_ENUMERATE))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "result", sr_js_int_prop(result, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "reason", sr_js_int_prop(reason, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "errcode", sr_js_int_prop(errcode, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "spfRecord", sr_js_str_prop(cx, received_spf, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "spfValue", sr_js_str_prop(cx, received_spf_value, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "headerComment", sr_js_str_prop(cx, header_comment, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "smtpComment", sr_js_str_prop(cx, smtp_comment, rp)))
		return NULL;

	if (!JS_DefineProperty(cx, obj, "explanation", sr_js_str_prop(cx, explanation, rp)))
		return NULL;

	// TODO iterate through SPF_response_messages/SPF_response_message and populate array

	return obj;
}

/* {{{ SpfServer */

static void SpfServer_finalize(JSFreeOp *fop, JSObject *obj);
static JSClass SpfServer_class = {
	"SpfServer", JSCLASS_HAS_PRIVATE, JS_PropertyStub,
	JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
	JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub,
	SpfServer_finalize, JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SpfServer_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj;
	int32_t dnstype;
	SPF_server_t *server;

	if (argc < 1)
		return JS_RetErrno(cx, EINVAL);

	if (!JS_ValueToInt32(cx, JS_ARGV(cx, vp)[0], &dnstype))
		return JS_RetErrno(cx, EINVAL);

	obj = JS_NewObjectForConstructor(cx, &SpfServer_class, vp);
	if (!obj)
		return JS_RetErrno(cx, ENOMEM);

	server = SPF_server_new(dnstype, 1);
	if (!server)
		return JS_RetErrno(cx, EINVAL);

	JS_SetPrivate(obj, server);

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

static void SpfServer_finalize(JSFreeOp *fop, JSObject *obj)
{
	SPF_server_t *server = JS_GetPrivate(obj);
	if (server)
		SPF_server_free(server);
}

// FIXME de vazut ce face SPF_request_query_rcptto; eventual fac 2 metode: queryMailFrom si queryRcptTo
// TODO primeste ca param adresa si domeniul
static JSBool SpfServer_query(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *self = JSVAL_TO_OBJECT(JS_THIS(cx, vp));
	JSObject *robj;
	char *addr, *from;
	JSBool ret = JS_FALSE;
	SPF_request_t *spf_request = NULL;
	SPF_response_t  *spf_response = NULL;
	SPF_errcode_t status;

	if (argc < 2)
		return JS_RetErrno(cx, EINVAL);

	addr = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[0]);
	from = JS_EncodeStringValue(cx, JS_ARGV(cx, vp)[1]);
	if (!addr || !from) {
		JS_ReportErrno(cx, EINVAL);
		goto out_clean;
	}

	spf_request = SPF_request_new(JS_GetPrivate(self));
	if (!spf_request) {
		JS_ReportErrno(cx, ENOMEM);
		goto out_clean;
	}

	status = SPF_request_set_ipv4_str(spf_request, addr);
	if (status == SPF_E_INVALID_IP4)
		status = SPF_request_set_ipv6_str(spf_request, addr);
	if (status != SPF_E_SUCCESS) {
		JS_ReportErrno(cx, EINVAL);
		goto out_clean;
	}

	status = SPF_request_set_env_from(spf_request, from);
	if (status != SPF_E_SUCCESS) {
		JS_ReportErrno(cx, EINVAL);
		goto out_clean;
	}

	status = SPF_request_query_mailfrom(spf_request, &spf_response);
	/*
	 * The libspf2 API is messed up. Don't check status here and
	 * throw an error, because we may get status != SPF_E_SUCCESS if
	 * e.g. the domain does not exist. Check if spf_response was set
	 * instead.
	 */
	if (!spf_response) {
		JS_ReportErrno(cx, EIO);
		goto out_clean;
	}

	robj = build_spf_response(cx, status, spf_response);
	if (robj) {
		JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(robj));
		ret = JS_TRUE;
	}

out_clean:
	if (spf_response)
		SPF_response_free(spf_response);
	if (spf_request)
		SPF_request_free(spf_request);
	JS_free(cx, addr);
	JS_free(cx, from);
	return ret;
}

static JSFunctionSpec SpfServer_functions[] = {
	JS_FS("query", SpfServer_query, 0, 0),
	JS_FS_END
};

/* }}} SpfServer */

/* {{{ SpfResponse */

static JSClass SpfResponse_class = {
	"SpfResponse", 0, JS_PropertyStub, JS_PropertyStub,
	JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
	JS_ResolveStub, JS_ConvertStub, NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool SpfResponse_construct(JSContext *cx, unsigned argc, jsval *vp)
{
	JSObject *obj;

	obj = JS_NewObjectForConstructor(cx, &SpfResponse_class, vp);
	if (!obj)
		return JS_RetErrno(cx, ENOMEM);

	JS_SET_RVAL(cx, vp, OBJECT_TO_JSVAL(obj));
	return JS_TRUE;
}

/* }}} SpfResponse */

/* {{{ libspf2 Logging Handlers */

static void __attribute__((noreturn)) JS_LogSpfError(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	JS_LogImpl(JS_LOG_ERR, "[%s:%d] %s\n", file, line, errmsg);
#else
	JS_LogImpl(JS_LOG_ERR, "[%s] %s\n", file, errmsg);
#endif
	/*
	 * FIXME abort() required by libspf2, but this really should be
	 * fixed upstream - who wants to link against a library that
	 * aborts instead of returning error codes?
	 */
	abort();
}

static void JS_LogSpfWarning(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	JS_LogImpl(JS_LOG_WARNING, "[%s:%d] %s\n", file, line, errmsg);
#else
	JS_LogImpl(JS_LOG_WARNING, "[%s] %s\n", file, errmsg);
#endif
}

static void JS_LogSpfInfo(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	JS_LogImpl(JS_LOG_INFO, "[%s:%d] %s\n", file, line, errmsg);
#else
	JS_LogImpl(JS_LOG_INFO, "[%s] %s\n", file, errmsg);
#endif
}

static void JS_LogSpfDebug(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	JS_LogImpl(JS_LOG_DEBUG, "[%s:%d] %s\n", file, line, errmsg);
#else
	JS_LogImpl(JS_LOG_DEBUG, "[%s] %s\n", file, errmsg);
#endif
}

/* }}} libspf2 Logging Handlers */

#define SPF_PROP(prop) {#prop, SPF_##prop}

static const struct {
	const char *name;
	int value;
} Spf_props[] = {
	/* enum SPF_server_dnstype_enum */
	SPF_PROP(DNS_RESOLV),
	SPF_PROP(DNS_CACHE),
	SPF_PROP(DNS_ZONE),
	/* enum SPF_result_enum */
	SPF_PROP(RESULT_INVALID),
	SPF_PROP(RESULT_NEUTRAL),
	SPF_PROP(RESULT_PASS),
	SPF_PROP(RESULT_FAIL),
	SPF_PROP(RESULT_SOFTFAIL),
	SPF_PROP(RESULT_NONE),
	SPF_PROP(RESULT_TEMPERROR),
	SPF_PROP(RESULT_PERMERROR),
	/* enum SPF_reason_enum */
	SPF_PROP(REASON_NONE),
	SPF_PROP(REASON_FAILURE),
	SPF_PROP(REASON_LOCALHOST),
	SPF_PROP(REASON_LOCAL_POLICY),
	SPF_PROP(REASON_MECH),
	SPF_PROP(REASON_DEFAULT),
	SPF_PROP(REASON_2MX),
	/* enum SPF_errcode_t */
	SPF_PROP(E_SUCCESS),
	SPF_PROP(E_NO_MEMORY),
	SPF_PROP(E_NOT_SPF),
	SPF_PROP(E_SYNTAX),
	SPF_PROP(E_MOD_W_PREF),
	SPF_PROP(E_INVALID_CHAR),
	SPF_PROP(E_UNKNOWN_MECH),
	SPF_PROP(E_INVALID_OPT),
	SPF_PROP(E_INVALID_CIDR),
	SPF_PROP(E_MISSING_OPT),
	SPF_PROP(E_INTERNAL_ERROR),
	SPF_PROP(E_INVALID_ESC),
	SPF_PROP(E_INVALID_VAR),
	SPF_PROP(E_BIG_SUBDOM),
	SPF_PROP(E_INVALID_DELIM),
	SPF_PROP(E_BIG_STRING),
	SPF_PROP(E_BIG_MECH),
	SPF_PROP(E_BIG_MOD),
	SPF_PROP(E_BIG_DNS),
	SPF_PROP(E_INVALID_IP4),
	SPF_PROP(E_INVALID_IP6),
	SPF_PROP(E_INVALID_PREFIX),
	SPF_PROP(E_RESULT_UNKNOWN),
	SPF_PROP(E_UNINIT_VAR),
	SPF_PROP(E_MOD_NOT_FOUND),
	SPF_PROP(E_NOT_CONFIG),
	SPF_PROP(E_DNS_ERROR),
	SPF_PROP(E_BAD_HOST_IP),
	SPF_PROP(E_BAD_HOST_TLD),
	SPF_PROP(E_MECH_AFTER_ALL),
	SPF_PROP(E_INCLUDE_RETURNED_NONE),
	SPF_PROP(E_RECURSIVE),
	SPF_PROP(E_MULTIPLE_RECORDS),
};

JSBool mod_spf_init(JSContext *cx, JSObject *global)
{
	JSObject *obj;
	int i;

	SPF_error_handler = JS_LogSpfError;
	SPF_warning_handler = JS_LogSpfWarning;
	SPF_info_handler = JS_LogSpfInfo;
	SPF_debug_handler = JS_LogSpfDebug;

	if (!JS_InitClass(cx, global, NULL, &SpfServer_class, SpfServer_construct, 1, NULL, SpfServer_functions, NULL, NULL))
		return JS_FALSE;

	if (!JS_InitClass(cx, global, NULL, &SpfResponse_class, SpfResponse_construct, 1, NULL, NULL/* FIXME SpfResponse_functions*/, NULL, NULL))
		return JS_FALSE;

	obj = JS_NewObject(cx, NULL, NULL, NULL);
	if (!obj)
		return JS_FALSE;

	for (i = 0; i < ARRAY_SIZE(Spf_props); i++)
		if (!JS_DefineProperty(cx, obj, Spf_props[i].name, INT_TO_JSVAL(Spf_props[i].value), NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT))
			return JS_FALSE;

	if (!JS_DefineProperty(cx, global, "Spf", OBJECT_TO_JSVAL(obj), NULL, NULL, JSPROP_ENUMERATE | JSPROP_PERMANENT))
		return JS_FALSE;

	return JS_TRUE;
}

// vim: foldmethod=marker
