#include <arpa/inet.h>
#include <sys/types.h>
#include <spf2/spf.h>
#include <jsmisc.h>
#include <errno.h>

#include "mailfilter.h"

/* {{{ SpfServer */

static int SpfServer_construct(duk_context *ctx)
{
	SPF_server_t *server;

	if (duk_is_undefined(ctx, 0))
		return js_ret_errno(ctx, EINVAL);

	server = SPF_server_new(duk_to_int32(ctx, 0), 1);
	if (!server)
		return js_ret_errno(ctx, EINVAL);

	duk_push_this(ctx);
	duk_push_pointer(ctx, server);
	duk_put_prop_string(ctx, -2, "server");
	duk_pop(ctx);

	return 0;
}

static int SpfServer_finalize(duk_context *ctx)
{
	SPF_server_t *server = NULL;

	duk_push_this(ctx);
	if (duk_get_prop_string(ctx, -1, "server")) {
		server = duk_get_pointer(ctx, -1);
	}
	duk_pop_2(ctx);

	if (server)
		SPF_server_free(server);

	return 0;
}

static duk_bool_t __build_spf_response(duk_context *ctx, SPF_errcode_t status, SPF_response_t *rp)
{
	int msglen, i;

	if (!duk_get_global_string(ctx, "SpfResponse")) {
		duk_pop(ctx);
		return 0;
	}

	duk_new(ctx, 0);

	duk_push_int(ctx, status);
	duk_put_prop_string(ctx, -2, "status");

	duk_push_int(ctx, SPF_response_result(rp));
	duk_put_prop_string(ctx, -2, "result");

	duk_push_int(ctx, SPF_response_reason(rp));
	duk_put_prop_string(ctx, -2, "reason");

	duk_push_int(ctx, SPF_response_errcode(rp));
	duk_put_prop_string(ctx, -2, "errcode");

	duk_push_string(ctx, SPF_response_get_received_spf(rp));
	duk_put_prop_string(ctx, -2, "spfRecord");

	duk_push_string(ctx, SPF_response_get_received_spf_value(rp));
	duk_put_prop_string(ctx, -2, "spfValue");

	duk_push_string(ctx, SPF_response_get_header_comment(rp));
	duk_put_prop_string(ctx, -2, "headerComment");

	duk_push_string(ctx, SPF_response_get_smtp_comment(rp));
	duk_put_prop_string(ctx, -2, "smtpComment");

	duk_push_string(ctx, SPF_response_get_explanation(rp));
	duk_put_prop_string(ctx, -2, "explanation");

	duk_push_array(ctx);
	msglen = SPF_response_messages(rp);
	for (i = 0; i < msglen; i++) {
		SPF_error_t *e = SPF_response_message(rp, i);

		duk_push_object(ctx);

		duk_push_int(ctx, SPF_error_code(e));
		duk_put_prop_string(ctx, -2, "code");

		duk_push_string(ctx, SPF_error_message(e));
		duk_put_prop_string(ctx, -2, "message");

		duk_push_boolean(ctx, SPF_error_errorp(e));
		duk_put_prop_string(ctx, -2, "isError");

		duk_put_prop_index(ctx, -2, i);
	}
	duk_put_prop_string(ctx, -2, "errors");

	return 1;
}

// FIXME de vazut ce face SPF_request_query_rcptto; eventual fac 2 metode: queryMailFrom si queryRcptTo
// TODO primeste ca param adresa si domeniul
static int SpfServer_query(duk_context *ctx)
{
	const char *addr, *from;
	SPF_server_t *server;
	SPF_request_t *spf_request;
	SPF_response_t  *spf_response = NULL;
	SPF_errcode_t status;
	duk_bool_t robj;

	duk_push_this(ctx);

	if (!duk_get_prop_string(ctx, -1, "server"))
		return js_ret_errno(ctx, EFAULT);
	server = duk_get_pointer(ctx, -1);

	if (duk_is_undefined(ctx, 0) || duk_is_undefined(ctx, 1))
		return js_ret_errno(ctx, EINVAL);

	addr = duk_to_string(ctx, 0);
	from = duk_to_string(ctx, 1);

	spf_request = SPF_request_new(server);
	if (!spf_request)
		return js_ret_errno(ctx, ENOMEM);

	status = SPF_request_set_ipv4_str(spf_request, addr);
	if (status == SPF_E_INVALID_IP4)
		status = SPF_request_set_ipv6_str(spf_request, addr);
	if (status != SPF_E_SUCCESS) {
		SPF_request_free(spf_request);
		return js_ret_errno(ctx, EINVAL);
	}

	status = SPF_request_set_env_from(spf_request, from);
	if (status != SPF_E_SUCCESS) {
		SPF_request_free(spf_request);
		return js_ret_errno(ctx, EINVAL);
	}

	status = SPF_request_query_mailfrom(spf_request, &spf_response);
	/*
	 * The libspf2 API is messed up. Don't check status here and
	 * throw an error, because we may get status != SPF_E_SUCCESS if
	 * e.g. the domain does not exist. Instead, check if spf_response
	 * has been set.
	 */
	if (!spf_response) {
		SPF_request_free(spf_request);
		return js_ret_errno(ctx, EIO);
	}

	robj = __build_spf_response(ctx, status, spf_response);
	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	if (!robj)
		return js_ret_error(ctx, "SpfResponse is not defined");

	return 1;
}

static duk_function_list_entry SpfServer_functions[] = {
	{"query",	SpfServer_query, 	2},
	{NULL,		NULL,			0}
};

/* }}} SpfServer */

/* {{{ SpfResponse */

static int SpfResponse_construct(duk_context *ctx)
{
	return 0;
}

/* }}} SpfResponse */

/* {{{ Spf */

#define SPF_PROP(prop) {#prop, SPF_##prop}

static const duk_number_list_entry Spf_props[] = {
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
	{NULL, 0.0}
};

/* }}} Spf */

/* {{{ libspf2 Logging Handlers */

static void __attribute__((noreturn)) js_log_spf_error(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	js_log_impl(JS_LOG_ERR, "[%s:%d] %s\n", file, line, errmsg);
#else
	jS_log_impl(JS_LOG_ERR, "[%s] %s\n", file, errmsg);
#endif
	/*
	 * FIXME abort() required by libspf2, but this really should be
	 * fixed upstream - who wants to link against a library that
	 * aborts instead of returning error codes?
	 */
	abort();
}

static void js_log_spf_warning(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	js_log_impl(JS_LOG_WARNING, "[%s:%d] %s\n", file, line, errmsg);
#else
	js_log_impl(JS_LOG_WARNING, "[%s] %s\n", file, errmsg);
#endif
}

static void js_log_spf_info(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	js_log_impl(JS_LOG_INFO, "[%s:%d] %s\n", file, line, errmsg);
#else
	js_log_impl(JS_LOG_INFO, "[%s] %s\n", file, errmsg);
#endif
}

static void js_log_spf_debug(const char *file, int line, const char *errmsg)
{
#ifdef JS_DEBUG
	js_log_impl(JS_LOG_DEBUG, "[%s:%d] %s\n", file, line, errmsg);
#else
	js_log_impl(JS_LOG_DEBUG, "[%s] %s\n", file, errmsg);
#endif
}

/* }}} libspf2 Logging Handlers */

duk_bool_t mod_spf_init(duk_context *ctx)
{
	SPF_error_handler = js_log_spf_error;
	SPF_warning_handler = js_log_spf_warning;
	SPF_info_handler = js_log_spf_info;
	SPF_debug_handler = js_log_spf_debug;

	duk_push_c_function(ctx, SpfServer_construct, 1);
	duk_push_object(ctx);
	duk_push_c_function(ctx, SpfServer_finalize, 2);
	duk_set_finalizer(ctx, -2);
	duk_put_function_list(ctx, -1, SpfServer_functions);
	duk_put_prop_string(ctx, -2, "prototype");
	duk_put_global_string(ctx, "SpfServer");

	duk_push_c_function(ctx, SpfResponse_construct, 0);
	duk_put_global_string(ctx, "SpfResponse");

	duk_push_object(ctx);
	duk_put_number_list(ctx, -1, Spf_props);
	duk_put_global_string(ctx, "Spf");

	return 1;
}

// vim: foldmethod=marker
