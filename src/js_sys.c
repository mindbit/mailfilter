#include <syslog.h>
#include <jsmisc.h>

#include "mailfilter.h"

static int Sys_openlog(duk_context *ctx)
{
	int argc = duk_get_top(ctx);
	const char *ident = "mailfilter";
	int facility = LOG_MAIL;

	if (argc >= 1)
		ident = duk_safe_to_string(ctx, 0);

	if (argc >= 2)
		facility = duk_to_int(ctx, 1);

	openlog(ident, LOG_PID, facility);

	// FIXME for better portability, do not pass vsyslog directly;
	// instead create a wrapper function that translates priority
	// from JS_LOG_* to LOG_*
	js_log_set_callback(vsyslog);

	return 0;
}

#if 0
static JSBool debug_protocol_hdlr(JSContext *cx, JSObject *obj, jsval *vp)
{
	/* Check if debugProtocol was assigned a boolean value */
	if (!JSVAL_IS_BOOLEAN(*vp))
		return JS_FALSE;

	if (JSVAL_TO_BOOLEAN(*vp) == JS_TRUE)
		config.smtp_debug = 1;
	else
		config.smtp_debug = 0;

	return JS_TRUE;
}
#endif

static int Sys_loadModule(duk_context *ctx)
{
	const char *module_name = duk_safe_to_string(ctx, 0);

	js_log(JS_LOG_INFO, "[STUB] Loading module \"%s\"\n", module_name);

	return 0;
}

#if 0
/* Handles the engine object after the script finished executing */
int js_engine_parse(JSContext *cx, JSObject *global)
{
	JSObject *engine;
	jsval engine_val, prop_val;

	if (!JS_GetProperty(cx, global, "engine", &engine_val))
		return -1;
	engine = JSVAL_TO_OBJECT(engine_val);

	/* Parse 'debugProtocol' property. */
	if (!JS_GetProperty(cx, engine, "debugProtocol", &prop_val))
		return -1;
	if (!debug_protocol_hdlr(cx, global, &prop_val))
		return -1;

	return 0;
}
#endif

static const duk_number_list_entry Sys_props[] = {
	// syslog facilities
	{"SYSLOG_DAEMON",	LOG_DAEMON },
	{"SYSLOG_USER",		LOG_USER },
	{"SYSLOG_MAIL",		LOG_MAIL },
	{"SYSLOG_LOCAL0",	LOG_LOCAL0},
	{"SYSLOG_LOCAL1",	LOG_LOCAL1},
	{"SYSLOG_LOCAL2",	LOG_LOCAL2},
	{"SYSLOG_LOCAL3",	LOG_LOCAL3},
	{"SYSLOG_LOCAL4",	LOG_LOCAL4},
	{"SYSLOG_LOCAL5",	LOG_LOCAL5},
	{"SYSLOG_LOCAL6",	LOG_LOCAL6},
	{"SYSLOG_LOCAL7",	LOG_LOCAL7},
#if 0
	// syslog priorities
	{"SYSLOG_EMERG",	LOG_EMERG},
	{"SYSLOG_ALERT",	LOG_ALERT},
	{"SYSLOG_CRIT",		LOG_CRIT},
	{"SYSLOG_ERR",		LOG_ERR},
	{"SYSLOG_WARNING",	LOG_WARNING},
	{"SYSLOG_NOTICE",	LOG_NOTICE},
	{"SYSLOG_INFO",		LOG_INFO},
	{"SYSLOG_DEBUG",	LOG_DEBUG},
#endif
	{NULL,			0.0}
};

static duk_function_list_entry Sys_functions[] = {
	{"openlog",	Sys_openlog, 	DUK_VARARGS},
	{"loadModule",	Sys_loadModule,	1},
	{NULL,		NULL,		0}
};

/**
 * @return 1 on success, throws error on failure
 */
duk_bool_t js_sys_init(duk_context *ctx)
{
	duk_push_object(ctx);
	duk_put_number_list(ctx, -1, Sys_props);
	duk_put_function_list(ctx, -1, Sys_functions);

	duk_put_global_string(ctx, "Sys");
	return 1;
}
