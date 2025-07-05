#include <syslog.h>
#include <jsmisc.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "mailfilter.h"

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

	js_log(LOG_INFO, "[STUB] Loading module \"%s\"\n", module_name);

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

#if 0
static const duk_number_list_entry Sys_props[] = {
	{NULL,			0.0}
};
#endif

static duk_function_list_entry Sys_functions[] = {
	{"loadModule",	Sys_loadModule,	1},
	{NULL,		NULL,		0}
};

duk_bool_t js_sys_get_prop(duk_context *ctx, const char *name)
{
	duk_bool_t ret;

	if (!duk_get_global_string(ctx, "Sys"))
		return 0;

	ret = duk_get_prop_string(ctx, -1, name);
	duk_remove(ctx, -2);

	return ret;
}

/**
 * @return 1 on success, throws error on failure
 */
duk_bool_t js_sys_init(duk_context *ctx)
{
	struct passwd *passwd;

	duk_push_object(ctx);
#if 0
	duk_put_number_list(ctx, -1, Sys_props);
#endif
	duk_put_function_list(ctx, -1, Sys_functions);

	if ((passwd = getpwuid(geteuid()))) {
		duk_push_string(ctx, passwd->pw_name);
		duk_put_prop_string(ctx, -2, "user");
	}

	duk_put_global_string(ctx, "Sys");
	return 1;
}
