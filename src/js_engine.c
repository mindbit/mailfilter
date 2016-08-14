#include <syslog.h>
#include <jsmisc.h>

#include "mailfilter.h"

static JSBool Engine_openlog(JSContext *cx, unsigned argc, jsval *vp)
{
	static char ident[40] = "mailfilter";
	size_t len = sizeof(ident) - 1;
	int facility = LOG_DAEMON;

	if (argc >= 1) {
		JSString *str = JSVAL_TO_STRING(JS_ARGV(cx, vp)[0]);
		len = JS_EncodeStringToBuffer(str, ident, len);
		if (len < 0 || len >= sizeof(ident))
			len = sizeof(ident) - 1;
		ident[len] = '\0';
	}

	if (argc >= 2)
		JS_ValueToECMAInt32(cx, JS_ARGV(cx, vp)[1], &facility);

	openlog(ident, LOG_PID, facility);

	// FIXME for better portability, do not pass vsyslog directly;
	// instead create a wrapper function that translates priority
	// from JS_LOG_* to LOG_*
	JS_LogSetCallback(vsyslog);

	return JS_TRUE;
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

static JSBool Engine_loadModule(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval module;
	JSString *module_str;
	char *module_name;

	module = JS_ARGV(cx, vp)[0];

	if (!JSVAL_IS_STRING(module))
		return JS_FALSE;

	module_str = JSVAL_TO_STRING(module);
	module_name = JS_EncodeString(cx, module_str);
	if (!module_name)
		return JS_FALSE;

	JS_Log(JS_LOG_INFO, "[STUB] Loading module \"%s\".\n", module_name);

	JS_free(cx, module_name);
	return JS_TRUE;
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

static JSClass Engine_class = {
	"Engine", 0, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	JS_StrictPropertyStub, JS_EnumerateStub, JS_ResolveStub,
	JS_ConvertStub, NULL, JSCLASS_NO_OPTIONAL_MEMBERS
};

static const struct {
	const char *name;
	int value;
} Engine_props[] = {
	// syslog facilities
	{"LOG_DAEMON",	LOG_DAEMON },
	{"LOG_USER",	LOG_USER },
	{"LOG_MAIL",	LOG_MAIL },
	{"LOG_LOCAL0",	LOG_LOCAL0},
	{"LOG_LOCAL1",	LOG_LOCAL1},
	{"LOG_LOCAL2",	LOG_LOCAL2},
	{"LOG_LOCAL3",	LOG_LOCAL3},
	{"LOG_LOCAL4",	LOG_LOCAL4},
	{"LOG_LOCAL5",	LOG_LOCAL5},
	{"LOG_LOCAL6",	LOG_LOCAL6},
	{"LOG_LOCAL7",	LOG_LOCAL7},
	// syslog priorities
	{"LOG_EMERG",	LOG_EMERG},
	{"LOG_ALERT",	LOG_ALERT},
	{"LOG_CRIT",	LOG_CRIT},
	{"LOG_ERR",	LOG_ERR},
	{"LOG_WARNING",	LOG_WARNING},
	{"LOG_NOTICE",	LOG_NOTICE},
	{"LOG_INFO",	LOG_INFO},
	{"LOG_DEBUG",	LOG_DEBUG},
};

static JSFunctionSpec Engine_functions[] = {
	JS_FS("openlog", Engine_openlog, 2, 0),
	JS_FS("loadModule", Engine_loadModule, 1, 0),
	JS_FS_END
};

int js_engine_init(JSContext *cx, JSObject *global)
{
	JSObject *engine;
	unsigned i;

	engine = JS_DefineObject(cx, global, Engine_class.name, &Engine_class, NULL, 0);
	if (!engine)
		return -1;

	if (!JS_DefineFunctions(cx, engine, Engine_functions))
		return -1;

	for (i = 0; i < ARRAY_SIZE(Engine_props); i++) {
		JSBool status = JS_DefineProperty(cx, engine,
				Engine_props[i].name,
				INT_TO_JSVAL(Engine_props[i].value),
				NULL, NULL,
				JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
		if (!status)
			return -1;
	}

	return 0;
}
