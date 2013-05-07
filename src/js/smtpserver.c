#include "smtpserver.h"

int js_smtp_server_parse(JSContext *cx, JSObject *global)
{
	jsval server_val;

	if (!JS_GetProperty(cx, global, "engine", &server_val))
		return -1;

	return 0;
}

static JSClass smtp_server_class = {
	"smtpServer", 0, JS_PropertyStub, JS_PropertyStub, JS_PropertyStub,
	JS_StrictPropertyStub, JS_EnumerateStub, JS_ResolveStub,
	JS_ConvertStub, JS_FinalizeStub, JSCLASS_NO_OPTIONAL_MEMBERS
};

int js_smtp_server_obj_init(JSContext *cx, JSObject *global)
{
	JSObject *smtp_server;

	smtp_server = JS_DefineObject(cx, global, "smtpServer", &smtp_server_class, NULL, 0);
	if (!smtp_server)
		return -1;

	return 0;
}
