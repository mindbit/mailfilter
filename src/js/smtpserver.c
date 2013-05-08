#include "smtpserver.h"

int js_smtp_server_obj_init(JSContext *cx, JSObject *global)
{
	static JSClass smtpserver_class = {
		"smtpServer", 0, JS_PropertyStub, JS_PropertyStub,
		JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
		JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
		JSCLASS_NO_OPTIONAL_MEMBERS
	};

	JSObject *smtpserver;

	smtpserver = JS_DefineObject(cx, global, "smtpServer", &smtpserver_class, NULL, 0);
	if (!smtpserver)
		return -1;

	return 0;
}
