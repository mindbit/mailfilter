#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include "js.h"

int js_smtp_server_obj_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval create_response(JSContext *cx, int status, const char* message, int disconnect);

// Define C stub functions
#define DEFINE_HANDLER_STUB(name) \
	static JSBool smtp##name (JSContext *cx, unsigned argc, jsval *vp) { \
		jsval rval = create_response(cx, 250, "def" #name, 0); \
		JS_SET_RVAL(cx, vp, rval); \
		return JS_TRUE; \
	} \

#endif
