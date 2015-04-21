#include "smtpserver.h"

jsval create_response(JSContext *cx, int status, const char* message) { 
	JSObject* response = JS_NewArrayObject(cx, 2, NULL);

	jsval rstatus = INT_TO_JSVAL(status);
	jsval rstr = STRING_TO_JSVAL(JS_InternString(cx, message));
	JS_SetElement(cx, response, 0, &rstatus);
	JS_SetElement(cx, response, 1, &rstr);

	return OBJECT_TO_JSVAL(response);
}

JSBool smtpInit(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cInit");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAuth(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAuth");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAlou(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAlou");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAlop(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAlop");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpEhlo(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cEhlo");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpData(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cData");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpMail(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cMail");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpRcpt(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cRcpt");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpRset(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cRset");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpQuit(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cQuit");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpBody(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cBody");

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}


int js_smtp_server_obj_init(JSContext *cx, JSObject *global)
{
	static JSClass smtpserver_class = {
		"smtpServer", 0, JS_PropertyStub, JS_PropertyStub,
		JS_PropertyStub, JS_StrictPropertyStub, JS_EnumerateStub,
		JS_ResolveStub, JS_ConvertStub, JS_PropertyStub,
		JSCLASS_NO_OPTIONAL_MEMBERS
	};

	JSObject *smtpServer;

	smtpServer = JS_DefineObject(cx, global, "smtpServer", &smtpserver_class, NULL, 0);
	if (!smtpServer)
		return -1;

	JSFunctionSpec smtp_command_handlers[] = {
		JS_FS("smtpInit", smtpInit, 0, 0),
		JS_FS("smtpAlou", smtpAlou, 0, 0),
		JS_FS("smtpAlop", smtpAlop, 0, 0),
		JS_FS("smtpEhlo", smtpEhlo, 0, 0),
		JS_FS("smtpData", smtpData, 0, 0),
		JS_FS("smtpMail", smtpMail, 0, 0),
		JS_FS("smtpRcpt", smtpRcpt, 0, 0),
		JS_FS("smtpRset", smtpRset, 0, 0),
		JS_FS("smtpBody", smtpBody, 0, 0),
		JS_FS("smtpQuit", smtpQuit, 0, 0),
		JS_FS_END
	};

	if (JS_DefineFunctions(cx, smtpServer, smtp_command_handlers) == JS_FALSE) {
		return -1;
	}

	return 0;
}
