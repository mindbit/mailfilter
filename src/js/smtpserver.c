#include "smtpserver.h"

jsval create_response(JSContext *cx, int code, const char* message, int disconnect) { 
	jsval rcode;
	jsval rmessage;
	JSObject *obj;
	jsval rdisconnect; 	// better name? 
				
	rcode = INT_TO_JSVAL(code);
	rdisconnect = disconnect == TRUE ? JSVAL_TRUE : JSVAL_FALSE;
	
	obj = JS_NewObject(cx, NULL, NULL, NULL);
	
	if (message != NULL) {
		rmessage = STRING_TO_JSVAL(JS_InternString(cx, message));
	} else {
		// TODO
		// define message property with default value for current code
		rmessage = STRING_TO_JSVAL(JS_InternString(cx, "default err message"));
	}
	
	JS_DefineProperty(cx, obj, "code", rcode, NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	JS_DefineProperty(cx, obj, "message", rmessage, NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	JS_DefineProperty(cx, obj, "disconnect", rdisconnect, NULL, NULL, JSPROP_ENUMERATE | JSPROP_READONLY | JSPROP_PERMANENT);
	
	return OBJECT_TO_JSVAL(obj);
}

JSBool smtpInit(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cInit", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAuth(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAuth", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAlou(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAlou", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpAlop(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cAlop", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpEhlo(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cEhlo", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpData(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cData", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpMail(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cMail", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpRcpt(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cRcpt", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpRset(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cRset", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpQuit(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cQuit", FALSE);

	JS_SET_RVAL(cx, vp, rval);

	return JS_TRUE;
}

JSBool smtpBody(JSContext *cx, unsigned argc, jsval *vp) {
        jsval rval = create_response(cx, 250, "cBody", FALSE);

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
