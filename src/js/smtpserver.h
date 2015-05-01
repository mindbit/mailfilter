#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include "js.h"

int js_smtp_server_obj_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval create_response(JSContext *cx, int status, const char* message, int disconnect);

// C stub handlers
static JSBool smtpInit(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpAuth(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpAlou(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpAlop(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpEhlo(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpData(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpMail(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpRcpt(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpRset(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpQuit(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpBody(JSContext *cx, unsigned argc, jsval *vp);

// Define C stub functions
#define DEFINE_HANDLER_STUB(name) \
	static JSBool smtp##name (JSContext *cx, unsigned argc, jsval *vp) { \
		jsval rval = create_response(cx, 250, "def" #name, 0); \
		JS_SET_RVAL(cx, vp, rval); \
		return JS_TRUE; \
	} \

DEFINE_HANDLER_STUB(Init);
DEFINE_HANDLER_STUB(Auth);
DEFINE_HANDLER_STUB(Alou);
DEFINE_HANDLER_STUB(Alop);
DEFINE_HANDLER_STUB(Ehlo);
DEFINE_HANDLER_STUB(Data);
DEFINE_HANDLER_STUB(Mail);
DEFINE_HANDLER_STUB(Rcpt);
DEFINE_HANDLER_STUB(Rset);
DEFINE_HANDLER_STUB(Quit);
DEFINE_HANDLER_STUB(Body);

#endif
