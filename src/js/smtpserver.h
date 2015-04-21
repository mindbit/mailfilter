#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include "js.h"

#define	TRUE	1
#define	FALSE	0

int js_smtp_server_obj_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval create_response(JSContext *cx, int status, const char* message, int disconnect);

// C stub handlers
JSBool smtpInit(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpAuth(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpAlou(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpAlop(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpEhlo(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpData(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpMail(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpRcpt(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpRset(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpQuit(JSContext *cx, unsigned argc, jsval *vp);
JSBool smtpBody(JSContext *cx, unsigned argc, jsval *vp);

#endif
