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

#endif
