#ifndef _JS_SMTP_SERVER_H
#define _JS_SMTP_SERVER_H

#include <jsapi.h>

int js_smtp_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval create_response(JSContext *cx, int status, const char* message, int disconnect);

// SmtpPath class methods
int init_smtp_path_class(JSContext *cx, JSObject *global);
static JSBool smtpPath_construct(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpPath_toString(JSContext *cx, unsigned argc, jsval *vp);

// Header class methods
int init_header_class(JSContext *cx, JSObject *global);
int delete_header_parts(JSContext *cx, jsval *header);
static JSBool header_construct(JSContext *cx, unsigned argc, jsval *vp);
static JSBool header_getValue(JSContext *cx, unsigned argc, jsval *vp);
static JSBool header_toString(JSContext *cx, unsigned argc, jsval *vp);
static JSBool header_refold(JSContext *cx, unsigned argc, jsval *vp);

// SmtpClient class methods
int init_smtp_client_class(JSContext *cx, JSObject *global);
static int connect_to_address(char *ip, char *port);
static JSBool smtp_client_construct(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpClient_sendMessageBody(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpClient_sendCommand(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpClient_readResponse(JSContext *cx, unsigned argc, jsval *vp);
static JSBool smtpClient_connect(JSContext *cx, unsigned argc, jsval *vp);

// SmtpResponse class methods
int init_smtp_response_class(JSContext *cx, JSObject *global);
static JSBool response_construct(JSContext *cx, unsigned argc, jsval *vp);

#endif
