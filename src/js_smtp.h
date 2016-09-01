#ifndef _JS_SMTP_SERVER_H
#define _JS_SMTP_SERVER_H

#include <jsapi.h>

#define PR_HOSTNAME	"hostname"
#define PR_SENDER	"sender"
#define PR_RECIPIENTS	"recipients"
#define PR_HEADERS	"headers"
#define PR_DISCONNECT	"disconnect"

int js_smtp_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval create_response(JSContext *cx, int status, const char* message, int disconnect);

#endif
