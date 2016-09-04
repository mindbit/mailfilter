#ifndef _JS_SMTP_SERVER_H
#define _JS_SMTP_SERVER_H

#include <jsapi.h>

#include "bfd.h"

#define PR_HOSTNAME	"hostname"
#define PR_SENDER	"sender"
#define PR_RECIPIENTS	"recipients"
#define PR_HEADERS	"headers"
#define PR_BODY		"body"
#define PR_DISCONNECT	"disconnect"

int smtp_copy_to_file(bfd_t *out, bfd_t *in, JSObject *hdrs);

int js_smtp_init(JSContext *cx, JSObject *global);

// Creates Javascript Object with response
jsval smtp_create_response(JSContext *cx, int status, const char* message, int disconnect);

#endif
