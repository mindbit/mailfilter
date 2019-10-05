#ifndef _JS_SMTP_H
#define _JS_SMTP_H

#include <duktape.h>

#include "bfd.h"

#define PR_HOSTNAME	"hostname"
#define PR_SENDER	"sender"
#define PR_RECIPIENTS	"recipients"
#define PR_DISCONNECT	"disconnect"
#define PR_PROTO	"proto"
#define PR_REMOTE_ADDR	"remoteAddr"
#define PR_REMOTE_PORT	"remotePort"

#if 0
int smtp_copy_to_file(bfd_t *out, bfd_t *in, JSObject *hdrs);

// Creates Javascript Object with response
jsval smtp_create_response(JSContext *cx, int status, const char* message, int disconnect);
#endif

duk_bool_t js_init_envelope(duk_context *ctx, duk_idx_t obj_idx);
duk_bool_t js_smtp_init(duk_context *ctx);

#endif
