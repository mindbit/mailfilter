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

int smtp_copy_to_file(duk_context *ctx, bfd_t *out, bfd_t *in);

// Creates Javascript Object with response
duk_bool_t smtp_create_response(duk_context *ctx, int code, const char *message, int disconnect);

duk_bool_t js_init_envelope(duk_context *ctx, duk_idx_t obj_idx);
duk_bool_t js_smtp_init(duk_context *ctx);

#endif
