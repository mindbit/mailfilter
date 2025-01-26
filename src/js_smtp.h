#ifndef _JS_SMTP_H
#define _JS_SMTP_H

#include <duktape.h>

#include "bfd.h"
#include "string_tools.h"

#define PR_HOSTNAME	"hostname"
#define PR_CLIENTNAME	"clientname"
#define PR_SENDER	"sender"
#define PR_RECIPIENTS	"recipients"
#define PR_DISCONNECT	"disconnect"
#define PR_PROTO	"proto"
#define PR_REMOTE_ADDR	"remoteAddr"
#define PR_REMOTE_PORT	"remotePort"

int smtp_copy_to_file(duk_context *ctx, bfd_t *out, bfd_t *in);
int smtp_copy_from_file(duk_context *ctx, bfd_t *out, bfd_t *in, int dotconv);
int smtp_headers_to_string(duk_context *ctx, struct string_buffer *sb, duk_idx_t idx);
bfd_t *smtp_body_open_read(duk_context *ctx, duk_idx_t obj_idx);

// Creates Javascript Object with response
duk_bool_t smtp_create_response(duk_context *ctx, int code, const char *message, int disconnect);

duk_bool_t js_init_envelope(duk_context *ctx, duk_idx_t obj_idx);
duk_bool_t js_smtp_init(duk_context *ctx);

#endif
