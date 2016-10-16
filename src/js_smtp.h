#ifndef _JS_SMTP_SERVER_H
#define _JS_SMTP_SERVER_H

#include <jsapi.h>

#include "bfd.h"

#define PR_HOSTNAME	"hostname"
#define PR_SENDER	"sender"
#define PR_RECIPIENTS	"recipients"
#define PR_DISCONNECT	"disconnect"
#define PR_PROTO	"proto"
#define PR_PEER_ADDR	"peerAddr"
#define PR_PEER_PORT	"peerPort"

int smtp_copy_to_file(bfd_t *out, bfd_t *in, JSObject *hdrs);

// Creates Javascript Object with response
jsval smtp_create_response(JSContext *cx, int status, const char* message, int disconnect);

JSBool js_init_envelope(JSContext *cx, JSObject *obj);
JSBool js_smtp_init(JSContext *cx, JSObject *global);

#endif
