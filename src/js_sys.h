#ifndef _JS_SYS_H
#define _JS_SYS_H

#include <duktape.h>

duk_bool_t js_sys_get_prop(duk_context *ctx, const char *name);
duk_bool_t js_sys_init(duk_context *ctx);

#endif
