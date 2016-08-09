#ifndef _JS_ENGINE_H
#define _JS_ENGINE_H

#include <jsapi.h>

int js_engine_init(JSContext *cx, JSObject *global);

#endif
