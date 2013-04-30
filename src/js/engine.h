#ifndef _ENGINE_H
#define _ENGINE_H

#include "js.h"

int js_engine_obj_init(JSContext *cx, JSObject *global);

int js_engine_parse(JSContext *cx, JSObject *global);

#endif
