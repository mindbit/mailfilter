#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include "js.h"

int js_smtp_server_obj_init(JSContext *cx, JSObject *global);

int js_smtp_server_parse(JSContext *cx, JSObject *global);

#endif
