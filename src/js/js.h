#ifndef _JS_H
#define _JS_H

#include "jsapi.h"

/* Initializes JavaScript engine */
int js_init(const char *filename);

/* Closes JavaScript engine and frees its resources */
void js_stop(void);

#endif
