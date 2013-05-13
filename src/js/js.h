#ifndef _JS_H
#define _JS_H

#include <jsapi.h>

#ifdef DEBUG

#error The application will not compile if DEBUG is defined,	\
because it is used by SpiderMonkey and will undefine		\
some macros (like JSVAL_NULL).

#endif

extern JSContext *js_context;

/* Initializes JavaScript engine */
int js_init(const char *filename);

/* Closes JavaScript engine and frees its resources */
void js_stop(void);

/*
 * Calls the given function of the given predefined object with the given
 * arguments. Last parameter of the function should ALWAYS be JSVAL_NULL.
 */
jsval js_call(const char *obj, const char *func, jsval arg, ...);

#endif
