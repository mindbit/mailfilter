#ifndef _JS_H
#define _JS_H

#include <jsapi.h>
#include "bfd.h"

#ifdef DEBUG

#error The application will not compile if DEBUG is defined,	\
because it is used by SpiderMonkey and will undefine		\
some macros (like JSVAL_NULL).

#endif

// Get response properties
jsval js_create_response(jsval *argv);

// SmtpPath class methods
int add_recipient(jsval *smtpPath);

// Header class methods
int add_body_stream(bfd_t *body_stream);
int add_part_to_header(jsval *header, char *c_str);
jsval new_header_instance(char *name);

#endif
