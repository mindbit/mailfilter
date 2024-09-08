/* SPDX-License-Identifier: GPLv2 */

#ifndef _PEXEC_H
#define _PEXEC_H

#include "js_smtp.h"

int pexec_fd_execv(char * const *argv, int fd_in, int fd_out);
JSBool pexec_put_msg(JSContext *cx, char * const *argv, jsval hdrs, jsval path,
		struct string_buffer *out, int *status);

#endif
