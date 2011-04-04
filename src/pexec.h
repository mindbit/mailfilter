#ifndef _PEXEC_H
#define _PEXEC_H

#include "smtp_server.h"

typedef int (*pexec_send_headers_t)(struct smtp_server_context *ctx, bfd_t *fw);
typedef int (*pexec_result_t)(struct smtp_server_context *ctx, bfd_t *fr, int status);

int pexec(char * const *argv, int fd_in, int fd_out);
#define pexec_hdlr_body(_ctx, _argv, _h, _r) \
	__pexec_hdlr_body(_ctx, module, _argv, _h, _r)
int __pexec_hdlr_body(struct smtp_server_context *ctx, const char *module, char * const *argv,
		pexec_send_headers_t pexec_send_headers, pexec_result_t pexec_result);

#endif
