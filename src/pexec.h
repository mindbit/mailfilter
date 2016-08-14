/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter.
 *
 * mailfilter is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * mailfilter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PEXEC_H
#define _PEXEC_H

#include "smtp_server.h"
#include "bfd.h"

typedef int (*pexec_send_headers_t)(struct smtp_server_context *ctx, bfd_t *fw);
typedef int (*pexec_result_t)(struct smtp_server_context *ctx, bfd_t *fr, int status);

int pexec(char * const *argv, int fd_in, int fd_out);
#define pexec_hdlr_body(_ctx, _argv, _h, _r) \
	__pexec_hdlr_body(_ctx, module, _argv, _h, _r)
int __pexec_hdlr_body(struct smtp_server_context *ctx, const char *module, char * const *argv,
		pexec_send_headers_t pexec_send_headers, pexec_result_t pexec_result);

#endif
