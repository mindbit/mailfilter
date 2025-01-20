/* SPDX-License-Identifier: GPLv2 */

#ifndef _SMTP_SERVER_H
#define _SMTP_SERVER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <duktape.h>

extern void smtp_server_main(duk_context *dcx, SSL_CTX *scx, int client_sock_fd, const struct sockaddr_in *peer);

#endif
