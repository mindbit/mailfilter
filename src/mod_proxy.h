#ifndef _MOD_PROXY_H
#define _MOD_PROXY_H

#include <stdio.h>

#include "smtp_server.h"

struct mod_proxy_priv {
	FILE *sock;
};

#endif
