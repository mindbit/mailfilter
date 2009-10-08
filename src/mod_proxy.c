#include <stdlib.h>

#include "mod_proxy.h"

static uint64_t key;

int mod_proxy_hdlr_init(struct smtp_server_context *ctx, const char *cmd, const char *arg, FILE *stream)
{
	struct mod_proxy_priv *priv;

	priv = malloc(sizeof(struct mod_proxy_priv));
	// FIXME check for NULL

	smtp_priv_register(ctx, key, priv);
	// FIXME check ret val
	
	return 0;
}


/* void __attribute__((constructor)) my_init() */

void mod_proxy_init(void)
{
	key = smtp_priv_key("proxy");
}

