#ifndef _LOGGING_H
#define _LOGGING_H

#include <syslog.h>

#include "config.h"

#ifdef DEBUG
#define log(cfg, level, text, par...) __log(cfg, level, text, ##par)
#else
#define log(cfg, level, text, par...) do {\
	if (level < LOG_DEBUG && level <= (cfg)->logging_level) \
		__log(cfg, level, text, ##par); \
} while (0)
#endif

#define mod_log(level, text, par...) \
	log(ctx->cfg, level, "[%s] " text, module, ##par)

extern void __log(struct config *cfg, int level, const char *format, ...);

#endif
