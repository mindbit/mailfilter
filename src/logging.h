/*
 * Copyright (C) 2010 Mindbit SRL
 *
 * This file is part of mailfilter, a free SIP server.
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

#ifndef _LOGGING_H
#define _LOGGING_H

#include <syslog.h>

#include "config.h"

#ifdef DEBUG
#define log(cfg, level, text, par...) __log(cfg, level, text, ##par)
#else
#define log(cfg, level, text, par...) do {\
	if (level <= (cfg)->logging_level) \
		__log(cfg, level, text, ##par); \
} while (0)
#endif

#ifdef DEBUG
#define assert_log(cond, cfg) do {\
	if (!(cond)) {\
		__assert_log(cfg, #cond, __FILE__, __LINE__);\
		exit(1); \
	} \
} while (0)
#define assert_mod_log(cond) assert_log(cond, ctx->cfg)
#else
#define assert_log(...)
#define assert_mod_log(...)
#endif


#define mod_log(level, text, par...) \
	log(ctx->cfg, level, "[%s] " text, module, ##par)

extern void __log(struct config *cfg, int level, const char *format, ...);

static inline void __assert_log(struct config *cfg, const char *cond, const char *file, int line)
{
	__log(cfg, LOG_ERR, "Assertion '%s' failed at %s:%d. Aborting.", cond, file, line);
}

#endif
