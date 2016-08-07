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

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "logging.h"
#include "string_tools.h"

/* Main server configuration */
struct config config = {
	.path = "/etc/mailfilter.js",
	.daemon = 1,
	.smtp_debug = 0,
	.logging_type = LOGGING_TYPE_STDERR,
	.logging_level = LOG_INFO,
	.logging_facility = LOG_DAEMON,
	.dbconn = NULL,
};

const struct str2val_map log_types[] = {
	{ "stderr", LOGGING_TYPE_STDERR },
	{ "syslog", LOGGING_TYPE_SYSLOG },
	{ "logfile", LOGGING_TYPE_LOGFILE },
	{ NULL, 0 }
};

const struct str2val_map log_levels[] = {
	{ "emerg", LOG_EMERG },
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "err", LOG_ERR },
	{ "warning", LOG_WARNING },
	{ "notice", LOG_NOTICE },
	{ "info", LOG_INFO },
	{ "debug", LOG_DEBUG },
	{ NULL, 0 }
};

const struct str2val_map log_facilities[] = {
	{ "daemon", LOG_DAEMON },
	{ "user", LOG_USER },
	{ "mail", LOG_MAIL },
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ NULL, 0 }
};

int str_2_val(const struct str2val_map *map, const char *str)
{
	int i;
	for (i = 0; map[i].name; i++) {
		if (!strcmp(map[i].name, str))
			return map[i].val;
	}
	return -EINVAL;
}
