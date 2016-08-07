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

#include <stdarg.h>
#include <syslog.h>

#include "logging.h"

void __log(struct config *cfg, int level, const char *format, ...)
{
	static int do_syslog_open = 1;
	va_list ap;

	va_start(ap, format);
	switch (cfg->logging_type) {
	case LOGGING_TYPE_STDERR:
		vfprintf(stderr, format, ap);
		break;
	case LOGGING_TYPE_SYSLOG:
		if (do_syslog_open) {
			do_syslog_open = 0;
			openlog("mailfilter", LOG_PID, cfg->logging_facility);
		}
		vsyslog(cfg->logging_facility | level, format, ap);
		break;
	case LOGGING_TYPE_LOGFILE:
		//vfprintf(config.log, format, ap);
		//FIXME we don't want to put the path to the (open) log file in
		//config and probably don't want to open the file each time we
		//log a message either
		break;
	}
	va_end(ap);
}
