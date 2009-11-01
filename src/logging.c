#define _BSD_SOURCE
#include <stdarg.h>
#include <syslog.h>

#include "logging.h"

void __log(struct config *cfg, int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	switch (cfg->logging_type) {
	case LOGGING_TYPE_STDERR:
		vfprintf(stderr, format, ap);
		break;
	case LOGGING_TYPE_SYSLOG:
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
