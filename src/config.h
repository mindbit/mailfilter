#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>

struct config {
	/* Global configuration parameters (not included in config file) */
	const char *path;
	int daemon;

	/* Configuration file parameters */
	enum {
		LOGGING_TYPE_STDERR,
		LOGGING_TYPE_SYSLOG,
		LOGGING_TYPE_LOGFILE
	} logging_type;
	int logging_level;
	int logging_facility;
	const char *logging_path;
	const char *dbconn;

	const char *listen_address;
	int listen_port;
};

int config_parse(struct config *current, struct config *next);

#endif
