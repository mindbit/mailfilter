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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <syslog.h>

struct config {
	/* Global configuration parameters (not included in config file) */
	const char *path;
	int daemon;
	int smtp_debug;

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

/*
 * Mapping from string representation to numeriv value.
 */
struct str2val_map {
	const char *name;
	const int val;
};

extern const struct str2val_map log_types[];
extern const struct str2val_map log_levels[];
extern const struct str2val_map log_facilities[];

/* Returns value associated with string given in config */
int str_2_val(const struct str2val_map *map, const char *str);

extern struct config config;

#endif
