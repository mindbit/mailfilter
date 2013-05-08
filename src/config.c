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

#define _GNU_SOURCE
#include <libconfig.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "logging.h"
#include "string_tools.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

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

/*
 * Server configuration file parser function.
 */
int config_parse(struct config *current, struct config *next)
{
	config_setting_t *node, *child;
	const char *value;
	int i, err = -EINVAL;
	config_t cf;
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;

	config_init(&cf);
	log(current, LOG_DEBUG, "Loading config from %s\n", current->path);
	if (config_read_file(&cf, current->path) == CONFIG_FALSE) {
		log(current, LOG_ERR, "Parse error at line %d: %s\n",
				config_error_line(&cf), config_error_text(&cf));
		goto out_err;
	}

	/*
	 * Logging configuration
	 */
#ifndef LIBCONFIG_NEW_API
	value = config_lookup_string(&cf, "logging.type");
	if (value) {
#else
	if (config_lookup_string(&cf, "logging.type", &value) == CONFIG_TRUE) {
#endif
		if (!strcmp(value, "file"))
			next->logging_type = LOGGING_TYPE_LOGFILE;
		else if (!strcmp(value, "stderr"))
			next->logging_type = LOGGING_TYPE_STDERR; 
		else if (!strcmp(value, "syslog"))
			next->logging_type = LOGGING_TYPE_SYSLOG;
		else {
			log(current, LOG_ERR, "Invalid logging.type value: '%s'\n", value);
			goto out_err;
		}
	}

	if (next->logging_type == LOGGING_TYPE_LOGFILE) {
#ifndef LIBCONFIG_NEW_API
		if (!(value = config_lookup_string(&cf, "logging.path"))) {
#else
		if (config_lookup_string(&cf, "logging.path", &value) == CONFIG_FALSE) {
#endif
			log(current, LOG_ERR, "logging.path not found in config file.\n");
			goto out_err;
		}
		next->logging_path = strdup(value);
	}

#ifndef LIBCONFIG_NEW_API
	if ((value = config_lookup_string(&cf, "logging.level"))) {
#else
	if (config_lookup_string(&cf, "logging.level", &value) == CONFIG_TRUE) {
#endif
		if ((next->logging_level = str_2_val(log_levels, value)) < 0) {
			log(current, LOG_ERR, "Invalid logging.level value: '%s'.\n", value);
			goto out_err;
		}
	}

#ifndef LIBCONFIG_NEW_API
	if ((value = config_lookup_string(&cf, "logging.facility"))) {
#else
	if (config_lookup_string(&cf, "logging.facility", &value) == CONFIG_TRUE) {
#endif
		if ((next->logging_facility = str_2_val(log_facilities, value)) < 0) {
			log(current, LOG_ERR, "Invalid logging.facility value: '%s'.\n", value);
			goto out_err;
		}
	}

	/*
	 * Database connection configuration
	 */
	if (!(node = config_lookup(&cf, "dbconn"))) {
		log(current, LOG_ERR, "dbconn node not found in config file.\n");
		goto out_err;
	}

	for (i = 0; i < config_setting_length(node); i++) {
		child = config_setting_get_elem(node, i);
		assert_log(child, current);
		if (i)
			string_buffer_append_char(&sb, ' ');
		string_buffer_append_string(&sb, config_setting_name(child));
		string_buffer_append_char(&sb, '=');
		string_buffer_append_string(&sb, config_setting_get_string(child));
	}

	next->dbconn = sb.s;
	err = 0;
out_err:
	config_destroy(&cf);
	return err;
}

struct config *config_get(void)
{
	return &config;
}
