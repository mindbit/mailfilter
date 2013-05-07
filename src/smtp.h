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

#ifndef _SMTP_H
#define _SMTP_H

#include "list.h"

#define SMTP_COMMAND_MAX 512

#define EMPTY_STRING ((void *)1)

struct smtp_domain {
	const char *domain;
	struct list_head lh;
};

struct smtp_mailbox {
	const char *local;
	struct smtp_domain domain;
};

struct smtp_path {
	struct smtp_mailbox mailbox;
	struct list_head domains;
};

extern const char *white;
char *smtp_path_to_string(struct smtp_path *path);
int smtp_path_parse(struct smtp_path *path, const char *arg, char **trailing);

#endif
