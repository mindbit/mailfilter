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

char *smtp_path_to_string(struct smtp_path *path);

#endif
