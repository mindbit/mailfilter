#include "smtp.h"
#include "string_tools.h"

char *smtp_path_to_string(struct smtp_path *path)
{
	struct string_buffer sb = STRING_BUFFER_INITIALIZER;
	struct smtp_domain *domain;

	if (string_buffer_append_char(&sb, '<'))
		goto out_err;

	list_for_each_entry(domain, &path->domains, lh) {
		if (string_buffer_append_char(&sb, '@'))
			goto out_err;
		if (string_buffer_append_string(&sb, domain->domain))
			goto out_err;
		if (string_buffer_append_char(&sb, ':'))
			goto out_err;
	}

	if (path->mailbox.local != EMPTY_STRING) {
		if (string_buffer_append_string(&sb, path->mailbox.local))
			goto out_err;
		if (string_buffer_append_char(&sb, '@'))
			goto out_err;
		if (string_buffer_append_string(&sb, path->mailbox.domain.domain))
			goto out_err;
	}

	if (string_buffer_append_char(&sb, '>'))
		goto out_err;
	return sb.s;

out_err:
	string_buffer_cleanup(&sb);
	return NULL;
}
