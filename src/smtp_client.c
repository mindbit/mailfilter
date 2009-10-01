#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtp_client.h"

int smtp_client_response(FILE *stream, smtp_client_callback_t callback, void *priv)
{
	char buf[SMTP_COMMAND_MAX + 1];
	long int code;
	char *p, sep;

	do {
		int oversized = 0;

		buf[SMTP_COMMAND_MAX] = '\n';
		if (fgets(buf, sizeof(buf), stream) == NULL)
			return SMTP_READ_ERROR;
		if (strlen(buf) < 4)
			return SMTP_PARSE_ERROR;
		sep = buf[3];
		buf[3] = '\0';
		code = strtol(buf, &p, 10);

		while (buf[SMTP_COMMAND_MAX] != '\n') {
			oversized = 1;
			buf[SMTP_COMMAND_MAX] = '\n';
			if (fgets(buf, sizeof(buf), stream) == NULL)
				return SMTP_READ_ERROR;
		}

		if ((sep != ' ' && sep != '-') || *p != '\0')
			return SMTP_PARSE_ERROR;
		if (code < 100 || code > 999)
			return SMTP_INVALID_CODE;

		if (callback != NULL && callback(code, &buf[0] + 4, sep == ' ', priv))
			return code;
	} while (sep == '-');

	return code;
}

int smtp_put_path(FILE *stream, struct smtp_path *path)
{
	int ret = 0;
	do {
		if (fputc('<', stream) == EOF) {
			ret = 1;
			break;
		}
	} while (0);

	ret = ret || (fputc('>', stream) == EOF);
	return ret;
}

int smtp_c_mail(FILE *stream, struct smtp_path *path)
{
	if (fputs("MAIL FROM:", stream) == EOF)
		return 1;
	if (smtp_c_mail(stream, path))
		return 1;
	if (fputs("\r\n", stream) == EOF)
		return 1;
	if (fflush(stream) == EOF)
		return 1;
	return 0;
}
