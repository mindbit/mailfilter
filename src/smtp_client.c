#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
	struct smtp_domain *domain;

	if (fputc('<', stream) == EOF)
		return 1;

	list_for_each_entry(domain, &path->domains, lh) {
		if (fputc('@', stream) == EOF)
			return 1;
		if (fputs(domain->domain, stream) == EOF)
			return 1;
		if (fputc(':', stream) == EOF)
			return 1;
	}

	if (path->mailbox.local != EMPTY_STRING) {
		if (fputs(path->mailbox.local, stream) == EOF)
			return 1;
		if (fputc('@', stream) == EOF)
			return 1;
		if (fputs(path->mailbox.domain.domain, stream) == EOF)
			return 1;
	}

	if (fputc('>', stream) == EOF)
		return 1;

	return 0;
}

int smtp_put_path_cmd(FILE *stream, const char *cmd, struct smtp_path *path)
{
	if (fputs(cmd, stream) == EOF)
		return 1;
	if (fputc(':', stream) == EOF)
		return 1;
	if (smtp_put_path(stream, path))
		return 1;
	if (fputs("\r\n", stream) == EOF)
		return 1;
	if (fflush(stream) == EOF)
		return 1;
	return 0;
}

int smtp_c_mail(FILE *stream, struct smtp_path *path)
{
	return smtp_put_path_cmd(stream, "MAIL FROM", path);
}

int smtp_c_rcpt(FILE *stream, struct smtp_path *path)
{
	return smtp_put_path_cmd(stream, "RCPT TO", path);
}

int smtp_copy_from_file(FILE *out, FILE *in)
{
	const uint32_t DOTLINE_MAGIC	= 0x0d0a2e;	/* <CR><LF>"." */
	const uint32_t DOTLINE_MASK		= 0xffffff;
	const uint32_t CRLF_MAGIC		= 0x0d0a;	/* <CR><LF> */
	const uint32_t CRLF_MASK		= 0xffff;
	uint32_t buf = 0;
	int fill = 0, needcrlf = 1;
	int c;

	while ((c = getc_unlocked(in)) != EOF) {
		if (++fill > 4) {
			if (putc_unlocked(buf >> 24, out) == EOF)
				return 1;
			fill = 4;
		}
		buf = (buf << 8) | c;
		if ((buf & DOTLINE_MASK) != DOTLINE_MAGIC)
			continue;
		if (putc_unlocked('.', out) == EOF)
			return 1;
	}

	/* flush remaining buffer */
	for (fill = (fill - 1) * 8; fill >= 0; fill -= 8) {
		if (fill == 8 && (buf & CRLF_MASK) == CRLF_MAGIC)
			needcrlf = 0;
		if (putc_unlocked((buf >> fill) & 0xff, out) == EOF)
			return 1;
	}

	/* send termination marker */
	if (needcrlf && fputs("\r\n", out) == EOF)
		return 1;
	if (fputs(".\r\n", out) == EOF)
		return 1;

	return 0;
}
