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

#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

char *base64_enc(const char *str, int len)
{
	BIO *bio, *b64;
	BUF_MEM *bptr;
	char *buf;
	int ret;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bio);

	ret = BIO_write(b64, str, len);
	if (ret <= 0) {
		buf = NULL;
		goto err;
	}
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	buf = malloc(bptr->length);
	if (buf) {
		memcpy(buf, bptr->data, bptr->length-1);
		buf[bptr->length - 1] = 0;
	}

err:
	BIO_free_all(b64);

	return buf;
}

char *base64_dec(char *str, int len, int *result_len)
{
	BIO *bio, *b64;
	char *buf;
	int ret;

	if (!(buf = malloc(len)))
		return NULL;

	memset(buf, 0, len);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_mem_buf(str, len);
	bio = BIO_push(b64, bio);

	ret = BIO_read(bio, buf, len);
	if (ret <= 0) {
		free(buf);
		buf = NULL;
	}
	BIO_free_all(bio);

	if (result_len)
		*result_len = ret;

	return buf;
}
