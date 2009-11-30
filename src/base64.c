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
