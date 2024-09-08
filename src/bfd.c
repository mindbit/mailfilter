/* SPDX-License-Identifier: GPLv2 */

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bfd.h"

void bfd_init(bfd_t *bfd, int fd)
{
	bfd->fd = fd;
	bfd->rh = 0;
	bfd->rt = 0;
	bfd->wi = 0;
}

bfd_t *bfd_alloc(int fd)
{
	bfd_t *ret = malloc(sizeof(bfd_t));

	if (ret)
		bfd_init(ret, fd);

	return ret;
}

/**
 * @return	0 on success;
 *		-1 on error (errno is set);
 */
int bfd_close(bfd_t *bfd)
{
	int ret = bfd_flush(bfd);
	return close(bfd->fd) ? -1 : ret;
}

/**
 * @return	0 on success;
 *		-1 on error (errno is set);
 */
int bfd_flush(bfd_t *bfd)
{
	ssize_t sz;
	size_t off = 0;

	while (off < bfd->wi) {
		sz = write(bfd->fd, &bfd->wb[off], bfd->wi - off);
		if (sz < 0) {
			if (off) {
				memcpy(&bfd->wb[0], &bfd->wb[off], bfd->wi - off);
				bfd->wi -= off;
			}
			return sz;
		}
		off += sz;
	}

	bfd->wi = 0;

	return 0;
}

/**
 * @return	0 or positive value: the number of bytes written;
 * 		-1 socket write error (errno is set)
 */
ssize_t bfd_write(bfd_t *bfd, const char *p, size_t len)
{
	ssize_t sz;

	if (!len)
		return 0;

	if (bfd->wi >= BFD_SIZE) {
		sz = write(bfd->fd, bfd->wb, BFD_SIZE);
		if (sz <= 0)
			return sz;
		bfd->wi = BFD_SIZE - sz;
		memcpy(&bfd->wb[0], &bfd->wb[sz], bfd->wi);
	}

	sz = BFD_SIZE - bfd->wi < len ? BFD_SIZE - bfd->wi : len;
	memcpy(&bfd->wb[bfd->wi], p, sz);
	bfd->wi += sz;

	return sz;
}

/**
 * @return	0 on success;
 * 		-1 socket write error (errno is set)
 */
int bfd_write_full(bfd_t *bfd, const char *p, size_t len)
{
	ssize_t sz;

	while (len) {
		sz = bfd_write(bfd, p, len);
		if (sz < 0)
			return sz;
		p += sz;
		len -= sz;
	}

	return 0;
}

/**
 * @return	positive value: number of bytes read;
 * 		0: no data could be read from the socket
 * 		-1: socket read error (errno is set)
 */
ssize_t bfd_read(bfd_t *bfd, char *p, size_t len)
{
	ssize_t sz;

	if (!len)
		return 0;

	if (bfd->rh >= bfd->rt) {
		sz = read(bfd->fd, bfd->rb, BFD_SIZE);
		if (sz <= 0)
			return sz;
		bfd->rh = 0;
		bfd->rt = sz;
	}

	sz = bfd->rt - bfd->rh < len ? bfd->rt - bfd->rh : len;
	memcpy(p, &bfd->rb[bfd->rh], sz);
	bfd->rh += sz;

	return sz;
}

/**
 * @return	0 on success;
 * 		-1 socket write error (errno is set)
 */
int bfd_printf(bfd_t *bfd, const char *format, ...)
{
	char buf[4096];
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	if (len >= sizeof(buf)) {
		errno = ENOMEM;
		return -1;
	}

	return bfd_write_full(bfd, buf, len) < 0 ? -1 : len;
}

/**
 * @return	positive value: number of bytes read;
 * 		0: no data could be read from the socket
 * 		-1: socket read error (errno is set)
 */
ssize_t bfd_read_line(bfd_t *bfd, char *buf, size_t len)
{
	char c = '\0';
	ssize_t sz, ret = 0;

	while (ret < len && c != '\n') {
		sz = bfd_read(bfd, &c, 1);
		if (sz < 0)
			return sz;
		if (!sz)
			return ret;
		buf[ret++] = c;
	}

	return ret;
}

int bfd_copy(bfd_t *src, bfd_t *dst)
{
	char buf[4096];
	size_t sz;

	// FIXME use read() and write() directly to avoid unnecessary memcpy()
	while ((sz = bfd_read(src, buf, sizeof(buf)))) {
		if (sz < 0)
			return sz;
		if (bfd_write_full(dst, buf, sz) < 0)
			return -1;
	}

	return 0;
}

off_t bfd_seek(bfd_t *bfd, off_t offset, int whence)
{
	if (bfd_flush(bfd) < 0)
		return -1;

	bfd->rh = bfd->rt = 0;

	return lseek(bfd->fd, offset, whence);
}
