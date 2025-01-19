/* SPDX-License-Identifier: GPLv2 */

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bfd.h"

#define BFD_SIZE 4096

struct bfd {
	int fd;
	char rb[BFD_SIZE];			/* read buffer */
	size_t rh, rt;				/* read head, read tail */
	char wb[BFD_SIZE];			/* write buffer */
	size_t wi;				/* write index */
};

bfd_t *bfd_alloc(int fd)
{
	bfd_t *bfd = malloc(sizeof(bfd_t));

	if (bfd) {
		bfd->fd = fd;
		bfd->rh = 0;
		bfd->rt = 0;
		bfd->wi = 0;
	}

	return bfd;
}

/**
 * @return	0 on success; POSIX error code on error
 */
int bfd_free(bfd_t *bfd)
{
	int ret = bfd_flush(bfd);
	ret = close(bfd->fd) ? errno : ret;
	free(bfd);
	return ret;
}

/**
 * @return	0 on success; POSIX error code on error
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
			return errno;
		}
		off += sz;
	}

	bfd->wi = 0;

	return 0;
}

/**
 * @return	0 or positive value: the number of bytes written;
 * 		negative POSIX error code on error
 */
ssize_t bfd_write(bfd_t *bfd, const char *p, size_t len)
{
	ssize_t sz;

	if (!len)
		return 0;

	if (bfd->wi >= BFD_SIZE) {
		sz = write(bfd->fd, bfd->wb, BFD_SIZE);
		if (sz <= 0)
			return sz ? -errno : 0;
		bfd->wi = BFD_SIZE - sz;
		memcpy(&bfd->wb[0], &bfd->wb[sz], bfd->wi);
	}

	sz = BFD_SIZE - bfd->wi < len ? BFD_SIZE - bfd->wi : len;
	memcpy(&bfd->wb[bfd->wi], p, sz);
	bfd->wi += sz;

	return sz;
}

/**
 * @return	0 on success; POSIX error code on error
 */
int bfd_write_full(bfd_t *bfd, const char *p, size_t len)
{
	ssize_t sz;

	while (len) {
		sz = bfd_write(bfd, p, len);
		if (sz < 0)
			return -sz;
		p += sz;
		len -= sz;
	}

	return 0;
}

/**
 * @return	0 or positive value: the number of bytes read;
 * 		negative POSIX error code on error
 */
ssize_t bfd_read(bfd_t *bfd, char *p, size_t len)
{
	ssize_t sz;

	if (!len)
		return 0;

	if (bfd->rh >= bfd->rt) {
		sz = read(bfd->fd, bfd->rb, BFD_SIZE);
		if (sz <= 0)
			return sz ? -errno : 0;
		bfd->rh = 0;
		bfd->rt = sz;
	}

	sz = bfd->rt - bfd->rh < len ? bfd->rt - bfd->rh : len;
	memcpy(p, &bfd->rb[bfd->rh], sz);
	bfd->rh += sz;

	return sz;
}

/**
 * @return	0 on success; POSIX error code on error
 */
int bfd_printf(bfd_t *bfd, const char *format, ...)
{
	char buf[4096];
	va_list ap;
	int len;

	va_start(ap, format);
	len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	if (len >= sizeof(buf))
		return ENOMEM;

	return bfd_write_full(bfd, buf, len);
}

/**
 * Read up to (and including) len bytes into buf or until '\n' is read,
 * whichever occurs first. The resulting string is *not* null terminated.
 * The '\n' character is included in the resulting string.
 *
 * @return	0 or positive value: the number of bytes read;
 * 		negative POSIX error code on error
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

/**
 * @return	0 on success; POSIX error code on error
 */
int bfd_copy(bfd_t *src, bfd_t *dst)
{
	char buf[4096];
	ssize_t sz;
	int err;

	// FIXME use read() and write() directly to avoid unnecessary memcpy()
	while ((sz = bfd_read(src, buf, sizeof(buf)))) {
		if (sz < 0)
			return -sz;
		if ((err = bfd_write_full(dst, buf, sz)))
			return err;
	}

	return 0;
}
