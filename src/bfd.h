/* SPDX-License-Identifier: GPLv2 */

#ifndef _BFD_H
#define _BFD_H

#include <string.h>
#include <sys/types.h>

struct bfd;
typedef struct bfd bfd_t;

bfd_t *bfd_alloc(int fd);
int bfd_free(bfd_t *bfd);
extern int bfd_flush(bfd_t *bfd);
extern ssize_t bfd_write(bfd_t *bfd, const char *p, size_t len);
extern int bfd_write_full(bfd_t *bfd, const char *p, size_t len);
extern ssize_t bfd_read(bfd_t *bfd, char *p, size_t len);
extern int bfd_printf(bfd_t *bfd, const char *format, ...);
extern ssize_t bfd_read_line(bfd_t *bfd, char *buf, size_t len);
extern int bfd_copy(bfd_t *src, bfd_t *dst);

static inline int bfd_puts(bfd_t *bfd, const char *s)
{
	return bfd_write_full(bfd, s, strlen(s));
}

extern off_t bfd_seek(bfd_t *bfd, off_t offset, int whence);

static inline int bfd_getc(bfd_t *bfd)
{
	unsigned char c;

	return bfd_read(bfd, (void *)&c, 1) <= 0 ? -1 : c;
}

static inline int bfd_putc(bfd_t *bfd, int _c)
{
	unsigned char c = _c & 0xff;

	return bfd_write(bfd, (void *)&c, 1) <= 0 ? -1 : 0;
}

#endif
