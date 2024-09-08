/* SPDX-License-Identifier: GPLv2 */

#ifndef _MAILFILTER_H
#define _MAILFILTER_H

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define ROUND_UP(n, d) ({							\
	typeof(d) _d = (d);							\
	(((n) + _d - 1) / _d) * d;						\
})

#define SMTP_COMMAND_MAX 512

extern const char *white;
extern const char *tab_space;

#endif
