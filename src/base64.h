/* SPDX-License-Identifier: GPLv2 */

#ifndef _BASE64_H
#define _BASE64_H

char *base64_enc(const char *str, int len);
char *base64_dec(char *str, int len, int *result_len);

#endif
