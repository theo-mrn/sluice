#ifndef SLUICE_JSON_H
#define SLUICE_JSON_H

#include <stddef.h>

#include "buf.h"

/* Appends s[0..n) to out as a quoted JSON string. Control characters are escaped and every byte
 * that is not part of valid UTF-8 becomes U+FFFD, so the output is always valid JSON whatever the
 * input (client supplied text such as user names and SQL is untrusted). Returns 0, or -1 when out
 * of memory. */
int sl_json_append_string(sl_buf *out, const void *s, size_t n);

/* The largest length <= max such that s[0..length) does not end in the middle of a UTF-8 sequence.
 * Use it to shorten a value before logging it. Returns n when n <= max. */
size_t sl_json_utf8_prefix(const void *s, size_t n, size_t max);

#endif
