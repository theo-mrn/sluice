#include "json.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Length of the valid UTF-8 sequence starting at s[0], or 0 when it is invalid (stray continuation
 * byte, overlong form, surrogate, beyond U+10FFFF, or truncated). */
static size_t utf8_valid_len(const uint8_t *s, size_t n)
{
    uint8_t c = s[0];
    uint8_t lo = 0x80;
    uint8_t hi = 0xBF;
    size_t extra;

    if (c < 0x80) {
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        extra = 1;
    } else if (c >= 0xE0 && c <= 0xEF) {
        extra = 2;
        if (c == 0xE0) {
            lo = 0xA0;
        }
        if (c == 0xED) {
            hi = 0x9F;
        }
    } else if (c >= 0xF0 && c <= 0xF4) {
        extra = 3;
        if (c == 0xF0) {
            lo = 0x90;
        }
        if (c == 0xF4) {
            hi = 0x8F;
        }
    } else {
        return 0;
    }

    if (n < extra + 1 || s[1] < lo || s[1] > hi) {
        return 0;
    }
    for (size_t i = 2; i <= extra; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            return 0;
        }
    }
    return extra + 1;
}

static int put(sl_buf *out, const char *s)
{
    return sl_buf_append(out, s, strlen(s));
}

int sl_json_append_string(sl_buf *out, const void *data, size_t n)
{
    const uint8_t *s = data;
    size_t i = 0;

    if (put(out, "\"") != 0) {
        return -1;
    }

    while (i < n) {
        uint8_t c = s[i];
        const char *esc = NULL;
        char tmp[8];
        int rc;

        if (c >= 0x80) {
            size_t k = utf8_valid_len(s + i, n - i);

            if (k == 0) {
                rc = put(out, "\\ufffd");
                k = 1;
            } else {
                rc = sl_buf_append(out, s + i, k);
            }
            if (rc != 0) {
                return -1;
            }
            i += k;
            continue;
        }

        switch (c) {
        case '"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        default:
            if (c < 0x20) {
                snprintf(tmp, sizeof tmp, "\\u%04x", (unsigned)c);
                esc = tmp;
            }
            break;
        }

        rc = esc ? put(out, esc) : sl_buf_append(out, &c, 1);
        if (rc != 0) {
            return -1;
        }
        i++;
    }

    return put(out, "\"");
}

size_t sl_json_utf8_prefix(const void *data, size_t n, size_t max)
{
    const uint8_t *s = data;
    size_t k = max;

    if (n <= max) {
        return n;
    }
    /* s[k] is the first byte left out: if it is a continuation byte, its sequence started before
     * it. */
    while (k > 0 && (s[k] & 0xC0) == 0x80) {
        k--;
    }
    return k;
}
