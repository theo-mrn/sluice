#include "buf.h"

#include <stdlib.h>
#include <string.h>

#define BUF_MIN_CAP 256

void sl_buf_init(sl_buf *b)
{
    b->data = NULL;
    b->off = 0;
    b->len = 0;
    b->cap = 0;
}

void sl_buf_free(sl_buf *b)
{
    free(b->data);
    sl_buf_init(b);
}

uint8_t *sl_buf_reserve(sl_buf *b, size_t n)
{
    if (b->cap - b->off - b->len >= n) {
        return b->data + b->off + b->len;
    }

    /* Not enough room at the tail: first reclaim the consumed prefix. */
    if (b->off > 0) {
        memmove(b->data, b->data + b->off, b->len);
        b->off = 0;
    }

    if (b->cap - b->len < n) {
        size_t need = b->len + n;
        size_t cap = b->cap ? b->cap : BUF_MIN_CAP;
        uint8_t *p;

        if (need < b->len) {
            return NULL; /* size_t overflow */
        }
        while (cap < need) {
            if (cap > SIZE_MAX / 2) {
                cap = need;
                break;
            }
            cap *= 2;
        }
        p = realloc(b->data, cap);
        if (p == NULL) {
            return NULL;
        }
        b->data = p;
        b->cap = cap;
    }
    return b->data + b->len;
}

void sl_buf_commit(sl_buf *b, size_t n)
{
    b->len += n;
}

int sl_buf_append(sl_buf *b, const void *src, size_t n)
{
    uint8_t *dst;

    if (n == 0) {
        return 0;
    }
    dst = sl_buf_reserve(b, n);
    if (dst == NULL) {
        return -1;
    }
    memcpy(dst, src, n);
    sl_buf_commit(b, n);
    return 0;
}

const uint8_t *sl_buf_data(const sl_buf *b)
{
    return b->data ? b->data + b->off : NULL;
}

size_t sl_buf_len(const sl_buf *b)
{
    return b->len;
}

int sl_buf_replace(sl_buf *b, size_t pos, size_t old_len, const void *src, size_t new_len)
{
    uint8_t *base;
    size_t tail_len = b->len - pos - old_len;

    if (new_len > old_len && sl_buf_reserve(b, new_len - old_len) == NULL) {
        return -1;
    }
    if (b->data == NULL) {
        return 0; /* nothing in it and nothing to put: there is no memory to move (and none to point
                     at) */
    }
    base = b->data + b->off; /* reserve may have moved the data: take the address afterwards */
    if (tail_len > 0 && new_len != old_len) {
        memmove(base + pos + new_len, base + pos + old_len, tail_len);
    }
    if (new_len > 0) {
        memcpy(base + pos, src, new_len);
    }
    b->len = b->len - old_len + new_len;
    return 0;
}

void sl_buf_consume(sl_buf *b, size_t n)
{
    if (n >= b->len) {
        b->len = 0;
        b->off = 0;
        return;
    }
    b->off += n;
    b->len -= n;
}
