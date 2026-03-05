#ifndef SLUICE_BUF_H
#define SLUICE_BUF_H

#include <stddef.h>
#include <stdint.h>

/* Growable byte queue: append at the tail, consume from the head. The zero value is not valid, call
 * sl_buf_init() first. */
typedef struct {
    uint8_t *data;
    size_t off; /* where the unconsumed bytes start in data */
    size_t len; /* number of unconsumed bytes */
    size_t cap; /* allocated size of data */
} sl_buf;

void sl_buf_init(sl_buf *b);

/* Frees the storage and leaves the buffer empty and reusable. */
void sl_buf_free(sl_buf *b);

/* Copies n bytes to the tail. Returns 0, or -1 when out of memory (the buffer is unchanged). */
int sl_buf_append(sl_buf *b, const void *src, size_t n);

/* Returns a pointer to n writable bytes at the tail, or NULL when out of memory. Write at most n
 * bytes there, then call sl_buf_commit() with the number actually written. n must not be 0. */
uint8_t *sl_buf_reserve(sl_buf *b, size_t n);
void sl_buf_commit(sl_buf *b, size_t n);

/* The unconsumed bytes. The pointer is invalidated by any call that adds data. NULL when empty. */
const uint8_t *sl_buf_data(const sl_buf *b);
size_t sl_buf_len(const sl_buf *b);

/* Drops n bytes from the head (everything, if n is larger than the length). */
void sl_buf_consume(sl_buf *b, size_t n);

/* Replaces old_len bytes at offset pos (counted from the head) by new_len bytes from src: the
 * content can grow, shrink or disappear (new_len == 0, src may then be NULL). pos + old_len must
 * not exceed the length. src must not point into the buffer. Returns 0, or -1 when out of memory
 * (the buffer is unchanged). */
int sl_buf_replace(sl_buf *b, size_t pos, size_t old_len, const void *src, size_t new_len);

#endif
