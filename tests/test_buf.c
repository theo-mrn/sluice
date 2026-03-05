#include <stdlib.h>

#include "buf.h"
#include "check.h"

int main(void)
{
    sl_buf b;
    uint8_t *p;

    sl_buf_init(&b);
    CHECK(sl_buf_len(&b) == 0);
    CHECK(sl_buf_data(&b) == NULL);

    /* append and consume */
    CHECK(sl_buf_append(&b, "hello", 5) == 0);
    CHECK(sl_buf_len(&b) == 5);
    CHECK_MEM(sl_buf_data(&b), "hello", 5);
    sl_buf_consume(&b, 2);
    CHECK(sl_buf_len(&b) == 3);
    CHECK_MEM(sl_buf_data(&b), "llo", 3);

    /* reserve then commit, with fewer bytes than reserved */
    p = sl_buf_reserve(&b, 10);
    CHECK(p != NULL);
    memcpy(p, "1234", 4);
    sl_buf_commit(&b, 4);
    CHECK(sl_buf_len(&b) == 7);
    CHECK_MEM(sl_buf_data(&b), "llo1234", 7);

    /* appending nothing is a no-op, even with a NULL source */
    CHECK(sl_buf_append(&b, NULL, 0) == 0);
    CHECK(sl_buf_len(&b) == 7);

    /* it is a FIFO: each round drops the 8 oldest bytes, so only the newest 7 stay ("bcdefgh"), and
     * the consumed prefix is reused instead of growing without bound */
    for (int i = 0; i < 1000; i++) {
        CHECK(sl_buf_append(&b, "abcdefgh", 8) == 0);
        sl_buf_consume(&b, 8);
    }
    CHECK(sl_buf_len(&b) == 7);
    CHECK_MEM(sl_buf_data(&b), "bcdefgh", 7);

    /* growth well past the initial capacity keeps the content */
    {
        size_t n = 200000;
        uint8_t *big = malloc(n);

        CHECK(big != NULL);
        for (size_t i = 0; i < n; i++) {
            big[i] = (uint8_t)(i * 31);
        }
        CHECK(sl_buf_append(&b, big, n) == 0);
        CHECK(sl_buf_len(&b) == 7 + n);
        CHECK_MEM(sl_buf_data(&b), "bcdefgh", 7);
        CHECK_MEM(sl_buf_data(&b) + 7, big, n);
        free(big);
    }

    /* consuming more than the length empties it, and the buffer stays usable */
    sl_buf_consume(&b, (size_t)-1);
    CHECK(sl_buf_len(&b) == 0);
    CHECK(sl_buf_append(&b, "x", 1) == 0);
    CHECK_MEM(sl_buf_data(&b), "x", 1);

    /* an absurd reservation fails cleanly and leaves the content alone */
    CHECK(sl_buf_reserve(&b, (size_t)-1) == NULL);
    CHECK(sl_buf_len(&b) == 1);
    CHECK_MEM(sl_buf_data(&b), "x", 1);

    sl_buf_free(&b);
    CHECK(sl_buf_len(&b) == 0);
    CHECK(sl_buf_append(&b, "again", 5) == 0);
    sl_buf_free(&b);

    /* replace: longer, shorter, same size, at both ends, and removal */
    sl_buf_init(&b);
    CHECK(sl_buf_append(&b, "0123456789", 10) == 0);
    CHECK(sl_buf_replace(&b, 3, 2, "abcdef", 6) == 0); /* 01 2 [34 -> abcdef] 56789 */
    CHECK(sl_buf_len(&b) == 14);
    CHECK_MEM(sl_buf_data(&b), "012abcdef56789", 14);
    CHECK(sl_buf_replace(&b, 3, 6, "X", 1) == 0); /* shorter */
    CHECK(sl_buf_len(&b) == 9);
    CHECK_MEM(sl_buf_data(&b), "012X56789", 9);
    CHECK(sl_buf_replace(&b, 3, 1, "Y", 1) == 0); /* same size */
    CHECK_MEM(sl_buf_data(&b), "012Y56789", 9);
    CHECK(sl_buf_replace(&b, 0, 0, ">>", 2) == 0); /* insert at the head */
    CHECK_MEM(sl_buf_data(&b), ">>012Y56789", 11);
    CHECK(sl_buf_replace(&b, 11, 0, "<<", 2) == 0); /* append at the tail */
    CHECK_MEM(sl_buf_data(&b), ">>012Y56789<<", 13);
    CHECK(sl_buf_replace(&b, 0, 2, NULL, 0) == 0); /* remove the head... */
    CHECK(sl_buf_replace(&b, 9, 2, NULL, 0) == 0); /* ...and the tail */
    CHECK(sl_buf_len(&b) == 9);
    CHECK_MEM(sl_buf_data(&b), "012Y56789", 9);

    /* after bytes were consumed from the head, positions are still relative to the head */
    sl_buf_consume(&b, 3);
    CHECK(sl_buf_replace(&b, 1, 2, "--", 2) == 0);
    CHECK_MEM(sl_buf_data(&b), "Y--789", 6);

    /* a replacement that forces the storage to grow keeps everything around it */
    {
        size_t n = 100000;
        uint8_t *big = malloc(n);

        CHECK(big != NULL);
        memset(big, 'z', n);
        CHECK(sl_buf_replace(&b, 1, 2, big, n) == 0);
        CHECK(sl_buf_len(&b) == 6 - 2 + n);
        CHECK_MEM(sl_buf_data(&b), "Y", 1);
        CHECK_MEM(sl_buf_data(&b) + 1, big, n);
        CHECK_MEM(sl_buf_data(&b) + 1 + n, "789", 3);
        free(big);
    }
    sl_buf_free(&b);

    /* an empty buffer owns no memory at all: replacing nothing by nothing must not touch any (glibc
     * declares the pointers of memcpy and memmove never null, even for a length of 0; the
     * sanitizers say so) */
    sl_buf_init(&b);
    CHECK(sl_buf_replace(&b, 0, 0, NULL, 0) == 0);
    CHECK(sl_buf_len(&b) == 0);
    CHECK(sl_buf_replace(&b, 0, 0, "ab", 2) == 0);
    CHECK(sl_buf_len(&b) == 2);
    CHECK_MEM(sl_buf_data(&b), "ab", 2);
    CHECK(sl_buf_replace(&b, 2, 0, NULL, 0) == 0); /* at the end: nothing after it to move */
    CHECK(sl_buf_len(&b) == 2);
    CHECK(sl_buf_replace(&b, 0, 2, NULL, 0) == 0); /* all of it */
    CHECK(sl_buf_len(&b) == 0);
    CHECK(sl_buf_replace(&b, 0, 0, NULL, 0) == 0);
    sl_buf_free(&b);

    return TEST_RESULT();
}
