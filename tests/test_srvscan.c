#include <stdlib.h>

#include "check.h"
#include "pg_proto.h"
#include "srvscan.h"

/* What the fake connection decides depends only on the message, so that cutting the stream
 * somewhere else cannot change anything. */
typedef struct {
    int read_types[8]; /* message types handed over to be read, 0 ends the list */
    int skip_type;     /* a type thrown away unread */
    int drop_type;     /* a type that is read, then dropped */
    int seen;          /* messages handed to message() */
    char order[64];    /* their types, in order */
    uint8_t last_z;    /* the status byte of the last ReadyForQuery read */
} fake;

static int fake_classify(void *ctx, uint8_t type, size_t payload_len)
{
    fake *f = ctx;

    (void)payload_len;
    if (type == f->skip_type) {
        return SL_SRV_SKIP;
    }
    for (int i = 0; f->read_types[i]; i++) {
        if (f->read_types[i] == type) {
            return SL_SRV_READ;
        }
    }
    return SL_SRV_PASS;
}

static int fake_message(void *ctx, uint8_t type, const uint8_t *payload, size_t len)
{
    fake *f = ctx;

    if (f->seen < (int)sizeof f->order - 1) {
        f->order[f->seen] = (char)type;
    }
    f->seen++;
    if (type == 'Z' && len == 1) {
        f->last_z = payload[0];
    }
    return type == f->drop_type ? SL_SRV_DROP : SL_SRV_KEEP;
}

static const sl_srv_ops ops = {fake_classify, fake_message};

static size_t put(uint8_t *out, size_t at, char type, const char *payload, size_t len)
{
    out[at] = (uint8_t)type;
    sl_pg_put_be32(out + at + 1, (uint32_t)(4 + len));
    if (len) {
        memcpy(out + at + 5, payload, len);
    }
    return at + 5 + len;
}

/* Feeds `in` in reads of `chunk` bytes, sends what is released. Returns the last result. */
static int drive(const uint8_t *in, size_t n, size_t chunk, fake *f, size_t read_max, sl_buf *out,
                 unsigned *oversized)
{
    sl_srv s;
    sl_buf buf;
    int rc = SL_SRV_OK;
    size_t pos = 0;

    sl_srv_init(&s, 0, read_max);
    sl_buf_init(&buf);
    while (pos < n) {
        size_t k = n - pos < chunk ? n - pos : chunk;

        CHECK(sl_buf_append(&buf, in + pos, k) == 0);
        pos += k;
        rc = sl_srv_run(&s, &buf, &ops, f, oversized);
        CHECK(s.released <= sl_buf_len(&buf));
        /* what is held is at most one message that is being read */
        CHECK(sl_buf_len(&buf) - s.released <= 5 + read_max);
        CHECK(sl_buf_append(out, sl_buf_data(&buf), s.released) == 0);
        sl_buf_consume(&buf, s.released);
        s.released = 0;
    }
    sl_buf_free(&buf);
    return rc;
}

static const size_t CHUNKS[] = {1, 2, 3, 5, 7, 13, 64, 1000000};

/* The same stream, cut in every way, must give the same bytes out and the same events. */
static void check_same(const uint8_t *in, size_t n, fake base, size_t read_max, const uint8_t *want,
                       size_t want_len, const char *want_order, int want_rc, unsigned want_over)
{
    for (size_t i = 0; i < sizeof CHUNKS / sizeof CHUNKS[0]; i++) {
        fake f = base;
        sl_buf out;
        unsigned over = 0;
        int rc;

        sl_buf_init(&out);
        rc = drive(in, n, CHUNKS[i], &f, read_max, &out, &over);
        if (rc != want_rc || sl_buf_len(&out) != want_len ||
            (want_len && memcmp(sl_buf_data(&out), want, want_len) != 0) ||
            strncmp(f.order, want_order, strlen(want_order)) != 0 ||
            f.seen != (int)strlen(want_order) || over != want_over) {
            fprintf(stderr,
                    "cut in reads of %zu: rc %d (want %d), %zu bytes (want %zu), order \"%.*s\" "
                    "(want \"%s\"), oversized %u (want %u)\n",
                    CHUNKS[i], rc, want_rc, sl_buf_len(&out), want_len, f.seen > 60 ? 60 : f.seen,
                    f.order, want_order, over, want_over);
            sl_test_failures++;
        }
        sl_buf_free(&out);
    }
}

static void test_pass_and_read(void)
{
    uint8_t in[512];
    size_t n = 0;
    fake base = {{'Z', 0}, 0, 0, 0, {0}, 0};

    n = put(in, n, 'T', "col\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 22);
    n = put(in, n, 'D', "\0\1\0\0\0\2ab", 8);
    n = put(in, n, 'C', "DELETE 1\0", 9);
    n = put(in, n, 'Z', "T", 1);
    /* nothing but Z is read; everything goes through, in order */
    check_same(in, n, base, SL_SRV_READ_MAX, in, n, "Z", SL_SRV_OK, 0);
    {
        fake f = base;
        sl_buf out;

        sl_buf_init(&out);
        drive(in, n, 4, &f, SL_SRV_READ_MAX, &out, NULL);
        CHECK(f.last_z == 'T');
        sl_buf_free(&out);
    }
}

static void test_drop_and_skip(void)
{
    uint8_t in[512];
    uint8_t want[512];
    size_t n = 0;
    size_t w = 0;
    fake base = {{'C', 'Z', 0}, 'D', 'C', 0, {0}, 0};

    n = put(in, n, 'T', "x", 1);
    w = put(want, w, 'T', "x", 1);
    n = put(in, n, 'D', "\0\1\0\0\0\2ab", 8); /* skipped unread */
    n = put(in, n, 'C', "DELETE 1\0", 9);     /* read, dropped */
    n = put(in, n, 'D', "\0\1\0\0\0\2cd", 8);
    n = put(in, n, 'C', "BEGIN\0", 6);
    n = put(in, n, 'N', "noticed", 7);
    w = put(want, w, 'N', "noticed", 7);
    n = put(in, n, 'Z', "I", 1); /* read and kept */
    w = put(want, w, 'Z', "I", 1);
    check_same(in, n, base, SL_SRV_READ_MAX, want, w, "CCZ", SL_SRV_OK, 0);
}

static void test_big_messages(void)
{
    static uint8_t in[200000];
    static uint8_t want[200000];
    size_t n = 0;
    size_t w = 0;
    fake base = {{'D', 'Z', 0}, 0, 0, 0, {0}, 0};
    static char body[100000];

    memset(body, 'x', sizeof body);
    /* a message above read_max that was to be read is thrown away unread, and counted */
    n = put(in, n, 'D', body, 60000);
    n = put(in, n, 'Z', "I", 1);
    w = put(want, w, 'Z', "I", 1);
    check_same(in, n, base, 1000, want, w, "Z", SL_SRV_OK, 1);

    /* a big message that is only relayed streams through even when it is longer than read_max */
    n = 0;
    w = 0;
    base.read_types[0] = 'Z';
    base.read_types[1] = 0;
    n = put(in, n, 'D', body, 90000);
    w = put(want, w, 'D', body, 90000);
    n = put(in, n, 'Z', "T", 1);
    w = put(want, w, 'Z', "T", 1);
    check_same(in, n, base, 1000, want, w, "Z", SL_SRV_OK, 0);
}

static void test_lost_framing(void)
{
    uint8_t in[128];
    size_t n = 0;
    fake base = {{'Z', 0}, 0, 0, 0, {0}, 0};
    sl_buf out;
    unsigned over = 0;
    fake f = base;

    n = put(in, n, 'Z', "I", 1);
    in[n++] = 'D'; /* a length of 2: not possible */
    in[n++] = 0;
    in[n++] = 0;
    in[n++] = 0;
    in[n++] = 2;
    n = put(in, n, 'Z', "T", 1); /* after that nothing is read any more */
    for (size_t i = 0; i < sizeof CHUNKS / sizeof CHUNKS[0]; i++) {
        fake g = base;

        sl_buf_init(&out);
        CHECK(drive(in, n, CHUNKS[i], &g, SL_SRV_READ_MAX, &out, &over) == SL_SRV_LOST);
        CHECK(sl_buf_len(&out) == n); /* every byte still goes to the client */
        CHECK_MEM(sl_buf_data(&out), in, n);
        CHECK(g.seen == 1 && g.last_z == 'I');
        sl_buf_free(&out);
    }
    (void)f;
}

int main(void)
{
    test_pass_and_read();
    test_drop_and_skip();
    test_big_messages();
    test_lost_framing();
    return TEST_RESULT();
}
