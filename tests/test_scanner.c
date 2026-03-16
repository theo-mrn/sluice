#include <stdlib.h>

#include "check.h"
#include "pg_proto.h"
#include "scanner.h"

/* ---- a fake connection: decisions that depend only on the bytes, so that cutting the stream
 * somewhere else cannot change them ---- */

typedef struct {
    int block_statements; /* block a Query / Parse whose body starts with 'B' */
    int block_unreadable;
    int close_on_frame_error;
    int statements;
    int unreadable;
    int too_big_seen;
    int frame_errors;
} fake;

static const char REPLACEMENT[] = "blocked";

/* What takes the place of a blocked message: a Query holding the word "blocked". */
static size_t replacement_message(uint8_t *out)
{
    out[0] = 'Q';
    sl_pg_put_be32(out + 1, 4 + sizeof REPLACEMENT);
    memcpy(out + 5, REPLACEMENT, sizeof REPLACEMENT);
    return 5 + sizeof REPLACEMENT;
}

static int fake_statement(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                          sl_buf *replacement)
{
    fake *f = ctx;
    uint8_t msg[32];
    size_t n;

    (void)type;
    f->statements++;
    if (!f->block_statements || len == 0 || payload[0] != 'B') {
        return SL_SCAN_RELAY;
    }
    n = replacement_message(msg);
    return sl_buf_append(replacement, msg, n) == 0 ? SL_SCAN_BLOCK : SL_SCAN_FAIL;
}

static int fake_unreadable(void *ctx, uint8_t type, size_t payload_len, int too_big,
                           sl_buf *replacement)
{
    fake *f = ctx;
    uint8_t msg[32];
    size_t n;

    (void)type;
    (void)payload_len;
    f->unreadable++;
    f->too_big_seen += too_big;
    if (!f->block_unreadable) {
        return SL_SCAN_RELAY;
    }
    n = replacement_message(msg);
    return sl_buf_append(replacement, msg, n) == 0 ? SL_SCAN_BLOCK : SL_SCAN_FAIL;
}

static int fake_frame_error(void *ctx)
{
    fake *f = ctx;

    f->frame_errors++;
    return f->close_on_frame_error;
}

static const sl_scan_ops ops = {fake_statement, fake_unreadable, fake_frame_error};

/* Plays the connection: feeds `in` in reads of `chunk` bytes, sends what the scanner releases, and
 * at the end of the stream sends whatever is still held. Returns the last scanner result; `out`
 * gets the bytes sent. */
static int drive(const uint8_t *in, size_t n, size_t chunk, fake *f, size_t inspect_max,
                 int fastpath, sl_buf *out)
{
    sl_scan s;
    sl_buf buf;
    int rc = SL_SCAN_OK;
    size_t pos = 0;

    sl_scan_init(&s, fastpath, inspect_max);
    sl_buf_init(&buf);
    while (pos < n && rc == SL_SCAN_OK) {
        size_t k = n - pos < chunk ? n - pos : chunk;

        CHECK(sl_buf_append(&buf, in + pos, k) == 0);
        pos += k;
        rc = sl_scan_run(&s, &buf, &ops, f);
        CHECK(s.released <= sl_buf_len(&buf));
        /* what is held back is bounded: one message that fits, or nothing */
        CHECK(rc != SL_SCAN_OK || sl_buf_len(&buf) - s.released <= 5 + inspect_max);
        CHECK(sl_buf_append(out, sl_buf_data(&buf), s.released) == 0);
        sl_buf_consume(&buf, s.released);
        s.released = 0;
    }
    if (rc == SL_SCAN_OK) { /* the client left: what is held goes through as it is */
        CHECK(sl_buf_append(out, sl_buf_data(&buf), sl_buf_len(&buf)) == 0);
    }
    sl_buf_free(&buf);
    return rc;
}

static size_t put(uint8_t *out, size_t at, char type, const char *payload, size_t len)
{
    out[at] = (uint8_t)type;
    sl_pg_put_be32(out + at + 1, (uint32_t)(4 + len));
    if (len) {
        memcpy(out + at + 5, payload, len);
    }
    return at + 5 + len;
}

/* The output of the same stream, cut in every way that matters, must be the same. */
static void same_for_every_cut(const uint8_t *in, size_t n, const fake *start, size_t inspect_max,
                               int fastpath, const uint8_t *want, size_t want_len, int want_rc)
{
    static const size_t chunks[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 64, 100000};

    for (size_t i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
        fake f = *start;
        sl_buf out;
        int rc;

        sl_buf_init(&out);
        rc = drive(in, n, chunks[i], &f, inspect_max, fastpath, &out);
        if (rc != want_rc || sl_buf_len(&out) != want_len ||
            (want_len && memcmp(sl_buf_data(&out), want, want_len) != 0)) {
            fprintf(stderr,
                    "cut in reads of %zu bytes: rc %d, %zu bytes out (want rc %d, %zu bytes)\n",
                    chunks[i], rc, sl_buf_len(&out), want_rc, want_len);
            sl_test_failures++;
        }
        sl_buf_free(&out);
    }
}

static void test_messages_pass(void)
{
    uint8_t in[256];
    size_t n = 0;
    fake f = {0};

    /* a typical extended-protocol batch and a password: nothing is read, nothing changes */
    n = put(in, n, 'p', "s3cret\0", 7);
    n = put(in, n, 'Q', "select 1\0", 9);
    n = put(in, n, 'P', "s1\0select $1\0\0\0", 15);
    n = put(in, n, 'B', "\0s1\0\0\0\0\0\0\0\0\0", 12);
    n = put(in, n, 'E', "\0\0\0\0\0", 5);
    n = put(in, n, 'S', "", 0);
    n = put(in, n, 'X', "", 0);
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, n, SL_SCAN_OK);
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 1, in, n, SL_SCAN_OK);
}

static void test_blocking(void)
{
    uint8_t in[256];
    uint8_t want[256];
    uint8_t rep[32];
    size_t n = 0;
    size_t w = 0;
    size_t rn = replacement_message(rep);
    fake f = {.block_statements = 1};

    n = put(in, n, 'Q', "select 1\0", 9);
    n = put(in, n, 'Q', "Bad\0", 4); /* blocked */
    n = put(in, n, 'S', "", 0);
    n = put(in, n, 'P', "Bp\0", 3); /* blocked */
    n = put(in, n, 'B', "Bind data",
            9); /* not a Query or Parse: never looked at, even with a 'B' inside */
    n = put(in, n, 'Q', "fine\0", 5);

    w = put(want, w, 'Q', "select 1\0", 9);
    memcpy(want + w, rep, rn);
    w += rn;
    w = put(want, w, 'S', "", 0);
    memcpy(want + w, rep, rn);
    w += rn;
    w = put(want, w, 'B', "Bind data", 9);
    w = put(want, w, 'Q', "fine\0", 5);

    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, want, w, SL_SCAN_OK);

    /* blocking is off: the same stream goes through */
    f.block_statements = 0;
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, n, SL_SCAN_OK);
}

static void test_big_messages(void)
{
    enum { MAX = 16 };
    uint8_t in[512];
    uint8_t want[512];
    uint8_t rep[32];
    char body[100];
    size_t n = 0;
    size_t w = 0;
    size_t rn = replacement_message(rep);
    fake f = {0};

    memset(body, 'y', sizeof body);
    n = put(in, n, 'Q', "ok\0", 3);
    n = put(in, n, 'Q', body, sizeof body); /* over the limit of 16 */
    n = put(in, n, 'Q', "after\0", 6);
    n = put(in, n, 'P', body, 50); /* also over it */
    n = put(in, n, 'Q', "end\0", 4);

    /* relayed unread: everything comes out as it went in */
    same_for_every_cut(in, n, &f, MAX, 0, in, n, SL_SCAN_OK);

    /* blocked: the header is replaced and the body thrown away, whatever the cuts */
    f.block_unreadable = 1;
    w = put(want, w, 'Q', "ok\0", 3);
    memcpy(want + w, rep, rn);
    w += rn;
    w = put(want, w, 'Q', "after\0", 6);
    memcpy(want + w, rep, rn);
    w += rn;
    w = put(want, w, 'Q', "end\0", 4);
    same_for_every_cut(in, n, &f, MAX, 0, want, w, SL_SCAN_OK);

    /* a message exactly at the limit is still read */
    {
        fake g = {0};
        sl_buf out;

        n = put(in, 0, 'Q', body, MAX);
        sl_buf_init(&out);
        CHECK(drive(in, n, 3, &g, MAX, 0, &out) == SL_SCAN_OK);
        CHECK(g.statements == 1 && g.unreadable == 0);
        sl_buf_free(&out);
        n = put(in, 0, 'Q', body, MAX + 1);
        sl_buf_init(&out);
        CHECK(drive(in, n, 3, &g, MAX, 0, &out) == SL_SCAN_OK);
        CHECK(g.unreadable == 1 && g.too_big_seen == 1);
        sl_buf_free(&out);
    }
}

static void test_fastpath(void)
{
    uint8_t in[64];
    uint8_t want[64];
    uint8_t rep[32];
    size_t n = 0;
    size_t w = 0;
    size_t rn = replacement_message(rep);
    fake f = {.block_unreadable = 1};

    n = put(in, n, 'F', "\0\0\x04\xd2\0\0\0\0\0\0", 10);
    n = put(in, n, 'Q', "x\0", 2);

    /* without a policy nobody asks about 'F': it is relayed like any other message */
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, n, SL_SCAN_OK);

    memcpy(want, rep, rn);
    w = rn;
    w = put(want, w, 'Q', "x\0", 2);
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 1, want, w, SL_SCAN_OK);
    {
        fake g = {0};
        sl_buf out;

        sl_buf_init(&out);
        CHECK(drive(in, n, 2, &g, SL_SCAN_INSPECT_MAX, 1, &out) == SL_SCAN_OK);
        CHECK(g.unreadable == 1 &&
              g.too_big_seen == 0); /* asked as "not too big": it is a fast-path call */
        sl_buf_free(&out);
    }
}

static void test_frame_errors(void)
{
    uint8_t in[64];
    size_t n = 0;
    size_t good;
    fake f = {0};

    n = put(in, n, 'Q', "select 1\0", 9);
    good = n;
    memcpy(in + n, "Z\x00\x00\x00\x02junk", 9); /* a length of 2: cannot be a message */
    n += 9;
    n = put(in, n, 'Q', "Bdrop\0", 6); /* what comes after is not to be trusted */

    /* audit: inspection stops, the rest goes through unread */
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, n, SL_SCAN_OK);
    f.block_statements = 1;
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, n, SL_SCAN_OK);

    /* enforce: the scanner says to close, and nothing after the last good message was released */
    f.close_on_frame_error = 1;
    same_for_every_cut(in, n, &f, SL_SCAN_INSPECT_MAX, 0, in, good, SL_SCAN_CLOSE);

    /* the frame error is reported once, not once per read */
    {
        fake g = {0};
        sl_buf out;

        sl_buf_init(&out);
        CHECK(drive(in, n, 1, &g, SL_SCAN_INSPECT_MAX, 0, &out) == SL_SCAN_OK);
        CHECK(g.frame_errors == 1);
        sl_buf_free(&out);
    }
}

static void test_held_and_eof(void)
{
    uint8_t in[64];
    sl_scan s;
    sl_buf buf;
    fake f = {0};
    size_t n = put(in, 0, 'Q', "select 1\0", 9);

    sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
    sl_buf_init(&buf);

    /* an incomplete Query is held: nothing may be sent until it is whole */
    CHECK(sl_buf_append(&buf, in, n - 1) == 0);
    CHECK(sl_scan_run(&s, &buf, &ops, &f) == SL_SCAN_OK);
    CHECK(s.released == 0 && f.statements == 0);
    CHECK(sl_buf_append(&buf, in + n - 1, 1) == 0);
    CHECK(sl_scan_run(&s, &buf, &ops, &f) == SL_SCAN_OK);
    CHECK(s.released == n && f.statements == 1);

    /* a header cut in two */
    sl_buf_consume(&buf, n);
    s.released = 0;
    CHECK(sl_buf_append(&buf, in, 3) == 0);
    CHECK(sl_scan_run(&s, &buf, &ops, &f) == SL_SCAN_OK && s.released == 0);
    sl_buf_free(&buf);

    /* a stream that never gets a body: bytes of the unread body are released as they come, not held
     */
    sl_scan_init(&s, 0, 8);
    sl_buf_init(&buf);
    {
        uint8_t big[5];

        big[0] = 'Q';
        sl_pg_put_be32(big + 1, 4 + 1000);
        CHECK(sl_buf_append(&buf, big, 5) == 0);
        CHECK(sl_buf_append(&buf, "xxxxxxxxxx", 10) == 0);
        CHECK(sl_scan_run(&s, &buf, &ops, &f) == SL_SCAN_OK);
        CHECK(s.released == 15 && s.pass_remaining == 990);
    }
    sl_buf_free(&buf);
}

/* ---- guard, wait, inject and the count of answers owed ---- */

typedef struct {
    int waits; /* how many times a "W..." statement is asked to wait before it is let through */
    int asked_wait; /* how many times it was handed over */
} guard_fake;

static int guard_statement(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                           sl_buf *replacement)
{
    guard_fake *g = ctx;
    uint8_t msg[32];
    size_t n;

    (void)type;
    if (len > 0 && payload[0] == 'G') {
        n = replacement_message(msg);
        return sl_buf_append(replacement, msg, n) == 0 ? SL_SCAN_GUARD : SL_SCAN_FAIL;
    }
    if (len > 0 && payload[0] == 'W') {
        g->asked_wait++;
        if (g->waits > 0) {
            g->waits--;
            return SL_SCAN_WAIT;
        }
    }
    return SL_SCAN_RELAY;
}

static const sl_scan_ops guard_ops = {guard_statement, fake_unreadable, fake_frame_error};

static void test_guard_wait_inject(void)
{
    uint8_t in[512];
    size_t n = 0;
    sl_scan s;
    sl_buf buf;
    guard_fake g = {0, 0};
    fake f = {0};

    /* a Query that is guarded: its replacement goes, and what follows waits */
    n = put(in, n, 'Q', "select 1\0", 9);
    n = put(in, n, 'Q', "Gdelete\0", 8);
    n = put(in, n, 'Q', "after\0", 6);
    n = put(in, n, 'S', "", 0);
    sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
    sl_buf_init(&buf);
    CHECK(sl_buf_append(&buf, in, n) == 0);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.paused == 1);
    CHECK(s.owed == 2); /* "select 1" and the replacement */
    {
        uint8_t first[64];
        size_t k = put(first, 0, 'Q', "select 1\0", 9);
        uint8_t repl[32];
        size_t rn = replacement_message(repl);

        CHECK(s.released == k + rn);
        CHECK_MEM(sl_buf_data(&buf) + k, repl, rn);
    }
    /* still paused: running again changes nothing */
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK && s.owed == 2);

    /* the caller puts a message of its own, then lets the stream go on */
    {
        uint8_t commit[16];
        size_t cn = put(commit, 0, 'Q', "COMMIT\0", 7);
        size_t before = s.released;

        CHECK(sl_scan_inject(&s, &buf, commit, cn, 1) == 0);
        CHECK(s.released == before + cn && s.owed == 3);
        CHECK_MEM(sl_buf_data(&buf) + before, commit, cn);
    }
    sl_scan_resume(&s);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.paused == 0);
    CHECK(s.owed == 5); /* "after" and the Sync */
    CHECK(s.released == sl_buf_len(&buf));
    sl_buf_free(&buf);

    /* a statement that waits stays where it is, and is handed over again after the resume */
    n = 0;
    n = put(in, n, 'Q', "Wsomething\0", 11);
    n = put(in, n, 'Q', "next\0", 5);
    g.waits = 2;
    g.asked_wait = 0;
    sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
    sl_buf_init(&buf);
    CHECK(sl_buf_append(&buf, in, n) == 0);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.paused == 1 && s.released == 0 && s.owed == 0 && g.asked_wait == 1);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK && g.asked_wait == 1); /* paused */
    sl_scan_resume(&s);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.paused == 1 && s.released == 0 && g.asked_wait == 2);
    sl_scan_resume(&s);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.paused == 0 && s.released == n && s.owed == 2 && g.asked_wait == 3);
    sl_buf_free(&buf);

    /* the answers owed: Query, Sync and fast-path call count; Parse, Bind, Execute, Flush do not */
    n = 0;
    n = put(in, n, 'P', "\0select 1\0\0\0", 12);
    n = put(in, n, 'B', "\0\0\0\0\0\0\0", 7);
    n = put(in, n, 'E', "\0\0\0\0\0", 5);
    n = put(in, n, 'H', "", 0);
    n = put(in, n, 'S', "", 0);
    n = put(in, n, 'Q', "select 2\0", 9);
    n = put(in, n, 'F', "\0\0\0\0\0\0\0\0\0\0", 10);
    sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
    sl_buf_init(&buf);
    CHECK(sl_buf_append(&buf, in, n) == 0);
    CHECK(sl_scan_run(&s, &buf, &guard_ops, &g) == SL_SCAN_OK);
    CHECK(s.owed == 3 && s.owed_unknown == 0);
    sl_buf_free(&buf);

    /* a blocked Query is replaced by a Query: still one answer. A blocked fast-path call too. */
    n = 0;
    n = put(in, n, 'Q', "Bdelete\0", 8);
    sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
    sl_buf_init(&buf);
    f.block_statements = 1;
    CHECK(sl_buf_append(&buf, in, n) == 0);
    {
        static const sl_scan_ops blocking = {fake_statement, fake_unreadable, fake_frame_error};

        CHECK(sl_scan_run(&s, &buf, &blocking, &f) == SL_SCAN_OK);
    }
    CHECK(s.owed == 1);
    sl_buf_free(&buf);

    /* once the framing is lost and let go, the count cannot be trusted */
    {
        uint8_t junk[16] = {'Q', 0, 0, 0, 1, 0, 0, 0, 0}; /* a length below 4 */

        f.close_on_frame_error = 0;
        sl_scan_init(&s, 0, SL_SCAN_INSPECT_MAX);
        sl_buf_init(&buf);
        CHECK(sl_buf_append(&buf, junk, sizeof junk) == 0);
        CHECK(sl_scan_run(&s, &buf, &ops, &f) == SL_SCAN_OK);
        CHECK(s.owed_unknown == 1);
        sl_buf_free(&buf);
    }
}

int main(void)
{
    test_messages_pass();
    test_blocking();
    test_big_messages();
    test_fastpath();
    test_frame_errors();
    test_held_and_eof();
    test_guard_wait_inject();
    return TEST_RESULT();
}
