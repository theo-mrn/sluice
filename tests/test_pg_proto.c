#include "check.h"
#include "pg_proto.h"

/* Builds a packet: int32 total length, int32 code, then body. Returns its length. */
static size_t make_packet(uint8_t *out, uint32_t code, const uint8_t *body, size_t body_len)
{
    sl_pg_put_be32(out, (uint32_t)(8 + body_len));
    sl_pg_put_be32(out + 4, code);
    if (body_len) {
        memcpy(out + 8, body, body_len);
    }
    return 8 + body_len;
}

static void test_startup_framing(void)
{
    uint8_t pkt[64];
    sl_pg_startup_packet p;
    size_t n;

    /* partial input is "need more", including nothing at all */
    CHECK(sl_pg_parse_startup_packet(NULL, 0, &p) == SL_PG_NEED_MORE);
    n = make_packet(pkt, SL_PG_SSL_REQUEST_CODE, NULL, 0);
    for (size_t i = 0; i < n; i++) {
        CHECK(sl_pg_parse_startup_packet(pkt, i, &p) == SL_PG_NEED_MORE);
    }

    /* SSLRequest, GSSENCRequest */
    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
    CHECK(p.kind == SL_PG_SSL_REQUEST && p.total_len == 8 && p.body_len == 0);
    n = make_packet(pkt, SL_PG_GSSENC_REQUEST_CODE, NULL, 0);
    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
    CHECK(p.kind == SL_PG_GSSENC_REQUEST);

    /* extra bytes after the packet are not part of it */
    n = make_packet(pkt, SL_PG_SSL_REQUEST_CODE, NULL, 0);
    memset(pkt + n, 0xAA, 16);
    CHECK(sl_pg_parse_startup_packet(pkt, n + 16, &p) == SL_PG_OK);
    CHECK(p.total_len == 8);

    /* CancelRequest carries pid and key: 16 bytes in total, and only 16 */
    {
        const uint8_t body[8] = {0, 0, 0, 7, 1, 2, 3, 4};

        n = make_packet(pkt, SL_PG_CANCEL_REQUEST_CODE, body, sizeof body);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(p.kind == SL_PG_CANCEL_REQUEST && p.total_len == 16 && p.body_len == 8);
        n = make_packet(pkt, SL_PG_CANCEL_REQUEST_CODE, body, 4);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_ERROR);
    }

    /* a request code with a wrong length is refused */
    {
        const uint8_t body[4] = {0};

        n = make_packet(pkt, SL_PG_SSL_REQUEST_CODE, body, sizeof body);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_ERROR);
    }

    /* lengths that cannot be right fail without waiting for more bytes */
    {
        const uint8_t too_short[4] = {0, 0, 0, 7};
        const uint8_t too_long[4] = {0, 0, 0x27, 0x11}; /* 10001 */
        const uint8_t huge[4] = {0xff, 0xff, 0xff, 0xff};

        CHECK(sl_pg_parse_startup_packet(too_short, 4, &p) == SL_PG_ERROR);
        CHECK(sl_pg_parse_startup_packet(too_long, 4, &p) == SL_PG_ERROR);
        CHECK(sl_pg_parse_startup_packet(huge, 4, &p) == SL_PG_ERROR);
    }

    /* unknown codes and other protocol majors */
    n = make_packet(pkt, 0x00010000, NULL, 0);
    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_ERROR);
    n = make_packet(pkt, 12345, NULL, 0);
    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_ERROR);
}

static void test_startup_params(void)
{
    static const uint8_t body[] = "user\0alice\0database\0db1\0application_name\0psql\0";
    /* sizeof includes the implicit final NUL, which is the list terminator */
    uint8_t pkt[128];
    sl_pg_startup_packet p;
    size_t n = make_packet(pkt, 196608, body, sizeof body);
    const char *val;
    size_t vlen;

    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
    CHECK(p.kind == SL_PG_STARTUP_MESSAGE && p.code == 196608);

    CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == 1);
    CHECK(vlen == 5 && memcmp(val, "alice", 5) == 0);
    CHECK(sl_pg_startup_param(&p, "database", &val, &vlen) == 1);
    CHECK(vlen == 3 && memcmp(val, "db1", 3) == 0);
    CHECK(sl_pg_startup_param(&p, "application_name", &val, &vlen) == 1);
    CHECK(vlen == 4 && memcmp(val, "psql", 4) == 0);
    CHECK(sl_pg_startup_param(&p, "options", &val, &vlen) == 0);
    CHECK(sl_pg_startup_param(&p, "use", &val, &vlen) == 0); /* a prefix is not a match */

    /* protocol 3.2 is still a startup message */
    n = make_packet(pkt, 196610, body, sizeof body);
    CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
    CHECK(p.kind == SL_PG_STARTUP_MESSAGE);

    /* empty parameter list: just the terminator */
    {
        const uint8_t empty[1] = {0};

        n = make_packet(pkt, 196608, empty, 1);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == 0);
    }

    /* malformed lists: no terminator, key without value, unterminated value, no body at all */
    {
        const uint8_t no_term[] = {'u', 's', 'e', 'r', 0, 'a', 0};
        const uint8_t key_only[] = {'u', 's', 'e', 'r', 0};
        const uint8_t open_value[] = {'u', 's', 'e', 'r', 0, 'a', 'b'};

        n = make_packet(pkt, 196608, no_term, sizeof no_term);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(sl_pg_startup_param(&p, "nope", &val, &vlen) == -1);
        CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == 1); /* found before the end */

        n = make_packet(pkt, 196608, key_only, sizeof key_only);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == -1);

        n = make_packet(pkt, 196608, open_value, sizeof open_value);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == -1);

        n = make_packet(pkt, 196608, NULL, 0);
        CHECK(sl_pg_parse_startup_packet(pkt, n, &p) == SL_PG_OK);
        CHECK(sl_pg_startup_param(&p, "user", &val, &vlen) == -1);
    }
}

static void test_messages(void)
{
    /* Query "SEL1": type, length 4 + 5, then the NUL terminated text */
    const uint8_t q[] = {'Q', 0, 0, 0, 9, 'S', 'E', 'L', '1', 0};
    sl_pg_header h;
    sl_pg_message m;

    /* the header needs only five bytes */
    CHECK(sl_pg_parse_header(q, 0, &h) == SL_PG_NEED_MORE);
    CHECK(sl_pg_parse_header(q, 4, &h) == SL_PG_NEED_MORE);
    CHECK(sl_pg_parse_header(q, 5, &h) == SL_PG_OK);
    CHECK(h.type == 'Q' && h.payload_len == 5);

    /* the message needs all of it */
    for (size_t i = 0; i < sizeof q; i++) {
        CHECK(sl_pg_parse_message(q, i, &m) == SL_PG_NEED_MORE);
    }
    CHECK(sl_pg_parse_message(q, sizeof q, &m) == SL_PG_OK);
    CHECK(m.type == 'Q' && m.payload_len == 5 && m.total_len == 10);
    CHECK(m.payload == q + 5);

    /* a following message does not matter */
    {
        uint8_t two[sizeof q * 2];

        memcpy(two, q, sizeof q);
        memcpy(two + sizeof q, q, sizeof q);
        CHECK(sl_pg_parse_message(two, sizeof two, &m) == SL_PG_OK);
        CHECK(m.total_len == sizeof q);
    }

    /* a message without payload: length is exactly 4 */
    {
        const uint8_t term[] = {'X', 0, 0, 0, 4};

        CHECK(sl_pg_parse_message(term, sizeof term, &m) == SL_PG_OK);
        CHECK(m.type == 'X' && m.payload_len == 0 && m.total_len == 5);
    }

    /* lengths below 4 and above the limit are errors, not "need more" */
    {
        const uint8_t small[] = {'Q', 0, 0, 0, 3};
        const uint8_t big[] = {'Q', 0x40, 0, 0, 0};
        const uint8_t max[] = {'Q', 0x3f, 0xff, 0xff, 0xff};

        CHECK(sl_pg_parse_header(small, sizeof small, &h) == SL_PG_ERROR);
        CHECK(sl_pg_parse_header(big, sizeof big, &h) == SL_PG_ERROR);
        CHECK(sl_pg_parse_header(max, sizeof max, &h) == SL_PG_OK);
        CHECK(h.payload_len == 0x3fffffffu - 4);
        /* the full message of that size is not there yet, and must not overflow */
        CHECK(sl_pg_parse_message(max, sizeof max, &m) == SL_PG_NEED_MORE);
    }
}

static void test_append_error(void)
{
    /* S, V, C and M fields, each NUL terminated, then the final NUL */
    static const char want[] = "SFATAL\0VFATAL\0C08001\0Mboom\0";
    sl_buf b;
    sl_pg_message m;

    sl_buf_init(&b);
    CHECK(sl_pg_append_error(&b, "FATAL", "08001", "boom") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    CHECK(m.type == 'E');
    CHECK(m.total_len == sl_buf_len(&b)); /* the length field is consistent */
    CHECK(m.payload_len == sizeof want);
    CHECK_MEM(m.payload, want, sizeof want);

    /* appending twice yields two messages back to back */
    CHECK(sl_pg_append_error(&b, "ERROR", "42501", "no") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    {
        size_t first = m.total_len;

        CHECK(sl_pg_parse_message(sl_buf_data(&b) + first, sl_buf_len(&b) - first, &m) == SL_PG_OK);
        CHECK(m.type == 'E' && first + m.total_len == sl_buf_len(&b));
    }
    sl_buf_free(&b);
}

static void test_statements(void)
{
    sl_pg_statement st;

    /* Query: the text and one NUL */
    {
        static const uint8_t q[] = "select 1"; /* sizeof includes the NUL */

        CHECK(sl_pg_statement_from_query(q, sizeof q, &st) == SL_PG_OK);
        CHECK(st.sql_len == 8 && memcmp(st.sql, "select 1", 8) == 0);
        CHECK(st.name_len == 0);
    }
    {
        const uint8_t empty[1] = {0}; /* an empty query is valid */

        CHECK(sl_pg_statement_from_query(empty, 1, &st) == SL_PG_OK);
        CHECK(st.sql_len == 0);
    }
    {
        const uint8_t no_nul[] = {'a', 'b', 'c'};
        const uint8_t inner_nul[] = {'a', 0, 'b', 0};

        CHECK(sl_pg_statement_from_query(NULL, 0, &st) == SL_PG_ERROR);
        CHECK(st.sql == NULL && st.sql_len == 0); /* zeroed on error */
        CHECK(sl_pg_statement_from_query(no_nul, sizeof no_nul, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_query(inner_nul, sizeof inner_nul, &st) == SL_PG_ERROR);
    }

    /* Parse: name, SQL, parameter count, type ids */
    {
        const uint8_t p[] = {'s', '1', 0, 's', 'e', 'l', ' ', '$', '1', 0, 0, 1, 0, 0, 0, 23};

        CHECK(sl_pg_statement_from_parse(p, sizeof p, &st) == SL_PG_OK);
        CHECK(st.name_len == 2 && memcmp(st.name, "s1", 2) == 0);
        CHECK(st.sql_len == 6 && memcmp(st.sql, "sel $1", 6) == 0);
    }
    {
        const uint8_t unnamed[] = {0, 'x', 0, 0, 0}; /* unnamed statement, no parameters */

        CHECK(sl_pg_statement_from_parse(unnamed, sizeof unnamed, &st) == SL_PG_OK);
        CHECK(st.name_len == 0 && st.sql_len == 1 && st.sql[0] == 'x');
    }
    {
        const uint8_t short_msg[] = {0, 0, 0};
        const uint8_t no_second_nul[] = {'n', 0, 'x', 'y'};
        const uint8_t no_name_nul[] = {'n', 'a', 'm', 'e', 'x'};
        const uint8_t no_count[] = {'n', 0, 'x', 0, 7};
        const uint8_t missing_ids[] = {'n', 0, 'x', 0, 0, 1};
        const uint8_t extra_bytes[] = {'n', 0, 'x', 0, 0, 0, 9};

        CHECK(sl_pg_statement_from_parse(NULL, 0, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(short_msg, sizeof short_msg, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(no_name_nul, sizeof no_name_nul, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(no_second_nul, sizeof no_second_nul, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(no_count, sizeof no_count, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(missing_ids, sizeof missing_ids, &st) == SL_PG_ERROR);
        CHECK(sl_pg_statement_from_parse(extra_bytes, sizeof extra_bytes, &st) == SL_PG_ERROR);
        CHECK(st.sql == NULL && st.name == NULL);
    }
}

static void test_failing_messages(void)
{
    sl_buf b;
    sl_pg_message m;
    sl_pg_statement st;

    /* Query: round trip through our own parsers */
    sl_buf_init(&b);
    CHECK(sl_pg_append_failing_query(&b, "sluice: blocked by rule r1") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    CHECK(m.type == 'Q' && m.total_len == sl_buf_len(&b));
    CHECK(sl_pg_statement_from_query(m.payload, m.payload_len, &st) == SL_PG_OK);
    CHECK(st.sql_len == strlen("select 'sluice: blocked by rule r1'::int"));
    CHECK_MEM(st.sql, "select 'sluice: blocked by rule r1'::int", st.sql_len);
    sl_buf_free(&b);

    /* the reason can not break out of the string literal, whatever it contains */
    sl_buf_init(&b);
    CHECK(sl_pg_append_failing_query(&b, "it's \\ a\ttest \xc3\xa9; drop table t; --") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    CHECK(sl_pg_statement_from_query(m.payload, m.payload_len, &st) == SL_PG_OK);
    {
        static const char want[] = "select 'it''s   a test ??; drop table t; --'::int";

        CHECK(st.sql_len == sizeof want - 1);
        CHECK_MEM(st.sql, want, sizeof want - 1);
    }
    sl_buf_free(&b);

    /* long reasons are cut */
    {
        char reason[1000];

        memset(reason, 'x', sizeof reason - 1);
        reason[sizeof reason - 1] = '\0';
        sl_buf_init(&b);
        CHECK(sl_pg_append_failing_query(&b, reason) == 0);
        CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
        CHECK(sl_pg_statement_from_query(m.payload, m.payload_len, &st) == SL_PG_OK);
        CHECK(st.sql_len == 8 + 300 + 6); /* select ' + 300 + '::int */
        sl_buf_free(&b);
    }

    /* Parse: the statement name is kept, there are no parameters, and our parser accepts the
     * message */
    sl_buf_init(&b);
    CHECK(sl_pg_append_failing_parse(&b, "stmt_1", 6, "sluice: no") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    CHECK(m.type == 'P' && m.total_len == sl_buf_len(&b));
    CHECK(sl_pg_statement_from_parse(m.payload, m.payload_len, &st) == SL_PG_OK);
    CHECK(st.name_len == 6 && memcmp(st.name, "stmt_1", 6) == 0);
    CHECK(st.sql_len == strlen("select 'sluice: no'::int"));
    sl_buf_free(&b);

    /* unnamed statement */
    sl_buf_init(&b);
    CHECK(sl_pg_append_failing_parse(&b, "", 0, "x") == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&b), sl_buf_len(&b), &m) == SL_PG_OK);
    CHECK(sl_pg_statement_from_parse(m.payload, m.payload_len, &st) == SL_PG_OK);
    CHECK(st.name_len == 0);
    sl_buf_free(&b);
}

/* an AuthenticationSASL payload: code 10, the names, the final NUL. `names` holds them with their
 * NULs. */
static size_t sasl_payload(uint8_t *out, const char *names, size_t names_len)
{
    sl_pg_put_be32(out, 10);
    memcpy(out + 4, names, names_len);
    out[4 + names_len] = 0;
    return 4 + names_len + 1;
}

static void test_sasl_offer(void)
{
    uint8_t pl[256];
    sl_buf out;
    sl_pg_message m;
    size_t n;

    /* PLUS and plain: only the plain one is left, in a well-formed message */
    sl_buf_init(&out);
    n = sasl_payload(pl, "SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0",
                     sizeof "SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0" - 1);
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 1);
    CHECK(sl_pg_parse_message(sl_buf_data(&out), sl_buf_len(&out), &m) == SL_PG_OK);
    CHECK(m.type == 'R' && m.total_len == sl_buf_len(&out));
    CHECK(m.payload_len ==
          4 + sizeof "SCRAM-SHA-256" + 1); /* code, the name and its NUL, the final NUL */
    CHECK(sl_pg_get_be32(m.payload) == 10);
    CHECK_MEM(m.payload + 4, "SCRAM-SHA-256\0\0", sizeof "SCRAM-SHA-256\0\0" - 1);
    sl_buf_free(&out);

    /* the order of the others is kept, whichever side PLUS is on */
    sl_buf_init(&out);
    n = sasl_payload(pl, "A\0SCRAM-SHA-256-PLUS\0B\0", sizeof "A\0SCRAM-SHA-256-PLUS\0B\0" - 1);
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 1);
    CHECK(sl_pg_parse_message(sl_buf_data(&out), sl_buf_len(&out), &m) == SL_PG_OK);
    CHECK_MEM(m.payload + 4, "A\0B\0\0", 5);
    CHECK(m.payload_len == 4 + 5);
    sl_buf_free(&out);

    /* nothing to change: the output stays empty */
    sl_buf_init(&out);
    n = sasl_payload(pl, "SCRAM-SHA-256\0", sizeof "SCRAM-SHA-256\0" - 1);
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 0 && sl_buf_len(&out) == 0);
    n = sasl_payload(pl, "SCRAM-SHA-256-PLUS\0",
                     sizeof "SCRAM-SHA-256-PLUS\0" - 1); /* only PLUS: keep it */
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 0 && sl_buf_len(&out) == 0);
    n = sasl_payload(pl, "", 0);
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 0);
    /* a name that only contains PLUS is not PLUS */
    n = sasl_payload(pl, "SCRAM-SHA-256-PLUS2\0SCRAM-SHA-256\0",
                     sizeof "SCRAM-SHA-256-PLUS2\0SCRAM-SHA-256\0" - 1);
    CHECK(sl_pg_sasl_drop_plus(pl, n, &out) == 0);

    /* another authentication message, and malformed ones */
    sl_pg_put_be32(pl, 0); /* AuthenticationOk */
    CHECK(sl_pg_sasl_drop_plus(pl, 4, &out) == 0);
    sl_pg_put_be32(pl, 11); /* AuthenticationSASLContinue */
    memcpy(pl + 4, "SCRAM-SHA-256-PLUS\0A\0\0", 21);
    CHECK(sl_pg_sasl_drop_plus(pl, 4 + 21, &out) == 0);
    sl_pg_put_be32(pl, 10);
    memcpy(pl + 4, "SCRAM-SHA-256-PLUS\0A\0", 21); /* no final NUL after the last name's own */
    CHECK(sl_pg_sasl_drop_plus(pl, 4 + 20, &out) == 0);
    memcpy(pl + 4, "SCRAM-SHA-256-PLUS\0A", 20); /* a name that never ends */
    CHECK(sl_pg_sasl_drop_plus(pl, 4 + 20, &out) == 0);
    CHECK(sl_pg_sasl_drop_plus(pl, 0, &out) == 0 && sl_buf_len(&out) == 0);
    sl_buf_free(&out);
}

int main(void)
{
    test_sasl_offer();
    test_failing_messages();
    test_statements();
    test_startup_framing();
    test_startup_params();
    test_messages();
    test_append_error();
    return TEST_RESULT();
}
