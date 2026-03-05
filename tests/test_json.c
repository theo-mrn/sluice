#include "check.h"
#include "json.h"

/* Escapes `in` (n bytes) and compares with the expected JSON text. */
static void expect(const char *in, size_t n, const char *want)
{
    sl_buf b;

    sl_buf_init(&b);
    CHECK(sl_json_append_string(&b, in, n) == 0);
    CHECK(sl_buf_len(&b) == strlen(want));
    if (sl_buf_len(&b) == strlen(want)) {
        CHECK_MEM(sl_buf_data(&b), want, strlen(want));
    }
    sl_buf_free(&b);
}

#define EXPECT(lit, want) expect((lit), sizeof(lit) - 1, (want))

int main(void)
{
    EXPECT("", "\"\"");
    EXPECT("abc", "\"abc\"");
    EXPECT("say \"hi\"", "\"say \\\"hi\\\"\"");
    EXPECT("back\\slash", "\"back\\\\slash\"");
    EXPECT("a\nb\rc\td", "\"a\\nb\\rc\\td\"");
    EXPECT("\b\f", "\"\\b\\f\"");
    EXPECT("\x01\x1f", "\"\\u0001\\u001f\"");
    EXPECT("a\0b", "\"a\\u0000b\""); /* an embedded NUL does not end the string */
    EXPECT("\x7f", "\"\x7f\"");

    /* valid UTF-8 goes through untouched: 2, 3 and 4 byte sequences */
    EXPECT("\xc3\xa9", "\"\xc3\xa9\"");
    EXPECT("\xe2\x82\xac", "\"\xe2\x82\xac\"");
    EXPECT("\xf0\x9f\x98\x80", "\"\xf0\x9f\x98\x80\"");

    /* invalid UTF-8 becomes U+FFFD, one per offending byte */
    EXPECT("\x80", "\"\\ufffd\"");                                  /* stray continuation byte */
    EXPECT("a\xc3", "\"a\\ufffd\"");                                /* truncated at the end */
    EXPECT("\xc3(", "\"\\ufffd(\"");                                /* bad continuation byte */
    EXPECT("\xc0\x80", "\"\\ufffd\\ufffd\"");                       /* overlong NUL */
    EXPECT("\xed\xa0\x80", "\"\\ufffd\\ufffd\\ufffd\"");            /* UTF-16 surrogate */
    EXPECT("\xf4\x90\x80\x80", "\"\\ufffd\\ufffd\\ufffd\\ufffd\""); /* beyond U+10FFFF */
    EXPECT("\xff", "\"\\ufffd\"");

    /* no input at all */
    expect(NULL, 0, "\"\"");

    /* shortening a value never cuts a UTF-8 sequence in two */
    CHECK(sl_json_utf8_prefix("abc", 3, 10) == 3);
    CHECK(sl_json_utf8_prefix("abcdef", 6, 3) == 3);
    CHECK(sl_json_utf8_prefix("a\xc3\xa9", 3, 2) == 1); /* é does not fit: drop it */
    CHECK(sl_json_utf8_prefix("a\xc3\xa9", 3, 3) == 3);
    CHECK(sl_json_utf8_prefix("\xe2\x82\xac", 3, 2) == 0); /* 3 byte sequence, 2 allowed */
    CHECK(sl_json_utf8_prefix("ab\xe2\x82\xac", 5, 4) == 2);
    CHECK(sl_json_utf8_prefix("ab\xe2\x82\xac", 5, 2) == 2); /* cut falls right before it */
    CHECK(sl_json_utf8_prefix("\xf0\x9f\x98\x80x", 5, 3) == 0);
    CHECK(sl_json_utf8_prefix("\x80\x80\x80\x80", 4, 2) == 0); /* only stray bytes: nothing safe */
    CHECK(sl_json_utf8_prefix(NULL, 0, 5) == 0);

    return TEST_RESULT();
}
