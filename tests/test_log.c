#include <stdio.h>

#include "check.h"
#include "log.h"

int main(void)
{
    FILE *f = tmpfile();
    char line[512];
    size_t n;
    sl_log_ev ev;

    CHECK(f != NULL);
    if (f == NULL) {
        return 1;
    }
    sl_log_set_sink(f);

    sl_log_begin(&ev, "test_event");
    sl_log_cstr(&ev, "text", "quote\" and \xc3\xa9");
    sl_log_int(&ev, "count", 42);
    sl_log_int(&ev, "negative", -7);
    sl_log_bool(&ev, "flag", 1);
    sl_log_bool(&ev, "off", 0);
    {
        const char *const names[] = {"orders", "public.a\"b"};

        sl_log_list(&ev, "tables", names, 2);
        sl_log_list(&ev, "none", names, 0);
    }
    sl_log_cstr(&ev, "nothing", NULL);
    sl_log_str(&ev, "raw", "ab\0cd", 5);
    sl_log_end(&ev);

    rewind(f);
    CHECK(fgets(line, sizeof line, f) != NULL);
    n = strlen(line);

    CHECK(strncmp(line, "{\"ts\":\"", 7) == 0);
    CHECK(strstr(line, "\"event\":\"test_event\"") != NULL);
    CHECK(strstr(line, "\"text\":\"quote\\\" and \xc3\xa9\"") != NULL);
    CHECK(strstr(line, "\"count\":42") != NULL);
    CHECK(strstr(line, "\"negative\":-7") != NULL);
    CHECK(strstr(line, "\"nothing\":null") != NULL);
    CHECK(strstr(line, "\"flag\":true") != NULL);
    CHECK(strstr(line, "\"tables\":[\"orders\",\"public.a\\\"b\"]") != NULL);
    CHECK(strstr(line, "\"none\":[]") != NULL);
    CHECK(strstr(line, "\"off\":false") != NULL);
    CHECK(strstr(line, "\"raw\":\"ab\\u0000cd\"") != NULL);
    CHECK(n >= 2 && line[n - 2] == '}' && line[n - 1] == '\n');

    /* a timestamp looks like 2026-11-16T10:00:00.123Z */
    CHECK(line[7 + 4] == '-' && line[7 + 10] == 'T' && line[7 + 23] == 'Z');

    /* exactly one line was written */
    CHECK(fgets(line, sizeof line, f) == NULL);

    sl_log_set_sink(NULL);
    fclose(f);
    return TEST_RESULT();
}
