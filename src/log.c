#include "log.h"

#include <string.h>
#include <time.h>

#include "json.h"

static FILE *g_sink;

void sl_log_set_sink(FILE *f)
{
    g_sink = f;
}

static void now_iso(char *out, size_t cap)
{
    struct timespec ts;
    struct tm tm;
    char base[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, cap, "%s.%03ldZ", base, (long)(ts.tv_nsec / 1000000));
}

static void raw(sl_log_ev *ev, const char *s)
{
    if (sl_buf_append(&ev->b, s, strlen(s)) != 0) {
        ev->failed = 1;
    }
}

static void json_string(sl_log_ev *ev, const void *s, size_t n)
{
    if (sl_json_append_string(&ev->b, s, n) != 0) {
        ev->failed = 1;
    }
}

static void key(sl_log_ev *ev, const char *k)
{
    raw(ev, ",\"");
    raw(ev, k);
    raw(ev, "\":");
}

void sl_log_begin(sl_log_ev *ev, const char *event)
{
    char ts[64];

    sl_buf_init(&ev->b);
    ev->failed = 0;
    now_iso(ts, sizeof ts);
    raw(ev, "{\"ts\":\"");
    raw(ev, ts);
    raw(ev, "\",\"event\":");
    json_string(ev, event, strlen(event));
}

void sl_log_str(sl_log_ev *ev, const char *k, const void *val, size_t len)
{
    key(ev, k);
    json_string(ev, val, len);
}

void sl_log_cstr(sl_log_ev *ev, const char *k, const char *val)
{
    if (val == NULL) {
        key(ev, k);
        raw(ev, "null");
        return;
    }
    sl_log_str(ev, k, val, strlen(val));
}

void sl_log_int(sl_log_ev *ev, const char *k, long long val)
{
    char num[32];

    snprintf(num, sizeof num, "%lld", val);
    key(ev, k);
    raw(ev, num);
}

void sl_log_bool(sl_log_ev *ev, const char *k, int val)
{
    key(ev, k);
    raw(ev, val ? "true" : "false");
}

void sl_log_list(sl_log_ev *ev, const char *k, const char *const *items, size_t n)
{
    key(ev, k);
    raw(ev, "[");
    for (size_t i = 0; i < n; i++) {
        if (i > 0) {
            raw(ev, ",");
        }
        json_string(ev, items[i], strlen(items[i]));
    }
    raw(ev, "]");
}

void sl_log_end(sl_log_ev *ev)
{
    FILE *f = g_sink ? g_sink : stdout;
    size_t len;

    raw(ev, "}\n");
    len = sl_buf_len(&ev->b);
    if (!ev->failed) {
        if (fwrite(sl_buf_data(&ev->b), 1, len, f) == len) {
            fflush(f);
        }
    }
    sl_buf_free(&ev->b);
}
