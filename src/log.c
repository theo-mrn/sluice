#include "log.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "json.h"

static FILE *g_sink;
static sl_log_tap_fn g_tap;
static void *g_tap_ctx;

void sl_log_set_tap(sl_log_tap_fn fn, void *ctx)
{
    g_tap = fn;
    g_tap_ctx = ctx;
}

/* the chain (log.h) */
static int g_chain_on;
static uint8_t g_chain_key[1024];
static size_t g_chain_key_len;
static uint8_t g_chain_prev[SL_LOG_CHAIN_HEX / 2];
static unsigned long long g_chain_seq;

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
    ev->name = event;
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

/* Adds seq and chain to the line (which has no closing brace yet). Returns the new chain value
 * in `next`, or -1. */
static int chain_line(sl_log_ev *ev, uint8_t next[SL_LOG_CHAIN_HEX / 2], unsigned long long seq)
{
    static const char hex[] = "0123456789abcdef";
    char tail[48];
    uint8_t *tmp;
    size_t len;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdl = 0;

    snprintf(tail, sizeof tail, ",\"seq\":%llu", seq);
    raw(ev, tail);
    if (ev->failed) {
        return -1;
    }
    len = sl_buf_len(&ev->b);
    tmp = malloc(sizeof g_chain_prev + len);
    if (tmp == NULL) {
        return -1;
    }
    memcpy(tmp, g_chain_prev, sizeof g_chain_prev);
    memcpy(tmp + sizeof g_chain_prev, sl_buf_data(&ev->b), len);
    if (HMAC(EVP_sha256(), g_chain_key, (int)g_chain_key_len, tmp, sizeof g_chain_prev + len, md,
             &mdl) == NULL ||
        mdl < sizeof g_chain_prev) {
        free(tmp);
        return -1;
    }
    free(tmp);
    memcpy(next, md, sizeof g_chain_prev);
    raw(ev, ",\"chain\":\"");
    for (size_t i = 0; i < sizeof g_chain_prev; i++) {
        char two[3] = {hex[next[i] >> 4], hex[next[i] & 15], 0};

        raw(ev, two);
    }
    raw(ev, "\"");
    return ev->failed ? -1 : 0;
}

void sl_log_end(sl_log_ev *ev)
{
    FILE *f = g_sink ? g_sink : stdout;
    size_t len;
    uint8_t next[SL_LOG_CHAIN_HEX / 2];

    if (g_chain_on && !ev->failed && chain_line(ev, next, g_chain_seq + 1) != 0) {
        ev->failed = 1; /* a line that cannot be chained is not written: it would break the chain */
    }
    raw(ev, "}\n");
    len = sl_buf_len(&ev->b);
    if (!ev->failed) {
        if (fwrite(sl_buf_data(&ev->b), 1, len, f) == len) {
            fflush(f);
            if (g_tap != NULL && ev->name != NULL) {
                g_tap(g_tap_ctx, ev->name, (const char *)sl_buf_data(&ev->b), len - 1);
            }
            if (g_chain_on) {
                g_chain_seq++;
                memcpy(g_chain_prev, next, sizeof g_chain_prev);
            }
        }
    }
    sl_buf_free(&ev->b);
}

int sl_log_chain_start(const uint8_t *key, size_t key_len)
{
    sl_log_ev ev;

    if (key_len == 0 || key_len > sizeof g_chain_key) {
        return -1;
    }
    memcpy(g_chain_key, key, key_len);
    g_chain_key_len = key_len;
    memset(g_chain_prev, 0, sizeof g_chain_prev);
    g_chain_seq = 0;
    g_chain_on = 1;
    sl_log_begin(&ev, "chain_start");
    sl_log_int(&ev, "version", 1);
    sl_log_end(&ev);
    return g_chain_seq == 1 ? 0 : -1;
}

void sl_log_chain_stop(void)
{
    sl_log_ev ev;

    if (!g_chain_on) {
        return;
    }
    sl_log_begin(&ev, "chain_end");
    sl_log_end(&ev);
    g_chain_on = 0;
    memset(g_chain_key, 0, sizeof g_chain_key);
}
