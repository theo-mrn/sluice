#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin.h"
#include "check.h"
#include "metrics.h"

/* ---- a fake for what the server gives the listener ---- */

static int answered_yes = -1;
static char answered_id[32];

static void gauges(void *ctx, sl_metrics_gauges *g)
{
    (void)ctx;
    g->active_connections = 3;
    g->pending_confirmations = 1;
    g->rules = 7;
    g->start_unix = 1000;
    g->now_unix = 1090;
    g->version = "9.9.9";
}

static int pending_json(void *ctx, sl_buf *out)
{
    (void)ctx;
    return sl_buf_append(out, "[{\"id\":\"0123456789abcdef\"}]\n", 28);
}

static int pending_text(void *ctx, const char *id, sl_buf *out)
{
    (void)ctx;
    if (strcmp(id, "0123456789abcdef") != 0) {
        return -1;
    }
    return sl_buf_append(out, "delete 3 rows\n", 14);
}

static int answer(void *ctx, const char *id, int yes)
{
    (void)ctx;
    if (strcmp(id, "0123456789abcdef") != 0) {
        return -1;
    }
    answered_yes = yes;
    snprintf(answered_id, sizeof answered_id, "%s", id);
    return 0;
}

static int has(const sl_buf *b, const char *s)
{
    size_t n = strlen(s);
    const char *d = (const char *)sl_buf_data(b);

    for (size_t i = 0; i + n <= sl_buf_len(b); i++) {
        if (memcmp(d + i, s, n) == 0) {
            return 1;
        }
    }
    return 0;
}

static int status(sl_admin *a, const char *method, const char *path, const char *auth, sl_buf *out)
{
    sl_buf_free(out);
    sl_buf_init(out);
    return sl_admin_respond(a, method, path, auth, out);
}

static void test_routes(void)
{
    sl_admin_ops ops = {NULL, gauges, pending_json, pending_text, answer};
    char err[200];
    sl_admin *a =
        sl_admin_new("127.0.0.1", "0", "s3cret-token-0123456789", 23, &ops, err, sizeof err);
    sl_buf out;

    CHECK(a != NULL);
    if (a == NULL) {
        return;
    }
    sl_buf_init(&out);
    /* /healthz needs no token; everything else does */
    CHECK(status(a, "GET", "/healthz", NULL, &out) == 200 && has(&out, "\r\n\r\nok\n"));
    CHECK(status(a, "GET", "/metrics", NULL, &out) == 401 && has(&out, "WWW-Authenticate: Bearer"));
    CHECK(status(a, "GET", "/metrics", "Bearer wrong-token-0123456789", &out) == 401);
    CHECK(status(a, "GET", "/metrics", "Basic s3cret-token-0123456789", &out) == 401);
    CHECK(status(a, "GET", "/metrics", "Bearer s3cret-token-012345678", &out) ==
          401); /* a prefix */
    CHECK(status(a, "GET", "/metrics", "Bearer s3cret-token-0123456789", &out) == 200);
    CHECK(has(&out, "Content-Type: text/plain; version=0.0.4") &&
          has(&out, "sluice_connections_active 3") && has(&out, "sluice_pending_confirmations 1") &&
          has(&out, "sluice_policy_rules 7") && has(&out, "sluice_uptime_seconds 90") &&
          has(&out, "sluice_build_info{version=\"9.9.9\"} 1"));
    CHECK(status(a, "GET", "/metrics?x=1", "bearer s3cret-token-0123456789", &out) ==
          200); /* scheme: any case */

    /* the confirmations */
    CHECK(status(a, "GET", "/pending", "Bearer s3cret-token-0123456789", &out) == 200 &&
          has(&out, "application/json") && has(&out, "0123456789abcdef"));
    CHECK(status(a, "GET", "/pending/0123456789abcdef", "Bearer s3cret-token-0123456789", &out) ==
              200 &&
          has(&out, "delete 3 rows"));
    CHECK(status(a, "GET", "/pending/fedcba9876543210", "Bearer s3cret-token-0123456789", &out) ==
          404);
    CHECK(status(a, "GET", "/pending/not-an-id", "Bearer s3cret-token-0123456789", &out) == 404);
    /* a GET never answers: a chat client or a browser fetches links by itself */
    CHECK(status(a, "GET", "/confirm/0123456789abcdef/yes", "Bearer s3cret-token-0123456789",
                 &out) == 404 &&
          answered_yes == -1);
    CHECK(status(a, "POST", "/confirm/0123456789abcdef/yes", NULL, &out) == 401 &&
          answered_yes == -1);
    CHECK(status(a, "POST", "/confirm/0123456789abcdef/maybe", "Bearer s3cret-token-0123456789",
                 &out) == 404 &&
          answered_yes == -1);
    CHECK(status(a, "POST", "/confirm/fedcba9876543210/yes", "Bearer s3cret-token-0123456789",
                 &out) == 404);
    CHECK(status(a, "POST", "/confirm/0123456789abcdef/no", "Bearer s3cret-token-0123456789",
                 &out) == 200 &&
          answered_yes == 0 && has(&out, "\"answered\":\"no\""));
    CHECK(status(a, "POST", "/confirm/0123456789abcdef/yes", "Bearer s3cret-token-0123456789",
                 &out) == 200 &&
          answered_yes == 1 && strcmp(answered_id, "0123456789abcdef") == 0);
    CHECK(status(a, "DELETE", "/metrics", "Bearer s3cret-token-0123456789", &out) == 405);
    CHECK(status(a, "GET", "/nothing", "Bearer s3cret-token-0123456789", &out) == 404);
    sl_buf_free(&out);
    CHECK(sl_admin_port(a) > 0);
    sl_admin_free(a);

    /* without a token on a loopback address: open (the server refuses this with --confirm-admin) */
    a = sl_admin_new("127.0.0.1", "0", NULL, 0, &ops, err, sizeof err);
    CHECK(a != NULL);
    if (a != NULL) {
        sl_buf_init(&out);
        CHECK(status(a, "GET", "/metrics", NULL, &out) == 200);
        sl_buf_free(&out);
        sl_admin_free(a);
    }
}

static void test_metrics(void)
{
    sl_metrics_gauges g = {1, 2, 3, 100, 160, "1.0"};
    sl_buf out;

    sl_metrics_reset();
    sl_metric_inc(SL_M_STATEMENTS, "allow", "relayed");
    sl_metric_inc(SL_M_STATEMENTS, "allow", "relayed");
    sl_metric_inc(SL_M_STATEMENTS, "deny", "blocked");
    sl_metric_add(SL_M_BYTES, "client_to_upstream", NULL, 1234);
    sl_metric_inc(SL_M_RULE_HITS, "weird \"name\"\nwith\\stuff", "deny");
    sl_buf_init(&out);
    CHECK(sl_metrics_render(&out, &g) == 0);
    CHECK(has(&out, "# HELP sluice_statements_total ") &&
          has(&out, "# TYPE sluice_statements_total counter"));
    CHECK(has(&out, "sluice_statements_total{verdict=\"allow\",action=\"relayed\"} 2\n"));
    CHECK(has(&out, "sluice_statements_total{verdict=\"deny\",action=\"blocked\"} 1\n"));
    CHECK(has(&out, "sluice_bytes_total{direction=\"client_to_upstream\"} 1234\n"));
    CHECK(has(&out, "sluice_connections_total 0\n")); /* a counter without labels starts at 0 */
    CHECK(has(&out, "sluice_rule_hits_total{rule=\"weird "
                    "\\\"name\\\"\\nwith\\\\stuff\",verdict=\"deny\"} 1\n"));
    CHECK(has(&out, "sluice_uptime_seconds 60\n"));
    sl_buf_free(&out);

    /* the number of series is bounded: the rest is counted as dropped, memory does not grow */
    sl_metrics_reset();
    for (int i = 0; i < 5000; i++) {
        char name[32];

        snprintf(name, sizeof name, "rule-%d", i);
        sl_metric_inc(SL_M_RULE_HITS, name, "deny");
    }
    sl_buf_init(&out);
    CHECK(sl_metrics_render(&out, &g) == 0);
    CHECK(has(&out, "sluice_metrics_dropped_series_total ") &&
          !has(&out, "sluice_metrics_dropped_series_total 0\n"));
    CHECK(has(&out, "rule=\"rule-0\"") && !has(&out, "rule=\"rule-4999\""));
    /* one that is already there still counts */
    sl_metric_inc(SL_M_RULE_HITS, "rule-0", "deny");
    sl_buf_free(&out);
    sl_buf_init(&out);
    CHECK(sl_metrics_render(&out, &g) == 0 && has(&out, "rule=\"rule-0\",verdict=\"deny\"} 2\n"));
    sl_buf_free(&out);
    /* labels are cut, never overrun */
    sl_metrics_reset();
    {
        char big[1000];

        memset(big, 'x', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        sl_metric_inc(SL_M_CLOSED, big, NULL);
        sl_metric_add(99, "x", NULL, 1); /* not a metric: ignored */
    }
    sl_buf_init(&out);
    CHECK(sl_metrics_render(&out, &g) == 0 &&
          has(&out, "sluice_connections_closed_total{reason=\"xxxxxxxx"));
    sl_buf_free(&out);
    sl_metrics_reset();
}

int main(void)
{
    test_metrics();
    test_routes();
    return TEST_RESULT();
}
