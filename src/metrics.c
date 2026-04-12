#include "metrics.h"

#include <stdio.h>
#include <string.h>

#define SERIES_MAX 1536
#define SLOTS 4096 /* a power of two, more than twice the series */
#define LABEL_MAX 72

static const struct {
    const char *name;
    const char *help;
    const char *l1, *l2; /* label names, or NULL */
} defs[SL_M_COUNT] = {
    [SL_M_CONNECTIONS] = {"sluice_connections_total", "Connections accepted.", NULL, NULL},
    [SL_M_CLOSED] = {"sluice_connections_closed_total", "Connections ended, by reason.", "reason",
                     NULL},
    [SL_M_STATEMENTS] = {"sluice_statements_total",
                         "Statements judged, by the verdict of the policy and what was done with "
                         "them (relayed, blocked, held).",
                         "verdict", "action"},
    [SL_M_RULE_HITS] = {"sluice_rule_hits_total",
                        "Statements decided by a rule, by rule and verdict.", "rule", "verdict"},
    [SL_M_CONFIRMATIONS] = {"sluice_confirmations_total",
                            "Confirmations of a DELETE, UPDATE, TRUNCATE or DROP, by outcome and "
                            "channel.",
                            "outcome", "channel"},
    [SL_M_LIMITS] = {"sluice_limits_total",
                     "Limits that cut a result or ended a connection, by kind.", "kind", NULL},
    [SL_M_BYTES] = {"sluice_bytes_total", "Bytes relayed between clients and the database.",
                    "direction", NULL},
    [SL_M_MASKED] = {"sluice_masked_values_total", "Values hidden in the rows that clients read.",
                     NULL, NULL},
    [SL_M_EVENTS] = {"sluice_log_events_total", "Lines written to the log, by event.", "event",
                     NULL},
    [SL_M_HOOKS] = {"sluice_event_commands_total",
                    "Commands run for events (--event-command), by outcome.", "outcome", NULL},
    [SL_M_ADMIN] = {"sluice_admin_requests_total", "Requests to the admin listener.", "path",
                    "status"},
    [SL_M_RELOADS] = {"sluice_policy_reloads_total", "Policy reloads, by outcome.", "outcome",
                      NULL},
    [SL_M_DROPPED] = {"sluice_metrics_dropped_series_total",
                      "Series that were not kept because the limit was reached.", NULL, NULL},
};

typedef struct {
    uint8_t metric;
    char l1[LABEL_MAX], l2[LABEL_MAX];
    unsigned long long v;
} series;

static series g_series[SERIES_MAX];
static size_t g_n;
static int16_t g_slot[SLOTS]; /* index + 1 into g_series, 0 empty */

static uint32_t hash(int metric, const char *a, const char *b)
{
    uint32_t h = 2166136261u ^ (uint32_t)metric;

    for (const char *p = a; p != NULL && *p; p++) {
        h = (h ^ (uint8_t)*p) * 16777619u;
    }
    h = (h ^ 0xffu) * 16777619u;
    for (const char *p = b; p != NULL && *p; p++) {
        h = (h ^ (uint8_t)*p) * 16777619u;
    }
    return h;
}

static void copy_label(char *to, const char *from)
{
    snprintf(to, LABEL_MAX, "%s", from != NULL ? from : "");
}

void sl_metric_add(int metric, const char *l1, const char *l2, unsigned long long n)
{
    char a[LABEL_MAX], b[LABEL_MAX];
    uint32_t h;

    if (metric < 0 || metric >= SL_M_COUNT) {
        return;
    }
    copy_label(a, l1);
    copy_label(b, l2);
    h = hash(metric, a, b);
    for (size_t probe = 0; probe < SLOTS; probe++) {
        size_t at = (h + probe) & (SLOTS - 1);
        int idx = g_slot[at];

        if (idx == 0) {
            if (g_n >= SERIES_MAX - 4 && metric != SL_M_DROPPED) { /* the last slots are for this */
                sl_metric_add(SL_M_DROPPED, NULL, NULL, 1);
                return;
            }
            if (g_n >= SERIES_MAX) {
                return;
            }
            g_series[g_n].metric = (uint8_t)metric;
            memcpy(g_series[g_n].l1, a, sizeof a);
            memcpy(g_series[g_n].l2, b, sizeof b);
            g_series[g_n].v = n;
            g_slot[at] = (int16_t)(++g_n);
            return;
        }
        if (g_series[idx - 1].metric == metric && strcmp(g_series[idx - 1].l1, a) == 0 &&
            strcmp(g_series[idx - 1].l2, b) == 0) {
            g_series[idx - 1].v += n;
            return;
        }
    }
}

void sl_metrics_reset(void)
{
    memset(g_series, 0, sizeof g_series);
    memset(g_slot, 0, sizeof g_slot);
    g_n = 0;
}

static int put(sl_buf *o, const char *s)
{
    return sl_buf_append(o, s, strlen(s));
}

/* ok |= put(...) style, without mixing booleans: the first failure is kept */
static void both(int *rc, int r)
{
    if (r != 0) {
        *rc = -1;
    }
}

/* A label value, quoted: a backslash, a quote and a newline are escaped (the text format). */
static int put_label(sl_buf *o, const char *name, const char *value)
{
    int rc = 0;

    both(&rc, put(o, name));
    both(&rc, put(o, "=\""));
    for (const char *p = value; *p; p++) {
        if (*p == '\\' || *p == '"') {
            both(&rc, sl_buf_append(o, "\\", 1));
            both(&rc, sl_buf_append(o, p, 1));
        } else if (*p == '\n') {
            both(&rc, put(o, "\\n"));
        } else if ((unsigned char)*p < 0x20) {
            both(&rc, sl_buf_append(o, "?", 1));
        } else {
            both(&rc, sl_buf_append(o, p, 1));
        }
    }
    both(&rc, put(o, "\""));
    return rc;
}

static int line(sl_buf *o, const char *name, const char *ln1, const char *v1, const char *ln2,
                const char *v2, unsigned long long v)
{
    char num[32];
    int rc = 0;

    both(&rc, put(o, name));
    if (ln1 != NULL) {
        both(&rc, put(o, "{"));
        both(&rc, put_label(o, ln1, v1));
        if (ln2 != NULL) {
            both(&rc, put(o, ","));
            both(&rc, put_label(o, ln2, v2));
        }
        both(&rc, put(o, "}"));
    }
    snprintf(num, sizeof num, " %llu\n", v);
    both(&rc, put(o, num));
    return rc;
}

static int header(sl_buf *o, const char *name, const char *help, const char *type)
{
    int rc = 0;

    both(&rc, put(o, "# HELP "));
    both(&rc, put(o, name));
    both(&rc, put(o, " "));
    both(&rc, put(o, help));
    both(&rc, put(o, "\n# TYPE "));
    both(&rc, put(o, name));
    both(&rc, put(o, " "));
    both(&rc, put(o, type));
    both(&rc, put(o, "\n"));
    return rc;
}

int sl_metrics_render(sl_buf *out, const sl_metrics_gauges *g)
{
    int rc = 0;
    char num[96];

    for (int m = 0; m < SL_M_COUNT; m++) {
        int any = 0;

        both(&rc, header(out, defs[m].name, defs[m].help, "counter"));
        for (size_t i = 0; i < g_n; i++) {
            if (g_series[i].metric == m) {
                both(&rc, line(out, defs[m].name, defs[m].l1, g_series[i].l1, defs[m].l2,
                               g_series[i].l2, g_series[i].v));
                any = 1;
            }
        }
        if (!any && defs[m].l1 == NULL) {
            both(&rc, line(out, defs[m].name, NULL, NULL, NULL, NULL, 0)); /* starts at 0 */
        }
    }
    both(&rc, header(out, "sluice_connections_active", "Connections open now.", "gauge"));
    both(&rc,
         line(out, "sluice_connections_active", NULL, NULL, NULL, NULL, g->active_connections));
    both(&rc, header(out, "sluice_pending_confirmations",
                     "Statements waiting for somebody's answer now.", "gauge"));
    both(&rc, line(out, "sluice_pending_confirmations", NULL, NULL, NULL, NULL,
                   g->pending_confirmations));
    both(&rc, header(out, "sluice_policy_rules", "Rules in the policy now.", "gauge"));
    both(&rc, line(out, "sluice_policy_rules", NULL, NULL, NULL, NULL, g->rules));
    both(&rc,
         header(out, "sluice_start_time_seconds", "When sluice started (unix time).", "gauge"));
    snprintf(num, sizeof num, "sluice_start_time_seconds %lld\n", g->start_unix);
    both(&rc, put(out, num));
    both(&rc, header(out, "sluice_uptime_seconds", "Seconds since sluice started.", "gauge"));
    snprintf(num, sizeof num, "sluice_uptime_seconds %lld\n",
             g->now_unix > g->start_unix ? g->now_unix - g->start_unix : 0);
    both(&rc, put(out, num));
    both(&rc, header(out, "sluice_build_info", "The version of this sluice, always 1.", "gauge"));
    both(&rc, put(out, "sluice_build_info{"));
    both(&rc, put_label(out, "version", g->version));
    both(&rc, put(out, "} 1\n"));
    return rc;
}
