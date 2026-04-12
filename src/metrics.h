#ifndef SLUICE_METRICS_H
#define SLUICE_METRICS_H

/* Counters for the people who run sluice, in the text format that Prometheus reads (version
 * 0.0.4), served by the admin listener (admin.h) at /metrics.
 *
 * The counters live in memory and are lost when sluice restarts, which Prometheus expects of a
 * counter (it sees the reset). Each is a name with at most two labels; the label values come from
 * a fixed set (verdicts, outcomes, rule names, event names) and never from what a client sent,
 * except a rule's name and an event's name, which the operator wrote. The number of series is
 * bounded: when it is reached, the counter that does not fit is added to
 * sluice_metrics_dropped_series_total instead of making memory grow.
 *
 * No sockets, no clock: so that it can be tested and fuzzed. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

enum {
    SL_M_CONNECTIONS,   /* connections accepted */
    SL_M_CLOSED,        /* connections ended, by reason */
    SL_M_STATEMENTS,    /* statements judged, by verdict and by what was done */
    SL_M_RULE_HITS,     /* statements a rule decided, by rule and verdict */
    SL_M_CONFIRMATIONS, /* confirmations decided, by outcome and channel */
    SL_M_LIMITS,        /* limits that cut a connection or a result, by kind */
    SL_M_BYTES,         /* bytes relayed, by direction */
    SL_M_MASKED,        /* values hidden in rows */
    SL_M_EVENTS,        /* every line of the log, by event */
    SL_M_HOOKS,         /* event commands, by outcome */
    SL_M_ADMIN,         /* requests to the admin listener, by path and status */
    SL_M_RELOADS,       /* policy reloads, by outcome */
    SL_M_DROPPED,       /* series that did not fit */
    SL_M_COUNT
};

/* Adds n to the counter of this series (a label that is not used is NULL). */
void sl_metric_add(int metric, const char *l1, const char *l2, unsigned long long n);
#define sl_metric_inc(m, a, b) sl_metric_add((m), (a), (b), 1)

/* What is only known when it is read. */
typedef struct {
    unsigned long long active_connections;
    unsigned long long pending_confirmations;
    unsigned long long rules;
    long long start_unix; /* when sluice started */
    long long now_unix;
    const char *version;
} sl_metrics_gauges;

/* Appends the whole text (counters, then gauges). */
int sl_metrics_render(sl_buf *out, const sl_metrics_gauges *g);

/* Forgets everything (the tests). */
void sl_metrics_reset(void);

#endif
