#ifndef SLUICE_BUDGET_H
#define SLUICE_BUDGET_H

/* How much a user has carried out of the database, or changed in it, over a sliding window of time:
 * the memory behind the "budget_*" keys of a limit rule (policy.h). A connection never sees more
 * than its own statements, but an agent that opens a new connection for every query is still one
 * user: what is counted here is per rule and per user, whatever the connection.
 *
 * Four things are counted: DataRows sent to the client, their bytes, rows changed (the count in
 * the CommandComplete tag of an INSERT, UPDATE, DELETE or MERGE), and round trips (each answer the
 * server ends with a ReadyForQuery: a Query, or the Sync of a prepared statement's cycle).
 *
 * The window is cut in SL_BUDGET_BUCKETS slices; a slice is forgotten as a whole when it has left
 * the window, so what is counted is exact to within one slice (window / 12). Time is given by the
 * caller (milliseconds, monotonic), so this can be tested and fuzzed without a clock. No sockets.
 */

#include <stddef.h>
#include <stdint.h>

#define SL_BUDGET_BUCKETS 12
#define SL_BUDGET_MAX_ENTRIES 4096 /* (rule, user) pairs held at once */

typedef struct sl_budget sl_budget;
typedef struct sl_budget_entry sl_budget_entry;

enum {
    SL_BUDGET_ROWS,
    SL_BUDGET_BYTES,
    SL_BUDGET_CHANGED,
    SL_BUDGET_STATEMENTS, /* round trips: one per Query and one per Sync */
    SL_BUDGET_KINDS
};

sl_budget *sl_budget_new(void);
void sl_budget_free(sl_budget *b);

/* The counters of this rule for this user, made when they do not exist, and held (released with
 * sl_budget_release) until the connection that asked is over. NULL when out of memory or when
 * SL_BUDGET_MAX_ENTRIES pairs are all held or still count something. window_s is the rule's window:
 * a pair is only shared between connections that agree on it. */
sl_budget_entry *sl_budget_acquire(sl_budget *b, const char *rule, const char *user,
                                   size_t user_len, unsigned window_s, int64_t now_ms);
void sl_budget_release(sl_budget *b, sl_budget_entry *e, int64_t now_ms);

/* Adds to what was carried out at now_ms. */
void sl_budget_add(sl_budget_entry *e, int64_t now_ms, int kind, unsigned long long n);

/* What counts in the window that ends at now_ms. */
unsigned long long sl_budget_used(const sl_budget_entry *e, int64_t now_ms, int kind);

/* How many seconds until the use of this kind is below `limit` again, if nothing more is added (the
 * oldest slices leave first). 0 when it already is. */
unsigned sl_budget_wait_s(const sl_budget_entry *e, int64_t now_ms, int kind,
                          unsigned long long limit);

#endif
