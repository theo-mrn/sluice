#include "budget.h"

#include <stdlib.h>
#include <string.h>

#define RULE_MAX 72
#define USER_MAX 128

struct sl_budget_entry {
    char rule[RULE_MAX];
    char user[USER_MAX];
    size_t user_len;
    unsigned window_s;
    int64_t width_ms; /* one bucket */
    unsigned held;    /* connections that hold it */
    struct {
        int64_t index; /* which slice of time this slot holds; -1: empty */
        unsigned long long n[SL_BUDGET_KINDS];
    } slot[SL_BUDGET_BUCKETS];
    sl_budget_entry *next;
};

struct sl_budget {
    sl_budget_entry *head;
    size_t count;
};

sl_budget *sl_budget_new(void)
{
    return calloc(1, sizeof(sl_budget));
}

void sl_budget_free(sl_budget *b)
{
    if (b == NULL) {
        return;
    }
    while (b->head != NULL) {
        sl_budget_entry *e = b->head;

        b->head = e->next;
        free(e);
    }
    free(b);
}

static int64_t index_of(const sl_budget_entry *e, int64_t now_ms)
{
    return (now_ms < 0 ? 0 : now_ms) / e->width_ms;
}

/* Is the slot inside the window that ends in the slice `cur`? */
static int live(const sl_budget_entry *e, size_t i, int64_t cur)
{
    return e->slot[i].index >= 0 && e->slot[i].index > cur - SL_BUDGET_BUCKETS &&
           e->slot[i].index <= cur;
}

static int idle(const sl_budget_entry *e, int64_t now_ms)
{
    int64_t cur = index_of(e, now_ms);

    for (size_t i = 0; i < SL_BUDGET_BUCKETS; i++) {
        if (live(e, i, cur)) {
            return 0;
        }
    }
    return 1;
}

/* Forgets the pairs nobody holds and that have nothing left in their window. */
static void sweep(sl_budget *b, int64_t now_ms)
{
    sl_budget_entry **pp = &b->head;

    while (*pp != NULL) {
        sl_budget_entry *e = *pp;

        if (e->held == 0 && idle(e, now_ms)) {
            *pp = e->next;
            free(e);
            b->count--;
        } else {
            pp = &e->next;
        }
    }
}

sl_budget_entry *sl_budget_acquire(sl_budget *b, const char *rule, const char *user,
                                   size_t user_len, unsigned window_s, int64_t now_ms)
{
    sl_budget_entry *e;

    if (user_len > USER_MAX - 1 || window_s == 0 || strlen(rule) > RULE_MAX - 1) {
        return NULL;
    }
    for (e = b->head; e != NULL; e = e->next) {
        if (e->window_s == window_s && e->user_len == user_len &&
            memcmp(e->user, user, user_len) == 0 && strcmp(e->rule, rule) == 0) {
            e->held++;
            return e;
        }
    }
    if (b->count >= SL_BUDGET_MAX_ENTRIES) {
        sweep(b, now_ms);
    }
    if (b->count >= SL_BUDGET_MAX_ENTRIES) {
        return NULL;
    }
    e = calloc(1, sizeof *e);
    if (e == NULL) {
        return NULL;
    }
    memcpy(e->rule, rule, strlen(rule));
    memcpy(e->user, user, user_len);
    e->user_len = user_len;
    e->window_s = window_s;
    e->width_ms = ((int64_t)window_s * 1000 + SL_BUDGET_BUCKETS - 1) / SL_BUDGET_BUCKETS;
    for (size_t i = 0; i < SL_BUDGET_BUCKETS; i++) {
        e->slot[i].index = -1;
    }
    e->held = 1;
    e->next = b->head;
    b->head = e;
    b->count++;
    return e;
}

void sl_budget_release(sl_budget *b, sl_budget_entry *e, int64_t now_ms)
{
    if (e == NULL || e->held == 0) {
        return;
    }
    e->held--;
    /* only when the table is getting full is a pair that nobody holds and that has nothing left in
     * its window forgotten: otherwise it costs little, and a user that comes back finds its use */
    if (e->held == 0 && b->count > SL_BUDGET_MAX_ENTRIES / 2) {
        sweep(b, now_ms);
    }
}

void sl_budget_add(sl_budget_entry *e, int64_t now_ms, int kind, unsigned long long n)
{
    int64_t cur;
    size_t i;

    if (e == NULL || n == 0 || kind < 0 || kind >= SL_BUDGET_KINDS) {
        return;
    }
    cur = index_of(e, now_ms);
    i = (size_t)(cur % SL_BUDGET_BUCKETS);
    if (e->slot[i].index != cur) {
        memset(e->slot[i].n, 0, sizeof e->slot[i].n);
        e->slot[i].index = cur;
    }
    if (e->slot[i].n[kind] > ~0ULL - n) {
        e->slot[i].n[kind] = ~0ULL;
    } else {
        e->slot[i].n[kind] += n;
    }
}

unsigned long long sl_budget_used(const sl_budget_entry *e, int64_t now_ms, int kind)
{
    unsigned long long sum = 0;
    int64_t cur;

    if (e == NULL || kind < 0 || kind >= SL_BUDGET_KINDS) {
        return 0;
    }
    cur = index_of(e, now_ms);
    for (size_t i = 0; i < SL_BUDGET_BUCKETS; i++) {
        if (live(e, i, cur)) {
            unsigned long long v = e->slot[i].n[kind];

            sum = sum > ~0ULL - v ? ~0ULL : sum + v;
        }
    }
    return sum;
}

unsigned sl_budget_wait_s(const sl_budget_entry *e, int64_t now_ms, int kind,
                          unsigned long long limit)
{
    unsigned long long used = sl_budget_used(e, now_ms, kind);
    int64_t cur;

    if (e == NULL || used < limit) {
        return 0;
    }
    cur = index_of(e, now_ms);
    /* the oldest slices leave first: take them away until what is left is under the limit */
    for (int64_t k = cur - SL_BUDGET_BUCKETS + 1; k <= cur; k++) {
        size_t i = (size_t)(((k % SL_BUDGET_BUCKETS) + SL_BUDGET_BUCKETS) % SL_BUDGET_BUCKETS);

        if (e->slot[i].index != k) {
            continue;
        }
        used -= e->slot[i].n[kind] > used ? used : e->slot[i].n[kind];
        if (used < limit) {
            int64_t leaves = (k + SL_BUDGET_BUCKETS) * e->width_ms; /* the slice has left then */
            int64_t ms = leaves - (now_ms < 0 ? 0 : now_ms);

            return ms <= 0 ? 1 : (unsigned)((ms + 999) / 1000);
        }
    }
    return e->window_s;
}
