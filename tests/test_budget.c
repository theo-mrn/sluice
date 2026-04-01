#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "budget.h"
#include "check.h"

#define MIN 60000LL
#define HOUR (60 * MIN)

static sl_budget_entry *take(sl_budget *b, const char *rule, const char *user, unsigned window_s)
{
    return sl_budget_acquire(b, rule, user, strlen(user), window_s, 0);
}

static void test_counts_inside_the_window(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "agent", 3600);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, 100);
    sl_budget_add(e, 10 * MIN, SL_BUDGET_ROWS, 50);
    sl_budget_add(e, 10 * MIN, SL_BUDGET_BYTES, 4096);
    sl_budget_add(e, 20 * MIN, SL_BUDGET_CHANGED, 7);
    CHECK(sl_budget_used(e, 30 * MIN, SL_BUDGET_ROWS) == 150);
    CHECK(sl_budget_used(e, 30 * MIN, SL_BUDGET_BYTES) == 4096);
    CHECK(sl_budget_used(e, 30 * MIN, SL_BUDGET_CHANGED) == 7);
    sl_budget_release(b, e, 30 * MIN);
    sl_budget_free(b);
}

static void test_forgets_what_left_the_window(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "agent", 3600);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, 100);
    sl_budget_add(e, 50 * MIN, SL_BUDGET_ROWS, 10);
    /* a slice is a twelfth of the window (5 minutes): at 65 minutes the first has left, the second
     * has not */
    CHECK(sl_budget_used(e, 65 * MIN, SL_BUDGET_ROWS) == 10);
    CHECK(sl_budget_used(e, 59 * MIN, SL_BUDGET_ROWS) == 110);
    CHECK(sl_budget_used(e, 2 * HOUR, SL_BUDGET_ROWS) == 0);
    /* it starts again from nothing */
    sl_budget_add(e, 2 * HOUR, SL_BUDGET_ROWS, 3);
    CHECK(sl_budget_used(e, 2 * HOUR, SL_BUDGET_ROWS) == 3);
    sl_budget_free(b);
}

static void test_a_slot_is_reused_after_a_full_turn(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "u", 3600);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, 5);
    sl_budget_add(e, 12 * 5 * MIN, SL_BUDGET_ROWS, 1); /* the same slot, one turn later */
    CHECK(sl_budget_used(e, 12 * 5 * MIN, SL_BUDGET_ROWS) == 1);
    sl_budget_free(b);
}

static void test_users_and_rules_are_apart(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *a = take(b, "r", "alice", 3600);
    sl_budget_entry *bob = take(b, "r", "bob", 3600);
    sl_budget_entry *a2 = take(b, "other", "alice", 3600);
    sl_budget_entry *again = take(b, "r", "alice", 3600);

    CHECK(a != bob && a != a2 && a == again); /* the same pair is shared by connections */
    sl_budget_add(a, 0, SL_BUDGET_ROWS, 9);
    CHECK(sl_budget_used(again, 0, SL_BUDGET_ROWS) == 9);
    CHECK(sl_budget_used(bob, 0, SL_BUDGET_ROWS) == 0);
    CHECK(sl_budget_used(a2, 0, SL_BUDGET_ROWS) == 0);
    sl_budget_free(b);
}

static void test_how_long_to_wait(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "u", 3600);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, 60);
    sl_budget_add(e, 30 * MIN, SL_BUDGET_ROWS, 60);
    CHECK(sl_budget_wait_s(e, 31 * MIN, SL_BUDGET_ROWS, 200) == 0); /* under the limit */
    /* 120 used, limit 100: the first 60 have to leave, which happens when its slice is an hour old
     */
    unsigned w = sl_budget_wait_s(e, 31 * MIN, SL_BUDGET_ROWS, 100);
    CHECK(w >= 25 * 60 && w <= 35 * 60);
    /* both would have to leave for 0 to be under 1 */
    w = sl_budget_wait_s(e, 31 * MIN, SL_BUDGET_ROWS, 1);
    CHECK(w >= 55 * 60 && w <= 65 * 60);
    sl_budget_free(b);
}

static void test_does_not_overflow(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "u", 60);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, ~0ULL);
    sl_budget_add(e, 0, SL_BUDGET_ROWS, 5);
    CHECK(sl_budget_used(e, 0, SL_BUDGET_ROWS) == ~0ULL);
    sl_budget_add(e, 10000, SL_BUDGET_ROWS, ~0ULL); /* another slice: the sum saturates */
    CHECK(sl_budget_used(e, 10000, SL_BUDGET_ROWS) == ~0ULL);
    sl_budget_add(e, -5, SL_BUDGET_ROWS, 1); /* a clock that is wrong does no harm */
    sl_budget_add(NULL, 0, SL_BUDGET_ROWS, 1);
    sl_budget_add(e, 0, 99, 1);
    CHECK(sl_budget_used(e, 0, 99) == 0);
    sl_budget_free(b);
}

static void test_refuses_what_does_not_fit(void)
{
    sl_budget *b = sl_budget_new();
    char big[200];

    memset(big, 'x', sizeof big);
    CHECK(sl_budget_acquire(b, "r", big, sizeof big, 60, 0) == NULL); /* a name too long */
    CHECK(sl_budget_acquire(b, "r", "u", 1, 0, 0) == NULL);           /* no window */
    sl_budget_free(b);
}

static void test_table_is_bounded_and_forgets_idle_pairs(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *first = NULL;
    char name[32];
    size_t made = 0;

    for (size_t i = 0; i < SL_BUDGET_MAX_ENTRIES + 10; i++) {
        sl_budget_entry *e;

        snprintf(name, sizeof name, "user%zu", i);
        e = sl_budget_acquire(b, "r", name, strlen(name), 60, 0);
        if (e == NULL) {
            break;
        }
        if (first == NULL) {
            first = e;
        }
        made++;
    }
    CHECK(made == SL_BUDGET_MAX_ENTRIES); /* all held: no room for more, and nothing is lost */
    CHECK(sl_budget_acquire(b, "r", "newcomer", 8, 60, 0) == NULL);
    /* released, and with nothing counted, the pairs are forgotten when room is needed */
    for (size_t i = 0; i < SL_BUDGET_MAX_ENTRIES; i++) {
        snprintf(name, sizeof name, "user%zu", i);
        sl_budget_entry *e = sl_budget_acquire(b, "r", name, strlen(name), 60, 0);

        sl_budget_release(b, e, 0); /* the one just taken */
        sl_budget_release(b, e, 0); /* and the first */
    }
    CHECK(sl_budget_acquire(b, "r", "newcomer", 8, 60, 0) != NULL);
    sl_budget_free(b);
}

static void test_a_pair_that_counts_is_not_forgotten(void)
{
    sl_budget *b = sl_budget_new();
    sl_budget_entry *e = take(b, "r", "heavy", 3600);

    sl_budget_add(e, 0, SL_BUDGET_ROWS, 1000);
    sl_budget_release(b, e, 0);
    /* it comes back with its use, even if the table was swept meanwhile */
    for (size_t i = 0; i < SL_BUDGET_MAX_ENTRIES; i++) {
        char name[32];

        snprintf(name, sizeof name, "u%zu", i);
        sl_budget_entry *o = sl_budget_acquire(b, "r", name, strlen(name), 3600, MIN);
        if (o != NULL) {
            sl_budget_release(b, o, MIN);
        }
    }
    e = take(b, "r", "heavy", 3600);
    CHECK(e != NULL && sl_budget_used(e, MIN, SL_BUDGET_ROWS) == 1000);
    sl_budget_free(b);
}

int main(void)
{
    test_counts_inside_the_window();
    test_forgets_what_left_the_window();
    test_a_slot_is_reused_after_a_full_turn();
    test_users_and_rules_are_apart();
    test_how_long_to_wait();
    test_does_not_overflow();
    test_refuses_what_does_not_fit();
    test_table_is_bounded_and_forgets_idle_pairs();
    test_a_pair_that_counts_is_not_forgotten();
    return TEST_RESULT();
}
