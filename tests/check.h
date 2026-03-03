#ifndef SLUICE_TEST_CHECK_H
#define SLUICE_TEST_CHECK_H

/* A deliberately tiny test harness: no framework, a failed check prints its location and the test
 * binary exits non-zero at the end. */

#include <stdio.h>
#include <string.h>

static int sl_test_failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);               \
            sl_test_failures++;                                                                    \
        }                                                                                          \
    } while (0)

#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)
#define CHECK_STR(a, b) CHECK(strcmp((a), (b)) == 0)

#define TEST_RESULT() (sl_test_failures ? 1 : 0)

#endif
