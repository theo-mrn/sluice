#ifndef SLUICE_CLOCK_H
#define SLUICE_CLOCK_H

#include <stdint.h>
#include <time.h>

/* Milliseconds from a monotonic clock. Only differences between two calls mean anything. */
static inline int64_t sl_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

#endif
