#ifndef SLUICE_LOG_H
#define SLUICE_LOG_H

#include <stdio.h>

#include "buf.h"

/* Structured log: one JSON object per line, for example
 *   {"ts":"2026-11-16T10:00:00.123Z","event":"startup","id":4,"user":"app"}
 *
 * Usage:
 *   sl_log_ev ev;
 *   sl_log_begin(&ev, "startup");
 *   sl_log_int(&ev, "id", 4);
 *   sl_log_cstr(&ev, "user", user);
 *   sl_log_end(&ev);          writes the line and releases the event
 *
 * Event names and keys must be fixed literals (they are not escaped). Values are escaped. Out of
 * memory drops the event silently. */
typedef struct {
    sl_buf b;
    int failed;
} sl_log_ev;

/* Where lines go. The default is stdout. The stream is not owned and not closed. */
void sl_log_set_sink(FILE *f);

void sl_log_begin(sl_log_ev *ev, const char *event);
void sl_log_str(sl_log_ev *ev, const char *key, const void *val, size_t len);
void sl_log_cstr(sl_log_ev *ev, const char *key, const char *val); /* NULL becomes null */
void sl_log_int(sl_log_ev *ev, const char *key, long long val);
void sl_log_bool(sl_log_ev *ev, const char *key, int val);
/* A list of strings: "key":["a","b"]. */
void sl_log_list(sl_log_ev *ev, const char *key, const char *const *items, size_t n);
void sl_log_end(sl_log_ev *ev);

#endif
