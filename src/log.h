#ifndef SLUICE_LOG_H
#define SLUICE_LOG_H

#include <stdint.h>
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
    const char *name; /* the event, a literal */
} sl_log_ev;

/* Somebody who wants to see every line that was written, with the name of its event and without the
 * newline (metrics, the event command). One tap; NULL removes it. It must not write to the log. */
typedef void (*sl_log_tap_fn)(void *ctx, const char *event, const char *line, size_t len);
void sl_log_set_tap(sl_log_tap_fn fn, void *ctx);

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

/* A hash chain over the lines of the log, so that a line taken out, changed, added or moved can be
 * found afterwards (docs/policy.md, "A log that shows when it was changed").
 *
 * From the call on, every line ends with `,"seq":N,"chain":"<32 hex digits>"}`: N counts the lines
 * from 1, and the chain is the HMAC-SHA256 (key given here), cut to 16 bytes, of the previous
 * chain value (zeros for the first line) followed by the line up to and including "seq". The first
 * line is a chain_start event, the last of a clean shutdown a chain_end. `sluice --verify-log`
 * checks a file against the key. The key has to be kept somewhere the one who could edit the log
 * cannot read: whoever has it can write a log that checks out. */
#define SL_LOG_CHAIN_HEX 32
int sl_log_chain_start(const uint8_t *key, size_t key_len);
void sl_log_chain_stop(void);

/* `sluice --verify-log FILE --log-chain-key-file KEYFILE`. Exit status: 0 whole and closed, 1 a
 * line does not check out, 3 checks out but was not closed (crash, kill -9, or cut), 2 usage. */
int sl_log_verify_main(int argc, char **argv);

#endif
