#include "scanner.h"

#include <string.h>

#include "pg_proto.h"

void sl_scan_init(sl_scan *s, int judge_fastpath, size_t inspect_max)
{
    memset(s, 0, sizeof *s);
    s->inspect_on = 1;
    s->judge_fastpath = judge_fastpath;
    s->inspect_max = inspect_max;
}

/* Replaces `span` bytes at the release point by the replacement, and releases it. Returns 0 or -1.
 */
static int swap_in(sl_scan *s, sl_buf *buf, size_t span, const sl_buf *replacement)
{
    if (sl_buf_replace(buf, s->released, span, sl_buf_data(replacement), sl_buf_len(replacement)) !=
        0) {
        return -1;
    }
    s->released += sl_buf_len(replacement);
    return 0;
}

void sl_scan_resume(sl_scan *s)
{
    s->paused = 0;
}

int sl_scan_inject(sl_scan *s, sl_buf *buf, const void *data, size_t len, unsigned answers)
{
    if (sl_buf_replace(buf, s->released, 0, data, len) != 0) {
        return -1;
    }
    s->released += len;
    s->owed += answers;
    return 0;
}

int sl_scan_run(sl_scan *s, sl_buf *buf, const sl_scan_ops *ops, void *ctx)
{
    for (;;) {
        size_t total = sl_buf_len(buf);
        size_t avail;
        const uint8_t *p;
        sl_pg_header h;
        int rc;

        if (s->paused) {
            return SL_SCAN_OK;
        }
        if (!s->inspect_on) {
            s->released = total;
            return SL_SCAN_OK;
        }
        avail = total - s->released;
        if (avail == 0) {
            return SL_SCAN_OK;
        }

        if (s->skip_remaining > 0) {
            size_t n = avail < s->skip_remaining ? avail : s->skip_remaining;

            (void)sl_buf_replace(buf, s->released, n, NULL, 0); /* shrinking cannot fail */
            s->skip_remaining -= n;
            continue;
        }
        if (s->pass_remaining > 0) {
            size_t n = avail < s->pass_remaining ? avail : s->pass_remaining;

            s->released += n;
            s->pass_remaining -= n;
            continue;
        }

        p = sl_buf_data(buf) + s->released;
        rc = sl_pg_parse_header(p, avail, &h);
        if (rc == SL_PG_NEED_MORE) {
            return SL_SCAN_OK;
        }
        if (rc == SL_PG_ERROR) {
            if (ops->frame_error(ctx)) {
                return SL_SCAN_CLOSE;
            }
            s->inspect_on = 0;
            s->owed_unknown = 1;
            continue;
        }

        if (h.type == 'Q' || h.type == 'P') {
            if (h.payload_len <= s->inspect_max) {
                sl_buf repl;
                int r;

                if (avail < 5 + h.payload_len) {
                    return SL_SCAN_OK; /* wait for the rest of the message */
                }
                sl_buf_init(&repl);
                r = ops->statement(ctx, h.type, p + 5, h.payload_len, &repl);
                if (r == SL_SCAN_WAIT) {
                    s->paused = 1;
                } else if (r == SL_SCAN_BLOCK || r == SL_SCAN_GUARD) {
                    int guard = r == SL_SCAN_GUARD;

                    r = swap_in(s, buf, 5 + h.payload_len, &repl) == 0 ? SL_SCAN_BLOCK
                                                                       : SL_SCAN_FAIL;
                    if (r == SL_SCAN_BLOCK) {
                        s->owed += h.type == 'Q'; /* the replacement of a Query is a Query */
                        s->paused = guard;
                    }
                } else if (r == SL_SCAN_RELAY) {
                    s->released += 5 + h.payload_len;
                    s->owed += h.type == 'Q';
                }
                sl_buf_free(&repl);
                if (r == SL_SCAN_FAIL) {
                    return SL_SCAN_NOMEM;
                }
                continue;
            }
        } else if (!(h.type == 'F' && s->judge_fastpath)) {
            s->released += 5;
            s->pass_remaining = h.payload_len;
            s->owed += h.type == 'S' || h.type == 'F'; /* Sync, fast-path call */
            continue;
        }

        /* too big to be read, or a fast-path call: judged on its header, body not held */
        {
            sl_buf repl;
            int r;

            sl_buf_init(&repl);
            r = ops->unreadable(ctx, h.type, h.payload_len, h.type != 'F', &repl);
            if (r == SL_SCAN_BLOCK) {
                r = swap_in(s, buf, 5, &repl) == 0 ? SL_SCAN_BLOCK : SL_SCAN_FAIL;
                if (r == SL_SCAN_BLOCK) {
                    s->skip_remaining = h.payload_len;
                    s->owed += h.type == 'Q' || h.type == 'F'; /* both are replaced by a Query */
                }
            } else if (r == SL_SCAN_RELAY) {
                s->released += 5;
                s->pass_remaining = h.payload_len;
                s->owed += h.type == 'Q' || h.type == 'F';
            }
            sl_buf_free(&repl);
            if (r == SL_SCAN_FAIL) {
                return SL_SCAN_NOMEM;
            }
        }
    }
}
