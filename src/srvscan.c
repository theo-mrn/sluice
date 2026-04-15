#include "srvscan.h"

#include <string.h>

#include "pg_proto.h"

void sl_srv_init(sl_srv *s, size_t released, size_t read_max)
{
    memset(s, 0, sizeof *s);
    sl_buf_init(&s->replacement);
    s->released = released;
    s->read_max = read_max;
}

void sl_srv_resume(sl_srv *s)
{
    s->paused = 0;
}

int sl_srv_run(sl_srv *s, sl_buf *buf, const sl_srv_ops *ops, void *ctx, unsigned *oversized)
{
    for (;;) {
        size_t total = sl_buf_len(buf);
        size_t avail;
        const uint8_t *p;
        sl_pg_header h;
        int how;

        if (s->paused) {
            return s->lost ? SL_SRV_LOST : SL_SRV_OK;
        }
        if (s->lost) {
            s->released = total;
            return SL_SRV_LOST;
        }
        avail = total - s->released;
        if (avail == 0) {
            return SL_SRV_OK;
        }
        if (s->skip_remaining > 0) {
            size_t n = avail < s->skip_remaining ? avail : s->skip_remaining;

            (void)sl_buf_replace(buf, s->released, n, NULL, 0);
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
        switch (sl_pg_parse_header(p, avail, &h)) {
        case SL_PG_NEED_MORE:
            return SL_SRV_OK;
        case SL_PG_ERROR:
            s->lost = 1;
            continue;
        default:
            break;
        }

        how = ops->classify(ctx, h.type, h.payload_len);
        if (how == SL_SRV_READ && h.payload_len > s->read_max) {
            how = SL_SRV_SKIP;
            if (oversized != NULL) {
                (*oversized)++;
            }
        }
        if (how == SL_SRV_PASS) {
            if (ops->passed != NULL) {
                ops->passed(ctx, h.type, h.payload_len);
            }
            s->released += 5;
            s->pass_remaining = h.payload_len;
        } else if (how == SL_SRV_SKIP) {
            if (ops->skipped != NULL) {
                ops->skipped(ctx, h.type, h.payload_len);
            }
            (void)sl_buf_replace(buf, s->released, 5, NULL, 0);
            s->skip_remaining = h.payload_len;
        } else { /* SL_SRV_READ */
            if (avail < 5 + h.payload_len) {
                return SL_SRV_OK; /* wait for the rest of the message */
            }
            int r = ops->message(ctx, h.type, p + 5, h.payload_len);

            if (r == SL_SRV_DROP) {
                (void)sl_buf_replace(buf, s->released, 5 + h.payload_len, NULL, 0);
            } else if (r == SL_SRV_REPLACE) {
                size_t n = sl_buf_len(&s->replacement);

                if (sl_buf_replace(buf, s->released, 5 + h.payload_len,
                                   sl_buf_data(&s->replacement), n) != 0) {
                    n = 0; /* out of memory: the message is lost; the caller sees the error */
                    (void)sl_buf_replace(buf, s->released, 5 + h.payload_len, NULL, 0);
                    s->lost = 1;
                }
                s->released += n;
                sl_buf_free(&s->replacement);
            } else {
                s->released += 5 + h.payload_len;
            }
        }
    }
}
