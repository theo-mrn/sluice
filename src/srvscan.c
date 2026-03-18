#include "srvscan.h"

#include <string.h>

#include "pg_proto.h"

void sl_srv_init(sl_srv *s, size_t released, size_t read_max)
{
    memset(s, 0, sizeof *s);
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
            s->released += 5;
            s->pass_remaining = h.payload_len;
        } else if (how == SL_SRV_SKIP) {
            (void)sl_buf_replace(buf, s->released, 5, NULL, 0);
            s->skip_remaining = h.payload_len;
        } else { /* SL_SRV_READ */
            if (avail < 5 + h.payload_len) {
                return SL_SRV_OK; /* wait for the rest of the message */
            }
            if (ops->message(ctx, h.type, p + 5, h.payload_len) == SL_SRV_DROP) {
                (void)sl_buf_replace(buf, s->released, 5 + h.payload_len, NULL, 0);
            } else {
                s->released += 5 + h.payload_len;
            }
        }
    }
}
