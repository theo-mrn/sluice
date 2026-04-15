#ifndef SLUICE_SRVSCAN_H
#define SLUICE_SRVSCAN_H

/* Walks the bytes the server sends, message by message, so that sluice knows where the server is in
 * its conversation (which answers are done, whether a transaction is open) and, when it has to,
 * keeps some of them from the client.
 *
 * Like scanner.c for the client's bytes it works on a byte queue, without sockets or policy, so
 * that it can be tested, and fuzzed with the stream cut anywhere. The queue holds the bytes
 * received and not yet sent to the client; the first `released` of them may go.
 *
 * For each message the caller says, from its header alone, what to do:
 *   - SL_SRV_PASS: relay it as it arrives, unread. Nothing is held: a result of any size streams.
 *   - SL_SRV_READ: hold it until complete (up to read_max bytes), then hand it to ops->message,
 *     which keeps it for the client or drops it.
 *   - SL_SRV_SKIP: throw it away as it arrives, unread.
 * A relayed message is also announced to ops->passed (once, from its header) when there is one, for
 * the callers that only need to count them.
 * The result never depends on how the stream was cut into reads. A header that cannot be valid
 * ends the scanning for good: everything that follows is relayed unread, and the caller is told. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

/* The biggest message that will be held to be read. */
#define SL_SRV_READ_MAX ((size_t)1 << 20)

typedef struct {
    size_t released;       /* bytes at the head of the queue that may be sent */
    size_t pass_remaining; /* bytes of the message being relayed that are still to come */
    size_t skip_remaining; /* bytes of the message being thrown away that are still to come */
    int lost;              /* the stream stopped being framed: everything is relayed unread */
    int paused; /* a callback asked to stop: nothing is looked at until sl_srv_resume() */
    size_t read_max;
    sl_buf replacement; /* what the callback puts there when it answers SL_SRV_REPLACE */
} sl_srv;

/* What to do with a message, decided from its header. */
enum { SL_SRV_PASS = 0, SL_SRV_READ = 1, SL_SRV_SKIP = 2 };

/* What to do with a message that was read. */
enum {
    SL_SRV_KEEP = 0,
    SL_SRV_DROP = 1,
    SL_SRV_REPLACE = 2 /* give the client the bytes in sl_srv.replacement instead */
};

typedef struct {
    int (*classify)(void *ctx, uint8_t type, size_t payload_len);
    int (*message)(void *ctx, uint8_t type, const uint8_t *payload, size_t len);
    void (*passed)(void *ctx, uint8_t type, size_t payload_len); /* may be NULL */
    void (*skipped)(void *ctx, uint8_t type,
                    size_t payload_len); /* may be NULL: a message thrown away */
} sl_srv_ops;

enum { SL_SRV_OK = 0, SL_SRV_LOST = 1 /* the framing is gone, from now on all is relayed */ };

void sl_srv_init(sl_srv *s, size_t released, size_t read_max);

/* Starts again after a callback set s->paused. */
void sl_srv_resume(sl_srv *s);

/* Looks at the bytes of buf beyond s->released. A message that classify wants read but that is
 * longer than read_max is thrown away instead, and counted in *oversized when it is not NULL. */
int sl_srv_run(sl_srv *s, sl_buf *buf, const sl_srv_ops *ops, void *ctx, unsigned *oversized);

#endif
