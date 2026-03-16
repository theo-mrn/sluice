#ifndef SLUICE_SCANNER_H
#define SLUICE_SCANNER_H

/* Walks the bytes a client sends, message by message, and decides which of them may go to the
 * server.
 *
 * It is the part of sluice that sits between "bytes received" and "bytes sent", so it is kept free
 * of sockets, logging and policy: it works on a byte queue and asks three questions through
 * callbacks. That is what makes it possible to test it, and to fuzz it with the stream cut at any
 * place.
 *
 * The queue holds the bytes received and not yet sent. The first `released` of them may be sent;
 * the rest is held back (an incomplete Query, typically). The caller sends the released bytes,
 * removes them from the queue and subtracts them from `released`, and calls sl_scan_run again after
 * each read.
 *
 * What is done with each message:
 *   - Query ('Q') and Parse ('P') of at most inspect_max bytes: held until complete, then handed to
 *     ops->statement, which lets it through or supplies a message to send in its place.
 *   - Query and Parse above inspect_max, and the fast-path call ('F') when judge_fastpath is set:
 * handed to ops->unreadable by their header alone; either they stream through unread, or their
 * header is replaced and the body is thrown away as it arrives.
 *   - Everything else is released as it arrives, header and body, without being read.
 *   - A header that cannot be valid: ops->frame_error decides between "close the connection" and
 * "stop inspecting and relay the rest unread". The result never depends on how the stream was cut
 * into reads. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

/* Bigger Query and Parse messages are not held to be read: 1 MiB bounds what a client can make us
 * keep. */
#define SL_SCAN_INSPECT_MAX ((size_t)1 << 20)

typedef struct {
    size_t released;       /* bytes at the head of the queue that may be sent */
    size_t pass_remaining; /* bytes of the message being relayed unread that are still to come */
    size_t
        skip_remaining; /* bytes of the blocked message being thrown away that are still to come */
    int inspect_on;     /* 0 after a framing error that was let go: everything is relayed unread */
    int paused;         /* a callback asked to wait: nothing is looked at until sl_scan_resume() */
    uint64_t
        owed; /* ReadyForQuery answers the server owes for what has been released (Q, Sync, F) */
    int owed_unknown; /* set when the stream stopped being framed: `owed` cannot be trusted any more
                       */
    int judge_fastpath; /* ask about 'F' messages (they are relayed unasked otherwise) */
    size_t inspect_max;
} sl_scan;

/* What the callbacks answer. */
enum {
    SL_SCAN_RELAY = 0, /* let the message through as it is */
    SL_SCAN_BLOCK = 1, /* send what was put in *replacement instead */
    /* Send what was put in *replacement instead, and then stop scanning until sl_scan_resume(): the
     * caller is going to run the statement in a way of its own, and what the client sent after it
     * must wait for the end. */
    SL_SCAN_GUARD = 2,
    /* Leave the message where it is and stop scanning until sl_scan_resume(); it is handed to the
     * callback again then. (The server still owes answers to what came before, for instance.) */
    SL_SCAN_WAIT = 3,
    SL_SCAN_FAIL = -1 /* out of memory */
};

typedef struct {
    /* A complete Query or Parse message: payload is its body. Replacement is empty and ready for a
     * message. */
    int (*statement)(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                     sl_buf *replacement);
    /* A message that will not be read: only its header is known. too_big says why (else: fast-path
     * call). */
    int (*unreadable)(void *ctx, uint8_t type, size_t payload_len, int too_big,
                      sl_buf *replacement);
    /* Returns non-zero to stop for good (sl_scan_run then returns SL_SCAN_CLOSE), zero to relay the
     * rest. */
    int (*frame_error)(void *ctx);
} sl_scan_ops;

enum {
    SL_SCAN_OK = 0,
    SL_SCAN_CLOSE = 1, /* the stream is not framed any more and the callback asked to stop */
    SL_SCAN_NOMEM = -1
};

void sl_scan_init(sl_scan *s, int judge_fastpath, size_t inspect_max);

/* Starts scanning again after SL_SCAN_GUARD or SL_SCAN_WAIT. */
void sl_scan_resume(sl_scan *s);

/* Puts a message of the caller's own at the release point and releases it: it goes to the server
 * before anything that follows. `answers` is the number of ReadyForQuery the server will owe for
 * it. Returns 0, or -1 when out of memory. */
int sl_scan_inject(sl_scan *s, sl_buf *buf, const void *data, size_t len, unsigned answers);

/* Looks at the bytes of buf beyond s->released. Returns one of the SL_SCAN_ values. */
int sl_scan_run(sl_scan *s, sl_buf *buf, const sl_scan_ops *ops, void *ctx);

#endif
