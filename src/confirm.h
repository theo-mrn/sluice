#ifndef SLUICE_CONFIRM_H
#define SLUICE_CONFIRM_H

/* Running a DELETE or an UPDATE inside a transaction that is not committed yet, looking at what it
 * did, and having someone confirm before it becomes final. See docs/design.md, section 20.
 *
 * This is the state machine of one such exchange, with no socket, no terminal and no policy. It is
 * given the messages the server answers and says what to send back to the server, what to give the
 * client, and when to ask the person. That is what makes it testable message by message.
 *
 * The exchange, for a session that is idle ('I'):
 *   to the server:   BEGIN; <statement> RETURNING *        (RETURNING added when the client had
 * none) from the server: the rows, "DELETE n", ReadyForQuery('T')      (all kept back) then,
 * depending on n and on the answer of the person: to the server:   COMMIT      or      ROLLBACK to
 * the client:   the statement's own answer and ReadyForQuery   or   an error and ReadyForQuery For
 * a session that is already in a transaction ('T') a savepoint takes the place of BEGIN / COMMIT /
 * ROLLBACK, so that the client's transaction goes on.
 *
 * If the statement fails with the RETURNING added (the role may delete but not read, say), it is
 * run again as the client wrote it, and the person is shown the count only. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

typedef struct sl_confirm sl_confirm;

typedef struct {
    const char *sql; /* the statement as the client wrote it, without the trailing ; or comment */
    size_t sql_len;
    const char *sql_returning; /* the same with RETURNING * added; NULL when it cannot be (or is not
                                  needed) */
    size_t sql_returning_len;
    int client_returning; /* the client's statement has a RETURNING of its own: its rows are given
                             back */
    int tx_status;        /* 'I' (idle) or 'T' (in a transaction) */
    unsigned long long over_rows; /* more rows than this are asked about; fewer are committed */
    const char *user;
    size_t user_len;
    const char *database;
    size_t database_len;
    const char *rule;
    const char
        *message; /* what the rule says to the client when it is not confirmed; may be NULL */
} sl_confirm_args;

/* What the caller must do after a message: both are zero while the exchange goes on. */
typedef struct {
    int ask;  /* show the prompt (sl_confirm_render) and call sl_confirm_answer with the reply */
    int done; /* the exchange is over: what is in *to_client goes to the client, the stream goes on
               */
} sl_confirm_step;

/* How many rows of the result are kept to be shown. */
#define SL_CONFIRM_SAMPLE_ROWS 10
/* The most a client's own RETURNING may hold while waiting for the answer. */
#define SL_CONFIRM_HELD_MAX ((size_t)64 << 20)

sl_confirm *sl_confirm_new(void);
void sl_confirm_free(sl_confirm *c);

/* Starts: puts the first message to send to the server in *to_server. 0, or -1 when out of memory.
 */
int sl_confirm_start(sl_confirm *c, const sl_confirm_args *a, sl_buf *to_server);

/* One message from the server, which belongs to the exchange. Returns SL_SRV_KEEP (give it to the
 * client now: notices and the like) or SL_SRV_DROP (it is consumed), or -1 when out of memory.
 * Messages for the server go to *to_server, for the client to *to_client. */
int sl_confirm_server(sl_confirm *c, uint8_t type, const uint8_t *payload, size_t len,
                      sl_buf *to_server, sl_buf *to_client, sl_confirm_step *step);

/* A message of the result was too large to be held (a client's own RETURNING): the statement will
 * not be confirmable, and is rolled back with an error when its answer ends. */
void sl_confirm_overflow(sl_confirm *c);

/* The person's reply (yes), or what stands for it: outcome is "no", "timeout" or "no_terminal". */
int sl_confirm_answer(sl_confirm *c, int yes, const char *outcome, sl_buf *to_server);

/* The text to show before asking: the statement, the rows, the question. Control characters are
 * replaced, so that what the database holds cannot write on the terminal. Returns its length. */
size_t sl_confirm_render(const sl_confirm *c, char *out, size_t cap);

unsigned long long sl_confirm_rows(const sl_confirm *c);
/* "yes", "auto" (not above the threshold), "no", "timeout", "no_terminal", "error", "too_large". */
const char *sl_confirm_outcome(const sl_confirm *c);
int sl_confirm_has_detail(const sl_confirm *c);

#endif
