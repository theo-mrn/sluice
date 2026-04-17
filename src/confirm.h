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
#include "journal.h"
#include "mask.h"

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
    int limit; /* nobody is asked: more than over_rows rows is undone, at most that is committed */
    int kind; /* 'D' or 'U' (rows to count and show), 'T' (TRUNCATE) or 'R' (DROP): run as it is, no
                 rows, always asked about whatever over_rows says */
    int side_effects; /* look at what else the statement changed (cascades, triggers) before asking
                       */
    /* A DELETE that a rule wants kept for undo (journal.h). The rows of the statement are held
     * while it runs, and handed to journal_fn just before the COMMIT: it fills in what only the
     * caller knows (who, which statement) and writes the entry. Non-zero from it means the entry is
     * not written: with SL_JOURNAL_REQUIRED the DELETE is then not applied. */
    int journal; /* SL_JOURNAL_* */
    const char *schema;
    const char *table; /* what the DELETE deletes from, as written; may be empty */
    int (*journal_fn)(void *ctx, sl_journal_entry *e);
    void *journal_ctx;
    sl_mask *mask; /* the values this user may not read are hidden in the rows shown and given back
                      (mask.h); not owned; may be NULL */
    int extended;  /* the statement is run through the extended protocol (docs/design.md, section
                      21): its Execute is already on its way, so there is nothing to start with, and
                      the exchange ends without a ReadyForQuery: the client's Sync follows */
} sl_confirm_args;

/* What the caller must do after a message: both are zero while the exchange goes on. */
typedef struct {
    int ask;  /* show the prompt (sl_confirm_render) and call sl_confirm_answer with the reply */
    int done; /* the exchange is over: what is in *to_client goes to the client, the stream goes on
               */
} sl_confirm_step;

/* What else a statement changed (cascades, triggers) comes from the statistics of the transaction,
 * which a session keeps per table: the tables that have counted inserted, updated and deleted rows.
 * They are read just before the statement and just after it, in the same exchange with the server
 * (nothing in between, so nothing is flushed), and the difference is what the statement did. The
 * first look is needed because the counters also hold what earlier transactions of the session did
 * and had not been reported yet. */
#define SL_CONFIRM_LOOK_MAX 256
/* The tables shown. */
#define SL_CONFIRM_SIDE_MAX 8

#define SL_CONFIRM_SIDE_SQL                                                                        \
    "select schemaname || '.' || relname, n_tup_ins, n_tup_upd, n_tup_del from "                   \
    "pg_stat_xact_user_tables where n_tup_ins + n_tup_upd + n_tup_del > 0 limit 256"

/* How many rows of the result are kept to be shown. */
/* The most rows, and bytes of them, held to be kept for undo: a DELETE of more is recorded as not
 * whole. */
#define SL_CONFIRM_JOURNAL_ROWS 10000
#define SL_CONFIRM_JOURNAL_BYTES ((size_t)8 << 20)

#define SL_CONFIRM_SAMPLE_ROWS 50
/* ... of which a terminal shows this many (the client of a session can ask for all of them). */
#define SL_CONFIRM_TERMINAL_ROWS 10
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

/* The messages of an extended exchange, to be sent in place of the client's Execute: a Describe of
 * the portal (the names of the columns), the first look at the statistics, the Execute itself
 * (`execute` is its payload: portal NUL and the row limit), the second look, the closing of what
 * the looks used, and a Flush, so that the answers come now and not at the Sync. 0, or -1 when out
 * of memory. */
int sl_confirm_ext_wrap(const sl_confirm *c, const uint8_t *portal, size_t portal_len,
                        const uint8_t *execute, size_t execute_len, sl_buf *out);

/* Like sl_confirm_answer for an extended exchange: a yes gives the client its answer at once (the
 * Sync that commits is the client's own), a no sends a message that fails to the server and gives
 * the client an error. The caller must look at step->done. */
int sl_confirm_answer_ext(sl_confirm *c, int yes, const char *outcome, sl_buf *to_server,
                          sl_buf *to_client, sl_confirm_step *step);

int sl_confirm_is_extended(const sl_confirm *c);

/* The text to show before asking: the statement, the rows, the question. Control characters are
 * replaced, so that what the database holds cannot write on the terminal. Returns its length. */
size_t sl_confirm_render(const sl_confirm *c, char *out, size_t cap);

/* The same without the last line, which asks: for when the question is put in the client's own
 * session (the answer is a statement of its own, see conn.c). */
size_t sl_confirm_render_body(const sl_confirm *c, char *out, size_t cap);

/* A few lines for a client that has just typed the statement and knows what it is: how many rows,
 * the first `rows`, and what else changed, in one line. */
size_t sl_confirm_render_brief(const sl_confirm *c, char *out, size_t cap, int rows);

/* What to do on the server to end an exchange that is waiting in the client's session: the single
 * statement to run for a yes or a no, or NULL for a no when only a failing message can undo it (the
 * extended protocol, where there is no transaction block to roll back). */
/* A statement that the person asked said yes to, in their own session, is about to be committed by
 * the caller (the confirmation does not see the COMMIT): its rows go to the journal first. 0:
 * commit. -1: do not (the reason is sl_confirm_why, the outcome is "journal"). */
int sl_confirm_journal_gate(sl_confirm *c);
const char *sl_confirm_why(const sl_confirm *c);

const char *sl_confirm_resolution_sql(const sl_confirm *c, int yes);

/* The command tag of the statement ("DELETE 41234"), the rule and its message, for the texts that
 * are shown to the client. */
const char *sl_confirm_tag(const sl_confirm *c);
const char *sl_confirm_rule(const sl_confirm *c);
const char *sl_confirm_message(const sl_confirm *c);
void sl_confirm_set_outcome(sl_confirm *c, const char *outcome);

unsigned long long sl_confirm_rows(const sl_confirm *c);
/* "yes", "auto" (not above the threshold), "no", "timeout", "no_terminal", "error", "too_large". */
const char *sl_confirm_outcome(const sl_confirm *c);
int sl_confirm_has_detail(const sl_confirm *c);

#endif
