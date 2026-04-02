#ifndef SLUICE_EXTSTATE_H
#define SLUICE_EXTSTATE_H

/* What sluice has to remember about the extended query protocol to confirm a DELETE or an UPDATE
 * that a client prepares (Parse), binds (Bind) and runs (Execute), possibly many messages apart and
 * several at a time without waiting for the answers (a pipeline). See docs/design.md, section 21.
 *
 * Two things are kept, with no socket and no policy so that they can be tested and fuzzed:
 *
 *   - Which prepared statements and portals are "guarded": the statement a rule wants confirmed,
 *     and the portals made from it. Only guarded ones are stored (a name that is not there is not
 *     guarded), so the tables stay small whatever the client does.
 *
 *   - The answers the server still owes, as a queue of what each forwarded message will bring back:
 *     a Describe brings a RowDescription (or NoData), an Execute brings rows and one terminal
 *     message, a Sync or a Query brings ReadyForQuery. It is what tells which answers belong to a
 *     guarded statement when the server's stream is read: the RowDescription of a guarded
 *     Describe has to become NoData (sluice added a RETURNING the client does not know about), and
 *     the answers of a guarded Execute are held for the person.
 *
 * After an ErrorResponse the server ignores everything up to the next Sync, so the queue stops
 * matching until ReadyForQuery arrives, which also ends the cycle. */

#include <stddef.h>
#include <stdint.h>

/* The longest name that is tracked. The server keeps only the first 63 bytes of a name, so a longer
 * one cannot be compared the way the server does: it is refused where it could matter. */
#define SL_EXT_NAME_MAX 63
/* How many guarded statements, and as many guarded portals, one connection may hold. */
#define SL_EXT_GUARDED_MAX 256
/* The queue of answers is run-length encoded, so a long batch of ordinary Executes is one entry. */
#define SL_EXT_SLOTS_MAX 1024

enum {
    SL_EXT_OK = 0,
    SL_EXT_FULL = -1,     /* a table or the queue is full */
    SL_EXT_TOO_LONG = -2, /* the name is longer than SL_EXT_NAME_MAX, or not terminated */
    SL_EXT_NOMEM = -3
};

/* What a forwarded message will be answered with. */
enum {
    SL_EXT_PARAMS,    /* ParameterDescription (Describe of a statement) */
    SL_EXT_ROWDESC,   /* RowDescription or NoData */
    SL_EXT_ROWDESC_G, /* the same, for a guarded statement: RowDescription becomes NoData */
    SL_EXT_EXEC,      /* rows and a CommandComplete, EmptyQuery, PortalSuspended or error */
    SL_EXT_EXEC_G,    /* the same for a guarded portal, with the RowDescription of a Describe that
                         sluice added in front of the Execute */
    SL_EXT_SYNC,      /* Sync: ends with ReadyForQuery */
    SL_EXT_SIMPLE, /* Query or fast-path call: whatever comes is theirs, ends with ReadyForQuery */
    SL_EXT_EXEC_M  /* an Execute that sluice put a Describe of the portal in front of, to know the
                      columns of the rows (masking): first a RowDescription or NoData that is
                      sluice's own, then as for SL_EXT_EXEC */
};

typedef struct {
    uint8_t kind;
    uint32_t count;
} sl_ext_slot;

/* What is kept of a guarded statement, to be able to ask about it when it is run. */
#define SL_EXT_SQL_MAX 4096

typedef struct {
    const char *sql; /* the statement as the client wrote it */
    size_t sql_len;
    const char *rule;
    const char *message; /* what the rule tells the client when it is refused; may be NULL */
    unsigned long long over_rows;
    int rewritten;      /* sluice added a RETURNING the client did not write */
    int side_effects;   /* look at what else it changes before asking */
    int kind;           /* 'D', 'U', 'T' (truncate) or 'R' (drop) */
    int limit;          /* a limit rule: undone above over_rows rows, nobody is asked */
    int via;            /* SL_VIA_*: who is asked */
    int journal;        /* SL_JOURNAL_*: the rows of a DELETE are kept for undo */
    const char *schema; /* the table it deletes from, as written (may be NULL) */
    const char *table;
} sl_ext_guard;

typedef struct {
    char name[SL_EXT_NAME_MAX + 1];
    char rule[72];
    char message[208];
    unsigned long long over_rows;
    int rewritten;
    int side_effects;
    int kind;
    int limit;
    int via;
    int journal;
    char schema[64];
    char table[64];
    char *sql; /* at most SL_EXT_SQL_MAX bytes; owned */
    size_t sql_len;
} sl_ext_entry;

typedef struct sl_ext {
    sl_ext_entry *stmts[SL_EXT_GUARDED_MAX]; /* only the guarded ones */
    size_t nstmts;
    sl_ext_entry *portals[SL_EXT_GUARDED_MAX];
    size_t nportals;
    sl_ext_entry *unnamed_stmt;   /* the unnamed statement, when it is guarded */
    sl_ext_entry *unnamed_portal; /* and the unnamed portal */

    sl_ext_slot slots[SL_EXT_SLOTS_MAX];
    size_t head, len; /* a ring: slots[head] is the front, `len` entries */
    int skipping;     /* after an error: nothing matches until ReadyForQuery */
    int desc_seen;    /* the front SL_EXT_EXEC_M has had its RowDescription */
} sl_ext;

sl_ext *sl_ext_new(void);
void sl_ext_free(sl_ext *e);

/* Reads a name at the start of p (a string ending in a NUL, within avail bytes). Returns its length
 * and sets *name, or SL_EXT_TOO_LONG. */
int sl_ext_name(const uint8_t *p, size_t avail, const char **name);

/* ---- statements and portals ---- */

/* A Parse of a statement a rule wants confirmed. A named statement keeps the guard it first got:
 * the server refuses to define a name twice (and a statement closed behind sluice's back by
 * DEALLOCATE is not noticed), so what was recorded stays. The unnamed statement is replaced by
 * every Parse. */
int sl_ext_parse_guarded(sl_ext *e, const char *name, size_t len, const sl_ext_guard *g);
/* A Parse of any other statement. */
void sl_ext_parse_plain(sl_ext *e, const char *name, size_t len);
/* The guard of a statement, or NULL when it is not guarded. */
const sl_ext_entry *sl_ext_stmt_guard(const sl_ext *e, const char *name, size_t len);
void sl_ext_stmt_close(sl_ext *e, const char *name, size_t len);

/* A Bind: the portal takes the guard of its statement (`stmt` is what sl_ext_stmt_guard said, NULL
 * when it is not guarded). */
int sl_ext_bind(sl_ext *e, const char *portal, size_t len, const sl_ext_entry *stmt);
const sl_ext_entry *sl_ext_portal_guard(const sl_ext *e, const char *name, size_t len);
void sl_ext_portal_close(sl_ext *e, const char *name, size_t len);

/* The transaction ended (ReadyForQuery 'I'): its portals are gone. */
void sl_ext_portals_end(sl_ext *e);

/* How many statements and portals are guarded. */
size_t sl_ext_guarded(const sl_ext *e);

/* ---- the answers the server owes ---- */

/* Notes what a message that is being sent to the server will bring back. SL_EXT_FULL when the queue
 * is full: the caller refuses the message. */
int sl_ext_expect(sl_ext *e, int kind);

/* Flags returned by sl_ext_answer. */
enum {
    SL_EXT_TO_NODATA = 1, /* this RowDescription is of a guarded statement: send NoData instead */
    SL_EXT_SKIPPED = 2,   /* a guarded Execute will not run: an error came before it */
    SL_EXT_OURS = 4       /* this RowDescription (or NoData) answers the Describe that sluice added
                             before an Execute: it is for sluice alone */
};

/* A message of this type came from the server; settles it against the queue. */
int sl_ext_answer(sl_ext *e, uint8_t type);

/* The next answer is the one of a guarded Execute. */
int sl_ext_front_guarded_exec(const sl_ext *e);
/* The next answer is the RowDescription of a guarded statement. */
int sl_ext_front_guarded_rowdesc(const sl_ext *e);
/* A guarded answer is still owed (a Describe or an Execute). */
int sl_ext_guard_pending(const sl_ext *e);
/* The queue matches what the server sends (no error since the last ReadyForQuery). */
int sl_ext_in_step(const sl_ext *e);

#endif
