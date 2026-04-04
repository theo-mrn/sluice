#ifndef SLUICE_JOURNAL_H
#define SLUICE_JOURNAL_H

/* A journal of the rows that DELETEs removed (and the old values of UPDATEs), to put them back
 * (docs/policy.md, "Undoing a DELETE").
 *
 * One line of JSON per DELETE, appended to a file before the DELETE is committed: who, when, which
 * statement and rule, the table, the columns and every row the server gave back (as text), whether
 * the rows are all there, and what else the statement changed (cascades, triggers). `sluice --undo`
 * reads it and prints the SQL that puts the rows back; it does not connect to anything.
 *
 * What is written is the data itself: the file is readable by its owner only, and holds what a mask
 * hides from a user. The writer has no socket and no policy: it is given what it writes. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

#define SL_JOURNAL_ID_LEN 16 /* hexadecimal digits */

/* What a rule does with the rows of a DELETE it lets through: nothing, record them for undo as well
 * as it can, or record them and not apply the DELETE when it cannot. */
enum { SL_JOURNAL_OFF = 0, SL_JOURNAL_ON = 1, SL_JOURNAL_REQUIRED = 2 };

typedef struct sl_journal sl_journal;

/* What happened to the rows beside the DELETE itself. */
typedef struct {
    const char *table;
    unsigned long long inserted, updated, deleted;
} sl_journal_side;

typedef struct {
    const char *user;
    size_t user_len;
    const char *database;
    size_t database_len;
    const char *rule;
    const char *protocol; /* "simple" or "extended" */
    const char *sql;
    size_t sql_len;
    const char *schema; /* where the rows were: as written in the statement */
    const char *table;
    const char *tag; /* "DELETE 3" */
    int update;      /* an UPDATE: every row is the old row and the new row side by side
                      * (RETURNING OLD.*, NEW.*), so there are twice the columns */
    unsigned long long rows;
    /* the RowDescription of the rows and the rows: each DataRow payload preceded by its length (4
     * bytes, big endian). NULL desc: the rows were not kept. */
    const uint8_t *desc;
    size_t desc_len;
    const uint8_t *data;
    size_t data_len;
    size_t nrows;
    const char *incomplete; /* why the rows cannot be put back whole; NULL when they can */
    int side_known; /* the statistics of the transaction were read, so `side` is all there is */
    const sl_journal_side *side;
    size_t nside;
} sl_journal_entry;

/* Opens (creates, owner-only) the file for appending. The journal stops taking entries when it
 * would grow past max_bytes (0: no limit). NULL with a message in err on failure. */
sl_journal *sl_journal_open(const char *path, unsigned long long max_bytes, char *err,
                            size_t errcap);
void sl_journal_close(sl_journal *j);

/* Opens the same path again and writes there from now on: after the file was renamed to be archived
 * (SIGHUP), the next entry starts a new one. The old one stays as it was if this fails. */
int sl_journal_reopen(sl_journal *j, char *err, size_t errcap);

/* Appends one entry and makes it durable (fsync). id receives its identifier (16 hexadecimal digits
 * and a NUL). 0, or -1 with a reason in err: out of room, not valid text, the disk. Nothing partial
 * is left behind that a reader would take for an entry. */
int sl_journal_append(sl_journal *j, const sl_journal_entry *e, char id[SL_JOURNAL_ID_LEN + 1],
                      char *err, size_t errcap);

/* The same line without writing it, for the tests. */
int sl_journal_format(const sl_journal_entry *e, const char id[SL_JOURNAL_ID_LEN + 1],
                      long long unix_s, sl_buf *out);

#endif
