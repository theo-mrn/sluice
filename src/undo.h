#ifndef SLUICE_UNDO_H
#define SLUICE_UNDO_H

/* `sluice --undo FILE [--id ID] [--partial]`: reads the journal of the rows that DELETEs removed
 * (journal.h) and prints, for one entry, the SQL that puts them back (the deleted rows are inserted
 * again; the rows of an UPDATE get their old values back). Without --id it lists the
 * entries. It connects to nothing: the script is for a person to read, and to run when they have.
 *
 * Exit status: 0, 1 when the entry cannot be put back whole (and --partial was not given) or the
 * file cannot be read, 2 for a command line that is wrong. */

#include <stddef.h>

#include "buf.h"

typedef struct {
    char *table;
    unsigned long long inserted, updated, deleted;
} sl_undo_side;

typedef struct {
    char *id, *ts, *user, *database, *rule, *protocol, *sql, *schema, *table, *tag, *incomplete,
        *kind;
    unsigned long long rows;
    int complete;
    int side_known;
    char **columns;
    size_t ncols;
    char **
        *data; /* nrows x ncols; a NULL is a NULL: the rows deleted, or the rows before an UPDATE */
    size_t nrows;
    char ***fresh; /* an UPDATE: the rows after it, as many as `data` */
    size_t nfresh;
    sl_undo_side *side;
    size_t nside;
} sl_undo_entry;

int sl_undo_main(int argc, char **argv);

/* One line of the journal. 0, or -1 with a message in err. Release with sl_undo_free. */
int sl_undo_parse(const char *line, size_t len, sl_undo_entry *e, char *err, size_t errcap);
void sl_undo_free(sl_undo_entry *e);

/* The script for an entry. 0, or -1 when the entry is not whole and `partial` is 0 (the reason in
 * err), or on an entry that cannot be written as SQL. */
int sl_undo_sql(const sl_undo_entry *e, int partial, sl_buf *out, char *err, size_t errcap);

#endif
