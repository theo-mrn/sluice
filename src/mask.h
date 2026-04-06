#ifndef SLUICE_MASK_H
#define SLUICE_MASK_H

/* Hiding values in the rows that go to the client (the "mask" action of a rule, docs/policy.md).
 *
 * What is built here is a garde-fou, not a security boundary: it works on what the client could
 * read anyway, by the name the client gives the column and by the look of the value, and a client
 * that can run SQL can compute around it (md5(email), substr, a comparison in a WHERE clause). The
 * boundary is the privileges of the database. What it does well is keep personal data out of what
 * an agent reads and out of the transcripts and logs that follow, by accident or by a careless
 * query.
 *
 * Two ways to find what to hide, which complement each other:
 *   - by NAME: the output name of a column (what the RowDescription says, so an alias is a new
 *     name), compared without regard to case;
 *   - by PATTERN: an e-mail address, a payment card number (13-19 digits that pass the Luhn check)
 *     or an IBAN (country, two check digits, mod 97 = 1), found inside any text-like value whatever
 *     its column is called. The scans are hand written and linear: no regular expression, so no
 *     input makes them slow.
 *
 * And four ways to hide it (`how`): a stable token made with HMAC-SHA256 (the same value gives the
 * same token while the key stays the same, so joins and counts still work: "hash"), a part of the
 * value kept ("partial"), NULL ("null"), or "[masked]" ("redact").
 *
 * Types. A whole value can be replaced by text only where the client expects text: text, varchar,
 * bpchar, name and "char" (binary format is the same bytes). Any other type of a column picked by
 * name becomes NULL, whatever `how` says. The patterns are looked for in those types and in json,
 * jsonb and xml. A value is never changed when nothing is found in it.
 *
 * No socket, no policy: messages in, messages out, so that it can be tested and fuzzed. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

/* what to look for */
enum { SL_MASK_EMAIL = 1, SL_MASK_CARD = 2, SL_MASK_IBAN = 4 };
/* how to hide it */
enum { SL_MASK_HASH = 0, SL_MASK_PARTIAL = 1, SL_MASK_NULL = 2, SL_MASK_REDACT = 3 };

#define SL_MASK_MAX_RULES 8
#define SL_MASK_MAX_COLUMNS 64 /* names in one rule */
#define SL_MASK_NAME_MAX 63    /* the longest identifier of PostgreSQL */
#define SL_MASK_MAX_FIELDS 2048
#define SL_MASK_KEY_MAX 1024

/* One rule, as the policy has it (read, not kept). */
typedef struct {
    const char *name;
    char *const *columns;
    size_t ncolumns;
    unsigned detect;
    int how;
} sl_mask_rule_view;

typedef struct sl_mask sl_mask;

/* Copies the rules. The key makes the tokens of "hash": the same key, the same token. NULL when out
 * of memory, or when there are more rules than SL_MASK_MAX_RULES. */
sl_mask *sl_mask_new(const sl_mask_rule_view *rules, size_t n, const uint8_t *key, size_t key_len);
void sl_mask_free(sl_mask *m);

/* ---- qualified names ----
 *
 * A name in `columns` may be written table.column or schema.table.column: the column is hidden only
 * when the rows come from that table. The RowDescription says which table a column comes from, as
 * an OID, so the connection asks the server once, when it starts, for the OIDs and names of its
 * tables (SL_MASK_CATALOG_SQL, sent by the caller as a query of its own whose answer the client
 * never sees) and hands each DataRow of the answer here.
 *
 * What it cannot do is wrong on the side of hiding. A column that comes from no table (a computed
 * value), a table made after the list was read, a list that was not read or not complete: the
 * column is hidden, as if its name were not qualified. A view is a table of its own: to hide a
 * column through a view, name the view. */

#define SL_MASK_CATALOG_MAX 20000
#define SL_MASK_CATALOG_SQL                                                                        \
    "select c.oid::bigint, n.nspname, c.relname from pg_catalog.pg_class c join "                  \
    "pg_catalog.pg_namespace n on n.oid = c.relnamespace where c.relkind in "                      \
    "('r','p','v','m','f') limit 20000"

/* Is any name qualified (so that the catalog is worth reading)? */
int sl_mask_qualified(const sl_mask *m);
void sl_mask_catalog_start(sl_mask *m);
/* A DataRow of the answer (oid, schema, table, in text). -1 when it is not what was asked for. */
int sl_mask_catalog_row(sl_mask *m, const uint8_t *payload, size_t len);
/* The answer is over; ok is 0 when it ended in an error or was cut. */
void sl_mask_catalog_end(sl_mask *m, int ok);

/* ---- rows ---- */

/* The RowDescription that the rows that follow belong to (its payload). 0, or -1 when it is not
 * well formed: the rows that follow are then refused (sl_mask_row returns SL_MASK_BAD). */
int sl_mask_describe(sl_mask *m, const uint8_t *payload, size_t len);
/* There are no rows to come (NoData, or the end of a result). */
void sl_mask_forget(sl_mask *m);
/* Is there anything to do to the rows of the current description? When not they may go unread. */
int sl_mask_has_work(const sl_mask *m);
/* Is a description known? */
int sl_mask_described(const sl_mask *m);

enum { SL_MASK_SAME = 0, SL_MASK_CHANGED = 1, SL_MASK_BAD = -1, SL_MASK_NOMEM = -2 };

/* A DataRow (its payload). SL_MASK_CHANGED: the row to send instead is in *out (its payload,
 * appended). SL_MASK_SAME: nothing was found, send it as it is. SL_MASK_BAD: it does not match the
 * description. */
int sl_mask_row(sl_mask *m, const uint8_t *payload, size_t len, sl_buf *out);

/* How many values have been changed since the last call (and resets the count). */
unsigned long long sl_mask_take_count(sl_mask *m);

/* ---- errors and notices ---- */

/* An ErrorResponse or NoticeResponse (its payload) quotes values: "Key (email)=(a@b.com) already
 * exists", "Failing row contains (...)". The patterns are looked for in every text field, and the
 * values of a Key or Failing row detail are hidden when a named column could be in them.
 * SL_MASK_CHANGED: the message to send is in *out; SL_MASK_SAME otherwise. */
int sl_mask_message(sl_mask *m, const uint8_t *payload, size_t len, sl_buf *out);

/* ---- the pieces, for the tests ---- */

/* Finds the first match of a kind of pattern at or after `from` in text[0..len): its start and end.
 * kind is one SL_MASK_* bit. 1 when found. */
int sl_mask_find(unsigned kind, const char *text, size_t len, size_t from, size_t *start,
                 size_t *end);
int sl_mask_luhn(const char *digits, size_t n);

#endif
