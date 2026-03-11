#ifndef SLUICE_SQL_CHECK_H
#define SLUICE_SQL_CHECK_H

/* Understands what a piece of SQL does, using the PostgreSQL parser itself (libpg_query), so that
 * the answer follows the real grammar instead of a guess made from keywords.
 *
 * The SQL of one message is split into the statements that would run. Each of them gets a set of
 * flags. Besides the statements written in the message, the ones hidden inside them count as well:
 *   - data-modifying CTEs:            WITH d AS (DELETE FROM t RETURNING *) SELECT ...
 *   - EXPLAIN ANALYZE <statement>     (it really runs the statement)
 *   - PREPARE p AS <statement>, DECLARE c CURSOR FOR <query>, COPY (<query>) TO ...
 * What cannot be seen is documented in docs/design.md: function bodies, DO blocks, views, rules. */

#include <stddef.h>
#include <stdint.h>

enum {
    SL_SQL_UNBOUNDED_WRITE = 1u << 0, /* UPDATE or DELETE without a WHERE clause */
    SL_SQL_DDL = 1u << 1, /* changes the schema, roles or privileges (includes DROP, TRUNCATE) */
    SL_SQL_DROP = 1u << 2,
    SL_SQL_TRUNCATE = 1u << 3,
    SL_SQL_NOT_READ_ONLY = 1u
        << 4,                    /* anything that is not on the read-only allowlist (see below) */
    SL_SQL_PROCEDURAL = 1u << 5, /* DO and CALL: code that cannot be looked into */
    SL_SQL_MULTI = 1u << 6,      /* part of a message that holds several statements */
    SL_SQL_TABLES_UNSEEN = 1u
        << 7,                /* the tables this statement touches cannot be known (see below) */
    SL_SQL_DELETE = 1u << 8, /* a DELETE (also when it is hidden inside another statement) */
    SL_SQL_UPDATE = 1u << 9  /* an UPDATE (likewise) */
};

/* Tables. For a rule that talks about tables, sluice needs to know which ones a statement touches.
 * The PostgreSQL parser reports them well for the usual statements (SELECT with joins, sub-selects
 * and CTEs, INSERT, UPDATE, DELETE, COPY, TRUNCATE, CREATE / ALTER TABLE, CREATE INDEX...), but not
 * for all: MERGE leaves out its source table, and DROP SCHEMA, GRANT ON ALL TABLES, COMMENT, VACUUM
 * without a target, CREATE FUNCTION, DO and CALL touch tables without naming them. Statements of
 * any kind whose tables are not fully reported carry SL_SQL_TABLES_UNSEEN, so that a rule can
 * assume the worst about them instead of being walked around. */

/* The read-only allowlist: SELECT without INTO or FOR UPDATE, SHOW, EXPLAIN without ANALYZE,
 * EXECUTE, DEALLOCATE, DISCARD, cursors (FETCH, CLOSE), transaction control (not the two-phase
 * kinds), and SET or RESET of a few harmless settings (application_name, DateStyle, TimeZone,
 * search_path, timeouts...). Everything else, and every statement kind this version does not know,
 * is NOT_READ_ONLY. */

/* A table as written in the SQL: schema is "" when none was given. Names are as the parser gives
 * them: lower-cased unless quoted. */
typedef struct {
    char *schema;
    char *name;
} sl_sql_table;

typedef struct {
    sl_sql_table *items;
    size_t count;
} sl_sql_tables;

typedef struct {
    uint32_t *flags; /* one entry per effective statement */
    size_t *group;   /* for each of them, the statement of the message it comes from (0-based) */
    size_t count;
    size_t top_level; /* statements written in the message */
    /* When the message is one statement: 'D' if it is a DELETE, 'U' if it is an UPDATE, else 0; and
     * whether it has a RETURNING of its own. */
    uint8_t top_kind;
    int top_returning;
    sl_sql_tables *tables; /* the tables of each statement of the message; NULL unless asked for */
} sl_sql_info;

/* Returns 0 and fills *out (release it with sl_sql_info_free), or -1 with a message in err when the
 * SQL cannot be understood: syntax error, nesting too deep, out of memory. Such SQL is
 * "uninspectable". */
int sl_sql_classify(const char *sql, size_t len, sl_sql_info *out, char *err, size_t errcap);

/* The same, and also lists the tables of each statement of the message (info.tables). The
 * statements hidden inside another one (a data-modifying CTE, the statement of EXPLAIN ANALYZE...)
 * share the tables of the statement that holds them. Costs a second parse per statement, so only
 * ask when a rule needs it. */
int sl_sql_classify_with_tables(const char *sql, size_t len, sl_sql_info *out, char *err,
                                size_t errcap);

void sl_sql_info_free(sl_sql_info *info);

/* Where the statement really ends: the offset after its last token that is not a comment and not a
 * semicolon (so that " RETURNING *" can be added there). Returns 0 when there is no such token or
 * the text cannot be read by the lexer. */
size_t sl_sql_statement_end(const char *sql, size_t len);

/* What can be written in a log without writing the values that the SQL carries.
 *
 * The PostgreSQL normalizer replaces literals with $1, $2... (`where email = 'a@b.c'` becomes
 * `where email = $1`), and the fingerprint is a hash of what is left: the same for the same query
 * whatever its values. But the normalizer only knows about the usual statements. It leaves the
 * values in CREATE SERVER ... OPTIONS (password '...'), COPY ... FROM PROGRAM '...', COMMENT ON,
 * PREPARE, column defaults, and all comments. So its output is trusted only after the PostgreSQL
 * lexer has been run over it and found no constant and no comment; otherwise the text is withheld
 * and only the fingerprint remains. */
typedef struct {
    char fingerprint[17]; /* 16 hex digits */
    char *text;           /* the normalized SQL; NULL when it cannot be shown without risk */
} sl_sql_redacted;

/* Returns 0 with *out filled (release with sl_sql_redacted_free), or -1 when the SQL cannot be
 * parsed, with a message in err from which the quoted piece of SQL has been removed ("syntax
 * error", not "syntax error at or near "hunter2""). */
int sl_sql_redact(const char *sql, size_t len, sl_sql_redacted *out, char *err, size_t errcap);
void sl_sql_redacted_free(sl_sql_redacted *r);

/* Cuts a parser message before the part that quotes the SQL (" at or near ..."). */
void sl_sql_scrub_error(char *err);

#endif
