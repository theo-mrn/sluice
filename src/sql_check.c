#include "sql_check.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pg_query.h>
#include <sys/resource.h>

#include "protobuf/pg_query.upb.h"

/* The parse tree of a long expression (1 + 1 + ... or a chain of UNION) is as deep as it is long.
 * The default of upb is 100, which would reject ordinary generated SQL. */
#define DECODE_MAX_DEPTH 4000
/* How far we follow statements hidden in other statements (EXPLAIN ANALYZE of a PREPARE of ...). */
#define MAX_NESTING 8
/* The same, for the arms of a chain of UNION / INTERSECT / EXCEPT. */
#define MAX_SETOP_DEPTH 2000

/* How deep the PostgreSQL parser may recurse. libpg_query sizes that from the stack it can see
 * below it, with pthread_getattr_np(): on glibc and macOS that is the real stack of the main thread
 * (8 MiB usually) and the budget goes up to 2 MiB. On musl the same call only reports the part of
 * the main stack that is mapped so far, a few dozen kB, and the budget stays at the default of 100
 * kB: "select 1 + 1 + ... + 1" of 1000 terms, ordinary generated SQL, ends in "stack depth limit
 * exceeded". When the library cannot do better we give it the limit that the process really has.
 * These two variables belong to the library (src/postgres/), which the subproject pins by hash. */
extern __thread int max_stack_depth;
extern void assign_max_stack_depth(int newval, void *extra);

static void allow_deep_statements(void)
{
    static int done;
    struct rlimit rl;
    long kb;

    if (done) {
        return;
    }
    done = 1;
    if (getrlimit(RLIMIT_STACK, &rl) != 0) {
        return;
    }
    /* up to half of what is left after the first MiB, and no more than the 2 MiB the library itself
     * allows */
    kb = rl.rlim_cur == RLIM_INFINITY ? 2048 : ((long)(rl.rlim_cur / 1024) - 1024) / 2;
    if (kb > 2048) {
        kb = 2048;
    }
    if (kb > max_stack_depth) { /* the default is 100 kB: only ever raise it */
        max_stack_depth = (int)kb;
        assign_max_stack_depth((int)kb, NULL);
    }
}

typedef struct {
    uint32_t *flags;
    size_t *group;
    size_t count;
    size_t cap;
    size_t cur_group; /* the statement of the message being classified */
    int oom;
} collector;

static void add(collector *c, uint32_t f)
{
    if (c->count == c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 8;
        uint32_t *p = realloc(c->flags, cap * sizeof *p);
        size_t *g;

        if (p == NULL) {
            c->oom = 1;
            return;
        }
        c->flags = p;
        g = realloc(c->group, cap * sizeof *g);
        if (g == NULL) {
            c->oom = 1;
            return;
        }
        c->group = g;
        c->cap = cap;
    }
    c->flags[c->count] = f;
    c->group[c->count] = c->cur_group;
    c->count++;
}

static int sv_eq_nocase(upb_StringView sv, const char *s)
{
    size_t n = strlen(s);

    if (sv.size != n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)sv.data[i]) != tolower((unsigned char)s[i])) {
            return 0;
        }
    }
    return 1;
}

/* Settings a client may change without it meaning anything for what the session can do. Custom
 * settings (names with a dot, like myapp.user_id) are in too. */
static int set_is_harmless(upb_StringView name)
{
    static const char *const ok[] = {
        "application_name",
        "client_encoding",
        "datestyle",
        "extra_float_digits",
        "intervalstyle",
        "timezone",
        "statement_timeout",
        "lock_timeout",
        "idle_in_transaction_session_timeout",
        "standard_conforming_strings",
        "bytea_output",
        "search_path",
        "client_min_messages",
        "transaction",
        "session characteristics",
    };

    if (memchr(name.data, '.', name.size) != NULL) {
        return 1;
    }
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        if (sv_eq_nocase(name, ok[i])) {
            return 1;
        }
    }
    return 0;
}

/* The flags of a SELECT itself: SELECT INTO creates a table, FOR UPDATE / FOR SHARE takes row
 * locks. The arms of UNION / INTERSECT / EXCEPT are followed. */
static uint32_t select_flags(const pg_query_SelectStmt *s, int depth)
{
    uint32_t f = 0;
    size_t n = 0;

    if (depth > MAX_SETOP_DEPTH) {
        return SL_SQL_NOT_READ_ONLY;
    }
    if (pg_query_SelectStmt_has_into_clause(s)) {
        f |= SL_SQL_DDL | SL_SQL_NOT_READ_ONLY;
    }
    (void)pg_query_SelectStmt_locking_clause(s, &n);
    if (n > 0) {
        f |= SL_SQL_NOT_READ_ONLY;
    }
    if (pg_query_SelectStmt_larg(s) != NULL) {
        f |= select_flags(pg_query_SelectStmt_larg(s), depth + 1);
    }
    if (pg_query_SelectStmt_rarg(s) != NULL) {
        f |= select_flags(pg_query_SelectStmt_rarg(s), depth + 1);
    }
    return f;
}

static int arg_is_false(const pg_query_Node *arg)
{
    switch (pg_query_Node_node_case(arg)) {
    case pg_query_Node_node_boolean:
        return !pg_query_Boolean_boolval(pg_query_Node_boolean(arg));
    case pg_query_Node_node_integer:
        return pg_query_Integer_ival(pg_query_Node_integer(arg)) == 0;
    case pg_query_Node_node_string: {
        upb_StringView v = pg_query_String_sval(pg_query_Node_string(arg));

        return sv_eq_nocase(v, "false") || sv_eq_nocase(v, "off") || sv_eq_nocase(v, "0") ||
               sv_eq_nocase(v, "no") || sv_eq_nocase(v, "f") || sv_eq_nocase(v, "n");
    }
    default:
        return 0;
    }
}

/* EXPLAIN runs the statement only with ANALYZE. Anything we do not understand counts as "runs". */
static int explain_runs_query(const pg_query_ExplainStmt *s)
{
    size_t n = 0;
    const pg_query_Node *const *opts = pg_query_ExplainStmt_options(s, &n);

    for (size_t i = 0; i < n; i++) {
        const pg_query_DefElem *d;
        const pg_query_Node *arg;

        if (pg_query_Node_node_case(opts[i]) != pg_query_Node_node_def_elem) {
            continue;
        }
        d = pg_query_Node_def_elem(opts[i]);
        if (!sv_eq_nocase(pg_query_DefElem_defname(d), "analyze")) {
            continue;
        }
        arg = pg_query_DefElem_arg(d);
        return arg == NULL || !arg_is_false(arg);
    }
    return 0;
}

/* Whether the parser's list of tables is complete for this kind of statement: either it names the
 * tables the statement works on (checked in tests/test_sql_check.c), or the statement touches none.
 * Kinds that reach tables without naming them (MERGE leaves its source out; DROP SCHEMA, GRANT ON
 * ALL TABLES, COMMENT, VACUUM, CREATE FUNCTION, DO...) and kinds this version does not know are not
 * on the list. */
static int tables_known(const pg_query_Node *node)
{
    switch (pg_query_Node_node_case(node)) {
    case pg_query_Node_node_select_stmt:
    case pg_query_Node_node_insert_stmt:
    case pg_query_Node_node_update_stmt:
    case pg_query_Node_node_delete_stmt:
    case pg_query_Node_node_copy_stmt:
    case pg_query_Node_node_explain_stmt:
    case pg_query_Node_node_prepare_stmt:
    case pg_query_Node_node_declare_cursor_stmt:
    case pg_query_Node_node_truncate_stmt:
    case pg_query_Node_node_create_stmt:
    case pg_query_Node_node_create_table_as_stmt:
    case pg_query_Node_node_index_stmt:
    case pg_query_Node_node_view_stmt:
    case pg_query_Node_node_lock_stmt:
    case pg_query_Node_node_refresh_mat_view_stmt:
    /* no table at all */
    case pg_query_Node_node_transaction_stmt:
    case pg_query_Node_node_variable_set_stmt:
    case pg_query_Node_node_variable_show_stmt:
    case pg_query_Node_node_execute_stmt:
    case pg_query_Node_node_deallocate_stmt:
    case pg_query_Node_node_discard_stmt:
    case pg_query_Node_node_fetch_stmt:
    case pg_query_Node_node_close_portal_stmt:
    case pg_query_Node_node_listen_stmt:
    case pg_query_Node_node_unlisten_stmt:
    case pg_query_Node_node_notify_stmt:
    case pg_query_Node_node_check_point_stmt:
    case pg_query_Node_node_constraints_set_stmt:
    case pg_query_Node_node_create_schema_stmt:
    case pg_query_Node_node_create_role_stmt:
    case pg_query_Node_node_alter_role_stmt:
    case pg_query_Node_node_alter_role_set_stmt:
    case pg_query_Node_node_drop_role_stmt:
    case pg_query_Node_node_create_domain_stmt:
    case pg_query_Node_node_create_enum_stmt:
    case pg_query_Node_node_create_range_stmt:
    case pg_query_Node_node_composite_type_stmt:
    case pg_query_Node_node_create_extension_stmt:
    case pg_query_Node_node_create_seq_stmt:
    case pg_query_Node_node_createdb_stmt:
    case pg_query_Node_node_dropdb_stmt:
    case pg_query_Node_node_create_table_space_stmt:
    case pg_query_Node_node_drop_table_space_stmt:
        return 1;
    case pg_query_Node_node_drop_stmt:
        return pg_query_DropStmt_remove_type(pg_query_Node_drop_stmt(node)) ==
               pg_query_OBJECT_TABLE;
    case pg_query_Node_node_alter_table_stmt:
        return pg_query_AlterTableStmt_objtype(pg_query_Node_alter_table_stmt(node)) ==
               pg_query_OBJECT_TABLE;
    default:
        return 0;
    }
}

static void classify_node(collector *c, const pg_query_Node *node, int depth);

/* Data-modifying CTEs run with the statement that carries them. */
static void visit_with(collector *c, const pg_query_WithClause *w, int depth)
{
    size_t n = 0;
    const pg_query_Node *const *ctes;

    if (w == NULL) {
        return;
    }
    ctes = pg_query_WithClause_ctes(w, &n);
    for (size_t i = 0; i < n; i++) {
        const pg_query_Node *q;

        if (pg_query_Node_node_case(ctes[i]) != pg_query_Node_node_common_table_expr) {
            continue;
        }
        q = pg_query_CommonTableExpr_ctequery(pg_query_Node_common_table_expr(ctes[i]));
        if (q != NULL) {
            classify_node(c, q, depth + 1);
        }
    }
}

static void classify_node(collector *c, const pg_query_Node *node, int depth)
{
    /* what this statement adds to every set of flags it gets: its tables are not all reported */
    uint32_t op = tables_known(node) ? 0 : SL_SQL_TABLES_UNSEEN;

#define ADD(f) add(c, (f) | op)

    if (depth > MAX_NESTING) {
        ADD(SL_SQL_NOT_READ_ONLY); /* too deep to follow: never read-only */
        return;
    }

    switch (pg_query_Node_node_case(node)) {
    /* ---- data ---- */
    case pg_query_Node_node_insert_stmt: {
        const pg_query_InsertStmt *s = pg_query_Node_insert_stmt(node);
        const pg_query_OnConflictClause *oc = pg_query_InsertStmt_on_conflict_clause(s);

        /* ON CONFLICT DO UPDATE changes rows that are there: for a rule it is an UPDATE */
        ADD(SL_SQL_NOT_READ_ONLY |
            (oc != NULL && pg_query_OnConflictClause_action(oc) == pg_query_ONCONFLICT_UPDATE
                 ? SL_SQL_UPDATE
                 : 0));
        visit_with(c, pg_query_InsertStmt_with_clause(s), depth);
        return;
    }
    case pg_query_Node_node_update_stmt: {
        const pg_query_UpdateStmt *s = pg_query_Node_update_stmt(node);

        ADD(SL_SQL_NOT_READ_ONLY | SL_SQL_UPDATE |
            (pg_query_UpdateStmt_has_where_clause(s) ? 0 : SL_SQL_UNBOUNDED_WRITE));
        visit_with(c, pg_query_UpdateStmt_with_clause(s), depth);
        return;
    }
    case pg_query_Node_node_delete_stmt: {
        const pg_query_DeleteStmt *s = pg_query_Node_delete_stmt(node);

        ADD(SL_SQL_NOT_READ_ONLY | SL_SQL_DELETE |
            (pg_query_DeleteStmt_has_where_clause(s) ? 0 : SL_SQL_UNBOUNDED_WRITE));
        visit_with(c, pg_query_DeleteStmt_with_clause(s), depth);
        return;
    }
    case pg_query_Node_node_merge_stmt: {
        const pg_query_MergeStmt *s = pg_query_Node_merge_stmt(node);
        size_t nwhen = 0;
        const pg_query_Node *const *when = pg_query_MergeStmt_merge_when_clauses(s, &nwhen);
        uint32_t flags = SL_SQL_NOT_READ_ONLY;

        /* a MERGE is what its WHEN clauses do: an UPDATE, a DELETE, or both */
        for (size_t i = 0; i < nwhen; i++) {
            if (pg_query_Node_node_case(when[i]) == pg_query_Node_node_merge_when_clause) {
                int32_t cmd =
                    pg_query_MergeWhenClause_command_type(pg_query_Node_merge_when_clause(when[i]));

                flags |= cmd == pg_query_CMD_UPDATE ? SL_SQL_UPDATE : 0;
                flags |= cmd == pg_query_CMD_DELETE ? SL_SQL_DELETE : 0;
            } else {
                flags |=
                    SL_SQL_UPDATE | SL_SQL_DELETE; /* not what was expected: assume the worst */
            }
        }
        ADD(flags);
        visit_with(c, pg_query_MergeStmt_with_clause(s), depth);
        return;
    }
    case pg_query_Node_node_select_stmt: {
        const pg_query_SelectStmt *s = pg_query_Node_select_stmt(node);

        ADD(select_flags(s, 0));
        visit_with(c, pg_query_SelectStmt_with_clause(s), depth);
        return;
    }
    case pg_query_Node_node_copy_stmt: {
        const pg_query_Node *q = pg_query_CopyStmt_query(pg_query_Node_copy_stmt(node));
        const pg_query_CopyStmt *cs = pg_query_Node_copy_stmt(node);

        /* a file on the server, or a program: not STDIN or STDOUT */
        ADD(SL_SQL_NOT_READ_ONLY |
            (pg_query_CopyStmt_is_program(cs) || pg_query_CopyStmt_filename(cs).size > 0
                 ? SL_SQL_DANGEROUS
                 : 0));
        if (q != NULL) {
            classify_node(c, q, depth + 1); /* COPY (DELETE ... RETURNING *) TO STDOUT */
        }
        return;
    }

    /* ---- statements that wrap another one ---- */
    case pg_query_Node_node_explain_stmt: {
        const pg_query_ExplainStmt *s = pg_query_Node_explain_stmt(node);
        const pg_query_Node *q = pg_query_ExplainStmt_query(s);

        ADD(0);
        if (q != NULL && explain_runs_query(s)) {
            classify_node(c, q, depth + 1);
        }
        return;
    }
    case pg_query_Node_node_prepare_stmt: {
        const pg_query_Node *q = pg_query_PrepareStmt_query(pg_query_Node_prepare_stmt(node));

        ADD(0);
        if (q != NULL) {
            classify_node(c, q, depth + 1);
        }
        return;
    }
    case pg_query_Node_node_declare_cursor_stmt: {
        const pg_query_Node *q =
            pg_query_DeclareCursorStmt_query(pg_query_Node_declare_cursor_stmt(node));

        ADD(0);
        if (q != NULL) {
            classify_node(c, q, depth + 1);
        }
        return;
    }

    /* ---- harmless ---- */
    case pg_query_Node_node_variable_show_stmt:
    case pg_query_Node_node_execute_stmt:
    case pg_query_Node_node_deallocate_stmt:
    case pg_query_Node_node_discard_stmt:
    case pg_query_Node_node_fetch_stmt:
    case pg_query_Node_node_close_portal_stmt:
        ADD(0);
        return;
    case pg_query_Node_node_variable_set_stmt: {
        const pg_query_VariableSetStmt *s = pg_query_Node_variable_set_stmt(node);

        upb_StringView nm = pg_query_VariableSetStmt_name(s);

        if (pg_query_VariableSetStmt_kind(s) == pg_query_VAR_RESET_ALL || set_is_harmless(nm)) {
            ADD(0);
        } else if (pg_query_VariableSetStmt_kind(s) != pg_query_VAR_RESET &&
                   (sv_eq_nocase(nm, "role") || sv_eq_nocase(nm, "session_authorization"))) {
            ADD(SL_SQL_NOT_READ_ONLY | SL_SQL_SET_SESSION); /* (SET ROLE and SET SESSION
                                                               AUTHORIZATION, LOCAL or not) */
        } else {
            ADD(SL_SQL_NOT_READ_ONLY);
        }
        return;
    }
    case pg_query_Node_node_transaction_stmt: {
        int kind = pg_query_TransactionStmt_kind(pg_query_Node_transaction_stmt(node));
        int two_phase = kind == pg_query_TRANS_STMT_PREPARE ||
                        kind == pg_query_TRANS_STMT_COMMIT_PREPARED ||
                        kind == pg_query_TRANS_STMT_ROLLBACK_PREPARED;

        ADD(two_phase ? SL_SQL_NOT_READ_ONLY : 0);
        return;
    }

    /* ---- code we cannot look into ---- */
    case pg_query_Node_node_do_stmt:
    case pg_query_Node_node_call_stmt:
        ADD(SL_SQL_PROCEDURAL | SL_SQL_NOT_READ_ONLY);
        return;

    /* ---- removal ---- */
    case pg_query_Node_node_truncate_stmt:
        ADD(SL_SQL_DDL | SL_SQL_TRUNCATE | SL_SQL_NOT_READ_ONLY);
        return;
    case pg_query_Node_node_drop_stmt:
    case pg_query_Node_node_drop_owned_stmt:
    case pg_query_Node_node_drop_role_stmt:
    case pg_query_Node_node_drop_subscription_stmt:
    case pg_query_Node_node_drop_table_space_stmt:
    case pg_query_Node_node_drop_user_mapping_stmt:
    case pg_query_Node_node_dropdb_stmt:
        ADD(SL_SQL_DDL | SL_SQL_DROP | SL_SQL_NOT_READ_ONLY);
        return;

    /* ---- schema, roles and privileges ---- */
    case pg_query_Node_node_alter_collation_stmt:
    case pg_query_Node_node_alter_database_refresh_coll_stmt:
    case pg_query_Node_node_alter_database_set_stmt:
    case pg_query_Node_node_alter_database_stmt:
    case pg_query_Node_node_alter_default_privileges_stmt:
    case pg_query_Node_node_alter_domain_stmt:
    case pg_query_Node_node_alter_enum_stmt:
    case pg_query_Node_node_alter_event_trig_stmt:
    case pg_query_Node_node_alter_extension_contents_stmt:
    case pg_query_Node_node_alter_extension_stmt:
    case pg_query_Node_node_alter_fdw_stmt:
    case pg_query_Node_node_alter_foreign_server_stmt:
    case pg_query_Node_node_alter_function_stmt:
    case pg_query_Node_node_alter_object_depends_stmt:
    case pg_query_Node_node_alter_object_schema_stmt:
    case pg_query_Node_node_alter_op_family_stmt:
    case pg_query_Node_node_alter_operator_stmt:
    case pg_query_Node_node_alter_owner_stmt:
    case pg_query_Node_node_alter_policy_stmt:
    case pg_query_Node_node_alter_publication_stmt:
    case pg_query_Node_node_alter_role_set_stmt:
    case pg_query_Node_node_alter_role_stmt:
    case pg_query_Node_node_alter_seq_stmt:
    case pg_query_Node_node_alter_stats_stmt:
    case pg_query_Node_node_alter_subscription_stmt:
    case pg_query_Node_node_alter_system_stmt:
    case pg_query_Node_node_alter_table_move_all_stmt:
    case pg_query_Node_node_alter_table_space_options_stmt:
    case pg_query_Node_node_alter_table_stmt:
    case pg_query_Node_node_alter_tsconfiguration_stmt:
    case pg_query_Node_node_alter_tsdictionary_stmt:
    case pg_query_Node_node_alter_type_stmt:
    case pg_query_Node_node_alter_user_mapping_stmt:
    case pg_query_Node_node_comment_stmt:
    case pg_query_Node_node_composite_type_stmt:
    case pg_query_Node_node_create_am_stmt:
    case pg_query_Node_node_create_cast_stmt:
    case pg_query_Node_node_create_conversion_stmt:
    case pg_query_Node_node_create_domain_stmt:
    case pg_query_Node_node_create_enum_stmt:
    case pg_query_Node_node_create_event_trig_stmt:
    case pg_query_Node_node_create_extension_stmt:
    case pg_query_Node_node_create_fdw_stmt:
    case pg_query_Node_node_create_foreign_server_stmt:
    case pg_query_Node_node_create_foreign_table_stmt:
    case pg_query_Node_node_create_function_stmt:
    case pg_query_Node_node_create_op_class_stmt:
    case pg_query_Node_node_create_op_family_stmt:
    case pg_query_Node_node_create_plang_stmt:
    case pg_query_Node_node_create_policy_stmt:
    case pg_query_Node_node_create_publication_stmt:
    case pg_query_Node_node_create_range_stmt:
    case pg_query_Node_node_create_role_stmt:
    case pg_query_Node_node_create_schema_stmt:
    case pg_query_Node_node_create_seq_stmt:
    case pg_query_Node_node_create_stats_stmt:
    case pg_query_Node_node_create_stmt:
    case pg_query_Node_node_create_subscription_stmt:
    case pg_query_Node_node_create_table_as_stmt:
    case pg_query_Node_node_create_table_space_stmt:
    case pg_query_Node_node_create_transform_stmt:
    case pg_query_Node_node_create_trig_stmt:
    case pg_query_Node_node_create_user_mapping_stmt:
    case pg_query_Node_node_createdb_stmt:
    case pg_query_Node_node_define_stmt:
    case pg_query_Node_node_grant_role_stmt:
    case pg_query_Node_node_grant_stmt:
    case pg_query_Node_node_import_foreign_schema_stmt:
    case pg_query_Node_node_index_stmt:
    case pg_query_Node_node_reassign_owned_stmt:
    case pg_query_Node_node_rename_stmt:
    case pg_query_Node_node_replica_identity_stmt:
    case pg_query_Node_node_rule_stmt:
    case pg_query_Node_node_sec_label_stmt:
    case pg_query_Node_node_view_stmt:
        ADD(SL_SQL_DDL | SL_SQL_NOT_READ_ONLY);
        return;

    /* ---- everything else, including kinds added by future PostgreSQL versions ---- */
    default:
        ADD(SL_SQL_NOT_READ_ONLY);
        return;
    }
#undef ADD
}

/* ---- tables ---- */

static char *dup_sv(upb_StringView sv)
{
    char *s = malloc(sv.size + 1);

    if (s != NULL) {
        if (sv.size > 0) {
            memcpy(s, sv.data, sv.size);
        }
        s[sv.size] = '\0';
    }
    return s;
}

static void free_tables(sl_sql_tables *t)
{
    for (size_t i = 0; i < t->count; i++) {
        free(t->items[i].schema);
        free(t->items[i].name);
    }
    for (size_t i = 0; i < t->nfuncs; i++) {
        free(t->funcs[i].schema);
        free(t->funcs[i].name);
    }
    free(t->items);
    free(t->funcs);
    memset(t, 0, sizeof *t);
}

/* ---- functions ----
 *
 * The parser's own summary leaves out the calls in a RETURNING list, in DECLARE CURSOR and in the
 * defaults of a table. The tree it parses is complete, so the calls are taken from the JSON of
 * the whole tree: every FuncCall, wherever it sits, starts with its name as a list of strings
 * ("funcname":[{"String":{"sval":"pg_catalog"}},{"String":{"sval":"pg_sleep"}}]). A string literal
 * of the SQL cannot make one up (its quotes are escaped in the JSON), and one that did could only
 * add a name to the list. What cannot be seen: a function body, a DO block, a view. */

static int add_func(sl_sql_tables *t, const char *schema, size_t sl, const char *name, size_t nl)
{
    sl_sql_table *n;

    for (size_t i = 0; i < t->nfuncs; i++) { /* once each */
        if (strlen(t->funcs[i].name) == nl && memcmp(t->funcs[i].name, name, nl) == 0 &&
            strlen(t->funcs[i].schema) == sl && memcmp(t->funcs[i].schema, schema, sl) == 0) {
            return 0;
        }
    }
    n = realloc(t->funcs, (t->nfuncs + 1) * sizeof *n);
    if (n == NULL) {
        return -1;
    }
    t->funcs = n;
    n = &t->funcs[t->nfuncs];
    n->schema = malloc(sl + 1);
    n->name = malloc(nl + 1);
    if (n->schema == NULL || n->name == NULL) {
        free(n->schema);
        free(n->name);
        return -1;
    }
    memcpy(n->schema, schema, sl);
    n->schema[sl] = '\0';
    memcpy(n->name, name, nl);
    n->name[nl] = '\0';
    t->nfuncs++;
    return 0;
}

/* One string of the JSON starting after its opening quote: its end (the closing quote), with the
 * escapes undone into out (at most cap-1 bytes). NULL when there is none or it does not fit. */
static const char *json_sval(const char *p, char *out, size_t cap)
{
    size_t n = 0;

    for (; *p != '\0' && *p != '"'; p++) {
        char ch = *p;

        if (ch == '\\') {
            p++;
            if (*p == '\0') {
                return NULL;
            }
            ch = *p == 'n' ? '\n' : *p == 't' ? '\t' : *p; /* the names that matter have none */
        }
        if (n + 1 >= cap) {
            return NULL;
        }
        out[n++] = ch;
    }
    out[n] = '\0';
    return *p == '"' ? p : NULL;
}

static int collect_functions(const char *sql, sl_sql_tables *out, char *err, size_t errcap)
{
    PgQueryParseResult r = pg_query_parse(sql);
    const char *p;
    int rc = 0;

    if (r.error != NULL || r.parse_tree == NULL) {
        snprintf(err, errcap, "cannot read the list of functions");
        pg_query_free_parse_result(r);
        return -1;
    }
    for (p = r.parse_tree; (p = strstr(p, "\"FuncCall\":{\"funcname\":[")) != NULL;) {
        char names[4][130];
        size_t nn = 0;

        p += strlen("\"FuncCall\":{\"funcname\":[");
        while (*p == '{') {
            const char *q = strstr(p, "\"sval\":\"");
            char one[130];

            if (q == NULL) {
                break;
            }
            q += strlen("\"sval\":\"");
            q = json_sval(q, one, sizeof one);
            if (q == NULL) {
                break;
            }
            if (nn < 4) {
                memcpy(names[nn++], one, sizeof one);
            }
            p = q;
            while (*p != '\0' && *p != '}') { /* the end of the String node, then of its wrapper */
                p++;
            }
            for (int close = 0; close < 2 && *p == '}'; close++) {
                p++;
            }
            if (*p == ',') {
                p++;
            }
        }
        if (nn > 0 &&
            add_func(out, nn >= 2 ? names[nn - 2] : "", nn >= 2 ? strlen(names[nn - 2]) : 0,
                     names[nn - 1], strlen(names[nn - 1])) != 0) {
            rc = -1;
            break;
        }
    }
    if (rc != 0) {
        snprintf(err, errcap, "out of memory");
    }
    pg_query_free_parse_result(r);
    return rc;
}

/* The tables the parser reports for one statement (text is not NUL terminated). */
static int summarize(const char *text, size_t len, sl_sql_tables *out, char *err, size_t errcap)
{
    char *sql = malloc(len + 1);
    PgQuerySummaryParseResult r;
    upb_Arena *arena;
    pg_query_SummaryResult *sr;
    const pg_query_SummaryResult_Table *const *tabs;
    size_t n = 0;

    memset(out, 0, sizeof *out);
    if (sql == NULL) {
        snprintf(err, errcap, "out of memory");
        return -1;
    }
    memcpy(sql, text, len);
    sql[len] = '\0';
    r = pg_query_summary(sql, 0, -1);
    if (r.error == NULL && collect_functions(sql, out, err, errcap) != 0) {
        free(sql);
        pg_query_free_summary_parse_result(r);
        return -1;
    }
    free(sql);
    if (r.error != NULL) {
        snprintf(err, errcap, "%s", r.error->message ? r.error->message : "parse error");
        pg_query_free_summary_parse_result(r);
        return -1;
    }

    arena = upb_Arena_New();
    sr = arena ? pg_query_SummaryResult_parse(r.summary.data, r.summary.len, arena) : NULL;
    if (sr == NULL) {
        if (arena) {
            upb_Arena_Free(arena);
        }
        pg_query_free_summary_parse_result(r);
        snprintf(err, errcap, "cannot read the list of tables");
        return -1;
    }
    tabs = pg_query_SummaryResult_tables(sr, &n);
    if (n > 0) {
        out->items = calloc(n, sizeof *out->items);
        if (out->items == NULL) {
            n = 0;
            snprintf(err, errcap, "out of memory");
            upb_Arena_Free(arena);
            pg_query_free_summary_parse_result(r);
            return -1;
        }
    }
    for (size_t i = 0; i < n; i++) {
        out->items[i].schema = dup_sv(pg_query_SummaryResult_Table_schema_name(tabs[i]));
        out->items[i].name = dup_sv(pg_query_SummaryResult_Table_table_name(tabs[i]));
        out->count++;
        if (out->items[i].schema == NULL || out->items[i].name == NULL) {
            free_tables(out);
            upb_Arena_Free(arena);
            pg_query_free_summary_parse_result(r);
            snprintf(err, errcap, "out of memory");
            return -1;
        }
    }
    upb_Arena_Free(arena);
    pg_query_free_summary_parse_result(r);
    return 0;
}

/* ---- strings that the server may read differently ---- */

/* sluice reads the SQL the way PostgreSQL does with its default settings. A client can change two
 * of them in the middle of a session (SET, set_config(), a role's own defaults), and then the
 * server cuts the text into strings elsewhere than sluice does, so that what sluice judged is not
 * what runs:
 *
 *   - standard_conforming_strings = off: inside 'plain' quotes a backslash escapes the next
 * character, so
 *     `\'` does not close the string. By default (on) it does.
 *   - client_encoding of a multi-byte kind (SJIS, BIG5, GBK...): the second byte of a character can
 * be 0x5c, a backslash, which then is no escape at all, and the quote after it closes the string.
 *
 * Both change where a string ends only when a quote comes right after a run of backslashes (the
 * quotes themselves can never be the second byte of a character). A string without such a quote is
 * read the same way whatever the settings. One with such a quote is "ambiguous" when:
 *   - it is a plain string and the run is odd (`'a\'`, `'a\\\'`): the two settings disagree; an
 * even run
 *     (`'C:\\'`) closes the string in both;
 *   - or the string holds a byte above 0x7f and the run is not empty: the backslash could be the
 * end of a character, which turns an even run into an odd one and the other way round. This covers
 * E'...' too, where a backslash escapes in every setting; without a high byte E'it\'s' is read
 * alike by all. */

typedef enum { AMBIG_NO, AMBIG_YES, AMBIG_UNKNOWN } ambig_result;

static int has_high_byte(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)s[i] >= 0x80) {
            return 1;
        }
    }
    return 0;
}

/* tok is a quoted string as the lexer cut it: '...', E'...' or U&'...' (not a dollar-quoted one).
 */
static int token_is_ambiguous(const char *tok, size_t len)
{
    int plain = tok[0] == '\'';
    int high = has_high_byte(tok, len);

    for (size_t i = 1; i < len; i++) {
        size_t run = 0;

        if (tok[i] != '\'') {
            continue;
        }
        while (run < i && tok[i - 1 - run] == '\\') {
            run++;
        }
        if (run > 0 && ((plain && run % 2 == 1) || high)) {
            return 1;
        }
    }
    return 0;
}

/* text is NUL terminated; len is its length. */
static ambig_result string_is_ambiguous(const char *text, size_t len)
{
    PgQueryScanResult r;
    upb_Arena *arena;
    pg_query_ScanResult *scan;
    const pg_query_ScanToken *const *tokens;
    ambig_result result = AMBIG_NO;
    size_t n = 0;

    if (memchr(text, '\\', len) == NULL) {
        return AMBIG_NO; /* no backslash anywhere: nothing to read two ways (and no cost for the
                            usual SQL) */
    }
    r = pg_query_scan(text);
    if (r.error != NULL) {
        pg_query_free_scan_result(r);
        return AMBIG_UNKNOWN; /* the parser will say what is wrong with it */
    }
    arena = upb_Arena_New();
    scan = arena ? pg_query_ScanResult_parse(r.pbuf.data, r.pbuf.len, arena) : NULL;
    if (scan == NULL) {
        result = AMBIG_UNKNOWN;
    } else {
        tokens = pg_query_ScanResult_tokens(scan, &n);
        for (size_t i = 0; i < n && result == AMBIG_NO; i++) {
            int32_t start = pg_query_ScanToken_start(tokens[i]);
            int32_t end = pg_query_ScanToken_end(tokens[i]);
            int kind = pg_query_ScanToken_token(tokens[i]);
            char first;

            if ((kind != pg_query_SCONST && kind != pg_query_USCONST) || start < 0 ||
                end <= start || (size_t)end > len) {
                continue;
            }
            first = text[start];
            if (first == '$') {
                continue; /* dollar-quoted: no escape of any kind in it */
            }
            if (token_is_ambiguous(text + start, (size_t)(end - start))) {
                result = AMBIG_YES;
            }
        }
    }
    if (arena) {
        upb_Arena_Free(arena);
    }
    pg_query_free_scan_result(r);
    return result;
}

/* ---- entry points ---- */

/* The table a DELETE or an UPDATE writes to, as written (schema and name), when it fits. */
static void name_relation(sl_sql_info *out, const pg_query_RangeVar *rv)
{
    if (rv != NULL) {
        upb_StringView sch = pg_query_RangeVar_schemaname(rv);
        upb_StringView rel = pg_query_RangeVar_relname(rv);

        if (sch.size < sizeof out->top_schema && rel.size < sizeof out->top_table && rel.size > 0) {
            if (sch.size > 0) { /* (data is NULL when there is no schema) */
                memcpy(out->top_schema, sch.data, sch.size);
            }
            memcpy(out->top_table, rel.data, rel.size);
        }
    }
}

/* The fingerprint of a message (16 hex digits), or "" when it cannot be had. */
static void fingerprint_of(const char *sql, size_t len, char out[17])
{
    char *copy = malloc(len + 1);
    PgQueryFingerprintResult fr;

    out[0] = '\0';
    if (copy == NULL) {
        return;
    }
    memcpy(copy, sql, len);
    copy[len] = '\0';
    fr = pg_query_fingerprint(copy);
    free(copy);
    if (fr.error == NULL && fr.fingerprint_str != NULL && strlen(fr.fingerprint_str) == 16) {
        memcpy(out, fr.fingerprint_str, 17);
    }
    pg_query_free_fingerprint_result(fr);
}

static int classify(const char *sql, size_t len, int want_tables, sl_sql_info *out, char *err,
                    size_t errcap)
{
    collector c;
    char *text;
    PgQueryProtobufParseResult r;
    upb_Arena *arena;
    pg_query_ParseResult *tree;
    const pg_query_RawStmt *const *stmts;
    size_t n = 0;
    sl_sql_tables *tables = NULL;
    uint8_t top_kind = 0;
    int top_returning = 0;

    memset(out, 0, sizeof *out);
    memset(&c, 0, sizeof c);
    allow_deep_statements();

    text = malloc(len + 1);
    if (text == NULL) {
        snprintf(err, errcap, "out of memory");
        return -1;
    }
    memcpy(text, sql, len);
    text[len] = '\0';
    if (string_is_ambiguous(text, len) == AMBIG_YES) {
        free(text);
        snprintf(err, errcap,
                 "a backslash inside a quoted string is read differently depending on "
                 "standard_conforming_strings and client_encoding");
        return -1;
    }
    r = pg_query_parse_protobuf(text);
    free(text);

    if (r.error != NULL) {
        snprintf(err, errcap, "%s", r.error->message ? r.error->message : "parse error");
        pg_query_free_protobuf_parse_result(r);
        return -1;
    }

    arena = upb_Arena_New();
    tree = arena
               ? pg_query_ParseResult_parse_ex(r.parse_tree.data, r.parse_tree.len, NULL,
                                               upb_DecodeOptions_MaxDepth(DECODE_MAX_DEPTH), arena)
               : NULL;
    pg_query_free_protobuf_parse_result(r);
    if (tree == NULL) {
        snprintf(err, errcap, "the statement is nested too deeply to be inspected");
        if (arena) {
            upb_Arena_Free(arena);
        }
        return -1;
    }

    stmts = pg_query_ParseResult_stmts(tree, &n);
    if (n == 1 && pg_query_RawStmt_stmt(stmts[0]) != NULL) {
        const pg_query_Node *top = pg_query_RawStmt_stmt(stmts[0]);

        if (pg_query_Node_node_case(top) == pg_query_Node_node_delete_stmt) {
            top_kind = 'D';
            top_returning =
                pg_query_DeleteStmt_has_returning_clause(pg_query_Node_delete_stmt(top)) != 0;
            name_relation(out, pg_query_DeleteStmt_relation(pg_query_Node_delete_stmt(top)));
        } else if (pg_query_Node_node_case(top) == pg_query_Node_node_update_stmt) {
            top_kind = 'U';
            top_returning =
                pg_query_UpdateStmt_has_returning_clause(pg_query_Node_update_stmt(top)) != 0;
            name_relation(out, pg_query_UpdateStmt_relation(pg_query_Node_update_stmt(top)));
        } else if (pg_query_Node_node_case(top) == pg_query_Node_node_insert_stmt &&
                   pg_query_InsertStmt_on_conflict_clause(pg_query_Node_insert_stmt(top)) != NULL &&
                   pg_query_OnConflictClause_action(pg_query_InsertStmt_on_conflict_clause(
                       pg_query_Node_insert_stmt(top))) == pg_query_ONCONFLICT_UPDATE) {
            top_kind = 'I'; /* INSERT ... ON CONFLICT DO UPDATE */
            top_returning =
                pg_query_InsertStmt_has_returning_clause(pg_query_Node_insert_stmt(top)) != 0;
        } else if (pg_query_Node_node_case(top) == pg_query_Node_node_merge_stmt) {
            top_kind = 'M';
            top_returning =
                pg_query_MergeStmt_has_returning_clause(pg_query_Node_merge_stmt(top)) != 0;
        } else if (pg_query_Node_node_case(top) == pg_query_Node_node_truncate_stmt) {
            top_kind = 'T';
            top_returning = 1; /* nothing to add: it is run as it is */
        } else if (pg_query_Node_node_case(top) == pg_query_Node_node_drop_stmt) {
            top_kind =
                'R'; /* DROP TABLE, VIEW, INDEX...: not DROP DATABASE, which cannot be undone */
            top_returning = 1;
        }
    }
    if (want_tables) {
        fingerprint_of(sql, len, out->fingerprint);
        tables = calloc(n ? n : 1, sizeof *tables);
        if (tables == NULL) {
            c.oom = 1;
        }
    }
    for (size_t i = 0; i < n && !c.oom; i++) {
        const pg_query_Node *node = pg_query_RawStmt_stmt(stmts[i]);

        c.cur_group = i;
        if (node != NULL) {
            classify_node(&c, node, 0);
        }
        if (want_tables && !c.oom) {
            /* a message with one statement is summarised whole; otherwise each statement on its own
             */
            size_t from = 0;
            size_t span = len;

            if (n > 1) {
                int32_t loc = pg_query_RawStmt_stmt_location(stmts[i]);
                int32_t slen = pg_query_RawStmt_stmt_len(stmts[i]);

                if (loc < 0 || (size_t)loc > len || (slen < 0) ||
                    (slen != 0 && (size_t)loc + (size_t)slen > len)) {
                    snprintf(err, errcap, "inconsistent statement boundaries");
                    c.oom = 2;
                    break;
                }
                from = (size_t)loc;
                span = slen == 0 ? len - from : (size_t)slen;
            }
            if (summarize(sql + from, span, &tables[i], err, errcap) != 0) {
                c.oom = 2; /* the message is already in err */
                break;
            }
        }
    }
    upb_Arena_Free(arena);

    if (c.oom) {
        if (tables != NULL) {
            for (size_t i = 0; i < n; i++) {
                free_tables(&tables[i]);
            }
            free(tables);
        }
        free(c.flags);
        free(c.group);
        if (c.oom == 1) {
            snprintf(err, errcap, "out of memory");
        }
        return -1;
    }
    if (n > 1) {
        for (size_t i = 0; i < c.count; i++) {
            c.flags[i] |= SL_SQL_MULTI;
        }
    }
    out->flags = c.flags;
    out->group = c.group;
    out->count = c.count;
    out->top_level = n;
    out->top_kind = top_kind;
    out->top_returning = top_returning;
    out->tables = tables;
    return 0;
}

int sl_sql_classify(const char *sql, size_t len, sl_sql_info *out, char *err, size_t errcap)
{
    return classify(sql, len, 0, out, err, errcap);
}

int sl_sql_classify_with_tables(const char *sql, size_t len, sl_sql_info *out, char *err,
                                size_t errcap)
{
    return classify(sql, len, 1, out, err, errcap);
}

/* ---- logging without the values ---- */

void sl_sql_scrub_error(char *err)
{
    char *at = strstr(err, " at or near");

    if (at != NULL) {
        *at = '\0';
    }
}

size_t sl_sql_statement_end(const char *sql, size_t len)
{
    char *text = malloc(len + 1);
    PgQueryScanResult r;
    upb_Arena *arena;
    pg_query_ScanResult *scan;
    const pg_query_ScanToken *const *tokens;
    size_t n = 0;
    size_t end = 0;

    if (text == NULL) {
        return 0;
    }
    memcpy(text, sql, len);
    text[len] = '\0';
    r = pg_query_scan(text);
    free(text);
    if (r.error != NULL) {
        pg_query_free_scan_result(r);
        return 0;
    }
    arena = upb_Arena_New();
    scan = arena ? pg_query_ScanResult_parse(r.pbuf.data, r.pbuf.len, arena) : NULL;
    if (scan != NULL) {
        tokens = pg_query_ScanResult_tokens(scan, &n);
        for (size_t i = 0; i < n; i++) {
            int kind = pg_query_ScanToken_token(tokens[i]);
            int32_t e = pg_query_ScanToken_end(tokens[i]);

            if (kind == pg_query_SQL_COMMENT || kind == pg_query_C_COMMENT || kind == ';') {
                continue;
            }
            if (e > 0 && (size_t)e <= len && (size_t)e > end) {
                end = (size_t)e;
            }
        }
    }
    if (arena) {
        upb_Arena_Free(arena);
    }
    pg_query_free_scan_result(r);
    return end;
}

/* True when the lexer finds in text no constant (string, number, bit or hex string) and no comment:
 * nothing where a value, or a note somebody wrote next to it, could be hiding. */
static int text_is_free_of_values(const char *text)
{
    PgQueryScanResult r = pg_query_scan(text);
    upb_Arena *arena;
    pg_query_ScanResult *scan;
    const pg_query_ScanToken *const *tokens;
    size_t n = 0;
    int clean = 1;

    if (r.error != NULL) {
        pg_query_free_scan_result(r);
        return 0;
    }
    arena = upb_Arena_New();
    scan = arena ? pg_query_ScanResult_parse(r.pbuf.data, r.pbuf.len, arena) : NULL;
    if (scan == NULL) {
        clean = 0;
    } else {
        tokens = pg_query_ScanResult_tokens(scan, &n);
        for (size_t i = 0; i < n && clean; i++) {
            switch (pg_query_ScanToken_token(tokens[i])) {
            case pg_query_SCONST:
            case pg_query_USCONST:
            case pg_query_BCONST:
            case pg_query_XCONST:
            case pg_query_ICONST:
            case pg_query_FCONST:
            case pg_query_SQL_COMMENT:
            case pg_query_C_COMMENT:
                clean = 0;
                break;
            default:
                break;
            }
        }
    }
    if (arena) {
        upb_Arena_Free(arena);
    }
    pg_query_free_scan_result(r);
    return clean;
}

int sl_sql_redact(const char *sql, size_t len, sl_sql_redacted *out, char *err, size_t errcap)
{
    char *text = malloc(len + 1);
    PgQueryFingerprintResult f;
    PgQueryNormalizeResult nr;

    memset(out, 0, sizeof *out);
    if (text == NULL) {
        snprintf(err, errcap, "out of memory");
        return -1;
    }
    memcpy(text, sql, len);
    text[len] = '\0';

    f = pg_query_fingerprint(text);
    if (f.error != NULL) {
        snprintf(err, errcap, "%s", f.error->message ? f.error->message : "parse error");
        sl_sql_scrub_error(err);
        pg_query_free_fingerprint_result(f);
        free(text);
        return -1;
    }
    snprintf(out->fingerprint, sizeof out->fingerprint, "%s",
             f.fingerprint_str ? f.fingerprint_str : "");
    pg_query_free_fingerprint_result(f);

    nr = pg_query_normalize(text);
    free(text);
    if (nr.error == NULL && nr.normalized_query != NULL &&
        text_is_free_of_values(nr.normalized_query)) {
        size_t n = strlen(nr.normalized_query);

        out->text = malloc(n + 1);
        if (out->text != NULL) {
            memcpy(out->text, nr.normalized_query, n + 1);
        }
    }
    pg_query_free_normalize_result(nr);
    return 0;
}

void sl_sql_redacted_free(sl_sql_redacted *r)
{
    free(r->text);
    memset(r, 0, sizeof *r);
}

void sl_sql_info_free(sl_sql_info *info)
{
    if (info->tables != NULL) {
        for (size_t i = 0; i < info->top_level; i++) {
            free_tables(&info->tables[i]);
        }
        free(info->tables);
    }
    free(info->flags);
    free(info->group);
    memset(info, 0, sizeof *info);
}
