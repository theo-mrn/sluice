#include "extstate.h"

#include <stdlib.h>
#include <string.h>

sl_ext *sl_ext_new(void)
{
    return calloc(1, sizeof(sl_ext));
}

int sl_ext_name(const uint8_t *p, size_t avail, const char **name)
{
    size_t n = avail < SL_EXT_NAME_MAX + 1 ? avail : SL_EXT_NAME_MAX + 1;
    const uint8_t *nul = n > 0 ? memchr(p, 0, n) : NULL;

    if (nul == NULL) {
        return SL_EXT_TOO_LONG;
    }
    *name = (const char *)p;
    return (int)(nul - p);
}

/* ---- the tables ---- */

static void entry_free(sl_ext_entry *x)
{
    if (x != NULL) {
        free(x->sql);
        free(x);
    }
}

static void clear(sl_ext_entry **tab, size_t *n)
{
    for (size_t i = 0; i < *n; i++) {
        entry_free(tab[i]);
    }
    *n = 0;
}

void sl_ext_free(sl_ext *e)
{
    if (e == NULL) {
        return;
    }
    clear(e->stmts, &e->nstmts);
    clear(e->portals, &e->nportals);
    entry_free(e->unnamed_stmt);
    entry_free(e->unnamed_portal);
    free(e);
}

static void copy_text(char *dst, size_t cap, const char *src)
{
    size_t n = src != NULL ? strlen(src) : 0;

    if (n >= cap) {
        n = cap - 1;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

static sl_ext_entry *entry_new(const char *name, size_t len, const char *rule, const char *message,
                               unsigned long long over_rows, int rewritten, int side_effects,
                               int kind, int limit, int via, const char *sql, size_t sql_len)
{
    sl_ext_entry *x = calloc(1, sizeof *x);

    if (x == NULL) {
        return NULL;
    }
    if (sql_len > SL_EXT_SQL_MAX) {
        sql_len = SL_EXT_SQL_MAX;
    }
    x->sql = malloc(sql_len + 1);
    if (x->sql == NULL) {
        free(x);
        return NULL;
    }
    if (sql_len > 0) {
        memcpy(x->sql, sql, sql_len);
    }
    x->sql[sql_len] = '\0';
    x->sql_len = sql_len;
    memcpy(x->name, name, len);
    x->name[len] = '\0';
    copy_text(x->rule, sizeof x->rule, rule);
    copy_text(x->message, sizeof x->message, message);
    x->over_rows = over_rows;
    x->rewritten = rewritten;
    x->side_effects = side_effects;
    x->kind = kind;
    x->limit = limit;
    x->via = via;
    return x;
}

static sl_ext_entry *entry_copy(const sl_ext_entry *o, const char *name, size_t len)
{
    sl_ext_entry *x = entry_new(name, len, o->rule, o->message, o->over_rows, o->rewritten,
                                o->side_effects, o->kind, o->limit, o->via, o->sql, o->sql_len);

    if (x != NULL) {
        x->journal = o->journal;
        memcpy(x->schema, o->schema, sizeof x->schema);
        memcpy(x->table, o->table, sizeof x->table);
    }
    return x;
}

static sl_ext_entry **find(sl_ext_entry **tab, size_t n, const char *name, size_t len)
{
    for (size_t i = 0; i < n; i++) {
        if (strlen(tab[i]->name) == len && memcmp(tab[i]->name, name, len) == 0) {
            return &tab[i];
        }
    }
    return NULL;
}

static int put_named(sl_ext_entry **tab, size_t *n, sl_ext_entry *x)
{
    if (find(tab, *n, x->name, strlen(x->name)) != NULL) {
        entry_free(x); /* sticky: the first one stays */
        return SL_EXT_OK;
    }
    if (*n >= SL_EXT_GUARDED_MAX) {
        entry_free(x);
        return SL_EXT_FULL;
    }
    tab[(*n)++] = x;
    return SL_EXT_OK;
}

static void drop(sl_ext_entry **tab, size_t *n, const char *name, size_t len)
{
    sl_ext_entry **x = find(tab, *n, name, len);

    if (x != NULL) {
        entry_free(*x);
        *x = tab[*n - 1];
        (*n)--;
    }
}

int sl_ext_parse_guarded(sl_ext *e, const char *name, size_t len, const sl_ext_guard *g)
{
    sl_ext_entry *x;

    if (len > SL_EXT_NAME_MAX) {
        return SL_EXT_TOO_LONG;
    }
    if (len > 0 && find(e->stmts, e->nstmts, name, len) != NULL) {
        return SL_EXT_OK;
    }
    x = entry_new(name, len, g->rule, g->message, g->over_rows, g->rewritten, g->side_effects,
                  g->kind, g->limit, g->via, g->sql, g->sql_len);
    if (x == NULL) {
        return SL_EXT_NOMEM;
    }
    x->journal = g->journal;
    copy_text(x->schema, sizeof x->schema, g->schema);
    copy_text(x->table, sizeof x->table, g->table);
    if (len == 0) {
        entry_free(e->unnamed_stmt);
        e->unnamed_stmt = x;
        return SL_EXT_OK;
    }
    return put_named(e->stmts, &e->nstmts, x);
}

void sl_ext_parse_plain(sl_ext *e, const char *name, size_t len)
{
    (void)name;
    if (len == 0) {
        entry_free(e->unnamed_stmt); /* the server drops the previous unnamed statement */
        e->unnamed_stmt = NULL;
    }
}

const sl_ext_entry *sl_ext_stmt_guard(const sl_ext *e, const char *name, size_t len)
{
    sl_ext_entry **x;

    if (len == 0) {
        return e->unnamed_stmt;
    }
    x = find((sl_ext_entry **)e->stmts, e->nstmts, name, len);
    return x != NULL ? *x : NULL;
}

void sl_ext_stmt_close(sl_ext *e, const char *name, size_t len)
{
    if (len == 0) {
        entry_free(e->unnamed_stmt);
        e->unnamed_stmt = NULL;
    } else {
        drop(e->stmts, &e->nstmts, name, len);
    }
}

int sl_ext_bind(sl_ext *e, const char *portal, size_t len, const sl_ext_entry *stmt)
{
    sl_ext_entry *x;

    if (len > SL_EXT_NAME_MAX) {
        return SL_EXT_TOO_LONG;
    }
    if (len == 0) {
        entry_free(e->unnamed_portal); /* replaced by every Bind */
        e->unnamed_portal = NULL;
        if (stmt == NULL) {
            return SL_EXT_OK;
        }
        e->unnamed_portal = entry_copy(stmt, portal, len);
        return e->unnamed_portal != NULL ? SL_EXT_OK : SL_EXT_NOMEM;
    }
    if (stmt == NULL || find(e->portals, e->nportals, portal, len) != NULL) {
        return SL_EXT_OK; /* a name keeps the guard it first got */
    }
    x = entry_copy(stmt, portal, len);
    return x == NULL ? SL_EXT_NOMEM : put_named(e->portals, &e->nportals, x);
}

const sl_ext_entry *sl_ext_portal_guard(const sl_ext *e, const char *name, size_t len)
{
    sl_ext_entry **x;

    if (len == 0) {
        return e->unnamed_portal;
    }
    x = find((sl_ext_entry **)e->portals, e->nportals, name, len);
    return x != NULL ? *x : NULL;
}

void sl_ext_portal_close(sl_ext *e, const char *name, size_t len)
{
    if (len == 0) {
        entry_free(e->unnamed_portal);
        e->unnamed_portal = NULL;
    } else {
        drop(e->portals, &e->nportals, name, len);
    }
}

void sl_ext_portals_end(sl_ext *e)
{
    clear(e->portals, &e->nportals);
    entry_free(e->unnamed_portal);
    e->unnamed_portal = NULL;
}

size_t sl_ext_guarded(const sl_ext *e)
{
    return e->nstmts + e->nportals + (e->unnamed_stmt != NULL) + (e->unnamed_portal != NULL);
}

/* ---- the queue ---- */

static sl_ext_slot *slot_at(sl_ext *e, size_t i)
{
    return &e->slots[(e->head + i) % SL_EXT_SLOTS_MAX];
}

static int is_barrier(int kind)
{
    return kind == SL_EXT_SYNC || kind == SL_EXT_SIMPLE;
}

static int is_guarded(int kind)
{
    return kind == SL_EXT_ROWDESC_G || kind == SL_EXT_EXEC_G;
}

int sl_ext_expect(sl_ext *e, int kind)
{
    sl_ext_slot *tail = e->len > 0 ? slot_at(e, e->len - 1) : NULL;

    if (tail != NULL && tail->kind == kind &&
        (kind == SL_EXT_ROWDESC || kind == SL_EXT_EXEC || kind == SL_EXT_EXEC_M) &&
        tail->count < UINT32_MAX) {
        tail->count++;
        return SL_EXT_OK;
    }
    if (e->len >= SL_EXT_SLOTS_MAX) {
        return SL_EXT_FULL;
    }
    tail = slot_at(e, e->len);
    tail->kind = (uint8_t)kind;
    tail->count = 1;
    e->len++;
    return SL_EXT_OK;
}

static void pop_front(sl_ext *e)
{
    sl_ext_slot *f = slot_at(e, 0);

    e->desc_seen = 0;
    if (f->count > 1) {
        f->count--;
        return;
    }
    e->head = (e->head + 1) % SL_EXT_SLOTS_MAX;
    e->len--;
}

/* Is a guarded answer owed before the first barrier? */
static int guarded_before_barrier(sl_ext *e)
{
    for (size_t i = 0; i < e->len; i++) {
        int k = slot_at(e, i)->kind;

        if (is_barrier(k)) {
            return 0;
        }
        if (is_guarded(k)) {
            return 1;
        }
    }
    return 0;
}

static int answer_z(sl_ext *e)
{
    int flags = 0;
    size_t barrier = e->len;

    for (size_t i = 0; i < e->len; i++) {
        if (is_barrier(slot_at(e, i)->kind)) {
            barrier = i;
            break;
        }
    }
    if (barrier == e->len) {
        e->skipping = 0;
        return 0; /* the login's, or one of sluice's own */
    }
    if (!e->skipping && guarded_before_barrier(e)) {
        flags |= SL_EXT_SKIPPED;
    }
    for (size_t i = 0; i <= barrier; i++) {
        pop_front(e);
    }
    e->skipping = 0;
    e->desc_seen = 0;
    return flags;
}

static int fail_cycle(sl_ext *e)
{
    int flags = guarded_before_barrier(e) ? SL_EXT_SKIPPED : 0;

    e->skipping = 1;
    e->desc_seen = 0;
    return flags;
}

int sl_ext_answer(sl_ext *e, uint8_t type)
{
    int kind;

    if (type == 'Z') {
        return answer_z(e);
    }
    if (e->skipping) {
        return 0;
    }
    if (type == 'E') {
        return fail_cycle(e);
    }
    kind = e->len > 0 ? slot_at(e, 0)->kind : -1;
    if (kind < 0 || is_barrier(kind)) {
        return 0; /* an answer of the login, of a Query, or one that is not tracked */
    }
    switch (type) {
    case 't':
        if (kind != SL_EXT_PARAMS) {
            return fail_cycle(e);
        }
        pop_front(e);
        return 0;
    case 'T':
    case 'n':
        if (kind == SL_EXT_EXEC_G) {
            return 0; /* the RowDescription (or NoData) of the Describe sluice put before the
                         Execute */
        }
        if (kind == SL_EXT_EXEC_M) {
            if (e->desc_seen) {
                return fail_cycle(e); /* a second one: not what was expected */
            }
            e->desc_seen = 1;
            return SL_EXT_OURS;
        }
        if (kind != SL_EXT_ROWDESC && kind != SL_EXT_ROWDESC_G) {
            return fail_cycle(e);
        }
        pop_front(e);
        return kind == SL_EXT_ROWDESC_G && type == 'T' ? SL_EXT_TO_NODATA : 0;
    case 'C':
    case 'I':
    case 's':
        if (kind == SL_EXT_EXEC_M && !e->desc_seen) {
            return fail_cycle(e); /* the Describe in front of it was not answered */
        }
        if (kind != SL_EXT_EXEC && kind != SL_EXT_EXEC_G && kind != SL_EXT_EXEC_M) {
            return fail_cycle(e);
        }
        pop_front(e);
        return 0;
    default:
        return 0;
    }
}

int sl_ext_front_guarded_exec(const sl_ext *e)
{
    return !e->skipping && e->len > 0 && e->slots[e->head].kind == SL_EXT_EXEC_G;
}

int sl_ext_front_guarded_rowdesc(const sl_ext *e)
{
    return !e->skipping && e->len > 0 && e->slots[e->head].kind == SL_EXT_ROWDESC_G;
}

int sl_ext_guard_pending(const sl_ext *e)
{
    for (size_t i = 0; i < e->len; i++) {
        if (is_guarded(e->slots[(e->head + i) % SL_EXT_SLOTS_MAX].kind)) {
            return 1;
        }
    }
    return 0;
}

int sl_ext_in_step(const sl_ext *e)
{
    return !e->skipping;
}
