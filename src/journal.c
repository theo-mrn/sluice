#include "journal.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "json.h"
#include "pg_proto.h"

struct sl_journal {
    char *path;
    int fd;
    unsigned long long size;
    unsigned long long max;
};

/* A literal, whatever its length: the length is not written by hand. */
static int lit(sl_buf *b, const char *s)
{
    return sl_buf_append(b, s, strlen(s));
}

static int utf8_ok(const uint8_t *s, size_t n)
{
    size_t i = 0;

    while (i < n) {
        uint8_t c = s[i];
        size_t need;
        uint32_t cp;

        if (c == 0) {
            return 0; /* a NUL cannot be in a text value; never in what is written */
        }
        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) {
            need = 1;
            cp = c & 0x1f;
        } else if (c >= 0xe0 && c <= 0xef) {
            need = 2;
            cp = c & 0x0f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            need = 3;
            cp = c & 0x07;
        } else {
            return 0;
        }
        if (n - i - 1 < need) {
            return 0;
        }
        for (size_t k = 1; k <= need; k++) {
            if ((s[i + k] & 0xc0) != 0x80) {
                return 0;
            }
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((need == 2 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) ||
            (need == 3 && (cp < 0x10000 || cp > 0x10ffff))) {
            return 0;
        }
        i += need + 1;
    }
    return 1;
}

static int str(sl_buf *o, const char *key, const void *v, size_t n)
{
    return sl_buf_append(o, key, strlen(key)) != 0 || sl_json_append_string(o, v, n) != 0 ? -1 : 0;
}

static int cstr(sl_buf *o, const char *key, const char *v)
{
    return str(o, key, v != NULL ? v : "", v != NULL ? strlen(v) : 0);
}

static int num(sl_buf *o, const char *key, unsigned long long v)
{
    char t[40];

    snprintf(t, sizeof t, "%s%llu", key, v);
    return sl_buf_append(o, t, strlen(t));
}

/* The columns and the rows, if they are all there and can be written as they are. Writes
 * `"columns":[...],"data":[...]` and returns 0; or sets *why and writes empty lists. */
static int rows_json(const sl_journal_entry *e, sl_buf *o, const char **why)
{
    size_t pos = 0;
    unsigned n;
    sl_buf cols;
    sl_buf data;
    sl_buf fresh; /* an UPDATE: the new rows, the old ones are in data */
    unsigned half;
    int upd = e->update;
    int rc = -1;
    size_t start = sl_buf_len(o);
    size_t rows = 0;

    (void)start;
    *why = NULL;
    sl_buf_init(&cols);
    sl_buf_init(&data);
    sl_buf_init(&fresh);
    if (e->desc == NULL || e->data == NULL) {
        *why = e->incomplete != NULL ? e->incomplete : "the rows were not kept";
        goto empty;
    }
    if (e->desc_len < 2) {
        *why = "the description of the rows is not readable";
        goto empty;
    }
    n = (unsigned)((e->desc[0] << 8) | e->desc[1]);
    if (upd && (n == 0 || (n & 1) != 0)) {
        *why = "the rows of an UPDATE are not the old and the new row side by side";
        goto empty;
    }
    half = upd ? n / 2 : n;
    pos = 2;
    if (lit(&cols, "[") != 0) {
        goto fail;
    }
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *nul = pos < e->desc_len ? memchr(e->desc + pos, 0, e->desc_len - pos) : NULL;

        if (nul == NULL || e->desc_len - (size_t)(nul - e->desc) - 1 < 18 ||
            !utf8_ok(e->desc + pos, (size_t)(nul - (e->desc + pos)))) {
            *why = "the description of the rows is not readable";
            goto empty;
        }
        if (i < half &&
            ((i > 0 && lit(&cols, ",") != 0) ||
             sl_json_append_string(&cols, e->desc + pos, (size_t)(nul - (e->desc + pos))) != 0)) {
            goto fail;
        }
        pos = (size_t)(nul - e->desc) + 1 + 18;
    }
    if (pos != e->desc_len || lit(&cols, "]") != 0) {
        *why = "the description of the rows is not readable";
        goto empty;
    }
    if (lit(&data, "[") != 0 || (upd && lit(&fresh, "[") != 0)) {
        goto fail;
    }
    pos = 0;
    while (pos < e->data_len) {
        uint32_t l;
        const uint8_t *r;
        size_t rp = 2;
        unsigned fields;

        if (e->data_len - pos < 4) {
            *why = "the rows are cut short";
            goto empty;
        }
        l = sl_pg_get_be32(e->data + pos);
        pos += 4;
        if (l > e->data_len - pos || l < 2) {
            *why = "the rows are cut short";
            goto empty;
        }
        r = e->data + pos;
        pos += l;
        fields = (unsigned)((r[0] << 8) | r[1]);
        if (fields != n) {
            *why = "a row does not have the columns it should";
            goto empty;
        }
        if ((rows > 0 && (lit(&data, ",") != 0 || (upd && lit(&fresh, ",") != 0))) ||
            lit(&data, "[") != 0 || (upd && lit(&fresh, "[") != 0)) {
            goto fail;
        }
        for (unsigned f = 0; f < fields; f++) {
            int32_t fl;
            sl_buf *dst = upd && f >= half ? &fresh : &data;
            unsigned at = upd && f >= half ? f - half : f;

            if (l - rp < 4) {
                *why = "a row is cut short";
                goto empty;
            }
            fl = (int32_t)sl_pg_get_be32(r + rp);
            rp += 4;
            if (at > 0 && lit(dst, ",") != 0) {
                goto fail;
            }
            if (fl == -1) {
                if (lit(dst, "null") != 0) {
                    goto fail;
                }
                continue;
            }
            if (fl < 0 || (size_t)fl > l - rp) {
                *why = "a row is cut short";
                goto empty;
            }
            if (!utf8_ok(r + rp, (size_t)fl)) {
                *why = "a value is not text that can be written as it is (not valid UTF-8)";
                goto empty;
            }
            if (sl_json_append_string(dst, r + rp, (size_t)fl) != 0) {
                goto fail;
            }
            rp += (size_t)fl;
        }
        if (rp != l || lit(&data, "]") != 0 || (upd && lit(&fresh, "]") != 0)) {
            *why = "a row is cut short";
            goto empty;
        }
        rows++;
    }
    if (lit(&data, "]") != 0 || (upd && lit(&fresh, "]") != 0)) {
        goto fail;
    }
    if (rows != e->nrows || rows != e->rows) {
        *why = e->incomplete != NULL ? e->incomplete : "not every row was kept";
    } else if (e->incomplete != NULL) {
        *why = e->incomplete;
    }
    if (lit(o, "\"columns\":") != 0 ||
        sl_buf_append(o, sl_buf_data(&cols), sl_buf_len(&cols)) != 0 || lit(o, ",\"data\":") != 0 ||
        sl_buf_append(o, sl_buf_data(&data), sl_buf_len(&data)) != 0) {
        goto fail;
    }
    if (upd && (lit(o, ",\"new\":") != 0 ||
                sl_buf_append(o, sl_buf_data(&fresh), sl_buf_len(&fresh)) != 0)) {
        goto fail;
    }
    rc = 0;
    goto done;
empty:
    if (lit(o, upd ? "\"columns\":[],\"data\":[],\"new\":[]" : "\"columns\":[],\"data\":[]") != 0) {
        goto fail;
    }
    rc = 0;
    goto done;
fail:
    rc = -1;
done:
    sl_buf_free(&cols);
    sl_buf_free(&data);
    sl_buf_free(&fresh);
    return rc;
}

int sl_journal_format(const sl_journal_entry *e, const char id[SL_JOURNAL_ID_LEN + 1],
                      long long unix_s, sl_buf *out)
{
    struct tm tm;
    time_t t = (time_t)unix_s;
    char ts[32];
    const char *why = NULL;
    sl_buf body;
    int bad = 0;

    gmtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
    sl_buf_init(&body);
    if (rows_json(e, &body, &why) != 0) {
        sl_buf_free(&body);
        return -1;
    }
    bad |= lit(out, "{\"id\":\"") != 0 || sl_buf_append(out, id, SL_JOURNAL_ID_LEN) != 0 ||
           lit(out, "\",\"ts\":\"") != 0 || sl_buf_append(out, ts, strlen(ts)) != 0 ||
           lit(out, "\"") != 0;
    bad |= str(out, ",\"user\":", e->user, e->user_len) != 0;
    bad |= str(out, ",\"database\":", e->database, e->database_len) != 0;
    bad |= cstr(out, ",\"rule\":", e->rule) != 0;
    bad |= cstr(out, ",\"protocol\":", e->protocol) != 0;
    bad |= cstr(out, ",\"kind\":", e->update ? "update" : "delete") != 0;
    bad |= str(out, ",\"sql\":", e->sql, e->sql_len) != 0;
    bad |= cstr(out, ",\"schema\":", e->schema) != 0;
    bad |= cstr(out, ",\"table\":", e->table) != 0;
    bad |= cstr(out, ",\"tag\":", e->tag) != 0;
    bad |= num(out, ",\"rows\":", e->rows) != 0;
    {
        const char *c = why == NULL ? ",\"complete\":true" : ",\"complete\":false";

        bad |= sl_buf_append(out, c, strlen(c)) != 0;
    }
    if (why != NULL) {
        bad |= cstr(out, ",\"incomplete\":", why) != 0;
    }
    bad |= lit(out, ",") != 0 || sl_buf_append(out, sl_buf_data(&body), sl_buf_len(&body)) != 0;
    {
        const char *c =
            e->side_known ? ",\"side_known\":true,\"side\":[" : ",\"side_known\":false,\"side\":[";

        bad |= sl_buf_append(out, c, strlen(c)) != 0;
    }
    for (size_t i = 0; i < e->nside; i++) {
        bad |= (i > 0 && lit(out, ",") != 0);
        bad |= str(out, "{\"table\":", e->side[i].table, strlen(e->side[i].table)) != 0;
        bad |= num(out, ",\"inserted\":", e->side[i].inserted) != 0;
        bad |= num(out, ",\"updated\":", e->side[i].updated) != 0;
        bad |= num(out, ",\"deleted\":", e->side[i].deleted) != 0;
        bad |= lit(out, "}") != 0;
    }
    bad |= lit(out, "]}\n") != 0;
    sl_buf_free(&body);
    return bad ? -1 : 0;
}

sl_journal *sl_journal_open(const char *path, unsigned long long max_bytes, char *err,
                            size_t errcap)
{
    sl_journal *j = calloc(1, sizeof *j);
    struct stat st;

    if (j == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    j->path = strdup(path);
    j->fd = j->path != NULL ? open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (j->fd < 0) {
        snprintf(err, errcap, "cannot open the undo journal %s: %s", path, strerror(errno));
        free(j->path);
        free(j);
        return NULL;
    }
    if (fstat(j->fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errcap, "the undo journal %s is not a regular file", path);
        close(j->fd);
        free(j->path);
        free(j);
        return NULL;
    }
    j->size = (unsigned long long)st.st_size;
    j->max = max_bytes;
    return j;
}

void sl_journal_close(sl_journal *j)
{
    if (j == NULL) {
        return;
    }
    close(j->fd);
    free(j->path);
    free(j);
}

int sl_journal_reopen(sl_journal *j, char *err, size_t errcap)
{
    struct stat st;
    int fd = open(j->path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);

    if (fd < 0) {
        snprintf(err, errcap, "cannot open the undo journal %s again: %s", j->path,
                 strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errcap, "the undo journal %s is not a regular file", j->path);
        close(fd);
        return -1;
    }
    close(j->fd);
    j->fd = fd;
    j->size = (unsigned long long)st.st_size;
    return 0;
}

int sl_journal_append(sl_journal *j, const sl_journal_entry *e, char id[SL_JOURNAL_ID_LEN + 1],
                      char *err, size_t errcap)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t rnd[8];
    sl_buf line;
    size_t off = 0;
    const uint8_t *d;
    size_t len;

    if (RAND_bytes(rnd, sizeof rnd) != 1) {
        snprintf(err, errcap, "no random bytes for an identifier");
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        id[2 * i] = hex[rnd[i] >> 4];
        id[2 * i + 1] = hex[rnd[i] & 15];
    }
    id[SL_JOURNAL_ID_LEN] = '\0';
    sl_buf_init(&line);
    if (sl_journal_format(e, id, (long long)time(NULL), &line) != 0) {
        sl_buf_free(&line);
        snprintf(err, errcap, "out of memory");
        return -1;
    }
    d = sl_buf_data(&line);
    len = sl_buf_len(&line);
    if (j->max != 0 && j->size + len > j->max) {
        sl_buf_free(&line);
        snprintf(err, errcap,
                 "the undo journal is full (%llu bytes, limit %llu): archive it and start another",
                 j->size, j->max);
        return -1;
    }
    while (off < len) {
        ssize_t w = write(j->fd, d + off, len - off);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            snprintf(err, errcap, "cannot write the undo journal: %s", strerror(errno));
            if (ftruncate(j->fd, (off_t)j->size) != 0) { /* take back a part of a line */
                snprintf(err, errcap,
                         "cannot write the undo journal, and left a part of a line in it");
            }
            sl_buf_free(&line);
            return -1;
        }
        off += (size_t)w;
    }
    if (fsync(j->fd) != 0) {
        snprintf(err, errcap, "cannot make the undo journal durable: %s", strerror(errno));
        sl_buf_free(&line);
        return -1;
    }
    j->size += len;
    sl_buf_free(&line);
    return 0;
}
