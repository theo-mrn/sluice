#include "pg_proto.h"

#include <string.h>

int sl_pg_parse_startup_packet(const uint8_t *data, size_t len, sl_pg_startup_packet *out)
{
    uint32_t total;
    uint32_t code;
    sl_pg_startup_kind kind;

    if (len < 4) {
        return SL_PG_NEED_MORE;
    }
    total = sl_pg_get_be32(data);
    if (total < 8 || total > SL_PG_MAX_STARTUP_LEN) {
        return SL_PG_ERROR;
    }
    if (len < total) {
        return SL_PG_NEED_MORE;
    }

    code = sl_pg_get_be32(data + 4);
    if ((code >> 16) == 3) {
        kind = SL_PG_STARTUP_MESSAGE;
    } else if (code == SL_PG_SSL_REQUEST_CODE && total == 8) {
        kind = SL_PG_SSL_REQUEST;
    } else if (code == SL_PG_GSSENC_REQUEST_CODE && total == 8) {
        kind = SL_PG_GSSENC_REQUEST;
    } else if (code == SL_PG_CANCEL_REQUEST_CODE && total == 16) {
        kind = SL_PG_CANCEL_REQUEST;
    } else {
        return SL_PG_ERROR;
    }

    out->kind = kind;
    out->code = code;
    out->total_len = total;
    out->body = data + 8;
    out->body_len = total - 8;
    return SL_PG_OK;
}

int sl_pg_startup_param(const sl_pg_startup_packet *p, const char *key, const char **val,
                        size_t *vlen)
{
    const uint8_t *s = p->body;
    const uint8_t *end = p->body + p->body_len;

    while (s < end) {
        const uint8_t *k_end;
        const uint8_t *v;
        const uint8_t *v_end;

        if (*s == 0) {
            return 0; /* terminator: the list ended without the key */
        }
        k_end = memchr(s, 0, (size_t)(end - s));
        if (k_end == NULL || k_end + 1 >= end) {
            return -1;
        }
        v = k_end + 1;
        v_end = memchr(v, 0, (size_t)(end - v));
        if (v_end == NULL) {
            return -1;
        }
        if (strcmp((const char *)s, key) == 0) {
            *val = (const char *)v;
            *vlen = (size_t)(v_end - v);
            return 1;
        }
        s = v_end + 1;
    }
    return -1; /* ran off the end without the final terminator */
}

int sl_pg_parse_header(const uint8_t *data, size_t len, sl_pg_header *out)
{
    uint32_t length;

    if (len < 5) {
        return SL_PG_NEED_MORE;
    }
    length = sl_pg_get_be32(data + 1);
    if (length < 4 || length > SL_PG_MAX_MESSAGE_LEN) {
        return SL_PG_ERROR;
    }
    out->type = data[0];
    out->payload_len = length - 4;
    return SL_PG_OK;
}

int sl_pg_parse_message(const uint8_t *data, size_t len, sl_pg_message *out)
{
    sl_pg_header h;
    int rc = sl_pg_parse_header(data, len, &h);

    if (rc != SL_PG_OK) {
        return rc;
    }
    if (len - 5 < h.payload_len) {
        return SL_PG_NEED_MORE;
    }
    out->type = h.type;
    out->payload = data + 5;
    out->payload_len = h.payload_len;
    out->total_len = 5 + h.payload_len;
    return SL_PG_OK;
}

int sl_pg_statement_from_query(const uint8_t *payload, size_t len, sl_pg_statement *out)
{
    memset(out, 0, sizeof *out);
    if (len == 0 || payload[len - 1] != 0 || memchr(payload, 0, len - 1) != NULL) {
        return SL_PG_ERROR;
    }
    out->name = "";
    out->sql = (const char *)payload;
    out->sql_len = len - 1;
    return SL_PG_OK;
}

int sl_pg_statement_from_parse(const uint8_t *payload, size_t len, sl_pg_statement *out)
{
    const uint8_t *name_end;
    const uint8_t *sql;
    const uint8_t *sql_end;
    const uint8_t *tail;
    size_t tail_len;
    uint32_t nparams;

    memset(out, 0, sizeof *out);
    if (len < 4) { /* at least: NUL, NUL, int16 */
        return SL_PG_ERROR;
    }
    name_end = memchr(payload, 0, len);
    if (name_end == NULL) {
        return SL_PG_ERROR;
    }
    sql = name_end + 1;
    sql_end = memchr(sql, 0, len - (size_t)(sql - payload));
    if (sql_end == NULL) {
        return SL_PG_ERROR;
    }
    tail = sql_end + 1;
    tail_len = len - (size_t)(tail - payload);
    if (tail_len < 2) {
        return SL_PG_ERROR;
    }
    nparams = ((uint32_t)tail[0] << 8) | (uint32_t)tail[1];
    if (tail_len - 2 != (size_t)nparams * 4) {
        return SL_PG_ERROR;
    }

    out->name = (const char *)payload;
    out->name_len = (size_t)(name_end - payload);
    out->sql = (const char *)sql;
    out->sql_len = (size_t)(sql_end - sql);
    return SL_PG_OK;
}

int sl_pg_sasl_drop_plus(const uint8_t *payload, size_t len, sl_buf *out)
{
    static const char plus[] = "SCRAM-SHA-256-PLUS";
    const uint8_t *p;
    const uint8_t *end;
    size_t kept = 0;
    size_t others = 0;
    int found_plus = 0;
    uint8_t head[9];
    const uint8_t zero = 0;

    if (len < 5 || sl_pg_get_be32(payload) != 10 || payload[len - 1] != 0) {
        return 0;
    }
    p = payload + 4;
    end = payload + len - 1; /* the NUL that ends the list */
    while (p < end && *p != 0) {
        const uint8_t *nul = memchr(p, 0, (size_t)(end - p));
        size_t n;

        if (nul == NULL) {
            return 0;
        }
        n = (size_t)(nul - p);
        if (n == sizeof plus - 1 && memcmp(p, plus, n) == 0) {
            found_plus = 1;
        } else {
            kept += n + 1;
            others++;
        }
        p = nul + 1;
    }
    if (p != end || !found_plus || others == 0) {
        return 0; /* not a clean list, no PLUS to drop, or nothing would be left */
    }

    head[0] = 'R';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + 4 + kept + 1));
    sl_pg_put_be32(head + 5, 10);
    if (sl_buf_append(out, head, sizeof head) != 0) {
        return -1;
    }
    for (p = payload + 4; p < end && *p != 0;) {
        const uint8_t *nul = memchr(p, 0, (size_t)(end - p));
        size_t n = (size_t)(nul - p);

        if (!(n == sizeof plus - 1 && memcmp(p, plus, n) == 0) &&
            sl_buf_append(out, p, n + 1) != 0) {
            return -1;
        }
        p = nul + 1;
    }
    return sl_buf_append(out, &zero, 1) != 0 ? -1 : 1;
}

#define REASON_MAX 300

/* "select '<reason>'::int", the reason made safe to sit inside a string literal whatever the
 * settings of the session (standard_conforming_strings, client_encoding). */
static int build_failing_sql(sl_buf *sql, const char *reason)
{
    size_t n = strlen(reason);

    if (n > REASON_MAX) {
        n = REASON_MAX;
    }
    if (sl_buf_append(sql, "select '", 8) != 0) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)reason[i];
        char out = (char)ch;

        if (ch == '\'') {
            if (sl_buf_append(sql, "''", 2) != 0) {
                return -1;
            }
            continue;
        }
        if (ch == '\\' || ch < 0x20 || ch == 0x7f) {
            out = ' ';
        } else if (ch >= 0x80) {
            out = '?';
        }
        if (sl_buf_append(sql, &out, 1) != 0) {
            return -1;
        }
    }
    return sl_buf_append(sql, "'::int", 6);
}

int sl_pg_append_failing_query(sl_buf *out, const char *reason)
{
    sl_buf sql;
    uint8_t head[5];
    const uint8_t zero = 0;
    int rc = -1;

    sl_buf_init(&sql);
    if (build_failing_sql(&sql, reason) == 0) {
        head[0] = 'Q';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + sl_buf_len(&sql) + 1));
        if (sl_buf_append(out, head, sizeof head) == 0 &&
            sl_buf_append(out, sl_buf_data(&sql), sl_buf_len(&sql)) == 0 &&
            sl_buf_append(out, &zero, 1) == 0) {
            rc = 0;
        }
    }
    sl_buf_free(&sql);
    return rc;
}

int sl_pg_append_failing_parse(sl_buf *out, const char *name, size_t name_len, const char *reason)
{
    sl_buf sql;
    uint8_t head[5];
    const uint8_t no_params[2] = {0, 0}; /* int16 parameter count: 0 */
    const uint8_t zero = 0;
    int rc = -1;

    sl_buf_init(&sql);
    if (build_failing_sql(&sql, reason) == 0) {
        /* name NUL, sql NUL, int16 count */
        head[0] = 'P';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + name_len + 1 + sl_buf_len(&sql) + 1 + 2));
        if (sl_buf_append(out, head, sizeof head) == 0 && sl_buf_append(out, name, name_len) == 0 &&
            sl_buf_append(out, &zero, 1) == 0 &&
            sl_buf_append(out, sl_buf_data(&sql), sl_buf_len(&sql)) == 0 &&
            sl_buf_append(out, &zero, 1) == 0 && sl_buf_append(out, no_params, 2) == 0) {
            rc = 0;
        }
    }
    sl_buf_free(&sql);
    return rc;
}

static int append_field(sl_buf *out, char tag, const char *value)
{
    if (sl_buf_append(out, &tag, 1) != 0) {
        return -1;
    }
    return sl_buf_append(out, value, strlen(value) + 1);
}

int sl_pg_append_report(sl_buf *out, uint8_t type, const char *severity, const char *sqlstate,
                        const char *message, const char *detail, const char *hint)
{
    size_t length = 4 + (1 + strlen(severity) + 1) * 2 + (1 + strlen(sqlstate) + 1) +
                    (1 + strlen(message) + 1) + 1;
    uint8_t head[5];
    const uint8_t zero = 0;

    if (detail != NULL) {
        length += 1 + strlen(detail) + 1;
    }
    if (hint != NULL) {
        length += 1 + strlen(hint) + 1;
    }
    if (length > SL_PG_MAX_MESSAGE_LEN) {
        return -1;
    }
    head[0] = type;
    sl_pg_put_be32(head + 1, (uint32_t)length);
    if (sl_buf_append(out, head, sizeof head) != 0 || append_field(out, 'S', severity) != 0 ||
        append_field(out, 'V', severity) != 0 || append_field(out, 'C', sqlstate) != 0 ||
        append_field(out, 'M', message) != 0 ||
        (detail != NULL && append_field(out, 'D', detail) != 0) ||
        (hint != NULL && append_field(out, 'H', hint) != 0) || sl_buf_append(out, &zero, 1) != 0) {
        return -1;
    }
    return 0;
}

int sl_pg_append_error(sl_buf *out, const char *severity, const char *sqlstate, const char *message)
{
    return sl_pg_append_report(out, 'E', severity, sqlstate, message, NULL, NULL);
}
