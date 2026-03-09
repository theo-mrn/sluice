#ifndef SLUICE_PG_PROTO_H
#define SLUICE_PG_PROTO_H

/* PostgreSQL frontend/backend protocol, version 3: framing only.
 *
 * Everything here is a pure function over bytes: no I/O, no allocation (except sl_pg_append_error,
 * which appends to a caller's buffer), no global state. Input is untrusted: functions never read
 * past `len`.
 *
 * Two kinds of packets exist on the client side:
 *   - the first packet of a connection has NO type byte: int32 length, int32 code, body;
 *   - every other message has a type byte: byte type, int32 length (counting itself, not the type),
 * body. The server side only uses the second form. */

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

/* Result of the parse functions. */
enum {
    SL_PG_OK = 0,
    SL_PG_NEED_MORE = 1, /* the input is a valid prefix: read more bytes and call again */
    SL_PG_ERROR = -1     /* the input can never become valid */
};

#define SL_PG_SSL_REQUEST_CODE 80877103u
#define SL_PG_GSSENC_REQUEST_CODE 80877104u
#define SL_PG_CANCEL_REQUEST_CODE 80877102u

/* Same limit as the PostgreSQL server for the first packet. */
#define SL_PG_MAX_STARTUP_LEN 10000u
/* Largest length field PostgreSQL accepts for a message (1 GiB - 1). */
#define SL_PG_MAX_MESSAGE_LEN 0x3fffffffu

static inline uint32_t sl_pg_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void sl_pg_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---- first packet of a connection ---- */

typedef enum {
    SL_PG_STARTUP_MESSAGE, /* protocol 3.x StartupMessage: body is key\0value\0...\0 */
    SL_PG_SSL_REQUEST,
    SL_PG_GSSENC_REQUEST,
    SL_PG_CANCEL_REQUEST
} sl_pg_startup_kind;

typedef struct {
    sl_pg_startup_kind kind;
    uint32_t code;       /* protocol version (major << 16 | minor) or request code */
    size_t total_len;    /* bytes this packet takes in the stream */
    const uint8_t *body; /* after the 8 byte header, points into the input */
    size_t body_len;
} sl_pg_startup_packet;

/* SL_PG_OK fills *out. SL_PG_ERROR for a bad length, an unknown code or a protocol major other
 * than 3. */
int sl_pg_parse_startup_packet(const uint8_t *data, size_t len, sl_pg_startup_packet *out);

/* Looks up a parameter (user, database, application_name...) of a SL_PG_STARTUP_MESSAGE.
 * Returns 1 and sets *val / *vlen (not NUL terminated, points into the packet) when found,
 * 0 when the key is absent, -1 when the parameter list is malformed. */
int sl_pg_startup_param(const sl_pg_startup_packet *p, const char *key, const char **val,
                        size_t *vlen);

/* ---- regular messages ---- */

typedef struct {
    uint8_t type;
    size_t payload_len;
} sl_pg_header;

typedef struct {
    uint8_t type;
    const uint8_t *payload; /* points into the input */
    size_t payload_len;
    size_t total_len; /* 1 + 4 + payload_len */
} sl_pg_message;

/* Needs only the first 5 bytes. Useful to relay a large message without buffering all of it. */
int sl_pg_parse_header(const uint8_t *data, size_t len, sl_pg_header *out);

/* Needs the whole message. */
int sl_pg_parse_message(const uint8_t *data, size_t len, sl_pg_message *out);

/* ---- statements: the SQL carried by Query and Parse messages ---- */

typedef struct {
    const char *name; /* Parse only: statement name, "" for the unnamed statement */
    size_t name_len;
    const char *sql; /* not NUL terminated, points into the input */
    size_t sql_len;
} sl_pg_statement;

/* Payload of a simple Query message ('Q'): the SQL text followed by one NUL. SL_PG_OK, or
 * SL_PG_ERROR when the payload is malformed (no final NUL, or a NUL inside the text). On error *out
 * is zeroed. */
int sl_pg_statement_from_query(const uint8_t *payload, size_t len, sl_pg_statement *out);

/* Payload of a Parse message ('P'): name NUL, SQL NUL, int16 parameter count, then that many int32
 * type ids. The length must match exactly. SL_PG_OK, or SL_PG_ERROR (*out zeroed). */
int sl_pg_statement_from_parse(const uint8_t *payload, size_t len, sl_pg_statement *out);

/* ---- the server's authentication offer ---- */

/* payload is that of an AuthenticationSASL message ('R'): int32 10, then the names of the
 * mechanisms, each ending in a NUL, then one more NUL. When it offers SCRAM-SHA-256-PLUS (channel
 * binding) next to at least one other mechanism, appends to out a complete 'R' message with the
 * same offer minus that one and returns 1. Returns 0, and appends nothing, when there is nothing to
 * change or the payload is malformed; -1 when out of memory.
 *
 * Why: channel binding ties the authentication to the TLS session between client and server. With
 * sluice in the middle there are two sessions and the binding cannot hold, and a client that is not
 * on TLS refuses an offer that includes it. */
int sl_pg_sasl_drop_plus(const uint8_t *payload, size_t len, sl_buf *out);

/* ---- building messages ---- */

/* How sluice blocks a statement: it does not answer in place of the server, it sends the server a
 * message that is guaranteed to fail, with `reason` in the error text, so that the server itself
 * replies with the ErrorResponse, ReadyForQuery, aborted transaction and "skip until Sync" that the
 * client expects.
 *
 * The statement is "SELECT '<reason>'::int": an unknown literal that cannot be an integer, which
 * PostgreSQL rejects while analysing the statement, whatever the roles, the database or the
 * extended-protocol phase. reason is made safe first: quotes are doubled, control characters,
 * backslashes and non-ASCII bytes become spaces or '?', and it is cut at 300 bytes. Both return 0,
 * or -1 when out of memory. */
int sl_pg_append_failing_query(sl_buf *out, const char *reason);
/* The extended-protocol twin: a Parse message for statement `name` (kept, as the client will refer
 * to it) with no parameters. */
int sl_pg_append_failing_parse(sl_buf *out, const char *name, size_t name_len, const char *reason);

/* Appends an ErrorResponse with the given severity ("FATAL", "ERROR"), SQLSTATE (5 characters, for
 * example "08006") and message. Returns 0, or -1 when out of memory or too long. */
int sl_pg_append_error(sl_buf *out, const char *severity, const char *sqlstate,
                       const char *message);

#endif
