#ifndef SLUICE_CONN_H
#define SLUICE_CONN_H

/* One proxied connection: a client socket, an upstream socket, two byte queues and a state machine
 * (STARTUP, CONNECTING, RELAY, DONE). See docs/architecture.md.
 *
 * The connection never blocks and never polls by itself. The server asks which events it wants on
 * each socket, polls, then reports what happened. */

#include <stdint.h>

#include "budget.h"
#include "config.h"
#include "journal.h"
#include "policy.h"
#include "prompt.h"
#include "tls.h"

typedef struct sl_conn sl_conn;

/* What every connection shares. All of it must outlive the connections. */
typedef struct {
    const sl_config *cfg;
    /* NULL: relay and log only. Otherwise the address of the pointer to the policy in force, which
     * the server replaces when the policy file is reloaded: connections read it each time they
     * judge a message, so a stricter policy applies at once, to connections that are already open
     * as well. */
    const sl_policy *const *policy;
    sl_tls_ctx *tls;        /* NULL: plain text to the upstream */
    sl_tls_ctx *client_tls; /* NULL: clients are served in clear text; else they must use TLS */
    /* How many connections (other than `self`) are open for this user: for max_connections. May be
     * NULL. */
    unsigned long long (*count_user)(void *ctx, const sl_conn *self, const char *user, size_t len);
    void *count_ctx;
    sl_journal *journal;     /* where the rows of DELETEs are kept for undo; may be NULL */
    const uint8_t *mask_key; /* makes the tokens of a "hash" mask: they are the same while it is */
    size_t mask_key_len;
    sl_budget
        *budget; /* what each user has carried out and changed lately (budget.h); may be NULL */
    sl_prompt *prompt; /* where a person confirms a DELETE or UPDATE (see confirm.h); may be NULL */
} sl_conn_env;

/* Takes ownership of client_fd (already non-blocking) on success. Returns NULL when out of memory,
 * in which case the caller still owns client_fd. Logs "connection_open". */
sl_conn *sl_conn_new(const sl_conn_env *env, int client_fd, uint64_t id);

/* TLS keeps decrypted bytes inside its library, where poll() cannot see them. These two tell the
 * server loop that a connection has bytes to read although its socket is quiet, and serve them. */
int sl_conn_has_pending(const sl_conn *c);
void sl_conn_service_pending(sl_conn *c);

/* Logs "connection_close", closes both sockets, frees everything. */
void sl_conn_free(sl_conn *c);

int sl_conn_client_fd(const sl_conn *c);
int sl_conn_upstream_fd(const sl_conn *c); /* -1 when there is no upstream socket */

/* poll() event masks wanted right now. 0 means "do not poll this socket". */
short sl_conn_client_events(const sl_conn *c);
short sl_conn_upstream_events(const sl_conn *c);

/* Report what poll() returned for one of the two sockets. */
void sl_conn_on_client(sl_conn *c, short revents);
void sl_conn_on_upstream(sl_conn *c, short revents);

/* Monotonic time (ms) at which the connection gives up, or -1 for no deadline. */
int64_t sl_conn_deadline(const sl_conn *c);
void sl_conn_check_deadline(sl_conn *c, int64_t now_ms);

/* Ends the connection as soon as possible (used at shutdown). */
void sl_conn_abort(sl_conn *c, const char *reason);

/* Non-zero once the connection is finished and can be freed. */
int sl_conn_is_done(const sl_conn *c);

/* Is this a live connection of that user (one that has told its name)? */
int sl_conn_is_user(const sl_conn *c, const char *user, size_t len);

#endif
