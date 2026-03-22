#ifndef SLUICE_TLS_H
#define SLUICE_TLS_H

/* TLS towards the upstream database, with OpenSSL. sluice is always the TLS client.
 *
 * The negotiation is PostgreSQL's own: sluice sends an SSLRequest on the TCP connection, the server
 * answers one byte ('S' or 'N'), and on 'S' the TLS handshake follows on the same socket. That part
 * is in conn.c; this module only wraps the TLS library, with non-blocking calls that say what they
 * wait for. */

#include <stddef.h>
#include <sys/types.h>

#include "config.h"

typedef struct sl_tls_ctx sl_tls_ctx; /* one per process: protocol settings and trusted CAs */
typedef struct sl_tls sl_tls;         /* one per connection */

/* cert_file and key_file (PEM, both or neither) are the client certificate shown to a server that
 * asks for one. A key that needs a passphrase is refused: sluice never asks for one, on a terminal
 * or elsewhere. mode must not be SL_TLS_OFF. ca_file may be NULL or empty to use the system store
 * (verify-full only). Returns NULL with a message in err when the library or the CA file cannot be
 * set up. */
sl_tls_ctx *sl_tls_ctx_new(sl_tls_mode mode, const char *ca_file, const char *cert_file,
                           const char *key_file, char *err, size_t errcap);
void sl_tls_ctx_free(sl_tls_ctx *ctx);

/* The other direction: sluice as the TLS server of its clients. Many clients refuse to talk to a
 * server that does not do TLS (sslmode=require, which the connection strings of managed databases
 * carry), so sluice has to be able to. The certificate comes from PEM files (the key is not
 * encrypted: sluice never asks for a passphrase), or, with self_signed, is made at startup and kept
 * in memory: that is enough for a client that only wants encryption (sslmode=require), not for one
 * that checks who the server is. */
sl_tls_ctx *sl_tls_server_ctx_new(const char *cert_file, const char *key_file, int self_signed,
                                  char *err, size_t errcap);

/* Starts the server side of a session on the client's connected, non-blocking socket. Handshake and
 * I/O are the same calls as for the upstream (sl_tls_handshake, sl_tls_read, sl_tls_write). */
sl_tls *sl_tls_start_server(sl_tls_ctx *ctx, int fd, char *err, size_t errcap);

/* Starts a client session on a connected, non-blocking socket. host is the name the certificate
 * must carry in verify-full mode (a DNS name or an IP address). The socket stays owned by the
 * caller. */
sl_tls *sl_tls_start(sl_tls_ctx *ctx, int fd, const char *host, char *err, size_t errcap);
void sl_tls_free(sl_tls *t);

/* What a call waits for before it can be tried again. */
enum { SL_TLS_DONE = 0, SL_TLS_WANT_READ = 1, SL_TLS_WANT_WRITE = 2, SL_TLS_FAILED = -1 };

/* Advances the handshake. Returns SL_TLS_DONE, SL_TLS_WANT_READ or _WRITE (call again when the
 * socket is readable or writable), or SL_TLS_FAILED with a message in err (certificate problems are
 * spelled out). */
int sl_tls_handshake(sl_tls *t, char *err, size_t errcap);

/* Return the number of bytes read or written, 0 when the peer closed the connection (reads only),
 * -1 when the call must be retried once the socket is ready for *want (SL_TLS_WANT_READ or _WRITE),
 * -2 on error. Retry a write with the same bytes. */
ssize_t sl_tls_read(sl_tls *t, void *buf, size_t n, int *want);
ssize_t sl_tls_write(sl_tls *t, const void *buf, size_t n, int *want);

/* Why the last read or write returned -2. The code is stable and meant for machines:
 * "tls_peer_alert" (the server sent a TLS alert, and sl_tls_last_alert says which, by its number in
 * RFC 8446: 48 is unknown_ca, 116 is certificate_required...), "tls_error" or "io_error" (the
 * socket failed under TLS). The text is for people: it is the library's own and changes from one
 * version to the next. */
const char *sl_tls_last_code(const sl_tls *t);
int sl_tls_last_alert(const sl_tls *t); /* -1 unless the code is tls_peer_alert */
const char *sl_tls_last_error(const sl_tls *t);

/* Non-zero when decrypted or received-but-unprocessed data is waiting inside the library: the
 * socket may not be readable although a read would succeed. */
int sl_tls_pending(const sl_tls *t);

/* "TLSv1.3 TLS_AES_256_GCM_SHA384" */
void sl_tls_describe(const sl_tls *t, char *out, size_t cap);

#endif
