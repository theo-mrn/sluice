#include "tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

struct sl_tls_ctx {
    SSL_CTX *ctx;
    sl_tls_mode mode;
};

struct sl_tls {
    SSL *ssl;
    sl_tls_mode mode;
    char last_error[200]; /* why the last read or write failed; empty until one does */
    const char *last_code;
    int last_alert; /* the TLS alert the server sent, or -1 */
};

/* The oldest error of the OpenSSL queue, as text; empties the queue. */
static void openssl_error(char *out, size_t cap)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        snprintf(out, cap, "unknown TLS error");
        return;
    }
    ERR_error_string_n(e, out, cap);
    ERR_clear_error();
}

/* Never ask anybody for a passphrase: OpenSSL would otherwise prompt on the terminal of a daemon.
 */
static int no_passphrase(char *buf, int size, int rwflag, void *userdata)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)userdata;
    return 0;
}

sl_tls_ctx *sl_tls_ctx_new(sl_tls_mode mode, const char *ca_file, const char *cert_file,
                           const char *key_file, char *err, size_t errcap)
{
    sl_tls_ctx *c = calloc(1, sizeof *c);

    if (c == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    c->mode = mode;
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (c->ctx == NULL) {
        openssl_error(err, errcap);
        free(c);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    /* PostgreSQL closes the socket without a close_notify: that is an end of stream, not an attack
     * on one. */
    SSL_CTX_set_options(c->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
    /* The queue of bytes to send moves around between two attempts, and a write may be partial. */
    SSL_CTX_set_mode(c->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /* Read as much as the socket has in one go. Several records can then be waiting inside the
     * library while the socket is quiet, which conn.c handles (sl_tls_pending); asking for it makes
     * that path the normal one, and so a tested one, instead of one that shows up on another
     * OpenSSL version. */
    SSL_CTX_set_read_ahead(c->ctx, 1);

    if (mode == SL_TLS_VERIFY_FULL) {
        SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
        if (ca_file != NULL && ca_file[0] != '\0') {
            if (SSL_CTX_load_verify_file(c->ctx, ca_file) != 1) {
                char why[200];

                openssl_error(why, sizeof why);
                snprintf(err, errcap, "cannot read the CA file %s: %s", ca_file, why);
                SSL_CTX_free(c->ctx);
                free(c);
                return NULL;
            }
        } else if (SSL_CTX_set_default_verify_paths(c->ctx) != 1) {
            openssl_error(err, errcap);
            SSL_CTX_free(c->ctx);
            free(c);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
    }

    if (cert_file != NULL && cert_file[0] != '\0' && key_file != NULL && key_file[0] != '\0') {
        const char *what = NULL;

        SSL_CTX_set_default_passwd_cb(c->ctx, no_passphrase);
        if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_file) != 1) {
            what = "cannot read the client certificate";
        } else if (SSL_CTX_use_PrivateKey_file(c->ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            what = "cannot read the client private key (is it encrypted? sluice does not ask for a "
                   "passphrase)";
        } else if (SSL_CTX_check_private_key(c->ctx) != 1) {
            what = "the client private key does not match the client certificate";
        }
        if (what != NULL) {
            char why[200];

            openssl_error(why, sizeof why);
            if (strstr(why, "mismatch") !=
                NULL) { /* found while loading the key, not by the check below */
                what = "the client private key does not match the client certificate";
            }
            snprintf(err, errcap, "%s: %s", what, why);
            SSL_CTX_free(c->ctx);
            free(c);
            return NULL;
        }
    }
    return c;
}

/* A certificate for "sluice" that only the process knows, valid for ten years. */
static int use_self_signed(SSL_CTX *ctx, char *err, size_t errcap)
{
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *x = X509_new();
    X509_NAME *name = X509_NAME_new();
    unsigned char serial[8];
    int ok = 0;

    if (key == NULL || x == NULL || name == NULL || RAND_bytes(serial, sizeof serial) != 1) {
        goto done;
    }
    serial[0] &= 0x7f; /* a positive number */
    {
        BIGNUM *bn = BN_bin2bn(serial, sizeof serial, NULL);
        int set = bn != NULL && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) != NULL;

        BN_free(bn);
        if (!set) {
            goto done;
        }
    }
    if (X509_set_version(x, 2) != 1 ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"sluice", -1,
                                   -1, 0) != 1 ||
        X509_set_subject_name(x, name) != 1 || X509_set_issuer_name(x, name) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(x), 10L * 365 * 24 * 3600) == NULL ||
        X509_set_pubkey(x, key) != 1 || X509_sign(x, key, EVP_sha256()) == 0 ||
        SSL_CTX_use_certificate(ctx, x) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        goto done;
    }
    ok = 1;
done:
    if (!ok) {
        openssl_error(err, errcap);
    }
    X509_NAME_free(name);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

sl_tls_ctx *sl_tls_server_ctx_new(const char *cert_file, const char *key_file, int self_signed,
                                  char *err, size_t errcap)
{
    sl_tls_ctx *c = calloc(1, sizeof *c);
    int ok;

    if (c == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    c->mode = SL_TLS_REQUIRE;
    c->ctx = SSL_CTX_new(TLS_server_method());
    if (c->ctx == NULL) {
        openssl_error(err, errcap);
        free(c);
        return NULL;
    }
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(c->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(c->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_read_ahead(c->ctx, 1);
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL); /* no client certificate is asked for */

    if (self_signed) {
        ok = use_self_signed(c->ctx, err, errcap);
    } else {
        const char *what = NULL;

        SSL_CTX_set_default_passwd_cb(c->ctx, no_passphrase);
        if (SSL_CTX_use_certificate_chain_file(c->ctx, cert_file) != 1) {
            what = "cannot read the certificate";
        } else if (SSL_CTX_use_PrivateKey_file(c->ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            what = "cannot read the private key (is it encrypted? sluice does not ask for a "
                   "passphrase)";
        } else if (SSL_CTX_check_private_key(c->ctx) != 1) {
            what = "the private key does not match the certificate";
        }
        ok = what == NULL;
        if (!ok) {
            char why[200];

            openssl_error(why, sizeof why);
            if (strstr(why, "mismatch") != NULL) {
                what = "the private key does not match the certificate";
            }
            snprintf(err, errcap, "%s: %s", what, why);
        }
    }
    if (!ok) {
        SSL_CTX_free(c->ctx);
        free(c);
        return NULL;
    }
    return c;
}

sl_tls *sl_tls_start_server(sl_tls_ctx *ctx, int fd, char *err, size_t errcap)
{
    sl_tls *t = calloc(1, sizeof *t);

    if (t == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    t->mode = ctx->mode;
    t->ssl = SSL_new(ctx->ctx);
    if (t->ssl == NULL || SSL_set_fd(t->ssl, fd) != 1) {
        openssl_error(err, errcap);
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    SSL_set_accept_state(t->ssl);
    return t;
}

void sl_tls_ctx_free(sl_tls_ctx *ctx)
{
    if (ctx != NULL) {
        SSL_CTX_free(ctx->ctx);
        free(ctx);
    }
}

static int is_ip_literal(const char *host)
{
    unsigned char buf[sizeof(struct in6_addr)];

    return inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1;
}

sl_tls *sl_tls_start(sl_tls_ctx *ctx, int fd, const char *host, char *err, size_t errcap)
{
    sl_tls *t = calloc(1, sizeof *t);

    if (t == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    t->mode = ctx->mode;
    t->ssl = SSL_new(ctx->ctx);
    if (t->ssl == NULL || SSL_set_fd(t->ssl, fd) != 1) {
        openssl_error(err, errcap);
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    SSL_set_connect_state(t->ssl);

    if (!is_ip_literal(host)) {
        (void)SSL_set_tlsext_host_name(t->ssl, host); /* SNI: names only, never an address */
    }
    if (ctx->mode == SL_TLS_VERIFY_FULL) {
        X509_VERIFY_PARAM *param = SSL_get0_param(t->ssl);
        int ok = is_ip_literal(host) ? X509_VERIFY_PARAM_set1_ip_asc(param, host)
                                     : X509_VERIFY_PARAM_set1_host(param, host, 0);

        if (ok != 1) {
            openssl_error(err, errcap);
            SSL_free(t->ssl);
            free(t);
            return NULL;
        }
    }
    return t;
}

void sl_tls_free(sl_tls *t)
{
    if (t != NULL) {
        SSL_free(t->ssl);
        free(t);
    }
}

int sl_tls_handshake(sl_tls *t, char *err, size_t errcap)
{
    int r;

    ERR_clear_error();
    r = SSL_do_handshake(t->ssl); /* connect or accept, as the session was started */
    if (r == 1) {
        return SL_TLS_DONE;
    }
    switch (SSL_get_error(t->ssl, r)) {
    case SSL_ERROR_WANT_READ:
        return SL_TLS_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
        return SL_TLS_WANT_WRITE;
    default: {
        long v = SSL_get_verify_result(t->ssl);

        if (t->mode == SL_TLS_VERIFY_FULL && v != X509_V_OK) {
            snprintf(err, errcap, "the server certificate is not trusted: %s",
                     X509_verify_cert_error_string(v));
            ERR_clear_error();
        } else {
            openssl_error(err, errcap);
        }
        return SL_TLS_FAILED;
    }
    }
}

/* The number, in RFC 8446, of the TLS alert that an OpenSSL error stands for when the server sent
 * it, or -1. OpenSSL reports the alerts it receives as SSL_AD_REASON_OFFSET plus the alert number.
 */
static int peer_alert(unsigned long error)
{
    int reason = ERR_GET_REASON(error);

    if (ERR_GET_LIB(error) == ERR_LIB_SSL && reason >= SSL_AD_REASON_OFFSET &&
        reason < SSL_AD_REASON_OFFSET + 256) {
        return reason - SSL_AD_REASON_OFFSET;
    }
    return -1;
}

static ssize_t finish_io(sl_tls *t, int r, int *want, int is_read)
{
    int saved_errno = errno;
    int e;

    if (r > 0) {
        return r;
    }
    t->last_code = "tls_error";
    t->last_alert = -1;
    e = SSL_get_error(t->ssl, r);
    switch (e) {
    case SSL_ERROR_ZERO_RETURN:
        ERR_clear_error();
        return is_read ? 0 : -2;
    case SSL_ERROR_WANT_READ:
        ERR_clear_error();
        *want = SL_TLS_WANT_READ;
        return -1;
    case SSL_ERROR_WANT_WRITE:
        ERR_clear_error();
        *want = SL_TLS_WANT_WRITE;
        return -1;
    case SSL_ERROR_SYSCALL:
        /* r == 0 is an end of stream without close_notify; anything else is a real failure */
        if (is_read && r == 0 && saved_errno == 0) {
            ERR_clear_error();
            return 0;
        }
        t->last_code = "io_error";
        if (ERR_peek_error() != 0) {
            openssl_error(t->last_error, sizeof t->last_error);
        } else {
            snprintf(t->last_error, sizeof t->last_error, "connection error: %s",
                     saved_errno != 0 ? strerror(saved_errno) : "unexpected end of stream");
        }
        return -2;
    default:
        /* SSL_ERROR_SSL: a protocol failure, or an alert from the server (a refused client
         * certificate arrives as one, after the handshake, in TLS 1.3) */
        t->last_alert = peer_alert(ERR_peek_error());
        t->last_code = t->last_alert >= 0 ? "tls_peer_alert" : "tls_error";
        openssl_error(t->last_error, sizeof t->last_error);
        return -2;
    }
}

ssize_t sl_tls_read(sl_tls *t, void *buf, size_t n, int *want)
{
    int r;

    *want = 0;
    ERR_clear_error();
    errno = 0;
    r = SSL_read(t->ssl, buf, n > INT_MAX ? INT_MAX : (int)n);
    return finish_io(t, r, want, 1);
}

ssize_t sl_tls_write(sl_tls *t, const void *buf, size_t n, int *want)
{
    int r;

    *want = 0;
    ERR_clear_error();
    errno = 0;
    r = SSL_write(t->ssl, buf, n > INT_MAX ? INT_MAX : (int)n);
    return finish_io(t, r, want, 0);
}

int sl_tls_pending(const sl_tls *t)
{
    return SSL_has_pending(t->ssl);
}

const char *sl_tls_last_error(const sl_tls *t)
{
    return t->last_error[0] != '\0' ? t->last_error : "TLS error";
}

const char *sl_tls_last_code(const sl_tls *t)
{
    return t->last_code != NULL ? t->last_code : "tls_error";
}

int sl_tls_last_alert(const sl_tls *t)
{
    return t->last_code != NULL ? t->last_alert : -1;
}

void sl_tls_describe(const sl_tls *t, char *out, size_t cap)
{
    snprintf(out, cap, "%s %s", SSL_get_version(t->ssl), SSL_get_cipher_name(t->ssl));
}
