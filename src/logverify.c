#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define KEY_MAX 1024
#define LINE_MAX_BYTES ((size_t)64 << 20)
#define CHAIN_BYTES (SL_LOG_CHAIN_HEX / 2)
/* the end of every chained line: ,"chain":"<32 hex>"} */
#define CHAIN_SUFFIX (10 + SL_LOG_CHAIN_HEX + 2)

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/* The number at the end of `content`, after `,"seq":`. 0 when there is none. */
static unsigned long long seq_of(const char *content, size_t len)
{
    size_t i = len;
    unsigned long long v = 0, mul = 1;
    size_t digits = 0;

    while (i > 0 && content[i - 1] >= '0' && content[i - 1] <= '9' && digits < 19) {
        v += (unsigned long long)(content[i - 1] - '0') * mul;
        mul *= 10;
        i--;
        digits++;
    }
    if (digits == 0 || i < 7 || memcmp(content + i - 7, ",\"seq\":", 7) != 0) {
        return 0;
    }
    return v;
}

static void usage(void)
{
    fputs("usage: sluice --verify-log FILE --log-chain-key-file KEYFILE\n", stderr);
}

int sl_log_verify_main(int argc, char **argv)
{
    const char *path = NULL, *keypath = NULL;
    uint8_t key[KEY_MAX + 1];
    size_t klen = 0;
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    unsigned long long lineno = 0, seq = 0, segment_lines = 0, segments = 0, total = 0;
    uint8_t prev[CHAIN_BYTES];
    int open_segment = 0;
    int bad = 0, unclosed = 0;
    char last_hex[SL_LOG_CHAIN_HEX + 1] = "";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--log-chain-key-file") == 0 && i + 1 < argc) {
            keypath = argv[++i];
        } else if (strncmp(argv[i], "--log-chain-key-file=", 21) == 0) {
            keypath = argv[i] + 21;
        } else if (argv[i][0] != '-' && path == NULL) {
            path = argv[i];
        } else {
            usage();
            return 2;
        }
    }
    if (path == NULL || keypath == NULL) {
        usage();
        return 2;
    }
    f = fopen(keypath, "rb");
    if (f == NULL || (klen = fread(key, 1, sizeof key, f)) < 16 || klen > KEY_MAX) {
        fprintf(stderr, "sluice: %s must be a readable file of 16 to %d bytes\n", keypath, KEY_MAX);
        if (f != NULL) {
            fclose(f);
        }
        return 2;
    }
    fclose(f);
    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "sluice: cannot read %s\n", path);
        return 2;
    }

    while (!bad && (n = getline(&line, &cap, f)) > 0) {
        size_t len = (size_t)n;
        size_t content_len;
        uint8_t got[CHAIN_BYTES], want[EVP_MAX_MD_SIZE];
        unsigned int wl = 0;
        unsigned long long s;
        uint8_t *tmp;
        int start;

        lineno++;
        if (len > LINE_MAX_BYTES) {
            fprintf(stderr, "line %llu: too long to be a line of the log\n", lineno);
            bad = 1;
            break;
        }
        if (line[len - 1] == '\n') {
            len--;
        }
        if (len < CHAIN_SUFFIX + 2 || memcmp(line + len - CHAIN_SUFFIX, ",\"chain\":\"", 10) != 0 ||
            line[len - 2] != '"' || line[len - 1] != '}') {
            fprintf(stderr, "line %llu: not chained (edited, added, or not from this log)\n",
                    lineno);
            bad = 1;
            break;
        }
        for (size_t i = 0; i < CHAIN_BYTES; i++) {
            int hi = hex_val((unsigned char)line[len - CHAIN_SUFFIX + 10 + 2 * i]);
            int lo = hex_val((unsigned char)line[len - CHAIN_SUFFIX + 10 + 2 * i + 1]);

            if (hi < 0 || lo < 0) {
                fprintf(stderr, "line %llu: the chain value is not hexadecimal\n", lineno);
                bad = 1;
                break;
            }
            got[i] = (uint8_t)(hi << 4 | lo);
        }
        if (bad) {
            break;
        }
        content_len = len - CHAIN_SUFFIX;
        s = seq_of(line, content_len);
        start = s == 1 && strstr(line, "\"event\":\"chain_start\"") != NULL &&
                strstr(line, "\"event\":\"chain_start\"") < line + 64;
        if (start) {
            if (open_segment) {
                unclosed = 1;
                fprintf(stderr,
                        "a run ends at line %llu without a chain_end (crash, kill -9, or "
                        "the end of the log was cut)\n",
                        lineno - 1);
            }
            memset(prev, 0, sizeof prev);
            seq = 0;
            segment_lines = 0;
            segments++;
            open_segment = 1;
        } else if (!open_segment) {
            fprintf(stderr,
                    "line %llu: a chained line before any chain_start (the start of the log "
                    "was cut)\n",
                    lineno);
            bad = 1;
            break;
        }
        if (s != seq + 1) {
            fprintf(stderr,
                    "line %llu: the count is %llu, %llu was expected (a line was taken out "
                    "or moved)\n",
                    lineno, s, seq + 1);
            bad = 1;
            break;
        }
        tmp = malloc(CHAIN_BYTES + content_len);
        if (tmp == NULL) {
            fprintf(stderr, "sluice: out of memory\n");
            bad = 1;
            break;
        }
        memcpy(tmp, prev, CHAIN_BYTES);
        memcpy(tmp + CHAIN_BYTES, line, content_len);
        if (HMAC(EVP_sha256(), key, (int)klen, tmp, CHAIN_BYTES + content_len, want, &wl) == NULL ||
            wl < CHAIN_BYTES || CRYPTO_memcmp(want, got, CHAIN_BYTES) != 0) {
            free(tmp);
            fprintf(stderr,
                    "line %llu: does not check out (the line was changed, or another key)\n",
                    lineno);
            bad = 1;
            break;
        }
        free(tmp);
        memcpy(prev, got, CHAIN_BYTES);
        memcpy(last_hex, line + len - CHAIN_SUFFIX + 10, SL_LOG_CHAIN_HEX);
        last_hex[SL_LOG_CHAIN_HEX] = '\0';
        seq = s;
        segment_lines++;
        total++;
        if (strstr(line, "\"event\":\"chain_end\"") != NULL &&
            strstr(line, "\"event\":\"chain_end\"") < line + 64) {
            printf("run %llu: %llu lines, closed; last chain %s\n", segments, segment_lines,
                   last_hex);
            open_segment = 0;
        }
    }
    free(line);
    fclose(f);
    if (bad) {
        fprintf(stderr, "NOT intact\n");
        return 1;
    }
    if (open_segment) {
        unclosed = 1;
        printf("run %llu: %llu lines, NOT closed (crash, kill -9, or the end was cut); last chain "
               "%s\n",
               segments, segment_lines, last_hex);
    }
    printf("%s: %llu lines in %llu run%s check out%s.\n", path, total, segments,
           segments == 1 ? "" : "s",
           unclosed ? ", but not every run ends cleanly" : ", all closed");
    printf("(Keep the last chain value somewhere else: a log cut at its end only shows it that "
           "way.)\n");
    return unclosed ? 3 : 0;
}
