#include "learn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql_check.h"

#define LINE_MAX_BYTES ((size_t)16 << 20)
#define SHAPES_MAX 100000

typedef struct {
    char fp[17];
    unsigned long long count;
    char *text; /* normalized, or NULL */
} shape;

/* The string value of "key":"..." in a line of the log (escapes undone), or -1. */
static int field(const char *line, const char *key, char *out, size_t cap)
{
    char pat[64];
    const char *p;
    size_t n = 0;

    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    p = strstr(line, pat);
    if (p == NULL) {
        return -1;
    }
    for (p += strlen(pat); *p != '\0' && *p != '"'; p++) {
        char ch = *p;

        if (ch == '\\') {
            p++;
            if (*p == '\0') {
                return -1;
            }
            ch = *p == 'n' ? ' ' : *p == 't' ? ' ' : *p;
            if (*p == 'u') { /* é and the like: not worth decoding for a comment */
                ch = '?';
                for (int k = 0; k < 4 && p[1] != '\0'; k++) {
                    p++;
                }
            }
        }
        if (n + 1 >= cap) {
            return -1;
        }
        out[n++] = ch;
    }
    out[n] = '\0';
    return *p == '"' ? 0 : -1;
}

static void usage(void)
{
    fputs("usage: sluice --learn LOG [LOG...] [--user NAME] [--database NAME] "
          "[--action deny|confirm|alert]\n",
          stderr);
}

int sl_learn_main(int argc, char **argv)
{
    const char *files[64];
    size_t nfiles = 0;
    const char *user = NULL, *database = NULL, *action = "deny";
    shape *shapes = NULL;
    size_t nshapes = 0;
    unsigned long long seen = 0;
    char *line = NULL;
    size_t cap = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (strcmp(argv[i], "--database") == 0 && i + 1 < argc) {
            database = argv[++i];
        } else if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) {
            action = argv[++i];
        } else if (argv[i][0] != '-' && nfiles < 64) {
            files[nfiles++] = argv[i];
        } else {
            usage();
            return 2;
        }
    }
    if (nfiles == 0 || (strcmp(action, "deny") != 0 && strcmp(action, "confirm") != 0 &&
                        strcmp(action, "alert") != 0)) {
        usage();
        return 2;
    }
    for (size_t f = 0; f < nfiles; f++) {
        FILE *in = fopen(files[f], "r");
        ssize_t n;

        if (in == NULL) {
            fprintf(stderr, "sluice: cannot read %s\n", files[f]);
            return 2;
        }
        while ((n = getline(&line, &cap, in)) > 0) {
            char fp[32], who[256], act[32], sql[8192];
            size_t i;

            if ((size_t)n > LINE_MAX_BYTES || strstr(line, "\"event\":\"statement\"") == NULL ||
                field(line, "fingerprint", fp, sizeof fp) != 0 || strlen(fp) != 16 ||
                field(line, "action", act, sizeof act) != 0 ||
                (strcmp(act, "relayed") != 0 && strcmp(act, "held") != 0)) {
                continue;
            }
            if (user != NULL &&
                (field(line, "user", who, sizeof who) != 0 || strcmp(who, user) != 0)) {
                continue;
            }
            if (database != NULL &&
                (field(line, "database", who, sizeof who) != 0 || strcmp(who, database) != 0)) {
                continue;
            }
            seen++;
            for (i = 0; i < nshapes; i++) {
                if (strcmp(shapes[i].fp, fp) == 0) {
                    break;
                }
            }
            if (i == nshapes) {
                shape *grown;

                if (nshapes >= SHAPES_MAX) {
                    continue;
                }
                grown = realloc(shapes, (nshapes + 1) * sizeof *shapes);
                if (grown == NULL) {
                    fprintf(stderr, "sluice: out of memory\n");
                    return 1;
                }
                shapes = grown;
                memset(&shapes[nshapes], 0, sizeof shapes[nshapes]);
                memcpy(shapes[nshapes].fp, fp, 17);
                nshapes++;
            }
            shapes[i].count++;
            if (shapes[i].text == NULL && field(line, "sql", sql, sizeof sql) == 0) {
                /* whatever the log holds, the comment is the normalized form: no values */
                sl_sql_redacted rd;
                char err[128];

                if (sl_sql_redact(sql, strlen(sql), &rd, err, sizeof err) == 0) {
                    shapes[i].text = rd.text;
                    rd.text = NULL;
                    sl_sql_redacted_free(&rd);
                }
            }
        }
        fclose(in);
    }
    free(line);
    if (nshapes == 0) {
        fprintf(stderr, "sluice: no statement that went through in %s\n",
                nfiles == 1 ? files[0] : "those logs");
        return 1;
    }
    printf("# sluice --learn: %zu shape%s in %llu statement%s that went through\n", nshapes,
           nshapes == 1 ? "" : "s", seen, seen == 1 ? "" : "s");
    printf("# Read it before you use it: a shape here is a shape you accept.\n");
    printf("[[rule]]\nname = \"unknown-shapes\"\nmatch = \"any\"\n");
    if (strcmp(action, "deny") != 0) {
        printf("action = \"%s\"\n", action);
    }
    if (user != NULL) {
        printf("users = [\"%s\"]\n", user);
    }
    if (database != NULL) {
        printf("databases = [\"%s\"]\n", database);
    }
    printf("message = \"this kind of statement has not been seen from this user\"\n");
    printf("outside_fingerprints = [\n");
    for (size_t i = 0; i < nshapes; i++) {
        printf("  \"%s\",", shapes[i].fp);
        printf("  # %llux", shapes[i].count);
        if (shapes[i].text != NULL) {
            for (const char *t = shapes[i].text; *t; t++) {
                putchar(*t == '\n' || *t == '\r' ? ' ' : *t);
            }
        }
        putchar('\n');
        free(shapes[i].text);
    }
    printf("]\n");
    free(shapes);
    return 0;
}
