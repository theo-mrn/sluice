#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"
#include "sql_check.h"
#include "testpolicy.h"

#define LINE_MAX_BYTES 65536

static void usage(void)
{
    fputs("usage: sluice --test-policy POLICY TESTS\n", stderr);
}

static char *trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) {
        *--e = '\0';
    }
    return s;
}

/* "agent", "agent@prod": sets who the following statements are from */
static void who_is(char *spec, char *user, size_t ucap, char *db, size_t dcap)
{
    char *at = strchr(spec, '@');

    if (at != NULL) {
        *at = '\0';
        snprintf(db, dcap, "%s", at + 1);
    }
    snprintf(user, ucap, "%s", spec);
}

int sl_test_policy_main(int argc, char **argv)
{
    sl_policy p;
    char err[512];
    FILE *f;
    char line[LINE_MAX_BYTES];
    char user[128] = "", db[128] = "";
    unsigned lineno = 0, ran = 0, failed = 0;

    if (argc != 2) {
        usage();
        return 2;
    }
    if (sl_policy_load(&p, argv[0], err, sizeof err) != 0) {
        fprintf(stderr, "sluice: %s\n", err);
        return 1;
    }
    f = fopen(argv[1], "r");
    if (f == NULL) {
        fprintf(stderr, "sluice: cannot read %s\n", argv[1]);
        sl_policy_free(&p);
        return 2;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char *text = trim(line);
        char *sep;
        char *sql;
        char want[16] = "", rule[128] = "";
        char luser[128], ldb[128];
        sl_sql_info info;
        sl_verdict v;
        const char *got = NULL;
        const char *got_rule = NULL;
        int ok = 0;

        lineno++;
        if (text[0] == '\0' || text[0] == '#') {
            continue;
        }
        sep = strstr(text, "::");
        if (sep == NULL) { /* a directive: who the next statements are from, and when */
            char *hash = strstr(text, " #");

            if (hash != NULL) {
                *hash = '\0'; /* a comment after it (never after SQL: a # can be in the SQL) */
                trim(text);
            }
            if (strncmp(text, "as ", 3) == 0) {
                user[0] = db[0] = '\0';
                who_is(trim(text + 3), user, sizeof user, db, sizeof db);
            } else if (strncmp(text, "at ", 3) == 0) {
                long long t;
                char *when = trim(text + 3);

                if (strcmp(when, "now") == 0) {
                    sl_policy_set_time(-1);
                } else if (sl_policy_parse_instant(when, &t) == 0) {
                    sl_policy_set_time(t);
                } else {
                    fprintf(stderr,
                            "%s:%u: 'at' takes now or a moment in UTC like "
                            "2026-12-01T18:30Z\n",
                            argv[1], lineno);
                    failed++;
                }
            } else {
                fprintf(stderr, "%s:%u: not a test (VERDICT [RULE] [as USER[@DB]] :: SQL)\n",
                        argv[1], lineno);
                failed++;
            }
            continue;
        }
        *sep = '\0';
        sql = trim(sep + 2);
        snprintf(luser, sizeof luser, "%s", user);
        snprintf(ldb, sizeof ldb, "%s", db);
        {
            char *tok = strtok(text, " \t");
            int pos = 0;

            while (tok != NULL) {
                if (strcmp(tok, "as") == 0) {
                    char *w = strtok(NULL, " \t");

                    if (w != NULL) {
                        ldb[0] = '\0';
                        who_is(w, luser, sizeof luser, ldb, sizeof ldb);
                    }
                } else if (pos == 0) {
                    snprintf(want, sizeof want, "%s", tok);
                    pos++;
                } else if (pos == 1) {
                    snprintf(rule, sizeof rule, "%s", tok);
                    pos++;
                }
                tok = strtok(NULL, " \t");
            }
        }
        ran++;
        if (sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err) != 0) {
            ok = strcmp(want, "uninspectable") == 0;
            got = "uninspectable";
        } else {
            v = sl_policy_evaluate(&p, &info, luser, strlen(luser), ldb, strlen(ldb));
            sl_sql_info_free(&info);
            got = v.deny      ? (v.kill ? "kill" : "deny")
                  : v.confirm ? (v.rule->limit ? "limit" : "confirm")
                              : "allow";
            got_rule = v.rule != NULL ? v.rule->name : NULL;
            if (strcmp(want, "alert") == 0) {
                ok = v.alert != NULL;
                got = ok ? "alert" : "no alert";
                got_rule = v.alert != NULL ? v.alert->name : NULL;
            } else if (strcmp(want, "dry") == 0) {
                ok = v.dry != NULL;
                got = ok ? "dry" : "no dry run";
                got_rule = v.dry != NULL ? v.dry->name : NULL;
            } else {
                ok = strcmp(want, got) == 0;
            }
        }
        if (ok && rule[0] != '\0' && (got_rule == NULL || strcmp(rule, got_rule) != 0)) {
            ok = 0;
        }
        if (!ok) {
            failed++;
            printf("FAIL %s:%u: %s%s%s  (as %s%s%s)\n     wanted: %s%s%s\n     got:    %s%s%s\n",
                   argv[1], lineno, sql, "", "", luser[0] ? luser : "?", ldb[0] ? "@" : "", ldb,
                   want, rule[0] ? " " : "", rule, got, got_rule ? " " : "",
                   got_rule ? got_rule : "");
        }
    }
    fclose(f);
    sl_policy_set_time(-1);
    sl_policy_free(&p);
    printf("%u test%s, %u failed.\n", ran, ran == 1 ? "" : "s", failed);
    return failed ? 1 : 0;
}
