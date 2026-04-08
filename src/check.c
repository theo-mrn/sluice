#include "check.h"

#include <stdio.h>
#include <string.h>

#include "policy.h"
#include "sql_check.h"

#define MAX_STATEMENTS 64

static void usage(FILE *out)
{
    fputs("usage: sluice --check-policy FILE [--sql TEXT]... [--user NAME] [--database NAME]\n"
          "  reads the policy and, for each --sql, says what it would do with that message\n"
          "  (as the given user and database, which default to none)\n",
          out);
}

static const char *action_of(const sl_rule *r)
{
    return r->kill      ? "kill"
           : r->deny    ? "deny"
           : r->alert   ? "alert"
           : r->mask    ? "mask"
           : r->limit   ? "limit"
           : r->confirm ? "confirm"
                        : "allow";
}

int sl_check_main(int argc, char **argv)
{
    const char *path = NULL;
    const char *sqls[MAX_STATEMENTS];
    size_t nsql = 0;
    const char *user = "";
    const char *database = "";
    sl_policy p;
    char err[512];
    int refused = 0;
    int held = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--check-policy") == 0 && i + 1 < argc && path == NULL) {
            path = argv[++i];
        } else if (strcmp(a, "--sql") == 0 && i + 1 < argc && nsql < MAX_STATEMENTS) {
            sqls[nsql++] = argv[++i];
        } else if (strcmp(a, "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (strcmp(a, "--database") == 0 && i + 1 < argc) {
            database = argv[++i];
        } else if (strcmp(a, "--at") == 0 && i + 1 < argc) {
            long long t;

            if (sl_policy_parse_instant(argv[++i], &t) != 0) {
                fprintf(stderr, "sluice: --at takes a moment in UTC like 2026-12-01T18:30Z\n");
                return 2;
            }
            sl_policy_set_time(t); /* the rules that depend on the time are judged at that moment */
        } else {
            fprintf(stderr, "sluice: cannot use '%s' here\n\n", a);
            usage(stderr);
            return 2;
        }
    }
    if (path == NULL) {
        usage(stderr);
        return 2;
    }
    if (sl_policy_load(&p, path, err, sizeof err) != 0) {
        fprintf(stderr, "sluice: %s\n", err);
        return 1;
    }

    printf("%s: valid. mode %s, %zu rule%s, uninspectable messages are %s.\n", path,
           p.mode == SL_MODE_ENFORCE ? "enforce" : "audit", p.nrules, p.nrules == 1 ? "" : "s",
           p.deny_uninspectable ? "refused" : "allowed");
    for (size_t i = 0; i < p.nrules; i++) {
        const sl_rule *r = &p.rules[i];

        printf("  %zu. %-24s %s", i + 1, r->name, action_of(r));
        if (r->conn_limit) {
            printf(" (on the connection:");
            if (r->max_result_rows) {
                printf(" %llu rows per result", r->max_result_rows);
            }
            if (r->max_result_bytes) {
                printf(" %llu bytes per result", r->max_result_bytes);
            }
            if (r->max_total_bytes) {
                printf(" %llu bytes in all", r->max_total_bytes);
            }
            if (r->max_duration_s) {
                printf(" %us per statement", r->max_duration_s);
            }
            if (r->max_idle_in_transaction_s) {
                printf(" %us idle in a transaction", r->max_idle_in_transaction_s);
            }
            if (r->max_transaction_s) {
                printf(" %us per transaction", r->max_transaction_s);
            }
            if (r->max_connections) {
                printf(" %llu connections", r->max_connections);
            }
            if (r->budget) {
                printf(" per user, in %us:", r->window_s != 0 ? r->window_s : 3600);
                if (r->budget_rows) {
                    printf(" %llu rows read", r->budget_rows);
                }
                if (r->budget_bytes) {
                    printf(" %llu bytes read", r->budget_bytes);
                }
                if (r->budget_statements) {
                    printf(" %llu round trips", r->budget_statements);
                }
                if (r->budget_changed) {
                    printf(" %llu rows changed", r->budget_changed);
                }
            }
            printf(")");
        } else if (r->mask) {
            static const char *const how[] = {"hash", "partial", "null", "redact"};

            printf(" (%s;", how[r->mask_how & 3]);
            for (size_t c = 0; c < r->nmask_columns; c++) {
                printf("%s %s", c ? "," : " columns", r->mask_columns[c]);
            }
            if (r->mask_detect) {
                const char *sep = " ";

                printf("%s looks for", r->nmask_columns ? ";" : "");
                if (r->mask_detect & SL_MASK_EMAIL) {
                    printf("%se-mails", sep);
                    sep = ", ";
                }
                if (r->mask_detect & SL_MASK_CARD) {
                    printf("%scard numbers", sep);
                    sep = ", ";
                }
                if (r->mask_detect & SL_MASK_IBAN) {
                    printf("%sIBANs", sep);
                }
            }
            printf(")");
        } else if (r->limit) {
            printf(" (more than %llu rows)", r->over_rows);
        } else if (r->confirm) {
            printf(" (above %llu rows%s)", r->over_rows,
                   r->via == SL_VIA_SESSION    ? ", asked in the session"
                   : r->via == SL_VIA_OPERATOR ? ", asked at the proxy"
                                               : "");
        }
        printf("\n");
    }

    for (size_t s = 0; s < nsql; s++) {
        const char *sql = sqls[s];
        sl_sql_info info;
        sl_verdict v;
        int rc;

        printf("\n  %s\n    ", sql);
        rc = sl_policy_needs_tables(&p)
                 ? sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err)
                 : sl_sql_classify(sql, strlen(sql), &info, err, sizeof err);
        if (rc != 0) {
            printf("cannot be inspected (%s): %s\n", err,
                   p.deny_uninspectable ? "refused by on_uninspectable = \"deny\"" : "allowed");
            refused |= p.deny_uninspectable;
            continue;
        }
        v = sl_policy_evaluate(&p, &info, user, strlen(user), database, strlen(database));
        if (v.alert != NULL) {
            printf("[alert: rule %s will be logged] ", v.alert->name);
        }
        if (v.dry != NULL) {
            printf("[dry run: rule %s would %s] ", v.dry->name, sl_rule_would(v.dry));
        }
        if (v.deny) {
            char reason[256];

            sl_policy_reason(v.rule, reason, sizeof reason);
            printf("REFUSED: %s%s%s\n", reason, v.kill ? ", and the connection is closed" : "",
                   p.mode == SL_MODE_ENFORCE ? "" : "  (audit mode: it would only be logged)");
            refused = 1;
        } else if (v.confirm && v.rule->limit) {
            printf("allowed up to %llu rows, undone beyond (rule %s)%s\n", v.rule->over_rows,
                   v.rule->name,
                   info.top_kind == 'T' || info.top_kind == 'R'
                       ? "; but a limit cannot count TRUNCATE or DROP: refused"
                       : "");
            held = 1;
            refused |= info.top_kind == 'T' || info.top_kind == 'R';
        } else if (v.confirm) {
            if (info.top_kind == 'T' || info.top_kind == 'R') {
                printf("held for a confirmation, always (rule %s)\n", v.rule->name);
            } else if (info.top_kind == 0) {
                printf("rule %s asks for a confirmation, but this is not one DELETE, UPDATE, "
                       "TRUNCATE or "
                       "DROP: it would be refused\n",
                       v.rule->name);
            } else {
                printf("held for a confirmation above %llu rows (rule %s)\n", v.rule->over_rows,
                       v.rule->name);
            }
            held = 1;
            refused |= info.top_kind == 0;
        } else {
            printf("allowed%s%s\n", v.rule != NULL ? " by rule " : "",
                   v.rule != NULL ? v.rule->name : "");
        }
        sl_sql_info_free(&info);
    }
    sl_policy_free(&p);
    return refused ? 3 : held ? 4 : 0;
}
