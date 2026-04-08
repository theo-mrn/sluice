#ifndef SLUICE_TESTPOLICY_H
#define SLUICE_TESTPOLICY_H

/* `sluice --test-policy POLICY TESTS`: a policy as code. TESTS says, one line each, what a
 * statement must get from the policy:
 *
 *   # comment
 *   as agent@prod                       who the statements that follow are from (user[@database])
 *   at 2026-12-01T20:00Z                the moment the rules are judged at ("at now" for the clock)
 *   deny no-ddl :: drop table t         VERDICT [RULE] [as USER[@DB]] :: SQL
 *   allow :: select 1
 *   confirm confirm-deletes :: delete from t where id < 5
 *   limit cap :: update t set a = 1 where id < 100
 *   kill no-files as dba :: select pg_read_file('x')
 *   alert honey :: select * from honeypot       an alert rule matched (besides what was decided)
 *   dry try-ddl :: create table t (a int)       a rule that is being tried (dry_run) matched
 *   uninspectable :: select (
 *
 * Exit status: 0 all as wanted, 1 a test failed (or the policy is not valid), 2 usage. */
int sl_test_policy_main(int argc, char **argv);

#endif
