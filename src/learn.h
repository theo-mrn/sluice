#ifndef SLUICE_LEARN_H
#define SLUICE_LEARN_H

/* `sluice --learn LOG [LOG...] [--user NAME] [--database NAME] [--action deny|confirm|alert]`:
 * reads the log of a session in audit mode (or any run) and prints a rule that lets through the
 * shapes of statements it saw and treats every other as the action says (default deny):
 *
 *   [[rule]]
 *   name = "unknown-shapes"
 *   match = "any"
 *   users = ["app"]
 *   outside_fingerprints = [
 *     "3f9a0c61d2b4e7a8",   # 1203x  select * from users where id = $1
 *   ]
 *
 * Only statements that went through (relayed or held for a confirmation) count. The text beside a
 * shape is the normalized one (no values), even when the log was written with --log-sql full.
 * Exit status: 0, 1 nothing learned, 2 usage. */
int sl_learn_main(int argc, char **argv);

#endif
