#ifndef SLUICE_CHECK_H
#define SLUICE_CHECK_H

/* `sluice --check-policy FILE [--sql TEXT]... [--user NAME] [--database NAME]`: read a policy and
 * say what it does with statements, without a server, a connection or a client. For writing a
 * policy and for keeping it right (a CI can run it on the file that is deployed).
 *
 * Exit status: 0 the policy is valid and every statement given is allowed, 1 the policy is invalid,
 * 2 the arguments are wrong, 3 some statement is refused (or would be, in audit mode), 4 none is
 * refused but some is held for a confirmation or a limit. */

int sl_check_main(int argc, char **argv);

#endif
