# Security policy

sluice sits in front of a database and decides what gets through, so a flaw in it can be a flaw in the protection
that people rely on. Please report it privately and give it a chance to be fixed before it is public.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** (the repository's *Security* tab, then *Report a vulnerability*).
Do not open a public issue for it. Say which version (`sluice --version`), what you did, what you expected and what
happened; a policy file and a statement that reproduce it are the most useful thing you can send.

You can expect an answer within a few days. A fix is released as a new version with a `Security` entry in the
[changelog](CHANGELOG.md), and you are credited if you wish.

## Supported versions

sluice is pre-1.0: only **the latest release** gets fixes.

## What counts

In scope: a statement that a rule should have refused or asked about and that goes through (a bypass of the
parser's reading, of the quoting and `search_path` protections, of a limit or a budget, of `kill`); a way to make
sluice crash, hang or grow without bound from the network; values that reach the log, the metrics or an event when they
should not; a way to answer a confirmation without the token, or to read a question without it; a flaw in the chain of
the log that lets a change go unseen when the key was not available.

Known limits, described in [docs/policy.md](docs/policy.md#what-a-policy-cannot-do) and
[docs/design.md](docs/design.md), and not vulnerabilities by themselves:

- **Masking is a guard-rail, not a security boundary.** A client that can run SQL can compute around it. The boundary
  is the privileges of the database.
- **What sluice cannot see is not judged**: the body of a function, a view, a trigger, a `DO` block (use the
  `procedural` match), what a role can do through `SET ROLE` if the policy has no `set_session` rule.
- **The admin listener speaks plain HTTP.** Keep it on a loopback address or a private network, or behind a reverse
  proxy with TLS; give it a token.
- **A client that uses the application's own credentials is the application** for sluice (it keeps no password and
  enforces by database role).

## Hardening a deployment

Run it as an unprivileged user (the container image does), give the policy file and the keys read-only, keep
`--mask-key-file`, `--log-chain-key-file` and the admin token where only sluice and the operator can read them, and
use `--upstream-tls verify-full`. [docs/deploy.md](docs/deploy.md) has the details.
