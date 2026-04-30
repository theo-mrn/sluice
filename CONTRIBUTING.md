# Contributing

sluice is small on purpose: one binary, no runtime dependencies beyond OpenSSL, a short list of things it does. A change
is welcome when it keeps it that way and comes with its tests.

## Building and testing

```bash
meson setup build && meson compile -C build      # OpenSSL 3 or newer, a C11 compiler, Python 3
meson test -C build --print-errorlogs
sh tools/format.sh                               # clang-format; the CI does not reformat for you
```

The tests link the real code (`tests/test_*.c`), run the proxy against fake servers (`tests/integration.py`) and, with
Docker, against a real PostgreSQL and real client libraries (`SLUICE_REAL_PG=1 meson test -C build realpg`). Also run the
address and undefined-behaviour sanitizers, which find what the plain build does not:

```bash
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false && meson test -C build-asan
```

A release build (`--buildtype=release`) has other warnings than the debug one; the CI builds both.

## What a change needs

- **A test that fails without it**, at the level where the defect shows: a unit test for a parser or a rule, an integration
  scenario for a behaviour of the proxy, the real server for anything that depends on what PostgreSQL does.
- **Fuzz seeds** when it reads bytes from the network or a file (`fuzz/make_corpus.py`).
- **The documentation**: `docs/policy.md` for what a user can write, `docs/design.md` for why (what was tried, what was
  rejected, what it cannot do).
- **A line in the [changelog](CHANGELOG.md)** under *Unreleased*.
- No new dependency without a very good reason, and never one that is loaded at run time.

## Security

Report a vulnerability privately, as described in [SECURITY.md](SECURITY.md).
