project(
  'sluice', 'c',
  version : '0.0.1',
  license : 'MIT',
  default_options : [
    'c_std=c11',
    'warning_level=3',
    'werror=true',
    'b_ndebug=if-release',
  ],
)

# Strict C11 hides POSIX; ask for the POSIX.1-2008 interfaces (sockets, poll, clock_gettime...).
add_project_arguments(
  '-DSLUICE_VERSION="@0@"'.format(meson.project_version()),
  '-D_POSIX_C_SOURCE=200809L',
  language : 'c',
)
if host_machine.system() == 'darwin'
  add_project_arguments('-D_DARWIN_C_SOURCE', language : 'c')
endif

# A sanitizer report has to fail the test that triggers it. Left alone, GCC only prints the reports of the
# undefined-behaviour sanitizer and carries on, and a test run looks green with them scrolling by.
if get_option('b_sanitize').contains('undefined')
  add_project_arguments('-fno-sanitize-recover=undefined', language : 'c')
  add_project_link_arguments('-fno-sanitize-recover=undefined', language : 'c')
endif

src_inc = include_directories('src')

# The PostgreSQL parser itself, as a library, to understand what a statement does. Pinned by hash in
# subprojects/libpg_query.wrap.
pg_query_dep = subproject('libpg_query').get_variable('libpg_query_dep')

# TLS towards the database. OpenSSL 3 or newer, found through pkg-config (LibreSSL is not supported).
ssl_dep = dependency('openssl', version : '>=3.0')

# Everything except main() lives in a library so that the tests link the real code.
core = static_library(
  'sluice-core',
  files(
    'src/buf.c',
    'src/config.c',
    'src/confirm.c',
    'src/conn.c',
    'src/json.c',
    'src/log.c',
    'src/net.c',
    'src/pg_proto.c',
    'src/policy.c',
    'src/prompt.c',
    'src/scanner.c',
    'src/server.c',
    'src/sql_check.c',
    'src/srvscan.c',
    'src/tls.c',
  ),
  include_directories : src_inc,
  dependencies : [pg_query_dep, ssl_dep],
)

# What the program and the tests link against: our code and the libraries it needs.
core_dep = declare_dependency(
  link_with : core,
  include_directories : src_inc,
  dependencies : [pg_query_dep, ssl_dep],
)

sluice = executable(
  'sluice',
  'src/main.c',
  dependencies : [core_dep],
  install : true,
)

test('version', sluice, args : ['--version'])
test('help', sluice, args : ['--help'])
test('no arguments is an error', sluice, should_fail : true)
test('a missing policy file stops sluice', sluice,
     args : ['--listen', '127.0.0.1:0', '--upstream', '127.0.0.1:5432', '--policy', '/nonexistent/policy.toml'],
     should_fail : true)

subdir('tests')
subdir('fuzz')
