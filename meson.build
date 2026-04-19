project(
  'sluice', 'c',
  version : '0.27.0',
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

# Which commit this is, for `sluice --version`: given, or asked of git, or unknown (a source archive).
commit = get_option('commit')
if commit == ''
  git = find_program('git', required : false)
  commit = 'unknown'
  if git.found()
    rev = run_command(git, '-C', meson.project_source_root(), 'rev-parse', '--short=9', 'HEAD', check : false)
    if rev.returncode() == 0
      commit = rev.stdout().strip()
      dirty = run_command(git, '-C', meson.project_source_root(), 'status', '--porcelain', '--untracked-files=no', check : false)
      if dirty.returncode() == 0 and dirty.stdout().strip() != ''
        commit += '-dirty'
      endif
    endif
  endif
endif
add_project_arguments(
  '-DSLUICE_COMMIT="@0@"'.format(commit),
  '-DSLUICE_STATIC=@0@'.format(get_option('static') ? 1 : 0),
  language : 'c',
)

src_inc = include_directories('src')

# The PostgreSQL parser itself, as a library, to understand what a statement does. Pinned by hash in
# subprojects/libpg_query.wrap.
pg_query_dep = subproject('libpg_query').get_variable('libpg_query_dep')

# TLS towards the database. OpenSSL 3 or newer, found through pkg-config (LibreSSL is not supported).
ssl_dep = dependency('openssl', version : '>=3.0', static : get_option('static'))

# A fully static program is only sensible with musl: glibc's name lookups load libraries at run time.
static_link_args = []
if get_option('static') and host_machine.system() == 'linux'
  static_link_args = ['-static']
endif

# Everything except main() lives in a library so that the tests link the real code.
core = static_library(
  'sluice-core',
  files(
    'src/budget.c',
    'src/buf.c',
    'src/check.c',
    'src/config.c',
    'src/confirm.c',
    'src/conn.c',
    'src/extstate.c',
    'src/journal.c',
    'src/learn.c',
    'src/logverify.c',
    'src/admin.c',
    'src/events.c',
    'src/metrics.c',
    'src/testpolicy.c',
    'src/json.c',
    'src/log.c',
    'src/mask.c',
    'src/net.c',
    'src/pg_proto.c',
    'src/policy.c',
    'src/prompt.c',
    'src/scanner.c',
    'src/server.c',
    'src/sql_check.c',
    'src/srvscan.c',
    'src/tls.c',
    'src/undo.c',
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
  link_args : static_link_args,
  install : true,
)

# What `meson install` puts beside the binary: the documents, the example policies, the webhook command.
docdir = get_option('datadir') / 'doc' / 'sluice'
install_data(
  'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'README.md', 'SECURITY.md',
  install_dir : docdir,
)
install_subdir('docs', install_dir : docdir, strip_directory : false)
install_data(
  'examples/policies/agent-readonly.toml', 'examples/policies/agent-readonly.tests',
  'examples/policies/app-guarded.toml', 'examples/policies/app-guarded.tests',
  install_dir : get_option('datadir') / 'sluice' / 'examples' / 'policies',
)
install_data(
  'tools/webhook.sh',
  install_dir : get_option('datadir') / 'sluice',
  install_mode : 'rwxr-xr-x',
)

test('version', sluice, args : ['--version'])
foreach example : ['agent-readonly', 'app-guarded']
  test(
    'example policy ' + example,
    sluice,
    args : ['--test-policy', files('examples/policies' / example + '.toml'), files('examples/policies' / example + '.tests')],
  )
endforeach
test('help', sluice, args : ['--help'])
test(
  'policy as code',
  sluice,
  args : ['--test-policy', files('tests/policies/example.toml'), files('tests/policies/example.tests')],
)
test('no arguments is an error', sluice, should_fail : true)
test('a missing policy file stops sluice', sluice,
     args : ['--listen', '127.0.0.1:0', '--upstream', '127.0.0.1:5432', '--policy', '/nonexistent/policy.toml'],
     should_fail : true)

subdir('tests')
subdir('fuzz')
