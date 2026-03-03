test_inc = include_directories('.')

foreach name : ['buf', 'json', 'log', 'pg_proto', 'config', 'sql_check', 'policy', 'scanner', 'net', 'srvscan', 'confirm', 'prompt']
  exe = executable(
    'test_' + name,
    'test_' + name + '.c',
    dependencies : [core_dep],
    include_directories : [test_inc],
  )
  test(name, exe)
endforeach

python = find_program('python3', required : false)
if python.found()
  # The openssl tool that goes with the library we build against (the one of the system may be too old to
  # make certificates with subject alternative names).
  openssl_prefix = ssl_dep.get_variable(pkgconfig : 'prefix', default_value : '')
  openssl_tool = openssl_prefix != '' ? openssl_prefix / 'bin' / 'openssl' : ''

  test(
    'integration',
    python,
    args : [files('integration.py'), sluice],
    env : {'SLUICE_OPENSSL' : openssl_tool},
    timeout : 180,
  )

  # Against a real PostgreSQL, in a Docker container: skipped (status 77) unless SLUICE_REAL_PG=1 is set. Run
  # it with: SLUICE_REAL_PG=1 meson test -C build realpg
  test(
    'realpg',
    python,
    args : [files('realpg.py'), sluice],
    env : {'SLUICE_OPENSSL' : openssl_tool},
    timeout : 600,
    suite : 'realpg',
  )
endif
