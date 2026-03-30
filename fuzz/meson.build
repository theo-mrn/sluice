# The fuzz targets (targets.c) and a small deterministic driver (driver.c) that mutates the seed corpus. The
# driver works with any compiler; it is what the test below runs, under the sanitizers of the build.
fuzz_targets = static_library(
  'sluice-fuzz-targets',
  'targets.c',
  dependencies : [core_dep],
)

fuzz_driver = executable(
  'fuzz_driver',
  'driver.c',
  link_with : fuzz_targets,
  dependencies : [core_dep],
)

corpus = meson.current_source_dir() / 'corpus'

# A short, fixed-seed run: it replays every seed and 20 000 mutations in a few seconds. A longer run is
#   build/fuzz/fuzz_driver -t 600 -s 7 fuzz/corpus
test(
  'fuzz smoke',
  fuzz_driver,
  args : ['-n', '20000', '-s', '1', '-o', 'fuzz-last-input-smoke', corpus],
  timeout : 180,
)

# With a compiler that ships libFuzzer (clang from LLVM, not Apple's), -Dfuzzer=enabled also builds the
# targets as a coverage-guided fuzzer. Build everything with -fsanitize=fuzzer-no-link for it to see
# coverage, for example CFLAGS=-fsanitize=fuzzer-no-link meson setup build-fuzz -Dfuzzer=enabled.
# This part could not be exercised on the machine it was written on.
if get_option('fuzzer').allowed()
  if meson.get_compiler('c').has_link_argument('-fsanitize=fuzzer')
    executable(
      'fuzz_libfuzzer',
      'targets.c',
      c_args : ['-fsanitize=fuzzer-no-link'],
      link_args : ['-fsanitize=fuzzer'],
      dependencies : [core_dep],
    )
  elif get_option('fuzzer').enabled()
    error('-Dfuzzer=enabled needs a compiler whose runtime has libFuzzer (-fsanitize=fuzzer)')
  endif
endif
