project('ASTHarbor', ['cpp', 'c'],
        version : '1.0.0',
        meson_version : '>= 1.1.0',
        default_options : ['warning_level=3', 'werror=true', 'cpp_std=c++23'])

cpp_compiler = meson.get_compiler('cpp')

llvm_dep = dependency('llvm', version : '>=14.0', required : true)

llvm_config = find_program('llvm-config', 'llvm-config-23', 'llvm-config-22', 'llvm-config-21', 'llvm-config-20', 'llvm-config-19', 'llvm-config-18', 'llvm-config-17', 'llvm-config-16', 'llvm-config-15', 'llvm-config-14', required : true)
llvm_libdir = run_command(llvm_config, '--libdir', check : true).stdout().strip()
llvm_includedir = run_command(llvm_config, '--includedir', check : true).stdout().strip()

clang_cpp_lib = cpp_compiler.find_library('clang-cpp', dirs : llvm_libdir, required : true)

clang_deps = [
  clang_cpp_lib,
]

include_dirs = include_directories('include')

extra_args = ['-isystem' + llvm_includedir, '-fno-rtti']

core_sources = [
  'src/core/rule_registry.cpp',
  'src/core/analyzer.cpp',
  'src/emitters/json_emitter.cpp',
  'src/emitters/text_emitter.cpp',
  'src/emitters/sarif_emitter.cpp',
]

libastharbor = static_library('astharbor',
  core_sources,
  include_directories : include_dirs,
  dependencies : [llvm_dep] + clang_deps,
  cpp_args : extra_args
)

astharbor_dep = declare_dependency(
  link_with : libastharbor,
  include_directories : include_dirs,
  dependencies : [llvm_dep] + clang_deps,
  compile_args : extra_args
)

cli_sources = [
  'src/cli/main.cpp'
]

executable('astharbor',
  cli_sources,
  dependencies : astharbor_dep,
  install : true
)

if get_option('tests')
  catch2_dep = dependency('catch2-with-main', required : true, default_options: ['tests=false'])

  test_sources = [
    'tests/unit/test_rule_registry.cpp',
    'tests/unit/test_cli.cpp',
    'tests/unit/test_rules.cpp'
  ]

  # `-Wno-character-conversion` silences a Catch2 noise warning but
  # only exists in clang 19+; omit it on older toolchains rather than
  # failing `-Werror`.
  test_cpp_args = []
  if cpp_compiler.has_argument('-Wno-character-conversion')
    test_cpp_args += '-Wno-character-conversion'
  endif

  test_exe = executable('astharbor_test',
    test_sources,
    dependencies : [astharbor_dep, catch2_dep],
    cpp_args : test_cpp_args
  )
  test('unit tests', test_exe)
endif
