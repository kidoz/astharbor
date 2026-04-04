project('ASTHarbor', ['cpp', 'c'],
        version : '1.0.0',
        default_options : ['warning_level=3', 'werror=true', 'cpp_std=c++23'])

cpp_compiler = meson.get_compiler('cpp')

llvm_dep = dependency('llvm', version : '>=14.0', required : true)

llvm_config = find_program('llvm-config', required : true)
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
  gtest_dep = dependency('gtest', main : true, required : true)

  test_sources = [
    'tests/unit/test_rule_registry.cpp',
    'tests/unit/test_cli.cpp',
    'tests/unit/test_rules.cpp'
  ]

  test_exe = executable('astharbor_test',
    test_sources,
    dependencies : [astharbor_dep, gtest_dep],
    cpp_args : ['-Wno-character-conversion']
  )
  test('unit tests', test_exe)
endif
