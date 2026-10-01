# Test configuration for grlx-rpc
#
# Each topic-scoped test file builds as its own binary and is registered as
# its own test() target, so one failure doesn't mask another.

gtest_dep      = dependency('gtest', fallback: ['gtest', 'gtest_dep'])
gtest_main_dep = dependency('gtest_main', fallback: ['gtest', 'gtest_main_dep'])

# cereal is header-only and needed by grlx-rpc's encoder. Fall back to the
# parent project's cereal subproject when grlx-rpc is built as a subproject.
cereal_dep = dependency('cereal', fallback: ['cereal', 'cereal_dep'])

# OpenSSL is needed for TLS tests and for generating test certs in-process.
openssl_dep = dependency('openssl')

test_common_deps = [
  grlx_rpc_dep,
  cereal_dep,
  gtest_dep,
  gtest_main_dep,
  # rpc_fixture.hpp includes ssl_channel.hpp, which pulls in boost::asio::ssl
  # symbols transitively — every test binary needs libcrypto linked even if
  # it only runs over plain TCP.
  openssl_dep,
]

test_common_inc = [
  include_directories('../include'),
  include_directories('.'),
]

test_files = {
  'test_rpc':        {'sources': ['test_rpc.cpp']},
  'test_session':    {'sources': ['test_session.cpp']},
  'test_server':     {'sources': ['test_server.cpp']},
  'test_dispatcher': {'sources': ['test_dispatcher.cpp']},
  'test_ssl':        {'sources': ['test_ssl.cpp']},
  'test_security':   {'sources': ['test_security.cpp']},
  'test_credentials': {'sources': ['test_credentials.cpp']},
}

foreach name, spec : test_files
  extra_deps = spec.get('extra_deps', [])
  exe = executable(
    name,
    sources: spec['sources'],
    dependencies: test_common_deps + extra_deps,
    include_directories: test_common_inc,
  )
  test('grlx-rpc ' + name, exe, suite: 'grlx-rpc', timeout: 30)
endforeach
