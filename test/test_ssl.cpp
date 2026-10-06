// Baseline SSL/TLS roundtrip test over ssl_channel.
//
// This locks in the current (pre-hardening) behavior:
//   - server presents a cert signed by the test CA
//   - client uses verify_none so the handshake succeeds without strict mTLS
// When Phase 1 enforces mTLS by default, this test will change to the
// mTLS-positive variant and a new negative test will be added.

#include "fixtures/rpc_fixture.hpp"

#include <gtest/gtest.h>

#include <format>
#include <string>

namespace asio = boost::asio;
using grlx::rpc::testing::make_insecure_client_ctx;
using grlx::rpc::testing::make_server_ctx;
using grlx::rpc::testing::rpc_fixture;
using grlx::rpc::testing::shared_cert_set;
using grlx::rpc::testing::ssl_ch;

class rpc_ssl_test : public rpc_fixture {};

TEST_F(rpc_ssl_test, tls_roundtrip_echo) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{make_server_ctx(certs.server, certs.primary_ca)};
    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("echo", [](std::string const& payload) -> std::string { return payload; });
    });

    grlx::rpc::client<ssl_ch> client{make_insecure_client_ctx()};
    co_await client.connect(endpoint);

    auto response = co_await client.invoke<std::string>("echo", std::string("tls-ping"));
    EXPECT_EQ(response, "tls-ping");
  });
}

// See rpc_tcp_test.connect_by_name_tries_every_address: the IPv4-only server
// is reached by name even where "localhost" resolves to ::1 first.
TEST_F(rpc_ssl_test, connect_by_name_tries_every_address) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{make_server_ctx(certs.server, certs.primary_ca)};
    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("echo", [](std::string const& payload) -> std::string { return payload; });
    });

    grlx::rpc::client<ssl_ch> client{make_insecure_client_ctx()};
    co_await client.connect(std::format("localhost:{}", endpoint.port()));
    EXPECT_EQ(co_await client.invoke<std::string>("echo", std::string("by-name")), "by-name");
  });
}
