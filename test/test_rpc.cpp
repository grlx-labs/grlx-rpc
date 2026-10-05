// Baseline TCP-channel regression tests.
//
// These exercise the happy paths of the RPC stack over a plain tcp_channel so
// that subsequent hardening work can refer back to them. Each test drives a
// single io_context via the rpc_fixture helper; servers bind to ephemeral
// ports so tests can run in parallel.

#include "fixtures/rpc_fixture.hpp"

#include <gtest/gtest.h>

#include <string>
#include <tuple>

namespace asio = boost::asio;
using grlx::rpc::testing::rpc_fixture;
using grlx::rpc::testing::tcp_ch;

class rpc_tcp_test : public rpc_fixture {};

TEST_F(rpc_tcp_test, roundtrip_returns_tuple) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("echo", [](int a, double b, std::string const& c) -> std::tuple<int, double, std::string> {
        return {a, b, c};
      });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);
    auto r = co_await client.invoke<std::tuple<int, double, std::string>>(
        "echo", 10, 20.0, std::string("hello"));

    EXPECT_EQ(std::get<0>(r), 10);
    EXPECT_DOUBLE_EQ(std::get<1>(r), 20.0);
    EXPECT_EQ(std::get<2>(r), "hello");
  });
}

TEST_F(rpc_tcp_test, coroutine_handler_member_and_lambda) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("answer", []() -> asio::awaitable<int> { co_return 42; });
      s.attach("add", [](int a, int b) -> asio::awaitable<int> { co_return a + b; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    EXPECT_EQ(co_await client.invoke<int>("answer"), 42);
    EXPECT_EQ(co_await client.invoke<int>("add", 2, 3), 5);
  });
}

TEST_F(rpc_tcp_test, large_payload_roundtrip_256KiB) {
  // Locks in that legitimately-large messages work today. When Phase 1 adds a
  // message-size cap, the cap must be ≥ this size or this test must be updated
  // deliberately.
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("echo_bytes", [](std::string const& payload) -> std::string { return payload; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    std::string payload(256 * 1024, 'x');
    auto        response = co_await client.invoke<std::string>("echo_bytes", payload);
    EXPECT_EQ(response.size(), payload.size());
    EXPECT_EQ(response, payload);
  });
}

// A name can resolve to several addresses — "localhost" to ::1 and 127.0.0.1
// — and a server may listen on only some of them. The fixture's server is
// IPv4-only, so where "localhost" resolves to ::1 first this connect only
// succeeds if the client moves on to the next address after a refusal.
TEST_F(rpc_tcp_test, connect_by_name_tries_every_address) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("answer", []() -> int { return 42; });
    });
    auto const port = address.substr(address.rfind(':') + 1);

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect("localhost:" + port);
    EXPECT_EQ(co_await client.invoke<int>("answer"), 42);
  });
}
