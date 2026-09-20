// Server-level regression tests: multi-client concurrency, notifications,
// and graceful shutdown.

#include "fixtures/rpc_fixture.hpp"

#include <grlx/rpc/security.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace asio = boost::asio;
using grlx::rpc::testing::rpc_fixture;
using grlx::rpc::testing::tcp_ch;

class rpc_server_test : public rpc_fixture {};

namespace {

// A client that has claimed a logical session id, plus whatever it received
// on the "tick" notification. notify_session / notify_sessions route on the
// logical id, which is normally stamped by an application-level handshake
// (entt_ext::sync does it in handle_handshake_request); "login" below is the
// minimal stand-in.
struct identified_client {
  std::shared_ptr<grlx::rpc::client<tcp_ch>> rpc;
  std::shared_ptr<std::string>               received = std::make_shared<std::string>();
};

inline void attach_login(grlx::rpc::server<tcp_ch>& s) {
  s.attach("login", [](std::string id) -> bool {
    // The context is only valid in the synchronous prefix of a handler, which
    // is all this needs (see grlx/rpc/security.hpp).
    auto const* cc = grlx::rpc::current_call_context();
    if (cc == nullptr || !cc->set_logical_session_id) {
      return false;
    }
    cc->set_logical_session_id(std::move(id));
    return true;
  });
}

inline auto connect_identified(std::string const& address, std::string const& session_id)
    -> asio::awaitable<identified_client> {
  identified_client c;
  c.rpc = std::make_shared<grlx::rpc::client<tcp_ch>>();
  co_await c.rpc->connect(address);
  c.rpc->register_notification_handler("tick", [received = c.received](std::string const& payload) {
    *received = payload;
  });
  bool ok = co_await c.rpc->template invoke<bool>("login", session_id);
  EXPECT_TRUE(ok) << "login failed for " << session_id;
  co_return c;
}

inline auto sleep_for_ms(int ms) -> asio::awaitable<void> {
  asio::steady_timer t(co_await asio::this_coro::executor);
  t.expires_after(std::chrono::milliseconds(ms));
  co_await t.async_wait(asio::use_awaitable);
}

} // namespace

// notify_sessions is the fan-out form of notify_session: one encode and one
// sessions_strand_ hop for the whole target set instead of one of each per
// target. The routing contract must stay identical to notify_session's.
TEST_F(rpc_server_test, notify_sessions_delivers_only_to_listed_sessions) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) { attach_login(s); });

    auto a = co_await connect_identified(address, "sess-a");
    auto b = co_await connect_identified(address, "sess-b");
    auto c = co_await connect_identified(address, "sess-c");

    // Let each client's notification-handling coroutine register with its
    // session before the server sends (see notification_reaches_connected_client).
    co_await sleep_for_ms(50);

    co_await server.notify_sessions(std::unordered_set<std::string>{"sess-a", "sess-c"}, "tick",
                                    std::string("fan-out"));

    for (int attempt = 0; attempt < 100; ++attempt) {
      co_await sleep_for_ms(10);
      if (!a.received->empty() && !c.received->empty()) break;
    }
    // Give a non-target one more full grace period to (incorrectly) arrive.
    co_await sleep_for_ms(50);

    EXPECT_EQ(*a.received, "fan-out");
    EXPECT_EQ(*c.received, "fan-out");
    EXPECT_TRUE(b.received->empty()) << "unlisted session received: " << *b.received;
  });
}

// The single-target case must be byte-for-byte what notify_session produces —
// nexus's camera media push switched from one to the other without a wire
// version bump, so a divergence here would silently break every client.
TEST_F(rpc_server_test, notify_sessions_single_target_matches_notify_session) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) { attach_login(s); });

    auto a = co_await connect_identified(address, "sess-a");
    auto b = co_await connect_identified(address, "sess-b");
    co_await sleep_for_ms(50);

    co_await server.notify_session("sess-a", "tick", std::string("same-payload"));
    co_await server.notify_sessions(std::unordered_set<std::string>{"sess-b"}, "tick",
                                    std::string("same-payload"));

    for (int attempt = 0; attempt < 100; ++attempt) {
      co_await sleep_for_ms(10);
      if (!a.received->empty() && !b.received->empty()) break;
    }

    EXPECT_EQ(*a.received, "same-payload");
    EXPECT_EQ(*b.received, *a.received);
  });
}

TEST_F(rpc_server_test, notify_sessions_ignores_empty_and_unknown_targets) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) { attach_login(s); });

    auto a = co_await connect_identified(address, "sess-a");
    co_await sleep_for_ms(50);

    co_await server.notify_sessions(std::unordered_set<std::string>{}, "tick", std::string("empty"));
    co_await server.notify_sessions(std::unordered_set<std::string>{"nobody-here"}, "tick",
                                    std::string("unknown"));

    co_await sleep_for_ms(100);
    EXPECT_TRUE(a.received->empty()) << "delivered despite no matching target: " << *a.received;

    // Still healthy afterwards — the no-op paths must not wedge the session.
    co_await server.notify_sessions(std::unordered_set<std::string>{"sess-a"}, "tick", std::string("real"));
    for (int attempt = 0; attempt < 100; ++attempt) {
      co_await sleep_for_ms(10);
      if (!a.received->empty()) break;
    }
    EXPECT_EQ(*a.received, "real");
  });
}

TEST_F(rpc_server_test, notification_reaches_connected_client) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto&) {});

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    auto received = std::make_shared<std::string>();
    client.register_notification_handler("tick", [received](std::string const& payload) {
      *received = payload;
    });

    // Give the client's notification-handling coroutine time to register with
    // its session before the server sends.
    asio::steady_timer warmup(co_await asio::this_coro::executor);
    warmup.expires_after(std::chrono::milliseconds(50));
    co_await warmup.async_wait(asio::use_awaitable);

    co_await server.notify("tick", std::string("hello"));

    for (int attempt = 0; attempt < 100; ++attempt) {
      asio::steady_timer t(co_await asio::this_coro::executor);
      t.expires_after(std::chrono::milliseconds(10));
      co_await t.async_wait(asio::use_awaitable);
      if (!received->empty()) break;
    }
    EXPECT_EQ(*received, "hello");
  });
}

TEST_F(rpc_server_test, multi_client_concurrent_calls) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("double", [](int x) -> int { return x * 2; });
    });

    constexpr int kClients      = 5;
    constexpr int kCallsPerClient = 10;

    std::vector<std::shared_ptr<grlx::rpc::client<tcp_ch>>> clients;
    for (int i = 0; i < kClients; ++i) {
      auto c = std::make_shared<grlx::rpc::client<tcp_ch>>();
      co_await c->connect(address);
      clients.push_back(c);
    }

    auto executor = co_await asio::this_coro::executor;

    // Fire off every call in parallel, collect them sequentially.
    using namespace asio::experimental::awaitable_operators;

    std::atomic<int> successes{0};
    std::atomic<int> failures{0};

    for (int ci = 0; ci < kClients; ++ci) {
      for (int k = 0; k < kCallsPerClient; ++k) {
        int expected = (ci * 100 + k) * 2;
        int input    = ci * 100 + k;
        asio::co_spawn(
            executor,
            [c = clients[ci], input, expected, &successes, &failures]() -> asio::awaitable<void> {
              try {
                int got = co_await c->invoke<int>("double", input);
                if (got == expected) ++successes;
                else ++failures;
              } catch (...) {
                ++failures;
              }
              co_return;
            },
            asio::detached);
      }
    }

    // Wait for completions.
    for (int attempt = 0; attempt < 500; ++attempt) {
      asio::steady_timer t(executor);
      t.expires_after(std::chrono::milliseconds(10));
      co_await t.async_wait(asio::use_awaitable);
      if (successes + failures >= kClients * kCallsPerClient) break;
    }

    EXPECT_EQ(successes.load(), kClients * kCallsPerClient);
    EXPECT_EQ(failures.load(), 0);
  });
}

TEST_F(rpc_server_test, server_stop_closes_all_sessions) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", []() -> int { return 0; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);
    EXPECT_EQ(co_await client.invoke<int>("ping"), 0);

    // Wait until the server has recorded the session.
    for (int attempt = 0; attempt < 50; ++attempt) {
      asio::steady_timer t(co_await asio::this_coro::executor);
      t.expires_after(std::chrono::milliseconds(10));
      co_await t.async_wait(asio::use_awaitable);
      if (co_await server.session_count() >= 1u) break;
    }
    // Can't use ASSERT_EQ inside a coroutine (macro expands to `return;`).
    auto count = co_await server.session_count();
    EXPECT_EQ(count, 1u);
    if (count != 1u) {
      co_return;  // bail out cleanly
    }

    co_await server.stop();
    EXPECT_EQ(co_await server.session_count(), 0u);
  });
}
