// Phase 1 hardening tests — red-then-green.
//
// Each test drives a single feature of the hardened RPC stack. They are all
// skeptical of the wire: they open raw TCP sockets, send malformed framing,
// or wait for the server to give up on bad peers. Baseline happy-path
// coverage lives in test_rpc.cpp / test_ssl.cpp.

#include "fixtures/rpc_fixture.hpp"

#include <grlx/rpc/security.hpp>
#include <grlx/rpc/ssl_channel.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace asio = boost::asio;
using grlx::rpc::testing::make_server_ctx;
using grlx::rpc::testing::rpc_fixture;
using grlx::rpc::testing::shared_cert_set;
using grlx::rpc::testing::ssl_ch;
using grlx::rpc::testing::tcp_ch;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

class rpc_security_test : public rpc_fixture {};

namespace {

// Frame a grlx-rpc header by hand for use in DoS / malformed-input tests.
// Matches session.hpp's layout exactly:
//   [magic][size][type|call_id][call_id][token]
// but we only need magic, size, and type for the size-cap test.
struct wire_header {
  std::uint64_t magic;
  std::uint64_t msg_size;
  std::uint64_t msg_type;
  std::uint64_t call_id;
  std::uint64_t user_token;
};
static_assert(sizeof(wire_header) == 40, "wire_header must match grlx-rpc framing");

constexpr std::uint64_t kMagic                = 0xBADC0FFEE;
constexpr std::uint64_t kMsgTypeRequestShifted = static_cast<std::uint64_t>(1) << 32;  // msg_type::request

}  // namespace

// A slow peer that opens a raw TCP connection but never sends a TLS
// ClientHello must have the server abandon the handshake within the
// configured handshake_timeout. The accept loop must recover and continue
// serving legitimate clients.
TEST_F(rpc_security_test, handshake_timeout_drops_slow_peer) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    // 300 ms handshake budget. Well under the test timeout; generous enough
    // to avoid flakes on a loaded CI box.
    constexpr auto kHandshakeTimeout = 300ms;

    grlx::rpc::server<ssl_ch> server{
        make_server_ctx(certs.server, certs.primary_ca),
        kHandshakeTimeout};
    auto endpoint = co_await start_ssl_server(server, [](auto&) {});

    auto executor = co_await asio::this_coro::executor;

    // Open a raw TCP socket, complete the TCP handshake, then just sit there.
    tcp::socket slow_socket(executor);
    co_await slow_socket.async_connect(endpoint, asio::use_awaitable);
    EXPECT_TRUE(slow_socket.is_open());

    // Read a byte — we expect EOF / connection_reset once the server's
    // handshake timer fires. Cap our own wait at kHandshakeTimeout × 3
    // so a broken implementation fails fast rather than hanging.
    std::array<std::byte, 1> scratch{};
    boost::system::error_code read_ec;
    asio::steady_timer         read_timer(executor);
    read_timer.expires_after(kHandshakeTimeout * 3);

    using namespace asio::experimental::awaitable_operators;
    auto result = co_await (
        slow_socket.async_read_some(asio::buffer(scratch), asio::as_tuple(asio::use_awaitable))
        || read_timer.async_wait(asio::use_awaitable));

    if (result.index() == 0) {
      auto [ec, bytes] = std::get<0>(result);
      read_ec = ec;
      EXPECT_EQ(bytes, 0u) << "server should close, not send data";
    } else {
      ADD_FAILURE() << "server did not close the slow connection within "
                    << (kHandshakeTimeout * 3).count() << "ms";
    }
    EXPECT_TRUE(read_ec == asio::error::eof || read_ec == asio::error::connection_reset)
        << "unexpected close reason: " << read_ec.message();

    // Accept loop must still be alive — a fresh, well-behaved TLS client
    // should complete a full RPC roundtrip.
    grlx::rpc::server<ssl_ch>* sp = &server;  // silence unused-warning
    (void)sp;

    grlx::rpc::client<ssl_ch> client{grlx::rpc::testing::make_insecure_client_ctx()};
    co_await client.connect(endpoint);
    EXPECT_TRUE(client.is_connected());
  });
}

// A peer that forges a header claiming a 1 GiB body must be rejected before
// any buffer is resized — the server must not even attempt the allocation.
// We assert this observationally: the server closes the connection and never
// reads the fake body (verified by the connection failing on any further
// write from our side).
TEST_F(rpc_security_test, oversized_message_is_rejected) {
  run([this]() -> asio::awaitable<void> {
    constexpr std::uint64_t kLimit  = 4 * 1024;     // 4 KiB
    constexpr std::uint64_t kBogus  = 1ull << 30;   // 1 GiB — would OOM if honored

    grlx::rpc::session_limits limits{.max_message_bytes = kLimit};
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("echo", [](std::string const& p) { return p; });
    });
    server.set_session_limits(limits);

    auto executor = co_await asio::this_coro::executor;

    // Parse back into an endpoint.
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"),
                     static_cast<unsigned short>(server.channel().endpoint().port())};

    tcp::socket bad(executor);
    co_await bad.async_connect(ep, asio::use_awaitable);

    wire_header hdr{kMagic, kBogus, kMsgTypeRequestShifted, 0xDEADBEEFull, 1ull};
    co_await asio::async_write(bad, asio::buffer(&hdr, sizeof(hdr)), asio::use_awaitable);

    // Server must reject the oversized framing without allocating the body.
    // It is allowed (and preferred) to send back a 40-byte msg_type::error
    // header so the peer knows why it was dropped. It must then close the
    // connection — a second read must yield EOF.
    wire_header err_frame{};
    auto [read_ec, read_bytes] = co_await asio::async_read(
        bad, asio::buffer(&err_frame, sizeof(err_frame)),
        asio::transfer_exactly(sizeof(err_frame)),
        asio::as_tuple(asio::use_awaitable));

    if (read_ec == asio::error::eof || read_ec == asio::error::connection_reset) {
      // Immediate close, no error frame — also an acceptable outcome.
    } else {
      EXPECT_FALSE(read_ec) << "error reading error frame: " << read_ec.message();
      EXPECT_EQ(read_bytes, sizeof(err_frame));
      EXPECT_EQ(err_frame.magic, kMagic);
      EXPECT_EQ(err_frame.msg_type >> 32, 4u) << "expected msg_type::error (4)";
      EXPECT_EQ(err_frame.msg_size, 0u) << "error frame must have no body";
    }

    // Subsequent read must close: the server must not reuse this session.
    std::array<std::byte, 1> eof_scratch{};
    asio::steady_timer        wait_timer(executor);
    wait_timer.expires_after(1000ms);

    using namespace asio::experimental::awaitable_operators;
    auto tail = co_await (
        bad.async_read_some(asio::buffer(eof_scratch), asio::as_tuple(asio::use_awaitable))
        || wait_timer.async_wait(asio::use_awaitable));

    EXPECT_EQ(tail.index(), 0u) << "server did not close the socket within 1s";
    if (tail.index() != 0) co_return;
    auto [tail_ec, tail_bytes] = std::get<0>(tail);
    EXPECT_EQ(tail_bytes, 0u);
    EXPECT_TRUE(tail_ec == asio::error::eof || tail_ec == asio::error::connection_reset)
        << "unexpected tail close reason: " << tail_ec.message();

    // Accept loop must still be alive.
    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);
    EXPECT_EQ(co_await client.invoke<std::string>("echo", std::string{"ok"}), "ok");
  });
}

// An established session that sees no bytes at all for longer than
// idle_timeout must be reaped. This is the primary defense against zombie
// mobile sockets behind NAT where the OS never surfaces the dead peer.
TEST_F(rpc_security_test, idle_timeout_closes_session) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::session_limits limits{.idle_timeout = 200ms};
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto&) {});
    server.set_session_limits(limits);

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    auto executor = co_await asio::this_coro::executor;

    // Give the server a moment to record the session.
    asio::steady_timer warmup(executor);
    warmup.expires_after(50ms);
    co_await warmup.async_wait(asio::use_awaitable);

    auto before = co_await server.session_count();
    EXPECT_EQ(before, 1u);

    // Sit idle longer than idle_timeout + slack. Server must reap the session.
    asio::steady_timer wait(executor);
    wait.expires_after(600ms);
    co_await wait.async_wait(asio::use_awaitable);

    auto after = co_await server.session_count();
    EXPECT_EQ(after, 0u) << "server failed to drop idle session";
  });
}

// Once a valid header is received, the peer must deliver the declared body
// within message_read_timeout or be dropped. Defends against slow-loris on
// the body read (where handshake + header succeed but the body drips).
TEST_F(rpc_security_test, body_read_timeout_drops_peer) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::session_limits limits{
        .max_message_bytes    = 1ull << 20,
        .idle_timeout         = 10s,          // plenty — not the deadline we're testing
        .message_read_timeout = 250ms,
    };
    grlx::rpc::server<tcp_ch> server;
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("echo", [](std::string const& p) { return p; });
    });
    server.set_session_limits(limits);

    auto executor = co_await asio::this_coro::executor;
    tcp::endpoint ep{asio::ip::make_address("127.0.0.1"),
                     static_cast<unsigned short>(server.channel().endpoint().port())};

    tcp::socket slow(executor);
    co_await slow.async_connect(ep, asio::use_awaitable);

    // Send a well-formed header promising 128 body bytes, then never deliver
    // them. Server's body read must time out and close.
    wire_header hdr{kMagic, 128, kMsgTypeRequestShifted, 0xCAFEULL, 1ULL};
    co_await asio::async_write(slow, asio::buffer(&hdr, sizeof(hdr)), asio::use_awaitable);

    // Wait long enough for the body-read deadline to fire. Server may send
    // back an error frame or may close directly — both are acceptable.
    // Give the server's 250ms body-read deadline enough slack to fire.
    asio::steady_timer drain_timer(executor);
    drain_timer.expires_after(600ms);
    co_await drain_timer.async_wait(asio::use_awaitable);

    std::array<std::byte, 64> scratch{};
    boost::system::error_code probe_ec;
    auto [pec, pbytes] = co_await slow.async_read_some(
        asio::buffer(scratch), asio::as_tuple(asio::use_awaitable));
    EXPECT_TRUE(pec == asio::error::eof || pec == asio::error::connection_reset
                || pbytes == sizeof(wire_header))
        << "expected EOF or a 40-byte error frame, got ec=" << pec.message()
        << " bytes=" << pbytes;
  });
}

// ---- mTLS ----
//
// With require_client_cert=true on the server, a client that presents no cert
// must fail at the TLS handshake — before any RPC framing is exchanged.
TEST_F(rpc_security_test, mtls_rejects_missing_client_cert) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{
        grlx::rpc::make_server_context(certs.server.cert_pem, certs.server.key_pem,
                                       certs.primary_ca.cert_pem)};
    auto endpoint = co_await start_ssl_server(server, [](auto&) {});

    // Client provides no cert/key, only trusts the CA.
    grlx::rpc::client<ssl_ch> client{
        grlx::rpc::make_client_context("", "", certs.primary_ca.cert_pem)};

    bool threw_connect = false;
    try {
      co_await client.connect(endpoint);
    } catch (std::exception const&) {
      threw_connect = true;
    }

    // TLS 1.3 allows `async_handshake` to return success on the client side
    // even when the server will reject the empty-cert case — the server's
    // reject arrives on the first read. So additionally probe by issuing an
    // RPC; it must fail because the server must have torn the session down.
    bool invoke_failed = false;
    if (!threw_connect) {
      try {
        co_await client.invoke<int>("ping");
      } catch (std::exception const&) {
        invoke_failed = true;
      }
    }

    EXPECT_TRUE(threw_connect || invoke_failed)
        << "server must reject a missing client cert, either at handshake or on first RPC";
  });
}

// A client presenting a cert signed by an *untrusted* CA must also fail.
TEST_F(rpc_security_test, mtls_rejects_unknown_ca_cert) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{
        grlx::rpc::make_server_context(certs.server.cert_pem, certs.server.key_pem,
                                       certs.primary_ca.cert_pem)};
    auto endpoint = co_await start_ssl_server(server, [](auto&) {});

    // Rogue cert is signed by rogue_ca, which the server does not trust.
    grlx::rpc::client<ssl_ch> client{
        grlx::rpc::make_client_context(certs.rogue_client.cert_pem,
                                       certs.rogue_client.key_pem,
                                       certs.primary_ca.cert_pem)};

    bool threw_connect = false;
    try {
      co_await client.connect(endpoint);
    } catch (std::exception const&) {
      threw_connect = true;
    }
    bool invoke_failed = false;
    if (!threw_connect) {
      try {
        co_await client.invoke<int>("ping");
      } catch (std::exception const&) {
        invoke_failed = true;
      }
    }
    EXPECT_TRUE(threw_connect || invoke_failed)
        << "server must reject an untrusted-CA client cert";
  });
}

// A client with a CA-signed cert completes the handshake. The server's
// on_session_open hook sees a non-empty SHA-256 fingerprint.
TEST_F(rpc_security_test, mtls_accepts_valid_client_and_exposes_fingerprint) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{
        grlx::rpc::make_server_context(certs.server.cert_pem, certs.server.key_pem,
                                       certs.primary_ca.cert_pem)};

    std::string captured_fp;
    std::string captured_addr;
    server.on_session_open([&](grlx::rpc::session_info const& info) {
      captured_fp   = info.peer_fingerprint;
      captured_addr = info.peer_address;
    });

    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("ping", []() -> int { return 1; });
    });

    grlx::rpc::client<ssl_ch> client{
        grlx::rpc::make_client_context(certs.client_a.cert_pem, certs.client_a.key_pem,
                                       certs.primary_ca.cert_pem)};
    co_await client.connect(endpoint);
    EXPECT_TRUE(client.is_connected());
    EXPECT_EQ(co_await client.invoke<int>("ping"), 1);

    // Wait for the on_session_open hook to fire (runs on server's strand).
    for (int i = 0; i < 50 && captured_fp.empty(); ++i) {
      asio::steady_timer t(co_await asio::this_coro::executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
    }

    EXPECT_EQ(captured_fp.size(), 64u) << "SHA-256 fingerprint should be 64 hex chars";
    // All hex, lowercase.
    for (char c : captured_fp) {
      EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) << "got: " << c;
    }
    EXPECT_FALSE(captured_addr.empty()) << "peer_address should be recorded";
  });
}

// With tls13_only=true on the server, a client that caps its negotiation at
// TLS 1.2 must be rejected during handshake.
TEST_F(rpc_security_test, tls13_only_rejects_tls12_client) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{
        grlx::rpc::make_server_context(certs.server.cert_pem, certs.server.key_pem,
                                       certs.primary_ca.cert_pem)};
    auto endpoint = co_await start_ssl_server(server, [](auto&) {});

    // Build a deliberately-legacy client context: still mTLS-capable, but
    // max version pinned to TLS 1.2 so the handshake cannot agree on 1.3.
    auto ctx = grlx::rpc::make_client_context(
        certs.client_a.cert_pem, certs.client_a.key_pem, certs.primary_ca.cert_pem,
        grlx::rpc::tls_config{.require_client_cert = true, .verify_server_cert = true, .tls13_only = false});
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_2_VERSION);

    grlx::rpc::client<ssl_ch> client{std::move(ctx)};
    bool                      threw = false;
    try {
      co_await client.connect(endpoint);
    } catch (std::exception const&) {
      threw = true;
    }
    EXPECT_TRUE(threw) << "server should not accept TLS 1.2-only client";
  });
}

// ---- pre-dispatch auth hook ----
//
// When the auth callback denies, the handler MUST NOT run. The server
// replies with a generic error; the client sees an exception on invoke.
TEST_F(rpc_security_test, dispatch_denies_when_callback_rejects) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    std::atomic<int>          handler_invocations{0};
    server.set_auth_callback([](grlx::rpc::client_context const&, std::string const&) {
      return grlx::rpc::auth_result{.allow = false, .deny_reason = "nope"};
    });
    auto address = co_await start_tcp_server(server, [&](auto& s) {
      s.attach("secret", grlx::rpc::visibility::authenticated,
               [&handler_invocations]() -> int {
                 ++handler_invocations;
                 return 42;
               });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    bool threw = false;
    try {
      co_await client.invoke<int>("secret");
    } catch (std::exception const&) {
      threw = true;
    }
    EXPECT_TRUE(threw) << "denied call must surface as an error on the client";
    EXPECT_EQ(handler_invocations.load(), 0) << "handler must never be invoked on deny";
  });
}

// visibility::public_ endpoints bypass the callback entirely — useful for
// login / version probe endpoints that must work pre-auth.
TEST_F(rpc_security_test, public_method_bypasses_auth_callback) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    std::atomic<int>          cb_invocations{0};
    server.set_auth_callback([&](grlx::rpc::client_context const&, std::string const&) {
      ++cb_invocations;
      return grlx::rpc::auth_result{.allow = false, .deny_reason = "never reached"};
    });
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::public_, []() -> int { return 7; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    EXPECT_EQ(co_await client.invoke<int>("ping"), 7);
    EXPECT_EQ(cb_invocations.load(), 0) << "auth callback must not be consulted for public_ methods";
  });
}

// visibility::admin requires the callback to return BOTH allow AND is_admin.
// A non-admin identity is rejected even if the callback otherwise allows.
TEST_F(rpc_security_test, admin_method_requires_is_admin_flag) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    std::atomic<bool>         grant_admin{false};
    server.set_auth_callback([&](grlx::rpc::client_context const&, std::string const&) {
      return grlx::rpc::auth_result{.allow = true, .is_admin = grant_admin.load()};
    });
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("danger", grlx::rpc::visibility::admin, []() -> int { return 1; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    bool non_admin_rejected = false;
    try {
      co_await client.invoke<int>("danger");
    } catch (std::exception const&) {
      non_admin_rejected = true;
    }
    EXPECT_TRUE(non_admin_rejected) << "admin endpoint must reject non-admin callers";

    grant_admin.store(true);
    EXPECT_EQ(co_await client.invoke<int>("danger"), 1)
        << "admin endpoint must accept admin callers";
  });
}

// ---- connection caps ----
//
// The global cap must drop extra TCP accepts without ever paying for a
// handshake. Sessions already in the set stay; the over-cap connection
// should not appear in session_count.
TEST_F(rpc_security_test, global_session_cap_rejects_extras) {
  run([this]() -> asio::awaitable<void> {
    constexpr std::size_t kCap = 3;

    grlx::rpc::server<tcp_ch> server;
    server.set_server_limits({.max_concurrent_sessions = kCap,
                              .max_sessions_per_ip     = kCap + 10});
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::public_, []() -> int { return 1; });
    });

    std::vector<std::shared_ptr<grlx::rpc::client<tcp_ch>>> clients;
    for (std::size_t i = 0; i < kCap; ++i) {
      auto c = std::make_shared<grlx::rpc::client<tcp_ch>>();
      co_await c->connect(address);
      clients.push_back(c);
    }

    // Give the accept loop time to register all three.
    auto executor = co_await asio::this_coro::executor;
    for (int i = 0; i < 50; ++i) {
      asio::steady_timer t(executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
      if (co_await server.session_count() >= kCap) break;
    }
    EXPECT_EQ(co_await server.session_count(), kCap);

    // Try one more. The TCP connect itself may succeed (kernel handshakes
    // the SYN/ACK), but the server will close immediately without starting
    // a session — so session_count must stay at the cap.
    grlx::rpc::client<tcp_ch> extra;
    try { co_await extra.connect(address); } catch (...) {}

    for (int i = 0; i < 25; ++i) {
      asio::steady_timer t(executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
    }
    EXPECT_EQ(co_await server.session_count(), kCap)
        << "global cap must prevent session count from growing";

    // Drop the caller-held refs cleanly before the fixture tears down.
    for (auto& c : clients) c->disconnect();
  });
}

// Per-IP cap rejects extra connections from the same source even if the
// global cap has plenty of headroom.
TEST_F(rpc_security_test, per_ip_cap_rejects_extras_from_same_source) {
  run([this]() -> asio::awaitable<void> {
    constexpr std::size_t kPerIp = 2;

    grlx::rpc::server<tcp_ch> server;
    server.set_server_limits({.max_concurrent_sessions = 100,
                              .max_sessions_per_ip     = kPerIp});
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::public_, []() -> int { return 1; });
    });

    std::vector<std::shared_ptr<grlx::rpc::client<tcp_ch>>> clients;
    for (std::size_t i = 0; i < kPerIp; ++i) {
      auto c = std::make_shared<grlx::rpc::client<tcp_ch>>();
      co_await c->connect(address);
      clients.push_back(c);
    }

    auto executor = co_await asio::this_coro::executor;
    for (int i = 0; i < 50; ++i) {
      asio::steady_timer t(executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
      if (co_await server.session_count() >= kPerIp) break;
    }
    EXPECT_EQ(co_await server.session_count(), kPerIp);

    grlx::rpc::client<tcp_ch> extra;
    try { co_await extra.connect(address); } catch (...) {}

    for (int i = 0; i < 25; ++i) {
      asio::steady_timer t(executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
    }
    EXPECT_EQ(co_await server.session_count(), kPerIp)
        << "per-IP cap must prevent session count from growing";
    for (auto& c : clients) c->disconnect();
  });
}

// ---- rate limiting ----
//
// With a tiny burst and effectively-zero refill, only the first N accepts
// from a given IP should succeed — the rest must be rejected at the filter.
TEST_F(rpc_security_test, accept_rate_limit_rejects_burst_from_same_ip) {
  run([this]() -> asio::awaitable<void> {
    constexpr std::size_t kBurst = 3;

    grlx::rpc::server<tcp_ch> server;
    server.set_server_limits({
        .max_concurrent_sessions       = 100,
        .max_sessions_per_ip           = 100,
        .accept_burst_per_ip           = static_cast<double>(kBurst),
        .accept_refill_per_ip_per_s    = 0.01,  // ~1 token per 100s: effectively frozen
    });
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::public_, []() -> int { return 1; });
    });

    auto executor = co_await asio::this_coro::executor;

    // Keep clients alive so the server's session records stay distinct and
    // we can read session_count as the ground truth.
    std::vector<std::shared_ptr<grlx::rpc::client<tcp_ch>>> clients;
    for (int i = 0; i < static_cast<int>(kBurst) + 5; ++i) {
      auto c = std::make_shared<grlx::rpc::client<tcp_ch>>();
      try { co_await c->connect(address); } catch (...) {}
      clients.push_back(c);
    }

    // Give the server time to admit/reject each attempt.
    for (int i = 0; i < 50; ++i) {
      asio::steady_timer t(executor);
      t.expires_after(20ms);
      co_await t.async_wait(asio::use_awaitable);
      if (co_await server.session_count() >= kBurst) break;
    }

    EXPECT_EQ(co_await server.session_count(), kBurst)
        << "only burst tokens worth of accepts should have been admitted";

    for (auto& c : clients) c->disconnect();
  });
}

// Per-session request rate: a burst beyond capacity must surface errors on
// the client. The session itself stays alive (rate-limit is recoverable).
TEST_F(rpc_security_test, request_rate_limit_rejects_burst_but_keeps_session_alive) {
  run([this]() -> asio::awaitable<void> {
    constexpr int kBurst = 3;

    grlx::rpc::session_limits sl{
        .request_burst   = static_cast<double>(kBurst),
        .request_rate_ps = 0.01,  // effectively frozen over the test window
    };

    grlx::rpc::server<tcp_ch> server;
    server.set_session_limits(sl);
    auto address = co_await start_tcp_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::public_, []() -> int { return 1; });
    });

    grlx::rpc::client<tcp_ch> client;
    co_await client.connect(address);

    int successes = 0;
    int failures  = 0;
    for (int i = 0; i < kBurst + 5; ++i) {
      try {
        int r = co_await client.invoke<int>("ping");
        if (r == 1) ++successes;
      } catch (...) {
        ++failures;
      }
    }

    EXPECT_EQ(successes, kBurst) << "first `burst` requests should succeed";
    EXPECT_GT(failures, 0)       << "extra requests past burst should error";
    EXPECT_TRUE(client.is_connected()) << "rate-limit must not close the session";
  });
}

// The auth callback receives the peer's cert fingerprint captured during
// the TLS handshake — the primary way apps bind auth tokens to TLS identity.
TEST_F(rpc_security_test, auth_callback_sees_cert_fingerprint) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{
        grlx::rpc::make_server_context(certs.server.cert_pem, certs.server.key_pem,
                                       certs.primary_ca.cert_pem)};

    std::string seen_fp;
    std::string seen_method;
    server.set_auth_callback([&](grlx::rpc::client_context const& ctx, std::string const& name) {
      seen_fp     = ctx.peer_fingerprint;
      seen_method = name;
      return grlx::rpc::auth_result{.allow = true};
    });

    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("whoami", []() -> int { return 1; });
    });

    grlx::rpc::client<ssl_ch> client{
        grlx::rpc::make_client_context(certs.client_a.cert_pem, certs.client_a.key_pem,
                                       certs.primary_ca.cert_pem)};
    co_await client.connect(endpoint);
    EXPECT_EQ(co_await client.invoke<int>("whoami"), 1);

    EXPECT_EQ(seen_fp.size(), 64u) << "callback should see a 64-char SHA-256 fingerprint";
    EXPECT_EQ(seen_method, "whoami");
  });
}

// --- Optional mTLS (tls_config::request_client_cert) -------------------------
// The server asks for a client cert but doesn't require one: a client without
// one gets in, and the auth callback sees an empty fingerprint — what an app
// keys "this session may only enroll" on.
TEST_F(rpc_security_test, optional_mtls_accepts_certless_client_with_empty_fingerprint) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{grlx::rpc::make_server_context(
        certs.server.cert_pem, certs.server.key_pem, certs.primary_ca.cert_pem,
        grlx::rpc::tls_config{.require_client_cert = false, .request_client_cert = true})};

    std::string seen_fp = "unset";
    server.set_auth_callback([&](grlx::rpc::client_context const& ctx, std::string const&) {
      seen_fp = ctx.peer_fingerprint;
      return grlx::rpc::auth_result{.allow = true};
    });
    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::authenticated, []() -> int { return 1; });
    });

    grlx::rpc::client<ssl_ch> client{grlx::rpc::make_client_context("", "", certs.primary_ca.cert_pem)};
    co_await client.connect(endpoint);
    EXPECT_EQ(co_await client.invoke<int>("ping"), 1);
    EXPECT_EQ(seen_fp, "") << "a cert-less session must reach the callback with an empty fingerprint";
  });
}

// Optional mTLS still verifies a cert that IS presented: a valid one is
// fingerprinted, one from an untrusted CA fails the handshake.
TEST_F(rpc_security_test, optional_mtls_still_verifies_presented_certs) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{grlx::rpc::make_server_context(
        certs.server.cert_pem, certs.server.key_pem, certs.primary_ca.cert_pem,
        grlx::rpc::tls_config{.require_client_cert = false, .request_client_cert = true})};

    std::string seen_fp;
    server.set_auth_callback([&](grlx::rpc::client_context const& ctx, std::string const&) {
      seen_fp = ctx.peer_fingerprint;
      return grlx::rpc::auth_result{.allow = true};
    });
    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::authenticated, []() -> int { return 1; });
    });

    grlx::rpc::client<ssl_ch> good{grlx::rpc::make_client_context(
        certs.client_a.cert_pem, certs.client_a.key_pem, certs.primary_ca.cert_pem)};
    co_await good.connect(endpoint);
    EXPECT_EQ(co_await good.invoke<int>("ping"), 1);
    EXPECT_EQ(seen_fp.size(), 64u) << "a presented cert must still be fingerprinted";

    grlx::rpc::client<ssl_ch> rogue{grlx::rpc::make_client_context(
        certs.rogue_client.cert_pem, certs.rogue_client.key_pem, certs.primary_ca.cert_pem)};
    bool failed = false;
    try {
      co_await rogue.connect(endpoint);
      co_await rogue.invoke<int>("ping");
    } catch (std::exception const&) {
      failed = true;
    }
    EXPECT_TRUE(failed) << "an untrusted-CA cert must still be rejected in optional mode";
  });
}

// --- WI-12: inbound notifications go through the auth gate -------------------
// A notification is an inbound call too. Hand-framed (the client API has no
// way to send one), aimed at an authenticated method: with the callback
// denying, the handler must not run; with it allowing, the same frame does —
// which proves the frame was valid.
TEST_F(rpc_security_test, notification_is_subject_to_auth_callback) {
  run([this]() -> asio::awaitable<void> {
    grlx::rpc::server<tcp_ch> server;
    std::atomic<bool> allow{false};
    std::atomic<int>  handler_runs{0};
    server.set_auth_callback([&](grlx::rpc::client_context const&, std::string const&) {
      return grlx::rpc::auth_result{.allow = allow.load(), .deny_reason = "nope"};
    });
    co_await start_tcp_server(server, [&](auto& s) {
      s.attach("secret", grlx::rpc::visibility::authenticated, [&handler_runs]() -> int {
        ++handler_runs;
        return 0;
      });
    });

    auto executor = co_await asio::this_coro::executor;
    tcp::endpoint const ep{asio::ip::make_address("127.0.0.1"),
                           static_cast<unsigned short>(server.channel().endpoint().port())};
    tcp::socket sock(executor);
    co_await sock.async_connect(ep, asio::use_awaitable);

    grlx::rpc::buffer_type body;
    grlx::rpc::binary_encoder::encode(body, grlx::rpc::message_request<>{});
    auto send_notification = [&]() -> asio::awaitable<void> {
      constexpr std::uint64_t kMsgTypeNotificationShifted = static_cast<std::uint64_t>(3) << 32;
      wire_header hdr{kMagic, body.size(), kMsgTypeNotificationShifted,
                      grlx::rpc::shash64("secret").value(), 0};
      co_await asio::async_write(sock, asio::buffer(&hdr, sizeof(hdr)), asio::use_awaitable);
      co_await asio::async_write(sock, asio::buffer(body), asio::use_awaitable);
    };
    auto settle = [&]() -> asio::awaitable<void> {
      asio::steady_timer t(executor);
      t.expires_after(300ms);
      co_await t.async_wait(asio::use_awaitable);
    };

    co_await send_notification();
    co_await settle();
    EXPECT_EQ(handler_runs.load(), 0) << "a denied notification must not reach the handler";

    allow = true;
    co_await send_notification();
    co_await settle();
    EXPECT_EQ(handler_runs.load(), 1) << "control: the same notification runs when allowed";
  });
}

// --- server::close_sessions_if -----------------------------------------------
// Revoking one device: close the sessions with its fingerprint, leave the
// others connected.
TEST_F(rpc_security_test, close_sessions_if_closes_only_matching_sessions) {
  auto const& certs = shared_cert_set();

  run([this, &certs]() -> asio::awaitable<void> {
    grlx::rpc::server<ssl_ch> server{grlx::rpc::make_server_context(
        certs.server.cert_pem, certs.server.key_pem, certs.primary_ca.cert_pem)};

    std::string fp_seen;
    server.set_auth_callback([&](grlx::rpc::client_context const& ctx, std::string const&) {
      fp_seen = ctx.peer_fingerprint;
      return grlx::rpc::auth_result{.allow = true};
    });
    auto endpoint = co_await start_ssl_server(server, [](auto& s) {
      s.attach("ping", grlx::rpc::visibility::authenticated, []() -> int { return 1; });
    });

    grlx::rpc::client<ssl_ch> a{grlx::rpc::make_client_context(
        certs.client_a.cert_pem, certs.client_a.key_pem, certs.primary_ca.cert_pem)};
    grlx::rpc::client<ssl_ch> b{grlx::rpc::make_client_context(
        certs.client_b.cert_pem, certs.client_b.key_pem, certs.primary_ca.cert_pem)};
    co_await a.connect(endpoint);
    EXPECT_EQ(co_await a.invoke<int>("ping"), 1);
    auto const fp_a = fp_seen;
    co_await b.connect(endpoint);
    EXPECT_EQ(co_await b.invoke<int>("ping"), 1);
    ASSERT_EQ(fp_a.size(), 64u);
    ASSERT_NE(fp_a, fp_seen) << "the two clients must have different fingerprints";

    auto const closed = co_await server.close_sessions_if(
        [&](grlx::rpc::session_info const& info) { return info.peer_fingerprint == fp_a; });
    EXPECT_EQ(closed, 1u);

    asio::steady_timer t(co_await asio::this_coro::executor);
    t.expires_after(200ms);
    co_await t.async_wait(asio::use_awaitable);

    bool a_failed = false;
    try {
      co_await a.invoke<int>("ping");
    } catch (std::exception const&) {
      a_failed = true;
    }
    EXPECT_TRUE(a_failed) << "the closed session must not serve calls";
    EXPECT_EQ(co_await b.invoke<int>("ping"), 1) << "the other session must be unaffected";
  });
}
