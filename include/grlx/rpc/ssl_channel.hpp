#pragma once

#include "security.hpp"
#include "session.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace grlx::rpc {

namespace asio = boost::asio;
using tcp      = asio::ip::tcp;

// Thrown when a TLS handshake does not complete within the configured
// timeout. Callers (server accept loops) can catch and continue serving.
class handshake_timeout_error : public std::runtime_error {
public:
  handshake_timeout_error() : std::runtime_error("TLS handshake timed out") {}
};

// Thrown when the pre-handshake filter rejects an incoming connection.
// Server accept loops catch this, log structured info, and continue.
class connection_rejected_error : public std::runtime_error {
public:
  explicit connection_rejected_error(std::string reason)
    : std::runtime_error("connection rejected: " + reason) {}
};

// Predicate that inspects a freshly accepted peer endpoint and decides
// whether to proceed with the TLS handshake. Return false to reject; the
// socket will be closed without paying for a handshake.
using pre_handshake_filter = std::function<bool(tcp::endpoint const& peer,
                                                std::string&        reject_reason)>;

namespace detail {

inline void apply_tls_config(asio::ssl::context& ctx, tls_config const& cfg, bool server_side) {
  // OpenSSL baseline options — disable renegotiation surprises, turn off
  // compression (CRIME), disable SSLv2/3 explicitly even if we're pinning
  // TLS 1.3 below (belt + suspenders for ancient OpenSSL builds).
  ctx.set_options(asio::ssl::context::default_workarounds |
                  asio::ssl::context::no_sslv2 |
                  asio::ssl::context::no_sslv3 |
                  asio::ssl::context::no_compression |
                  asio::ssl::context::single_dh_use);

  if (cfg.tls13_only) {
    if (SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION) != 1) {
      throw std::runtime_error("failed to set TLS 1.3 minimum");
    }
  } else {
    // TLS 1.2+: keep pre-TLS-1.2 disabled but allow 1.2 for legacy peers.
    if (SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION) != 1) {
      throw std::runtime_error("failed to set TLS 1.2 minimum");
    }
  }

  // Verification: server-side and client-side are orthogonal. A server
  // that enforces mTLS (require_client_cert) can coexist with a client
  // that either verifies the server cert or doesn't — in practice, a
  // well-configured deployment turns both on.
  int mode = SSL_VERIFY_NONE;
  if (server_side) {
    if (cfg.require_client_cert) {
      mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else if (cfg.request_client_cert) {
      // Optional mTLS: a presented cert is verified, a missing one is fine.
      mode = SSL_VERIFY_PEER;
    }
  } else {
    if (cfg.verify_server_cert) {
      mode = SSL_VERIFY_PEER;
    }
  }
  SSL_CTX_set_verify(ctx.native_handle(), mode, nullptr);
  SSL_CTX_set_verify_depth(ctx.native_handle(), 5);
}

// Populate the list of CA names a server advertises in its CertificateRequest
// during mTLS. OpenSSL does not derive this from the trust store — if the
// list is empty, some clients will not offer a certificate at all (or will
// offer the wrong one). We feed in the same PEM bundle used to configure
// the trust store so both sides see a consistent view.
inline void add_client_ca_list_from_pem(SSL_CTX* ctx, std::string const& ca_pem) {
  if (ca_pem.empty()) return;
  auto* bio = BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size()));
  if (!bio) return;
  STACK_OF(X509_NAME)* names = sk_X509_NAME_new_null();
  if (!names) {
    BIO_free(bio);
    return;
  }
  while (X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
    X509_NAME* name = X509_NAME_dup(X509_get_subject_name(cert));
    if (name) sk_X509_NAME_push(names, name);
    X509_free(cert);
  }
  BIO_free(bio);
  SSL_CTX_set_client_CA_list(ctx, names);
}

// Add EVERY certificate in a PEM bundle to the context's verify store. asio's
// ctx.add_certificate_authority() reads only the FIRST cert in a buffer, so it
// cannot pin more than one anchor. This loads them all — required for a
// root-CA rotation transition where the client trusts both the new root CA and
// the legacy leaf that already-deployed peers still present (WI-14).
inline void add_all_cas_from_pem(asio::ssl::context& ctx, std::string const& ca_pem) {
  if (ca_pem.empty()) return;
  auto* bio = BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size()));
  if (!bio) return;
  X509_STORE* store = SSL_CTX_get_cert_store(ctx.native_handle());
  while (X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
    (void)X509_STORE_add_cert(store, cert);  // returns 0 for a duplicate — harmless
    X509_free(cert);
  }
  BIO_free(bio);
}

// SHA-256 of a peer X.509 cert in DER, as lowercase hex.
inline std::string fingerprint_sha256(X509* cert) {
  if (!cert) return {};

  std::array<unsigned char, EVP_MAX_MD_SIZE> buf{};
  unsigned int                               len = 0;
  if (!X509_digest(cert, EVP_sha256(), buf.data(), &len)) {
    return {};
  }

  std::string hex;
  hex.reserve(static_cast<std::size_t>(len) * 2);
  static constexpr char kHex[] = "0123456789abcdef";
  for (unsigned int i = 0; i < len; ++i) {
    hex.push_back(kHex[buf[i] >> 4]);
    hex.push_back(kHex[buf[i] & 0x0f]);
  }
  return hex;
}

inline std::string peer_fingerprint(asio::ssl::stream<tcp::socket>& s) {
  X509* peer = SSL_get_peer_certificate(s.native_handle());
  if (!peer) return {};
  std::string fp = fingerprint_sha256(peer);
  X509_free(peer);
  return fp;
}

// Disable Nagle's algorithm on a freshly connected socket, before the TLS
// handshake runs. session::dispatch_requests() sets the same option, but only
// once the session exists — i.e. after the handshake has already completed.
// Under mTLS the peer's second flight (Certificate + CertificateVerify +
// Finished) leaves the trailing small segment parked in the kernel waiting on
// a delayed ACK (~40 ms), which silently spends part of the handshake timeout
// budget on every connect and every client reconnect. The option survives the
// moves into ssl::stream and then into the session, so setting it here is
// enough. Best-effort and deliberately silent: a failure recurs on the same
// socket in dispatch_requests(), which logs it.
inline void disable_nagle(tcp::socket& sock) {
  boost::system::error_code ignored;
  sock.set_option(asio::ip::tcp::no_delay(true), ignored);
}

}  // namespace detail

// Build a server-side TLS context loaded with cert/key and a CA bundle that
// incoming client certs must chain to. Locked-down defaults:
//   - TLS 1.3 only
//   - mTLS required (verify_peer | verify_fail_if_no_peer_cert)
//   - no compression, no SSLv2/3, workarounds enabled
// Inputs are PEM strings so callers can keep keys out of the filesystem if
// they want (e.g. load from secret manager → in-memory → context).
inline asio::ssl::context make_server_context(std::string const& cert_pem,
                                              std::string const& key_pem,
                                              std::string const& ca_pem,
                                              tls_config         config = {}) {
  asio::ssl::context ctx(asio::ssl::context::tls_server);
  detail::apply_tls_config(ctx, config, /*server_side=*/true);
  ctx.use_certificate_chain(asio::buffer(cert_pem));
  ctx.use_private_key(asio::buffer(key_pem), asio::ssl::context::pem);
  if (!ca_pem.empty()) {
    ctx.add_certificate_authority(asio::buffer(ca_pem));
    // Advertise the CA list in CertificateRequest so clients know which cert
    // to send. Without this, some clients won't present one and we'd reject
    // with a confusing "no peer cert" error even when they have a valid one.
    detail::add_client_ca_list_from_pem(ctx.native_handle(), ca_pem);
  }
  return ctx;
}

// Client-side counterpart. `cert_pem` + `key_pem` are the client cert used
// for mTLS (required unless the server's tls_config loosens the policy).
// `ca_pem` is the CA bundle the server's cert must chain to.
inline asio::ssl::context make_client_context(std::string const& cert_pem,
                                              std::string const& key_pem,
                                              std::string const& ca_pem,
                                              tls_config         config = {}) {
  asio::ssl::context ctx(asio::ssl::context::tls_client);
  detail::apply_tls_config(ctx, config, /*server_side=*/false);
  if (!cert_pem.empty() && !key_pem.empty()) {
    ctx.use_certificate_chain(asio::buffer(cert_pem));
    ctx.use_private_key(asio::buffer(key_pem), asio::ssl::context::pem);
  }
  if (!ca_pem.empty()) {
    // WI-14: load EVERY anchor in the bundle (asio adds only the first), so the
    // client can pin a root CA plus a legacy leaf during a rotation transition.
    detail::add_all_cas_from_pem(ctx, ca_pem);
  }
  return ctx;
}

template <typename EncoderT>
class ssl_channel {
public:
  using encoder_type  = EncoderT;
  using buffer_type   = typename EncoderT::buffer_type;
  using ssl_socket    = asio::ssl::stream<tcp::socket>;
  using session_type  = session<ssl_socket, EncoderT>;
  using executor_type = tcp::acceptor::executor_type;

  // Caps the worst case for a legitimate handshake on a slow network. Kept
  // tight (WI-9) because the accept loop now runs handshakes off-loop and a
  // shorter deadline evicts stalling peers from the in-flight budget sooner.
  // Lower it in tests; raise only if you understand the DoS risk.
  static constexpr std::chrono::milliseconds kDefaultHandshakeTimeout{3000};

  ssl_channel(asio::ssl::context ctx, std::chrono::milliseconds handshake_timeout = kDefaultHandshakeTimeout)
    : ssl_ctx_(std::move(ctx))
    , handshake_timeout_(handshake_timeout) {
  }

  ssl_channel(ssl_channel&&)                 = default;
  ssl_channel(ssl_channel const&)            = delete;
  ssl_channel& operator=(ssl_channel const&) = delete;

  auto get_executor() -> executor_type {
    if (acceptor_) {
      return acceptor_->get_executor();
    }
    throw std::runtime_error("ssl_channel: get_executor() called before bind()");
  }

  auto bind(tcp::endpoint const& endpoint) -> asio::awaitable<void> {
    auto executor = co_await asio::this_coro::executor;
    acceptor_     = std::make_unique<tcp::acceptor>(executor, endpoint);
    acceptor_->set_option(asio::socket_base::reuse_address(true));
    acceptor_->listen(asio::socket_base::max_listen_connections);
    co_return;
  }

  auto close() -> asio::awaitable<void> {
    if (acceptor_) {
      acceptor_->cancel();
      acceptor_->close();
    }
    co_return;
  }

  auto endpoint() -> tcp::endpoint {
    if (acceptor_) {
      return acceptor_->local_endpoint();
    }
    return tcp::endpoint();
  }

  void set_pre_handshake_filter(pre_handshake_filter f) {
    pre_filter_ = std::move(f);
  }

  // Accept a raw TCP socket and run the cheap pre-handshake filter. Does NOT
  // run the TLS handshake (WI-9) — the server accepts these serially on the
  // acceptor and hands the slow handshake off to a per-connection coroutine via
  // handshake() below, so one stalling peer cannot starve new accepts. Throws
  // connection_rejected_error when the filter denies the peer.
  auto accept_raw() -> asio::awaitable<tcp::socket> {
    auto tcp_sock = co_await acceptor_->async_accept(asio::use_awaitable);

    // Drop at the cheap TCP layer when the filter says so, before we pay
    // for the TLS handshake. This is the only defense against a peer that
    // can open handshakes faster than we can complete them.
    if (pre_filter_) {
      boost::system::error_code ep_ec;
      auto                      peer = tcp_sock.remote_endpoint(ep_ec);
      std::string               reason;
      if (!ep_ec && !pre_filter_(peer, reason)) {
        boost::system::error_code ignored;
        tcp_sock.close(ignored);
        throw connection_rejected_error(reason.empty() ? "filter denied" : reason);
      }
    }

    detail::disable_nagle(tcp_sock);
    co_return tcp_sock;
  }

  // Complete a pre-accepted connection: run the TLS handshake (bounded by the
  // handshake timeout) and build the session. Slow; the server runs this off
  // the accept loop. Concurrent handshakes each operate on their own ssl_socket,
  // so running many at once is safe.
  template <typename... ArgsT>
  auto handshake(tcp::socket&& tcp_sock, ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    ssl_socket ssl_sock(std::move(tcp_sock), ssl_ctx_);
    co_await race_handshake(ssl_sock, asio::ssl::stream_base::server);
    // Capture the peer's cert fingerprint + endpoint *before* moving the
    // socket into the session. session owns both and surfaces them to the
    // auth layer via session_info.
    auto info = detail::peer_fingerprint(ssl_sock);
    tcp::endpoint remote;
    boost::system::error_code ep_ec;
    remote = ssl_sock.lowest_layer().remote_endpoint(ep_ec);
    // SSL_read / SSL_write share OpenSSL state and must never run concurrently,
    // so hand the session a strand to bind its stream I/O to. This is the SSL
    // transport's concern, which is why it lives here and not in the generic
    // session. Computed before the socket is moved into the session.
    auto io_strand = asio::make_strand(ssl_sock.get_executor());
    auto sess = std::make_shared<session_type>(std::move(ssl_sock), io_strand, std::forward<ArgsT>(args)...);
    sess->set_peer_fingerprint(std::move(info));
    if (!ep_ec) {
      sess->set_peer_ip(remote.address().to_string());
      sess->set_peer_address(remote.address().to_string() + ":" + std::to_string(remote.port()));
    }
    co_return sess;
  }

  // Convenience: accept + handshake in one step. Kept for tests and callers
  // that don't need the decoupled accept loop.
  template <typename... ArgsT>
  auto accept(ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto sock = co_await accept_raw();
    co_return co_await handshake(std::move(sock), std::forward<ArgsT>(args)...);
  }

  auto connect(std::string const& address) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto          executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);

    auto colon_pos = address.rfind(':');
    auto host      = colon_pos != std::string::npos ? address.substr(0, colon_pos) : address;
    auto port      = colon_pos != std::string::npos ? address.substr(colon_pos + 1) : "0";

    auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);
    co_return co_await connect(*std::begin(endpoints));
  }

  auto connect(tcp::endpoint const& endpoint) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto       executor = co_await asio::this_coro::executor;
    ssl_socket ssl_sock(executor, ssl_ctx_);

    // Non-throwing TCP connect. Letting async_connect THROW here
    // (use_awaitable) crashes on Android during the coroutine-frame unwind
    // when the connect FAILS — most reliably on an immediate ECONNREFUSED
    // (a refused loopback/LAN port), where the completion is delivered inline
    // and the exception tears down `ssl_sock` while the connect op is still
    // on the stack (SIGSEGV in reactive_socket_connect_op::do_complete ->
    // awaitable pump -> connect.resume). Offline-first clients hit this path
    // every time the server is unreachable, so it MUST NOT crash — take the
    // error_code form and fail by returning a null session instead. The
    // caller (client::connect) treats a null session as a connect failure.
    auto [ec] = co_await ssl_sock.next_layer().async_connect(endpoint, asio::as_tuple(asio::use_awaitable));
    if (ec) {
      // Hop off the (possibly inline) completion stack before ssl_sock is
      // destroyed, so its teardown can never race the connect op unwinding
      // beneath us.
      co_await asio::post(executor, asio::use_awaitable);
      co_return nullptr;
    }

    detail::disable_nagle(ssl_sock.next_layer());

    co_await race_handshake(ssl_sock, asio::ssl::stream_base::client);
    // Bind the session's stream I/O to a strand — SSL is not safe for
    // concurrent SSL_read/SSL_write (see the accept() path for the rationale).
    auto io_strand = asio::make_strand(ssl_sock.get_executor());
    co_return std::make_shared<session_type>(std::move(ssl_sock), io_strand);
  }

private:
  // Run async_handshake with a deadline. If the timer fires first, close the
  // underlying TCP socket (which aborts any in-flight TLS I/O on it) and
  // raise handshake_timeout_error. Callers propagate/catch as appropriate.
  auto race_handshake(ssl_socket& sock, asio::ssl::stream_base::handshake_type side) -> asio::awaitable<void> {
    auto               executor = co_await asio::this_coro::executor;
    asio::steady_timer timer(executor);
    timer.expires_after(handshake_timeout_);

    using namespace asio::experimental::awaitable_operators;
    auto result = co_await (
        sock.async_handshake(side, asio::as_tuple(asio::use_awaitable))
        || timer.async_wait(asio::as_tuple(asio::use_awaitable)));

    if (result.index() == 0) {
      auto [ec] = std::get<0>(result);
      timer.cancel();
      if (ec) {
        throw boost::system::system_error(ec, "TLS handshake failed");
      }
      co_return;
    }
    // Timer fired first — abort the in-flight handshake by closing the socket.
    boost::system::error_code ec;
    sock.lowest_layer().close(ec);
    throw handshake_timeout_error{};
  }

  asio::ssl::context             ssl_ctx_;
  std::chrono::milliseconds      handshake_timeout_;
  std::unique_ptr<tcp::acceptor> acceptor_;
  pre_handshake_filter           pre_filter_;
};

} // namespace grlx::rpc
