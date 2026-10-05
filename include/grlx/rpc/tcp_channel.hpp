#pragma once

#include "session.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace grlx::rpc {

namespace asio = boost::asio;
using tcp      = asio::ip::tcp;

// Thrown when the pre-session filter rejects a freshly accepted TCP peer.
// The server's accept loop catches and continues.
class tcp_connection_rejected_error : public std::runtime_error {
public:
  explicit tcp_connection_rejected_error(std::string reason)
    : std::runtime_error("connection rejected: " + reason) {}
};

// Predicate that inspects a freshly accepted peer endpoint and decides
// whether to proceed. Return false to reject the connection.
using tcp_pre_session_filter = std::function<bool(tcp::endpoint const& peer,
                                                  std::string&        reject_reason)>;

namespace detail {
// Simple host:port parser to avoid URL library dependency
inline std::pair<std::string, std::string> parse_address(std::string_view address) {
  // Find the last colon (to handle IPv6 addresses like [::1]:8080)
  auto colon_pos = address.rfind(':');

  if (colon_pos == std::string_view::npos) {
    // No port specified, assume default port
    return {std::string(address), "0"};
  }

  // Check if this might be an IPv6 address without brackets
  if (address.find(':') != colon_pos) {
    // Multiple colons - likely IPv6, need brackets or assume no port
    return {std::string(address), "0"};
  }

  std::string host = std::string(address.substr(0, colon_pos));
  std::string port = std::string(address.substr(colon_pos + 1));

  return {host, port};
}
} // namespace detail

template <typename EncoderT>
class tcp_channel {
public:
  using encoder_type  = EncoderT;
  using buffer_type   = typename EncoderT::buffer_type;
  using session_type  = session<tcp::socket, EncoderT>;
  using executor_type = tcp::acceptor::executor_type;

  tcp_channel() = default;
  tcp_channel(tcp_channel&& other)
    : acceptor_(std::move(other.acceptor_)) {
  }

  tcp_channel(tcp_channel const&)           = delete;
  tcp_channel operator=(tcp_channel const&) = delete;

  auto get_executor() -> executor_type {
    if (acceptor_) {
      return acceptor_->get_executor();
    }
    // Return a default-constructed executor if acceptor is not available
    // This should only happen before bind() is called
    throw std::runtime_error("tcp_channel: get_executor() called before bind()");
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
    if (acceptor_ != nullptr) {
      return acceptor_->local_endpoint();
    }
    return tcp::endpoint();
  }

  void set_pre_handshake_filter(tcp_pre_session_filter f) {
    pre_filter_ = std::move(f);
  }

  // Accept a raw TCP socket + run the pre-session filter. Mirrors
  // ssl_channel::accept_raw so the server's decoupled accept loop (WI-9) is
  // channel-agnostic. Plain TCP has no handshake, but the split keeps a uniform
  // interface. Throws tcp_connection_rejected_error when the filter denies.
  auto accept_raw() -> asio::awaitable<tcp::socket> {
    auto tcp_socket = co_await acceptor_->async_accept(asio::use_awaitable);

    boost::system::error_code ep_ec;
    auto                      peer = tcp_socket.remote_endpoint(ep_ec);
    if (pre_filter_ && !ep_ec) {
      std::string reason;
      if (!pre_filter_(peer, reason)) {
        boost::system::error_code ignored;
        tcp_socket.close(ignored);
        throw tcp_connection_rejected_error(reason.empty() ? "filter denied" : reason);
      }
    }
    co_return tcp_socket;
  }

  // Build the session from a pre-accepted socket. No TLS handshake for plain
  // TCP; the name matches ssl_channel::handshake for a uniform accept loop.
  template <typename... ArgsT>
  auto handshake(tcp::socket&& tcp_socket, ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    boost::system::error_code ep_ec;
    auto                      peer = tcp_socket.remote_endpoint(ep_ec);
    // Plain TCP allows one concurrent read + one concurrent write, so the
    // session's stream I/O needs no strand — hand it the raw socket executor.
    // (SSL is the case that needs a strand; see ssl_channel.) Read the executor
    // before the socket is moved into the session.
    auto io_executor = tcp_socket.get_executor();
    auto sess = std::make_shared<session_type>(std::move(tcp_socket), io_executor, std::forward<ArgsT>(args)...);
    if (!ep_ec) {
      sess->set_peer_ip(peer.address().to_string());
      sess->set_peer_address(peer.address().to_string() + ":" + std::to_string(peer.port()));
    }
    co_return sess;
  }

  // Convenience: accept + build in one step. Kept for tests and non-decoupled callers.
  template <typename... ArgsT>
  auto accept(ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto sock = co_await accept_raw();
    co_return co_await handshake(std::move(sock), std::forward<ArgsT>(args)...);
  }

  auto connect(std::string const& address) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto          executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);

    auto [host, port] = detail::parse_address(address);
    auto endpoints    = co_await resolver.async_resolve(host, port, asio::use_awaitable);
    // A name can resolve to several addresses — "localhost" to ::1 and
    // 127.0.0.1, a dual-stack host to its AAAA and A records — and a server may
    // listen on only some of them. Try each in resolver order until one
    // connects.
    for (auto const& entry : endpoints)
      if (auto session = co_await connect(entry.endpoint())) co_return session;
    co_return nullptr;
  }

  auto connect(tcp::endpoint const& endpoint) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto        executor = co_await asio::this_coro::executor;
    tcp::socket tcp_socket(executor);

    // Non-throwing TCP connect — see ssl_channel::connect for the full
    // rationale. A throwing async_connect crashes on Android during the
    // coroutine unwind on the connect-FAILURE path (esp. immediate
    // ECONNREFUSED). Return a null session on error instead.
    auto [ec] = co_await tcp_socket.async_connect(endpoint, asio::as_tuple(asio::use_awaitable));
    if (ec) {
      co_await asio::post(executor, asio::use_awaitable);
      co_return nullptr;
    }

    auto io_executor = tcp_socket.get_executor();
    co_return std::make_shared<session_type>(std::move(tcp_socket), io_executor);
  }

private:
  std::unique_ptr<tcp::acceptor> acceptor_;
  tcp_pre_session_filter         pre_filter_;
};

} // namespace grlx::rpc