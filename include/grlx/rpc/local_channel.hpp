#pragma once

// RPC over a Unix-domain stream socket — same sessions, framing and dispatcher
// as tcp_channel, for peers on the same host. Who may connect is decided by
// the socket file's owner and mode, so there is no TLS and no pre-session
// filter: the server's per-IP caps and accept buckets have no IP to key on.
//
// A server can bind a path, or adopt a socket it inherited already listening
// (systemd socket activation: see inherited_listen_fd()).

#include "session.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <unistd.h>

namespace grlx::rpc {

namespace asio = boost::asio;
using local    = asio::local::stream_protocol;

// The first socket systemd passed this process (sd_listen_fds(3): LISTEN_PID
// names us and LISTEN_FDS >= 1; the fds start at 3). nullopt when the process
// wasn't socket-activated. Read without libsystemd — the protocol is two
// environment variables.
inline std::optional<int> inherited_listen_fd() {
  char const* pid = std::getenv("LISTEN_PID");
  char const* fds = std::getenv("LISTEN_FDS");
  if (!pid || !fds || std::atol(pid) != static_cast<long>(::getpid()) || std::atoi(fds) < 1) {
    return std::nullopt;
  }
  return 3; // SD_LISTEN_FDS_START
}

template <typename EncoderT>
class local_channel {
public:
  using encoder_type  = EncoderT;
  using buffer_type   = typename EncoderT::buffer_type;
  using session_type  = session<local::socket, EncoderT>;
  using executor_type = local::acceptor::executor_type;

  // The server installs its IP-keyed connection filter on every channel; a
  // local peer has no IP, so it is accepted and never run (see above).
  using pre_session_filter = std::function<bool(asio::ip::tcp::endpoint const& peer, std::string& reject_reason)>;

  local_channel() = default;
  local_channel(local_channel&& other)
    : acceptor_(std::move(other.acceptor_))
    , bound_path_(std::move(other.bound_path_)) {
    other.bound_path_.clear();
  }
  local_channel(local_channel const&)            = delete;
  local_channel& operator=(local_channel const&) = delete;

  ~local_channel() { unlink_bound_path(); }

  auto get_executor() -> executor_type {
    if (acceptor_) {
      return acceptor_->get_executor();
    }
    throw std::runtime_error("local_channel: get_executor() called before bind()");
  }

  // Listen on a socket file this channel creates (a stale file left by a
  // previous run is replaced) and removes again when closed.
  auto bind(local::endpoint const& endpoint) -> asio::awaitable<void> {
    auto executor = co_await asio::this_coro::executor;
    std::error_code ec;
    std::filesystem::remove(endpoint.path(), ec);
    acceptor_ = std::make_unique<local::acceptor>(executor, endpoint);
    bound_path_ = endpoint.path();
    co_return;
  }

  // Adopt a socket that is already bound and listening (socket activation).
  // Its file belongs to whoever created it, so it is left in place.
  auto bind(int listening_fd) -> asio::awaitable<void> {
    auto executor = co_await asio::this_coro::executor;
    acceptor_     = std::make_unique<local::acceptor>(executor);
    acceptor_->assign(local{}, listening_fd);
    co_return;
  }

  auto close() -> asio::awaitable<void> {
    if (acceptor_) {
      boost::system::error_code ec;
      acceptor_->cancel(ec);
      acceptor_->close(ec);
    }
    unlink_bound_path();
    co_return;
  }

  auto endpoint() -> local::endpoint {
    if (acceptor_) {
      return acceptor_->local_endpoint();
    }
    return local::endpoint();
  }

  void set_pre_handshake_filter(pre_session_filter) {}

  auto accept_raw() -> asio::awaitable<local::socket> {
    co_return co_await acceptor_->async_accept(asio::use_awaitable);
  }

  template <typename... ArgsT>
  auto handshake(local::socket&& socket, ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    // Like plain TCP: one concurrent read + one concurrent write need no strand.
    auto io_executor = socket.get_executor();
    auto sess        = std::make_shared<session_type>(std::move(socket), io_executor, std::forward<ArgsT>(args)...);
    sess->set_peer_address("unix:" + bound_or_inherited_name());
    co_return sess;
  }

  template <typename... ArgsT>
  auto accept(ArgsT&&... args) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto sock = co_await accept_raw();
    co_return co_await handshake(std::move(sock), std::forward<ArgsT>(args)...);
  }

  auto connect(std::string const& path) -> asio::awaitable<std::shared_ptr<session_type>> {
    co_return co_await connect(local::endpoint(path));
  }

  auto connect(local::endpoint const& endpoint) -> asio::awaitable<std::shared_ptr<session_type>> {
    auto          executor = co_await asio::this_coro::executor;
    local::socket socket(executor);
    // Non-throwing, as tcp_channel/ssl_channel: a null session on failure.
    auto [ec] = co_await socket.async_connect(endpoint, asio::as_tuple(asio::use_awaitable));
    if (ec) {
      co_await asio::post(executor, asio::use_awaitable);
      co_return nullptr;
    }
    auto io_executor = socket.get_executor();
    co_return std::make_shared<session_type>(std::move(socket), io_executor);
  }

private:
  std::string bound_or_inherited_name() const { return bound_path_.empty() ? std::string("inherited") : bound_path_; }

  void unlink_bound_path() {
    if (!bound_path_.empty()) {
      std::error_code ec;
      std::filesystem::remove(bound_path_, ec);
      bound_path_.clear();
    }
  }

  std::unique_ptr<local::acceptor> acceptor_;
  std::string                      bound_path_; // empty for an adopted socket
};

} // namespace grlx::rpc
