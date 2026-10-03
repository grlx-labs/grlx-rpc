#pragma once

#include "async_logger.hpp"
#include "async_manager.hpp"
#include "dispatcher.hpp"
#include "security.hpp"
#include "string_hash.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <memory>
#include <type_traits>
#include <unordered_map>

namespace grlx::rpc {

namespace asio = boost::asio;

template <typename AsyncStreamT, typename EncoderT>
class session : public std::enable_shared_from_this<session<AsyncStreamT, EncoderT>> {

public:
  using next_layer_type    = AsyncStreamT;
  using encoder_type       = EncoderT;
  using buffer_type        = typename EncoderT::buffer_type;
  using dispatcher_type    = dispatcher<encoder_type>;
  using header_type        = std::array<std::uint64_t, 5>;
  using executor_type      = typename AsyncStreamT::executor_type;
  using async_manager_type = async_manager<buffer_type>;

  // Response channel type
  using response_channel           = asio::experimental::concurrent_channel<void(boost::system::error_code, buffer_type)>;
  using notification_callback_type = std::function<void(std::uint64_t, buffer_type const&)>;

  // Write serialization: all outgoing data is queued through this channel
  // and written by a single msg_writer coroutine, preventing interleaved async_writes.
  struct write_item {
    header_type header;
    buffer_type body;
  };
  using write_channel_type = asio::experimental::concurrent_channel<void(boost::system::error_code, write_item)>;

  // Header layout
  static inline const std::uint64_t MAGIC_HEADER_NUMBER = 0xBADC0FFEE;
  static inline const int           MAGIC_HEADER_IDX    = 0;
  static inline const int           MSG_SIZE_IDX        = 1;
  static inline const int           MSG_TYPE_IDX        = 2;
  static inline const int           CALL_ID_IDX         = 3;
  static inline const int           USER_TOKEN_IDX      = 4;

  enum class msg_type : std::uint32_t {
    nop,
    request,
    response,
    notification,
    error,
    // Symmetric keepalive: a ping elicits a pong from the receiver. Either
    // side may send ping; pong is sent only as a reply and never elicits
    // a further reply, so there is no infinite loop. This keeps both
    // peers' idle_timeout deadlines fresh from a single ping cadence.
    ping,
    pong
  };

  // io_bound_executor is the executor that stream_ I/O is serialized on. The
  // CHANNEL supplies it (a strand for SSL, the raw executor for TCP); the
  // session never decides serialization for the underlying transport itself.
  session(AsyncStreamT&& stream, executor_type io_bound_executor)
    : session(std::move(stream), std::move(io_bound_executor), std::make_shared<dispatcher_type>(), session_limits{}) {
  }

  session(AsyncStreamT&& stream, executor_type io_bound_executor, std::shared_ptr<dispatcher_type> const& disp)
    : session(std::move(stream), std::move(io_bound_executor), disp, session_limits{}) {
  }

  session(AsyncStreamT&& stream, executor_type io_bound_executor, std::shared_ptr<dispatcher_type> const& disp, session_limits limits)
    : stream_(std::move(stream))
    , dispatcher_(disp)
    , logger_(std::make_shared<async_logger>(stream_.get_executor()))
    , io_bound_executor_(std::move(io_bound_executor))
    , notification_strand_(asio::make_strand(stream_.get_executor()))
    , async_manager_(io_bound_executor_)
    , write_channel_(stream_.get_executor(), 256)
    , limits_(limits) {
    logger_->start();
    // Seed the per-session request-rate bucket from the limits. All reads
    // and mutations happen on msg_reader's coroutine, so no extra sync.
    request_bucket_.capacity       = limits_.request_burst;
    request_bucket_.refill_per_sec = limits_.request_rate_ps;
  }

  // Sessions are always owned via std::make_shared and never moved or copied
  // (enable_shared_from_this + shared_ptr throughout — see ssl_channel /
  // tcp_channel, which only ever std::move the *socket* into make_shared).
  // The old move ctor silently omitted async_manager_ (left unbound — its ctor
  // needs io_bound_executor_), request_bucket_ (left zero-capacity → would reject every
  // request), and the peer_*/logical_session_id_ identity. A moved-into session
  // was therefore broken. Forbid moves outright so it can never happen by
  // accident; copy is already implicitly deleted by the non-copyable members.
  session(session&&)            = delete;
  session& operator=(session&&) = delete;

  virtual ~session() {
    close();
  }

  auto handshake() -> asio::awaitable<bool> {
    co_return true;
  }

  // Peer identity captured during the TLS handshake. Empty if the session is
  // over plain TCP or the peer did not present a certificate. Set by the
  // ssl_channel right after accept(); do not mutate from application code.
  void set_peer_fingerprint(std::string fp) { peer_fingerprint_ = std::move(fp); }
  std::string const& peer_fingerprint() const noexcept { return peer_fingerprint_; }

  void set_peer_address(std::string addr) { peer_address_ = std::move(addr); }
  std::string const& peer_address() const noexcept { return peer_address_; }

  // Just the IP portion of peer_address, separately stored so per-IP
  // connection counters can key on it without re-parsing.
  void set_peer_ip(std::string ip) { peer_ip_ = std::move(ip); }
  std::string const& peer_ip() const noexcept { return peer_ip_; }

  // Logical session identifier set by the application layer (e.g.
  // entt_ext::sync after a successful handshake). Used by
  // server::notify_session to target notifications at one specific
  // session rather than broadcasting. Distinct from the RPC-layer
  // identity captured by peer_fingerprint / peer_address.
  void set_logical_session_id(std::string id) { logical_session_id_ = std::move(id); }
  std::string const& logical_session_id() const noexcept { return logical_session_id_; }

  // Authenticated device identity, stamped by the application's handshake
  // handler after auth succeeds (see client_context::set_logical_device_id).
  // Surfaced to every subsequent call via current_call_context() so handlers
  // can authorize against it instead of trusting per-request payload fields.
  void set_logical_device_id(std::string id) { logical_device_id_ = std::move(id); }
  std::string const& logical_device_id() const noexcept { return logical_device_id_; }

  // Authenticated role, stamped by the application's handshake handler after
  // auth succeeds (see client_context::set_logical_role). -1 until then, which
  // the dispatch auth_callback reads as "unauthenticated" to deny non-public
  // methods. 0 = user, 1 = admin.
  void set_logical_role(int r) { logical_role_ = r; }
  int  logical_role() const noexcept { return logical_role_; }

  auto call(std::string const& call_name, buffer_type const& req_buffer, std::chrono::milliseconds timeout = std::chrono::seconds(30))
      -> asio::awaitable<buffer_type> {

    auto call_id = shash64(call_name);

    // Register the operation (token + response channel, capacity 1).
    auto async_op = async_manager_.create_operation();

    // Build and queue request
    header_type req_header;
    req_header[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
    req_header[MSG_SIZE_IDX]     = req_buffer.size();
    req_header[MSG_TYPE_IDX]     = static_cast<std::uint64_t>(msg_type::request) << 32;
    req_header[CALL_ID_IDX]      = call_id.value();
    req_header[USER_TOKEN_IDX]   = async_op.token;

    co_await queue_write(std::move(req_header), buffer_type(req_buffer));

    // Wait for the response with a timeout — INLINE in this coroutine frame,
    // using the same manual-timer + channel-cancel pattern as deadline_read.
    //
    // The previous implementation went through operation_token::async_wait,
    // which co_spawned a DETACHED coroutine that captured the completion
    // handler and then resumed this call() from there. That detached frame
    // (plus its timer/channel) outlived and raced session teardown: when a
    // session was closed while an RPC was in flight (server restart, WiFi
    // blip mid-sync, or a rapid disconnect/reconnect), the cancel path and
    // the detached-handler path could tear down the same state on two
    // executors and double-free — a scudo "invalid chunk" / MTE
    // "pointer tag truncated" SIGABRT on Android (glibc/desktop tolerated
    // it, so sanitizers stayed clean). Same failure class that already
    // forced deadline_read and msg_reader off awaitable_operators::||.
    //
    // Doing the wait here removes the detached frame entirely: it lives in
    // this call() frame, which the caller (client::invoke_with_timeout)
    // keeps alive via its session shared_ptr for the whole await. The
    // response channel is a shared_ptr, so it stays valid even if the
    // session's async_manager is torn down underneath us — a concurrent
    // close()/cancel_all_operations() just cancels our async_receive, which
    // we surface as a clean error instead of a crash.
    auto ch = async_op.channel;
    struct wait_state {
      asio::steady_timer timer;
      std::atomic<bool>  timed_out{false};
      std::atomic<bool>  finished{false};
      explicit wait_state(asio::any_io_executor ex) : timer(std::move(ex)) {}
    };
    auto executor = co_await asio::this_coro::executor;
    auto st       = std::make_shared<wait_state>(executor);
    st->timer.expires_after(timeout);
    st->timer.async_wait([st, ch](boost::system::error_code ec) {
      if (ec) return;                 // timer cancelled → response already received
      if (st->finished.load()) return;
      st->timed_out.store(true);
      ch->cancel();                   // unblocks async_receive with operation_aborted
    });

    auto [channel_ec, result] = co_await ch->async_receive(asio::as_tuple(asio::use_awaitable));
    st->finished.store(true);
    st->timer.cancel();

    if (st->timed_out.load()) {
      throw std::runtime_error("RPC call timeout: " + call_name);
    }
    if (channel_ec) {
      // Channel cancelled/closed by session teardown (disconnect / drop).
      throw boost::system::system_error(channel_ec, "RPC call failed");
    }

    auto& [ec, buffer] = result;
    if (ec) {
      if (ec == asio::error::timed_out) {
        throw std::runtime_error("RPC call timeout: " + call_name);
      }
      throw boost::system::system_error(ec, "RPC call failed");
    }

    co_return std::move(buffer);
  }

  auto dispatch_requests() -> asio::awaitable<void> {
    if (!stream_.lowest_layer().is_open()) {
      spdlog::error("rpc::session::dispatch_requests: socket is not open, aborting");
      co_return;
    }

    // Disable Nagle's algorithm. This is a request/response protocol layered
    // over TLS: small control messages (handshake, pings, signature/delta
    // requests, per-chunk pull requests, commit acks) and the trailing partial
    // segment of every bulk write would otherwise sit in the kernel waiting for
    // a delayed ACK (up to ~40 ms), collapsing throughput on an otherwise fast
    // link to a fraction of capacity. Both client and server reach dispatch on
    // a connected socket, so set it once here for every session. Best-effort:
    // a failure to set it is not fatal.
    // TCP only: a Unix-domain socket (local_channel) has no Nagle to disable.
    using lowest_protocol = typename std::remove_cvref_t<decltype(stream_.lowest_layer())>::protocol_type;
    if constexpr (std::is_same_v<lowest_protocol, asio::ip::tcp>) {
      boost::system::error_code nd_ec;
      stream_.lowest_layer().set_option(asio::ip::tcp::no_delay(true), nd_ec);
      if (nd_ec) {
        log_error_async("could not set TCP_NODELAY (peer=" + peer_address_ + "): " + nd_ec.message());
      }
    }
    // Keep the session alive for the entire lifetime of the reader/writer
    // coroutines. Both msg_reader() and msg_writer() capture `this` via their
    // member-function awaitables, so if the owning shared_ptr is released
    // (e.g. the server drops the session from its map) while an async_read
    // or parallel_group op is in flight, the completion handler ends up
    // touching freed stream_/channels. This was the UAF that
    // showed up as ~parallel_group_op_handler under ASan.
    auto self = this->shared_from_this();
    using namespace asio::experimental::awaitable_operators;
    // SSL serialization contract: this coroutine MUST be co_spawned on the
    // session's I/O executor (io_bound_executor_) by the caller — the client via
    // session->io_executor() (client.hpp), the server likewise (server.hpp).
    // That spawn executor is what the `&&` below propagates to msg_reader /
    // msg_writer, so every SSL_read / SSL_write against stream_ runs on the one
    // executor and never concurrently. For SSL io_bound_executor_ is a strand
    // (ssl_channel); for plain TCP it's the raw executor (one read + one write is
    // safe there). OpenSSL state is shared between read and write — concurrent
    // access corrupts records → "decryption failed / bad record mac".
    //
    // The dispatch() resumes us on io_bound_executor_, but note it does NOT
    // rebind this_coro::executor: the `&&` children inherit the *spawn* executor,
    // not the resumed-on one. So spawning on the strand (above) is the load-
    // bearing part; the hop is belt-and-suspenders. Relying on the hop alone,
    // with the coroutine spawned on a raw multi-threaded executor, WAS the bug —
    // reader/writer ran off-strand and raced under the file-sync push flood.
    co_await asio::dispatch(asio::bind_executor(io_bound_executor_, asio::use_awaitable));
    co_await (msg_reader() && msg_writer());
    co_return;
  }

  auto notify(std::string const& call_name, buffer_type const& buffer) -> asio::awaitable<void> {
    auto call_id = shash64(call_name);

    header_type notification_header;
    notification_header[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
    notification_header[MSG_SIZE_IDX]     = buffer.size();
    notification_header[CALL_ID_IDX]      = call_id.value();
    notification_header[USER_TOKEN_IDX]   = 0;
    notification_header[MSG_TYPE_IDX]     = (static_cast<std::uint64_t>(msg_type::notification) << 32);

    co_await queue_write(std::move(notification_header), buffer_type(buffer));
  }

  // Non-blocking keepalive: queues a msg_type::ping. The receiver replies
  // with msg_type::pong (see msg_reader), which resets *this* end's read
  // deadline too — so a single periodic ping from one side keeps both
  // peers' idle_timeout deadlines fresh. Returns false if the write
  // channel is full; in that case the session is already producing
  // plenty of traffic, so skipping the ping is fine.
  bool try_ping() {
    header_type h{};
    h[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
    h[MSG_SIZE_IDX]     = 0;
    h[MSG_TYPE_IDX]     = static_cast<std::uint64_t>(msg_type::ping) << 32;
    h[CALL_ID_IDX]      = 0;
    h[USER_TOKEN_IDX]   = 0;
    return write_channel_.try_send(boost::system::error_code{}, write_item{std::move(h), buffer_type{}});
  }

  // Non-blocking notify: returns false if the write channel is full (client too slow)
  bool try_notify(std::string const& call_name, buffer_type const& buffer) {
    auto call_id = shash64(call_name);

    header_type notification_header;
    notification_header[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
    notification_header[MSG_SIZE_IDX]     = buffer.size();
    notification_header[CALL_ID_IDX]      = call_id.value();
    notification_header[USER_TOKEN_IDX]   = 0;
    notification_header[MSG_TYPE_IDX]     = (static_cast<std::uint64_t>(msg_type::notification) << 32);

    return write_channel_.try_send(boost::system::error_code{}, write_item{std::move(notification_header), buffer_type(buffer)});
  }

  next_layer_type& next_layer() {
    return stream_;
  }
  const next_layer_type& next_layer() const {
    return stream_;
  }

  // The executor all stream I/O is serialized on (a strand for SSL, the raw
  // executor for TCP), supplied by the channel. The caller MUST co_spawn
  // dispatch_requests() on THIS so msg_reader/msg_writer inherit it and never
  // touch the SSL stream concurrently — see the contract in dispatch_requests().
  // It is a strand over the socket's own io_context, so spawning on it preserves
  // reactor affinity (the socket is still driven by the io_context it was
  // registered with).
  executor_type io_executor() const noexcept { return io_bound_executor_; }

  void close() {
    // Prevent double-close using atomic flag
    bool expected = false;
    if (!is_closed_.compare_exchange_strong(expected, true)) {
      return; // Already closed
    }

    // One-shot teardown marker. Because close() is idempotent, this logs
    // exactly once per session, at the instant teardown begins — whichever
    // side logs it first (by wall-clock across the two processes) is the side
    // that initiated the disconnect. Pair it with the msg_writer / msg_reader
    // exit logs to see *why* (which coroutine's socket op failed first).
    log_error_async("rpc::session: close() — tearing down (peer=" + peer_address_ + ")");

    // Close write channel so msg_writer exits
    write_channel_.close();

    // Cancel all pending operations before closing the stream
    try {
      async_manager_.cancel_all_operations();
    } catch (...) {
      // Ignore errors during cancellation
    }

    // Shutdown the socket before closing so pending async_reads unblock with
    // a clean EOF rather than tearing down underneath an in-flight SSL composite
    // op. lowest_layer() works for both tcp::socket and ssl::stream<tcp::socket>.
    // We skip the SSL close_notify handshake on purpose — close() callers are
    // abandoning the connection, not negotiating a graceful shutdown.
    boost::system::error_code ec;
    stream_.lowest_layer().shutdown(asio::socket_base::shutdown_both, ec);
    stream_.lowest_layer().close(ec);
  }

  void set_notification_callback(notification_callback_type callback) {
    notification_callback_ = std::move(callback);
  }

private:
  // Queue a write item for the msg_writer coroutine to send
  auto queue_write(header_type header, buffer_type body) -> asio::awaitable<void> {
    co_await write_channel_.async_send(boost::system::error_code{}, write_item{std::move(header), std::move(body)}, asio::use_awaitable);
  }

  // Dedicated writer coroutine — serializes all outgoing writes on the socket
  asio::awaitable<void> msg_writer() {
    try {
      for (;;) {
        // Name the as_tuple result and structured-bind by reference. With an
        // anonymous `auto [ec, item] = co_await …`, GCC's CFG analysis
        // emits a spurious -Wmaybe-uninitialized about the temporary across
        // the suspension point.
        auto recv_result = co_await write_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        auto& [ec, item] = recv_result;
        if (ec)
          break;

        std::array<asio::const_buffer, 2> buffers = {asio::buffer(item.header.data(), item.header.size() * sizeof(header_type::value_type)),
                                                     asio::buffer(item.body)};

        co_await asio::async_write(stream_, buffers, asio::use_awaitable);
      }
    } catch (boost::system::system_error const& e) {
      // Always log the writer's exit reason (even the "expected" close codes).
      // msg_writer only reaches this catch when async_write itself failed —
      // i.e. THIS side's write broke the socket, making this side the
      // teardown initiator. The reader's loud error on the peer is then just
      // the downstream truncation. Knowing the exact code (broken_pipe vs
      // connection_reset vs an SSL error) is what disambiguates the otherwise
      // circular "both sides see truncation" picture.
      log_error_async("msg_writer exiting (peer=" + peer_address_ + "): " + e.code().message()
                      + " [cat=" + e.code().category().name()
                      + " val=" + std::to_string(e.code().value()) + "]");
    } catch (...) {
      log_error_async("msg_writer exiting (peer=" + peer_address_ + "): unknown error");
    }
    close();
  }

  // async_read + deadline. Each call owns its timer + cancellation_signal
  // via a shared_ptr so the deadline handler stays valid even after the
  // async_read has completed and this function has returned — the lambda
  // gates its access with state->completed and only closes the loop by
  // emitting cancellation if the read hasn't actually finished.
  //
  // We deliberately do NOT use awaitable_operators::`||` / parallel_group
  // here: under SSL + tight loops, parallel_group's per-iteration
  // cancellation-state alloc/teardown produced the ~parallel_group_op_handler
  // UAF observed under ASan.
  template <typename MutableBuffer>
  auto deadline_read(MutableBuffer buffer, std::size_t size, std::chrono::milliseconds timeout) -> asio::awaitable<void> {
    struct deadline_state {
      asio::steady_timer        timer;
      asio::cancellation_signal signal;
      bool                      completed = false;
      explicit deadline_state(asio::any_io_executor ex) : timer(std::move(ex)) {}
    };

    auto executor = co_await asio::this_coro::executor;
    auto state    = std::make_shared<deadline_state>(executor);

    state->timer.expires_after(timeout);
    state->timer.async_wait([state](boost::system::error_code ec) {
      if (ec || state->completed) return;
      state->signal.emit(asio::cancellation_type::terminal);
    });

    auto [ec, bytes] = co_await asio::async_read(
        stream_, buffer, asio::transfer_exactly(size),
        asio::bind_cancellation_slot(
            state->signal.slot(),
            asio::as_tuple(asio::use_awaitable)));

    state->completed = true;
    state->timer.cancel();

    if (ec == asio::error::operation_aborted)
      throw boost::system::system_error(asio::error::timed_out, "deadline_read");
    if (ec)
      throw boost::system::system_error(ec, "deadline_read");
    co_return;
  }

  asio::awaitable<void> msg_reader() {
    try {
      for (;;) {
        header_type msg_header;

        co_await deadline_read(asio::buffer(msg_header.data(), msg_header.size() * sizeof(header_type::value_type)),
                               msg_header.size() * sizeof(header_type::value_type),
                               limits_.idle_timeout);

        // spdlog::debug("Read {}: 0x{:X} {} 0x{:X} {} {}",
        //               __FUNCTION__,
        //               msg_header[MAGIC_HEADER_IDX],
        //               msg_type_to_string(to_msg_type(msg_header[MSG_TYPE_IDX])),
        //               msg_header[CALL_ID_IDX],
        //               msg_header[USER_TOKEN_IDX],
        //               msg_header[MSG_SIZE_IDX]);

        if (MAGIC_HEADER_NUMBER != msg_header[MAGIC_HEADER_IDX]) {
          // A bad magic means the stream is desynchronized — we just read
          // bytes from the middle of some frame's body as if they were a
          // header. There is NO in-band way to resync a length-prefixed
          // multiplexed stream; the only correct action is to drop the
          // session so both ends reconnect and reframe from scratch.
          //
          // The previous behavior (send an error built from the garbage
          // header, then `continue`) was the root of the mid-sync crashes:
          // it kept reading garbage frame after frame until one coincidentally
          // parsed as a `response`, at which point a junk body was decoded
          // into a real pending call and corrupted it (the cereal underflow
          // SIGSEGV). Never continue past a framing violation.
          log_error_async("Invalid magic header (stream desync) — closing session");
          break;
        }

        auto const incoming_type = static_cast<msg_type>(msg_header[MSG_TYPE_IDX] >> 32);
        switch (incoming_type) {
          case msg_type::nop:
            // Fire-and-forget keepalive. Reading the bytes already reset
            // our read deadline; intentionally no reply.
            break;
          case msg_type::ping: {
            // Symmetric keepalive. The peer wants its read deadline reset
            // too, so reply with pong. Non-blocking — if the write channel
            // is full the peer will retry on its next keepalive tick.
            header_type pong_h{};
            pong_h[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
            pong_h[MSG_SIZE_IDX]     = 0;
            pong_h[MSG_TYPE_IDX]     = static_cast<std::uint64_t>(msg_type::pong) << 32;
            pong_h[CALL_ID_IDX]      = 0;
            pong_h[USER_TOKEN_IDX]   = 0;
            (void)write_channel_.try_send(boost::system::error_code{}, write_item{std::move(pong_h), buffer_type{}});
            break;
          }
          case msg_type::pong:
            // Reply to our ping. Reading the bytes already reset our read
            // deadline — that's the whole point. No further reply, which
            // is what prevents an infinite ping-pong loop.
            break;
          case msg_type::request:
            co_await dispatch_request(msg_header);
            break;
          case msg_type::response:
            co_await handle_response(msg_header);
            break;
          case msg_type::notification:
            co_await handle_notification(msg_header);
            break;
          case msg_type::error:
            co_await handle_error(msg_header);
            break;
          default:
            // Valid magic but an unknown message type is also a framing
            // violation (or a protocol mismatch). Don't try to interpret the
            // body — drop the session and reconnect.
            log_error_async("Unknown message type "
                            + std::to_string(static_cast<std::uint64_t>(incoming_type))
                            + " — closing session");
            close();
            co_return;
        }
      }
    } catch (boost::system::system_error const& e) {
      if (e.code() == asio::error::eof || e.code() == asio::error::connection_reset || e.code() == asio::error::broken_pipe ||
          e.code() == asio::error::operation_aborted) {
        // Connection closed - this is expected during shutdown
        log_error_async("Connection closed: " + e.code().message());
      } else {
        // Unexpected error — include category + value so a vague generic
        // message ("unspecified system error") is still diagnosable.
        log_error_async("Unexpected error in msg_reader: " + e.code().message()
                        + " [cat=" + e.code().category().name()
                        + " val=" + std::to_string(e.code().value()) + "]");
      }
    } catch (std::exception const& e) {
      // Catch any other standard exceptions
      log_error_async(std::string("Exception in msg_reader: ") + e.what());
    } catch (...) {
      // Catch everything else to prevent crashes
      log_error_async("Unknown exception in msg_reader");
    }

    // Clean up on exit - close() is now exception-safe
    close();
    co_return;
  }

  asio::awaitable<void> respond(msg_type msgtype, header_type const& related_msg, buffer_type const& rsp_buffer = buffer_type{}) {
    header_type rsp_header;
    rsp_header[MAGIC_HEADER_IDX] = MAGIC_HEADER_NUMBER;
    rsp_header[MSG_TYPE_IDX]     = static_cast<std::uint64_t>(msgtype) << 32;
    rsp_header[CALL_ID_IDX]      = related_msg[CALL_ID_IDX];
    rsp_header[USER_TOKEN_IDX]   = related_msg[USER_TOKEN_IDX];
    rsp_header[MSG_SIZE_IDX]     = rsp_buffer.size();

    co_await queue_write(std::move(rsp_header), buffer_type(rsp_buffer));
  }

  // Gatekeeper context for one inbound call (request or notification).
  // Identity comes from the TLS handshake, which ran before this session was
  // accepted, plus what an earlier handshake call bound to the session: the
  // logical session id (server::notify_session targets it), the device
  // identity and the authenticated role (enforce_auth gates on it). The
  // setters let a handshake handler bind those after auth succeeds.
  client_context make_call_context() {
    std::weak_ptr<session> weak_self = this->shared_from_this();
    return client_context{
        .peer_fingerprint   = peer_fingerprint_,
        .peer_address       = peer_address_,
        .peer_ip            = peer_ip_,
        .logical_session_id = logical_session_id_,
        .set_logical_session_id =
            [weak_self](std::string id) {
              if (auto s = weak_self.lock()) {
                s->set_logical_session_id(std::move(id));
              }
            },
        .logical_device_id = logical_device_id_,
        .set_logical_device_id =
            [weak_self](std::string id) {
              if (auto s = weak_self.lock()) {
                s->set_logical_device_id(std::move(id));
              }
            },
        .logical_role = logical_role_,
        .set_logical_role =
            [weak_self](int r) {
              if (auto s = weak_self.lock()) {
                s->set_logical_role(r);
              }
            },
    };
  }

  asio::awaitable<void> dispatch_request(header_type const& req_header) {
    // Run handlers on the raw io_context (stream_.get_executor()), NOT on
    // io_bound_executor_ — handlers run in parallel; only stream_ I/O is bound
    // to io_bound_executor_. The socket is never itself stranded (the channel
    // hands us a separate strand for I/O), so stream_.get_executor() is the
    // unserialized io_context.
    auto executor = stream_.get_executor();
    auto req_size = req_header[MSG_SIZE_IDX];

    if (req_size > limits_.max_message_bytes) {
      log_error_async("Rejecting oversized request: " + std::to_string(req_size)
                      + " > limit " + std::to_string(limits_.max_message_bytes));
      co_await respond(msg_type::error, req_header);
      close();
      co_return;
    }

    // Per-session request-rate gate. A breach returns an error and drains
    // the body so the session stays framed. We deliberately don't close —
    // a well-behaved client will back off; a broken one will keep hitting
    // errors until idle_timeout reaps the session.
    if (!request_bucket_.try_take()) {
      log_error_async("Request rate limit exceeded");
      buffer_type drain;
      drain.resize(req_size);
      co_await deadline_read(asio::buffer(drain), req_size, limits_.message_read_timeout);
      co_await respond(msg_type::error, req_header);
      co_return;
    }

    buffer_type req_buffer;
    req_buffer.resize(req_size);

    co_await deadline_read(asio::buffer(req_buffer), req_size, limits_.message_read_timeout);

    // Spawn request handling to avoid blocking the reader
    // IMPORTANT: Capture shared_from_this() to keep session alive while processing
    auto self = this->shared_from_this();
    asio::co_spawn(
        executor,
        [self, req_buffer = std::move(req_buffer), req_header]() -> asio::awaitable<void> {
          bool send_error = false;
          try {
            auto& call_id = req_header[CALL_ID_IDX];

            // Gatekeeper context — see make_call_context. The dispatcher
            // enforces auth before invoking the handler (enforce_auth).
            client_context ctx = self->make_call_context();

            // Make the ctx visible to the handler via
            // current_call_context() for the synchronous prefix of its
            // coroutine. Handlers must read it before the first
            // co_await — after a suspension the value is unreliable.
            current_call_context_scope ctx_scope(&ctx);

            // Check if the function is async and dispatch accordingly
            if (self->dispatcher_->is_async(call_id)) {
              auto rsp_buffer = co_await self->dispatcher_->dispatch_async(call_id, req_buffer, ctx);
              co_await self->respond(msg_type::response, req_header, rsp_buffer);
            } else {
              auto rsp_buffer = self->dispatcher_->dispatch(call_id, req_buffer, ctx);
              co_await self->respond(msg_type::response, req_header, rsp_buffer);
            }

          } catch (std::exception const& e) {
            self->log_error_async(std::string("Request dispatch error: ") + e.what());
            send_error = true;
          } catch (...) {
            self->log_error_async("Unknown request dispatch error");
            send_error = true;
          }

          if (send_error) {
            try {
              co_await self->respond(msg_type::error, req_header);
            } catch (...) {
              // Ignore errors when sending error response (connection might be closed)
            }
          }
        },
        asio::detached);

    co_return;
  }

  asio::awaitable<void> handle_response(header_type const& resp_header) {
    auto        rsp_size = resp_header[MSG_SIZE_IDX];

    if (rsp_size > limits_.max_message_bytes) {
      log_error_async("Rejecting oversized response: " + std::to_string(rsp_size)
                      + " > limit " + std::to_string(limits_.max_message_bytes));
      close();
      co_return;
    }

    buffer_type rsp_buffer;
    rsp_buffer.resize(rsp_size);

    co_await deadline_read(asio::buffer(rsp_buffer), rsp_size, limits_.message_read_timeout);

    // spdlog::debug("Read payload for {}: 0x{:X} {} 0x{:X} {} {}",
    //               __FUNCTION__,
    //               resp_header[MAGIC_HEADER_IDX],
    //               msg_type_to_string(to_msg_type(resp_header[MSG_TYPE_IDX])),
    //               resp_header[CALL_ID_IDX],
    //               resp_header[USER_TOKEN_IDX],
    //               resp_header[MSG_SIZE_IDX]);
    auto token = resp_header[USER_TOKEN_IDX];
    // spdlog::debug("Completing {}: {} {}", __FUNCTION__, token, rsp_buffer.size());

    if (!co_await async_manager_.complete_operation(token, std::move(rsp_buffer))) {

      // spdlog::debug("Error completing {}: {} {}", __FUNCTION__, token, rsp_buffer.size());

      // Token not found - response arrived for unknown/cancelled request
    }

    co_return;
  }

  asio::awaitable<void> handle_notification(header_type const& msg_header) {
    auto call_id  = msg_header[CALL_ID_IDX];
    auto req_size = msg_header[MSG_SIZE_IDX];

    if (req_size > limits_.max_message_bytes) {
      log_error_async("Rejecting oversized notification: " + std::to_string(req_size)
                      + " > limit " + std::to_string(limits_.max_message_bytes));
      close();
      co_return;
    }

    buffer_type buffer;
    buffer.resize(req_size);

    co_await deadline_read(asio::buffer(buffer), req_size, limits_.message_read_timeout);

    // Dispatch the notification on the dedicated notification_strand_, NOT the
    // I/O strand we're currently on: the handler runs synchronously (no
    // suspension before the work), so leaving it here would block the next
    // async_read and any pending async_write until it returns. The notification
    // strand keeps handlers off the I/O path while still serializing them, so
    // inbound updates apply in wire order (see notification_strand_'s decl).
    // IMPORTANT: Capture shared_from_this() to keep session alive while processing
    auto self = this->shared_from_this();
    asio::co_spawn(
        notification_strand_,
        [self, call_id, buffer_data = std::move(buffer)]() mutable -> asio::awaitable<void> {
          try {
            // Use notification callback if set (for client-side), otherwise use dispatcher (for server-side)
            if (self->notification_callback_) {
              self->notification_callback_(call_id, buffer_data);
            } else {
              // Same auth gate as requests (WI-12): an inbound notification
              // is a call too, and must not reach a handler the session isn't
              // authorized for — the context-less dispatch overload skips
              // enforce_auth entirely.
              client_context ctx = self->make_call_context();
              current_call_context_scope ctx_scope(&ctx);
              self->dispatcher_->dispatch(call_id, buffer_data, ctx);
            }
          } catch (std::exception const& e) {
            self->log_error_async(std::string("Notification handling error: ") + e.what());
          } catch (...) {
            self->log_error_async("Unknown notification handling error");
          }
          co_return;
        },
        asio::detached);

    co_return;
  }

  asio::awaitable<void> handle_error(header_type const& related_msg) {
    log_error_async("Received error message");

    // Drain any error payload the peer attached so the next framed message
    // starts at a clean boundary.
    auto err_size = related_msg[MSG_SIZE_IDX];
    if (err_size > 0) {
      if (err_size > limits_.max_message_bytes) {
        log_error_async("Rejecting oversized error frame: " + std::to_string(err_size));
        close();
        co_return;
      }
      buffer_type scratch;
      scratch.resize(err_size);
      co_await deadline_read(asio::buffer(scratch), err_size, limits_.message_read_timeout);
    }

    // Notify the pending client-side call (if any) so it raises instead of
    // waiting for the RPC-call timeout. The token embedded in the error
    // header echoes the original request's USER_TOKEN_IDX.
    auto token = related_msg[USER_TOKEN_IDX];
    co_await async_manager_.complete_operation_with_error(token, asio::error::invalid_argument);
    co_return;
  }

  // Helper method for non-blocking error logging
  void log_error_async(const std::string& message) {
    // Capture logger by shared_ptr to avoid accessing 'this' after session destruction
    auto logger = logger_;
    if (logger) {
      asio::co_spawn(
          logger->strand_,
          [logger, message]() -> asio::awaitable<void> {
            co_await logger->error(message);
            co_return;
          },
          asio::detached);
    }
  }

private:
  std::string msg_type_to_string(msg_type type) const {

    switch (type) {
      case msg_type::nop:
        return "nop";
      case msg_type::request:
        return "request";
      case msg_type::response:
        return "response";
      case msg_type::notification:
        return "notification";
      case msg_type::error:
        return "error";
      case msg_type::ping:
        return "ping";
      case msg_type::pong:
        return "pong";
    }
    return "unknown";
  }

  msg_type to_msg_type(std::uint64_t type) const {
    return static_cast<msg_type>(type >> 32);
  }

private:
  AsyncStreamT                     stream_;
  std::shared_ptr<dispatcher_type> dispatcher_;
  std::shared_ptr<async_logger>    logger_;
  // The executor that all stream_ I/O (async_read / async_write) is bound to.
  // Provided by the channel that created this session, NOT created here: only
  // the channel knows whether the underlying stream needs serialization. For
  // SSL the channel passes a strand (SSL_read/SSL_write share OpenSSL state and
  // must never run concurrently); for plain TCP it passes the raw executor (one
  // concurrent read + one concurrent write is safe, so no strand needed). The
  // session itself stays transport-agnostic. stream_.get_executor() remains the
  // *unserialized* io_context, used below for the off-I/O work.
  executor_type                    io_bound_executor_;
  // Notifications are dispatched on their own strand — off io_bound_executor_ so
  // a non-trivial handler (e.g. decoding a large synced component) can't stall
  // the next async_read / pending async_write, yet still serialized so inbound
  // notifications are applied in wire order. Order matters: server→client sync
  // rides notifications and the client applies them with emplace_or_replace
  // (last-applied-wins, no version guard), so parallel dispatch would let a
  // stale update clobber a fresh one. Built on the raw io_context
  // (stream_.get_executor()), independent of the I/O executor. Requests, being
  // independent, use the parallel io_context directly (see dispatch_request).
  asio::strand<executor_type>      notification_strand_;
  async_manager_type               async_manager_;
  write_channel_type               write_channel_;
  notification_callback_type       notification_callback_;
  std::atomic<bool>                is_closed_{false};
  session_limits                   limits_{};
  std::string                      peer_fingerprint_;
  std::string                      peer_address_;
  std::string                      peer_ip_;
  std::string                      logical_session_id_;
  std::string                      logical_device_id_;
  int                              logical_role_ = -1; // -1 = unauthenticated; 0 = user, 1 = admin (WI-3)
  token_bucket                     request_bucket_;
};

} // namespace grlx::rpc