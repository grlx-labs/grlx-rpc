#pragma once

#include "dispatcher.hpp"
#include "message.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <atomic>
#include <functional>
#include <future>
#include <istream>
#include <mutex>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>

namespace grlx::rpc {

namespace asio = boost::asio;

// Portable thread-safe shared_ptr holder with the subset of the
// std::atomic<std::shared_ptr<>> API we need. C++20's atomic<shared_ptr>
// specialization is NOT implemented by the Android NDK's libc++ (its
// std::atomic<T> hard-requires a trivially-copyable T), so we can't use it.
// A single mutex gives identical load/store/exchange/compare_exchange
// semantics on every toolchain. The held pointer is touched only on
// connect / disconnect / once per RPC call — never a hot loop — so the lock
// cost is negligible next to the network round-trip it guards.
template <typename T>
class synchronized_shared_ptr {
public:
  synchronized_shared_ptr() = default;
  explicit synchronized_shared_ptr(std::shared_ptr<T> v)
    : ptr_(std::move(v)) {
  }

  std::shared_ptr<T> load() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ptr_;
  }

  void store(std::shared_ptr<T> v) {
    std::lock_guard<std::mutex> lock(mutex_);
    ptr_ = std::move(v);
  }

  std::shared_ptr<T> exchange(std::shared_ptr<T> v) {
    std::lock_guard<std::mutex> lock(mutex_);
    ptr_.swap(v);
    return v;
  }

  // Atomically set to `desired` iff the current value equals `expected`.
  // On failure, refresh `expected` with the current value (mirrors the
  // std::atomic contract we relied on).
  bool compare_exchange_strong(std::shared_ptr<T>& expected, std::shared_ptr<T> desired) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ptr_ == expected) {
      ptr_ = std::move(desired);
      return true;
    }
    expected = ptr_;
    return false;
  }

private:
  mutable std::mutex            mutex_;
  std::shared_ptr<T>            ptr_;
};

template <typename ChannelT>
class client {
public:
  using buffer_type               = typename ChannelT::buffer_type;
  using encoder_type              = typename ChannelT::encoder_type;
  using session_type              = typename ChannelT::session_type;
  using dispatcher_type           = dispatcher<encoder_type>;
  using notification_handler_type = std::function<void(buffer_type const&)>;

  template <typename... ArgsT>
  client(ArgsT&&... args)
    : channel_(std::forward<ArgsT>(args)...) {
  }

  // Take the session, don't share it: a moved-from client must own nothing,
  // or its destructor (below) would close the connection the new one uses.
  client(client&& other)
    : channel_(std::move(other.channel_))
    , client_session_(other.client_session_.exchange(nullptr))
    , function_hash_cache_(std::move(other.function_hash_cache_)) {
  }

  // Destroying a client closes its connection. The session keeps itself alive
  // via shared_from_this() inside dispatch_requests(), so without this the
  // socket stayed open after the client was gone and the server held a dead
  // session until its idle_timeout reaped it.
  ~client() { disconnect(); }

  client(client const&)            = delete;
  client& operator=(client const&) = delete;

  template <typename EndpointT>
  asio::awaitable<void> connect(EndpointT const& endpoint) {
    auto executor = co_await asio::this_coro::executor;

    // Run the ENTIRE connect + handshake flow on ONE strand. The caller's
    // executor is typically the bare multi-threaded concurrent_io_context;
    // without the strand, the daemon crash-loops on Android the moment
    // async_connect completes (SIGSEGV in reactive_socket_connect_op::
    // do_complete -> awaitable pump -> connect.resume, tiny fault addrs, scudo
    // heap corruption). EMPIRICALLY REQUIRED on Android NDK: with the strand
    // (plus the sync_client reconcile registry-race fix) a 45GB/3429-file
    // upload ran flawlessly; reverting only the strand brought the crash back
    // at the exact original location. Desktop ASan/TSan see nothing either
    // way, so the precise mechanism is unproven — do NOT remove this without
    // an on-device crash-free connect+sync run. dispatch_requests (the
    // steady-state RPC loop) still runs on the session's OWN strand
    // (io_executor()), so post-connect concurrency is unchanged.
    // Never let an exception propagate OUT of the co_spawn'd strand body: on
    // Android, an exception unwinding across the co_spawn/strand-resume
    // boundary on the connect-FAILURE path crashes (see ssl_channel::connect).
    // The body catches everything, records the reason in `connect_error`, and
    // this coroutine re-raises it below from its own clean (non-resume) frame,
    // preserving client::connect's "throws on failure" contract for callers.
    auto connect_error = std::make_shared<std::string>();

    co_await asio::co_spawn(
        asio::make_strand(executor),
        [this, endpoint, connect_error]() -> asio::awaitable<void> {
          try {
            auto session = co_await channel_.connect(endpoint);

            // Descend to the TCP socket via lowest_layer() so the check works for
            // both plain tcp_channel and ssl_channel (next_layer() is ssl::stream).
            if (!session || !session->next_layer().lowest_layer().is_open()) {
              client_session_.store(nullptr);
              *connect_error = "invalid session after connect (server unreachable?)";
              co_return;
            }

            co_await session->handshake();

            // Publish the session only after the handshake succeeds.
            setup_notification_handling(session);
            client_session_.store(session);

            // Spawn dispatch_requests on the session's OWN I/O executor
            // (io_executor() = a strand over the socket's io_context) — SSL is not
            // safe for concurrent SSL_read/SSL_write, so this serializes the
            // msg_reader/msg_writer while preserving reactor affinity.
            auto io_executor = session->io_executor();
            asio::co_spawn(io_executor, session->dispatch_requests(),
              [this, weak_session = std::weak_ptr<session_type>(session)](std::exception_ptr error) {
                if (error) {
                  try {
                    std::rethrow_exception(error);
                  } catch (std::exception const& e) {
                    spdlog::error("rpc::client::dispatch_requests error: {}", e.what());
                  } catch (...) {
                    spdlog::error("rpc::client::dispatch_requests unknown error");
                  }
                }
                // Session is dead — clear it so is_connected() returns false and
                // the health-check reconnects. compare_exchange so a completion
                // from an OLD session can't clobber one installed by a concurrent
                // reconnect.
                auto self = weak_session.lock();
                if (self) {
                  std::shared_ptr<session_type> expected = self;
                  client_session_.compare_exchange_strong(expected, nullptr);
                }
              });
          } catch (std::exception const& ex) {
            client_session_.store(nullptr);
            *connect_error = ex.what();
          } catch (...) {
            client_session_.store(nullptr);
            *connect_error = "unknown connect error";
          }
          co_return;
        },
        asio::use_awaitable);

    // Re-raise from this clean frame (not mid strand-resume) so the caller's
    // try/catch sees the failure exactly as before.
    if (!connect_error->empty()) {
      throw std::runtime_error("rpc::client::connect: " + *connect_error);
    }

    co_return;
  }

  template <typename ReturnT, typename... ArgsT>
  auto invoke(std::string const& func_name, ArgsT&&... args) -> asio::awaitable<ReturnT> {
    co_return co_await invoke_with_timeout<ReturnT>(std::chrono::seconds(30), func_name, std::forward<ArgsT>(args)...);
  }

  // invoke with an explicit per-call timeout. Short control calls (e.g. the
  // sync handshake) should pass a small timeout so a lost request becomes a
  // quick retry on a fresh session instead of a 30 s "Connecting..." stall.
  template <typename ReturnT, typename... ArgsT>
  auto invoke_with_timeout(std::chrono::milliseconds timeout, std::string const& func_name, ArgsT&&... args) -> asio::awaitable<ReturnT> {
    // Load the session ONCE into a local. This is the critical fix for the
    // concurrent-disconnect race: a plain re-read of client_session_ at the
    // call site could be torn by a concurrent reset() and hand call() a null
    // `this`. The local copy is both synchronized (atomic load) and keeps the
    // session object alive for the whole call, even if a reconnect swaps the
    // member out underneath us.
    auto session = client_session_.load();
    if (!session) [[unlikely]] {
      throw std::runtime_error("not connected");
    }

    // A fresh request buffer per call — owned solely by this coroutine frame,
    // so there is no shared/pooled state to race with concurrent invokes.
    // (The allocation is negligible next to the network round-trip.)
    buffer_type req_buffer;

    message_request<typename std::decay<ArgsT>::type...> request{std::make_tuple(std::forward<ArgsT>(args)...)};

    if (!encoder_type::encode(req_buffer, request)) [[unlikely]] {
      throw std::runtime_error("Failed to encode request");
    }

    auto rsp_buffer = co_await session->call(func_name, req_buffer, timeout);

    message_response<typename std::decay<ReturnT>::type> response;

    if (!encoder_type::decode(rsp_buffer, response)) [[unlikely]] {
      throw std::runtime_error("Failed to decode response");
    }

    if constexpr (std::is_void<ReturnT>::value) {
      co_return;
    } else {
      spdlog::debug("Invoke finished: {}", func_name);
      co_return std::move(response.result); // Move result for efficiency
    }
  }

  // template <typename ReturnT, typename... ArgsT>
  // auto invoke_async(std::string const& func_name, ArgsT&&... args) -> std::future<ReturnT> {
  //   if (!client_session_) {
  //     auto promise = std::promise<ReturnT>();
  //     promise.set_exception(std::make_exception_ptr(std::runtime_error("not connected")));
  //     return promise.get_future();
  //   }

  //   auto  call_id          = get_cached_function_hash(func_name);
  //   auto  req_buffer_guard = buffer_pool_.get_buffer();
  //   auto& req_buffer       = *req_buffer_guard;

  //   message_request<typename std::decay<ArgsT>::type...> request{std::make_tuple(std::forward<ArgsT>(args)...)};

  //   if (!encoder_type::encode(req_buffer, request)) {
  //     auto promise = std::promise<ReturnT>();
  //     promise.set_exception(std::make_exception_ptr(std::runtime_error("Failed to encode request")));
  //     return promise.get_future();
  //   }

  //   auto [operation, guard] = client_session_->call_future(func_name, req_buffer);

  //   auto promise = std::make_shared<std::promise<ReturnT>>();
  //   auto future  = promise->get_future();

  //   operation.set_completion_handler([promise](buffer_type&& rsp_buffer) {
  //     try {
  //       message_response<typename std::decay<ReturnT>::type> response;
  //       if (!encoder_type::decode(rsp_buffer, response)) {
  //         promise->set_exception(std::make_exception_ptr(std::runtime_error("Failed to decode response")));
  //         return;
  //       }

  //       if constexpr (std::is_void<ReturnT>::value) {
  //         promise->set_value();
  //       } else {
  //         promise->set_value(std::move(response.result));
  //       }
  //     } catch (...) {
  //       promise->set_exception(std::current_exception());
  //     }
  //   });

  //   return future;
  // }

  // Notification handling methods - with automatic type deduction!
  template <typename... ArgsT>
  void register_notification_handler(std::string const& notification_name, std::function<void(ArgsT...)>&& handler) {
    auto wrapper = [handler = std::move(handler)](buffer_type const& buffer) {
      message_request<typename std::decay<ArgsT>::type...> request;
      if (encoder_type::decode(buffer, request)) {
        std::apply(handler, request.args);
      }
    };

    auto   hash_value = shash64(notification_name).value();
    size_t total;
    {
      std::lock_guard<std::mutex> lock(notification_mutex_);
      notification_handlers_[hash_value] = std::move(wrapper);
      total                              = notification_handlers_.size();
    }
    spdlog::info("RPC: registered notification handler '{}' hash=0x{:X} (total={})",
                  notification_name, hash_value, total);
  }

  // Automatic type deduction for lambdas and function objects (like server's attach!)
  template <typename F>
  void register_notification_handler(std::string const& notification_name, F&& func) {
    register_notification_handler(notification_name, std::function{std::forward<F>(func)});
  }

  void unregister_notification_handler(std::string const& notification_name) {
    auto hash_value = shash64(notification_name).value();
    std::lock_guard<std::mutex> lock(notification_mutex_);
    notification_handlers_.erase(hash_value);
  }

  void clear_notification_handlers() {
    std::lock_guard<std::mutex> lock(notification_mutex_);
    notification_handlers_.clear();
  }

  bool has_notification_handler(std::string const& notification_name) const {
    auto hash_value = shash64(notification_name).value();
    std::lock_guard<std::mutex> lock(notification_mutex_);
    return notification_handlers_.find(hash_value) != notification_handlers_.end();
  }

  size_t notification_handler_count() const {
    std::lock_guard<std::mutex> lock(notification_mutex_);
    return notification_handlers_.size();
  }

  ChannelT& channel() {
    return channel_;
  }

  const ChannelT& channel() const {
    return channel_;
  }

  bool is_connected() const noexcept {
    return client_session_.load() != nullptr;
  }

  // Non-blocking keepalive. Returns false if no session or the write channel
  // is full. Apps with long idle periods (watching a video stream but not
  // issuing RPCs) should call this periodically to keep both peers'
  // idle_timeouts from firing — the server replies with msg_type::pong so a
  // single client-side ping resets *both* read deadlines.
  bool try_ping() {
    auto session = client_session_.load();
    return session && session->try_ping();
  }

  void disconnect() {
    // Tear down the socket so the session's msg_reader/msg_writer unblock and
    // exit. Without this, the session stays alive via its own shared_from_this
    // inside dispatch_requests(), the server keeps streaming notifications,
    // and every one of them logs "unhandled notification" because we've cleared
    // notification_handlers_ below.
    auto session = client_session_.exchange(nullptr);
    if (session) {
      session->close();
    }
    function_hash_cache_.clear();
    {
      std::lock_guard<std::mutex> lock(notification_mutex_);
      notification_handlers_.clear();
    }
  }

  struct performance_stats {
    size_t total_calls       = 0;
    size_t hash_cache_hits   = 0;
    size_t hash_cache_misses = 0;

    double hash_cache_hit_ratio() const {
      auto total = hash_cache_hits + hash_cache_misses;
      return total > 0 ? static_cast<double>(hash_cache_hits) / total : 0.0;
    }
  };

  performance_stats get_performance_stats() const {
    performance_stats stats;
    stats.total_calls       = total_calls_;
    stats.hash_cache_hits   = hash_cache_hits_;
    stats.hash_cache_misses = hash_cache_misses_;
    return stats;
  }

private:
  std::uint64_t get_cached_function_hash(const std::string& func_name) {
    auto it = function_hash_cache_.find(func_name);
    if (it != function_hash_cache_.end()) {
      hash_cache_hits_++;
      return it->second;
    }

    auto hash_value                 = shash64(func_name).value();
    function_hash_cache_[func_name] = hash_value;
    hash_cache_misses_++;
    return hash_value;
  }

  void setup_notification_handling(std::shared_ptr<session_type> const& session) {
    if (!session) {
      return;
    }

    // Set up the notification callback for the session
    auto notification_callback = [this](std::uint64_t call_id, buffer_type const& buffer) {
      handle_notification(call_id, buffer);
    };

    session->set_notification_callback(std::move(notification_callback));
  }

  void handle_notification(std::uint64_t call_id, buffer_type const& buffer) {
    // Copy the handler out under the lock, then invoke it UNLOCKED. This
    // dispatch runs on the session's notification path (pool/strand) while
    // disconnect()/clear() can be mutating the map on another thread — a
    // concurrent find vs erase/rehash on the unordered_map is a heap-corrupting
    // data race. Copying out also means a concurrent clear() can't invalidate
    // the iterator under the handler call.
    notification_handler_type handler;
    {
      std::lock_guard<std::mutex> lock(notification_mutex_);
      auto it = notification_handlers_.find(call_id);
      if (it != notification_handlers_.end()) {
        handler = it->second;
      }
    }
    if (handler) {
      try {
        handler(buffer);
      } catch (const std::exception& e) {
        spdlog::error("Error in notification handling: {}", e.what());
      } catch (...) {
        spdlog::error("Unknown error in notification handling");
      }
    } else {
      spdlog::warn("RPC: unhandled notification call_id=0x{:X}, buffer={} bytes", call_id, buffer.size());
    }
  }

private:
  ChannelT                      channel_;
  // Accessed concurrently: invoke() coroutines read it on the RPC worker pool
  // while connect()/disconnect()/the dispatch-completion handler reset it. A
  // plain shared_ptr here is a data race — a torn read hands call() a null or
  // half-valid session pointer (the SIGSEGV in async_manager::create_operation
  // and the cereal bufferbuf::underflow heap corruption both trace back here).
  // synchronized_shared_ptr makes every access mutex-synchronized, and loading
  // it into a local keeps the session alive for the duration of an in-flight
  // call. (std::atomic<shared_ptr> would be ideal but the Android NDK's libc++
  // doesn't implement that C++20 specialization — see the type's comment.)
  synchronized_shared_ptr<session_type> client_session_;

  std::unordered_map<std::string, std::uint64_t>               function_hash_cache_;
  // Guards notification_handlers_: dispatched (read) on the session's
  // notification path while register/clear/disconnect mutate it on other
  // threads. A concurrent find vs erase/rehash corrupts the map.
  mutable std::mutex                                           notification_mutex_;
  std::unordered_map<std::uint64_t, notification_handler_type> notification_handlers_;

  mutable std::atomic<size_t> total_calls_{0};
  mutable std::atomic<size_t> hash_cache_hits_{0};
  mutable std::atomic<size_t> hash_cache_misses_{0};
};
} // namespace grlx::rpc