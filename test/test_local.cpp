// local_channel: RPC over a Unix-domain socket, bound to a path or adopted
// already listening (systemd socket activation).

#include "fixtures/rpc_fixture.hpp"

#include <grlx/rpc/local_channel.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace asio = boost::asio;
namespace fs   = std::filesystem;
using grlx::rpc::testing::rpc_fixture;

using local_ch = grlx::rpc::local_channel<grlx::rpc::binary_encoder>;
using local    = grlx::rpc::local;

namespace {

class rpc_local_test : public rpc_fixture {
protected:
  void SetUp() override {
    rpc_fixture::SetUp();
    dir_ = fs::temp_directory_path() /
           ("grlx_rpc_local_" + std::to_string(::getpid()) + "_" +
            ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
    fs::create_directories(dir_);
  }
  void TearDown() override {
    rpc_fixture::TearDown();
    fs::remove_all(dir_);
  }

  std::string sock_path() const { return (dir_ / "rpc.sock").string(); }

  fs::path dir_;
};

void attach_echo(grlx::rpc::server<local_ch>& s) {
  s.attach("add", [](int a, int b) -> int { return a + b; });
  s.attach("echo", [](std::string text) -> std::string { return text; });
}

// A socket bound and listening the way systemd hands one over.
int listening_socket(std::string const& path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(fd, 16) != 0) {
    return -1;
  }
  return fd;
}

} // namespace

TEST_F(rpc_local_test, invokes_over_a_bound_path_and_removes_the_file_on_close) {
  auto const path = sock_path();
  run([&]() -> asio::awaitable<void> {
    grlx::rpc::server<local_ch> server;
    attach_echo(server);
    co_await server.start(local::endpoint(path));
    EXPECT_TRUE(fs::exists(path));

    grlx::rpc::client<local_ch> client;
    co_await client.connect(local::endpoint(path));
    EXPECT_EQ(co_await client.template invoke<int>("add", 2, 3), 5);
    EXPECT_EQ(co_await client.template invoke<std::string>("echo", std::string("über % 100")), "über % 100");
    client.disconnect();

    co_await server.channel().close();
    EXPECT_FALSE(fs::exists(path)) << "the channel created the socket file, so it removes it";
  });
}

TEST_F(rpc_local_test, a_stale_socket_file_from_a_previous_run_is_replaced) {
  auto const path = sock_path();
  std::ofstream(path) << "stale";
  run([&]() -> asio::awaitable<void> {
    grlx::rpc::server<local_ch> server;
    attach_echo(server);
    co_await server.start(local::endpoint(path));
    grlx::rpc::client<local_ch> client;
    co_await client.connect(local::endpoint(path));
    EXPECT_EQ(co_await client.template invoke<int>("add", 40, 2), 42);
    client.disconnect();
    co_await server.channel().close();
  });
}

TEST_F(rpc_local_test, adopts_an_inherited_listening_socket_and_leaves_its_file) {
  auto const path = sock_path();
  int const  fd   = listening_socket(path);
  ASSERT_GE(fd, 0);
  run([&]() -> asio::awaitable<void> {
    grlx::rpc::server<local_ch> server;
    attach_echo(server);
    co_await server.start(fd);

    grlx::rpc::client<local_ch> client;
    co_await client.connect(local::endpoint(path));
    EXPECT_EQ(co_await client.template invoke<int>("add", 1, 1), 2);
    client.disconnect();

    co_await server.channel().close();
    EXPECT_TRUE(fs::exists(path)) << "an adopted socket's file belongs to whoever created it";
  });
}

TEST_F(rpc_local_test, connecting_to_nothing_fails_cleanly) {
  auto const path = sock_path();
  run([&]() -> asio::awaitable<void> {
    grlx::rpc::client<local_ch> client;
    bool threw = false;
    try {
      co_await client.connect(local::endpoint(path));
    } catch (std::exception const&) {
      threw = true;
    }
    EXPECT_TRUE(threw);
  });
}

TEST(rpc_local, inherited_listen_fd_follows_the_systemd_protocol) {
  ::unsetenv("LISTEN_PID");
  ::unsetenv("LISTEN_FDS");
  EXPECT_FALSE(grlx::rpc::inherited_listen_fd()) << "not socket-activated";

  ::setenv("LISTEN_PID", std::to_string(::getpid()).c_str(), 1);
  ::setenv("LISTEN_FDS", "1", 1);
  EXPECT_EQ(grlx::rpc::inherited_listen_fd(), 3);

  ::setenv("LISTEN_PID", std::to_string(::getpid() + 1).c_str(), 1);
  EXPECT_FALSE(grlx::rpc::inherited_listen_fd()) << "the sockets were meant for another process";

  ::setenv("LISTEN_PID", std::to_string(::getpid()).c_str(), 1);
  ::setenv("LISTEN_FDS", "0", 1);
  EXPECT_FALSE(grlx::rpc::inherited_listen_fd());

  ::unsetenv("LISTEN_PID");
  ::unsetenv("LISTEN_FDS");
}
