// read_credential: systemd $CREDENTIALS_DIRECTORY first, then the fallback
// directory, with errors that name every path tried.

#include <grlx/rpc/credentials.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using grlx::rpc::read_credential;

namespace {

class credentials_test : public ::testing::Test {
protected:
  void SetUp() override {
    root_ = fs::temp_directory_path() /
            ("grlx_rpc_credentials_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "_" +
             ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::create_directories(root_ / "systemd");
    fs::create_directories(root_ / "fallback");
    ::unsetenv("CREDENTIALS_DIRECTORY");
  }

  void TearDown() override {
    ::unsetenv("CREDENTIALS_DIRECTORY");
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  static void write(fs::path const& path, std::string const& data) {
    std::ofstream(path, std::ios::binary) << data;
  }

  fs::path root_;
};

}  // namespace

TEST_F(credentials_test, prefers_systemd_credentials_directory) {
  write(root_ / "systemd" / "server_key.pem", "from-systemd");
  write(root_ / "fallback" / "server_key.pem", "from-fallback");
  ::setenv("CREDENTIALS_DIRECTORY", (root_ / "systemd").c_str(), 1);

  EXPECT_EQ(read_credential("server_key.pem", root_ / "fallback"), "from-systemd");
}

TEST_F(credentials_test, falls_back_when_not_under_systemd) {
  write(root_ / "fallback" / "server_key.pem", "from-fallback");

  EXPECT_EQ(read_credential("server_key.pem", root_ / "fallback"), "from-fallback");
}

TEST_F(credentials_test, falls_back_when_systemd_lacks_the_credential) {
  write(root_ / "fallback" / "server_key.pem", "from-fallback");
  ::setenv("CREDENTIALS_DIRECTORY", (root_ / "systemd").c_str(), 1);

  EXPECT_EQ(read_credential("server_key.pem", root_ / "fallback"), "from-fallback");
}

TEST_F(credentials_test, missing_credential_names_every_path_tried) {
  ::setenv("CREDENTIALS_DIRECTORY", (root_ / "systemd").c_str(), 1);

  try {
    read_credential("server_key.pem", root_ / "fallback");
    FAIL() << "expected std::runtime_error";
  } catch (std::runtime_error const& e) {
    std::string const what = e.what();
    EXPECT_NE(what.find((root_ / "systemd" / "server_key.pem").string()), std::string::npos) << what;
    EXPECT_NE(what.find((root_ / "fallback" / "server_key.pem").string()), std::string::npos) << what;
  }
}

TEST_F(credentials_test, rejects_empty_file) {
  write(root_ / "fallback" / "server_key.pem", "");

  EXPECT_THROW(read_credential("server_key.pem", root_ / "fallback"), std::runtime_error);
}

TEST_F(credentials_test, rejects_oversized_file) {
  write(root_ / "fallback" / "server_key.pem", std::string((1u << 20) + 1, 'x'));

  EXPECT_THROW(read_credential("server_key.pem", root_ / "fallback"), std::runtime_error);
}
