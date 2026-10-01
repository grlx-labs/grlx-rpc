#pragma once

// Secrets a service reads at startup instead of compiling them in — e.g. the
// server's TLS private key, so release binaries carry public material only.
//
// Lookup order for credential `name`:
//   1. $CREDENTIALS_DIRECTORY/<name> — systemd `LoadCredential=` (and
//      `LoadCredentialEncrypted=`): systemd copies the file from a root-only
//      path into a private per-service directory at start, so the service
//      user never needs read access to the original.
//   2. <fallback_dir>/<name> — runs outside systemd (development, tests).
//      Relative paths resolve against the working directory.
//
// Read once at startup; this is blocking file I/O and must not be called from
// a hot path or an event-loop handler.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace grlx::rpc {

// Throws std::runtime_error naming every path tried when the credential is
// missing, unreadable, empty or implausibly large (> 1 MiB — a PEM key or
// certificate is a few KiB; anything bigger is the wrong file).
inline std::string read_credential(std::string_view name, std::filesystem::path const& fallback_dir = "tls") {
  namespace fs = std::filesystem;
  constexpr std::uintmax_t max_size = 1u << 20;

  std::string tried;
  auto try_read = [&](fs::path const& path) -> std::string {
    if (!tried.empty()) {
      tried += ", ";
    }
    tried += path.string();

    std::error_code ec;
    auto const size = fs::file_size(path, ec);
    if (ec) {
      return {};
    }
    if (size == 0 || size > max_size) {
      throw std::runtime_error("credential '" + std::string{name} + "' at " + path.string() + " has implausible size " +
                               std::to_string(size));
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      throw std::runtime_error("credential '" + std::string{name} + "' at " + path.string() + " is not readable");
    }
    std::string data(static_cast<std::size_t>(size), '\0');
    in.read(data.data(), static_cast<std::streamsize>(data.size()));
    if (!in) {
      throw std::runtime_error("credential '" + std::string{name} + "' at " + path.string() + " could not be read");
    }
    return data;
  };

  if (char const* dir = std::getenv("CREDENTIALS_DIRECTORY"); dir && *dir) {
    if (auto data = try_read(fs::path{dir} / name); !data.empty()) {
      return data;
    }
  }
  if (auto data = try_read(fallback_dir / name); !data.empty()) {
    return data;
  }
  throw std::runtime_error("credential '" + std::string{name} + "' not found (tried " + tried + ")");
}

}  // namespace grlx::rpc
