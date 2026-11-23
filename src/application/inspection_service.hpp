#pragma once

#include "crypto/secret.hpp"
#include "repository/snapshot.hpp"

#include <filesystem>
#include <optional>

namespace cpcp::application {

struct RestoreOptions {
    std::filesystem::path destination;
    std::optional<std::uint32_t> root;
    std::optional<std::string> path;
    bool strip_root = false;
    bool overwrite = false;
    bool yes = false;
    bool strict_metadata = false;
    bool repo_read_only = false;
};

struct RestoreReport {
    std::uint64_t files = 0;
    std::uint64_t directories = 0;
    std::uint64_t metadata_warnings = 0;
};

struct VerifyOptions {
    bool deep = false;
    bool repo_read_only = false;
};

struct VerifyReport {
    std::uint64_t snapshots = 0;
    std::uint64_t chunks = 0;
    bool degraded_redundancy = false;
};

domain::Result<RestoreReport> restore_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::optional<std::uint64_t> generation,
    const RestoreOptions& options
);

domain::Result<VerifyReport> verify_repository(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const VerifyOptions& options
);

}
