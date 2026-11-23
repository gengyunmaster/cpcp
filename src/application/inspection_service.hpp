#pragma once

#include "crypto/secret.hpp"
#include "repository/snapshot.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace cpcp::repository {
class ChunkStore;
}

namespace cpcp::application {

struct SnapshotRequest {
    std::optional<std::uint64_t> generation;
    bool latest_complete = false;
};

struct SnapshotEntry {
    std::string type;
    std::uint32_t root = 0;
    std::string root_label;
    std::string path;
    std::uint64_t size = 0;
    std::int64_t mtime_seconds = 0;
    std::uint32_t mtime_nanoseconds = 0;
    std::uint32_t mode = 0;
};

struct BrowseOptions {
    SnapshotRequest snapshot;
    std::optional<std::uint32_t> root;
    std::optional<std::string> root_label;
    std::string path_prefix;
    std::string glob;
};

struct RestoreOptions {
    std::filesystem::path destination;
    std::optional<std::uint32_t> root;
    std::optional<std::string> path;
    bool strip_root = false;
    bool overwrite = false;
    bool yes = false;
    bool strict_metadata = false;
    bool repo_read_only = false;
    bool allow_partial = false;
    bool latest_complete = false;
};

struct RestoreReport {
    std::uint64_t snapshot_generation = 0;
    std::string snapshot_status;
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

domain::Result<repository::SnapshotSummary> resolve_snapshot(
    const std::vector<repository::SnapshotSummary>& snapshots,
    const SnapshotRequest& request
);

domain::Result<std::uint64_t> verify_snapshot_manifest(
    const std::filesystem::path& repository,
    const repository::RepositoryConfig& config,
    const crypto::SecureKey& master,
    const repository::SnapshotSummary& summary,
    repository::ChunkStore& store,
    bool deep
);

struct BrowseReport {
    std::uint64_t snapshot_generation = 0;
    std::string snapshot_status;
    std::uint64_t entries = 0;
};

using SnapshotEntrySink = std::function<domain::Result<void>(const SnapshotEntry&)>;

domain::Result<BrowseReport> browse_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const BrowseOptions& options,
    bool repo_read_only,
    const SnapshotEntrySink& sink
);

}
