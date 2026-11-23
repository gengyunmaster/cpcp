#pragma once

#include "crypto/secret.hpp"
#include "repository/snapshot.hpp"

#include <filesystem>
#include <vector>

namespace cpcp::application {

struct BackupOptions {
    bool revalidate_all = false;
    bool full_source_read = false;
    bool cross_file_systems = false;
    bool no_parent = false;
};

struct BackupReport {
    repository::SnapshotSummary snapshot;
    std::uint64_t skipped_entries = 0;
};

domain::Result<BackupReport> backup_add(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const std::vector<std::filesystem::path>& roots,
    const BackupOptions& options
);

}
