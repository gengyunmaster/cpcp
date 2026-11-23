#pragma once

#include "crypto/secret.hpp"
#include "repository/snapshot.hpp"

#include <filesystem>
#include <map>
#include <vector>

namespace cpcp::application {

struct BackupOptions {
    bool revalidate_all = false;
    bool full_source_read = false;
    bool cross_file_systems = false;
    bool no_parent = false;
    std::optional<std::uint64_t> base_generation;
    bool allow_partial = false;
    bool unsupported_fail = false;
    std::uint64_t interrupt_after_chunks_for_testing = 0;
    bool interrupt_after_main_for_testing = false;
};

struct BackupReport {
    repository::SnapshotSummary snapshot;
    std::uint64_t skipped_entries = 0;
    domain::Uuid session_uuid{};
    bool resumed = false;
};

struct ResumeOptions {
    bool revalidate_all = false;
    bool restart_files = false;
    std::map<std::string, std::filesystem::path> remap_roots;
    std::uint64_t interrupt_after_chunks_for_testing = 0;
    bool interrupt_after_main_for_testing = false;
};

struct BackupSessionStatus {
    domain::Uuid session_uuid{};
    std::uint64_t snapshot_generation = 0;
    std::uint64_t records = 0;
    std::vector<repository::RootInfo> roots;
    std::string state;
    bool torn_tail = false;
};

domain::Result<BackupReport> backup_add(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const std::vector<std::filesystem::path>& roots,
    const BackupOptions& options
);

domain::Result<BackupReport> backup_resume(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const domain::Uuid& session_uuid,
    const ResumeOptions& options
);

domain::Result<std::vector<BackupSessionStatus>> backup_status(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
);

domain::Result<void> backup_discard(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const domain::Uuid& session_uuid,
    bool confirmed
);

}
