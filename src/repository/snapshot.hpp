#pragma once

#include "repository/config.hpp"
#include "storage/session_spool.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace cpcp::repository {

struct RootInfo {
    std::uint32_t index;
    domain::Uuid uuid;
    std::string label;
    std::string path;
};

struct DirectoryInfo {
    std::uint32_t root;
    std::string path;
    std::int64_t mtime_seconds;
    std::uint32_t mtime_nanoseconds;
    std::uint32_t mode;
};

struct FileInfo {
    std::uint64_t sequence;
    std::uint32_t root;
    std::string path;
    std::uint64_t size;
    std::uint64_t chunk_count;
    crypto::Digest file_id;
    std::int64_t mtime_seconds;
    std::uint32_t mtime_nanoseconds;
    std::uint32_t mode;
};

struct ChunkBatch {
    std::uint64_t file;
    std::uint64_t batch;
    std::vector<crypto::ChunkDescriptor> chunks;
};

struct FileEnd {
    std::uint64_t file;
    std::uint64_t chunk_count;
    crypto::Digest file_id;
};

struct PolicySkip {
    std::uint32_t root;
    std::string path;
    std::string reason;
};

struct FailureInfo {
    std::uint32_t root;
    std::string path;
    std::string reason;
};

struct SelectionPolicy {
    std::string unsupported = "skip";
    bool one_file_system = true;
};

struct SelectionStats {
    std::uint64_t policy_skipped_entries = 0;
    std::uint64_t failed_entries = 0;
};

struct SnapshotStats {
    std::uint64_t files = 0;
    std::uint64_t directories = 0;
    std::uint64_t logical_bytes = 0;
    std::uint64_t chunk_references = 0;
    std::uint64_t new_chunks = 0;
    std::uint64_t deduplicated_chunks = 0;
    crypto::Digest chunk_set_commitment{};
    std::optional<SelectionStats> selection;
};

struct SnapshotSummary {
    crypto::SnapshotContext context;
    domain::Uuid session_uuid{};
    domain::Uuid parent_uuid{};
    crypto::Digest parent_summary_digest{};
    bool has_parent = false;
    std::string status = "complete";
    SelectionPolicy selection_policy;
    std::int64_t created_seconds = 0;
    std::uint32_t created_nanoseconds = 0;
    std::vector<RootInfo> roots;
    SnapshotStats stats;
    crypto::Digest main_ciphertext_digest{};
    std::uint64_t main_stored_length = 0;
};

std::string snapshot_basename(
    std::uint64_t generation,
    const domain::Uuid& snapshot_uuid
);
std::filesystem::path snapshot_main_path(
    const std::filesystem::path& repository,
    const SnapshotSummary& summary
);
std::filesystem::path snapshot_summary_path(
    const std::filesystem::path& repository,
    const SnapshotSummary& summary
);

domain::Result<void> write_snapshot_summary(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key,
    const SnapshotSummary& summary
);
domain::Result<SnapshotSummary> read_snapshot_summary(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key
);

class SnapshotWriter {
public:
    SnapshotWriter(const SnapshotWriter&) = delete;
    SnapshotWriter& operator=(const SnapshotWriter&) = delete;
    SnapshotWriter(SnapshotWriter&&) = default;
    SnapshotWriter& operator=(SnapshotWriter&&) = default;

    static domain::Result<SnapshotWriter> create(
        std::filesystem::path repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key,
        crypto::SnapshotContext context,
        domain::Uuid session_uuid,
        std::optional<SnapshotSummary> parent = std::nullopt,
        SelectionPolicy selection_policy = {}
    );

    domain::Result<void> append_root(const RootInfo& root);
    domain::Result<void> append_directory(const DirectoryInfo& directory);
    domain::Result<void> append_file_header(const FileInfo& file);
    domain::Result<void> append_chunk_batch(const ChunkBatch& batch);
    domain::Result<void> append_file_end(const FileEnd& end);
    domain::Result<void> append_policy_skip(const PolicySkip& skip);
    domain::Result<void> append_failure(const FailureInfo& failure);
    domain::Result<SnapshotSummary> finish(
        SnapshotStats stats,
        std::string status = "complete",
        bool interrupt_after_main_for_testing = false
    );
    domain::Result<void> abort();

private:
    SnapshotWriter(
        std::filesystem::path repository,
        RepositoryConfig config,
        SnapshotSummary summary,
        crypto::SecureKey snapshot_key,
        std::unique_ptr<storage::SessionSpoolWriter> writer
    );

    domain::Result<void> append(
        crypto::RecordType type,
        const nlohmann::json& record
    );

    std::filesystem::path repository_;
    RepositoryConfig config_;
    SnapshotSummary summary_;
    crypto::SecureKey snapshot_key_;
    std::unique_ptr<storage::SessionSpoolWriter> writer_;
    SelectionStats selection_stats_;
    bool finished_ = false;
};

class SnapshotReader {
public:
    SnapshotReader(const SnapshotReader&) = delete;
    SnapshotReader& operator=(const SnapshotReader&) = delete;
    SnapshotReader(SnapshotReader&&) = default;
    SnapshotReader& operator=(SnapshotReader&&) = default;

    static domain::Result<SnapshotReader> open(
        const std::filesystem::path& repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key,
        const SnapshotSummary& summary
    );

    domain::Result<std::optional<storage::SpoolRecord>> next();
    const SnapshotSummary& summary() const;

private:
    SnapshotReader(
        RepositoryConfig config,
        SnapshotSummary summary,
        crypto::SecureKey snapshot_key,
        std::unique_ptr<storage::SessionSpoolReader> reader
    );

    RepositoryConfig config_;
    SnapshotSummary summary_;
    crypto::SecureKey snapshot_key_;
    std::unique_ptr<storage::SessionSpoolReader> reader_;
};

domain::Result<std::vector<SnapshotSummary>> list_snapshots(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key
);

struct SnapshotHeaderInfo {
    std::int64_t created_seconds = 0;
    std::uint32_t created_nanoseconds = 0;
    std::string tool_version;
    SelectionPolicy selection_policy;
    bool has_parent = false;
    domain::Uuid parent_uuid{};
    crypto::Digest parent_summary_digest{};
};

domain::Result<crypto::SnapshotContext> parse_snapshot_context(
    const storage::SpoolRecord& record
);
domain::Result<SnapshotHeaderInfo> parse_snapshot_header(
    const storage::SpoolRecord& record
);
domain::Result<RootInfo> parse_root(const storage::SpoolRecord& record);
domain::Result<DirectoryInfo> parse_directory(const storage::SpoolRecord& record);
domain::Result<FileInfo> parse_file_header(const storage::SpoolRecord& record);
domain::Result<ChunkBatch> parse_chunk_batch(const storage::SpoolRecord& record);
domain::Result<FileEnd> parse_file_end(const storage::SpoolRecord& record);
domain::Result<PolicySkip> parse_policy_skip(const storage::SpoolRecord& record);
domain::Result<FailureInfo> parse_failure(const storage::SpoolRecord& record);
domain::Result<SnapshotStats> parse_final_stats(const storage::SpoolRecord& record);
domain::Result<std::string> parse_final_status(const storage::SpoolRecord& record);

}
