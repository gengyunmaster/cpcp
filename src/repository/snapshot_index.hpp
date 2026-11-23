#pragma once

#include "crypto/content_id.hpp"
#include "crypto/secret.hpp"
#include "domain/encoding.hpp"
#include "domain/result.hpp"
#include "platform/binary_file.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace cpcp::repository {

enum class SnapshotEntryType : std::uint8_t {
    directory = 1,
    file = 2,
    presence = 255,
};

struct SnapshotPathMetadata {
    SnapshotEntryType type = SnapshotEntryType::presence;
    std::uint64_t size = 0;
    std::int64_t mtime_seconds = 0;
    std::uint32_t mtime_nanoseconds = 0;
    std::uint32_t mode = 0;
    crypto::Digest file_id{};
};

class SnapshotPathIndex {
public:
    static domain::Result<SnapshotPathIndex> create(
        std::filesystem::path temporary_directory,
        const crypto::SecureKey& id_key
    );

    SnapshotPathIndex(const SnapshotPathIndex&) = delete;
    SnapshotPathIndex& operator=(const SnapshotPathIndex&) = delete;
    SnapshotPathIndex(SnapshotPathIndex&&) noexcept;
    SnapshotPathIndex& operator=(SnapshotPathIndex&&) noexcept;
    ~SnapshotPathIndex();

    domain::Result<void> add(
        const domain::Uuid& root_uuid,
        std::string_view path,
        const SnapshotPathMetadata& metadata
    );
    domain::Result<void> finish();
    domain::Result<std::optional<SnapshotPathMetadata>> find(
        const domain::Uuid& root_uuid,
        std::string_view path
    );

private:
    SnapshotPathIndex(
        std::filesystem::path temporary_directory,
        crypto::SecureKey id_key
    );

    domain::Result<void> flush_run();
    domain::Result<void> compact();
    domain::Result<void> merge(
        const std::vector<std::filesystem::path>& inputs,
        const std::filesystem::path& output
    );

    std::filesystem::path temporary_directory_;
    crypto::SecureKey id_key_;
    std::vector<domain::Bytes> buffer_;
    std::vector<std::filesystem::path> runs_;
    std::uint64_t next_run_ = 0;
    std::uint64_t record_count_ = 0;
    std::optional<platform::BinaryFile> sorted_;
    bool finished_ = false;
};

}
