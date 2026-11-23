#pragma once

#include "crypto/snapshot_stream.hpp"
#include "domain/result.hpp"
#include "platform/binary_file.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>

namespace cpcp::storage {

struct SpoolRecord {
    crypto::RecordType type;
    crypto::Bytes plaintext;
};

class SessionSpoolWriter {
public:
    SessionSpoolWriter() = default;

    SessionSpoolWriter(const SessionSpoolWriter&) = delete;
    SessionSpoolWriter& operator=(const SessionSpoolWriter&) = delete;
    SessionSpoolWriter(SessionSpoolWriter&&) = delete;
    SessionSpoolWriter& operator=(SessionSpoolWriter&&) = delete;

    domain::Result<void> create(
        const std::filesystem::path& path,
        const crypto::SecureKey& key,
        const crypto::SnapshotContext& context
    );
    domain::Result<void> append(
        crypto::RecordType type,
        std::span<const std::byte> plaintext
    );
    domain::Result<void> finalize(std::span<const std::byte> summary);
    bool finalized() const;

private:
    domain::Result<void> write_frame(const crypto::SnapshotFrame& frame);

    std::optional<platform::BinaryFile> file_;
    std::optional<crypto::SnapshotEncoder> encoder_;
    bool finalized_ = false;
};

class SessionSpoolReader {
public:
    SessionSpoolReader() = default;

    SessionSpoolReader(const SessionSpoolReader&) = delete;
    SessionSpoolReader& operator=(const SessionSpoolReader&) = delete;
    SessionSpoolReader(SessionSpoolReader&&) = delete;
    SessionSpoolReader& operator=(SessionSpoolReader&&) = delete;

    domain::Result<void> open(
        const std::filesystem::path& path,
        const crypto::SecureKey& key,
        const crypto::SnapshotContext& context
    );
    domain::Result<std::optional<SpoolRecord>> next();
    domain::Result<void> finish() const;

private:
    std::optional<platform::BinaryFile> file_;
    std::optional<crypto::SnapshotDecoder> decoder_;
    bool done_ = false;
};

}
