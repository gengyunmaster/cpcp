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
        const crypto::SnapshotContext& context,
        crypto::StreamDomain domain = crypto::StreamDomain::session_spool
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
        const crypto::SnapshotContext& context,
        crypto::StreamDomain domain = crypto::StreamDomain::session_spool
    );
    domain::Result<std::optional<SpoolRecord>> next();
    domain::Result<void> finish() const;
    domain::Result<crypto::Digest> ciphertext_digest() const;
    std::uint64_t stored_length() const;
    const crypto::SnapshotContext& context() const;

private:
    std::optional<platform::BinaryFile> file_;
    std::optional<crypto::SnapshotDecoder> decoder_;
    crypto::SnapshotContext context_{};
    crypto_hash_sha256_state digest_state_{};
    std::uint64_t stored_length_ = 0;
    bool done_ = false;

    domain::Result<void> read_tracked(std::span<std::byte> output);
    void update_digest(std::span<const std::byte> bytes);
};

}
