#pragma once

#include "crypto/aead.hpp"
#include "domain/result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <sodium.h>

namespace cpcp::crypto {

inline constexpr std::size_t snapshot_frame_limit = 1024 * 1024;
inline constexpr std::size_t snapshot_header_size = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

struct SnapshotContext {
    std::array<std::byte, 16> repository_uuid;
    std::array<std::byte, 16> storage_epoch;
    std::array<std::byte, 16> snapshot_uuid;
    std::array<std::byte, 16> lineage_uuid;
    std::uint64_t generation;

    bool operator==(const SnapshotContext&) const = default;
};

enum class RecordType : std::uint8_t {
    context = 1,
    snapshot_header = 2,
    root = 3,
    file_header = 4,
    chunk_batch = 5,
    file_end = 6,
    policy_skip = 7,
    failure = 8,
    final_summary = 255,
};

struct SnapshotFrame {
    std::uint64_t index;
    RecordType type;
    Bytes ciphertext;
};

enum class StreamDomain {
    snapshot,
    session_spool,
};

class SnapshotEncoder {
public:
    SnapshotEncoder(
        const SnapshotContext& context,
        const SecureKey& key,
        StreamDomain domain = StreamDomain::snapshot
    );
    ~SnapshotEncoder();

    SnapshotEncoder(const SnapshotEncoder&) = delete;
    SnapshotEncoder& operator=(const SnapshotEncoder&) = delete;
    SnapshotEncoder(SnapshotEncoder&&) = delete;
    SnapshotEncoder& operator=(SnapshotEncoder&&) = delete;

    const std::array<std::byte, snapshot_header_size>& header() const;
    domain::Result<SnapshotFrame> push(
        RecordType type,
        std::span<const std::byte> plaintext
    );
    bool finalized() const;

private:
    SnapshotContext context_;
    StreamDomain domain_;
    crypto_secretstream_xchacha20poly1305_state state_;
    std::array<std::byte, snapshot_header_size> header_;
    std::uint64_t next_index_ = 0;
    bool finalized_ = false;
};

class SnapshotDecoder {
public:
    SnapshotDecoder(
        const SnapshotContext& context,
        const SecureKey& key,
        const std::array<std::byte, snapshot_header_size>& header,
        StreamDomain domain = StreamDomain::snapshot
    );
    ~SnapshotDecoder();

    SnapshotDecoder(const SnapshotDecoder&) = delete;
    SnapshotDecoder& operator=(const SnapshotDecoder&) = delete;
    SnapshotDecoder(SnapshotDecoder&&) = delete;
    SnapshotDecoder& operator=(SnapshotDecoder&&) = delete;

    domain::Result<Bytes> pull(const SnapshotFrame& frame);
    domain::Result<void> finish() const;
    bool finalized() const;

private:
    SnapshotContext context_;
    StreamDomain domain_;
    crypto_secretstream_xchacha20poly1305_state state_;
    std::uint64_t next_index_ = 0;
    bool finalized_ = false;
    bool poisoned_ = false;
};

}
