#include "crypto/snapshot_stream.hpp"

#include <array>
#include <stdexcept>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

namespace {

void append_u64(Bytes& output, std::uint64_t value) {
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_string(Bytes& output, std::string_view value) {
    for (const char byte : value) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
    }
}

bool valid_record_type(RecordType type) {
    switch (type) {
    case RecordType::context:
    case RecordType::snapshot_header:
    case RecordType::root:
    case RecordType::file_header:
    case RecordType::chunk_batch:
    case RecordType::file_end:
    case RecordType::policy_skip:
    case RecordType::failure:
    case RecordType::directory:
    case RecordType::final_summary:
        return true;
    }
    return false;
}

Bytes frame_aad(
    const SnapshotContext& context,
    std::uint64_t index,
    RecordType type,
    StreamDomain domain
) {
    Bytes aad;
    aad.reserve(16 + 16 + 16 + 16 + 8 + 8 + 1 + 16);
    append_string(
        aad,
        domain == StreamDomain::snapshot ? "cpcp.snapshot.v1" : "cpcp.spool.v1"
    );
    aad.insert(aad.end(), context.repository_uuid.begin(), context.repository_uuid.end());
    aad.insert(aad.end(), context.storage_epoch.begin(), context.storage_epoch.end());
    aad.insert(aad.end(), context.snapshot_uuid.begin(), context.snapshot_uuid.end());
    aad.insert(aad.end(), context.lineage_uuid.begin(), context.lineage_uuid.end());
    append_u64(aad, context.generation);
    append_u64(aad, index);
    aad.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(type)));
    return aad;
}

unsigned char* as_mutable(std::byte* data) {
    return reinterpret_cast<unsigned char*>(data);
}

const unsigned char* as_const(const std::byte* data) {
    return reinterpret_cast<const unsigned char*>(data);
}

}

SnapshotEncoder::SnapshotEncoder(
    const SnapshotContext& context,
    const SecureKey& key,
    StreamDomain domain
) : context_(context), domain_(domain) {
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &state_,
            as_mutable(header_.data()),
            as_const(key.bytes().data())
        ) != 0) {
        throw std::runtime_error("secretstream initialization failed");
    }
}

SnapshotEncoder::~SnapshotEncoder() {
    sodium_memzero(&state_, sizeof(state_));
}

const std::array<std::byte, snapshot_header_size>& SnapshotEncoder::header() const {
    return header_;
}

domain::Result<SnapshotFrame> SnapshotEncoder::push(
    RecordType type,
    std::span<const std::byte> plaintext
) {
    if (finalized_) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot stream is already finalized"});
    }
    if (!valid_record_type(type)) {
        return std::unexpected(Error{ErrorCode::usage, "unknown snapshot record type"});
    }
    if (plaintext.size() > snapshot_frame_limit) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot frame exceeds the size limit"});
    }

    const auto aad = frame_aad(context_, next_index_, type, domain_);
    SnapshotFrame frame{next_index_, type, Bytes(plaintext.size() + crypto_secretstream_xchacha20poly1305_ABYTES)};
    const unsigned char tag = type == RecordType::final_summary
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    if (crypto_secretstream_xchacha20poly1305_push(
            &state_,
            as_mutable(frame.ciphertext.data()),
            nullptr,
            as_const(plaintext.data()),
            static_cast<unsigned long long>(plaintext.size()),
            as_const(aad.data()),
            static_cast<unsigned long long>(aad.size()),
            tag
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "snapshot frame encryption failed"});
    }

    ++next_index_;
    finalized_ = type == RecordType::final_summary;
    return frame;
}

bool SnapshotEncoder::finalized() const {
    return finalized_;
}

SnapshotDecoder::SnapshotDecoder(
    const SnapshotContext& context,
    const SecureKey& key,
    const std::array<std::byte, snapshot_header_size>& header,
    StreamDomain domain
) : context_(context), domain_(domain) {
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &state_,
            as_const(header.data()),
            as_const(key.bytes().data())
        ) != 0) {
        throw std::runtime_error("secretstream decoder initialization failed");
    }
}

SnapshotDecoder::~SnapshotDecoder() {
    sodium_memzero(&state_, sizeof(state_));
}

domain::Result<Bytes> SnapshotDecoder::pull(const SnapshotFrame& frame) {
    if (finalized_ || poisoned_) {
        return std::unexpected(Error{ErrorCode::integrity, "snapshot decoder is not available"});
    }
    if (frame.index != next_index_ || !valid_record_type(frame.type)) {
        return std::unexpected(Error{ErrorCode::integrity, "unexpected snapshot frame sequence"});
    }
    if (frame.ciphertext.size() < crypto_secretstream_xchacha20poly1305_ABYTES
        || frame.ciphertext.size() > snapshot_frame_limit + crypto_secretstream_xchacha20poly1305_ABYTES) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid snapshot frame size"});
    }

    const auto aad = frame_aad(context_, frame.index, frame.type, domain_);
    Bytes plaintext(frame.ciphertext.size() - crypto_secretstream_xchacha20poly1305_ABYTES);
    unsigned long long plaintext_size = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &state_,
            as_mutable(plaintext.data()),
            &plaintext_size,
            &tag,
            as_const(frame.ciphertext.data()),
            static_cast<unsigned long long>(frame.ciphertext.size()),
            as_const(aad.data()),
            static_cast<unsigned long long>(aad.size())
        ) != 0) {
        if (!plaintext.empty()) {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        poisoned_ = true;
        return std::unexpected(Error{ErrorCode::integrity, "snapshot frame authentication failed"});
    }

    const bool final_frame = frame.type == RecordType::final_summary;
    if ((final_frame && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        || (!final_frame && tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)) {
        if (!plaintext.empty()) {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        poisoned_ = true;
        return std::unexpected(Error{ErrorCode::integrity, "snapshot frame tag does not match its record"});
    }

    plaintext.resize(static_cast<std::size_t>(plaintext_size));
    ++next_index_;
    finalized_ = final_frame;
    return plaintext;
}

domain::Result<void> SnapshotDecoder::finish() const {
    if (!finalized_) {
        return std::unexpected(Error{ErrorCode::integrity, "snapshot stream is missing FINAL"});
    }
    return {};
}

bool SnapshotDecoder::finalized() const {
    return finalized_;
}

}
