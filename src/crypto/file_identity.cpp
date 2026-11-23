#include "crypto/file_identity.hpp"

#include <array>
#include <string_view>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

namespace {

void update(
    crypto_auth_hmacsha256_state& state,
    std::span<const std::byte> bytes
) {
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(bytes.data()),
        static_cast<unsigned long long>(bytes.size())
    );
}

void update_u64(crypto_auth_hmacsha256_state& state, std::uint64_t value) {
    std::array<unsigned char, 8> encoded{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        encoded[index] = static_cast<unsigned char>(value & 0xffU);
        value >>= 8U;
    }
    crypto_auth_hmacsha256_update(&state, encoded.data(), encoded.size());
}

void update_u32(crypto_auth_hmacsha256_state& state, std::uint32_t value) {
    std::array<unsigned char, 4> encoded{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        encoded[index] = static_cast<unsigned char>(value & 0xffU);
        value >>= 8U;
    }
    crypto_auth_hmacsha256_update(&state, encoded.data(), encoded.size());
}

}

FileIdentityBuilder::~FileIdentityBuilder() {
    sodium_memzero(&state_, sizeof(state_));
}

domain::Result<void> FileIdentityBuilder::initialize(
    const SecureKey& key,
    std::uint64_t file_length,
    std::uint64_t chunk_count,
    std::uint32_t chunk_size
) {
    if (initialized_) {
        return std::unexpected(Error{ErrorCode::usage, "file identity builder is already initialized"});
    }
    if (chunk_size == 0) {
        return std::unexpected(Error{ErrorCode::usage, "chunk size must be positive"});
    }

    const std::uint64_t expected_chunks = file_length / chunk_size
        + (file_length % chunk_size == 0 ? 0 : 1);
    if (chunk_count != expected_chunks) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk count does not match file size"});
    }
    if (crypto_auth_hmacsha256_init(
            &state_,
            reinterpret_cast<const unsigned char*>(key.bytes().data()),
            key.bytes().size()
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "file identity initialization failed"});
    }

    constexpr std::string_view domain = "cpcp.file.v1";
    crypto_auth_hmacsha256_update(
        &state_,
        reinterpret_cast<const unsigned char*>(domain.data()),
        domain.size()
    );
    update_u64(state_, file_length);
    update_u64(state_, chunk_count);
    file_length_ = file_length;
    chunk_count_ = chunk_count;
    chunk_size_ = chunk_size;
    initialized_ = true;
    return {};
}

domain::Result<void> FileIdentityBuilder::reject() {
    poisoned_ = true;
    return std::unexpected(Error{ErrorCode::integrity, "invalid chunk continuation sequence"});
}

domain::Result<void> FileIdentityBuilder::append(
    std::span<const ChunkDescriptor> chunks
) {
    if (!initialized_ || finished_ || poisoned_) {
        return std::unexpected(Error{ErrorCode::usage, "file identity builder is not available"});
    }

    for (const auto& chunk : chunks) {
        if (seen_chunks_ >= chunk_count_
            || chunk.plaintext_length == 0
            || chunk.plaintext_length > chunk_size_
            || (seen_chunks_ + 1 < chunk_count_ && chunk.plaintext_length != chunk_size_)
            || chunk.plaintext_length > file_length_ - next_offset_) {
            return reject();
        }
        update(state_, chunk.chunk_id);
        update_u32(state_, chunk.plaintext_length);
        next_offset_ += chunk.plaintext_length;
        ++seen_chunks_;
    }
    return {};
}

domain::Result<Digest> FileIdentityBuilder::finish() {
    if (!initialized_ || finished_ || poisoned_) {
        return std::unexpected(Error{ErrorCode::usage, "file identity builder is not available"});
    }
    if (seen_chunks_ != chunk_count_ || next_offset_ != file_length_) {
        const auto rejected = reject();
        return std::unexpected(rejected.error());
    }

    Digest digest;
    crypto_auth_hmacsha256_final(&state_, reinterpret_cast<unsigned char*>(digest.data()));
    finished_ = true;
    return digest;
}

std::uint64_t FileIdentityBuilder::next_offset() const {
    return next_offset_;
}

std::uint64_t FileIdentityBuilder::seen_chunks() const {
    return seen_chunks_;
}

}
