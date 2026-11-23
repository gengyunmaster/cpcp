#pragma once

#include "crypto/content_id.hpp"
#include "domain/result.hpp"

#include <cstddef>
#include <cstdint>
#include <sodium.h>
#include <span>

namespace cpcp::crypto {

class FileIdentityBuilder {
public:
    FileIdentityBuilder() = default;
    ~FileIdentityBuilder();

    FileIdentityBuilder(const FileIdentityBuilder&) = delete;
    FileIdentityBuilder& operator=(const FileIdentityBuilder&) = delete;
    FileIdentityBuilder(FileIdentityBuilder&&) noexcept = default;
    FileIdentityBuilder& operator=(FileIdentityBuilder&&) noexcept = default;

    domain::Result<void> initialize(
        const SecureKey& key,
        std::uint64_t file_length,
        std::uint64_t chunk_count,
        std::uint32_t chunk_size
    );
    domain::Result<void> append(std::span<const ChunkDescriptor> chunks);
    domain::Result<Digest> finish();

    std::uint64_t next_offset() const;
    std::uint64_t seen_chunks() const;

private:
    domain::Result<void> reject();

    crypto_auth_hmacsha256_state state_{};
    std::uint64_t file_length_ = 0;
    std::uint64_t chunk_count_ = 0;
    std::uint64_t next_offset_ = 0;
    std::uint64_t seen_chunks_ = 0;
    std::uint32_t chunk_size_ = 0;
    bool initialized_ = false;
    bool finished_ = false;
    bool poisoned_ = false;
};

}
