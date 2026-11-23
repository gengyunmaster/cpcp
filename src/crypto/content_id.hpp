#pragma once

#include "crypto/keys.hpp"
#include "domain/result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace cpcp::crypto {

using Digest = std::array<std::byte, 32>;

struct ChunkDescriptor {
    Digest chunk_id;
    std::uint32_t plaintext_length;
    std::uint64_t stored_length;
    std::uint32_t format_version = 1;
    std::uint16_t content_encoding = 0;
};

domain::Result<Digest> compute_hmac_sha256(
    const SecureKey& key,
    std::span<const std::byte> input
);
domain::Result<Digest> compute_chunk_id(
    const SecureKey& key,
    std::span<const std::byte> plaintext
);

domain::Result<Digest> compute_file_id(
    const SecureKey& key,
    std::uint64_t file_length,
    std::span<const ChunkDescriptor> chunks
);

std::string to_hex(const Digest& digest);
domain::Result<Digest> digest_from_hex(std::string_view text);

}
