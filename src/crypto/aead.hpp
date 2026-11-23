#pragma once

#include "crypto/content_id.hpp"
#include "crypto/keys.hpp"
#include "domain/result.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <vector>

namespace cpcp::crypto {

using Bytes = std::vector<std::byte>;

inline constexpr std::size_t nonce_size = 24;

struct SealedObject {
    std::array<std::byte, nonce_size> nonce;
    Bytes ciphertext;
};

domain::Result<SealedObject> seal_object(
    const SecureKey& key,
    std::span<const std::byte> aad,
    std::span<const std::byte> plaintext
);

domain::Result<Bytes> open_object(
    const SecureKey& key,
    std::span<const std::byte> aad,
    const SealedObject& object
);

domain::Result<Digest> compute_ciphertext_digest(std::span<const std::byte> bytes);

}
