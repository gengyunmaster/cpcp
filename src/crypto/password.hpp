#pragma once

#include "crypto/keys.hpp"
#include "crypto/secret.hpp"
#include "domain/encoding.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace cpcp::crypto {

inline constexpr std::size_t password_salt_size = 16;

struct PasswordKdfParameters {
    std::uint64_t memory_kib = 64 * 1024;
    std::uint64_t iterations = 3;
};

domain::Result<SecureKey> derive_password_key(
    const SecretBytes& password,
    const std::array<std::byte, password_salt_size>& salt,
    const PasswordKdfParameters& parameters
);

domain::Uuid random_uuid();
void fill_random(std::span<std::byte> output);

}
