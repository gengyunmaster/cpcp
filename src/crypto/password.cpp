#include "crypto/password.hpp"

#include "crypto/keys.hpp"

#include <sodium.h>

#include <limits>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

domain::Result<SecureKey> derive_password_key(
    const SecretBytes& password,
    const std::array<std::byte, password_salt_size>& salt,
    const PasswordKdfParameters& parameters
) {
    if (password.size() == 0 || parameters.memory_kib < 1024
        || parameters.iterations == 0 || parameters.memory_kib > 1024 * 1024
        || parameters.iterations > 100) {
        return std::unexpected(Error{ErrorCode::usage, "invalid password or KDF parameters"});
    }

    auto key = SecureKey::zero();
    if (!key) {
        return std::unexpected(key.error());
    }
    if (crypto_pwhash(
            reinterpret_cast<unsigned char*>(key->writable_bytes().data()),
            key_size,
            reinterpret_cast<const char*>(password.bytes().data()),
            static_cast<unsigned long long>(password.size()),
            reinterpret_cast<const unsigned char*>(salt.data()),
            static_cast<unsigned long long>(parameters.iterations),
            parameters.memory_kib * 1024,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "Argon2id derivation failed"});
    }
    return key;
}

domain::Uuid random_uuid() {
    domain::Uuid uuid{};
    randombytes_buf(uuid.data(), uuid.size());
    return uuid;
}

void fill_random(std::span<std::byte> output) {
    randombytes_buf(output.data(), output.size());
}

}
