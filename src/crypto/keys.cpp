#include "crypto/keys.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

namespace {

domain::Result<void> initialize_sodium() {
    if (sodium_init() < 0) {
        return std::unexpected(Error{
            ErrorCode::internal,
            "libsodium initialization failed",
        });
    }
    return {};
}

struct KeyContext {
    std::uint64_t id;
    std::array<char, crypto_kdf_CONTEXTBYTES> name;
};

KeyContext key_context(KeyPurpose purpose) {
    switch (purpose) {
    case KeyPurpose::chunk_encryption:
        return {1, {'c', 'h', 'u', 'n', 'k', '0', '0', '1'}};
    case KeyPurpose::snapshot_encryption:
        return {1, {'s', 'n', 'a', 'p', '0', '0', '0', '1'}};
    case KeyPurpose::journal_encryption:
        return {1, {'j', 'r', 'n', 'l', '0', '0', '0', '1'}};
    case KeyPurpose::content_id:
        return {1, {'i', 'd', 'k', 'e', 'y', '0', '0', '1'}};
    case KeyPurpose::configuration_authentication:
        return {1, {'c', 'o', 'n', 'f', '0', '0', '0', '1'}};
    case KeyPurpose::cache_authentication:
        return {1, {'c', 'a', 'c', 'h', '0', '0', '0', '1'}};
    }
    throw std::invalid_argument("unknown key purpose");
}

}

SecureKey::SecureKey(unsigned char* data) : data_(data) {
}

domain::Result<SecureKey> SecureKey::zero() {
    const auto initialized = initialize_sodium();
    if (!initialized) {
        return std::unexpected(initialized.error());
    }

    auto* data = static_cast<unsigned char*>(sodium_malloc(key_size));
    if (data == nullptr) {
        return std::unexpected(Error{
            ErrorCode::internal,
            "secure key allocation failed",
        });
    }
    sodium_mlock(data, key_size);
    sodium_memzero(data, key_size);
    return SecureKey(data);
}

domain::Result<SecureKey> SecureKey::generate() {
    auto key = zero();
    if (!key) {
        return std::unexpected(key.error());
    }
    randombytes_buf(key->writable_bytes().data(), key_size);
    return key;
}

domain::Result<SecureKey> SecureKey::from_bytes(
    std::span<const std::byte, key_size> bytes
) {
    auto key = zero();
    if (!key) {
        return std::unexpected(key.error());
    }
    std::ranges::copy(bytes, key->writable_bytes().begin());
    return key;
}

SecureKey::SecureKey(SecureKey&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)) {
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
    if (this != &other) {
        sodium_free(data_);
        data_ = std::exchange(other.data_, nullptr);
    }
    return *this;
}

SecureKey::~SecureKey() {
    sodium_free(data_);
}

std::span<const std::byte, key_size> SecureKey::bytes() const {
    return std::span<const std::byte, key_size>{
        reinterpret_cast<const std::byte*>(data_),
        key_size,
    };
}

std::span<std::byte, key_size> SecureKey::writable_bytes() {
    return std::span<std::byte, key_size>{
        reinterpret_cast<std::byte*>(data_),
        key_size,
    };
}

domain::Result<SecureKey> derive_key(
    const SecureKey& master,
    KeyPurpose purpose
) {
    auto key = SecureKey::zero();
    if (!key) {
        return std::unexpected(key.error());
    }

    const auto context = key_context(purpose);
    if (crypto_kdf_derive_from_key(
            reinterpret_cast<unsigned char*>(key->writable_bytes().data()),
            key_size,
            context.id,
            context.name.data(),
            reinterpret_cast<const unsigned char*>(master.bytes().data())
        ) != 0) {
        return std::unexpected(Error{
            ErrorCode::internal,
            "subkey derivation failed",
        });
    }
    return key;
}

}
