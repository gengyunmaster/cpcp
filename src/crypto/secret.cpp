#include "crypto/secret.hpp"

#include <sodium.h>

#include <algorithm>
#include <utility>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

domain::Result<void> initialize_crypto() {
    if (sodium_init() < 0) {
        return std::unexpected(Error{ErrorCode::internal, "libsodium initialization failed"});
    }
    return {};
}

SecretBytes::SecretBytes(std::size_t size, unsigned char* data)
    : size_(size), data_(data) {
}

domain::Result<SecretBytes> SecretBytes::allocate(std::size_t size) {
    const auto initialized = initialize_crypto();
    if (!initialized) {
        return std::unexpected(initialized.error());
    }
    if (size == 0) {
        return std::unexpected(Error{ErrorCode::usage, "secret allocation cannot be empty"});
    }

    auto* data = static_cast<unsigned char*>(sodium_malloc(size));
    if (data == nullptr) {
        return std::unexpected(Error{ErrorCode::internal, "secure allocation failed"});
    }
    sodium_mlock(data, size);
    sodium_memzero(data, size);
    return SecretBytes(size, data);
}

domain::Result<SecretBytes> SecretBytes::copy(std::span<const std::byte> bytes) {
    auto secret = allocate(bytes.size());
    if (!secret) {
        return std::unexpected(secret.error());
    }
    std::ranges::copy(bytes, secret->writable_bytes().begin());
    return secret;
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept
    : size_(std::exchange(other.size_, 0)),
      data_(std::exchange(other.data_, nullptr)) {
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
    if (this != &other) {
        sodium_free(data_);
        size_ = std::exchange(other.size_, 0);
        data_ = std::exchange(other.data_, nullptr);
    }
    return *this;
}

SecretBytes::~SecretBytes() {
    sodium_free(data_);
}

std::size_t SecretBytes::size() const {
    return size_;
}

std::span<const std::byte> SecretBytes::bytes() const {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(data_), size_};
}

std::span<std::byte> SecretBytes::writable_bytes() {
    return std::span<std::byte>{reinterpret_cast<std::byte*>(data_), size_};
}

}
