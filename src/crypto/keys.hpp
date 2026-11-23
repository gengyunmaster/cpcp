#pragma once

#include "domain/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace cpcp::crypto {

inline constexpr std::size_t key_size = 32;

class SecureKey {
public:
    static domain::Result<SecureKey> generate();
    static domain::Result<SecureKey> zero();
    static domain::Result<SecureKey> from_bytes(
        std::span<const std::byte, key_size> bytes
    );

    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;
    SecureKey(SecureKey&& other) noexcept;
    SecureKey& operator=(SecureKey&& other) noexcept;
    ~SecureKey();

    std::span<const std::byte, key_size> bytes() const;
    std::span<std::byte, key_size> writable_bytes();

private:
    explicit SecureKey(unsigned char* data);

    unsigned char* data_ = nullptr;
};

enum class KeyPurpose {
    chunk_encryption,
    snapshot_encryption,
    journal_encryption,
    content_id,
    configuration_authentication,
    cache_authentication,
};

domain::Result<SecureKey> derive_key(
    const SecureKey& master,
    KeyPurpose purpose
);

}
