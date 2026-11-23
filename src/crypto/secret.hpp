#pragma once

#include "domain/result.hpp"

#include <cstddef>
#include <span>

namespace cpcp::crypto {

class SecretBytes {
public:
    static domain::Result<SecretBytes> allocate(std::size_t size);
    static domain::Result<SecretBytes> copy(std::span<const std::byte> bytes);

    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept;
    SecretBytes& operator=(SecretBytes&& other) noexcept;
    ~SecretBytes();

    std::size_t size() const;
    std::span<const std::byte> bytes() const;
    std::span<std::byte> writable_bytes();

private:
    SecretBytes(std::size_t size, unsigned char* data);

    std::size_t size_ = 0;
    unsigned char* data_ = nullptr;
};

domain::Result<void> initialize_crypto();

}
