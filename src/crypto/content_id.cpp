#include "crypto/content_id.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <limits>

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

void update(
    crypto_auth_hmacsha256_state& state,
    std::string_view text
) {
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(text.data()),
        static_cast<unsigned long long>(text.size())
    );
}

template<std::size_t N>
void update_little_endian(crypto_auth_hmacsha256_state& state, std::uint64_t value) {
    static_assert(N == 4 || N == 8);
    std::array<unsigned char, N> encoded{};
    for (std::size_t index = 0; index < N; ++index) {
        encoded[index] = static_cast<unsigned char>(value & 0xffU);
        value >>= 8U;
    }
    crypto_auth_hmacsha256_update(&state, encoded.data(), encoded.size());
}

domain::Result<crypto_auth_hmacsha256_state> initialize_state(const SecureKey& key) {
    crypto_auth_hmacsha256_state state;
    if (crypto_auth_hmacsha256_init(
            &state,
            reinterpret_cast<const unsigned char*>(key.bytes().data()),
            key.bytes().size()
        ) != 0) {
        return std::unexpected(Error{
            ErrorCode::internal,
            "HMAC initialization failed",
        });
    }
    return state;
}

Digest finalize(crypto_auth_hmacsha256_state& state) {
    Digest digest{};
    crypto_auth_hmacsha256_final(
        &state,
        reinterpret_cast<unsigned char*>(digest.data())
    );
    return digest;
}

int hexadecimal_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

}

domain::Result<Digest> compute_hmac_sha256(
    const SecureKey& key,
    std::span<const std::byte> input
) {
    auto state = initialize_state(key);
    if (!state) {
        return std::unexpected(state.error());
    }
    update(*state, input);
    return finalize(*state);
}

domain::Result<Digest> compute_chunk_id(
    const SecureKey& key,
    std::span<const std::byte> plaintext
) {
    auto state = initialize_state(key);
    if (!state) {
        return std::unexpected(state.error());
    }
    update(*state, "cpcp.chunk.v1");
    update_little_endian<8>(*state, plaintext.size());
    update(*state, plaintext);
    return finalize(*state);
}

domain::Result<Digest> compute_file_id(
    const SecureKey& key,
    std::uint64_t file_length,
    std::span<const ChunkDescriptor> chunks
) {
    auto state = initialize_state(key);
    if (!state) {
        return std::unexpected(state.error());
    }
    update(*state, "cpcp.file.v1");
    update_little_endian<8>(*state, file_length);
    update_little_endian<8>(*state, chunks.size());
    for (const auto& chunk : chunks) {
        update(*state, chunk.chunk_id);
        update_little_endian<4>(*state, chunk.plaintext_length);
    }
    return finalize(*state);
}

std::string to_hex(const Digest& digest) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result(digest.size() * 2, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const auto value = std::to_integer<unsigned int>(digest[index]);
        result[index * 2] = digits[value >> 4U];
        result[index * 2 + 1] = digits[value & 0x0fU];
    }
    return result;
}

domain::Result<Digest> digest_from_hex(std::string_view text) {
    if (text.size() != 64) {
        return std::unexpected(Error{
            ErrorCode::usage,
            "a SHA-256 digest requires 64 hexadecimal characters",
        });
    }

    Digest digest{};
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const int high = hexadecimal_value(text[index * 2]);
        const int low = hexadecimal_value(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return std::unexpected(Error{
                ErrorCode::usage,
                "digest contains a non-hexadecimal character",
            });
        }
        digest[index] = static_cast<std::byte>((high << 4) | low);
    }
    return digest;
}

}
