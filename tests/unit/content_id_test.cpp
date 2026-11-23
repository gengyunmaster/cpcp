#include "crypto/content_id.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <utility>
#include <vector>

namespace {

using cpcp::crypto::ChunkDescriptor;
using cpcp::crypto::KeyPurpose;
using cpcp::crypto::SecureKey;

std::array<std::byte, 32> sequential_key_bytes() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return bytes;
}

std::vector<std::byte> plaintext(const std::string& text) {
    std::vector<std::byte> result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

SecureKey test_key() {
    const auto bytes = sequential_key_bytes();
    return cpcp::crypto::SecureKey::from_bytes(bytes).value();
}

TEST_CASE("chunk IDs match an independent HMAC vector") {
    const auto key = test_key();

    const auto hello = cpcp::crypto::compute_chunk_id(key, plaintext("hello")).value();
    const auto world = cpcp::crypto::compute_chunk_id(key, plaintext("world")).value();

    REQUIRE(
        cpcp::crypto::to_hex(hello)
        == "1d2ad3fb87be975582421b6449e6a4d7941c6ef4afd13ef46d68a9aadcde25ce"
    );
    REQUIRE(
        cpcp::crypto::to_hex(world)
        == "4a0157b363763d273f1068b949d1c3876b44d14e3bbe2236ce8bfb6a717fb688"
    );
}

TEST_CASE("file IDs commit to ordered descriptors rather than stored sizes") {
    const auto key = test_key();
    const auto hello = cpcp::crypto::compute_chunk_id(key, plaintext("hello")).value();
    const auto world = cpcp::crypto::compute_chunk_id(key, plaintext("world")).value();
    const ChunkDescriptor chunks[] = {
        {hello, 5, 61},
        {world, 5, 61},
    };

    const auto digest = cpcp::crypto::compute_file_id(key, 10, chunks).value();

    REQUIRE(
        cpcp::crypto::to_hex(digest)
        == "e7a49e51fb17276070548aec8d9a0bd46e6568e0b4a88e78aa6ec07685bc278b"
    );

    ChunkDescriptor changed_storage[] = {chunks[0], chunks[1]};
    changed_storage[0].stored_length = 99;
    const auto changed = cpcp::crypto::compute_file_id(key, 10, changed_storage).value();
    REQUIRE(changed == digest);
}

TEST_CASE("subkeys are deterministic and domain separated") {
    const auto master = test_key();

    const auto first = cpcp::crypto::derive_key(master, KeyPurpose::content_id).value();
    const auto second = cpcp::crypto::derive_key(master, KeyPurpose::content_id).value();
    const auto other = cpcp::crypto::derive_key(master, KeyPurpose::chunk_encryption).value();

    REQUIRE(std::ranges::equal(first.bytes(), second.bytes()));
    REQUIRE_FALSE(std::ranges::equal(first.bytes(), other.bytes()));
}

TEST_CASE("generated keys are distinct and movable") {
    auto first = SecureKey::generate().value();
    auto second = SecureKey::generate().value();
    const auto original = first.bytes();

    second = std::move(first);

    REQUIRE(std::ranges::equal(second.bytes(), original));
}

TEST_CASE("digest hexadecimal parsing is strict") {
    const auto key = test_key();
    const auto digest = cpcp::crypto::compute_chunk_id(key, plaintext("hello")).value();

    REQUIRE(cpcp::crypto::digest_from_hex(cpcp::crypto::to_hex(digest)).value() == digest);
    REQUIRE_FALSE(cpcp::crypto::digest_from_hex("00"));
    REQUIRE_FALSE(cpcp::crypto::digest_from_hex(std::string(64, 'x')));
}

}
