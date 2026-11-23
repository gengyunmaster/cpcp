#include "crypto/file_identity.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::ChunkDescriptor;
using cpcp::crypto::FileIdentityBuilder;
using cpcp::crypto::SecureKey;

SecureKey test_key() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return SecureKey::from_bytes(bytes).value();
}

std::vector<std::byte> bytes(const std::string& text) {
    std::vector<std::byte> result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

std::array<ChunkDescriptor, 2> test_chunks(const SecureKey& key) {
    return {
        ChunkDescriptor{cpcp::crypto::compute_chunk_id(key, bytes("hello")).value(), 5, 61},
        ChunkDescriptor{cpcp::crypto::compute_chunk_id(key, bytes("world")).value(), 5, 61},
    };
}

TEST_CASE("streaming file identity matches the descriptor vector") {
    const auto key = test_key();
    const auto chunks = test_chunks(key);
    FileIdentityBuilder builder;
    REQUIRE(builder.initialize(key, 10, 2, 5));

    REQUIRE(builder.append(std::span(chunks).first(1)));
    REQUIRE(builder.next_offset() == 5);
    REQUIRE(builder.append(std::span(chunks).last(1)));

    const auto digest = builder.finish().value();
    REQUIRE(
        cpcp::crypto::to_hex(digest)
        == "e7a49e51fb17276070548aec8d9a0bd46e6568e0b4a88e78aa6ec07685bc278b"
    );
    REQUIRE(builder.seen_chunks() == 2);
}

TEST_CASE("empty file identity has a valid zero-chunk encoding") {
    const auto key = test_key();
    FileIdentityBuilder builder;
    REQUIRE(builder.initialize(key, 0, 0, 5));

    const auto streamed = builder.finish().value();
    const auto direct = cpcp::crypto::compute_file_id(key, 0, {}).value();

    REQUIRE(streamed == direct);
}

TEST_CASE("continuation rejects incomplete and oversized sequences") {
    const auto key = test_key();
    const auto chunks = test_chunks(key);
    FileIdentityBuilder incomplete;
    REQUIRE(incomplete.initialize(key, 10, 2, 5));
    REQUIRE(incomplete.append(std::span(chunks).first(1)));
    REQUIRE_FALSE(incomplete.finish());

    FileIdentityBuilder excess;
    REQUIRE(excess.initialize(key, 10, 2, 5));
    const ChunkDescriptor oversized{chunks[0].chunk_id, 6, 62};
    REQUIRE_FALSE(excess.append(std::span(&oversized, 1)));
}

TEST_CASE("continuation requires full non-final chunks") {
    const auto key = test_key();
    const auto chunks = test_chunks(key);
    FileIdentityBuilder builder;
    REQUIRE(builder.initialize(key, 9, 2, 5));
    ChunkDescriptor short_first = chunks[0];
    short_first.plaintext_length = 4;

    REQUIRE_FALSE(builder.append(std::span(&short_first, 1)));
}

TEST_CASE("chunk count must agree with fixed chunking") {
    const auto key = test_key();
    FileIdentityBuilder builder;

    REQUIRE_FALSE(builder.initialize(key, 10, 1, 5));
}

}
