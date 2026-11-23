#include "repository/chunk_set.hpp"

#include "crypto/password.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::ChunkDescriptor;
using cpcp::crypto::SecureKey;
using cpcp::repository::RawChunk;

SecureKey test_key() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return SecureKey::from_bytes(bytes).value();
}

ChunkDescriptor chunk_at(std::size_t index, const SecureKey& key) {
    const auto text = std::to_string(index);
    std::vector<std::byte> bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return {
        cpcp::crypto::compute_chunk_id(key, bytes).value(),
        1,
        56 + index % 11,
    };
}

cpcp::crypto::Digest expected_digest(
    std::vector<RawChunk> chunks,
    const SecureKey& key
) {
    std::sort(chunks.begin(), chunks.end());
    cpcp::domain::Bytes input;
    constexpr std::string_view domain = "cpcp.chunk-set.v1";
    for (const char value : domain) {
        input.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    std::optional<RawChunk> previous;
    for (const auto& chunk : chunks) {
        if (previous && previous->id == chunk.id) {
            continue;
        }
        input.insert(input.end(), chunk.id.begin(), chunk.id.end());
        cpcp::domain::append_le(input, chunk.stored_length, 8);
        previous = chunk;
    }
    return cpcp::crypto::compute_hmac_sha256(key, input).value();
}

TEST_CASE("external chunk-set commitment is order independent and deduplicated") {
    const auto key = test_key();
    const auto directory = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "chunk-set-basic";
    std::vector<RawChunk> expected;
    std::optional<cpcp::crypto::Digest> actual;
    {
        auto builder = cpcp::repository::ChunkSetBuilder::create(directory, key).value();
        for (std::size_t index = 0; index < 2500; ++index) {
            const auto chunk = chunk_at(index % 1200, key);
            REQUIRE(builder.add(chunk));
            expected.push_back(RawChunk{chunk.chunk_id, chunk.stored_length});
        }
        actual = builder.finish().value();
    }

    REQUIRE(actual.value() == expected_digest(expected, key));
    REQUIRE_FALSE(std::filesystem::exists(directory));
}

TEST_CASE("external chunk-set compaction remains correct beyond open run limits") {
    const auto key = test_key();
    const auto directory = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "chunk-set-compact";
    std::vector<RawChunk> expected;
    std::optional<cpcp::crypto::Digest> actual;
    {
        auto builder = cpcp::repository::ChunkSetBuilder::create(directory, key).value();
        for (std::size_t index = 0; index < 33 * 1024 + 17; ++index) {
            const auto chunk = chunk_at(index, key);
            REQUIRE(builder.add(chunk));
            expected.push_back(RawChunk{chunk.chunk_id, chunk.stored_length});
        }
        actual = builder.finish().value();
    }

    REQUIRE(actual.value() == expected_digest(expected, key));
}

TEST_CASE("duplicate IDs cannot change stored length") {
    const auto key = test_key();
    const auto directory = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "chunk-set-conflict";
    auto builder = cpcp::repository::ChunkSetBuilder::create(directory, key).value();
    auto first = chunk_at(1, key);
    auto second = first;
    ++second.stored_length;
    REQUIRE(builder.add(first));
    REQUIRE(builder.add(second));

    REQUIRE_FALSE(builder.finish());
}

}
