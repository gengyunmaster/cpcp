#include "storage/session_spool.hpp"

#include "crypto/content_id.hpp"
#include "crypto/password.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::Bytes;
using cpcp::crypto::RecordType;
using cpcp::crypto::SecureKey;
using cpcp::crypto::SnapshotContext;

SecureKey test_key() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return SecureKey::from_bytes(bytes).value();
}

SnapshotContext context() {
    SnapshotContext result;
    result.repository_uuid.fill(std::byte{1});
    result.storage_epoch.fill(std::byte{2});
    result.snapshot_uuid.fill(std::byte{3});
    result.lineage_uuid.fill(std::byte{4});
    result.generation = 1;
    return result;
}

Bytes payload(std::uint64_t file, std::uint64_t batch) {
    std::string text = "{\"schema\":\"cpcp.chunk-batch.v1\",\"file\":\""
        + std::to_string(file) + "\",\"batch\":\"" + std::to_string(batch)
        + "\",\"chunks\":[";
    for (std::size_t index = 0; index < 64; ++index) {
        if (index != 0) {
            text += ',';
        }
        text += "{\"id\":\""
            + std::string(64, '0') + "\",\"plain\":1048576,\"stored\":\"1048632\"}";
    }
    text += "]}";
    const auto view = std::as_bytes(std::span(text));
    return Bytes(view.begin(), view.end());
}

TEST_CASE("multi-gigabyte snapshot manifests stream with bounded memory") {
    constexpr std::uint64_t descriptor_count = 31'000'000;
    constexpr std::uint64_t batch_size = 64;
    const auto directory = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "large-manifest-stress";
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    const auto path = directory / "large.snap";
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotContext spool = snapshot;
    spool.session_uuid = cpcp::crypto::random_uuid();

    {
        cpcp::storage::SessionSpoolWriter writer;
        REQUIRE(writer.create(path, key, spool, cpcp::crypto::StreamDomain::snapshot));
        std::uint64_t batch = 0;
        for (std::uint64_t first = 0; first < descriptor_count; first += batch_size) {
            REQUIRE(writer.append(
                RecordType::chunk_batch,
                payload(first / batch_size, batch)
            ));
            ++batch;
        }
        REQUIRE(writer.finalize({}));
    }

    std::uint64_t batches = 0;
    cpcp::storage::SessionSpoolReader reader;
    REQUIRE(reader.open(path, key, spool, cpcp::crypto::StreamDomain::snapshot));
    while (true) {
        const auto record = reader.next().value();
        if (!record.has_value()) {
            break;
        }
        if (record->type == RecordType::chunk_batch) {
            ++batches;
        }
    }

    REQUIRE(batches == (descriptor_count + batch_size - 1) / batch_size);
    REQUIRE(reader.stored_length() > 2ULL * 1024ULL * 1024ULL * 1024ULL);
    REQUIRE(reader.finish());
    REQUIRE(reader.ciphertext_digest().has_value());
    std::filesystem::remove_all(directory);
}

}
