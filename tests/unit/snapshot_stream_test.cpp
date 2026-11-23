#include "crypto/snapshot_stream.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::Bytes;
using cpcp::crypto::RecordType;
using cpcp::crypto::SnapshotContext;
using cpcp::crypto::SnapshotDecoder;
using cpcp::crypto::SnapshotEncoder;
using cpcp::crypto::SecureKey;

SecureKey test_key() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return SecureKey::from_bytes(bytes).value();
}

Bytes bytes(const std::string& text) {
    Bytes result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

SnapshotContext context() {
    SnapshotContext result;
    result.repository_uuid.fill(std::byte{1});
    result.storage_epoch.fill(std::byte{2});
    result.snapshot_uuid.fill(std::byte{3});
    result.lineage_uuid.fill(std::byte{4});
    result.generation = 7;
    return result;
}

TEST_CASE("snapshot frames round trip through authenticated FINAL") {
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotEncoder encoder(snapshot, key);
    const auto context_frame = encoder.push(RecordType::context, bytes("context")).value();
    const auto file_frame = encoder.push(RecordType::file_header, bytes("file")).value();
    const auto final_frame = encoder.push(RecordType::final_summary, bytes("done")).value();

    SnapshotDecoder decoder(snapshot, key, encoder.header());
    REQUIRE(decoder.pull(context_frame).value() == bytes("context"));
    REQUIRE(decoder.pull(file_frame).value() == bytes("file"));
    REQUIRE(decoder.pull(final_frame).value() == bytes("done"));
    REQUIRE(decoder.finish());
    REQUIRE(decoder.finalized());
    REQUIRE(encoder.finalized());
}

TEST_CASE("snapshot frame tampering is an integrity failure") {
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotEncoder encoder(snapshot, key);
    auto frame = encoder.push(RecordType::file_header, bytes("secret")).value();
    frame.ciphertext.front() ^= std::byte{1};
    SnapshotDecoder decoder(snapshot, key, encoder.header());

    const auto result = decoder.pull(frame);

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::integrity);
    REQUIRE_FALSE(decoder.finish());
}

TEST_CASE("snapshot AAD binds repository context") {
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotEncoder encoder(snapshot, key);
    const auto frame = encoder.push(RecordType::context, bytes("context")).value();
    auto other = snapshot;
    other.generation = 8;
    SnapshotDecoder decoder(other, key, encoder.header());

    REQUIRE_FALSE(decoder.pull(frame));
}

TEST_CASE("snapshot decoder rejects reordered frames") {
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotEncoder encoder(snapshot, key);
    const auto first = encoder.push(RecordType::context, bytes("first")).value();
    const auto second = encoder.push(RecordType::file_header, bytes("second")).value();
    SnapshotDecoder decoder(snapshot, key, encoder.header());

    REQUIRE_FALSE(decoder.pull(second));
    REQUIRE(decoder.pull(first).value() == bytes("first"));
}

TEST_CASE("missing FINAL and writes after FINAL are rejected") {
    const auto key = test_key();
    const auto snapshot = context();
    SnapshotEncoder encoder(snapshot, key);
    const auto frame = encoder.push(RecordType::context, bytes("context")).value();
    SnapshotDecoder decoder(snapshot, key, encoder.header());
    REQUIRE(decoder.pull(frame));
    REQUIRE_FALSE(decoder.finish());

    const auto final = encoder.push(RecordType::final_summary, bytes("done")).value();
    REQUIRE_FALSE(encoder.push(RecordType::file_header, bytes("late")).has_value());
    REQUIRE(decoder.pull(final));
    REQUIRE(decoder.finish());
    REQUIRE_FALSE(decoder.pull(final));
}

TEST_CASE("snapshot frame size is bounded") {
    const auto key = test_key();
    SnapshotEncoder encoder(context(), key);
    const Bytes oversized(cpcp::crypto::snapshot_frame_limit + 1, std::byte{1});

    const auto result = encoder.push(RecordType::chunk_batch, oversized);

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::usage);
}

}
