#include "storage/session_spool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <string>

namespace {

using cpcp::crypto::Bytes;
using cpcp::crypto::RecordType;
using cpcp::crypto::SnapshotContext;
using cpcp::crypto::SecureKey;
using cpcp::storage::SessionSpoolReader;
using cpcp::storage::SessionSpoolWriter;

class TestDirectory {
public:
    explicit TestDirectory(const std::string& name) {
        path_ = std::filesystem::path(CPCP_TEST_TEMP_DIR) / name;
        std::filesystem::remove_all(path_);
        std::filesystem::create_directories(path_);
    }

    ~TestDirectory() {
        std::filesystem::remove_all(path_);
    }

    std::filesystem::path path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

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
    result.generation = 1;
    return result;
}

TEST_CASE("encrypted session spool round trips bounded records") {
    TestDirectory directory("spool-roundtrip");
    const auto path = directory.path() / "session.spool";
    const auto key = test_key();
    const auto session = context();
    SessionSpoolWriter writer;
    REQUIRE(writer.create(path, key, session));
    REQUIRE(writer.append(RecordType::file_header, bytes("/home/alice/secret.txt")));
    REQUIRE(writer.append(RecordType::chunk_batch, bytes("descriptor")));
    REQUIRE(writer.finalize(bytes("complete")));
    REQUIRE(writer.finalized());

    SessionSpoolReader reader;
    REQUIRE(reader.open(path, key, session));
    const auto first = reader.next().value();
    REQUIRE(first.has_value());
    REQUIRE(first->type == RecordType::file_header);
    REQUIRE(first->plaintext == bytes("/home/alice/secret.txt"));
    const auto second = reader.next().value();
    REQUIRE(second->type == RecordType::chunk_batch);
    const auto final = reader.next().value();
    REQUIRE(final->type == RecordType::final_summary);
    REQUIRE(reader.finish());
    REQUIRE_FALSE(reader.next().value().has_value());
}

TEST_CASE("session spool does not expose plaintext paths on disk") {
    TestDirectory directory("spool-confidentiality");
    const auto path = directory.path() / "session.spool";
    const auto key = test_key();
    const auto session = context();
    SessionSpoolWriter writer;
    REQUIRE(writer.create(path, key, session));
    REQUIRE(writer.append(RecordType::file_header, bytes("/home/alice/secret.txt")));
    REQUIRE(writer.finalize(bytes("complete")));

    auto file = cpcp::platform::BinaryFile::open_read(path).value();
    Bytes raw;
    std::array<std::byte, 256> buffer{};
    while (true) {
        const auto count = file.read_some(buffer).value();
        if (count == 0) {
            break;
        }
        raw.insert(raw.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count));
    }
    const std::string contents{
        reinterpret_cast<const char*>(raw.data()),
        raw.size(),
    };

    REQUIRE(contents.find("/home/alice/secret.txt") == std::string::npos);
}

TEST_CASE("session spool rejects a missing FINAL") {
    TestDirectory directory("spool-missing-final");
    const auto path = directory.path() / "session.spool";
    const auto key = test_key();
    const auto session = context();
    {
        SessionSpoolWriter writer;
        REQUIRE(writer.create(path, key, session));
        REQUIRE(writer.append(RecordType::file_header, bytes("file")));
    }

    SessionSpoolReader reader;
    REQUIRE(reader.open(path, key, session));
    REQUIRE(reader.next().value().has_value());
    const auto result = reader.next();

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::integrity);
    REQUIRE_FALSE(reader.finish());
}

TEST_CASE("session spool AAD rejects a different session") {
    TestDirectory directory("spool-wrong-session");
    const auto path = directory.path() / "session.spool";
    const auto key = test_key();
    SessionSpoolWriter writer;
    REQUIRE(writer.create(path, key, context()));
    REQUIRE(writer.append(RecordType::file_header, bytes("file")));
    REQUIRE(writer.finalize(bytes("complete")));
    auto other = context();
    other.snapshot_uuid.fill(std::byte{9});

    SessionSpoolReader reader;
    REQUIRE(reader.open(path, key, other));

    REQUIRE_FALSE(reader.next());
}

}
