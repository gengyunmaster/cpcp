#include "repository/snapshot.hpp"

#include "repository/chunk_set.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::ChunkDescriptor;
using cpcp::crypto::SecretBytes;
using cpcp::repository::ChunkBatch;
using cpcp::repository::DirectoryInfo;
using cpcp::repository::FileEnd;
using cpcp::repository::FileInfo;
using cpcp::repository::RepositoryConfig;
using cpcp::repository::RootInfo;
using cpcp::repository::SnapshotStats;
using cpcp::repository::SnapshotSummary;

class TestDirectory {
public:
    explicit TestDirectory(const std::string& name) {
        path_ = std::filesystem::path(CPCP_TEST_TEMP_DIR) / name;
        std::filesystem::remove_all(path_);
        std::filesystem::create_directories(path_ / "tmp");
        std::filesystem::create_directories(path_ / "snapshots");
        std::filesystem::create_directories(path_ / "chunks");
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

struct Fixture {
    TestDirectory directory;
    RepositoryConfig config;
    cpcp::crypto::SecureKey master;

    explicit Fixture(const std::string& name)
        : directory(name),
          config(make_config()),
          master(cpcp::repository::unlock_config(config, password()).value()) {
    }

    static SecretBytes password() {
        const std::string text = "password";
        cpcp::domain::Bytes bytes;
        for (const char value : text) {
            bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
        }
        return SecretBytes::copy(bytes).value();
    }

    static RepositoryConfig make_config() {
        cpcp::repository::ConfigOptions options;
        options.kdf = {8192, 1};
        options.chunk_size = 1024 * 1024;
        return cpcp::repository::create_config(password(), options).value();
    }

    std::filesystem::path path() const {
        return directory.path();
    }
};

std::vector<std::byte> bytes(const std::string& text) {
    std::vector<std::byte> result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

cpcp::crypto::SnapshotContext context() {
    cpcp::crypto::SnapshotContext result;
    result.repository_uuid.fill(std::byte{1});
    result.storage_epoch.fill(std::byte{2});
    result.snapshot_uuid.fill(std::byte{3});
    result.lineage_uuid.fill(std::byte{4});
    result.generation = 7;
    return result;
}

SnapshotStats one_file_stats(const cpcp::crypto::SecureKey& id_key, const ChunkDescriptor& chunk) {
    auto builder = cpcp::repository::ChunkSetBuilder::create(
        std::filesystem::path(CPCP_TEST_TEMP_DIR) / "snapshot-chunk-set",
        id_key
    ).value();
    REQUIRE(builder.add(chunk));
    SnapshotStats stats;
    stats.files = 1;
    stats.directories = 1;
    stats.logical_bytes = 5;
    stats.chunk_references = 1;
    stats.new_chunks = 1;
    stats.chunk_set_commitment = builder.finish().value();
    return stats;
}

SnapshotSummary write_snapshot(Fixture& fixture) {
    const auto id_key = cpcp::crypto::derive_key(
        fixture.master,
        cpcp::crypto::KeyPurpose::content_id
    ).value();
    const auto chunk_id = cpcp::crypto::compute_chunk_id(id_key, bytes("hello")).value();
    const ChunkDescriptor chunk{chunk_id, 5, 61};
    auto writer = cpcp::repository::SnapshotWriter::create(
        fixture.path(),
        fixture.config,
        fixture.master,
        context(),
        cpcp::crypto::random_uuid()
    ).value();
    REQUIRE(writer.append_root(RootInfo{0, cpcp::crypto::random_uuid(), "Documents", "/home/alice/Documents"}));
    REQUIRE(writer.append_directory(DirectoryInfo{0, "", 100, 20, 0644}));
    REQUIRE(writer.append_file_header(FileInfo{
        0,
        0,
        "a.txt",
        5,
        1,
        cpcp::crypto::compute_file_id(id_key, 5, std::span(&chunk, 1)).value(),
        100,
        20,
        0644,
    }));
    REQUIRE(writer.append_chunk_batch(ChunkBatch{0, 0, {chunk}}));
    REQUIRE(writer.append_file_end(FileEnd{
        0,
        1,
        cpcp::crypto::compute_file_id(id_key, 5, std::span(&chunk, 1)).value(),
    }));
    return writer.finish(one_file_stats(id_key, chunk)).value();
}

TEST_CASE("snapshot stream and summary round trip through typed records") {
    Fixture fixture("snapshot-roundtrip");
    const auto summary = write_snapshot(fixture);
    const auto summaries = cpcp::repository::list_snapshots(
        fixture.path(),
        fixture.config,
        fixture.master
    ).value();
    REQUIRE(summaries.size() == 1);
    REQUIRE(summaries[0].context.generation == 7);

    auto reader = cpcp::repository::SnapshotReader::open(
        fixture.path(),
        fixture.config,
        fixture.master,
        summaries[0]
    ).value();
    const auto root = reader.next().value();
    REQUIRE(cpcp::repository::parse_root(*root));
    const auto directory = reader.next().value();
    REQUIRE(cpcp::repository::parse_directory(*directory));
    const auto file = reader.next().value();
    REQUIRE(cpcp::repository::parse_file_header(*file));
    const auto chunks = reader.next().value();
    REQUIRE(cpcp::repository::parse_chunk_batch(*chunks));
    const auto end = reader.next().value();
    REQUIRE(cpcp::repository::parse_file_end(*end));
    const auto final = reader.next().value();
    REQUIRE(cpcp::repository::parse_final_stats(*final));
    REQUIRE_FALSE(reader.next().value().has_value());
}

TEST_CASE("snapshot summary tampering fails during listing") {
    Fixture fixture("snapshot-summary-tamper");
    const auto summary = write_snapshot(fixture);
    const auto path = cpcp::repository::snapshot_summary_path(fixture.path(), summary);
    {
        std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-1, std::ios::end);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(-1, std::ios::end);
        stream.write(&value, 1);
    }

    REQUIRE_FALSE(cpcp::repository::list_snapshots(fixture.path(), fixture.config, fixture.master));
}

TEST_CASE("main tampering is detected only by full stream verification") {
    Fixture fixture("snapshot-main-tamper");
    const auto summary = write_snapshot(fixture);
    const auto path = cpcp::repository::snapshot_main_path(fixture.path(), summary);
    {
        std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-1, std::ios::end);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(-1, std::ios::end);
        stream.write(&value, 1);
    }
    REQUIRE(cpcp::repository::list_snapshots(fixture.path(), fixture.config, fixture.master));

    auto reader = cpcp::repository::SnapshotReader::open(
        fixture.path(),
        fixture.config,
        fixture.master,
        summary
    ).value();
    bool failed = false;
    while (true) {
        const auto record = reader.next();
        if (!record) {
            failed = true;
            break;
        }
        if (!record->has_value()) {
            break;
        }
    }
    REQUIRE(failed);
}

}
