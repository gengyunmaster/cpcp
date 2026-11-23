#include "application/recovery_service.hpp"

#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"
#include "repository/chunk_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <stdexcept>
#include <vector>

namespace {

using cpcp::crypto::SecretBytes;
using cpcp::repository::SnapshotSummary;

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

SecretBytes password() {
    const std::string text = "password";
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return SecretBytes::copy(bytes).value();
}

struct Fixture {
    TestDirectory directory;
    std::filesystem::path repository;
    std::filesystem::path source;
    SnapshotSummary snapshot;

    explicit Fixture(const std::string& name)
        : directory(name),
          repository(directory.path() / "repo"),
          source(directory.path() / "source") {
        std::filesystem::create_directories(source);
        {
            std::ofstream output(source / "a.txt");
            output << "hello";
        }
        cpcp::repository::ConfigOptions options;
        options.kdf = {8192, 1};
        options.chunk_size = 1024 * 1024;
        cpcp::application::initialize_repository(repository, password(), options).value();
        snapshot = cpcp::application::backup_add(repository, password(), {source}, {}).value().snapshot;
    }
};

std::pair<cpcp::crypto::Digest, std::filesystem::path> first_chunk(
    const Fixture& fixture
) {
    const auto unlocked = cpcp::repository::load_config(fixture.repository, password()).value();
    auto reader = cpcp::repository::SnapshotReader::open(
        fixture.repository,
        unlocked.config,
        unlocked.master_key,
        fixture.snapshot
    ).value();
    while (true) {
        const auto record = reader.next().value();
        if (!record.has_value()) {
            throw std::runtime_error("snapshot has no chunk batch");
        }
        if (record->type == cpcp::crypto::RecordType::chunk_batch) {
            const auto batch = cpcp::repository::parse_chunk_batch(*record).value();
            const auto id = batch.chunks.front().chunk_id;
            const auto hex = cpcp::crypto::to_hex(id);
            return {
                id,
                fixture.repository / "chunks" / hex.substr(0, 2) / hex.substr(2, 2) / hex,
            };
        }
    }
}

void flip_last_byte(const std::filesystem::path& path) {
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    stream.seekp(-1, std::ios::end);
    char value = 0;
    stream.read(&value, 1);
    value ^= 1;
    stream.seekp(-1, std::ios::end);
    stream.write(&value, 1);
}

TEST_CASE("quarantined chunk can be recreated and verified") {
    Fixture fixture("recovery-chunk");
    const auto [id, path] = first_chunk(fixture);
    flip_last_byte(path);

    const auto report = cpcp::application::quarantine_chunk(
        fixture.repository,
        password(),
        id,
        false
    ).value();
    REQUIRE(report.moved.size() == 1);
    REQUIRE_FALSE(std::filesystem::exists(path));
    REQUIRE(std::filesystem::exists(report.moved.front().second));

    const auto recreated = cpcp::application::backup_add(
        fixture.repository,
        password(),
        {fixture.source},
        {}
    ).value();
    REQUIRE(recreated.snapshot.stats.new_chunks == 1);
    REQUIRE(cpcp::application::verify_repository(
        fixture.repository,
        password(),
        cpcp::application::VerifyOptions{true, false}
    ));
}

TEST_CASE("damaged summary is independently rebuilt from main") {
    Fixture fixture("recovery-summary");
    const auto path = cpcp::repository::snapshot_summary_path(
        fixture.repository,
        fixture.snapshot
    );
    flip_last_byte(path);

    const auto repaired = cpcp::application::repair_summary(
        fixture.repository,
        password(),
        fixture.snapshot.context.generation
    ).value();

    REQUIRE(repaired.main_ciphertext_digest == fixture.snapshot.main_ciphertext_digest);
    REQUIRE(repaired.context.lineage_uuid == fixture.snapshot.context.lineage_uuid);
    const auto unlocked = cpcp::repository::load_config(fixture.repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(fixture.repository, unlocked.config, unlocked.master_key));
    const auto restored = cpcp::application::restore_snapshot(
        fixture.repository,
        password(),
        repaired.context.generation,
        cpcp::application::RestoreOptions{
            .destination = fixture.directory.path() / "restored",
            .root = std::nullopt,
            .path = std::nullopt,
        }
    ).value();
    REQUIRE(restored.files == 1);
}

TEST_CASE("snapshot quarantine preserves objects and no-parent starts a new lineage") {
    Fixture fixture("recovery-no-parent");
    const auto second = cpcp::application::backup_add(
        fixture.repository,
        password(),
        {fixture.source},
        {}
    ).value().snapshot;
    const auto quarantined = cpcp::application::quarantine_snapshot(
        fixture.repository,
        password(),
        second.context.generation,
        false
    ).value();
    REQUIRE(quarantined.moved.size() == 2);

    cpcp::application::BackupOptions options;
    options.no_parent = true;
    const auto restarted = cpcp::application::backup_add(
        fixture.repository,
        password(),
        {fixture.source},
        options
    ).value();

    REQUIRE(restarted.snapshot.context.lineage_uuid != second.context.lineage_uuid);
    REQUIRE(restarted.snapshot.context.generation > fixture.snapshot.context.generation);
}

TEST_CASE("configuration repair restores both replicas") {
    Fixture fixture("recovery-config");
    flip_last_byte(fixture.repository / "cpcp.config.json");

    REQUIRE(cpcp::application::repair_config(fixture.repository, password()));
    const auto loaded = cpcp::repository::load_config(fixture.repository, password()).value();

    REQUIRE_FALSE(loaded.degraded_redundancy);
}

}
