#include "application/backup_service.hpp"

#include "application/repository_service.hpp"
#include "application/inspection_service.hpp"
#include "application/recovery_service.hpp"
#include "repository/chunk_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

using cpcp::application::BackupOptions;
using cpcp::crypto::SecretBytes;

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

void write_file(const std::filesystem::path& path, const std::string& contents) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << contents;
}

TEST_CASE("backup creates and reuses snapshots with deduplication") {
    TestDirectory fixture("backup-service");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    std::filesystem::create_directories(source / "sub");
    write_file(source / "empty.txt", "");
    write_file(source / "a.txt", "hello");
    write_file(source / "sub" / "b.txt", "world");
    write_file(source / "duplicate.txt", "hello");
#ifndef _WIN32
    std::filesystem::create_symlink(source / "a.txt", source / "link.txt");
#endif
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));

    const auto first = cpcp::application::backup_add(repository, password(), {source}, {}).value();

    REQUIRE(first.snapshot.stats.files == 4);
    REQUIRE(first.snapshot.stats.chunk_references == 3);
    REQUIRE(first.snapshot.stats.new_chunks == 2);
    REQUIRE(first.snapshot.stats.deduplicated_chunks == 1);
#ifndef _WIN32
    REQUIRE(first.skipped_entries == 0);
    REQUIRE(first.snapshot.stats.symlinks == 1);
#endif

    const auto second = cpcp::application::backup_add(repository, password(), {source}, {}).value();

    REQUIRE(second.snapshot.context.generation == 2);
    REQUIRE(second.snapshot.stats.new_chunks == 0);
    REQUIRE(second.snapshot.stats.deduplicated_chunks == 3);
    REQUIRE(second.snapshot.context.lineage_uuid == first.snapshot.context.lineage_uuid);

    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    auto store = cpcp::repository::ChunkStore::create(repository, unlocked.config, unlocked.master_key).value();
    auto reader = cpcp::repository::SnapshotReader::open(
        repository,
        unlocked.config,
        unlocked.master_key,
        second.snapshot
    ).value();
    std::map<std::string, std::vector<std::byte>> restored;
    while (true) {
        const auto record = reader.next().value();
        if (!record.has_value()) {
            break;
        }
        if (record->type == cpcp::crypto::RecordType::file_header) {
            const auto header = cpcp::repository::parse_file_header(*record).value();
            restored.emplace(header.path, std::vector<std::byte>{});
        } else if (record->type == cpcp::crypto::RecordType::chunk_batch) {
            const auto batch = cpcp::repository::parse_chunk_batch(*record).value();
            const auto& header = restored.find("sub/b.txt") != restored.end() && batch.chunks.front().plaintext_length == 5
                ? restored.find("sub/b.txt")
                : restored.end();
            static_cast<void>(header);
            for (const auto& chunk : batch.chunks) {
                const auto plaintext = store.get(cpcp::repository::ChunkMetadata{
                    chunk.chunk_id,
                    chunk.plaintext_length,
                    chunk.stored_length,
                    false,
                    chunk.format_version,
                    chunk.content_encoding,
                }).value();
                if (plaintext == std::vector<std::byte>{std::byte{'w'}, std::byte{'o'}, std::byte{'r'}, std::byte{'l'}, std::byte{'d'}}) {
                    restored["sub/b.txt"].insert(restored["sub/b.txt"].end(), plaintext.begin(), plaintext.end());
                }
            }
        }
    }
    const std::vector<std::byte> expected{std::byte{'w'}, std::byte{'o'}, std::byte{'r'}, std::byte{'l'}, std::byte{'d'}};
    REQUIRE(restored["sub/b.txt"] == expected);
}

TEST_CASE("partial snapshots authenticate failures and require explicit restore approval") {
    TestDirectory fixture("backup-partial");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    std::filesystem::create_directories(source);
    write_file(source / "a.txt", "hello");
    REQUIRE(mkfifo((source / "fifo").c_str(), 0600) == 0);
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));

    const auto complete = cpcp::application::backup_add(
        repository,
        password(),
        {source},
        {}
    ).value();
    REQUIRE(complete.snapshot.status == "complete");
    REQUIRE(complete.snapshot.stats.selection->policy_skipped_entries == 1);

    cpcp::application::BackupOptions options;
    options.unsupported_fail = true;
    const auto rejected = cpcp::application::backup_add(repository, password(), {source}, options);
    REQUIRE_FALSE(rejected);
    REQUIRE(rejected.error().code == cpcp::domain::ErrorCode::source_changed);

    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(
        repository,
        unlocked.config,
        unlocked.master_key
    ).value().size() == 1);

    options.allow_partial = true;
    const auto partial = cpcp::application::backup_add(
        repository,
        password(),
        {source},
        options
    ).value();
    REQUIRE(partial.snapshot.status == "partial");
    REQUIRE(partial.snapshot.selection_policy.unsupported == "fail");
    REQUIRE(partial.snapshot.stats.selection->failed_entries == 1);
    REQUIRE(partial.snapshot.stats.files == 1);
    REQUIRE(cpcp::application::verify_repository(repository, password(), {}));

    cpcp::application::RestoreOptions restore;
    restore.destination = fixture.path() / "latest-rejected";
    const auto latest = cpcp::application::restore_snapshot(
        repository,
        password(),
        std::nullopt,
        restore
    );
    REQUIRE_FALSE(latest);
    REQUIRE(latest.error().code == cpcp::domain::ErrorCode::usage);

    restore.destination = fixture.path() / "latest-complete";
    restore.latest_complete = true;
    const auto selected_complete = cpcp::application::restore_snapshot(
        repository,
        password(),
        std::nullopt,
        restore
    ).value();
    REQUIRE(selected_complete.snapshot_generation == complete.snapshot.context.generation);
    REQUIRE(selected_complete.snapshot_status == "complete");

    restore.destination = fixture.path() / "latest-partial";
    restore.latest_complete = false;
    restore.allow_partial = true;
    const auto selected_partial = cpcp::application::restore_snapshot(
        repository,
        password(),
        std::nullopt,
        restore
    ).value();
    REQUIRE(selected_partial.snapshot_generation == partial.snapshot.context.generation);
    REQUIRE(selected_partial.snapshot_status == "partial");
    REQUIRE(selected_partial.files == 1);

    const auto repaired = cpcp::application::repair_summary(
        repository,
        password(),
        partial.snapshot.context.generation
    ).value();
    REQUIRE(repaired.status == "partial");
    REQUIRE(repaired.selection_policy.unsupported == "fail");
    REQUIRE(repaired.stats.selection->failed_entries == 1);
    REQUIRE(cpcp::application::verify_repository(repository, password(), {}));
}

TEST_CASE("an explicit older base preserves lineage and allocates the global next generation") {
    TestDirectory fixture("backup-explicit-base");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    write_file(source / "a.txt", "first");
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    const auto first = cpcp::application::backup_add(repository, password(), {source}, {}).value();
    write_file(source / "a.txt", "second");
    const auto second = cpcp::application::backup_add(repository, password(), {source}, {}).value();

    cpcp::application::BackupOptions options;
    options.base_generation = first.snapshot.context.generation;
    options.tag = "weekly";
    const auto third = cpcp::application::backup_add(repository, password(), {source}, options).value();
    REQUIRE(third.snapshot.context.generation == second.snapshot.context.generation + 1);
    REQUIRE(third.snapshot.has_parent);
    REQUIRE(third.snapshot.parent_uuid == first.snapshot.context.snapshot_uuid);
    REQUIRE(third.snapshot.context.lineage_uuid == first.snapshot.context.lineage_uuid);
    REQUIRE(third.snapshot.tag == "weekly");

    options.no_parent = true;
    const auto conflicting = cpcp::application::backup_add(repository, password(), {source}, options);
    REQUIRE_FALSE(conflicting);
    REQUIRE(conflicting.error().code == cpcp::domain::ErrorCode::usage);
}

}
