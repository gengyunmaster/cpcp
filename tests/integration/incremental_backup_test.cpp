#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

cpcp::crypto::SecretBytes password() {
    const std::string text = "password";
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return cpcp::crypto::SecretBytes::copy(bytes).value();
}

TEST_CASE("incremental backups distinguish source reuse from full source reads") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "incremental-backup-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    {
        std::ofstream(source / "a.txt") << "hello";
        std::ofstream(source / "b.txt") << "world";
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    const auto first = cpcp::application::backup_add(repository, password(), {source}, {}).value();
    REQUIRE(first.snapshot.stats.source_reused_files == 0);

    const auto incremental = cpcp::application::backup_add(repository, password(), {source}, {}).value();
    REQUIRE(incremental.snapshot.stats.files == 2);
    REQUIRE(incremental.snapshot.stats.source_reused_files == 2);
    REQUIRE(incremental.snapshot.stats.new_chunks == 0);
    REQUIRE(incremental.snapshot.stats.deduplicated_chunks == 2);
    REQUIRE(cpcp::application::verify_repository(
        repository,
        password(),
        cpcp::application::VerifyOptions{true, false}
    ));

    cpcp::application::BackupOptions full;
    full.full_source_read = true;
    const auto reread = cpcp::application::backup_add(repository, password(), {source}, full).value();
    REQUIRE(reread.snapshot.stats.source_reused_files == 0);
    REQUIRE(reread.snapshot.stats.deduplicated_chunks == 2);

    const auto changed_time = std::filesystem::last_write_time(source / "a.txt") + std::chrono::seconds(1);
    std::filesystem::last_write_time(source / "a.txt", changed_time);
    const auto changed = cpcp::application::backup_add(repository, password(), {source}, {}).value();
    REQUIRE(changed.snapshot.stats.source_reused_files == 1);
    REQUIRE(changed.snapshot.stats.new_chunks == 0);

    cpcp::application::RestoreOptions restore;
    restore.destination = root / "restored";
    REQUIRE(cpcp::application::restore_snapshot(
        repository,
        password(),
        incremental.snapshot.context.generation,
        restore
    ));
    REQUIRE(std::filesystem::file_size(restore.destination / "source" / "a.txt") == 5);
    std::filesystem::remove_all(root);
}

TEST_CASE("bounded compression workers preserve snapshot ordering and content") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "bounded-jobs-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    std::ofstream output(source / "large.bin", std::ios::binary);
    const std::string block(1024 * 1024, 'x');
    for (unsigned int index = 0; index < 4; ++index) {
        output << block;
    }
    output.close();
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    cpcp::application::BackupOptions options;
    options.jobs = 4;
    const auto snapshot = cpcp::application::backup_add(repository, password(), {source}, options).value().snapshot;
    REQUIRE(snapshot.stats.chunk_references == 4);
    REQUIRE(snapshot.stats.files == 1);
    REQUIRE(cpcp::application::verify_repository(
        repository,
        password(),
        cpcp::application::VerifyOptions{true, false}
    ));
    std::filesystem::remove_all(root);
}

TEST_CASE("repository statistics distinguish stored and allocated bytes") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "repository-stats-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    {
        std::ofstream(source / "a.txt") << "hello";
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));
    const auto stats = cpcp::application::repository_statistics(repository, password()).value();
    REQUIRE(stats.snapshots == 1);
    REQUIRE(stats.latest_generation == 1);
    REQUIRE(stats.logical_bytes == 5);
    REQUIRE(stats.chunk_objects == 1);
    REQUIRE(stats.chunk_stored_bytes == 69);
    REQUIRE(stats.chunk_allocated_bytes >= stats.chunk_stored_bytes);
    REQUIRE(stats.snapshot_main_bytes > 0);
    REQUIRE(stats.snapshot_summary_bytes > 0);
    REQUIRE(stats.session_files == 0);
    REQUIRE(stats.quarantine_files == 0);
    std::filesystem::remove_all(root);
}

}
