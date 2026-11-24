#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

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

TEST_CASE("ownership and privileged permission bits require explicit restoration") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "metadata-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    std::ofstream(source / "a.txt") << "hello";
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));
    std::filesystem::permissions(
        source / "a.txt",
        std::filesystem::perms::set_uid | std::filesystem::perms::set_gid,
        std::filesystem::perm_options::add
    );
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));

    std::size_t ownership_records = 0;
    std::optional<cpcp::repository::OwnershipInfo> recorded;
    cpcp::application::BrowseOptions browse_options;
    browse_options.snapshot.generation = 3;
    const auto browsed = cpcp::application::browse_snapshot(
        repository,
        password(),
        browse_options,
        false,
        [&](const cpcp::application::SnapshotEntry&) -> cpcp::domain::Result<void> {
            return {};
        }
    );
    REQUIRE(browsed);
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    const auto summaries = cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value();
    auto reader = cpcp::repository::SnapshotReader::open(repository, unlocked.config, unlocked.master_key, summaries.back()).value();
    while (true) {
        const auto record = reader.next().value();
        if (!record) {
            break;
        }
        if (record->type == cpcp::crypto::RecordType::ownership) {
            recorded = cpcp::repository::parse_ownership(*record).value();
            ++ownership_records;
        }
    }
    REQUIRE(ownership_records == 1);
    const auto source_file = cpcp::platform::BinaryFile::open_read(source / "a.txt").value();
    REQUIRE(recorded->uid == source_file.metadata()->uid);

    cpcp::application::RestoreOptions restore;
    restore.destination = root / "restored-default";
    const auto restored = cpcp::application::restore_snapshot(repository, password(), 3, restore).value();
    REQUIRE(restored.metadata_warnings == 1);
    const auto mode = std::filesystem::status(restore.destination / "source" / "a.txt").permissions();
    REQUIRE((mode & std::filesystem::perms::set_uid) == std::filesystem::perms::none);
    REQUIRE((mode & std::filesystem::perms::set_gid) == std::filesystem::perms::none);

    restore.destination = root / "restored-privileged";
    restore.restore_privileged_bits = true;
    restore.restore_ownership = true;
    REQUIRE(cpcp::application::restore_snapshot(repository, password(), 3, restore));
    const auto privileged = std::filesystem::status(restore.destination / "source" / "a.txt").permissions();
    REQUIRE((privileged & std::filesystem::perms::set_uid) != std::filesystem::perms::none);
    REQUIRE((privileged & std::filesystem::perms::set_gid) != std::filesystem::perms::none);

    cpcp::application::RestoreOptions strict;
    strict.destination = root / "restored-strict";
    strict.strict_metadata = true;
    REQUIRE_FALSE(cpcp::application::restore_snapshot(repository, password(), 3, strict));
    std::filesystem::remove_all(root);
}

}
