#include "application/backup_service.hpp"
#include "application/check_service.hpp"
#include "application/diff_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <map>
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

TEST_CASE("symbolic links survive resume, checks, diffs, and restoration") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "symlink-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    std::ofstream(source / "a.txt") << "hello";
    std::filesystem::create_symlink("a.txt", source / "link.txt");
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    cpcp::application::BackupOptions options;
    options.interrupt_after_chunks_for_testing = 1;
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {source}, options));
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    const auto resumed = cpcp::application::backup_resume(repository, password(), sessions[0].session_uuid, {});
    if (!resumed) {
        INFO(resumed.error().message);
    }
    REQUIRE(resumed.has_value());
    const auto first = resumed->snapshot;
    REQUIRE(first.stats.files == 1);
    REQUIRE(first.stats.symlinks == 1);
    REQUIRE(first.selection_policy.symlinks);
    const auto verified = cpcp::application::verify_repository(repository, password(), {});
    if (!verified) {
        FAIL(verified.error().message);
    }

    cpcp::application::RestoreOptions restore;
    restore.destination = root / "restored";
    const auto restored = cpcp::application::restore_snapshot(repository, password(), first.context.generation, restore).value();
    REQUIRE(restored.symlinks == 1);
    REQUIRE(std::filesystem::read_symlink(restore.destination / "source" / "link.txt") == "a.txt");

    cpcp::application::CheckOptions check;
    check.source = source;
    check.content = true;
    std::map<std::string, std::string> statuses;
    const auto checked = cpcp::application::check_backup(repository, password(), check, [&](const cpcp::application::CheckEvent& event) -> cpcp::domain::Result<void> {
        statuses[event.path] = event.status;
        return {};
    }).value();
    REQUIRE(checked.differences == 0);
    REQUIRE(statuses.at("link.txt") == "content-match");

    std::filesystem::remove(source / "link.txt");
    std::filesystem::create_symlink("other.txt", source / "link.txt");
    const auto second = cpcp::application::backup_add(repository, password(), {source}, {});
    if (!second) {
        FAIL(second.error().message);
    }
    const auto diff = cpcp::application::diff_snapshots(repository, password(), 1, 2, [&](const cpcp::application::DiffEvent& event) -> cpcp::domain::Result<void> {
        if (event.path == "link.txt") {
            REQUIRE(event.status == "changed");
        }
        return {};
    }).value();
    REQUIRE(diff.differences == 1);
    std::filesystem::remove_all(root);
}

}
