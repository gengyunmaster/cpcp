#include "application/backup_service.hpp"
#include "application/lifecycle_service.hpp"
#include "application/repository_service.hpp"
#include "application/inspection_service.hpp"

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

TEST_CASE("snapshot retirement and two-phase garbage collection preserve reachability") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "lifecycle-test";
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
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));

    REQUIRE_FALSE(cpcp::application::forget_snapshot(repository, password(), 1, false, false));
    const auto planned = cpcp::application::forget_snapshot(repository, password(), 1, true, false).value();
    REQUIRE(planned.moved.size() == 2);
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().size() == 2);
    REQUIRE(cpcp::application::forget_snapshot(repository, password(), 1, false, true));
    const auto active = cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key);
    if (!active) {
        INFO(active.error().message);
    }
    REQUIRE(active.has_value());
    REQUIRE(active->size() == 1);
    REQUIRE(cpcp::application::purge_quarantine(repository, password(), std::chrono::seconds(0), false, true));

    auto gc = cpcp::application::collect_garbage(repository, password(), std::chrono::hours(24), false, true).value();
    REQUIRE(gc.moved.empty());
    REQUIRE(cpcp::application::forget_snapshot(repository, password(), 2, false, true));
    REQUIRE(cpcp::application::purge_quarantine(repository, password(), std::chrono::seconds(0), false, true));
    gc = cpcp::application::collect_garbage(repository, password(), std::chrono::hours(24), false, true).value();
    REQUIRE(gc.moved.size() == 1);
    REQUIRE(cpcp::application::repository_statistics(repository, password()).value().chunk_objects == 0);
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().empty());

    const auto dry = cpcp::application::collect_garbage(repository, password(), std::chrono::seconds(0), true, false).value();
    REQUIRE(dry.deleted.size() == 5);
    REQUIRE(cpcp::application::repository_statistics(repository, password()).value().trash_files == 5);
    const auto deleted = cpcp::application::collect_garbage(repository, password(), std::chrono::seconds(0), false, true).value();
    REQUIRE(deleted.deleted.size() == 5);
    REQUIRE(cpcp::application::repository_statistics(repository, password()).value().trash_files == 0);
    std::filesystem::remove_all(root);
}

TEST_CASE("quarantine and incomplete sessions block garbage collection") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "lifecycle-blocked-test";
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
    {
        std::ofstream(repository / "quarantine" / "damage.bin") << "damaged";
    }
    REQUIRE_FALSE(cpcp::application::collect_garbage(repository, password(), std::chrono::seconds(0), true, false));
    REQUIRE(cpcp::application::purge_quarantine(repository, password(), std::chrono::seconds(0), false, true));
    REQUIRE(cpcp::application::collect_garbage(repository, password(), std::chrono::seconds(0), true, false));

    cpcp::application::BackupOptions options;
    options.interrupt_after_chunks_for_testing = 1;
    options.no_parent = true;
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {source}, options));
    REQUIRE_FALSE(cpcp::application::collect_garbage(repository, password(), std::chrono::seconds(0), true, false));
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    REQUIRE(cpcp::application::backup_discard(repository, password(), sessions[0].session_uuid, true));
    std::filesystem::remove_all(root);
}

}
