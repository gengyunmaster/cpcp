#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
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

TEST_CASE("name sanitization is deterministic, mapped, and dry-run safe") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "sanitize-restore-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    for (const auto& name : {"CON", "trail.", "percent%.txt", "normal.txt"}) {
        std::ofstream(source / name) << name;
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));

    cpcp::application::RestoreOptions dry;
    dry.destination = root / "dry-run";
    dry.sanitize_names = true;
    dry.dry_run = true;
    const auto planned = cpcp::application::restore_snapshot(repository, password(), 1, dry).value();
    REQUIRE(planned.files == 4);
    REQUIRE_FALSE(std::filesystem::exists(dry.destination));

    cpcp::application::RestoreOptions restore;
    restore.destination = root / "restored";
    restore.sanitize_names = true;
    REQUIRE(cpcp::application::restore_snapshot(repository, password(), 1, restore));
    REQUIRE(std::filesystem::exists(restore.destination / "source" / "%43ON"));
    REQUIRE(std::filesystem::exists(restore.destination / "source" / "trail%2E"));
    REQUIRE(std::filesystem::exists(restore.destination / "source" / "percent%25.txt"));
    REQUIRE(std::filesystem::exists(restore.destination / "source" / "normal.txt"));
    std::ifstream map_input(restore.destination / "cpcp-name-map.ndjson", std::ios::binary);
    const std::string map((std::istreambuf_iterator<char>(map_input)), std::istreambuf_iterator<char>());
    REQUIRE(map.find("\"original_path\":\"CON\"") != std::string::npos);
    REQUIRE(map.find("\"restored_path\":\"source/%43ON\"") != std::string::npos);

    cpcp::application::RestoreOptions selected;
    selected.destination = root / "selected";
    selected.root_label = "source";
    selected.path = "normal.txt";
    REQUIRE(cpcp::application::restore_snapshot(repository, password(), 1, selected));
    REQUIRE(std::filesystem::exists(selected.destination / "source" / "normal.txt"));
    std::filesystem::remove_all(root);
}

TEST_CASE("strip-root rejects colliding multi-root destinations") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "restore-collision-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto left = root / "left";
    const auto right = root / "right";
    std::filesystem::create_directories(left);
    std::filesystem::create_directories(right);
    std::ofstream(left / "a.txt") << "left";
    std::ofstream(right / "a.txt") << "right";
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    REQUIRE(cpcp::application::backup_add(repository, password(), {left, right}, {}));
    cpcp::application::RestoreOptions restore;
    restore.destination = root / "restored";
    restore.strip_root = true;
    const auto result = cpcp::application::restore_snapshot(repository, password(), 1, restore);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::conflict);
    std::filesystem::remove_all(root);
}

}
