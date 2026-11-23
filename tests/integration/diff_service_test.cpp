#include "application/backup_service.hpp"
#include "application/diff_service.hpp"
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

TEST_CASE("snapshot diff reports both directions and change reasons") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "snapshot-diff-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    {
        std::ofstream(source / "a.txt") << "before";
        std::ofstream(source / "b.txt") << "missing";
        std::ofstream(source / "c.txt") << "type";
        std::ofstream(source / "e.txt") << "same";
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));
    {
        std::ofstream(source / "a.txt", std::ios::trunc) << "after";
        std::ofstream(source / "d.txt") << "added";
    }
    std::filesystem::remove(source / "b.txt");
    std::filesystem::remove(source / "c.txt");
    std::filesystem::create_directory(source / "c.txt");
    REQUIRE(cpcp::application::backup_add(repository, password(), {source}, {}));

    std::map<std::string, cpcp::application::DiffEvent> events;
    const auto report = cpcp::application::diff_snapshots(
        repository,
        password(),
        1,
        2,
        [&](const cpcp::application::DiffEvent& event) -> cpcp::domain::Result<void> {
            events[event.path] = event;
            return {};
        }
    ).value();
    REQUIRE(events.at("a.txt").status == "changed");
    REQUIRE(events.at("a.txt").reason == "content identity differs");
    REQUIRE(events.at("b.txt").status == "missing");
    REQUIRE(events.at("c.txt").status == "type-changed");
    REQUIRE(events.at("d.txt").status == "added");
    REQUIRE(events.at("e.txt").status == "unchanged");
    REQUIRE(report.total == 5);
    REQUIRE(report.differences == 4);
    REQUIRE(report.left_status == "complete");
    REQUIRE(report.right_status == "complete");
    std::filesystem::remove_all(root);
}

}
