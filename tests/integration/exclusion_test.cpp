#include "application/backup_service.hpp"
#include "application/check_service.hpp"
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

TEST_CASE("authenticated exclusions survive resume and remain visible in checks") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "exclusion-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source / "sub" / "ignore");
    std::filesystem::create_directories(source / "sub" / "keep");
    {
        std::ofstream(source / "keep.txt") << "keep";
        std::ofstream(source / "skip.tmp") << "skip";
        std::ofstream(source / "sub" / "ignore" / "file.txt") << "ignored";
        std::ofstream(source / "sub" / "keep" / "file.txt") << "kept";
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));

    cpcp::application::BackupOptions options;
    options.exclude_patterns = {"*.tmp", "sub/ignore"};
    options.interrupt_after_chunks_for_testing = 1;
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {source}, options));
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    const auto snapshot = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        {}
    ).value().snapshot;
    REQUIRE(snapshot.stats.files == 2);
    REQUIRE(snapshot.stats.selection->policy_skipped_entries == 2);
    REQUIRE(snapshot.selection_policy.exclusions == options.exclude_patterns);
    REQUIRE(cpcp::application::verify_repository(repository, password(), {}));

    cpcp::application::CheckOptions check;
    check.source = source;
    std::map<std::string, std::string> statuses;
    const auto report = cpcp::application::check_backup(
        repository,
        password(),
        check,
        [&](const cpcp::application::CheckEvent& event) -> cpcp::domain::Result<void> {
            statuses[event.path] = event.status;
            return {};
        }
    ).value();
    REQUIRE(statuses.at("skip.tmp") == "skipped");
    REQUIRE(statuses.at("sub/ignore") == "skipped");
    REQUIRE(statuses.at("keep.txt") == "metadata-match");
    REQUIRE(report.differences == 2);
    std::filesystem::remove_all(root);
}

}
