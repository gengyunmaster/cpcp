#include "application/backup_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

cpcp::crypto::SecretBytes password() {
    const std::string text = "password";
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return cpcp::crypto::SecretBytes::copy(bytes).value();
}

std::vector<std::string> repository_state(const std::filesystem::path& repository) {
    std::vector<std::string> result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(repository)) {
        const auto size = entry.is_regular_file() ? entry.file_size() : 0;
        result.push_back(
            std::filesystem::relative(entry.path(), repository).generic_string()
            + ":" + std::to_string(static_cast<std::uint64_t>(size))
            + ":" + std::to_string(static_cast<std::int64_t>(entry.last_write_time().time_since_epoch().count()))
        );
    }
    std::ranges::sort(result);
    return result;
}

TEST_CASE("backup dry-run reads sources without changing the repository") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "backup-dry-run-test";
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
    std::ofstream(source / "b.txt") << "new";

    const auto before = repository_state(repository);
    cpcp::application::BackupOptions options;
    options.dry_run = true;
    const auto plan = cpcp::application::backup_add(repository, password(), {source}, options).value();
    REQUIRE(plan.snapshot.status == "dry-run");
    REQUIRE(plan.snapshot.stats.files == 2);
    REQUIRE(plan.snapshot.stats.chunk_references == 2);
    REQUIRE(plan.snapshot.stats.new_chunks == 1);
    REQUIRE(plan.snapshot.stats.deduplicated_chunks == 1);
    REQUIRE(repository_state(repository) == before);
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().size() == 1);
    REQUIRE(cpcp::application::backup_status(repository, password()).value().empty());
    std::filesystem::remove_all(root);
}

}
