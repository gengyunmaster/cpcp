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

TEST_CASE("files larger than 4 GiB preserve offsets and content") {
    const auto fixture = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "large-file-test";
    std::filesystem::remove_all(fixture);
    std::filesystem::create_directories(fixture);
    const auto repository = fixture / "repo";
    const auto source = fixture / "source";
    std::filesystem::create_directories(source);
    constexpr std::uint64_t file_size = 4ULL * 1024ULL * 1024ULL * 1024ULL + 123ULL;
    const auto source_file = source / "large.bin";
    {
        std::ofstream output(source_file, std::ios::binary);
        output.close();
        std::filesystem::resize_file(source_file, file_size);
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 64 * 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    const auto snapshot = cpcp::application::backup_add(repository, password(), {source}, {}).value().snapshot;
    REQUIRE(snapshot.stats.files == 1);
    REQUIRE(snapshot.stats.logical_bytes == file_size);
    REQUIRE(snapshot.stats.chunk_references == 65);
    REQUIRE(snapshot.stats.new_chunks == 2);
    REQUIRE(snapshot.stats.deduplicated_chunks == 63);
    REQUIRE(cpcp::application::verify_repository(
        repository,
        password(),
        cpcp::application::VerifyOptions{true, false}
    ));

    cpcp::application::RestoreOptions restore;
    restore.destination = fixture / "restored";
    REQUIRE(cpcp::application::restore_snapshot(
        repository,
        password(),
        snapshot.context.generation,
        restore
    ));
    REQUIRE(std::filesystem::file_size(restore.destination / "source" / "large.bin") == file_size);
    std::filesystem::remove_all(fixture);
}

}
