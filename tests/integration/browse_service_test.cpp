#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using cpcp::application::BrowseOptions;
using cpcp::application::SnapshotEntry;
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

    const std::filesystem::path& path() const {
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

std::vector<SnapshotEntry> entries(
    const std::filesystem::path& repository,
    const BrowseOptions& options
) {
    std::vector<SnapshotEntry> result;
    const auto report = cpcp::application::browse_snapshot(
        repository,
        password(),
        options,
        false,
        [&](const SnapshotEntry& entry) -> cpcp::domain::Result<void> {
            result.push_back(entry);
            return {};
        }
    ).value();
    REQUIRE(report.entries == result.size());
    return result;
}

TEST_CASE("snapshot browsing filters authenticated entries without provisional output") {
    TestDirectory fixture("snapshot-browse");
    const auto repository = fixture.path() / "repo";
    const auto first = fixture.path() / "first";
    const auto second = fixture.path() / "second";
    write_file(first / "a.txt", "a");
    write_file(first / "sub" / "b.jpg", "jpg");
    write_file(second / "a.txt", "other a");
    write_file(second / "other.txt", "other");
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    const auto snapshot = cpcp::application::backup_add(
        repository,
        password(),
        {first, second},
        {}
    ).value().snapshot;

    BrowseOptions options;
    options.snapshot.generation = snapshot.context.generation;
    REQUIRE(entries(repository, options).size() == 5);

    options.root = 1;
    REQUIRE(entries(repository, options).size() == 2);

    options.root.reset();
    options.root_label = "first";
    REQUIRE(entries(repository, options).size() == 3);

    options.root_label.reset();
    options.glob = "*.txt";
    REQUIRE(entries(repository, options).size() == 3);

    options.glob = "*";
    options.path_prefix = "sub";
    const auto subtree = entries(repository, options);
    REQUIRE(subtree.size() == 2);
    REQUIRE(subtree[0].path == "sub");
    REQUIRE(subtree[1].path == "sub/b.jpg");

    options.path_prefix.clear();
    options.glob = "[";
    REQUIRE(entries(repository, options).empty());

    const auto main = cpcp::repository::snapshot_main_path(repository, snapshot);
    std::fstream stream(main, std::ios::in | std::ios::out | std::ios::binary);
    stream.seekp(-1, std::ios::end);
    char value = 0;
    stream.read(&value, 1);
    value ^= 1;
    stream.seekp(-1, std::ios::end);
    stream.write(&value, 1);
    stream.close();

    std::size_t callbacks = 0;
    const auto damaged = cpcp::application::browse_snapshot(
        repository,
        password(),
        options,
        false,
        [&](const SnapshotEntry&) -> cpcp::domain::Result<void> {
            ++callbacks;
            return {};
        }
    );
    REQUIRE_FALSE(damaged);
    REQUIRE(damaged.error().code == cpcp::domain::ErrorCode::integrity);
    REQUIRE(callbacks == 0);
}

}
