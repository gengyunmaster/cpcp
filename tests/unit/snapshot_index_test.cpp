#include "repository/snapshot_index.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

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

    std::filesystem::path path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

cpcp::crypto::SecureKey key() {
    std::array<std::byte, cpcp::crypto::key_size> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return cpcp::crypto::SecureKey::from_bytes(bytes).value();
}

TEST_CASE("snapshot path indexes externally sort and query keyed metadata") {
    TestDirectory fixture("snapshot-path-index");
    auto index = cpcp::repository::SnapshotPathIndex::create(
        fixture.path() / "index",
        key()
    ).value();
    cpcp::domain::Uuid root{};
    root.fill(std::byte{7});
    constexpr std::uint64_t count = 35000;
    for (std::uint64_t value = count; value-- > 0;) {
        cpcp::repository::SnapshotPathMetadata metadata;
        metadata.type = cpcp::repository::SnapshotEntryType::file;
        metadata.size = value;
        metadata.mtime_seconds = -static_cast<std::int64_t>(value);
        metadata.mtime_nanoseconds = static_cast<std::uint32_t>(value % 1000);
        metadata.file_id.fill(static_cast<std::byte>(value % 256));
        REQUIRE(index.add(root, "file-" + std::to_string(value), metadata));
    }
    REQUIRE(index.finish());

    const std::array<std::uint64_t, 6> samples{0, 1, 1023, 1024, 32768, 34999};
    for (const std::uint64_t value : samples) {
        const auto metadata = index.find(root, "file-" + std::to_string(value)).value();
        REQUIRE(metadata.has_value());
        REQUIRE(metadata->type == cpcp::repository::SnapshotEntryType::file);
        REQUIRE(metadata->size == static_cast<std::uint64_t>(value));
        REQUIRE(metadata->mtime_seconds == -static_cast<std::int64_t>(value));
        REQUIRE(metadata->mtime_nanoseconds == static_cast<std::uint32_t>(value % 1000));
    }
    REQUIRE_FALSE(index.find(root, "missing").value().has_value());
    root.fill(std::byte{8});
    REQUIRE_FALSE(index.find(root, "file-1").value().has_value());

    std::ifstream input(fixture.path() / "index" / "sorted.bin", std::ios::binary);
    const std::string bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );
    REQUIRE(bytes.find("file-123") == std::string::npos);
}

TEST_CASE("snapshot path indexes reject duplicate paths") {
    TestDirectory fixture("snapshot-path-index-duplicate");
    auto index = cpcp::repository::SnapshotPathIndex::create(
        fixture.path() / "index",
        key()
    ).value();
    cpcp::domain::Uuid root{};
    REQUIRE(index.add(root, "same", {}));
    REQUIRE(index.add(root, "same", {}));
    const auto finished = index.finish();
    REQUIRE_FALSE(finished);
    REQUIRE(finished.error().code == cpcp::domain::ErrorCode::integrity);
}

}
