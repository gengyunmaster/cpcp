#include "repository/config.hpp"

#include "domain/strict_json.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>

namespace {

using cpcp::crypto::SecretBytes;
using cpcp::repository::ConfigOptions;
using cpcp::repository::RepositoryConfig;

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

SecretBytes password(const std::string& text) {
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return SecretBytes::copy(bytes).value();
}

ConfigOptions options() {
    ConfigOptions result;
    result.kdf = {8192, 1};
    result.chunk_size = 1024 * 1024;
    return result;
}

cpcp::domain::Bytes to_bytes(const std::string& text) {
    const auto view = std::as_bytes(std::span(text));
    return cpcp::domain::Bytes(view.begin(), view.end());
}

TEST_CASE("configuration round trip unlocks with only the correct password") {
    const auto config = cpcp::repository::create_config(password("correct horse"), options()).value();
    const auto serialized = cpcp::repository::serialize_config(config).value();
    const cpcp::domain::Bytes bytes = to_bytes(serialized);
    const auto parsed = cpcp::repository::parse_config(bytes).value();

    REQUIRE(cpcp::repository::unlock_config(parsed, password("correct horse")));
    const auto wrong = cpcp::repository::unlock_config(parsed, password("wrong"));
    REQUIRE_FALSE(wrong);
    REQUIRE(wrong.error().code == cpcp::domain::ErrorCode::authentication);
}

TEST_CASE("configuration authentication rejects parameter tampering") {
    auto config = cpcp::repository::create_config(password("password"), options()).value();
    config.chunk_size += 1;

    const auto result = cpcp::repository::unlock_config(config, password("password"));

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::authentication);
}

TEST_CASE("one valid configuration replica provides degraded recovery") {
    TestDirectory directory("config-replica-test");
    const auto config = cpcp::repository::create_config(password("password"), options()).value();
    REQUIRE(cpcp::repository::write_new_config_replicas(directory.path(), config));
    REQUIRE(cpcp::repository::load_config(directory.path(), password("password")));

    {
        std::ofstream corrupted(directory.path() / "cpcp.config.json");
        corrupted << "not json";
    }
    auto degraded = cpcp::repository::load_config(directory.path(), password("password")).value();

    REQUIRE(degraded.degraded_redundancy);
}

TEST_CASE("exported header can restore both configuration replicas") {
    TestDirectory directory("config-header-test");
    const auto config = cpcp::repository::create_config(password("password"), options()).value();
    REQUIRE(cpcp::repository::write_new_config_replicas(directory.path(), config));
    std::filesystem::create_directory(directory.path() / "chunks");
    std::filesystem::create_directory(directory.path() / "snapshots");
    const auto header = directory.path() / "header.json";
    REQUIRE(cpcp::repository::export_config(config, header));
    REQUIRE(std::filesystem::remove(directory.path() / "cpcp.config.json"));
    REQUIRE(std::filesystem::remove(directory.path() / "cpcp.config.backup.json"));

    REQUIRE(cpcp::repository::import_config(header, directory.path(), password("password")));
    auto loaded = cpcp::repository::load_config(directory.path(), password("password")).value();

    REQUIRE_FALSE(loaded.degraded_redundancy);
    REQUIRE(loaded.config.repository_uuid == config.repository_uuid);
}

TEST_CASE("strict JSON rejects duplicate keys and excessive nesting") {
    const std::string duplicate = R"({"a":1,"a":2})";
    const cpcp::domain::Bytes duplicate_bytes = to_bytes(duplicate);
    REQUIRE_FALSE(cpcp::domain::parse_bounded_json(duplicate_bytes));

    std::string nested;
    for (int index = 0; index < 32; ++index) {
        nested += "[";
    }
    const cpcp::domain::Bytes nested_bytes = to_bytes(nested);
    REQUIRE_FALSE(cpcp::domain::parse_bounded_json(nested_bytes));

    const std::string valid = R"({"a":1,"b":[true,null]})";
    const cpcp::domain::Bytes valid_bytes = to_bytes(valid);
    REQUIRE(cpcp::domain::parse_bounded_json(valid_bytes));
}

}
