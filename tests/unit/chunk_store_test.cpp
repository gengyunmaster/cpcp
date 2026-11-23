#include "repository/chunk_store.hpp"

#include "platform/lock.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::SecretBytes;
using cpcp::repository::ChunkMetadata;
using cpcp::repository::ChunkStore;
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

SecretBytes password() {
    const std::string text = "password";
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return SecretBytes::copy(bytes).value();
}

struct Fixture {
    std::shared_ptr<TestDirectory> owner;
    std::filesystem::path path;
    RepositoryConfig config;
    cpcp::crypto::SecureKey master;
};

Fixture fixture(const std::string& name) {
    auto owner = std::make_shared<TestDirectory>(name);
    cpcp::repository::ConfigOptions options;
    options.kdf = {8192, 1};
    options.chunk_size = 1024 * 1024;
    auto config = cpcp::repository::create_config(password(), options).value();
    auto master = cpcp::repository::unlock_config(config, password()).value();
    return {owner, owner->path(), std::move(config), std::move(master)};
}

std::vector<std::byte> payload() {
    const std::string text = "content addressed payload";
    std::vector<std::byte> result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

std::filesystem::path chunk_path(const Fixture& repo, const ChunkMetadata& chunk) {
    const auto hex = cpcp::crypto::to_hex(chunk.id);
    return repo.path / "chunks" / hex.substr(0, 2) / hex.substr(2, 2) / hex;
}

TEST_CASE("chunk writes deduplicate and decrypt correctly") {
    auto repo = fixture("chunk-roundtrip");
    auto store = ChunkStore::create(repo.path, repo.config, repo.master).value();
    const auto data = payload();

    const auto first = store.put(data).value();
    const auto second = store.put(data).value();

    REQUIRE_FALSE(first.already_present);
    REQUIRE(second.already_present);
    REQUIRE(store.get(first).value() == data);
    REQUIRE(std::filesystem::exists(chunk_path(repo, first)));
}

TEST_CASE("chunk tampering is detected without prior evidence") {
    auto repo = fixture("chunk-tamper");
    auto store = ChunkStore::create(repo.path, repo.config, repo.master).value();
    const auto chunk = store.put(payload()).value();
    const auto path = chunk_path(repo, chunk);
    {
        std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-1, std::ios::end);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(-1, std::ios::end);
        stream.write(&value, 1);
    }

    auto fresh = ChunkStore::create(repo.path, repo.config, repo.master).value();
    const auto result = fresh.put(payload());

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::integrity);
}

TEST_CASE("base evidence is explicit and full revalidation overrides it") {
    auto repo = fixture("chunk-evidence");
    auto store = ChunkStore::create(repo.path, repo.config, repo.master).value();
    const auto chunk = store.put(payload()).value();
    store.allow_base_evidence(chunk.id);
    {
        std::fstream stream(chunk_path(repo, chunk), std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-1, std::ios::end);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(-1, std::ios::end);
        stream.write(&value, 1);
    }

    auto accepted = store.put(payload());
    REQUIRE(accepted);

    auto strict = ChunkStore::create(repo.path, repo.config, repo.master).value();
    strict.set_revalidate_all(true);
    const auto rejected = strict.put(payload());
    REQUIRE_FALSE(rejected);
}

TEST_CASE("a missing object is recreated from source even with prior evidence") {
    auto repo = fixture("chunk-recreate");
    auto store = ChunkStore::create(repo.path, repo.config, repo.master).value();
    const auto original = store.put(payload()).value();
    store.allow_base_evidence(original.id);
    REQUIRE(std::filesystem::remove(chunk_path(repo, original)));
    auto resumed = ChunkStore::create(repo.path, repo.config, repo.master).value();
    resumed.allow_base_evidence(original.id);

    const auto recreated = resumed.put(payload()).value();

    REQUIRE_FALSE(recreated.already_present);
    REQUIRE(store.get(recreated).value() == payload());
}

TEST_CASE("repository locks exclude writers while allowing shared readers") {
    TestDirectory directory("repository-lock-test");
    const auto path = directory.path() / "lock";
    auto first = cpcp::platform::FileLock::acquire(path, cpcp::platform::LockMode::shared).value();
    auto second = cpcp::platform::FileLock::acquire(path, cpcp::platform::LockMode::shared).value();

    REQUIRE(first.locked());
    REQUIRE(second.locked());
    REQUIRE_FALSE(cpcp::platform::FileLock::acquire(path, cpcp::platform::LockMode::exclusive));
    REQUIRE(first.release());
    REQUIRE(second.release());
    REQUIRE(cpcp::platform::FileLock::acquire(path, cpcp::platform::LockMode::exclusive));
}

}
