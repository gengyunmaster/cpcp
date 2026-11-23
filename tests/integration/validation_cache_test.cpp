#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"
#include "repository/chunk_store.hpp"
#include "repository/validation_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
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

struct Fixture {
    std::filesystem::path root;
    std::filesystem::path repository;
    cpcp::repository::SnapshotSummary snapshot;
    cpcp::crypto::ChunkDescriptor descriptor;

    Fixture() : root(std::filesystem::path(CPCP_TEST_TEMP_DIR) / "validation-cache-test") {
        std::filesystem::remove_all(root);
        const auto source = root / "source";
        std::filesystem::create_directories(source);
        {
            std::ofstream output(source / "a.txt", std::ios::binary);
            output << "hello";
        }
        repository = root / "repo";
        cpcp::repository::ConfigOptions config;
        config.kdf = {8192, 1};
        config.chunk_size = 1024 * 1024;
        cpcp::application::initialize_repository(repository, password(), config).value();
        snapshot = cpcp::application::backup_add(repository, password(), {source}, {}).value().snapshot;
        const auto unlocked = cpcp::repository::load_config(repository, password()).value();
        auto reader = cpcp::repository::SnapshotReader::open(repository, unlocked.config, unlocked.master_key, snapshot).value();
        while (true) {
            const auto record = reader.next().value();
            if (!record.has_value()) {
                break;
            }
            if (record->type == cpcp::crypto::RecordType::chunk_batch) {
                descriptor = cpcp::repository::parse_chunk_batch(*record).value().chunks.front();
                break;
            }
        }
    }

    ~Fixture() {
        std::filesystem::remove_all(root);
    }

    std::filesystem::path chunk_path() const {
        const auto hex = cpcp::crypto::to_hex(descriptor.chunk_id);
        return repository / "chunks" / hex.substr(0, 2) / hex.substr(2, 2) / hex;
    }

    void flip_chunk() const {
        std::fstream stream(chunk_path(), std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-1, std::ios::end);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(-1, std::ios::end);
        stream.write(&value, 1);
    }
};

TEST_CASE("authenticated validation caches provide disposable historical evidence") {
    Fixture fixture;
    cpcp::application::VerifyOptions verify;
    verify.deep = true;
    verify.refresh_validation_cache = true;
    const auto refreshed = cpcp::application::verify_repository(fixture.repository, password(), verify).value();
    REQUIRE(refreshed.cache_updated);
    REQUIRE(refreshed.cache_error.empty());
    const auto unlocked = cpcp::repository::load_config(fixture.repository, password()).value();
    const auto cache_path = cpcp::repository::validation_cache_path(fixture.repository, unlocked.config.storage_epoch);
    REQUIRE(std::filesystem::exists(cache_path));

    fixture.flip_chunk();
    auto store = cpcp::repository::ChunkStore::create(fixture.repository, unlocked.config, unlocked.master_key).value();
    REQUIRE(store.reuse(fixture.descriptor));
    REQUIRE(store.validated_objects().empty());
    store.set_revalidate_all(true);
    REQUIRE_FALSE(store.reuse(fixture.descriptor));

    std::filesystem::remove(cache_path);
    store = cpcp::repository::ChunkStore::create(fixture.repository, unlocked.config, unlocked.master_key).value();
    REQUIRE_FALSE(store.reuse(fixture.descriptor));

    verify.refresh_validation_cache = false;
    REQUIRE_FALSE(cpcp::application::verify_repository(fixture.repository, password(), verify));
    verify.refresh_validation_cache = true;
    verify.deep = false;
    REQUIRE_FALSE(cpcp::application::verify_repository(fixture.repository, password(), verify));
}

TEST_CASE("invalid cache authentication and epochs are never accepted") {
    Fixture fixture;
    cpcp::application::VerifyOptions verify;
    verify.deep = true;
    verify.refresh_validation_cache = true;
    REQUIRE(cpcp::application::verify_repository(fixture.repository, password(), verify));
    const auto unlocked = cpcp::repository::load_config(fixture.repository, password()).value();
    const auto cache_path = cpcp::repository::validation_cache_path(fixture.repository, unlocked.config.storage_epoch);
    std::ifstream cache_input(cache_path, std::ios::binary);
    const auto original = std::vector<char>(
        std::istreambuf_iterator<char>(cache_input),
        std::istreambuf_iterator<char>()
    );
    cache_input.close();
    fixture.flip_chunk();

    {
        std::fstream stream(cache_path, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(48 + 52);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(48 + 52);
        stream.write(&value, 1);
    }
    auto store = cpcp::repository::ChunkStore::create(fixture.repository, unlocked.config, unlocked.master_key).value();
    REQUIRE_FALSE(store.reuse(fixture.descriptor));

    {
        std::ofstream output(cache_path, std::ios::binary | std::ios::trunc);
        output.write(original.data(), static_cast<std::streamsize>(original.size()));
    }
    {
        std::fstream stream(cache_path, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(24);
        char value = 0;
        stream.read(&value, 1);
        value ^= 1;
        stream.seekp(24);
        stream.write(&value, 1);
    }
    store = cpcp::repository::ChunkStore::create(fixture.repository, unlocked.config, unlocked.master_key).value();
    REQUIRE_FALSE(store.reuse(fixture.descriptor));
}

}
