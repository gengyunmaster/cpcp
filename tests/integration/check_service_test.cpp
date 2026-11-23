#include "application/backup_service.hpp"
#include "application/check_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

using cpcp::application::CheckEvent;
using cpcp::application::CheckOptions;
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

void write_file(const std::filesystem::path& path, const std::string& contents) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << contents;
}

std::vector<std::string> repository_state(const std::filesystem::path& repository) {
    std::vector<std::string> state;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(repository)) {
        const auto relative = std::filesystem::relative(entry.path(), repository).generic_string();
        const auto size = entry.is_regular_file() ? entry.file_size() : 0;
        const auto modified = entry.last_write_time().time_since_epoch().count();
        state.push_back(relative + ":" + std::to_string(size) + ":" + std::to_string(modified));
    }
    std::ranges::sort(state);
    return state;
}

std::pair<std::map<std::string, std::string>, cpcp::application::CheckReport> check(
    const std::filesystem::path& repository,
    const CheckOptions& options
) {
    std::map<std::string, std::string> events;
    const auto report = cpcp::application::check_backup(
        repository,
        password(),
        options,
        [&](const CheckEvent& event) -> cpcp::domain::Result<void> {
            events[event.path] = event.status;
            return {};
        }
    ).value();
    return {events, report};
}

TEST_CASE("backup check reports recursive differences and assurance levels") {
    TestDirectory fixture("backup-check");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    write_file(source / "same.txt", "same");
    write_file(source / "changed.txt", "before");
    write_file(source / "missing.txt", "gone");
    write_file(source / "type.txt", "file");
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
    const auto snapshot = cpcp::application::backup_add(
        repository,
        password(),
        {source},
        {}
    ).value().snapshot;

    write_file(source / "changed.txt", "after");
    std::filesystem::remove(source / "missing.txt");
    std::filesystem::remove(source / "type.txt");
    std::filesystem::create_directory(source / "type.txt");
    write_file(source / "added.txt", "new");

    CheckOptions options;
    options.source = source;
    const auto [events, report] = check(repository, options);
    REQUIRE(events.at("same.txt") == "metadata-match");
    REQUIRE(events.at("changed.txt") == "changed");
    REQUIRE(events.at("missing.txt") == "missing");
    REQUIRE(events.at("type.txt") == "type-changed");
    REQUIRE(events.at("added.txt") == "added");
    REQUIRE(report.mode == "metadata");
    REQUIRE(report.total == 5);
    REQUIRE(report.differences == 4);

    options.path = "same.txt";
    const auto [narrow_events, narrow_report] = check(repository, options);
    REQUIRE(narrow_events.size() == 1);
    REQUIRE(narrow_events.at("same.txt") == "metadata-match");
    REQUIRE(narrow_report.differences == 0);

    cpcp::application::RestoreOptions restore;
    restore.destination = fixture.path() / "restored";
    REQUIRE(cpcp::application::restore_snapshot(
        repository,
        password(),
        snapshot.context.generation,
        restore
    ));

    CheckOptions relocated;
    relocated.source = restore.destination / "source";
    relocated.root = 0;
    relocated.content = true;
    const auto [content_events, content_report] = check(repository, relocated);
    REQUIRE(content_events.size() == 4);
    for (const auto& [path, status] : content_events) {
        REQUIRE(status == "content-match");
    }
    REQUIRE(content_report.mode == "content");
    REQUIRE(content_report.differences == 0);

    relocated.verify_repo = true;
    const auto [verified_events, verified_report] = check(repository, relocated);
    REQUIRE(verified_events.size() == 4);
    for (const auto& [path, status] : verified_events) {
        REQUIRE(status == "verified");
    }
    REQUIRE(verified_report.mode == "content+repository");
    REQUIRE(verified_report.repository_chunk_references == 4);

    relocated.repo_read_only = true;
    const auto before_read_only = repository_state(repository);
    const auto [read_only_events, read_only_report] = check(repository, relocated);
    REQUIRE(read_only_events.size() == 4);
    REQUIRE(read_only_report.differences == 0);
    REQUIRE(repository_state(repository) == before_read_only);
    relocated.repo_read_only = false;

    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    auto reader = cpcp::repository::SnapshotReader::open(
        repository,
        unlocked.config,
        unlocked.master_key,
        snapshot
    ).value();
    cpcp::crypto::Digest damaged_id{};
    while (true) {
        const auto record = reader.next().value();
        if (record->type == cpcp::crypto::RecordType::chunk_batch) {
            damaged_id = cpcp::repository::parse_chunk_batch(*record).value().chunks.front().chunk_id;
            break;
        }
    }
    const auto hex = cpcp::crypto::to_hex(damaged_id);
    const auto damaged_path = repository / "chunks" / hex.substr(0, 2) / hex.substr(2, 2) / hex;
    std::fstream stream(damaged_path, std::ios::in | std::ios::out | std::ios::binary);
    stream.seekp(-1, std::ios::end);
    char value = 0;
    stream.read(&value, 1);
    value ^= 1;
    stream.seekp(-1, std::ios::end);
    stream.write(&value, 1);
    stream.close();

    std::size_t callbacks = 0;
    const auto damaged = cpcp::application::check_backup(
        repository,
        password(),
        relocated,
        [&](const CheckEvent&) -> cpcp::domain::Result<void> {
            ++callbacks;
            return {};
        }
    );
    REQUIRE_FALSE(damaged);
    REQUIRE(damaged.error().code == cpcp::domain::ErrorCode::integrity);
    REQUIRE(callbacks == 0);
}

}
