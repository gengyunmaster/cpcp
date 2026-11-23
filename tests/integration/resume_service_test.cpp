#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/repository_service.hpp"
#include "repository/journal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

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

void initialize(const std::filesystem::path& repository) {
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, password(), config));
}

void write_pattern(const std::filesystem::path& path, std::size_t size) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    std::vector<char> block(1024 * 1024);
    for (std::size_t offset = 0; offset < size; offset += block.size()) {
        const auto block_number = offset / block.size();
        for (std::size_t index = 0; index < block.size(); ++index) {
            block[index] = static_cast<char>((index + block_number) % 251);
        }
        const auto count = std::min(block.size(), size - offset);
        output.write(block.data(), static_cast<std::streamsize>(count));
    }
}

TEST_CASE("resume continues from an authenticated chunk checkpoint") {
    TestDirectory fixture("resume-checkpoint");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    initialize(repository);
    write_pattern(source / "large.bin", 80 * 1024 * 1024);

    cpcp::application::BackupOptions interrupted_options;
    interrupted_options.interrupt_after_chunks_for_testing = 70;
    const auto interrupted = cpcp::application::backup_add(
        repository,
        password(),
        {source},
        interrupted_options
    );
    REQUIRE_FALSE(interrupted);
    REQUIRE(interrupted.error().code == cpcp::domain::ErrorCode::cancellation);

    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    REQUIRE(sessions[0].state == "active");
    REQUIRE(sessions[0].roots.size() == 1);
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().empty());

    const auto resumed = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        {}
    ).value();
    REQUIRE(resumed.resumed);
    REQUIRE(resumed.snapshot.stats.chunk_references == 80);
    REQUIRE(resumed.snapshot.stats.new_chunks == 74);
    REQUIRE(resumed.snapshot.stats.deduplicated_chunks == 6);
    REQUIRE(resumed.snapshot.stats.files == 1);
    REQUIRE(cpcp::application::verify_repository(
        repository,
        password(),
        cpcp::application::VerifyOptions{true, false}
    ));
    REQUIRE(cpcp::application::backup_status(repository, password()).value().empty());

    cpcp::application::RestoreOptions restore;
    restore.destination = fixture.path() / "restored";
    REQUIRE(cpcp::application::restore_snapshot(
        repository,
        password(),
        resumed.snapshot.context.generation,
        restore
    ));
    REQUIRE(std::filesystem::file_size(restore.destination / "source" / "large.bin") == 80 * 1024 * 1024);
}

TEST_CASE("resume finalizes an existing main snapshot without duplication") {
    TestDirectory fixture("resume-main-publication");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    initialize(repository);
    write_pattern(source / "file.bin", 2 * 1024 * 1024);

    cpcp::application::BackupOptions options;
    options.interrupt_after_main_for_testing = true;
    const auto interrupted = cpcp::application::backup_add(repository, password(), {source}, options);
    REQUIRE_FALSE(interrupted);
    REQUIRE(interrupted.error().code == cpcp::domain::ErrorCode::cancellation);
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().empty());
    std::size_t main_objects = 0;
    for (const auto& entry : std::filesystem::directory_iterator(repository / "snapshots")) {
        if (entry.path().extension() == ".snap") {
            ++main_objects;
        }
    }
    REQUIRE(main_objects == 1);

    const auto completed = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        {}
    ).value();
    REQUIRE(completed.snapshot.context.generation == 1);
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().size() == 1);
    REQUIRE(cpcp::application::backup_status(repository, password()).value().empty());
    REQUIRE(cpcp::application::verify_repository(repository, password(), {}));
}

TEST_CASE("resume repairs a torn tail and restart-files rereads changed sources") {
    TestDirectory fixture("resume-restart-files");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    initialize(repository);
    write_pattern(source / "file.bin", 2 * 1024 * 1024);
    cpcp::application::BackupOptions options;
    options.interrupt_after_chunks_for_testing = 1;
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {source}, options));
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    {
        std::ofstream journal(
            cpcp::repository::journal_path(repository, sessions[0].session_uuid),
            std::ios::binary | std::ios::app
        );
        journal << "torn";
    }
    write_pattern(source / "file.bin", 2 * 1024 * 1024);
    const auto changed = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        {}
    );
    REQUIRE_FALSE(changed);
    REQUIRE(changed.error().code == cpcp::domain::ErrorCode::source_changed);

    cpcp::application::ResumeOptions resume;
    resume.restart_files = true;
    const auto completed = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        resume
    ).value();
    REQUIRE(completed.snapshot.stats.files == 1);
    REQUIRE(cpcp::application::verify_repository(repository, password(), {}));
}

TEST_CASE("resume remaps roots explicitly and discard removes only session state") {
    TestDirectory fixture("resume-remap");
    const auto repository = fixture.path() / "repo";
    const auto source = fixture.path() / "source";
    initialize(repository);
    write_pattern(source / "large.bin", 80 * 1024 * 1024);

    cpcp::application::BackupOptions interrupted_options;
    interrupted_options.interrupt_after_chunks_for_testing = 70;
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {source}, interrupted_options));
    const auto sessions = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(sessions.size() == 1);
    const auto relocated = fixture.path() / "relocated";
    std::filesystem::rename(source, relocated);

    REQUIRE_FALSE(cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        {}
    ));
    cpcp::application::ResumeOptions resume;
    resume.remap_roots.emplace(cpcp::domain::hex_encode(sessions[0].roots[0].uuid), relocated);
    const auto completed = cpcp::application::backup_resume(
        repository,
        password(),
        sessions[0].session_uuid,
        resume
    ).value();
    REQUIRE(completed.snapshot.stats.files == 1);

    cpcp::application::BackupOptions second_interruption;
    second_interruption.interrupt_after_chunks_for_testing = 70;
    const auto other_source = fixture.path() / "other-source";
    write_pattern(other_source / "large.bin", 80 * 1024 * 1024);
    REQUIRE_FALSE(cpcp::application::backup_add(repository, password(), {other_source}, second_interruption));
    const auto active = cpcp::application::backup_status(repository, password()).value();
    REQUIRE(active.size() == 1);
    REQUIRE_FALSE(cpcp::application::backup_discard(
        repository,
        password(),
        active[0].session_uuid,
        false
    ));
    REQUIRE(cpcp::application::backup_discard(repository, password(), active[0].session_uuid, true));
    REQUIRE(cpcp::application::backup_status(repository, password()).value().empty());
    const auto unlocked = cpcp::repository::load_config(repository, password()).value();
    REQUIRE(cpcp::repository::list_snapshots(repository, unlocked.config, unlocked.master_key).value().size() == 1);
}

}
