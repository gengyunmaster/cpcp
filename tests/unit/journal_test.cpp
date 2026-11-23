#include "repository/journal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

using cpcp::crypto::SecretBytes;
using cpcp::repository::JournalRecordType;
using cpcp::repository::SessionJournal;

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
    TestDirectory directory;
    cpcp::repository::RepositoryConfig config;
    cpcp::crypto::SecureKey master;
    cpcp::domain::Uuid session;

    explicit Fixture(const std::string& name)
        : directory(name),
          config(make_config()),
          master(cpcp::repository::unlock_config(config, password()).value()),
          session(cpcp::crypto::random_uuid()) {
    }

    static cpcp::repository::RepositoryConfig make_config() {
        cpcp::repository::ConfigOptions options;
        options.kdf = {8192, 1};
        options.chunk_size = 1024 * 1024;
        return cpcp::repository::create_config(password(), options).value();
    }

    std::filesystem::path repository() const {
        return directory.path();
    }
};

std::string read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>()
    );
}

void flip_byte(const std::filesystem::path& path, std::uint64_t offset) {
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    stream.seekg(static_cast<std::streamoff>(offset));
    char value = 0;
    stream.read(&value, 1);
    value ^= 1;
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(&value, 1);
}

TEST_CASE("encrypted journals checkpoint chained records without plaintext paths") {
    Fixture fixture("journal-roundtrip");
    auto journal = SessionJournal::create(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    const auto first = journal.append(
        JournalRecordType::session,
        {{"path", "/private/source/secret.txt"}},
        true
    ).value();
    REQUIRE(journal.append(JournalRecordType::directory, {{"path", "sub"}}, true));
    REQUIRE(journal.append(JournalRecordType::file_begin, {{"path", "secret.txt"}}));
    REQUIRE(journal.next_sequence() == 3);
    REQUIRE(journal.close());

    const auto bytes = read_bytes(journal.path());
    REQUIRE(bytes.find("secret.txt") == std::string::npos);
    REQUIRE(bytes.find("/private/source") == std::string::npos);

    std::vector<std::uint64_t> sequences;
    const auto replayed = journal.replay([&](const cpcp::repository::JournalRecord& record) -> cpcp::domain::Result<void> {
        sequences.push_back(record.sequence);
        return {};
    }).value();
    REQUIRE_FALSE(replayed);
    REQUIRE(sequences == std::vector<std::uint64_t>{0, 1, 2});

    auto reopened = SessionJournal::open(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    REQUIRE(reopened.next_sequence() == 3);
    const auto third = reopened.append(JournalRecordType::file_complete, {{"file_id", "abcd"}}, true).value();
    REQUIRE(third.sequence == 3);
    REQUIRE(third.chain != first.chain);
    REQUIRE(reopened.close());
}

TEST_CASE("journal recovery discards only a torn or unauthenticated tail") {
    Fixture fixture("journal-tail-recovery");
    auto journal = SessionJournal::create(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    REQUIRE(journal.append(JournalRecordType::session, {{"root", 0}}, true));
    REQUIRE(journal.append(JournalRecordType::directory, {{"path", "sub"}}, true));
    REQUIRE(journal.close());
    const auto valid_size = std::filesystem::file_size(journal.path());

    {
        std::ofstream output(journal.path(), std::ios::binary | std::ios::app);
        output << "torn-tail";
    }
    auto recovered = SessionJournal::open(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    REQUIRE(recovered.next_sequence() == 2);
    REQUIRE(std::filesystem::file_size(journal.path()) == valid_size);
    REQUIRE(recovered.append(JournalRecordType::file_begin, {{"path", "a"}}, true));
    REQUIRE(recovered.close());
    const auto completed_size = std::filesystem::file_size(journal.path());

    flip_byte(journal.path(), completed_size - 1);
    recovered = SessionJournal::open(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    REQUIRE(recovered.next_sequence() == 2);
    REQUIRE(std::filesystem::file_size(journal.path()) == valid_size);
    REQUIRE(recovered.append(JournalRecordType::file_begin, {{"path", "replacement"}}, true));
    REQUIRE(recovered.close());
    REQUIRE_FALSE(recovered.replay([](const cpcp::repository::JournalRecord&) -> cpcp::domain::Result<void> {
        return {};
    }).value());
}

TEST_CASE("journal corruption before the final record is an integrity error") {
    Fixture fixture("journal-mid-corruption");
    auto journal = SessionJournal::create(
        fixture.repository(),
        fixture.config,
        fixture.master,
        fixture.session
    ).value();
    REQUIRE(journal.append(JournalRecordType::session, {{"root", 0}}, true));
    REQUIRE(journal.append(JournalRecordType::directory, {{"path", "later"}}, true));
    REQUIRE(journal.close());

    flip_byte(journal.path(), 38 + 17 + 24);

    const auto key = cpcp::crypto::derive_key(
        fixture.master,
        cpcp::crypto::KeyPurpose::journal_encryption
    ).value();
    auto reader = cpcp::repository::JournalReader::open(
        journal.path(),
        fixture.config.repository_uuid,
        fixture.session,
        key
    ).value();
    const auto corrupted = reader.next();
    REQUIRE_FALSE(corrupted);
    REQUIRE(corrupted.error().code == cpcp::domain::ErrorCode::integrity);
    REQUIRE_FALSE(reader.torn_tail());

    REQUIRE_FALSE(SessionJournal::open(
        fixture.repository(),
        fixture.config,
        fixture.master,
        cpcp::crypto::random_uuid()
    ));
}

}
