#pragma once

#include "crypto/aead.hpp"
#include "platform/binary_file.hpp"
#include "repository/config.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace cpcp::repository {

enum class JournalRecordType : std::uint8_t {
    session = 1,
    directory = 2,
    file_begin = 3,
    chunks = 4,
    file_complete = 5,
    policy_skip = 6,
    failure = 7,
    restart_files = 8,
    remap_root = 9,
    main_published = 10,
    committed = 11,
};

struct JournalRecord {
    std::uint64_t sequence = 0;
    JournalRecordType type = JournalRecordType::session;
    nlohmann::json payload;
    crypto::Digest chain{};
};

class JournalReader {
public:
    static domain::Result<JournalReader> open(
        const std::filesystem::path& path,
        const domain::Uuid& repository_uuid,
        const domain::Uuid& session_uuid,
        const crypto::SecureKey& journal_key
    );

    JournalReader(const JournalReader&) = delete;
    JournalReader& operator=(const JournalReader&) = delete;
    JournalReader(JournalReader&&) noexcept;
    JournalReader& operator=(JournalReader&&) noexcept;

    domain::Result<std::optional<JournalRecord>> next();
    domain::Result<void> close();
    bool torn_tail() const;
    std::uint64_t valid_bytes() const;
    std::uint64_t records() const;
    std::uint64_t last_sequence() const;
    const crypto::Digest& last_chain() const;

private:
    JournalReader(
        platform::BinaryFile file,
        domain::Uuid repository_uuid,
        domain::Uuid session_uuid,
        crypto::SecureKey journal_key,
        std::uint64_t stored_size
    );

    domain::Result<std::optional<JournalRecord>> trailing_error(domain::Error error);

    std::optional<platform::BinaryFile> file_;
    domain::Uuid repository_uuid_{};
    domain::Uuid session_uuid_{};
    crypto::SecureKey journal_key_;
    std::uint64_t stored_size_ = 0;
    std::uint64_t offset_ = 0;
    std::uint64_t valid_bytes_ = 0;
    std::uint64_t records_ = 0;
    std::uint64_t expected_sequence_ = 0;
    std::uint64_t last_sequence_ = 0;
    crypto::Digest previous_chain_{};
    crypto::Digest last_chain_{};
    bool done_ = false;
    bool torn_tail_ = false;
};

class SessionJournal {
public:
    static domain::Result<SessionJournal> create(
        const std::filesystem::path& repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key,
        const domain::Uuid& session_uuid
    );
    static domain::Result<SessionJournal> open(
        const std::filesystem::path& repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key,
        const domain::Uuid& session_uuid
    );

    SessionJournal(const SessionJournal&) = delete;
    SessionJournal& operator=(const SessionJournal&) = delete;
    SessionJournal(SessionJournal&&) noexcept = default;
    SessionJournal& operator=(SessionJournal&&) noexcept = default;

    domain::Result<JournalRecord> append(
        JournalRecordType type,
        const nlohmann::json& payload,
        bool checkpoint = false
    );
    domain::Result<void> flush();
    domain::Result<void> close();

    using RecordSink = std::function<domain::Result<void>(const JournalRecord&)>;
    domain::Result<bool> replay(const RecordSink& sink) const;

    const std::filesystem::path& path() const;
    std::uint64_t next_sequence() const;

private:
    SessionJournal(
        std::filesystem::path path,
        domain::Uuid repository_uuid,
        domain::Uuid session_uuid,
        crypto::SecureKey journal_key,
        platform::BinaryFile file,
        std::uint64_t next_sequence,
        crypto::Digest previous_chain
    );

    std::filesystem::path path_;
    domain::Uuid repository_uuid_{};
    domain::Uuid session_uuid_{};
    crypto::SecureKey journal_key_;
    std::optional<platform::BinaryFile> file_;
    std::uint64_t next_sequence_ = 0;
    crypto::Digest previous_chain_{};
};

std::filesystem::path journal_path(
    const std::filesystem::path& repository,
    const domain::Uuid& session_uuid
);

}
