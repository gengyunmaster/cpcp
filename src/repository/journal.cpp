#include "repository/journal.hpp"

#include "crypto/keys.hpp"
#include "domain/strict_json.hpp"

#include <sodium.h>

#include <array>
#include <charconv>
#include <system_error>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;
using nlohmann::json;

namespace {

constexpr std::size_t file_header_size = 38;
constexpr std::size_t record_header_size = 17;
constexpr std::size_t plaintext_record_limit = 1024 * 1024;
constexpr std::uint64_t record_auth_overhead = 16;

void append_domain(Bytes& output, std::string_view value) {
    for (const char byte : value) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
    }
}

Bytes record_aad(
    const domain::Uuid& repository_uuid,
    const domain::Uuid& session_uuid,
    std::uint64_t sequence,
    JournalRecordType type,
    const crypto::Digest& previous_chain
) {
    Bytes aad;
    append_domain(aad, "cpcp.journal.record.v1");
    aad.insert(aad.end(), repository_uuid.begin(), repository_uuid.end());
    aad.insert(aad.end(), session_uuid.begin(), session_uuid.end());
    domain::append_le(aad, sequence, 8);
    aad.push_back(static_cast<std::byte>(type));
    aad.insert(aad.end(), previous_chain.begin(), previous_chain.end());
    return aad;
}

std::uint32_t crc32(std::span<const std::byte> header, const crypto::SealedObject& object) {
    std::uint32_t crc = 0xffffffffU;
    const auto update = [&](std::span<const std::byte> bytes) {
        for (const auto byte : bytes) {
            crc ^= static_cast<std::uint32_t>(std::to_integer<unsigned int>(byte));
            for (unsigned int bit = 0; bit < 8; ++bit) {
                const std::uint32_t mask = 0U - (crc & 1U);
                crc = (crc >> 1U) ^ (0xedb88320U & mask);
            }
        }
    };
    update(header);
    update(object.nonce);
    update(object.ciphertext);
    return crc ^ 0xffffffffU;
}

domain::Result<crypto::Digest> chain_value(
    const crypto::SecureKey& key,
    const Bytes& aad,
    const crypto::SealedObject& object
) {
    crypto_auth_hmacsha256_state state{};
    if (crypto_auth_hmacsha256_init(
            &state,
            reinterpret_cast<const unsigned char*>(key.bytes().data()),
            key.bytes().size()
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "journal chain initialization failed"});
    }
    constexpr std::string_view domain = "cpcp.journal.chain.v1";
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(domain.data()),
        domain.size()
    );
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(aad.data()),
        aad.size()
    );
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(object.nonce.data()),
        object.nonce.size()
    );
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(object.ciphertext.data()),
        object.ciphertext.size()
    );
    crypto::Digest chain{};
    if (crypto_auth_hmacsha256_final(&state, reinterpret_cast<unsigned char*>(chain.data())) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "journal chain finalization failed"});
    }
    return chain;
}

domain::Result<std::uint64_t> sequence_number(const json& document) {
    if (!document.at("sequence").is_string()) {
        return std::unexpected(Error{ErrorCode::integrity, "journal sequence is not a string"});
    }
    const auto text = document.at("sequence").get<std::string>();
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid journal sequence"});
    }
    return value;
}

Bytes file_header(
    const domain::Uuid& repository_uuid,
    const domain::Uuid& session_uuid
) {
    Bytes header{
        std::byte{'C'}, std::byte{'P'}, std::byte{'J'}, std::byte{'R'},
        std::byte{1}, std::byte{0},
    };
    header.insert(header.end(), repository_uuid.begin(), repository_uuid.end());
    header.insert(header.end(), session_uuid.begin(), session_uuid.end());
    return header;
}

}

domain::Result<JournalReader> JournalReader::open(
    const std::filesystem::path& path,
    const domain::Uuid& repository_uuid,
    const domain::Uuid& session_uuid,
    const crypto::SecureKey& journal_key
) {
    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    const auto metadata = file->metadata();
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    if (metadata->size < file_header_size) {
        return std::unexpected(Error{ErrorCode::integrity, "journal header is truncated"});
    }
    auto key = crypto::SecureKey::from_bytes(journal_key.bytes());
    if (!key) {
        return std::unexpected(key.error());
    }
    JournalReader reader(
        std::move(file).value(),
        repository_uuid,
        session_uuid,
        std::move(key).value(),
        metadata->size
    );
    std::array<std::byte, file_header_size> header{};
    const auto read = reader.file_->read_exact(header);
    if (!read) {
        return std::unexpected(read.error());
    }
    const auto expected = file_header(repository_uuid, session_uuid);
    if (!std::ranges::equal(header, expected)) {
        return std::unexpected(Error{ErrorCode::integrity, "journal header context mismatch"});
    }
    reader.offset_ = file_header_size;
    reader.valid_bytes_ = file_header_size;
    return reader;
}

JournalReader::JournalReader(
    platform::BinaryFile file,
    domain::Uuid repository_uuid,
    domain::Uuid session_uuid,
    crypto::SecureKey journal_key,
    std::uint64_t stored_size
) : file_(std::move(file)),
    repository_uuid_(repository_uuid),
    session_uuid_(session_uuid),
    journal_key_(std::move(journal_key)),
    stored_size_(stored_size) {
}

JournalReader::JournalReader(JournalReader&&) noexcept = default;
JournalReader& JournalReader::operator=(JournalReader&&) noexcept = default;

domain::Result<std::optional<JournalRecord>> JournalReader::trailing_error(Error error) {
    if (offset_ == stored_size_) {
        done_ = true;
        torn_tail_ = true;
        return std::optional<JournalRecord>{};
    }
    error.code = ErrorCode::integrity;
    return std::unexpected(std::move(error));
}

domain::Result<std::optional<JournalRecord>> JournalReader::next() {
    if (done_) {
        return std::optional<JournalRecord>{};
    }
    if (offset_ == stored_size_) {
        done_ = true;
        return std::optional<JournalRecord>{};
    }
    if (stored_size_ - offset_ < record_header_size) {
        offset_ = stored_size_;
        return trailing_error(Error{ErrorCode::integrity, "torn journal record header"});
    }

    std::array<std::byte, record_header_size> header{};
    const auto header_read = file_->read_exact(header);
    if (!header_read) {
        offset_ = stored_size_;
        return trailing_error(header_read.error());
    }
    offset_ += record_header_size;
    const auto sequence = domain::read_le(std::span(header).first(8), 8).value();
    const auto type = static_cast<JournalRecordType>(std::to_integer<std::uint8_t>(header[8]));
    const auto ciphertext_length = domain::read_le(std::span(header).subspan(9, 4), 4).value();
    const auto expected_crc = static_cast<std::uint32_t>(
        domain::read_le(std::span(header).subspan(13, 4), 4).value()
    );
    if (ciphertext_length > stored_size_ - offset_
        || record_auth_overhead > stored_size_ - offset_ - ciphertext_length) {
        offset_ = stored_size_;
        return trailing_error(Error{ErrorCode::integrity, "torn journal record body"});
    }
    if (ciphertext_length < record_auth_overhead
        || ciphertext_length > plaintext_record_limit + record_auth_overhead) {
        return trailing_error(Error{ErrorCode::integrity, "journal record exceeds its bound"});
    }

    crypto::SealedObject object;
    auto result = file_->read_exact(object.nonce);
    if (!result) {
        offset_ = stored_size_;
        return trailing_error(result.error());
    }
    object.ciphertext.resize(ciphertext_length);
    result = file_->read_exact(object.ciphertext);
    if (!result) {
        offset_ = stored_size_;
        return trailing_error(result.error());
    }
    offset_ += object.nonce.size() + object.ciphertext.size();

    if (crc32(std::span(header).first(13), object) != expected_crc) {
        return trailing_error(Error{ErrorCode::integrity, "journal record checksum mismatch"});
    }
    if (sequence != expected_sequence_) {
        return trailing_error(Error{ErrorCode::integrity, "journal sequence mismatch"});
    }
    const auto aad = record_aad(repository_uuid_, session_uuid_, sequence, type, previous_chain_);
    auto plaintext = crypto::open_object(journal_key_, aad, object);
    if (!plaintext) {
        return trailing_error(plaintext.error());
    }
    const auto chain = chain_value(journal_key_, aad, object);
    if (!chain) {
        return std::unexpected(chain.error());
    }
    const auto document = domain::parse_bounded_json(*plaintext);
    if (!document) {
        return trailing_error(document.error());
    }
    try {
        if (document->at("schema").get<std::string>() != "cpcp.journal-record.v1"
            || document->at("session").get<std::string>() != domain::hex_encode(session_uuid_)
            || document->at("type").get<JournalRecordType>() != type
            || !document->contains("payload")) {
            return trailing_error(Error{ErrorCode::integrity, "journal record semantics mismatch"});
        }
        const auto inner_sequence = sequence_number(*document);
        if (!inner_sequence || *inner_sequence != sequence) {
            return trailing_error(Error{ErrorCode::integrity, "journal inner sequence mismatch"});
        }
        JournalRecord record{sequence, type, document->at("payload"), *chain};
        previous_chain_ = *chain;
        last_chain_ = *chain;
        last_sequence_ = sequence;
        ++expected_sequence_;
        ++records_;
        valid_bytes_ = offset_;
        return record;
    } catch (const std::exception& error) {
        return trailing_error(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<void> JournalReader::close() {
    if (!file_) {
        return {};
    }
    const auto result = file_->close();
    file_.reset();
    return result;
}

bool JournalReader::torn_tail() const {
    return torn_tail_;
}

std::uint64_t JournalReader::valid_bytes() const {
    return valid_bytes_;
}

std::uint64_t JournalReader::records() const {
    return records_;
}

std::uint64_t JournalReader::last_sequence() const {
    return last_sequence_;
}

const crypto::Digest& JournalReader::last_chain() const {
    return last_chain_;
}

domain::Result<SessionJournal> SessionJournal::create(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key,
    const domain::Uuid& session_uuid
) {
    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::journal_encryption);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto path = journal_path(repository, session_uuid);
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    const auto header = file_header(config.repository_uuid, session_uuid);
    auto result = file->write_all(header);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->flush();
    if (!result) {
        return std::unexpected(result.error());
    }
    const auto synced = platform::sync_directory(path.parent_path());
    if (!synced) {
        return std::unexpected(synced.error());
    }
    return SessionJournal(
        path,
        config.repository_uuid,
        session_uuid,
        std::move(key).value(),
        std::move(file).value(),
        0,
        {}
    );
}

domain::Result<SessionJournal> SessionJournal::open(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key,
    const domain::Uuid& session_uuid
) {
    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::journal_encryption);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto path = journal_path(repository, session_uuid);
    auto reader = JournalReader::open(path, config.repository_uuid, session_uuid, *key);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    while (true) {
        const auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
    }
    const auto closed = reader->close();
    if (!closed) {
        return std::unexpected(closed.error());
    }
    auto file = platform::BinaryFile::open_read_write(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    if (reader->torn_tail()) {
        const auto truncated = file->truncate(reader->valid_bytes());
        if (!truncated) {
            return std::unexpected(truncated.error());
        }
        const auto flushed = file->flush();
        if (!flushed) {
            return std::unexpected(flushed.error());
        }
    }
    const auto positioned = file->seek(reader->valid_bytes());
    if (!positioned) {
        return std::unexpected(positioned.error());
    }
    return SessionJournal(
        path,
        config.repository_uuid,
        session_uuid,
        std::move(key).value(),
        std::move(file).value(),
        reader->records(),
        reader->last_chain()
    );
}

SessionJournal::SessionJournal(
    std::filesystem::path path,
    domain::Uuid repository_uuid,
    domain::Uuid session_uuid,
    crypto::SecureKey journal_key,
    platform::BinaryFile file,
    std::uint64_t next_sequence,
    crypto::Digest previous_chain
) : path_(std::move(path)),
    repository_uuid_(repository_uuid),
    session_uuid_(session_uuid),
    journal_key_(std::move(journal_key)),
    file_(std::move(file)),
    next_sequence_(next_sequence),
    previous_chain_(previous_chain) {
}

domain::Result<JournalRecord> SessionJournal::append(
    JournalRecordType type,
    const nlohmann::json& payload,
    bool checkpoint
) {
    if (!file_) {
        return std::unexpected(Error{ErrorCode::usage, "journal is closed"});
    }
    const auto sequence = next_sequence_;
    const json document{
        {"schema", "cpcp.journal-record.v1"},
        {"session", domain::hex_encode(session_uuid_)},
        {"sequence", std::to_string(sequence)},
        {"type", type},
        {"payload", payload},
    };
    const auto text = document.dump();
    const auto view = std::as_bytes(std::span(text));
    const Bytes plaintext(view.begin(), view.end());
    if (plaintext.size() > plaintext_record_limit) {
        return std::unexpected(Error{ErrorCode::usage, "journal record exceeds its bound"});
    }
    const auto aad = record_aad(repository_uuid_, session_uuid_, sequence, type, previous_chain_);
    auto sealed = crypto::seal_object(journal_key_, aad, plaintext);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    const auto chain = chain_value(journal_key_, aad, *sealed);
    if (!chain) {
        return std::unexpected(chain.error());
    }

    Bytes header;
    domain::append_le(header, sequence, 8);
    header.push_back(static_cast<std::byte>(type));
    domain::append_le(header, sealed->ciphertext.size(), 4);
    const auto checksum = crc32(header, *sealed);
    domain::append_le(header, checksum, 4);

    auto result = file_->write_all(header);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file_->write_all(sealed->nonce);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file_->write_all(sealed->ciphertext);
    if (!result) {
        return std::unexpected(result.error());
    }
    if (checkpoint) {
        result = file_->flush();
        if (!result) {
            return std::unexpected(result.error());
        }
    }

    JournalRecord record{sequence, type, payload, *chain};
    previous_chain_ = *chain;
    ++next_sequence_;
    return record;
}

domain::Result<void> SessionJournal::flush() {
    if (!file_) {
        return std::unexpected(Error{ErrorCode::usage, "journal is closed"});
    }
    return file_->flush();
}

domain::Result<void> SessionJournal::close() {
    if (!file_) {
        return {};
    }
    const auto result = file_->close();
    file_.reset();
    return result;
}

domain::Result<bool> SessionJournal::replay(const RecordSink& sink) const {
    if (!sink) {
        return std::unexpected(Error{ErrorCode::usage, "a journal record consumer is required"});
    }
    auto reader = JournalReader::open(path_, repository_uuid_, session_uuid_, journal_key_);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    while (true) {
        const auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        const auto consumed = sink(**record);
        if (!consumed) {
            return std::unexpected(consumed.error());
        }
    }
    return reader->torn_tail();
}

const std::filesystem::path& SessionJournal::path() const {
    return path_;
}

std::uint64_t SessionJournal::next_sequence() const {
    return next_sequence_;
}

std::filesystem::path journal_path(
    const std::filesystem::path& repository,
    const domain::Uuid& session_uuid
) {
    return repository / "sessions" / (domain::hex_encode(session_uuid) + ".journal");
}

}
