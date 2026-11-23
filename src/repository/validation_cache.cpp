#include "repository/validation_cache.hpp"

#include "domain/encoding.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <limits>
#include <system_error>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;

namespace {

constexpr std::size_t header_size = 48;
constexpr std::size_t record_size = 84;

void append_domain(Bytes& output, std::string_view domain) {
    for (const char value : domain) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
}

Bytes entry_context(
    const domain::Uuid& repository_uuid,
    const domain::Uuid& storage_epoch,
    const ValidatedObject& entry,
    std::int64_t verified_at
) {
    Bytes context;
    append_domain(context, "cpcp.validation-entry.v1");
    context.insert(context.end(), repository_uuid.begin(), repository_uuid.end());
    context.insert(context.end(), storage_epoch.begin(), storage_epoch.end());
    context.insert(context.end(), entry.id.begin(), entry.id.end());
    domain::append_le(context, entry.stored_length, 8);
    domain::append_le(context, entry.format_version, 4);
    domain::append_le(context, std::bit_cast<std::uint64_t>(verified_at), 8);
    return context;
}

crypto::Digest entry_tag(const crypto::SecureKey& key, const Bytes& context) {
    crypto::Digest tag{};
    crypto_auth_hmacsha256(
        reinterpret_cast<unsigned char*>(tag.data()),
        reinterpret_cast<const unsigned char*>(context.data()),
        context.size(),
        reinterpret_cast<const unsigned char*>(key.bytes().data())
    );
    return tag;
}

Bytes encode_entry(
    const ValidatedObject& entry,
    std::int64_t verified_at,
    const crypto::Digest& tag
) {
    Bytes record;
    record.reserve(record_size);
    record.insert(record.end(), entry.id.begin(), entry.id.end());
    domain::append_le(record, entry.stored_length, 8);
    domain::append_le(record, entry.format_version, 4);
    domain::append_le(record, std::bit_cast<std::uint64_t>(verified_at), 8);
    record.insert(record.end(), tag.begin(), tag.end());
    return record;
}

}

domain::Result<std::optional<ValidationCache>> ValidationCache::open(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key
) {
    const auto path = validation_cache_path(repository, config.storage_epoch);
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        return std::optional<ValidationCache>{};
    }
    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::optional<ValidationCache>{};
    }
    const auto metadata = file->metadata();
    if (!metadata || metadata->size < header_size) {
        return std::optional<ValidationCache>{};
    }
    std::array<std::byte, header_size> header{};
    const auto read = file->read_exact(header);
    if (!read) {
        return std::optional<ValidationCache>{};
    }
    const Bytes expected{
        std::byte{'C'}, std::byte{'P'}, std::byte{'C'}, std::byte{'V'},
        std::byte{1}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    if (!std::ranges::equal(std::span(header).first<8>(), expected)
        || !std::ranges::equal(std::span(header).subspan<8, 16>(), config.repository_uuid)
        || !std::ranges::equal(std::span(header).subspan<24, 16>(), config.storage_epoch)) {
        return std::optional<ValidationCache>{};
    }
    const auto count = domain::read_le(std::span(header).subspan(40, 8), 8).value();
    if (count > (std::numeric_limits<std::uint64_t>::max() - header_size) / record_size
        || metadata->size != header_size + count * record_size) {
        return std::optional<ValidationCache>{};
    }
    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::cache_authentication);
    if (!key) {
        return std::unexpected(key.error());
    }
    return ValidationCache(
        std::move(file).value(),
        config.repository_uuid,
        config.storage_epoch,
        std::move(key).value(),
        count
    );
}

ValidationCache::ValidationCache(
    platform::BinaryFile file,
    domain::Uuid repository_uuid,
    domain::Uuid storage_epoch,
    crypto::SecureKey cache_key,
    std::uint64_t entries
) : file_(std::move(file)),
    repository_uuid_(repository_uuid),
    storage_epoch_(storage_epoch),
    cache_key_(std::move(cache_key)),
    entries_(entries) {
}

ValidationCache::ValidationCache(ValidationCache&&) noexcept = default;
ValidationCache& ValidationCache::operator=(ValidationCache&&) noexcept = default;
ValidationCache::~ValidationCache() = default;

bool ValidationCache::contains(
    const crypto::Digest& id,
    std::uint64_t stored_length,
    std::uint32_t format_version
) {
    if (!file_) {
        return false;
    }
    const auto read_at = [&](std::uint64_t index, std::array<std::byte, record_size>& record) {
        if (!file_->seek(header_size + index * record_size)) {
            return false;
        }
        return file_->read_exact(record).has_value();
    };
    std::uint64_t low = 0;
    std::uint64_t high = entries_;
    while (low < high) {
        const auto middle = low + (high - low) / 2;
        std::array<std::byte, record_size> record{};
        if (!read_at(middle, record)) {
            return false;
        }
        if (std::lexicographical_compare(record.begin(), record.begin() + 32, id.begin(), id.end())) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low == entries_) {
        return false;
    }
    std::array<std::byte, record_size> record{};
    if (!read_at(low, record)) {
        return false;
    }
    if (!std::ranges::equal(std::span(record).first<32>(), id)) {
        return false;
    }
    const auto length = domain::read_le(std::span(record).subspan(32, 8), 8).value();
    const auto version = domain::read_le(std::span(record).subspan(40, 4), 4).value();
    const auto verified = std::bit_cast<std::int64_t>(
        domain::read_le(std::span(record).subspan(44, 8), 8).value()
    );
    if (length != stored_length || version != format_version) {
        return false;
    }
    const ValidatedObject entry{id, stored_length, format_version};
    const auto expected = entry_tag(cache_key_, entry_context(repository_uuid_, storage_epoch_, entry, verified));
    return std::ranges::equal(std::span(record).subspan<52, 32>(), expected);
}

domain::Result<void> ValidationCache::write(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key,
    std::vector<ValidatedObject> entries
) {
    std::ranges::sort(entries, [](const ValidatedObject& left, const ValidatedObject& right) {
        return left.id < right.id;
    });
    const auto adjacent = std::ranges::adjacent_find(entries, [](const ValidatedObject& left, const ValidatedObject& right) {
        return left.id == right.id;
    });
    if (adjacent != entries.end()) {
        return std::unexpected(Error{ErrorCode::integrity, "duplicate validation-cache object"});
    }
    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::cache_authentication);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto final = validation_cache_path(repository, config.storage_epoch);
    std::error_code error;
    std::filesystem::create_directories(final.parent_path(), error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    const auto temporary = repository / "tmp" / ("validation-" + domain::hex_encode(config.storage_epoch) + ".part");
    std::filesystem::remove(temporary, error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    auto file = platform::BinaryFile::create_new(temporary);
    if (!file) {
        return std::unexpected(file.error());
    }
    Bytes header{
        std::byte{'C'}, std::byte{'P'}, std::byte{'C'}, std::byte{'V'},
        std::byte{1}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    header.insert(header.end(), config.repository_uuid.begin(), config.repository_uuid.end());
    header.insert(header.end(), config.storage_epoch.begin(), config.storage_epoch.end());
    domain::append_le(header, entries.size(), 8);
    auto result = file->write_all(header);
    if (!result) {
        return result;
    }
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto verified = std::chrono::floor<std::chrono::seconds>(now).count();
    for (const auto& entry : entries) {
        const auto context = entry_context(config.repository_uuid, config.storage_epoch, entry, verified);
        const auto tag = entry_tag(*key, context);
        result = file->write_all(encode_entry(entry, verified, tag));
        if (!result) {
            return result;
        }
    }
    result = file->flush();
    if (!result) {
        return result;
    }
    result = file->close();
    if (!result) {
        return result;
    }
    const auto replaced = platform::replace_file(temporary, final);
    if (!replaced) {
        return replaced;
    }
    const auto synced = platform::sync_directory(final.parent_path());
    if (!synced) {
        return synced;
    }
    auto cache = open(repository, config, master_key);
    if (!cache || !*cache) {
        return std::unexpected(Error{ErrorCode::integrity, "validation-cache read-back failed"});
    }
    for (const auto& entry : entries) {
        if (!(*cache)->contains(entry.id, entry.stored_length, entry.format_version)) {
            return std::unexpected(Error{ErrorCode::integrity, "validation-cache entry verification failed"});
        }
    }
    return {};
}

std::filesystem::path validation_cache_path(
    const std::filesystem::path& repository,
    const domain::Uuid& storage_epoch
) {
    return repository / "cache" / ("validation-" + domain::hex_encode(storage_epoch) + ".cache");
}

}
