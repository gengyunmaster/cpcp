#include "repository/chunk_store.hpp"

#include "crypto/aead.hpp"
#include "crypto/password.hpp"
#include "domain/compression.hpp"
#include "platform/binary_file.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <system_error>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;

namespace {

struct TemporaryCleanup {
    std::filesystem::path path;
    ~TemporaryCleanup() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
};

void append_u64(domain::Bytes& output, std::uint64_t value, std::size_t width) {
    domain::append_le(output, value, width);
}

Bytes chunk_aad(
    const RepositoryConfig& config,
    const ChunkMetadata& chunk
) {
    Bytes aad;
    constexpr std::string_view domain = "cpcp.chunk.object.v1";
    for (const char value : domain) {
        aad.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    aad.insert(aad.end(), config.repository_uuid.begin(), config.repository_uuid.end());
    aad.insert(aad.end(), chunk.id.begin(), chunk.id.end());
    append_u64(aad, chunk.plaintext_length, 8);
    append_u64(aad, 0, 2);
    return aad;
}

Bytes chunk_aad_v2(
    const RepositoryConfig& config,
    const ChunkMetadata& chunk,
    std::uint64_t encoded_length
) {
    Bytes aad;
    constexpr std::string_view domain = "cpcp.chunk.object.v2";
    for (const char value : domain) {
        aad.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    aad.insert(aad.end(), config.repository_uuid.begin(), config.repository_uuid.end());
    aad.insert(aad.end(), chunk.id.begin(), chunk.id.end());
    append_u64(aad, chunk.plaintext_length, 8);
    append_u64(aad, chunk.content_encoding, 2);
    append_u64(aad, encoded_length, 8);
    return aad;
}

}

domain::Result<ChunkStore> ChunkStore::create(
    std::filesystem::path repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key
) {
    auto encryption_key = crypto::derive_key(master_key, crypto::KeyPurpose::chunk_encryption);
    if (!encryption_key) {
        return std::unexpected(encryption_key.error());
    }
    auto id_key = crypto::derive_key(master_key, crypto::KeyPurpose::content_id);
    if (!id_key) {
        return std::unexpected(id_key.error());
    }
    ChunkStore result(
        std::move(repository),
        config,
        std::move(encryption_key).value(),
        std::move(id_key).value()
    );
    auto cache = ValidationCache::open(result.repository_, config, master_key);
    if (cache && *cache) {
        result.validation_cache_.emplace(std::move(**cache));
    }
    return result;
}

ChunkStore::ChunkStore(
    std::filesystem::path repository,
    RepositoryConfig config,
    crypto::SecureKey encryption_key,
    crypto::SecureKey id_key
) : repository_(std::move(repository)),
    config_(std::move(config)),
    encryption_key_(std::move(encryption_key)),
    id_key_(std::move(id_key)) {
}

std::filesystem::path ChunkStore::chunk_path(const crypto::Digest& id) const {
    const auto hex = crypto::to_hex(id);
    return repository_ / "chunks" / hex.substr(0, 2) / hex.substr(2, 2) / hex;
}

void ChunkStore::allow_base_evidence(const crypto::Digest& chunk_id) {
    base_evidence_[crypto::to_hex(chunk_id)] = true;
}

void ChunkStore::set_revalidate_all(bool enabled) {
    revalidate_all_ = enabled;
}

bool ChunkStore::historical_evidence(const ChunkMetadata& chunk) {
    const auto key = crypto::to_hex(chunk.id);
    if (base_evidence_.contains(key)) {
        return true;
    }
    return validation_cache_ && validation_cache_->contains(chunk.id, chunk.stored_length, chunk.format_version);
}

std::vector<ValidatedObject> ChunkStore::validated_objects() const {
    std::vector<ValidatedObject> result;
    for (const auto& [hex, check] : checks_) {
        if (check.current_validated) {
            result.push_back(ValidatedObject{
                domain::hex_decode<32>(hex).value(),
                check.stored_length,
                check.format_version,
            });
        }
    }
    return result;
}

domain::Result<void> ChunkStore::check_metadata(const ChunkMetadata& chunk) {
    if (chunk.plaintext_length == 0 || chunk.plaintext_length > config_.chunk_size) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid chunk plaintext length"});
    }
    const auto key = crypto::to_hex(chunk.id);
    if (checks_.contains(key)) {
        return {};
    }

    std::error_code error;
    const auto path = chunk_path(chunk.id);
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)
        || std::filesystem::is_symlink(status)) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk is not a regular non-symlink file"});
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size != chunk.stored_length) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk stored length mismatch"});
    }
    checks_.emplace(key, CachedCheck{chunk.stored_length, chunk.format_version, chunk.content_encoding, false});
    return {};
}

domain::Result<crypto::Bytes> ChunkStore::read_and_validate(
    const std::filesystem::path& path,
    const ChunkMetadata& chunk
) {
    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }

    std::array<std::byte, 8> prefix{};
    auto result = file->read_exact(prefix);
    if (!result) {
        return std::unexpected(result.error());
    }
    if (prefix[0] != std::byte{'C'} || prefix[1] != std::byte{'P'}
        || prefix[2] != std::byte{'C'} || prefix[3] != std::byte{'K'}) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid chunk envelope"});
    }
    const auto version = domain::read_le(std::span(prefix).subspan(4, 2), 2).value();
    const auto encoding = static_cast<std::uint16_t>(domain::read_le(std::span(prefix).subspan(6, 2), 2).value());
    if ((version != 1 && version != 2) || version != chunk.format_version
        || encoding != chunk.content_encoding || encoding > 1) {
        return std::unexpected(Error{ErrorCode::integrity, "unsupported or inconsistent chunk envelope"});
    }
    std::array<std::byte, 8> length_bytes{};
    result = file->read_exact(length_bytes);
    if (!result) {
        return std::unexpected(result.error());
    }
    const auto length = domain::read_le(length_bytes, 8);
    if (!length || *length != chunk.plaintext_length) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk plaintext length mismatch"});
    }
    std::uint64_t encoded_length = length.value();
    if (version == 2) {
        result = file->read_exact(length_bytes);
        if (!result) {
            return std::unexpected(result.error());
        }
        encoded_length = domain::read_le(length_bytes, 8).value();
    }
    if (encoded_length > static_cast<std::uint64_t>(config_.chunk_size)
            + config_.chunk_size / 8 + 1024
        || chunk.stored_length != (version == 1 ? 56 + encoded_length : 64 + encoded_length)) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk encoded length mismatch"});
    }

    crypto::SealedObject object;
    result = file->read_exact(object.nonce);
    if (!result) {
        return std::unexpected(result.error());
    }
    object.ciphertext.resize(encoded_length + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    result = file->read_exact(object.ciphertext);
    if (!result) {
        return std::unexpected(result.error());
    }
    std::byte trailing{};
    const auto trailing_size = file->read_some({&trailing, 1});
    if (!trailing_size) {
        return std::unexpected(trailing_size.error());
    }
    if (*trailing_size != 0) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk has trailing data"});
    }

    const auto aad = version == 1
        ? chunk_aad(config_, chunk)
        : chunk_aad_v2(config_, chunk, encoded_length);
    auto plaintext = crypto::open_object(encryption_key_, aad, object);
    if (!plaintext) {
        return std::unexpected(plaintext.error());
    }
    if (encoding == 1) {
        auto decompressed = domain::decompress_zstd(*plaintext, chunk.plaintext_length);
        if (!decompressed) {
            return std::unexpected(decompressed.error());
        }
        plaintext = std::move(*decompressed);
    } else if (encoded_length != chunk.plaintext_length) {
        return std::unexpected(Error{ErrorCode::integrity, "uncompressed chunk length mismatch"});
    }
    const auto actual_id = crypto::compute_chunk_id(id_key_, *plaintext);
    if (!actual_id || *actual_id != chunk.id) {
        return std::unexpected(Error{ErrorCode::integrity, "chunk content ID mismatch"});
    }
    return plaintext;
}

domain::Result<void> ChunkStore::inspect(const ChunkMetadata& chunk) {
    return check_metadata(chunk);
}

domain::Result<void> ChunkStore::validate(const ChunkMetadata& chunk) {
    const auto key = crypto::to_hex(chunk.id);
    const auto existing = checks_.find(key);
    if (existing != checks_.end() && existing->second.current_validated) {
        return {};
    }
    auto metadata = check_metadata(chunk);
    if (!metadata) {
        return metadata;
    }
    auto plaintext = read_and_validate(chunk_path(chunk.id), chunk);
    if (!plaintext) {
        return std::unexpected(plaintext.error());
    }
    checks_[key].validated = true;
    checks_[key].current_validated = true;
    return {};
}

domain::Result<ChunkMetadata> ChunkStore::reuse(const crypto::ChunkDescriptor& descriptor) {
    ChunkMetadata chunk{
        descriptor.chunk_id,
        descriptor.plaintext_length,
        descriptor.stored_length,
        true,
        descriptor.format_version,
        descriptor.content_encoding,
    };
    const auto metadata = check_metadata(chunk);
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    const auto key = crypto::to_hex(chunk.id);
    if (revalidate_all_ || !historical_evidence(chunk)) {
        const auto validated = validate(chunk);
        if (!validated) {
            return std::unexpected(validated.error());
        }
    } else {
        checks_[key].validated = true;
    }
    return chunk;
}

domain::Result<bool> ChunkStore::has_object(const crypto::Digest& id) const {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(chunk_path(id), error);
    if (error == std::errc::no_such_file_or_directory) {
        return false;
    }
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    return true;
}

domain::Result<crypto::Bytes> ChunkStore::get(const ChunkMetadata& chunk) {
    auto metadata = check_metadata(chunk);
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    return read_and_validate(chunk_path(chunk.id), chunk);
}

domain::Result<ChunkMetadata> ChunkStore::put(std::span<const std::byte> plaintext) {
    auto compressed = domain::compress_zstd(plaintext);
    if (!compressed) {
        return std::unexpected(compressed.error());
    }
    if (compressed->size() < plaintext.size()) {
        return put_encoded(plaintext, *compressed, 1);
    }
    return put_encoded(plaintext, plaintext, 0);
}

domain::Result<ChunkMetadata> ChunkStore::put_encoded(
    std::span<const std::byte> plaintext,
    std::span<const std::byte> encoded,
    std::uint16_t encoding
) {
    if (plaintext.empty() || plaintext.size() > config_.chunk_size
        || encoding > 1 || (encoding == 0 && !std::ranges::equal(encoded, plaintext))) {
        return std::unexpected(Error{ErrorCode::usage, "chunk plaintext length is invalid"});
    }
    const auto id = crypto::compute_chunk_id(id_key_, plaintext);
    if (!id) {
        return std::unexpected(id.error());
    }
    const auto key = crypto::to_hex(*id);
    const auto cached = checks_.find(key);
    if (cached != checks_.end() && cached->second.current_validated) {
        return ChunkMetadata{
            *id,
            static_cast<std::uint32_t>(plaintext.size()),
            cached->second.stored_length,
            true,
            cached->second.format_version,
            cached->second.content_encoding,
        };
    }

    ChunkMetadata chunk{
        *id,
        static_cast<std::uint32_t>(plaintext.size()),
        0,
        false,
        2,
        0,
    };
    const auto final_path = chunk_path(*id);
    if (std::filesystem::exists(final_path)) {
        auto existing = platform::BinaryFile::open_read(final_path);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        std::array<std::byte, 8> prefix{};
        auto read = existing->read_exact(prefix);
        if (!read) {
            return std::unexpected(read.error());
        }
        const auto version = domain::read_le(std::span(prefix).subspan(4, 2), 2).value();
        chunk.format_version = static_cast<std::uint32_t>(version);
        chunk.content_encoding = static_cast<std::uint16_t>(domain::read_le(std::span(prefix).subspan(6, 2), 2).value());
        std::array<std::byte, 8> length_bytes{};
        read = existing->read_exact(length_bytes);
        if (!read) {
            return std::unexpected(read.error());
        }
        if (domain::read_le(length_bytes, 8).value() != chunk.plaintext_length) {
            return std::unexpected(Error{ErrorCode::integrity, "existing chunk plaintext length mismatch"});
        }
        std::uint64_t encoded_length = chunk.plaintext_length;
        if (version == 2) {
            read = existing->read_exact(length_bytes);
            if (!read) {
                return std::unexpected(read.error());
            }
            encoded_length = domain::read_le(length_bytes, 8).value();
        }
        chunk.stored_length = (version == 1 ? 56 : 64) + encoded_length;
        auto metadata = check_metadata(chunk);
        if (!metadata) {
            return std::unexpected(metadata.error());
        }
        if (!revalidate_all_ && historical_evidence(chunk)) {
            checks_[key].validated = true;
        } else {
            auto validated = validate(chunk);
            if (!validated) {
                return std::unexpected(validated.error());
            }
        }
        chunk.already_present = true;
        return chunk;
    }

    chunk.content_encoding = encoding;
    chunk.stored_length = encoded.size() + 64;
    const auto temporary = repository_ / "tmp"
        / (domain::hex_encode(crypto::random_uuid()) + ".part");
    std::error_code directory_error;
    std::filesystem::create_directories(final_path.parent_path(), directory_error);
    std::filesystem::create_directories(temporary.parent_path(), directory_error);
    if (directory_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, directory_error.message()});
    }
    TemporaryCleanup cleanup{temporary};

    const auto aad = chunk_aad_v2(config_, chunk, encoded.size());
    auto sealed = crypto::seal_object(encryption_key_, aad, encoded);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    auto file = platform::BinaryFile::create_new(temporary);
    if (!file) {
        return std::unexpected(file.error());
    }
    const Bytes prefix{
        std::byte{'C'}, std::byte{'P'}, std::byte{'C'}, std::byte{'K'},
        std::byte{2}, std::byte{0},
        static_cast<std::byte>(chunk.content_encoding & 0xffU),
        static_cast<std::byte>(chunk.content_encoding >> 8U),
    };
    auto result = file->write_all(prefix);
    if (!result) {
        return std::unexpected(result.error());
    }
    Bytes length;
    append_u64(length, chunk.plaintext_length, 8);
    result = file->write_all(length);
    if (!result) {
        return std::unexpected(result.error());
    }
    length.clear();
    append_u64(length, encoded.size(), 8);
    result = file->write_all(length);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->write_all(sealed->nonce);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->write_all(sealed->ciphertext);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->flush();
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->close();
    if (!result) {
        return std::unexpected(result.error());
    }

    auto verified = read_and_validate(temporary, chunk);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    auto published = platform::publish_no_replace(temporary, final_path);
    if (!published) {
        if (std::filesystem::exists(final_path)) {
            auto validated = validate(chunk);
            if (!validated) {
                return std::unexpected(validated.error());
            }
            chunk.already_present = true;
            return chunk;
        }
        return std::unexpected(published.error());
    }
    auto current = final_path.parent_path();
    while (true) {
        auto synced = platform::sync_directory(current);
        if (!synced) {
            return std::unexpected(synced.error());
        }
        if (current == repository_ / "chunks") {
            break;
        }
        current = current.parent_path();
    }
    checks_[key] = CachedCheck{chunk.stored_length, chunk.format_version, chunk.content_encoding, true, true};
    return chunk;
}

}
