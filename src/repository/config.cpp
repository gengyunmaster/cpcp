#include "repository/config.hpp"

#include "crypto/content_id.hpp"
#include "domain/strict_json.hpp"

#include <sodium.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;
using nlohmann::json;

namespace {

void append_u32(Bytes& output, std::uint64_t value) {
    domain::append_le(output, value, 4);
}

void append_u64(Bytes& output, std::uint64_t value) {
    domain::append_le(output, value, 8);
}

void append_bytes(Bytes& output, std::span<const std::byte> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_text(Bytes& output, std::string_view text) {
    append_u32(output, text.size());
    for (const char value : text) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
}

void append_blob(Bytes& output, std::span<const std::byte> bytes) {
    append_u32(output, bytes.size());
    append_bytes(output, bytes);
}

void append_string(Bytes& output, std::string_view text) {
    for (const char value : text) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
}

Bytes wrap_aad(const RepositoryConfig& config) {
    Bytes aad;
    append_string(aad, "cpcp.master-key.v1");
    append_bytes(aad, config.repository_uuid);
    append_u32(aad, config.format_version);
    append_text(aad, config.slot_id);
    append_text(aad, config.slot_type);
    append_string(aad, "argon2id");
    append_u64(aad, config.kdf.memory_kib);
    append_u64(aad, config.kdf.iterations);
    append_bytes(aad, config.salt);
    return aad;
}

Bytes config_auth_bytes(const RepositoryConfig& config) {
    Bytes output;
    append_string(output, "cpcp.config.v1");
    append_u32(output, config.format_version);
    append_u64(output, config.revision);
    append_bytes(output, config.repository_uuid);
    append_bytes(output, config.storage_epoch);
    append_u64(output, static_cast<std::uint64_t>(config.created_seconds));
    append_u32(output, config.created_nanoseconds);
    append_u32(output, config.chunk_size);
    append_text(output, config.cipher_suite);
    append_text(output, config.hash_algorithm);
    append_string(output, "argon2id");
    append_u64(output, config.kdf.memory_kib);
    append_u64(output, config.kdf.iterations);
    append_text(output, config.slot_id);
    append_text(output, config.slot_type);
    append_bytes(output, config.salt);
    append_bytes(output, config.wrapped_master.nonce);
    append_blob(output, config.wrapped_master.ciphertext);
    return output;
}

domain::Result<crypto::Digest> compute_tag(
    const RepositoryConfig& config,
    const crypto::SecureKey& master
) {
    auto key = crypto::derive_key(master, crypto::KeyPurpose::configuration_authentication);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto input = config_auth_bytes(config);
    return crypto::compute_hmac_sha256(*key, input);
}

std::string uint_string(std::uint64_t value) {
    return std::to_string(value);
}

domain::Result<std::uint64_t> parse_uint_string(const json& value) {
    if (!value.is_string()) {
        return std::unexpected(Error{ErrorCode::integrity, "expected an unsigned integer string"});
    }
    const auto text = value.get<std::string>();
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid unsigned integer string"});
    }
    return result;
}

std::string require_string(const json& object, std::string_view key) {
    const auto& value = object.at(std::string(key));
    if (!value.is_string()) {
        throw std::invalid_argument("expected a JSON string");
    }
    return value.get<std::string>();
}

std::uint64_t require_uint(const json& object, std::string_view key) {
    const auto& value = object.at(std::string(key));
    if (!value.is_number_unsigned() && !value.is_number_integer()) {
        throw std::invalid_argument("expected a JSON integer");
    }
    return value.get<std::uint64_t>();
}

template<std::size_t N>
domain::Result<std::array<std::byte, N>> require_hex(
    const json& object,
    std::string_view key
) {
    const auto text = require_string(object, key);
    return domain::hex_decode<N>(text);
}

}

domain::Result<RepositoryConfig> create_config(
    const crypto::SecretBytes& password,
    const ConfigOptions& options
) {
    if (options.chunk_size < 1024 * 1024 || options.chunk_size > 64 * 1024 * 1024) {
        return std::unexpected(Error{ErrorCode::usage, "chunk size must be between 1 and 64 MiB"});
    }

    RepositoryConfig config;
    config.format_version = options.format_version;
    config.chunk_size = options.chunk_size;
    config.kdf = options.kdf;
    config.repository_uuid = crypto::random_uuid();
    config.storage_epoch = crypto::random_uuid();
    crypto::fill_random(config.salt);
    crypto::fill_random(config.wrapped_master.nonce);

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds);
    config.created_seconds = seconds.count();
    config.created_nanoseconds = static_cast<std::uint32_t>(nanoseconds.count());

    auto master = crypto::SecureKey::generate();
    if (!master) {
        return std::unexpected(master.error());
    }
    auto kek = crypto::derive_password_key(password, config.salt, config.kdf);
    if (!kek) {
        return std::unexpected(kek.error());
    }

    const auto aad = wrap_aad(config);
    auto wrapped = crypto::seal_object(*kek, aad, master->bytes());
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    config.wrapped_master = std::move(wrapped).value();

    auto tag = compute_tag(config, *master);
    if (!tag) {
        return std::unexpected(tag.error());
    }
    config.authentication_tag = *tag;
    return config;
}

domain::Result<crypto::SecureKey> unlock_config(
    const RepositoryConfig& config,
    const crypto::SecretBytes& password
) {
    auto kek = crypto::derive_password_key(password, config.salt, config.kdf);
    if (!kek) {
        return std::unexpected(kek.error());
    }
    const auto aad = wrap_aad(config);
    auto plaintext = crypto::open_object(*kek, aad, config.wrapped_master);
    if (!plaintext) {
        return std::unexpected(Error{ErrorCode::authentication, "password or key slot authentication failed"});
    }
    if (plaintext->size() != crypto::key_size) {
        return std::unexpected(Error{ErrorCode::authentication, "invalid wrapped master key length"});
    }

    std::array<std::byte, crypto::key_size> key_bytes{};
    std::ranges::copy(*plaintext, key_bytes.begin());
    auto master = crypto::SecureKey::from_bytes(key_bytes);
    if (!master) {
        return std::unexpected(master.error());
    }
    auto expected_tag = compute_tag(config, *master);
    if (!expected_tag) {
        return std::unexpected(expected_tag.error());
    }
    if (sodium_memcmp(
            expected_tag->data(),
            config.authentication_tag.data(),
            expected_tag->size()
        ) != 0) {
        return std::unexpected(Error{ErrorCode::authentication, "configuration authentication failed"});
    }
    return master;
}

domain::Result<std::string> serialize_config(const RepositoryConfig& config) {
    const json document = {
        {"magic", "CPCP"},
        {"format_version", config.format_version},
        {"revision", uint_string(config.revision)},
        {"repository_uuid", domain::hex_encode(config.repository_uuid)},
        {"storage_epoch", domain::hex_encode(config.storage_epoch)},
        {"created_at", {
            {"seconds", uint_string(static_cast<std::uint64_t>(config.created_seconds))},
            {"nanoseconds", config.created_nanoseconds},
        }},
        {"chunk_size", config.chunk_size},
        {"cipher_suite", config.cipher_suite},
        {"hash_algorithm", config.hash_algorithm},
        {"feature_versions", json::object()},
        {"kdf", {
            {"algorithm", "argon2id"},
            {"memory_kib", uint_string(config.kdf.memory_kib)},
            {"iterations", uint_string(config.kdf.iterations)},
        }},
        {"key_slots", json::array({{
            {"id", config.slot_id},
            {"type", config.slot_type},
            {"salt", domain::hex_encode(config.salt)},
            {"wrapped_mk", {
                {"nonce", domain::hex_encode(config.wrapped_master.nonce)},
                {"ciphertext", domain::hex_encode(config.wrapped_master.ciphertext)},
            }},
        }})},
        {"authentication_tag", domain::hex_encode(config.authentication_tag)},
    };
    return document.dump(2) + '\n';
}

domain::Result<RepositoryConfig> parse_config(std::span<const std::byte> input) {
    const auto document_result = domain::parse_bounded_json(
        input,
        domain::JsonLimits{.bytes = config_file_limit}
    );
    if (!document_result) {
        return std::unexpected(document_result.error());
    }

    try {
        const auto& document = *document_result;
        if (!document.is_object() || require_string(document, "magic") != "CPCP") {
            return std::unexpected(Error{ErrorCode::integrity, "invalid repository configuration"});
        }

        RepositoryConfig config;
        config.format_version = static_cast<std::uint32_t>(require_uint(document, "format_version"));
        const auto revision = parse_uint_string(document.at("revision"));
        if (!revision) {
            return std::unexpected(revision.error());
        }
        config.revision = *revision;
        const auto repository_uuid = require_hex<16>(document, "repository_uuid");
        if (!repository_uuid) {
            return std::unexpected(repository_uuid.error());
        }
        config.repository_uuid = *repository_uuid;
        const auto epoch = require_hex<16>(document, "storage_epoch");
        if (!epoch) {
            return std::unexpected(epoch.error());
        }
        config.storage_epoch = *epoch;

        const auto& created = document.at("created_at");
        const auto seconds = parse_uint_string(created.at("seconds"));
        if (!seconds || *seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(Error{ErrorCode::integrity, "invalid creation timestamp"});
        }
        config.created_seconds = static_cast<std::int64_t>(*seconds);
        config.created_nanoseconds = static_cast<std::uint32_t>(require_uint(created, "nanoseconds"));
        config.chunk_size = static_cast<std::uint32_t>(require_uint(document, "chunk_size"));
        config.cipher_suite = require_string(document, "cipher_suite");
        config.hash_algorithm = require_string(document, "hash_algorithm");
        if (config.cipher_suite != "xchacha20poly1305-secretstream"
            || config.hash_algorithm != "hmac-sha256") {
            return std::unexpected(Error{ErrorCode::unsupported, "unsupported cryptographic suite"});
        }

        const auto& kdf = document.at("kdf");
        if (require_string(kdf, "algorithm") != "argon2id") {
            return std::unexpected(Error{ErrorCode::unsupported, "unsupported password KDF"});
        }
        const auto memory = parse_uint_string(kdf.at("memory_kib"));
        const auto iterations = parse_uint_string(kdf.at("iterations"));
        if (!memory || !iterations) {
            return std::unexpected(Error{ErrorCode::integrity, "invalid KDF parameters"});
        }
        config.kdf = {*memory, *iterations};

        const auto& slots = document.at("key_slots");
        if (!slots.is_array() || slots.size() != 1) {
            return std::unexpected(Error{ErrorCode::unsupported, "configuration requires exactly one initial key slot"});
        }
        const auto& slot = slots.at(0);
        config.slot_id = require_string(slot, "id");
        config.slot_type = require_string(slot, "type");
        if (config.slot_type != "password") {
            return std::unexpected(Error{ErrorCode::unsupported, "unsupported key slot type"});
        }
        const auto salt = require_hex<crypto::password_salt_size>(slot, "salt");
        if (!salt) {
            return std::unexpected(salt.error());
        }
        config.salt = *salt;
        const auto& wrapped = slot.at("wrapped_mk");
        const auto nonce = require_hex<crypto::nonce_size>(wrapped, "nonce");
        if (!nonce) {
            return std::unexpected(nonce.error());
        }
        config.wrapped_master.nonce = *nonce;
        const auto ciphertext = require_string(wrapped, "ciphertext");
        const auto decoded = domain::hex_decode<48>(ciphertext);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        config.wrapped_master.ciphertext.assign(decoded->begin(), decoded->end());
        const auto tag = require_hex<32>(document, "authentication_tag");
        if (!tag) {
            return std::unexpected(tag.error());
        }
        config.authentication_tag = *tag;
        return config;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

}
