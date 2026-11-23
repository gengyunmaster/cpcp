#pragma once

#include "crypto/aead.hpp"
#include "crypto/password.hpp"
#include "domain/encoding.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

namespace cpcp::repository {

inline constexpr std::uint32_t experimental_format_version = 0;
inline constexpr std::size_t config_file_limit = 128 * 1024;

struct ConfigOptions {
    crypto::PasswordKdfParameters kdf;
    std::uint32_t chunk_size = 8 * 1024 * 1024;
    std::uint32_t format_version = experimental_format_version;
};

struct RepositoryConfig {
    std::uint32_t format_version = experimental_format_version;
    std::uint64_t revision = 1;
    domain::Uuid repository_uuid{};
    domain::Uuid storage_epoch{};
    std::int64_t created_seconds = 0;
    std::uint32_t created_nanoseconds = 0;
    std::uint32_t chunk_size = 0;
    std::string cipher_suite = "xchacha20poly1305-secretstream";
    std::string hash_algorithm = "hmac-sha256";
    crypto::PasswordKdfParameters kdf;
    std::string slot_id = "password-1";
    std::string slot_type = "password";
    std::array<std::byte, crypto::password_salt_size> salt{};
    crypto::SealedObject wrapped_master;
    crypto::Digest authentication_tag{};
};

struct UnlockedConfig {
    RepositoryConfig config;
    crypto::SecureKey master_key;
    bool degraded_redundancy = false;
};

domain::Result<RepositoryConfig> create_config(
    const crypto::SecretBytes& password,
    const ConfigOptions& options
);
domain::Result<crypto::SecureKey> unlock_config(
    const RepositoryConfig& config,
    const crypto::SecretBytes& password
);
domain::Result<std::string> serialize_config(const RepositoryConfig& config);
domain::Result<RepositoryConfig> parse_config(std::span<const std::byte> input);

domain::Result<void> write_new_config_replicas(
    const std::filesystem::path& repository,
    const RepositoryConfig& config
);
domain::Result<UnlockedConfig> load_config(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
);
domain::Result<void> export_config(
    const RepositoryConfig& config,
    const std::filesystem::path& output
);
domain::Result<void> import_config(
    const std::filesystem::path& header,
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
);

}
