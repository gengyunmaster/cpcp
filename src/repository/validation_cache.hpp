#pragma once

#include "crypto/content_id.hpp"
#include "platform/binary_file.hpp"
#include "repository/config.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace cpcp::repository {

struct ValidatedObject {
    crypto::Digest id{};
    std::uint64_t stored_length = 0;
    std::uint32_t format_version = 1;
};

class ValidationCache {
public:
    static domain::Result<std::optional<ValidationCache>> open(
        const std::filesystem::path& repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key
    );

    ValidationCache(const ValidationCache&) = delete;
    ValidationCache& operator=(const ValidationCache&) = delete;
    ValidationCache(ValidationCache&&) noexcept;
    ValidationCache& operator=(ValidationCache&&) noexcept;
    ~ValidationCache();

    bool contains(const crypto::Digest& id, std::uint64_t stored_length, std::uint32_t format_version);

    static domain::Result<void> write(
        const std::filesystem::path& repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key,
        std::vector<ValidatedObject> entries
    );

private:
    ValidationCache(
        platform::BinaryFile file,
        domain::Uuid repository_uuid,
        domain::Uuid storage_epoch,
        crypto::SecureKey cache_key,
        std::uint64_t entries
    );

    std::optional<platform::BinaryFile> file_;
    domain::Uuid repository_uuid_{};
    domain::Uuid storage_epoch_{};
    crypto::SecureKey cache_key_;
    std::uint64_t entries_ = 0;
};

std::filesystem::path validation_cache_path(
    const std::filesystem::path& repository,
    const domain::Uuid& storage_epoch
);

}
