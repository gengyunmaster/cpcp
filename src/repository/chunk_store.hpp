#pragma once

#include "crypto/content_id.hpp"
#include "crypto/keys.hpp"
#include "domain/result.hpp"
#include "repository/config.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>

namespace cpcp::repository {

struct ChunkMetadata {
    crypto::Digest id;
    std::uint32_t plaintext_length;
    std::uint64_t stored_length;
    bool already_present;
};

class ChunkStore {
public:
    static domain::Result<ChunkStore> create(
        std::filesystem::path repository,
        const RepositoryConfig& config,
        const crypto::SecureKey& master_key
    );

    domain::Result<ChunkMetadata> put(std::span<const std::byte> plaintext);
    domain::Result<ChunkMetadata> reuse(const crypto::ChunkDescriptor& descriptor);
    domain::Result<crypto::Bytes> get(const ChunkMetadata& chunk);
    domain::Result<void> inspect(const ChunkMetadata& chunk);
    domain::Result<void> validate(const ChunkMetadata& chunk);
    void allow_base_evidence(const crypto::Digest& chunk_id);
    void set_revalidate_all(bool enabled);

private:
    struct CachedCheck {
        std::uint64_t stored_length;
        bool validated = false;
    };

    ChunkStore(
        std::filesystem::path repository,
        RepositoryConfig config,
        crypto::SecureKey encryption_key,
        crypto::SecureKey id_key
    );

    std::filesystem::path chunk_path(const crypto::Digest& id) const;
    domain::Result<crypto::Bytes> read_and_validate(
        const std::filesystem::path& path,
        const ChunkMetadata& chunk
    );
    domain::Result<void> check_metadata(const ChunkMetadata& chunk);

    std::filesystem::path repository_;
    RepositoryConfig config_;
    crypto::SecureKey encryption_key_;
    crypto::SecureKey id_key_;
    std::map<std::string, CachedCheck> checks_;
    std::map<std::string, bool> base_evidence_;
    bool revalidate_all_ = false;
};

}
