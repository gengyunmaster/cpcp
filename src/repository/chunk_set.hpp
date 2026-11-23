#pragma once

#include "crypto/content_id.hpp"
#include "domain/result.hpp"

#include <cstddef>
#include <filesystem>
#include <vector>

namespace cpcp::repository {

struct RawChunk {
    crypto::Digest id;
    std::uint64_t stored_length;

    bool operator<(const RawChunk& other) const {
        for (std::size_t index = 0; index < id.size(); ++index) {
            if (id[index] != other.id[index]) {
                return id[index] < other.id[index];
            }
        }
        return false;
    }
};

class ChunkSetBuilder {
public:
    static domain::Result<ChunkSetBuilder> create(
        std::filesystem::path temporary_directory,
        const crypto::SecureKey& id_key
    );

    domain::Result<void> add(const crypto::ChunkDescriptor& chunk);
    domain::Result<crypto::Digest> finish();

private:
    ChunkSetBuilder(
        std::filesystem::path temporary_directory,
        crypto::SecureKey id_key
    );
public:
    ChunkSetBuilder(const ChunkSetBuilder&) = delete;
    ChunkSetBuilder& operator=(const ChunkSetBuilder&) = delete;
    ChunkSetBuilder(ChunkSetBuilder&&) = default;
    ChunkSetBuilder& operator=(ChunkSetBuilder&&) = default;
    ~ChunkSetBuilder();

    domain::Result<void> flush_run();
    domain::Result<void> compact();

    std::filesystem::path temporary_directory_;
    crypto::SecureKey id_key_;
    std::vector<RawChunk> buffer_;
    std::vector<std::filesystem::path> runs_;
    std::size_t next_run_ = 0;
    bool finished_ = false;
};

}
