#include "repository/chunk_set.hpp"

#include "domain/encoding.hpp"
#include "platform/binary_file.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <queue>
#include <system_error>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;

namespace {

constexpr std::size_t run_entry_limit = 1024;
constexpr std::size_t open_run_limit = 32;

Bytes raw_bytes(const RawChunk& chunk) {
    Bytes bytes;
    bytes.insert(bytes.end(), chunk.id.begin(), chunk.id.end());
    domain::append_le(bytes, chunk.stored_length, 8);
    return bytes;
}

domain::Result<void> write_raw(platform::BinaryFile& file, const RawChunk& chunk) {
    return file.write_all(raw_bytes(chunk));
}

struct RunReader {
    explicit RunReader(platform::BinaryFile input) : file(std::move(input)) {
    }

    platform::BinaryFile file;
    RawChunk current{};

    domain::Result<bool> next() {
        Bytes bytes(sizeof(RawChunk));
        const auto count = file.read_some(bytes);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return false;
        }
        const auto remainder = file.read_exact(std::span(bytes).subspan(*count));
        if (!remainder) {
            return std::unexpected(remainder.error());
        }
        std::ranges::copy_n(
            bytes.begin(),
            static_cast<std::ptrdiff_t>(current.id.size()),
            current.id.begin()
        );
        current.stored_length = domain::read_le(
            std::span(bytes).subspan(current.id.size(), 8),
            8
        ).value();
        return true;
    }
};

struct MergeItem {
    RawChunk chunk;
    std::size_t run;
};

struct MergeCompare {
    bool operator()(const MergeItem& left, const MergeItem& right) const {
        return right.chunk < left.chunk;
    }
};

domain::Result<void> merge_runs(
    const std::vector<std::filesystem::path>& inputs,
    const std::optional<std::filesystem::path>& output,
    const crypto::SecureKey* id_key,
    crypto::Digest* digest
) {
    std::vector<RunReader> readers;
    readers.reserve(inputs.size());
    for (const auto& path : inputs) {
        auto file = platform::BinaryFile::open_read(path);
        if (!file) {
            return std::unexpected(file.error());
        }
        readers.emplace_back(std::move(file).value());
    }

    std::optional<platform::BinaryFile> writer;
    if (output) {
        auto file = platform::BinaryFile::create_new(*output);
        if (!file) {
            return std::unexpected(file.error());
        }
        writer.emplace(std::move(file).value());
    }

    crypto_auth_hmacsha256_state digest_state{};
    if (id_key != nullptr && digest != nullptr) {
        if (crypto_auth_hmacsha256_init(
                &digest_state,
                reinterpret_cast<const unsigned char*>(id_key->bytes().data()),
                id_key->bytes().size()
            ) != 0) {
            return std::unexpected(Error{ErrorCode::internal, "chunk-set HMAC initialization failed"});
        }
        constexpr std::string_view domain = "cpcp.chunk-set.v1";
        crypto_auth_hmacsha256_update(
            &digest_state,
            reinterpret_cast<const unsigned char*>(domain.data()),
            domain.size()
        );
    }

    std::priority_queue<MergeItem, std::vector<MergeItem>, MergeCompare> queue;
    for (std::size_t index = 0; index < readers.size(); ++index) {
        const auto has_value = readers[index].next();
        if (!has_value) {
            return std::unexpected(has_value.error());
        }
        if (*has_value) {
            queue.push(MergeItem{readers[index].current, index});
        }
    }

    std::optional<RawChunk> previous;
    while (!queue.empty()) {
        const auto item = queue.top();
        queue.pop();
        if (previous && previous->id == item.chunk.id) {
            if (previous->stored_length != item.chunk.stored_length) {
                return std::unexpected(Error{ErrorCode::integrity, "duplicate chunk ID has different stored lengths"});
            }
        } else {
            if (writer) {
                const auto written = write_raw(*writer, item.chunk);
                if (!written) {
                    return written;
                }
            }
            if (id_key != nullptr && digest != nullptr) {
                const auto bytes = raw_bytes(item.chunk);
                crypto_auth_hmacsha256_update(
                    &digest_state,
                    reinterpret_cast<const unsigned char*>(bytes.data()),
                    static_cast<unsigned long long>(bytes.size())
                );
            }
            previous = item.chunk;
        }

        const auto has_value = readers[item.run].next();
        if (!has_value) {
            return std::unexpected(has_value.error());
        }
        if (*has_value) {
            queue.push(MergeItem{readers[item.run].current, item.run});
        }
    }

    if (writer) {
        auto result = writer->flush();
        if (!result) {
            return result;
        }
        result = writer->close();
        if (!result) {
            return result;
        }
    }
    if (id_key != nullptr && digest != nullptr) {
        crypto_auth_hmacsha256_final(
            &digest_state,
            reinterpret_cast<unsigned char*>(digest->data())
        );
    }
    return {};
}

}

domain::Result<ChunkSetBuilder> ChunkSetBuilder::create(
    std::filesystem::path temporary_directory,
    const crypto::SecureKey& id_key
) {
    auto key = crypto::SecureKey::from_bytes(id_key.bytes());
    if (!key) {
        return std::unexpected(key.error());
    }
    std::error_code error;
    std::filesystem::create_directories(temporary_directory, error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    return ChunkSetBuilder(std::move(temporary_directory), std::move(key).value());
}

ChunkSetBuilder::ChunkSetBuilder(
    std::filesystem::path temporary_directory,
    crypto::SecureKey id_key
) : temporary_directory_(std::move(temporary_directory)),
    id_key_(std::move(id_key)) {
    buffer_.reserve(run_entry_limit);
}

ChunkSetBuilder::~ChunkSetBuilder() {
    std::error_code ignored;
    std::filesystem::remove_all(temporary_directory_, ignored);
}

domain::Result<void> ChunkSetBuilder::add(const crypto::ChunkDescriptor& chunk) {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "chunk-set builder is finished"});
    }
    buffer_.push_back(RawChunk{chunk.chunk_id, chunk.stored_length});
    if (buffer_.size() == run_entry_limit) {
        return flush_run();
    }
    return {};
}

domain::Result<void> ChunkSetBuilder::flush_run() {
    if (buffer_.empty()) {
        return {};
    }
    if (runs_.size() >= open_run_limit) {
        auto compacted = compact();
        if (!compacted) {
            return compacted;
        }
    }

    std::sort(buffer_.begin(), buffer_.end());
    const auto path = temporary_directory_ / ("run-" + std::to_string(next_run_++) + ".bin");
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    for (const auto& chunk : buffer_) {
        const auto written = write_raw(*file, chunk);
        if (!written) {
            return written;
        }
    }
    auto result = file->flush();
    if (!result) {
        return result;
    }
    result = file->close();
    if (!result) {
        return result;
    }
    runs_.push_back(path);
    buffer_.clear();
    return {};
}

domain::Result<void> ChunkSetBuilder::compact() {
    const auto path = temporary_directory_ / ("compact-" + std::to_string(next_run_++) + ".bin");
    auto merged = merge_runs(runs_, path, nullptr, nullptr);
    if (!merged) {
        return merged;
    }
    for (const auto& run : runs_) {
        std::error_code ignored;
        std::filesystem::remove(run, ignored);
    }
    runs_.assign(1, path);
    return {};
}

domain::Result<crypto::Digest> ChunkSetBuilder::finish() {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "chunk-set builder is already finished"});
    }
    finished_ = true;
    auto flushed = flush_run();
    if (!flushed) {
        return std::unexpected(flushed.error());
    }

    crypto::Digest digest;
    auto merged = merge_runs(runs_, std::nullopt, &id_key_, &digest);
    if (!merged) {
        return std::unexpected(merged.error());
    }
    return digest;
}

}
