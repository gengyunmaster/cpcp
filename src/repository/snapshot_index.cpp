#include "repository/snapshot_index.hpp"

#include "domain/encoding.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <queue>
#include <system_error>
#include <utility>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;

namespace {

constexpr std::size_t record_size = 89;
constexpr std::size_t run_record_limit = 1024;
constexpr std::size_t open_run_limit = 32;

struct RunReader {
    explicit RunReader(platform::BinaryFile input) : file(std::move(input)) {
    }

    platform::BinaryFile file;
    Bytes current;

    domain::Result<bool> next() {
        current.resize(record_size);
        const auto count = file.read_some(current);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return false;
        }
        const auto remainder = file.read_exact(std::span(current).subspan(*count));
        if (!remainder) {
            return std::unexpected(remainder.error());
        }
        return true;
    }
};

struct MergeItem {
    Bytes record;
    std::size_t run = 0;
};

struct MergeCompare {
    bool operator()(const MergeItem& left, const MergeItem& right) const {
        return right.record < left.record;
    }
};

bool same_key(const Bytes& left, const Bytes& right) {
    return std::ranges::equal(
        std::span(left).first<32>(),
        std::span(right).first<32>()
    );
}

domain::Result<crypto::Digest> path_key(
    const crypto::SecureKey& id_key,
    const domain::Uuid& root_uuid,
    std::string_view path
) {
    crypto_auth_hmacsha256_state state{};
    if (crypto_auth_hmacsha256_init(
            &state,
            reinterpret_cast<const unsigned char*>(id_key.bytes().data()),
            id_key.bytes().size()
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "path-index HMAC initialization failed"});
    }
    constexpr std::string_view domain = "cpcp.path-index.v1";
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(domain.data()),
        domain.size()
    );
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(root_uuid.data()),
        root_uuid.size()
    );
    Bytes length;
    domain::append_le(length, path.size(), 8);
    crypto_auth_hmacsha256_update(
        &state,
        reinterpret_cast<const unsigned char*>(length.data()),
        length.size()
    );
    if (!path.empty()) {
        crypto_auth_hmacsha256_update(
            &state,
            reinterpret_cast<const unsigned char*>(path.data()),
            path.size()
        );
    }
    crypto::Digest key{};
    if (crypto_auth_hmacsha256_final(&state, reinterpret_cast<unsigned char*>(key.data())) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "path-index HMAC finalization failed"});
    }
    return key;
}

Bytes encode_record(
    const crypto::Digest& key,
    const SnapshotPathMetadata& metadata
) {
    Bytes record;
    record.reserve(record_size);
    record.insert(record.end(), key.begin(), key.end());
    record.push_back(static_cast<std::byte>(metadata.type));
    domain::append_le(record, metadata.size, 8);
    domain::append_le(record, std::bit_cast<std::uint64_t>(metadata.mtime_seconds), 8);
    domain::append_le(record, metadata.mtime_nanoseconds, 4);
    domain::append_le(record, metadata.mode, 4);
    record.insert(record.end(), metadata.file_id.begin(), metadata.file_id.end());
    return record;
}

SnapshotPathMetadata decode_metadata(std::span<const std::byte, record_size> record) {
    SnapshotPathMetadata metadata;
    metadata.type = static_cast<SnapshotEntryType>(std::to_integer<std::uint8_t>(record[32]));
    metadata.size = domain::read_le(record.subspan(33, 8), 8).value();
    metadata.mtime_seconds = std::bit_cast<std::int64_t>(
        domain::read_le(record.subspan(41, 8), 8).value()
    );
    metadata.mtime_nanoseconds = static_cast<std::uint32_t>(
        domain::read_le(record.subspan(49, 4), 4).value()
    );
    metadata.mode = static_cast<std::uint32_t>(
        domain::read_le(record.subspan(53, 4), 4).value()
    );
    std::ranges::copy_n(record.begin() + 57, 32, metadata.file_id.begin());
    return metadata;
}

}

domain::Result<SnapshotPathIndex> SnapshotPathIndex::create(
    std::filesystem::path temporary_directory,
    const crypto::SecureKey& id_key
) {
    std::error_code error;
    if (std::filesystem::exists(temporary_directory, error)) {
        return std::unexpected(Error{ErrorCode::conflict, "temporary index directory already exists"});
    }
    std::filesystem::create_directories(temporary_directory, error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    auto key = crypto::SecureKey::from_bytes(id_key.bytes());
    if (!key) {
        return std::unexpected(key.error());
    }
    return SnapshotPathIndex(std::move(temporary_directory), std::move(key).value());
}

SnapshotPathIndex::SnapshotPathIndex(
    std::filesystem::path temporary_directory,
    crypto::SecureKey id_key
) : temporary_directory_(std::move(temporary_directory)),
    id_key_(std::move(id_key)) {
    buffer_.reserve(run_record_limit);
}

SnapshotPathIndex::SnapshotPathIndex(SnapshotPathIndex&& other) noexcept
    : temporary_directory_(std::move(other.temporary_directory_)),
      id_key_(std::move(other.id_key_)),
      buffer_(std::move(other.buffer_)),
      runs_(std::move(other.runs_)),
      next_run_(other.next_run_),
      record_count_(other.record_count_),
      sorted_(std::move(other.sorted_)),
      finished_(other.finished_) {
    other.temporary_directory_.clear();
}

SnapshotPathIndex& SnapshotPathIndex::operator=(SnapshotPathIndex&& other) noexcept {
    if (this != &other) {
        sorted_.reset();
        std::error_code ignored;
        if (!temporary_directory_.empty()) {
            std::filesystem::remove_all(temporary_directory_, ignored);
        }
        temporary_directory_ = std::move(other.temporary_directory_);
        id_key_ = std::move(other.id_key_);
        buffer_ = std::move(other.buffer_);
        runs_ = std::move(other.runs_);
        next_run_ = other.next_run_;
        record_count_ = other.record_count_;
        sorted_ = std::move(other.sorted_);
        finished_ = other.finished_;
        other.temporary_directory_.clear();
    }
    return *this;
}

SnapshotPathIndex::~SnapshotPathIndex() {
    sorted_.reset();
    std::error_code ignored;
    if (!temporary_directory_.empty()) {
        std::filesystem::remove_all(temporary_directory_, ignored);
    }
}

domain::Result<void> SnapshotPathIndex::add(
    const domain::Uuid& root_uuid,
    std::string_view path,
    const SnapshotPathMetadata& metadata
) {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "path index is already finished"});
    }
    if (metadata.mtime_nanoseconds > 999999999) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid path-index timestamp"});
    }
    const auto key = path_key(id_key_, root_uuid, path);
    if (!key) {
        return std::unexpected(key.error());
    }
    buffer_.push_back(encode_record(*key, metadata));
    if (buffer_.size() == run_record_limit) {
        return flush_run();
    }
    return {};
}

domain::Result<void> SnapshotPathIndex::flush_run() {
    if (buffer_.empty()) {
        return {};
    }
    if (runs_.size() >= open_run_limit) {
        const auto compacted = compact();
        if (!compacted) {
            return compacted;
        }
    }
    std::ranges::sort(buffer_);
    const auto path = temporary_directory_ / ("run-" + std::to_string(next_run_++) + ".bin");
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    for (const auto& record : buffer_) {
        const auto written = file->write_all(record);
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

domain::Result<void> SnapshotPathIndex::compact() {
    const auto path = temporary_directory_ / ("compact-" + std::to_string(next_run_++) + ".bin");
    const auto merged = merge(runs_, path);
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

domain::Result<void> SnapshotPathIndex::merge(
    const std::vector<std::filesystem::path>& inputs,
    const std::filesystem::path& output
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
    auto destination = platform::BinaryFile::create_new(output);
    if (!destination) {
        return std::unexpected(destination.error());
    }

    std::priority_queue<MergeItem, std::vector<MergeItem>, MergeCompare> pending;
    for (std::size_t index = 0; index < readers.size(); ++index) {
        const auto next = readers[index].next();
        if (!next) {
            return std::unexpected(next.error());
        }
        if (*next) {
            pending.push(MergeItem{readers[index].current, index});
        }
    }
    std::optional<Bytes> previous;
    while (!pending.empty()) {
        const auto item = pending.top();
        pending.pop();
        if (previous && same_key(*previous, item.record)) {
            return std::unexpected(Error{ErrorCode::integrity, "duplicate path identity in index"});
        }
        const auto written = destination->write_all(item.record);
        if (!written) {
            return written;
        }
        previous = item.record;
        const auto next = readers[item.run].next();
        if (!next) {
            return std::unexpected(next.error());
        }
        if (*next) {
            pending.push(MergeItem{readers[item.run].current, item.run});
        }
    }
    auto result = destination->flush();
    if (!result) {
        return result;
    }
    return destination->close();
}

domain::Result<void> SnapshotPathIndex::finish() {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "path index is already finished"});
    }
    const auto flushed = flush_run();
    if (!flushed) {
        return flushed;
    }
    const auto sorted_path = temporary_directory_ / "sorted.bin";
    const auto merged = merge(runs_, sorted_path);
    if (!merged) {
        return merged;
    }
    auto sorted = platform::BinaryFile::open_read(sorted_path);
    if (!sorted) {
        return std::unexpected(sorted.error());
    }
    const auto metadata = sorted->metadata();
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    if (metadata->size % record_size != 0) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid sorted path-index length"});
    }
    record_count_ = metadata->size / record_size;
    sorted_.emplace(std::move(sorted).value());
    finished_ = true;
    return {};
}

domain::Result<std::optional<SnapshotPathMetadata>> SnapshotPathIndex::find(
    const domain::Uuid& root_uuid,
    std::string_view path
) {
    if (!finished_ || !sorted_) {
        return std::unexpected(Error{ErrorCode::usage, "path index is not finished"});
    }
    const auto key = path_key(id_key_, root_uuid, path);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto read_at = [&](std::uint64_t index) -> domain::Result<std::array<std::byte, record_size>> {
        if (index > std::numeric_limits<std::uint64_t>::max() / record_size) {
            return std::unexpected(Error{ErrorCode::integrity, "path-index offset overflow"});
        }
        const auto positioned = sorted_->seek(index * record_size);
        if (!positioned) {
            return std::unexpected(positioned.error());
        }
        std::array<std::byte, record_size> record{};
        const auto read = sorted_->read_exact(record);
        if (!read) {
            return std::unexpected(read.error());
        }
        return record;
    };

    std::uint64_t low = 0;
    std::uint64_t high = record_count_;
    while (low < high) {
        const auto middle = low + (high - low) / 2;
        const auto record = read_at(middle);
        if (!record) {
            return std::unexpected(record.error());
        }
        if (std::lexicographical_compare(
                record->begin(),
                record->begin() + 32,
                key->begin(),
                key->end()
            )) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low == record_count_) {
        return std::optional<SnapshotPathMetadata>{};
    }
    const auto record = read_at(low);
    if (!record) {
        return std::unexpected(record.error());
    }
    if (!std::ranges::equal(std::span(*record).first<32>(), std::span(*key))) {
        return std::optional<SnapshotPathMetadata>{};
    }
    const auto metadata = decode_metadata(*record);
    if (metadata.type != SnapshotEntryType::directory
        && metadata.type != SnapshotEntryType::file
        && metadata.type != SnapshotEntryType::presence) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid path-index entry type"});
    }
    return metadata;
}

}
