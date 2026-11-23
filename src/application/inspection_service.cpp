#include "application/inspection_service.hpp"

#include "crypto/file_identity.hpp"
#include "repository/chunk_store.hpp"
#include "platform/binary_file.hpp"
#include "platform/lock.hpp"
#include "platform/cancellation.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;
using repository::DirectoryInfo;
using repository::FileInfo;

namespace {

struct RemoveFile {
    std::filesystem::path path;
    ~RemoveFile() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
};

bool safe_label(const std::string& label) {
    if (label.empty() || label == "." || label == ".." || label == "CON"
        || label == "PRN" || label == "AUX" || label == "NUL") {
        return false;
    }
    return label.find_first_of("/\\:") == std::string::npos
        && label.front() != ' ' && label.back() != ' '
        && label.front() != '.' && label.back() != '.';
}

bool safe_relative(const std::string& path, bool allow_empty) {
    if (path.empty()) {
        return allow_empty;
    }
    const std::filesystem::path native(path);
    if (native.is_absolute() || native.has_root_name()) {
        return false;
    }
    for (const auto& component : native) {
        if (component == ".." || component.empty()) {
            return false;
        }
    }
    return true;
}

std::size_t path_depth(const std::string& path) {
    if (path.empty() || path == ".") {
        return 0;
    }
    return static_cast<std::size_t>(std::distance(
        std::filesystem::path(path).begin(),
        std::filesystem::path(path).end()
    ));
}

bool same_stats(
    const repository::SnapshotStats& left,
    const repository::SnapshotStats& right
) {
    return left.files == right.files
        && left.directories == right.directories
        && left.logical_bytes == right.logical_bytes
        && left.chunk_references == right.chunk_references
        && left.new_chunks == right.new_chunks
        && left.deduplicated_chunks == right.deduplicated_chunks
        && left.chunk_set_commitment == right.chunk_set_commitment;
}

domain::Result<std::uint64_t> verify_snapshot(
    const std::filesystem::path& repository,
    const repository::RepositoryConfig& config,
    const crypto::SecureKey& master,
    const repository::SnapshotSummary& summary,
    repository::ChunkStore& store,
    bool deep
) {
    auto reader = repository::SnapshotReader::open(repository, config, master, summary);
    if (!reader) {
        return std::unexpected(reader.error());
    }

    std::optional<FileInfo> current;
    std::optional<crypto::FileIdentityBuilder> identity;
    std::uint64_t expected_batch = 0;
    std::uint64_t chunk_count = 0;
    while (true) {
        auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        switch ((*record)->type) {
        case crypto::RecordType::file_header: {
            auto header = repository::parse_file_header(**record);
            if (!header) {
                return std::unexpected(header.error());
            }
            if (!safe_relative(header->path, false)) {
                return std::unexpected(Error{ErrorCode::integrity, "unsafe snapshot path"});
            }
            current = *header;
            expected_batch = 0;
            identity.emplace();
            const auto initialized = identity->initialize(
                *crypto::derive_key(master, crypto::KeyPurpose::content_id),
                current->size,
                current->chunk_count,
                config.chunk_size
            );
            if (!initialized) {
                return std::unexpected(initialized.error());
            }
            break;
        }
        case crypto::RecordType::chunk_batch: {
            auto batch = repository::parse_chunk_batch(**record);
            if (!batch || !current || batch->file != current->sequence
                || batch->batch != expected_batch) {
                return std::unexpected(Error{ErrorCode::integrity, "invalid chunk batch sequence"});
            }
            ++expected_batch;
            for (const auto& chunk : batch->chunks) {
                if (!identity) {
                    return std::unexpected(Error{ErrorCode::integrity, "chunk batch has no file identity"});
                }
                const auto appended = identity->append(std::span(&chunk, 1));
                if (!appended) {
                    return std::unexpected(appended.error());
                }
                const repository::ChunkMetadata metadata{
                    chunk.chunk_id,
                    chunk.plaintext_length,
                    chunk.stored_length,
                    false,
                };
                if (deep) {
                    const auto validated = store.validate(metadata);
                    if (!validated) {
                        return std::unexpected(validated.error());
                    }
                } else {
                    const auto inspected = store.inspect(metadata);
                    if (!inspected) {
                        return std::unexpected(inspected.error());
                    }
                }
                ++chunk_count;
            }
            break;
        }
        case crypto::RecordType::file_end: {
            auto end = repository::parse_file_end(**record);
            if (!end || !current || end->file != current->sequence
                || end->chunk_count != current->chunk_count
                || end->file_id != current->file_id || !identity) {
                return std::unexpected(Error{ErrorCode::integrity, "file-end does not match its header"});
            }
            const auto digest = identity->finish();
            if (!digest || *digest != current->file_id) {
                return std::unexpected(Error{ErrorCode::integrity, "file identity mismatch"});
            }
            current.reset();
            identity.reset();
            break;
        }
        case crypto::RecordType::root: {
            auto root = repository::parse_root(**record);
            if (!root || !safe_label(root->label)) {
                return std::unexpected(Error{ErrorCode::integrity, "invalid root record"});
            }
            break;
        }
        case crypto::RecordType::directory: {
            auto directory = repository::parse_directory(**record);
            if (!directory || !safe_relative(directory->path, true)) {
                return std::unexpected(Error{ErrorCode::integrity, "invalid directory record"});
            }
            break;
        }
        case crypto::RecordType::policy_skip: {
            auto skipped = repository::parse_policy_skip(**record);
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            break;
        }
        case crypto::RecordType::final_summary: {
            auto stats = repository::parse_final_stats(**record);
            if (!stats || !same_stats(*stats, summary.stats)) {
                return std::unexpected(Error{ErrorCode::integrity, "snapshot final statistics mismatch"});
            }
            break;
        }
        case crypto::RecordType::context:
        case crypto::RecordType::snapshot_header:
        case crypto::RecordType::failure:
            break;
        }
    }
    if (current || identity) {
        return std::unexpected(Error{ErrorCode::integrity, "snapshot ends with an incomplete file"});
    }
    return chunk_count;
}

std::filesystem::path output_path(
    const std::filesystem::path& destination,
    const repository::SnapshotSummary& summary,
    std::uint32_t root,
    const std::string& relative,
    bool strip_root
) {
    const auto root_info = std::ranges::find_if(summary.roots, [&](const repository::RootInfo& candidate) {
        return candidate.index == root;
    });
    if (root_info == summary.roots.end()) {
        throw std::invalid_argument("snapshot root does not exist");
    }
    if (!safe_label(root_info->label) || !safe_relative(relative, true)) {
        throw std::invalid_argument("unsafe restore path");
    }
    auto output = destination;
    if (!strip_root) {
        output /= root_info->label;
    }
    if (!relative.empty() && relative != ".") {
        output /= std::filesystem::path(relative);
    }
    return output;
}

domain::Result<void> apply_metadata(
    const std::filesystem::path& path,
    std::int64_t seconds,
    std::uint32_t nanoseconds,
    std::uint32_t mode,
    bool strict,
    std::uint64_t& warnings
) {
    std::error_code error;
    const auto safe_mode = mode & ~06000U;
    std::filesystem::permissions(
        path,
        static_cast<std::filesystem::perms>(safe_mode),
        std::filesystem::perm_options::replace,
        error
    );
    if (error) {
        ++warnings;
        if (strict) {
            return std::unexpected(Error{ErrorCode::source_changed, error.message()});
        }
    }

    const std::chrono::system_clock::time_point timestamp{
        std::chrono::seconds{seconds} + std::chrono::nanoseconds{nanoseconds}
    };
    const auto file_time = std::filesystem::file_time_type::clock::from_sys(timestamp);
    std::filesystem::last_write_time(path, file_time, error);
    if (error) {
        ++warnings;
        if (strict) {
            return std::unexpected(Error{ErrorCode::source_changed, error.message()});
        }
    }
    return {};
}

}

domain::Result<RestoreReport> restore_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::optional<std::uint64_t> generation,
    const RestoreOptions& options
) {
    if (options.destination.empty()) {
        return std::unexpected(Error{ErrorCode::usage, "restore destination is required"});
    }
    if (options.overwrite && !options.yes) {
        return std::unexpected(Error{ErrorCode::usage, "overwrite requires --yes"});
    }
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = options.repo_read_only
        ? domain::Result<platform::RepositoryLocks>{}
        : platform::RepositoryLocks::read(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries || summaries->empty()) {
        return std::unexpected(Error{ErrorCode::permanent_io, "no snapshots are available"});
    }
    const auto summary = generation
        ? std::ranges::find_if(*summaries, [&](const repository::SnapshotSummary& candidate) {
            return candidate.context.generation == *generation;
        })
        : std::ranges::prev(summaries->end());
    if (summary == summaries->end()) {
        return std::unexpected(Error{ErrorCode::permanent_io, "snapshot generation was not found"});
    }
    if (options.path && !safe_relative(*options.path, false)) {
        return std::unexpected(Error{ErrorCode::usage, "restore path must remain relative to its root"});
    }
    if (options.path && !options.root && summary->roots.size() != 1) {
        return std::unexpected(Error{ErrorCode::usage, "--root is required with --path in a multi-root snapshot"});
    }
    if (options.root && !std::ranges::any_of(summary->roots, [&](const repository::RootInfo& root) {
        return root.index == *options.root;
    })) {
        return std::unexpected(Error{ErrorCode::usage, "requested root does not exist"});
    }

    auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
    if (!store) {
        return std::unexpected(store.error());
    }
    const auto verified = verify_snapshot(repository, unlocked->config, unlocked->master_key, *summary, *store, false);
    if (!verified) {
        return std::unexpected(verified.error());
    }

    std::error_code filesystem_error;
    std::filesystem::create_directories(options.destination, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
    }
    auto reader = repository::SnapshotReader::open(repository, unlocked->config, unlocked->master_key, *summary);
    if (!reader) {
        return std::unexpected(reader.error());
    }

    RestoreReport report;
    std::optional<FileInfo> current;
    std::optional<crypto::FileIdentityBuilder> identity;
    std::optional<platform::BinaryFile> output;
    std::filesystem::path temporary;
    std::vector<std::pair<DirectoryInfo, std::filesystem::path>> directories;
    std::uint64_t expected_batch = 0;

    const auto selected_root = [&](std::uint32_t root) {
        return !options.root || *options.root == root;
    };
    const auto selected_file = [&](const FileInfo& file) {
        return selected_root(file.root) && (!options.path || *options.path == file.path);
    };
    const auto selected_directory = [&](const DirectoryInfo& directory) {
        if (!selected_root(directory.root)) {
            return false;
        }
        if (!options.path) {
            return true;
        }
        const auto& target = *options.path;
        if (directory.path.empty() || directory.path == ".") {
            return true;
        }
        return target.starts_with(directory.path)
            && (target.size() == directory.path.size()
                || target[directory.path.size()] == '/');
    };
    const auto pop_directories = [&](std::size_t depth) -> domain::Result<void> {
        while (directories.size() > depth) {
            auto result = apply_metadata(
                directories.back().second,
                directories.back().first.mtime_seconds,
                directories.back().first.mtime_nanoseconds,
                directories.back().first.mode,
                options.strict_metadata,
                report.metadata_warnings
            );
            if (!result) {
                return std::unexpected(result.error());
            }
            directories.pop_back();
            ++report.directories;
        }
        return domain::Result<void>{};
    };

    while (true) {
        auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        switch ((*record)->type) {
        case crypto::RecordType::directory: {
            auto directory = repository::parse_directory(**record);
            if (!directory) {
                return std::unexpected(directory.error());
            }
            if (selected_directory(*directory)) {
                const auto depth = path_depth(directory->path) + 1;
                const auto popped = pop_directories(depth);
                if (!popped) {
                    return std::unexpected(popped.error());
                }
                auto path = output_path(
                    options.destination,
                    *summary,
                    directory->root,
                    directory->path,
                    options.strip_root
                );
                std::filesystem::create_directories(path, filesystem_error);
                if (filesystem_error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
                }
                directories.emplace_back(*directory, std::move(path));
            }
            break;
        }
        case crypto::RecordType::file_header: {
            auto header = repository::parse_file_header(**record);
            if (!header) {
                return std::unexpected(header.error());
            }
            current = *header;
            expected_batch = 0;
            if (!selected_file(*header)) {
                break;
            }
            temporary = options.destination / "tmp"
                / (domain::hex_encode(crypto::random_uuid()) + ".part");
            std::filesystem::create_directories(temporary.parent_path(), filesystem_error);
            if (filesystem_error) {
                return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
            }
            output.emplace(platform::BinaryFile::create_new(temporary).value());
            identity.emplace();
            const auto initialized = identity->initialize(
                *crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::content_id),
                current->size,
                current->chunk_count,
                unlocked->config.chunk_size
            );
            if (!initialized) {
                return std::unexpected(initialized.error());
            }
            break;
        }
        case crypto::RecordType::chunk_batch: {
            auto batch = repository::parse_chunk_batch(**record);
            if (!batch || !current || batch->file != current->sequence
                || batch->batch != expected_batch) {
                return std::unexpected(Error{ErrorCode::integrity, "restore batch sequence mismatch"});
            }
            ++expected_batch;
            if (!output || !identity) {
                break;
            }
            for (const auto& chunk : batch->chunks) {
                const auto cancelled = platform::check_cancellation();
                if (!cancelled) {
                    return std::unexpected(cancelled.error());
                }
                const repository::ChunkMetadata metadata{
                    chunk.chunk_id,
                    chunk.plaintext_length,
                    chunk.stored_length,
                    false,
                };
                auto plaintext = store->get(metadata);
                if (!plaintext) {
                    return std::unexpected(plaintext.error());
                }
                const auto appended = identity->append(std::span(&chunk, 1));
                if (!appended) {
                    return std::unexpected(appended.error());
                }
                const auto written = output->write_all(*plaintext);
                if (!written) {
                    return std::unexpected(written.error());
                }
            }
            break;
        }
        case crypto::RecordType::file_end: {
            auto end = repository::parse_file_end(**record);
            if (!end || !current || end->file != current->sequence
                || end->chunk_count != current->chunk_count
                || end->file_id != current->file_id) {
                return std::unexpected(Error{ErrorCode::integrity, "restore file-end mismatch"});
            }
            if (output && identity) {
                const auto digest = identity->finish();
                if (!digest || *digest != current->file_id) {
                    return std::unexpected(Error{ErrorCode::integrity, "restored file identity mismatch"});
                }
                auto result = output->flush();
                if (!result) {
                    return std::unexpected(result.error());
                }
                result = output->close();
                if (!result) {
                    return std::unexpected(result.error());
                }
                output.reset();
                const auto final = output_path(
                    options.destination,
                    *summary,
                    current->root,
                    current->path,
                    options.strip_root
                );
                std::filesystem::create_directories(final.parent_path(), filesystem_error);
                if (filesystem_error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
                }
                result = apply_metadata(
                    temporary,
                    current->mtime_seconds,
                    current->mtime_nanoseconds,
                    current->mode,
                    options.strict_metadata,
                    report.metadata_warnings
                );
                if (!result) {
                    return std::unexpected(result.error());
                }
                if (options.overwrite) {
                    result = platform::replace_file(temporary, final);
                } else {
                    result = platform::publish_no_replace(temporary, final);
                }
                if (!result) {
                    return std::unexpected(result.error());
                }
                result = platform::sync_directory(final.parent_path());
                if (!result) {
                    return std::unexpected(result.error());
                }
                ++report.files;
            }
            current.reset();
            identity.reset();
            output.reset();
            temporary.clear();
            break;
        }
        case crypto::RecordType::root:
        case crypto::RecordType::context:
        case crypto::RecordType::snapshot_header:
        case crypto::RecordType::policy_skip:
        case crypto::RecordType::failure:
            break;
        case crypto::RecordType::final_summary:
            break;
        }
    }
    const auto popped = pop_directories(0);
    if (!popped) {
        return std::unexpected(popped.error());
    }
    if (current || identity || output) {
        return std::unexpected(Error{ErrorCode::integrity, "restore ended with an incomplete file"});
    }
    if (options.path && report.files == 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "requested restore path was not found"});
    }
    return report;
}

domain::Result<VerifyReport> verify_repository(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const VerifyOptions& options
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = options.repo_read_only
        ? domain::Result<platform::RepositoryLocks>{}
        : platform::RepositoryLocks::read(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
    if (!store) {
        return std::unexpected(store.error());
    }
    const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }

    VerifyReport report;
    report.degraded_redundancy = unlocked->degraded_redundancy;
    for (const auto& summary : *summaries) {
        const auto checked = verify_snapshot(repository, unlocked->config, unlocked->master_key, summary, *store, options.deep);
        if (!checked) {
            return std::unexpected(checked.error());
        }
        ++report.snapshots;
        report.chunks += *checked;
    }
    return report;
}

}
