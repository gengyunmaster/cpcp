#include "application/check_service.hpp"

#include "crypto/file_identity.hpp"
#include "platform/cancellation.hpp"
#include "platform/lock.hpp"
#include "repository/chunk_store.hpp"
#include "repository/snapshot_index.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;
using repository::SnapshotEntryType;
using repository::SnapshotPathMetadata;

namespace {

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

bool path_prefix(const std::filesystem::path& prefix, const std::filesystem::path& path) {
    auto left = prefix.begin();
    auto right = path.begin();
    while (left != prefix.end() && right != path.end()) {
        if (*left != *right) {
            return false;
        }
        ++left;
        ++right;
    }
    return left == prefix.end();
}

bool selected_path(const std::string& path, const std::string& selection) {
    return selection.empty()
        || path == selection
        || (path.starts_with(selection)
            && path.size() > selection.size()
            && path[selection.size()] == '/');
}

bool glob_match(std::string_view pattern, std::string_view text) {
    std::size_t pattern_index = 0;
    std::size_t text_index = 0;
    std::size_t star = std::string_view::npos;
    std::size_t star_text = 0;
    while (text_index < text.size()) {
        if (pattern_index < pattern.size()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == text[text_index])) {
            ++pattern_index;
            ++text_index;
        } else if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
            star = pattern_index++;
            star_text = text_index;
        } else if (star != std::string_view::npos) {
            pattern_index = star + 1;
            text_index = ++star_text;
        } else {
            return false;
        }
    }
    while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
        ++pattern_index;
    }
    return pattern_index == pattern.size();
}

std::optional<std::string> exclusion_reason(
    const repository::SelectionPolicy& selection,
    const std::string& path
) {
    for (const auto& pattern : selection.exclusions) {
        if (glob_match(pattern, path)) {
            return "excluded: " + pattern;
        }
    }
    return std::nullopt;
}

std::string relative_path(
    const std::filesystem::path& root,
    const std::filesystem::path& path
) {
    const auto relative = path.lexically_relative(root);
    if (relative.empty()) {
        throw std::invalid_argument("source path cannot be made root-relative");
    }
    for (const auto& component : relative) {
        if (component == "..") {
            throw std::invalid_argument("source path escapes its root");
        }
    }
    return relative.generic_string();
}

bool valid_utf8(std::string_view input) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(input.data());
    std::size_t index = 0;
    while (index < input.size()) {
        const auto first = bytes[index++];
        if (first <= 0x7f) {
            continue;
        }
        std::size_t continuation = 0;
        unsigned int codepoint = 0;
        unsigned int minimum = 0;
        if ((first & 0xe0) == 0xc0) {
            continuation = 1;
            codepoint = first & 0x1f;
            minimum = 0x80;
        } else if ((first & 0xf0) == 0xe0) {
            continuation = 2;
            codepoint = first & 0x0f;
            minimum = 0x800;
        } else if ((first & 0xf8) == 0xf0) {
            continuation = 3;
            codepoint = first & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (index + continuation > input.size()) {
            return false;
        }
        for (std::size_t count = 0; count < continuation; ++count) {
            const auto next = bytes[index++];
            if ((next & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff
            || (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
            return false;
        }
    }
    return true;
}

std::string display_path(const std::string& path) {
    if (valid_utf8(path)) {
        return path;
    }
    const auto view = std::as_bytes(std::span(path));
    return "hex:" + domain::hex_encode(view);
}

std::uint64_t path_device(const std::filesystem::path& path) {
#ifdef _WIN32
    return std::hash<std::wstring>{}(path.root_path().wstring());
#else
    struct stat status {};
    if (stat(path.c_str(), &status) != 0) {
        throw std::system_error(errno, std::generic_category());
    }
    return static_cast<std::uint64_t>(status.st_dev);
#endif
}

SnapshotPathMetadata directory_metadata(const std::filesystem::path& path) {
    const auto time = std::filesystem::file_time_type::clock::to_sys(
        std::filesystem::last_write_time(path)
    );
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
        time.time_since_epoch()
    );
    const auto seconds = std::chrono::floor<std::chrono::seconds>(nanoseconds);
    SnapshotPathMetadata metadata;
    metadata.type = SnapshotEntryType::directory;
    metadata.mtime_seconds = seconds.count();
    metadata.mtime_nanoseconds = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(nanoseconds - seconds).count()
    );
    metadata.mode = static_cast<std::uint32_t>(
        std::filesystem::status(path).permissions()
    );
    return metadata;
}

SnapshotPathMetadata file_metadata(
    const platform::FileMetadata& metadata,
    const crypto::Digest& file_id = {}
) {
    SnapshotPathMetadata result;
    result.type = SnapshotEntryType::file;
    result.size = metadata.size;
    result.mtime_seconds = metadata.mtime_seconds;
    result.mtime_nanoseconds = metadata.mtime_nanoseconds;
    result.mode = metadata.mode;
    result.file_id = file_id;
    return result;
}

bool metadata_matches(
    const SnapshotPathMetadata& source,
    const SnapshotPathMetadata& snapshot
) {
    return source.type == snapshot.type
        && source.size == snapshot.size
        && source.mtime_seconds == snapshot.mtime_seconds
        && source.mtime_nanoseconds == snapshot.mtime_nanoseconds;
}

bool same_identity(const platform::FileMetadata& left, const platform::FileMetadata& right) {
    return left.size == right.size
        && left.mtime_seconds == right.mtime_seconds
        && left.mtime_nanoseconds == right.mtime_nanoseconds
        && left.device == right.device
        && left.inode == right.inode
        && left.mode == right.mode;
}

domain::Result<std::size_t> read_chunk(
    platform::BinaryFile& file,
    std::span<std::byte> output
) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count = file.read_some(output.subspan(offset));
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            break;
        }
        offset += *count;
    }
    return offset;
}

bool difference_status(std::string_view status) {
    return status != "metadata-match" && status != "content-match" && status != "verified";
}

}

domain::Result<CheckReport> check_backup(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const CheckOptions& options,
    const CheckEventSink& sink
) {
    if (!sink) {
        return std::unexpected(Error{ErrorCode::usage, "a check event consumer is required"});
    }
    if (options.verify_repo && !options.content) {
        return std::unexpected(Error{ErrorCode::usage, "--verify-repo requires --content"});
    }
    if (options.root && options.root_label) {
        return std::unexpected(Error{ErrorCode::usage, "root index and label are mutually exclusive"});
    }
    if (!options.path.empty() && !safe_relative(options.path, false)) {
        return std::unexpected(Error{ErrorCode::usage, "check path must remain relative to its root"});
    }

    std::error_code filesystem_error;
    const auto source = std::filesystem::weakly_canonical(options.source, filesystem_error);
    if (filesystem_error || !std::filesystem::is_directory(source)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "check source is not a directory"});
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
    const auto canonical_repository = std::filesystem::weakly_canonical(repository, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
    }
    if (path_prefix(canonical_repository, source)) {
        return std::unexpected(Error{ErrorCode::usage, "repository cannot be its own check source"});
    }

    const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    const auto selected = resolve_snapshot(*summaries, options.snapshot);
    if (!selected) {
        return std::unexpected(selected.error());
    }

    std::vector<repository::RootInfo> matching_roots;
    if (options.root) {
        std::ranges::copy_if(selected->roots, std::back_inserter(matching_roots), [&](const repository::RootInfo& root) {
            return root.index == *options.root;
        });
    } else if (options.root_label) {
        std::ranges::copy_if(selected->roots, std::back_inserter(matching_roots), [&](const repository::RootInfo& root) {
            return root.label == *options.root_label;
        });
    } else {
        std::ranges::copy_if(selected->roots, std::back_inserter(matching_roots), [&](const repository::RootInfo& root) {
            const auto original = std::filesystem::weakly_canonical(root.path, filesystem_error);
            return !filesystem_error && original == source;
        });
    }
    if (matching_roots.size() != 1) {
        const auto message = matching_roots.empty()
            ? "source does not identify one original root; use --root for a relocated tree"
            : "source matches multiple snapshot roots; use --root";
        return std::unexpected(Error{ErrorCode::usage, message});
    }
    const auto root = matching_roots.front();

    auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
    if (!store) {
        return std::unexpected(store.error());
    }
    const auto verified = verify_snapshot_manifest(
        repository,
        unlocked->config,
        unlocked->master_key,
        *selected,
        *store,
        options.verify_repo
    );
    if (!verified) {
        return std::unexpected(verified.error());
    }
    auto id_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::content_id);
    if (!id_key) {
        return std::unexpected(id_key.error());
    }
    const auto temporary_root = std::filesystem::temp_directory_path(filesystem_error);
    if (filesystem_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
    }
    const auto temporary = temporary_root / ("cpcp-check-" + domain::hex_encode(crypto::random_uuid()));
    auto snapshot_index = repository::SnapshotPathIndex::create(
        temporary / "snapshot",
        *id_key
    );
    if (!snapshot_index) {
        return std::unexpected(snapshot_index.error());
    }
    auto source_index = repository::SnapshotPathIndex::create(
        temporary / "source",
        *id_key
    );
    if (!source_index) {
        return std::unexpected(source_index.error());
    }

    auto reader = repository::SnapshotReader::open(repository, unlocked->config, unlocked->master_key, *selected);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    while (true) {
        auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        if ((*record)->type == crypto::RecordType::file_header) {
            const auto file = repository::parse_file_header(**record);
            if (!file) {
                return std::unexpected(file.error());
            }
            if (file->root == root.index && selected_path(file->path, options.path)) {
                SnapshotPathMetadata metadata;
                metadata.type = SnapshotEntryType::file;
                metadata.size = file->size;
                metadata.mtime_seconds = file->mtime_seconds;
                metadata.mtime_nanoseconds = file->mtime_nanoseconds;
                metadata.mode = file->mode;
                metadata.file_id = file->file_id;
                const auto added = snapshot_index->add(root.uuid, file->path, metadata);
                if (!added) {
                    return std::unexpected(added.error());
                }
            }
        } else if ((*record)->type == crypto::RecordType::directory) {
            const auto directory = repository::parse_directory(**record);
            if (!directory) {
                return std::unexpected(directory.error());
            }
            if (directory->root == root.index && selected_path(directory->path, options.path)) {
                SnapshotPathMetadata metadata;
                metadata.type = SnapshotEntryType::directory;
                metadata.mtime_seconds = directory->mtime_seconds;
                metadata.mtime_nanoseconds = directory->mtime_nanoseconds;
                metadata.mode = directory->mode;
                const auto added = snapshot_index->add(root.uuid, directory->path, metadata);
                if (!added) {
                    return std::unexpected(added.error());
                }
            }
        }
    }
    const auto indexed = snapshot_index->finish();
    if (!indexed) {
        return std::unexpected(indexed.error());
    }

    CheckReport report;
    report.snapshot_generation = selected->context.generation;
    report.snapshot_status = selected->status;
    report.root = root.index;
    report.root_label = root.label;
    report.repository_chunk_references = options.verify_repo ? *verified : 0;
    report.mode = options.verify_repo ? "content+repository" : options.content ? "content" : "metadata";
    const auto emit = [&](CheckEvent event) -> domain::Result<void> {
        ++report.total;
        if (difference_status(event.status)) {
            ++report.differences;
        }
        return sink(event);
    };
    const auto root_device = path_device(source);
    std::filesystem::recursive_directory_iterator iterator(source);
    const auto end = std::filesystem::recursive_directory_iterator();
    while (iterator != end) {
        const auto cancelled = platform::check_cancellation();
        if (!cancelled) {
            return std::unexpected(cancelled.error());
        }
        const auto entry = *iterator;
        std::error_code error;
        const auto status = entry.symlink_status(error);
        if (error) {
            return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
        }
        const auto relative = relative_path(source, entry.path());
        const auto displayed = display_path(relative);
        const auto advance = [&]() -> domain::Result<void> {
            iterator.increment(error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
            return {};
        };
        if (!valid_utf8(relative)) {
            const auto emitted = emit(CheckEvent{
                root.index,
                displayed,
                selected->selection_policy.unsupported == "skip" ? "skipped" : "unsupported",
                "non-UTF-8 filename",
            });
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            if (entry.is_directory()) {
                iterator.disable_recursion_pending();
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }
        const bool in_scope = selected_path(relative, options.path);
        if (const auto excluded = exclusion_reason(selected->selection_policy, relative)) {
            if (in_scope) {
                const auto emitted = emit(CheckEvent{root.index, relative, "skipped", *excluded, 0});
                if (!emitted) {
                    return std::unexpected(emitted.error());
                }
            }
            if (std::filesystem::is_directory(status)) {
                iterator.disable_recursion_pending();
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }

        if (std::filesystem::is_directory(status)) {
            if (path_prefix(canonical_repository, entry.path())) {
                iterator.disable_recursion_pending();
                const auto advanced = advance();
                if (!advanced) {
                    return std::unexpected(advanced.error());
                }
                continue;
            }
            if (selected->selection_policy.one_file_system && path_device(entry.path()) != root_device) {
                if (in_scope) {
                    const auto emitted = emit(CheckEvent{root.index, relative, "skipped", "filesystem boundary"});
                    if (!emitted) {
                        return std::unexpected(emitted.error());
                    }
                }
                iterator.disable_recursion_pending();
            } else if (in_scope) {
                const auto metadata = directory_metadata(entry.path());
                const auto previous = snapshot_index->find(root.uuid, relative);
                if (!previous) {
                    return std::unexpected(previous.error());
                }
                const auto present = source_index->add(root.uuid, relative, SnapshotPathMetadata{});
                if (!present) {
                    return std::unexpected(present.error());
                }
                std::string event_status = "added";
                if (*previous) {
                    event_status = metadata_matches(metadata, **previous)
                        ? "metadata-match"
                        : (*previous)->type == SnapshotEntryType::directory ? "changed" : "type-changed";
                }
                const auto emitted = emit(CheckEvent{root.index, relative, event_status, "", 0});
                if (!emitted) {
                    return std::unexpected(emitted.error());
                }
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }

        if (!std::filesystem::is_regular_file(status)) {
            if (in_scope) {
                const auto emitted = emit(CheckEvent{
                    root.index,
                    relative,
                    selected->selection_policy.unsupported == "skip" ? "skipped" : "unsupported",
                    "unsupported entry type",
                });
                if (!emitted) {
                    return std::unexpected(emitted.error());
                }
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }
        if (!in_scope) {
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }

        const auto previous = snapshot_index->find(root.uuid, relative);
        if (!previous) {
            return std::unexpected(previous.error());
        }
        const auto present = source_index->add(root.uuid, relative, SnapshotPathMetadata{});
        if (!present) {
            return std::unexpected(present.error());
        }
        if (!*previous) {
            const auto emitted = emit(CheckEvent{root.index, relative, "added", "", 0});
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }
        if ((*previous)->type != SnapshotEntryType::file) {
            const auto emitted = emit(CheckEvent{root.index, relative, "type-changed", "", 0});
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }

        auto file = platform::BinaryFile::open_read(entry.path());
        if (!file) {
            const auto emitted = emit(CheckEvent{root.index, relative, "unreadable", file.error().message});
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }
        const auto before_result = file->metadata();
        if (!before_result) {
            return std::unexpected(before_result.error());
        }
        const auto before = *before_result;
        if (selected->selection_policy.one_file_system && before.device != root_device) {
            const auto emitted = emit(CheckEvent{root.index, relative, "skipped", "filesystem boundary"});
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
            continue;
        }
        const auto source_metadata = file_metadata(before);
        const bool metadata_match = metadata_matches(source_metadata, **previous);
        std::string event_status = metadata_match ? "metadata-match" : "changed";
        std::string reason;
        if (options.content) {
            crypto::FileIdentityBuilder identity;
            const auto expected_chunks = before.size / unlocked->config.chunk_size
                + (before.size % unlocked->config.chunk_size == 0 ? 0 : 1);
            const auto initialized = identity.initialize(
                *id_key,
                before.size,
                expected_chunks,
                unlocked->config.chunk_size
            );
            if (!initialized) {
                return std::unexpected(initialized.error());
            }
            std::vector<std::byte> buffer(unlocked->config.chunk_size);
            bool read_failed = false;
            while (true) {
                const auto cancelled_read = platform::check_cancellation();
                if (!cancelled_read) {
                    return std::unexpected(cancelled_read.error());
                }
                const auto count = read_chunk(*file, buffer);
                if (!count) {
                    event_status = "unreadable";
                    reason = count.error().message;
                    read_failed = true;
                    break;
                }
                if (*count == 0) {
                    break;
                }
                const auto chunk_id = crypto::compute_chunk_id(
                    *id_key,
                    std::span(buffer).first(*count)
                );
                if (!chunk_id) {
                    return std::unexpected(chunk_id.error());
                }
                const crypto::ChunkDescriptor descriptor{
                    *chunk_id,
                    static_cast<std::uint32_t>(*count),
                    0,
                };
                const auto appended = identity.append(std::span(&descriptor, 1));
                if (!appended) {
                    return std::unexpected(appended.error());
                }
            }
            if (!read_failed) {
                const auto after_result = file->metadata();
                if (!after_result) {
                    return std::unexpected(after_result.error());
                }
                if (!same_identity(before, *after_result)) {
                    event_status = "unreadable";
                    reason = "source file changed during content comparison";
                } else {
                    const auto actual_id = identity.finish();
                    if (!actual_id) {
                        return std::unexpected(actual_id.error());
                    }
                    if (*actual_id != (*previous)->file_id) {
                        event_status = "changed";
                        reason = "file content identity differs";
                    } else if (!metadata_match) {
                        event_status = "changed";
                        reason = "file content matches but metadata differs";
                    } else {
                        event_status = options.verify_repo ? "verified" : "content-match";
                    }
                }
            }
        }
        const auto emitted = emit(CheckEvent{root.index, relative, event_status, reason, before.size});
        if (!emitted) {
            return std::unexpected(emitted.error());
        }
        const auto advanced = advance();
        if (!advanced) {
            return std::unexpected(advanced.error());
        }
    }
    const auto source_finished = source_index->finish();
    if (!source_finished) {
        return std::unexpected(source_finished.error());
    }

    reader = repository::SnapshotReader::open(repository, unlocked->config, unlocked->master_key, *selected);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    while (true) {
        auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        std::optional<CheckEvent> event;
        if ((*record)->type == crypto::RecordType::file_header) {
            const auto file = repository::parse_file_header(**record);
            if (!file) {
                return std::unexpected(file.error());
            }
            if (file->root == root.index && selected_path(file->path, options.path)) {
                const auto present = source_index->find(root.uuid, file->path);
                if (!present) {
                    return std::unexpected(present.error());
                }
                if (!*present) {
                    event = CheckEvent{root.index, file->path, "missing", "", file->size};
                }
            }
        } else if ((*record)->type == crypto::RecordType::directory) {
            const auto directory = repository::parse_directory(**record);
            if (!directory) {
                return std::unexpected(directory.error());
            }
            if (directory->root == root.index && selected_path(directory->path, options.path)) {
                const auto present = source_index->find(root.uuid, directory->path);
                if (!present) {
                    return std::unexpected(present.error());
                }
                if (!*present) {
                    event = CheckEvent{root.index, directory->path, "missing", "", 0};
                }
            }
        } else if ((*record)->type == crypto::RecordType::failure) {
            const auto failure = repository::parse_failure(**record);
            if (!failure) {
                return std::unexpected(failure.error());
            }
            if (failure->root == root.index && selected_path(failure->path, options.path)) {
                event = CheckEvent{root.index, failure->path, "unreadable", failure->reason};
            }
        }
        if (event) {
            const auto emitted = emit(*event);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
        }
    }
    return report;
}

}
