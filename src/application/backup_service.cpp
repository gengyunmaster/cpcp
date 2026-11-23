#include "application/backup_service.hpp"

#include "crypto/file_identity.hpp"
#include "crypto/password.hpp"
#include "repository/chunk_set.hpp"
#include "repository/chunk_store.hpp"
#include "repository/config.hpp"
#include "platform/lock.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;
using repository::ChunkBatch;
using repository::DirectoryInfo;
using repository::FileEnd;
using repository::FileInfo;
using repository::PolicySkip;
using repository::RootInfo;
using repository::SnapshotStats;

namespace {

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

std::string relative_path(
    const std::filesystem::path& root,
    const std::filesystem::path& path
) {
    std::error_code error;
    const auto relative = std::filesystem::relative(path, root, error);
    if (error) {
        throw std::system_error(error);
    }
    for (const auto& component : relative) {
        if (component == "..") {
            throw std::invalid_argument("source path escapes its root");
        }
    }
    return relative.generic_string();
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
    return status.st_dev;
#endif
}

DirectoryInfo directory_info(
    std::uint32_t root,
    std::string path,
    const std::filesystem::path& native_path
) {
    const auto time = std::filesystem::file_time_type::clock::to_sys(
        std::filesystem::last_write_time(native_path)
    );
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
        time.time_since_epoch()
    ).count();
    const auto seconds = nanoseconds / 1000000000;
    return DirectoryInfo{
        root,
        std::move(path),
        seconds,
        static_cast<std::uint32_t>(nanoseconds % 1000000000),
        static_cast<std::uint32_t>(std::filesystem::status(native_path).permissions()),
    };
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

struct RemoveFile {
    std::filesystem::path path;
    ~RemoveFile() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
};

domain::Result<void> append_descriptor_batch(
    storage::SessionSpoolWriter& writer,
    const ChunkBatch& batch
) {
    nlohmann::json chunks = nlohmann::json::array();
    for (const auto& chunk : batch.chunks) {
        chunks.push_back({
            {"id", crypto::to_hex(chunk.chunk_id)},
            {"plain", chunk.plaintext_length},
            {"stored", std::to_string(chunk.stored_length)},
        });
    }
    const nlohmann::json document = {
        {"schema", "cpcp.chunk-batch.v1"},
        {"file", std::to_string(batch.file)},
        {"batch", std::to_string(batch.batch)},
        {"chunks", chunks},
    };
    const auto text = document.dump();
    const auto view = std::as_bytes(std::span(text));
    const domain::Bytes bytes(view.begin(), view.end());
    return writer.append(crypto::RecordType::chunk_batch, bytes);
}

domain::Result<void> add_base_evidence(
    const std::filesystem::path& repository,
    const repository::RepositoryConfig& config,
    const crypto::SecureKey& master,
    const repository::SnapshotSummary& parent,
    repository::ChunkStore& store,
    const crypto::SecureKey& id_key
) {
    if (parent.context.storage_epoch != config.storage_epoch) {
        return {};
    }
    auto reader = repository::SnapshotReader::open(repository, config, master, parent);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    auto set = repository::ChunkSetBuilder::create(
        repository / "tmp" / "base-evidence",
        id_key
    );
    if (!set) {
        return std::unexpected(set.error());
    }
    while (true) {
        auto record = reader->next();
        if (!record) {
            return std::unexpected(record.error());
        }
        if (!record->has_value()) {
            break;
        }
        if ((*record)->type != crypto::RecordType::chunk_batch) {
            continue;
        }
        auto batch = repository::parse_chunk_batch(**record);
        if (!batch) {
            return std::unexpected(batch.error());
        }
        for (const auto& chunk : batch->chunks) {
            store.allow_base_evidence(chunk.chunk_id);
            const auto added = set->add(chunk);
            if (!added) {
                return std::unexpected(added.error());
            }
        }
    }
    auto commitment = set->finish();
    if (!commitment || *commitment != parent.stats.chunk_set_commitment) {
        return std::unexpected(Error{ErrorCode::integrity, "base chunk-set commitment mismatch"});
    }
    return {};
}

}

domain::Result<BackupReport> backup_add(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const std::vector<std::filesystem::path>& roots,
    const BackupOptions& options
) {
    if (roots.empty()) {
        return std::unexpected(Error{ErrorCode::usage, "at least one source root is required"});
    }
    static_cast<void>(options.full_source_read);
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::backup(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto store = repository::ChunkStore::create(
        repository,
        unlocked->config,
        unlocked->master_key
    );
    if (!store) {
        return std::unexpected(store.error());
    }
    store->set_revalidate_all(options.revalidate_all);
    auto id_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::content_id);
    if (!id_key) {
        return std::unexpected(id_key.error());
    }
    auto journal_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::journal_encryption);
    if (!journal_key) {
        return std::unexpected(journal_key.error());
    }
    auto chunk_set = repository::ChunkSetBuilder::create(
        repository / "tmp" / "new-chunk-set",
        *id_key
    );
    if (!chunk_set) {
        return std::unexpected(chunk_set.error());
    }

    auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    std::optional<repository::SnapshotSummary> parent;
    if (!options.no_parent && !summaries->empty()) {
        parent = summaries->back();
        const auto evidence = add_base_evidence(repository, unlocked->config, unlocked->master_key, *parent, *store, *id_key);
        if (!evidence) {
            return std::unexpected(evidence.error());
        }
    }

    crypto::SnapshotContext context;
    context.repository_uuid = unlocked->config.repository_uuid;
    context.storage_epoch = unlocked->config.storage_epoch;
    context.snapshot_uuid = crypto::random_uuid();
    context.lineage_uuid = parent ? parent->context.lineage_uuid : crypto::random_uuid();
    context.generation = summaries->empty() ? 1 : summaries->back().context.generation + 1;
    auto writer = repository::SnapshotWriter::create(
        repository,
        unlocked->config,
        unlocked->master_key,
        context,
        crypto::random_uuid(),
        parent
    );
    if (!writer) {
        return std::unexpected(writer.error());
    }

    SnapshotStats stats;
    std::uint64_t skipped = 0;
    const auto canonical_repository = std::filesystem::weakly_canonical(repository);
    std::vector<std::string> labels;
    std::uint64_t file_sequence = 0;

    for (const auto& input_root : roots) {
        const auto root = std::filesystem::weakly_canonical(input_root);
        if (!std::filesystem::is_directory(root)) {
            return std::unexpected(Error{ErrorCode::usage, "source root is not a directory"});
        }
        if (path_prefix(canonical_repository, root)) {
            return std::unexpected(Error{ErrorCode::usage, "repository cannot be its own source root"});
        }
        if (path_prefix(root, canonical_repository)) {
            return std::unexpected(Error{ErrorCode::usage, "repository is inside a source root"});
        }

        const auto root_device = path_device(root);
        const auto label = root.filename().empty() ? "root" : root.filename().string();
        RootInfo root_record;
        root_record.index = static_cast<std::uint32_t>(labels.size());
        root_record.label = label;
        if (std::ranges::find(labels, label) != labels.end()) {
            root_record.label += "-" + std::to_string(labels.size());
        }
        labels.push_back(root_record.label);
        root_record.path = root.string();
        root_record.uuid = crypto::random_uuid();
        if (parent) {
            const auto previous = std::ranges::find_if(parent->roots, [&](const RootInfo& candidate) {
                return candidate.path == root_record.path;
            });
            if (previous != parent->roots.end()) {
                root_record.uuid = previous->uuid;
            }
        }
        auto appended = writer->append_root(root_record);
        if (!appended) {
            return std::unexpected(appended.error());
        }

        std::filesystem::recursive_directory_iterator iterator(root);
        const auto end = std::filesystem::recursive_directory_iterator();
        while (iterator != end) {
            const auto entry = *iterator;
            std::error_code error;
            const auto status = entry.symlink_status(error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
            const auto relative = relative_path(root, entry.path());
            if (!valid_utf8(relative)) {
                auto skipped_entry = writer->append_policy_skip(PolicySkip{
                    root_record.index,
                    display_path(relative),
                    "non-UTF-8 filename",
                });
                if (!skipped_entry) {
                    return std::unexpected(skipped_entry.error());
                }
                ++skipped;
                if (entry.is_directory()) {
                    iterator.disable_recursion_pending();
                }
                iterator.increment(error);
                if (error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                }
                continue;
            }

            if (std::filesystem::is_directory(status)) {
                if (path_prefix(canonical_repository, entry.path())) {
                    iterator.disable_recursion_pending();
                    iterator.increment(error);
                    if (error) {
                        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                    }
                    continue;
                }
                if (!options.cross_file_systems && path_device(entry.path()) != root_device) {
                    auto skipped_entry = writer->append_policy_skip(PolicySkip{
                        root_record.index,
                        relative,
                        "filesystem boundary",
                    });
                    if (!skipped_entry) {
                        return std::unexpected(skipped_entry.error());
                    }
                    ++skipped;
                    iterator.disable_recursion_pending();
                } else {
                    auto directory = directory_info(root_record.index, relative, entry.path());
                    appended = writer->append_directory(directory);
                    if (!appended) {
                        return std::unexpected(appended.error());
                    }
                    ++stats.directories;
                }
                iterator.increment(error);
                if (error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                }
                continue;
            }

            if (!std::filesystem::is_regular_file(status)) {
                auto skipped_entry = writer->append_policy_skip(PolicySkip{
                    root_record.index,
                    relative,
                    "unsupported entry type",
                });
                if (!skipped_entry) {
                    return std::unexpected(skipped_entry.error());
                }
                ++skipped;
                iterator.increment(error);
                if (error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                }
                continue;
            }

            auto file = platform::BinaryFile::open_read(entry.path());
            if (!file) {
                return std::unexpected(file.error());
            }
            const auto before = file->metadata().value();
            if (!options.cross_file_systems && before.device != root_device) {
                auto skipped_entry = writer->append_policy_skip(PolicySkip{
                    root_record.index,
                    relative,
                    "filesystem boundary",
                });
                if (!skipped_entry) {
                    return std::unexpected(skipped_entry.error());
                }
                ++skipped;
                iterator.increment(error);
                if (error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                }
                continue;
            }

            const auto expected_chunks = before.size / unlocked->config.chunk_size
                + (before.size % unlocked->config.chunk_size == 0 ? 0 : 1);
            crypto::FileIdentityBuilder identity;
            auto initialized = identity.initialize(
                *id_key,
                before.size,
                expected_chunks,
                unlocked->config.chunk_size
            );
            if (!initialized) {
                return std::unexpected(initialized.error());
            }
            std::vector<std::byte> buffer(unlocked->config.chunk_size);
            ChunkBatch batch;
            batch.file = file_sequence;
            batch.batch = 0;
            auto spool_context = context;
            spool_context.snapshot_uuid = crypto::random_uuid();
            spool_context.lineage_uuid = crypto::random_uuid();
            const auto spool_path = repository / "tmp"
                / (domain::hex_encode(spool_context.snapshot_uuid) + ".spool");
            RemoveFile spool_cleanup{spool_path};
            storage::SessionSpoolWriter descriptors;
            const auto spool_created = descriptors.create(
                spool_path,
                *journal_key,
                spool_context,
                crypto::StreamDomain::session_spool
            );
            if (!spool_created) {
                return std::unexpected(spool_created.error());
            }
            std::uint64_t chunk_count = 0;
            while (true) {
                const auto cancelled = platform::check_cancellation();
                if (!cancelled) {
                    return std::unexpected(cancelled.error());
                }
                const auto count = read_chunk(*file, buffer);
                if (!count) {
                    return std::unexpected(count.error());
                }
                if (*count == 0) {
                    break;
                }
                const auto chunk = store->put(std::span(buffer).first(*count));
                if (!chunk) {
                    return std::unexpected(chunk.error());
                }
                const crypto::ChunkDescriptor descriptor{chunk->id, chunk->plaintext_length, chunk->stored_length};
                const auto appended_chunk = identity.append(std::span(&descriptor, 1));
                if (!appended_chunk) {
                    return std::unexpected(appended_chunk.error());
                }
                batch.chunks.push_back(descriptor);
                ++chunk_count;
                ++stats.chunk_references;
                if (chunk->already_present) {
                    ++stats.deduplicated_chunks;
                } else {
                    ++stats.new_chunks;
                }
                const auto added = chunk_set->add(descriptor);
                if (!added) {
                    return std::unexpected(added.error());
                }
                if (batch.chunks.size() == 64) {
                    const auto spooled = append_descriptor_batch(descriptors, batch);
                    if (!spooled) {
                        return std::unexpected(spooled.error());
                    }
                    ++batch.batch;
                    batch.chunks.clear();
                }
            }
            const auto after = file->metadata().value();
            if (!same_identity(before, after)) {
                return std::unexpected(Error{ErrorCode::source_changed, "source file changed during backup"});
            }
            const auto file_id = identity.finish();
            if (!file_id) {
                return std::unexpected(file_id.error());
            }
            const FileInfo info{
                file_sequence,
                root_record.index,
                relative,
                before.size,
                chunk_count,
                *file_id,
                before.mtime_seconds,
                before.mtime_nanoseconds,
                before.mode,
            };
            appended = writer->append_file_header(info);
            if (!appended) {
                return std::unexpected(appended.error());
            }
            if (!batch.chunks.empty()) {
                const auto spooled = append_descriptor_batch(descriptors, batch);
                if (!spooled) {
                    return std::unexpected(spooled.error());
                }
            }
            const auto finalized = descriptors.finalize({});
            if (!finalized) {
                return std::unexpected(finalized.error());
            }
            storage::SessionSpoolReader replay;
            const auto opened = replay.open(
                spool_path,
                *journal_key,
                spool_context,
                crypto::StreamDomain::session_spool
            );
            if (!opened) {
                return std::unexpected(opened.error());
            }
            while (true) {
                auto record = replay.next();
                if (!record) {
                    return std::unexpected(record.error());
                }
                if (!record->has_value()) {
                    break;
                }
                if ((*record)->type != crypto::RecordType::chunk_batch) {
                    continue;
                }
                const auto parsed = repository::parse_chunk_batch(**record);
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                appended = writer->append_chunk_batch(*parsed);
                if (!appended) {
                    return std::unexpected(appended.error());
                }
            }
            appended = writer->append_file_end(FileEnd{file_sequence, chunk_count, *file_id});
            if (!appended) {
                return std::unexpected(appended.error());
            }
            ++stats.files;
            stats.logical_bytes += before.size;
            ++file_sequence;
            iterator.increment(error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
        }
    }

    const auto commitment = chunk_set->finish();
    if (!commitment) {
        return std::unexpected(commitment.error());
    }
    stats.chunk_set_commitment = *commitment;
    auto summary = writer->finish(stats);
    if (!summary) {
        return std::unexpected(summary.error());
    }
    return BackupReport{std::move(*summary), skipped};
}

}
