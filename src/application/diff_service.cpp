#include "application/diff_service.hpp"

#include "application/inspection_service.hpp"
#include "platform/lock.hpp"
#include "repository/chunk_store.hpp"
#include "repository/snapshot_index.hpp"

#include <algorithm>
#include <system_error>

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;

namespace {

domain::Result<repository::SnapshotPathMetadata> symlink_metadata(
    const repository::SymlinkInfo& link,
    const crypto::SecureKey& id_key
);

domain::Result<repository::SnapshotPathIndex> build_index(
    const std::filesystem::path& repository,
    const repository::RepositoryConfig& config,
    const crypto::SecureKey& master,
    const repository::SnapshotSummary& summary,
    repository::ChunkStore& store,
    const crypto::SecureKey& id_key,
    const std::filesystem::path& temporary
) {
    const auto verified = verify_snapshot_manifest(repository, config, master, summary, store, false);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    auto index = repository::SnapshotPathIndex::create(temporary, id_key);
    if (!index) {
        return std::unexpected(index.error());
    }
    auto reader = repository::SnapshotReader::open(repository, config, master, summary);
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
        std::optional<repository::RootInfo> root;
        repository::SnapshotPathMetadata metadata;
        std::string path;
        if ((*record)->type == crypto::RecordType::file_header) {
            const auto file = repository::parse_file_header(**record);
            if (!file) {
                return std::unexpected(file.error());
            }
            const auto found = std::ranges::find_if(summary.roots, [&](const repository::RootInfo& candidate) {
                return candidate.index == file->root;
            });
            if (found != summary.roots.end()) {
                root = *found;
            }
            metadata.type = repository::SnapshotEntryType::file;
            metadata.size = file->size;
            metadata.mtime_seconds = file->mtime_seconds;
            metadata.mtime_nanoseconds = file->mtime_nanoseconds;
            metadata.mode = file->mode;
            metadata.file_id = file->file_id;
            path = file->path;
        } else if ((*record)->type == crypto::RecordType::directory) {
            const auto directory = repository::parse_directory(**record);
            if (!directory) {
                return std::unexpected(directory.error());
            }
            const auto found = std::ranges::find_if(summary.roots, [&](const repository::RootInfo& candidate) {
                return candidate.index == directory->root;
            });
            if (found != summary.roots.end()) {
                root = *found;
            }
            metadata.type = repository::SnapshotEntryType::directory;
            metadata.mtime_seconds = directory->mtime_seconds;
            metadata.mtime_nanoseconds = directory->mtime_nanoseconds;
            metadata.mode = directory->mode;
            path = directory->path;
        } else if ((*record)->type == crypto::RecordType::symlink) {
            const auto link = repository::parse_symlink(**record);
            if (!link) {
                return std::unexpected(link.error());
            }
            const auto found = std::ranges::find_if(summary.roots, [&](const repository::RootInfo& candidate) {
                return candidate.index == link->root;
            });
            if (found != summary.roots.end()) {
                root = *found;
            }
            const auto parsed = symlink_metadata(*link, id_key);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            metadata = *parsed;
            path = link->path;
        } else {
            continue;
        }
        if (!root) {
            return std::unexpected(Error{ErrorCode::integrity, "snapshot entry references an unknown root"});
        }
        const auto added = index->add(root->uuid, path, metadata);
        if (!added) {
            return std::unexpected(added.error());
        }
    }
    const auto finished = index->finish();
    if (!finished) {
        return std::unexpected(finished.error());
    }
    return index;
}

domain::Result<repository::SnapshotPathMetadata> symlink_metadata(
    const repository::SymlinkInfo& link,
    const crypto::SecureKey& id_key
) {
    domain::Bytes input;
    for (const char value : "cpcp.symlink.v1") {
        input.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    const auto bytes = std::as_bytes(std::span(link.target));
    input.insert(input.end(), bytes.begin(), bytes.end());
    const auto id = crypto::compute_hmac_sha256(id_key, input);
    if (!id) {
        return std::unexpected(id.error());
    }
    repository::SnapshotPathMetadata metadata;
    metadata.type = repository::SnapshotEntryType::symlink;
    metadata.mtime_seconds = link.mtime_seconds;
    metadata.mtime_nanoseconds = link.mtime_nanoseconds;
    metadata.mode = link.mode;
    metadata.file_id = *id;
    return metadata;
}

bool difference(std::string_view status) {
    return status != "unchanged";
}

}

domain::Result<DiffReport> diff_snapshots(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t left,
    std::uint64_t right,
    const DiffEventSink& sink
) {
    if (!sink) {
        return std::unexpected(Error{ErrorCode::usage, "a diff event consumer is required"});
    }
    if (left == right) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot diff requires two different generations"});
    }
    const auto locks = platform::RepositoryLocks::read(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    const auto left_summary = resolve_snapshot(*summaries, SnapshotRequest{left, false});
    const auto right_summary = resolve_snapshot(*summaries, SnapshotRequest{right, false});
    if (!left_summary || !right_summary) {
        return std::unexpected(Error{ErrorCode::permanent_io, "diff snapshot generation was not found"});
    }
    auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
    if (!store) {
        return std::unexpected(store.error());
    }
    const auto id_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::content_id);
    if (!id_key) {
        return std::unexpected(id_key.error());
    }
    const auto temporary = std::filesystem::temp_directory_path()
        / ("cpcp-diff-" + domain::hex_encode(crypto::random_uuid()));
    auto left_index = build_index(repository, unlocked->config, unlocked->master_key, *left_summary, *store, *id_key, temporary / "left");
    if (!left_index) {
        return std::unexpected(left_index.error());
    }
    auto right_index = build_index(repository, unlocked->config, unlocked->master_key, *right_summary, *store, *id_key, temporary / "right");
    if (!right_index) {
        return std::unexpected(right_index.error());
    }

    DiffReport report;
    report.left = left;
    report.right = right;
    report.left_status = left_summary->status;
    report.right_status = right_summary->status;
    const auto emit = [&](DiffEvent event) -> domain::Result<void> {
        ++report.total;
        if (difference(event.status)) {
            ++report.differences;
        }
        return sink(event);
    };
    const auto compare = [&](const repository::SnapshotSummary& from, const repository::SnapshotSummary& to, bool additions) -> domain::Result<void> {
        auto reader = repository::SnapshotReader::open(repository, unlocked->config, unlocked->master_key, from);
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
            const repository::RootInfo* root = nullptr;
            const repository::RootInfo* other_root = nullptr;
            repository::SnapshotPathMetadata metadata;
            std::string path;
            if ((*record)->type == crypto::RecordType::file_header) {
                const auto file = repository::parse_file_header(**record);
                if (!file) {
                    return std::unexpected(file.error());
                }
                root = std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                    return candidate.index == file->root;
                }) != from.roots.end()
                    ? &*std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.index == file->root;
                    })
                    : nullptr;
                if (root != nullptr) {
                    other_root = std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.uuid == root->uuid;
                    }) != to.roots.end()
                        ? &*std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                            return candidate.uuid == root->uuid;
                        })
                        : nullptr;
                }
                metadata.type = repository::SnapshotEntryType::file;
                metadata.size = file->size;
                metadata.mtime_seconds = file->mtime_seconds;
                metadata.mtime_nanoseconds = file->mtime_nanoseconds;
                metadata.mode = file->mode;
                metadata.file_id = file->file_id;
                path = file->path;
            } else if ((*record)->type == crypto::RecordType::directory) {
                const auto directory = repository::parse_directory(**record);
                if (!directory) {
                    return std::unexpected(directory.error());
                }
                root = std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                    return candidate.index == directory->root;
                }) != from.roots.end()
                    ? &*std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.index == directory->root;
                    })
                    : nullptr;
                if (root != nullptr) {
                    other_root = std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.uuid == root->uuid;
                    }) != to.roots.end()
                        ? &*std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                            return candidate.uuid == root->uuid;
                        })
                        : nullptr;
                }
                metadata.type = repository::SnapshotEntryType::directory;
                metadata.mtime_seconds = directory->mtime_seconds;
                metadata.mtime_nanoseconds = directory->mtime_nanoseconds;
                metadata.mode = directory->mode;
                path = directory->path;
            } else if ((*record)->type == crypto::RecordType::symlink) {
                const auto link = repository::parse_symlink(**record);
                if (!link) {
                    return std::unexpected(link.error());
                }
                root = std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                    return candidate.index == link->root;
                }) != from.roots.end()
                    ? &*std::ranges::find_if(from.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.index == link->root;
                    })
                    : nullptr;
                if (root != nullptr) {
                    other_root = std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                        return candidate.uuid == root->uuid;
                    }) != to.roots.end()
                        ? &*std::ranges::find_if(to.roots, [&](const repository::RootInfo& candidate) {
                            return candidate.uuid == root->uuid;
                        })
                        : nullptr;
                }
                const auto parsed = symlink_metadata(*link, *id_key);
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                metadata = *parsed;
                path = link->path;
            } else {
                continue;
            }
            if (!root || !other_root) {
                return std::unexpected(Error{ErrorCode::integrity, "snapshot root identity mismatch"});
            }
            auto previous = additions ? left_index->find(root->uuid, path) : right_index->find(root->uuid, path);
            if (!previous) {
                return std::unexpected(previous.error());
            }
            if (!additions && *previous) {
                continue;
            }
            DiffEvent event{root->index, path, "", ""};
            if (!*previous) {
                event.status = additions ? "added" : "missing";
            } else if ((*previous)->type != metadata.type) {
                event.status = "type-changed";
            } else if (metadata.type == repository::SnapshotEntryType::file
                && (*previous)->file_id != metadata.file_id) {
                event.status = "changed";
                event.reason = "content identity differs";
            } else if ((*previous)->size != metadata.size
                || (*previous)->mtime_seconds != metadata.mtime_seconds
                || (*previous)->mtime_nanoseconds != metadata.mtime_nanoseconds
                || (*previous)->mode != metadata.mode) {
                event.status = "changed";
                event.reason = "metadata differs";
            } else {
                event.status = "unchanged";
            }
            const auto emitted = emit(event);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
        }
        return {};
    };
    auto result = compare(*right_summary, *left_summary, true);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = compare(*left_summary, *right_summary, false);
    if (!result) {
        return std::unexpected(result.error());
    }
    return report;
}

}
