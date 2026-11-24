#include "application/lifecycle_service.hpp"

#include "application/inspection_service.hpp"
#include "platform/lock.hpp"
#include "repository/chunk_store.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>
#include <system_error>

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;

namespace {

domain::Result<void> write_retirement_record(
    const std::filesystem::path& repository,
    const crypto::SecureKey& master,
    std::uint64_t generation
) {
    const auto key = crypto::derive_key(master, crypto::KeyPurpose::configuration_authentication);
    if (!key) {
        return std::unexpected(key.error());
    }
    const nlohmann::json record{
        {"schema", "cpcp.maintenance.v1"},
        {"type", "snapshot-retirement"},
        {"id", std::to_string(generation)},
        {"state", "retiring"},
    };
    const auto text = record.dump();
    const auto view = std::as_bytes(std::span(text));
    const auto tag = crypto::compute_hmac_sha256(*key, domain::Bytes(view.begin(), view.end()));
    if (!tag) {
        return std::unexpected(tag.error());
    }
    nlohmann::json authenticated = record;
    authenticated["authentication_tag"] = crypto::to_hex(*tag);
    const auto path = repository / "quarantine"
        / ("retirement-" + std::to_string(generation) + "-" + domain::hex_encode(crypto::random_uuid()) + ".json");
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    const auto serialized = authenticated.dump(2) + '\n';
    const auto bytes = std::as_bytes(std::span(serialized));
    auto result = file->write_all(bytes);
    if (!result) {
        return result;
    }
    result = file->flush();
    if (!result) {
        return result;
    }
    result = file->close();
    if (!result) {
        return result;
    }
    return platform::sync_directory(path.parent_path());
}

std::filesystem::path find_generation(
    const std::filesystem::path& directory,
    std::uint64_t generation,
    const std::string& extension
) {
    const auto prefix = repository::snapshot_basename(generation, domain::Uuid{}).substr(0, 16) + "-";
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() == extension
            && entry.path().filename().string().starts_with(prefix)) {
            return entry.path();
        }
    }
    throw std::invalid_argument("snapshot generation was not found");
}

std::vector<std::filesystem::path> regular_files(const std::filesystem::path& root) {
    std::vector<std::filesystem::path> files;
    std::error_code error;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root, error)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    if (error) {
        throw std::system_error(error);
    }
    return files;
}

bool expired(const std::filesystem::path& path, std::chrono::seconds grace) {
    const auto modified = std::filesystem::last_write_time(path);
    return std::filesystem::file_time_type::clock::now() - modified >= grace;
}

domain::Result<void> move_object(
    const std::filesystem::path& source,
    const std::filesystem::path& target
) {
    const auto moved = platform::publish_no_replace(source, target);
    if (!moved) {
        return moved;
    }
    auto synced = platform::sync_directory(source.parent_path());
    if (!synced) {
        return synced;
    }
    return platform::sync_directory(target.parent_path());
}

domain::Result<LifecycleReport> delete_expired(
    const std::filesystem::path& root,
    std::chrono::seconds grace,
    bool dry_run
) {
    LifecycleReport report;
    for (const auto& path : regular_files(root)) {
        if (!expired(path, grace)) {
            continue;
        }
        report.deleted.push_back(path);
        if (!dry_run) {
            std::error_code error;
            std::filesystem::remove(path, error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
        }
    }
    if (!dry_run) {
        std::error_code error;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root, error)) {
            if (entry.is_directory()) {
                std::filesystem::remove(entry.path(), error);
            }
        }
        if (error) {
            return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
        }
        const auto synced = platform::sync_directory(root);
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }
    return report;
}

}

domain::Result<LifecycleReport> forget_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation,
    bool dry_run,
    bool confirmed
) {
    if (!dry_run && !confirmed) {
        return std::unexpected(Error{ErrorCode::usage, "forgetting a snapshot requires --yes"});
    }
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    LifecycleReport report;
    try {
        const auto locate = [&](const std::string& extension) {
            try {
                return find_generation(repository / "snapshots", generation, extension);
            } catch (const std::exception&) {
                return find_generation(repository / "trash", generation, extension);
            }
        };
        const auto summary = locate(".summary");
        const auto main = locate(".snap");
        const auto summary_target = repository / "trash" / summary.filename();
        const auto main_target = repository / "trash" / main.filename();
        if (!dry_run && (summary != summary_target || main != main_target)) {
            const auto recorded = write_retirement_record(repository, unlocked->master_key, generation);
            if (!recorded) {
                return std::unexpected(recorded.error());
            }
        }
        if (!dry_run && summary != summary_target) {
            auto moved = move_object(summary, summary_target);
            if (!moved) {
                return std::unexpected(moved.error());
            }
        }
        if (!dry_run && main != main_target) {
            const auto moved = move_object(main, main_target);
            if (!moved) {
                return std::unexpected(moved.error());
            }
        }
        report.moved = {summary_target, main_target};
        return report;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.what()});
    }
}

domain::Result<LifecycleReport> purge_quarantine(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::chrono::seconds grace,
    bool dry_run,
    bool confirmed
) {
    if (grace.count() < 0 || (!dry_run && !confirmed)) {
        return std::unexpected(Error{ErrorCode::usage, "quarantine purge requires a nonnegative grace period and --yes"});
    }
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    return delete_expired(repository / "quarantine", grace, dry_run);
}

domain::Result<LifecycleReport> collect_garbage(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::chrono::seconds grace,
    bool dry_run,
    bool confirmed
) {
    if (grace.count() < 0 || (!dry_run && !confirmed)) {
        return std::unexpected(Error{ErrorCode::usage, "garbage collection requires a nonnegative grace period and --yes"});
    }
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    try {
        if (!regular_files(repository / "quarantine").empty()) {
            return std::unexpected(Error{ErrorCode::conflict, "quarantine must be empty before garbage collection"});
        }
        if (!regular_files(repository / "sessions").empty()) {
            return std::unexpected(Error{ErrorCode::conflict, "active or incomplete sessions block garbage collection"});
        }
        const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
        if (!summaries) {
            return std::unexpected(summaries.error());
        }
        auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
        if (!store) {
            return std::unexpected(store.error());
        }
        std::set<std::string> reachable;
        for (const auto& summary : *summaries) {
            const auto verified = verify_snapshot_manifest(repository, unlocked->config, unlocked->master_key, summary, *store, false);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            auto reader = repository::SnapshotReader::open(repository, unlocked->config, unlocked->master_key, summary);
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
                if ((*record)->type != crypto::RecordType::chunk_batch) {
                    continue;
                }
                const auto batch = repository::parse_chunk_batch(**record);
                if (!batch) {
                    return std::unexpected(batch.error());
                }
                for (const auto& chunk : batch->chunks) {
                    reachable.insert(crypto::to_hex(chunk.chunk_id));
                }
            }
        }

        auto report = delete_expired(repository / "trash", grace, dry_run);
        for (const auto& path : regular_files(repository / "chunks")) {
            const auto id = path.filename().string();
            if (reachable.contains(id)) {
                continue;
            }
            const auto target = repository / "trash" / ("chunk-" + id);
            report->moved.push_back(target);
            if (!dry_run) {
                const auto moved = move_object(path, target);
                if (!moved) {
                    return std::unexpected(moved.error());
                }
            }
        }
        return std::move(*report);
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.what()});
    }
}

}
