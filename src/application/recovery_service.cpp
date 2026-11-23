#include "application/recovery_service.hpp"

#include "domain/strict_json.hpp"

#include "crypto/content_id.hpp"
#include "crypto/password.hpp"
#include "platform/binary_file.hpp"
#include "platform/lock.hpp"
#include "repository/snapshot.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <system_error>

namespace cpcp::application {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;
using nlohmann::json;

namespace {

Bytes text_bytes(const std::string& text) {
    const auto view = std::as_bytes(std::span(text));
    return Bytes(view.begin(), view.end());
}

std::filesystem::path find_snapshot(
    const std::filesystem::path& repository,
    std::uint64_t generation,
    const std::string& extension
) {
    const auto prefix = repository::snapshot_basename(generation, domain::Uuid{}).substr(0, 16);
    for (const auto& entry : std::filesystem::directory_iterator(repository / "snapshots") ) {
        if (entry.path().extension() == extension
            && entry.path().filename().string().starts_with(prefix + "-")) {
            return entry.path();
        }
    }
    throw std::invalid_argument("snapshot generation was not found");
}

domain::Uuid snapshot_uuid(const std::filesystem::path& path) {
    const auto filename = path.filename().string();
    const auto separator = filename.find('-');
    const auto extension = filename.rfind('.');
    return domain::hex_decode<16>(filename.substr(separator + 1, extension - separator - 1)).value();
}

domain::Result<void> write_maintenance_record(
    const std::filesystem::path& repository,
    const crypto::SecureKey& master,
    const std::string& type,
    const std::string& id,
    const std::string& state,
    const std::vector<std::filesystem::path>& originals,
    const std::vector<std::filesystem::path>& targets
) {
    json original_json = json::array();
    json target_json = json::array();
    for (const auto& path : originals) {
        original_json.push_back(path.string());
    }
    for (const auto& path : targets) {
        target_json.push_back(path.string());
    }
    json record = {
        {"schema", "cpcp.maintenance.v1"},
        {"type", type},
        {"id", id},
        {"state", state},
        {"originals", original_json},
        {"targets", target_json},
    };
    auto key = crypto::derive_key(master, crypto::KeyPurpose::configuration_authentication);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto text = record.dump();
    const auto tag = crypto::compute_hmac_sha256(*key, text_bytes(text));
    if (!tag) {
        return std::unexpected(tag.error());
    }
    record["authentication_tag"] = crypto::to_hex(*tag);

    const auto path = repository / "quarantine"
        / (domain::hex_encode(crypto::random_uuid()) + ".json");
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    const auto bytes = text_bytes(record.dump(2) + '\n');
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
    return platform::sync_directory(repository / "quarantine");
}

domain::Result<RecoveryReport> quarantine_path(
    const std::filesystem::path& repository,
    const crypto::SecureKey& master,
    const std::string& type,
    const std::string& id,
    const std::filesystem::path& source,
    const std::filesystem::path& target,
    bool dry_run
) {
    RecoveryReport report;
    report.moved.emplace_back(source, target);
    if (dry_run) {
        return report;
    }
    if (!std::filesystem::exists(source)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "object to quarantine does not exist"});
    }
    auto recorded = write_maintenance_record(
        repository,
        master,
        type,
        id,
        "withdrawing",
        {source},
        {target}
    );
    if (!recorded) {
        return std::unexpected(recorded.error());
    }
    auto moved = platform::publish_no_replace(source, target);
    if (!moved) {
        return std::unexpected(moved.error());
    }
    auto synced = platform::sync_directory(source.parent_path());
    if (!synced) {
        return std::unexpected(synced.error());
    }
    synced = platform::sync_directory(repository / "quarantine");
    if (!synced) {
        return std::unexpected(synced.error());
    }
    return report;
}

}

domain::Result<RecoveryReport> quarantine_chunk(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const crypto::Digest& chunk_id,
    bool dry_run
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const auto id = crypto::to_hex(chunk_id);
    const auto source = repository / "chunks" / id.substr(0, 2) / id.substr(2, 2) / id;
    const auto target = repository / "quarantine" / ("chunk-" + id);
    return quarantine_path(repository, unlocked->master_key, "chunk", id, source, target, dry_run);
}

domain::Result<RecoveryReport> quarantine_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation,
    bool dry_run
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }

    RecoveryReport report;
    try {
        const auto summary = find_snapshot(repository, generation, ".summary");
        const auto main = find_snapshot(repository, generation, ".snap");
        const auto id = repository::snapshot_basename(generation, snapshot_uuid(summary));
        const auto summary_target = repository / "quarantine" / (id + ".summary");
        const auto main_target = repository / "quarantine" / (id + ".snap");
        report.moved.emplace_back(summary, summary_target);
        report.moved.emplace_back(main, main_target);
        if (dry_run) {
            return report;
        }
        auto recorded = write_maintenance_record(
            repository,
            unlocked->master_key,
            "snapshot",
            std::to_string(generation),
            "withdrawing-summary",
            std::vector<std::filesystem::path>{summary, main},
            std::vector<std::filesystem::path>{summary_target, main_target}
        );
        if (!recorded) {
            return std::unexpected(recorded.error());
        }
        auto moved = platform::publish_no_replace(summary, summary_target);
        if (!moved) {
            return std::unexpected(moved.error());
        }
        auto synced = platform::sync_directory(repository / "snapshots");
        if (!synced) {
            return std::unexpected(synced.error());
        }
        moved = platform::publish_no_replace(main, main_target);
        if (!moved) {
            return std::unexpected(moved.error());
        }
        synced = platform::sync_directory(repository / "snapshots");
        if (!synced) {
            return std::unexpected(synced.error());
        }
        synced = platform::sync_directory(repository / "quarantine");
        if (!synced) {
            return std::unexpected(synced.error());
        }
        return report;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.what()});
    }
}

domain::Result<repository::SnapshotSummary> repair_summary(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto snapshot_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::snapshot_encryption);
    if (!snapshot_key) {
        return std::unexpected(snapshot_key.error());
    }

    repository::SnapshotSummary recovered;
    try {
        const auto main = find_snapshot(repository, generation, ".snap");
        storage::SessionSpoolReader reader;
        const auto opened = reader.open(main, *snapshot_key, crypto::SnapshotContext{}, crypto::StreamDomain::snapshot);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        while (true) {
            const auto record = reader.next();
            if (!record) {
                return std::unexpected(record.error());
            }
            if (!record->has_value()) {
                break;
            }
            switch ((*record)->type) {
            case crypto::RecordType::snapshot_header: {
                const auto header = repository::parse_snapshot_header(**record);
                if (!header) {
                    return std::unexpected(header.error());
                }
                recovered.created_seconds = header->created_seconds;
                recovered.created_nanoseconds = header->created_nanoseconds;
                recovered.selection_policy = header->selection_policy;
                recovered.has_parent = header->has_parent;
                recovered.parent_uuid = header->parent_uuid;
                recovered.parent_summary_digest = header->parent_summary_digest;
                break;
            }
            case crypto::RecordType::root: {
                const auto root = repository::parse_root(**record);
                if (!root) {
                    return std::unexpected(root.error());
                }
                recovered.roots.push_back(*root);
                break;
            }
            case crypto::RecordType::final_summary: {
                const auto stats = repository::parse_final_stats(**record);
                if (!stats) {
                    return std::unexpected(stats.error());
                }
                recovered.stats = *stats;
                const auto document = domain::parse_bounded_json((*record)->plaintext);
                if (!document) {
                    return std::unexpected(document.error());
                }
                recovered.status = document->at("status").get<std::string>();
                break;
            }
            default:
                break;
            }
        }
        recovered.context = reader.context();
        recovered.session_uuid = reader.context().session_uuid;
        recovered.main_ciphertext_digest = reader.ciphertext_digest().value();
        recovered.main_stored_length = reader.stored_length();

        const auto summary_path = snapshot_summary_path(repository, recovered);
        if (std::filesystem::exists(summary_path)) {
            const auto target = repository / "quarantine"
                / (repository::snapshot_basename(generation, recovered.context.snapshot_uuid) + ".summary");
            auto quarantined = quarantine_path(
                repository,
                unlocked->master_key,
                "summary",
                std::to_string(generation),
                summary_path,
                target,
                false
            );
            if (!quarantined) {
                return std::unexpected(quarantined.error());
            }
        }

        const auto temporary = repository / "tmp"
            / (domain::hex_encode(crypto::random_uuid()) + ".summary.part");
        auto written = repository::write_snapshot_summary(temporary, *snapshot_key, recovered);
        if (!written) {
            return std::unexpected(written.error());
        }
        auto verified = repository::read_snapshot_summary(temporary, *snapshot_key);
        if (!verified) {
            return std::unexpected(verified.error());
        }
        auto published = platform::publish_no_replace(temporary, summary_path);
        if (!published) {
            return std::unexpected(published.error());
        }
        auto synced = platform::sync_directory(repository / "snapshots");
        if (!synced) {
            return std::unexpected(synced.error());
        }
        return recovered;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.what()});
    }
}

domain::Result<void> repair_config(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    if (!unlocked->degraded_redundancy) {
        return {};
    }
    auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const std::filesystem::path paths[] = {
        repository / "cpcp.config.json",
        repository / "cpcp.config.backup.json",
    };
    for (const auto& path : paths) {
        if (std::filesystem::exists(path)) {
            const auto target = repository / "quarantine" / path.filename();
            const auto quarantined = quarantine_path(
                repository,
                unlocked->master_key,
                "configuration",
                path.filename().string(),
                path,
                target,
                false
            );
            if (!quarantined) {
                return std::unexpected(quarantined.error());
            }
        }
    }
    return repository::write_new_config_replicas(repository, unlocked->config);
}

}
