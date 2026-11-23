#include "repository/snapshot.hpp"

#include "crypto/aead.hpp"
#include "crypto/password.hpp"
#include "domain/strict_json.hpp"
#include "platform/binary_file.hpp"

#include <charconv>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;
using nlohmann::json;

namespace {

Bytes json_bytes(const json& document) {
    const auto text = document.dump();
    const auto view = std::as_bytes(std::span(text));
    return Bytes(view.begin(), view.end());
}

std::string uint_string(std::uint64_t value) {
    return std::to_string(value);
}

domain::Result<std::uint64_t> parse_uint_string(const json& value) {
    if (!value.is_string()) {
        return std::unexpected(Error{ErrorCode::integrity, "expected an integer string"});
    }
    const auto text = value.get<std::string>();
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid integer string"});
    }
    return result;
}

std::string require_string(const json& object, std::string_view key) {
    const auto& value = object.at(std::string(key));
    if (!value.is_string()) {
        throw std::invalid_argument("expected a JSON string");
    }
    return value.get<std::string>();
}

std::uint64_t require_uint(const json& object, std::string_view key) {
    const auto& value = object.at(std::string(key));
    if (!value.is_number_unsigned() && !value.is_number_integer()) {
        throw std::invalid_argument("expected a JSON integer");
    }
    return value.get<std::uint64_t>();
}

std::uint64_t require_string_uint(const json& object, std::string_view key) {
    const auto& value = object.at(std::string(key));
    const auto parsed = parse_uint_string(value);
    if (!parsed) {
        throw std::invalid_argument("invalid integer string");
    }
    return *parsed;
}

template<std::size_t N>
std::array<std::byte, N> require_hex(const json& object, std::string_view key) {
    const auto text = require_string(object, key);
    const auto decoded = domain::hex_decode<N>(text);
    if (!decoded) {
        throw std::invalid_argument("invalid hexadecimal field");
    }
    return *decoded;
}

json selection_policy_json(const SelectionPolicy& policy) {
    return {
        {"unsupported", policy.unsupported},
        {"one_file_system", policy.one_file_system},
        {"exclusions", policy.exclusions},
    };
}

SelectionPolicy parse_selection_policy(const json& object) {
    SelectionPolicy policy;
    policy.unsupported = require_string(object, "unsupported");
    policy.one_file_system = object.at("one_file_system").get<bool>();
    if (object.contains("exclusions")) {
        policy.exclusions = object.at("exclusions").get<std::vector<std::string>>();
    }
    if ((policy.unsupported != "skip" && policy.unsupported != "fail")) {
        throw std::invalid_argument("invalid unsupported-entry policy");
    }
    return policy;
}

json selection_stats_json(const SelectionStats& selection) {
    return {
        {"policy_skipped_entries", uint_string(selection.policy_skipped_entries)},
        {"failed_entries", uint_string(selection.failed_entries)},
    };
}

json stats_json(const SnapshotStats& stats) {
    auto document = json{
        {"files", uint_string(stats.files)},
        {"directories", uint_string(stats.directories)},
        {"logical_bytes", uint_string(stats.logical_bytes)},
        {"chunk_references", uint_string(stats.chunk_references)},
        {"new_chunks", uint_string(stats.new_chunks)},
        {"deduplicated_chunks", uint_string(stats.deduplicated_chunks)},
        {"source_reused_files", uint_string(stats.source_reused_files)},
        {"chunk_set_commitment", crypto::to_hex(stats.chunk_set_commitment)},
    };
    if (stats.selection) {
        document["selection"] = selection_stats_json(*stats.selection);
    }
    return document;
}

SnapshotStats parse_stats(const json& object) {
    SnapshotStats stats;
    stats.files = require_string_uint(object, "files");
    stats.directories = require_string_uint(object, "directories");
    stats.logical_bytes = require_string_uint(object, "logical_bytes");
    stats.chunk_references = require_string_uint(object, "chunk_references");
    stats.new_chunks = require_string_uint(object, "new_chunks");
    stats.deduplicated_chunks = require_string_uint(object, "deduplicated_chunks");
    if (object.contains("source_reused_files")) {
        stats.source_reused_files = require_string_uint(object, "source_reused_files");
    }
    stats.chunk_set_commitment = require_hex<32>(object, "chunk_set_commitment");
    if (object.contains("selection")) {
        const auto& selection = object.at("selection");
        stats.selection = SelectionStats{
            require_string_uint(selection, "policy_skipped_entries"),
            require_string_uint(selection, "failed_entries"),
        };
    }
    return stats;
}

json root_json(const RootInfo& root) {
    return {
        {"schema", "cpcp.root.v1"},
        {"index", root.index},
        {"uuid", domain::hex_encode(root.uuid)},
        {"label", root.label},
        {"path", root.path},
    };
}

json summary_json(const SnapshotSummary& summary) {
    json roots = json::array();
    for (const auto& root : summary.roots) {
        roots.push_back(root_json(root));
    }
    return {
        {"schema", "cpcp.snapshot-summary.v1"},
        {"repository_uuid", domain::hex_encode(summary.context.repository_uuid)},
        {"storage_epoch", domain::hex_encode(summary.context.storage_epoch)},
        {"snapshot_uuid", domain::hex_encode(summary.context.snapshot_uuid)},
        {"lineage_uuid", domain::hex_encode(summary.context.lineage_uuid)},
        {"generation", uint_string(summary.context.generation)},
        {"session_uuid", domain::hex_encode(summary.session_uuid)},
        {"status", summary.status},
        {"selection_policy", selection_policy_json(summary.selection_policy)},
        {"has_parent", summary.has_parent},
        {"parent_uuid", summary.has_parent
            ? json(domain::hex_encode(summary.parent_uuid))
            : json(nullptr)},
        {"parent_summary_digest", summary.has_parent
            ? json(crypto::to_hex(summary.parent_summary_digest))
            : json(nullptr)},
        {"created_at", {
            {"seconds", uint_string(static_cast<std::uint64_t>(summary.created_seconds))},
            {"nanoseconds", summary.created_nanoseconds},
        }},
        {"roots", roots},
        {"stats", stats_json(summary.stats)},
        {"main", {
            {"digest", crypto::to_hex(summary.main_ciphertext_digest)},
            {"stored_length", uint_string(summary.main_stored_length)},
        }},
    };
}

SnapshotSummary parse_summary(const json& document) {
    SnapshotSummary summary;
    summary.context.repository_uuid = require_hex<16>(document, "repository_uuid");
    summary.context.storage_epoch = require_hex<16>(document, "storage_epoch");
    summary.context.snapshot_uuid = require_hex<16>(document, "snapshot_uuid");
    summary.context.lineage_uuid = require_hex<16>(document, "lineage_uuid");
    summary.context.generation = require_string_uint(document, "generation");
    summary.session_uuid = require_hex<16>(document, "session_uuid");
    summary.context.session_uuid = summary.session_uuid;
    summary.status = require_string(document, "status");
    if (summary.status != "complete" && summary.status != "partial") {
        throw std::invalid_argument("invalid snapshot status");
    }
    if (document.contains("selection_policy")) {
        summary.selection_policy = parse_selection_policy(document.at("selection_policy"));
    }
    summary.has_parent = document.at("has_parent").get<bool>();
    if (summary.has_parent) {
        summary.parent_uuid = require_hex<16>(document, "parent_uuid");
        summary.parent_summary_digest = require_hex<32>(document, "parent_summary_digest");
    }
    const auto& created = document.at("created_at");
    summary.created_seconds = static_cast<std::int64_t>(require_string_uint(created, "seconds"));
    summary.created_nanoseconds = static_cast<std::uint32_t>(require_uint(created, "nanoseconds"));
    for (const auto& root : document.at("roots")) {
        summary.roots.push_back(RootInfo{
            static_cast<std::uint32_t>(require_uint(root, "index")),
            require_hex<16>(root, "uuid"),
            require_string(root, "label"),
            require_string(root, "path"),
        });
    }
    summary.stats = parse_stats(document.at("stats"));
    const auto& main = document.at("main");
    summary.main_ciphertext_digest = require_hex<32>(main, "digest");
    summary.main_stored_length = require_string_uint(main, "stored_length");
    return summary;
}

Bytes summary_aad(const crypto::SnapshotContext& context) {
    Bytes aad;
    constexpr std::string_view domain = "cpcp.summary.v1";
    for (const char value : domain) {
        aad.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    aad.insert(aad.end(), context.repository_uuid.begin(), context.repository_uuid.end());
    aad.insert(aad.end(), context.storage_epoch.begin(), context.storage_epoch.end());
    aad.insert(aad.end(), context.snapshot_uuid.begin(), context.snapshot_uuid.end());
    aad.insert(aad.end(), context.lineage_uuid.begin(), context.lineage_uuid.end());
    domain::append_le(aad, context.generation, 8);
    return aad;
}

domain::Result<void> write_summary_file(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key,
    const SnapshotSummary& summary
) {
    const auto aad = summary_aad(summary.context);
    auto sealed = crypto::seal_object(snapshot_key, aad, json_bytes(summary_json(summary)));
    if (!sealed) {
        return std::unexpected(sealed.error());
    }

    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    const Bytes prefix{
        std::byte{'C'}, std::byte{'P'}, std::byte{'S'}, std::byte{'M'},
        std::byte{1}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    auto result = file->write_all(prefix);
    if (!result) {
        return result;
    }
    const auto& context = summary.context;
    result = file->write_all(context.repository_uuid);
    if (!result) {
        return result;
    }
    result = file->write_all(context.storage_epoch);
    if (!result) {
        return result;
    }
    result = file->write_all(context.snapshot_uuid);
    if (!result) {
        return result;
    }
    result = file->write_all(context.lineage_uuid);
    if (!result) {
        return result;
    }
    Bytes generation;
    domain::append_le(generation, context.generation, 8);
    result = file->write_all(generation);
    if (!result) {
        return result;
    }
    result = file->write_all(context.session_uuid);
    if (!result) {
        return result;
    }
    result = file->write_all(sealed->nonce);
    if (!result) {
        return result;
    }
    Bytes length;
    domain::append_le(length, sealed->ciphertext.size(), 4);
    result = file->write_all(length);
    if (!result) {
        return result;
    }
    result = file->write_all(sealed->ciphertext);
    if (!result) {
        return result;
    }
    result = file->flush();
    if (!result) {
        return result;
    }
    return file->close();
}

domain::Result<SnapshotSummary> read_summary_file(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key
) {
    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    std::array<std::byte, 8> prefix{};
    auto result = file->read_exact(prefix);
    if (!result) {
        return std::unexpected(result.error());
    }
    const std::array<std::byte, 8> expected{
        std::byte{'C'}, std::byte{'P'}, std::byte{'S'}, std::byte{'M'},
        std::byte{1}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    if (prefix != expected) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid snapshot summary envelope"});
    }

    crypto::SnapshotContext context;
    result = file->read_exact(context.repository_uuid);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->read_exact(context.storage_epoch);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->read_exact(context.snapshot_uuid);
    if (!result) {
        return std::unexpected(result.error());
    }
    result = file->read_exact(context.lineage_uuid);
    if (!result) {
        return std::unexpected(result.error());
    }
    std::array<std::byte, 8> generation{};
    result = file->read_exact(generation);
    if (!result) {
        return std::unexpected(result.error());
    }
    context.generation = domain::read_le(generation, 8).value();
    result = file->read_exact(context.session_uuid);
    if (!result) {
        return std::unexpected(result.error());
    }

    crypto::SealedObject object;
    result = file->read_exact(object.nonce);
    if (!result) {
        return std::unexpected(result.error());
    }
    std::array<std::byte, 4> length_bytes{};
    result = file->read_exact(length_bytes);
    if (!result) {
        return std::unexpected(result.error());
    }
    const auto length = domain::read_le(length_bytes, 4);
    if (!length || *length > 1024 * 1024) {
        return std::unexpected(Error{ErrorCode::integrity, "summary exceeds the size limit"});
    }
    object.ciphertext.resize(*length);
    result = file->read_exact(object.ciphertext);
    if (!result) {
        return std::unexpected(result.error());
    }
    std::byte trailing{};
    const auto trailing_size = file->read_some({&trailing, 1});
    if (!trailing_size || *trailing_size != 0) {
        return std::unexpected(Error{ErrorCode::integrity, "summary has trailing data"});
    }

    const auto aad = summary_aad(context);
    auto plaintext = crypto::open_object(snapshot_key, aad, object);
    if (!plaintext) {
        return std::unexpected(plaintext.error());
    }
    auto document = domain::parse_bounded_json(*plaintext);
    if (!document) {
        return std::unexpected(document.error());
    }
    try {
        if (require_string(*document, "schema") != "cpcp.snapshot-summary.v1") {
            return std::unexpected(Error{ErrorCode::integrity, "unsupported snapshot summary schema"});
        }
        auto summary = parse_summary(*document);
        if (summary.context != context) {
            std::string mismatch;
            if (summary.context.repository_uuid != context.repository_uuid) mismatch += "repository ";
            if (summary.context.storage_epoch != context.storage_epoch) mismatch += "epoch ";
            if (summary.context.snapshot_uuid != context.snapshot_uuid) mismatch += "snapshot ";
            if (summary.context.lineage_uuid != context.lineage_uuid) mismatch += "lineage ";
            if (summary.context.generation != context.generation) mismatch += "generation ";
            if (summary.context.session_uuid != context.session_uuid) {
                mismatch += "session(header=" + domain::hex_encode(context.session_uuid)
                    + ",payload=" + domain::hex_encode(summary.context.session_uuid) + ")";
            }
            return std::unexpected(Error{ErrorCode::integrity, "summary header and payload context mismatch: " + mismatch});
        }
        return summary;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

}

domain::Result<void> write_snapshot_summary(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key,
    const SnapshotSummary& summary
) {
    return write_summary_file(path, snapshot_key, summary);
}

domain::Result<SnapshotSummary> read_snapshot_summary(
    const std::filesystem::path& path,
    const crypto::SecureKey& snapshot_key
) {
    return read_summary_file(path, snapshot_key);
}

std::string snapshot_basename(
    std::uint64_t generation,
    const domain::Uuid& snapshot_uuid
) {
    std::ostringstream output;
    output << std::setw(16) << std::setfill('0') << generation
           << '-' << domain::hex_encode(snapshot_uuid);
    return output.str();
}

std::filesystem::path snapshot_main_path(
    const std::filesystem::path& repository,
    const SnapshotSummary& summary
) {
    return repository / "snapshots"
        / (snapshot_basename(summary.context.generation, summary.context.snapshot_uuid) + ".snap");
}

std::filesystem::path snapshot_summary_path(
    const std::filesystem::path& repository,
    const SnapshotSummary& summary
) {
    return repository / "snapshots"
        / (snapshot_basename(summary.context.generation, summary.context.snapshot_uuid) + ".summary");
}

domain::Result<SnapshotWriter> SnapshotWriter::create(
    std::filesystem::path repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key,
    crypto::SnapshotContext context,
    domain::Uuid session_uuid,
    std::optional<SnapshotSummary> parent,
    SelectionPolicy selection_policy
) {
    if (selection_policy.unsupported != "skip" && selection_policy.unsupported != "fail") {
        return std::unexpected(Error{ErrorCode::usage, "invalid unsupported-entry policy"});
    }
    SnapshotSummary summary;
    context.session_uuid = session_uuid;
    summary.context = context;
    summary.session_uuid = context.session_uuid;
    summary.selection_policy = std::move(selection_policy);
    if (parent) {
        summary.has_parent = true;
        summary.parent_uuid = parent->context.snapshot_uuid;
        summary.parent_summary_digest = parent->main_ciphertext_digest;
        summary.context.lineage_uuid = parent->context.lineage_uuid;
    }
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
    summary.created_seconds = seconds.count();
    summary.created_nanoseconds = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds).count()
    );

    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::snapshot_encryption);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto writer = std::make_unique<storage::SessionSpoolWriter>();
    const auto path = repository / "tmp"
        / (snapshot_basename(context.generation, context.snapshot_uuid) + ".part");
    std::error_code temporary_error;
    std::filesystem::remove(path, temporary_error);
    if (temporary_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, temporary_error.message()});
    }
    const auto created = writer->create(path, *key, context, crypto::StreamDomain::snapshot);
    if (!created) {
        return std::unexpected(created.error());
    }
    SnapshotWriter result(
        std::move(repository),
        config,
        std::move(summary),
        std::move(key).value(),
        std::move(writer)
    );
    auto appended = result.append(crypto::RecordType::context, {
        {"schema", "cpcp.snapshot-context.v1"},
        {"repository_uuid", domain::hex_encode(context.repository_uuid)},
        {"storage_epoch", domain::hex_encode(context.storage_epoch)},
        {"snapshot_uuid", domain::hex_encode(context.snapshot_uuid)},
        {"lineage_uuid", domain::hex_encode(context.lineage_uuid)},
        {"generation", std::to_string(context.generation)},
        {"session_uuid", domain::hex_encode(context.session_uuid)},
    });
    if (!appended) {
        return std::unexpected(appended.error());
    }
    appended = result.append(crypto::RecordType::snapshot_header, {
        {"schema", "cpcp.snapshot-header.v1"},
        {"created_at", {
            {"seconds", std::to_string(result.summary_.created_seconds)},
            {"nanoseconds", result.summary_.created_nanoseconds},
        }},
        {"tool_version", "0.1.0"},
        {"has_parent", result.summary_.has_parent},
        {"parent_uuid", result.summary_.has_parent
            ? json(domain::hex_encode(result.summary_.parent_uuid))
            : json(nullptr)},
        {"parent_summary_digest", result.summary_.has_parent
            ? json(crypto::to_hex(result.summary_.parent_summary_digest))
            : json(nullptr)},
        {"selection", selection_policy_json(result.summary_.selection_policy)},
    });
    if (!appended) {
        return std::unexpected(appended.error());
    }
    return result;
}

SnapshotWriter::SnapshotWriter(
    std::filesystem::path repository,
    RepositoryConfig config,
    SnapshotSummary summary,
    crypto::SecureKey snapshot_key,
    std::unique_ptr<storage::SessionSpoolWriter> writer
) : repository_(std::move(repository)),
    config_(std::move(config)),
    summary_(std::move(summary)),
    snapshot_key_(std::move(snapshot_key)),
    writer_(std::move(writer)) {
}

domain::Result<void> SnapshotWriter::append(
    crypto::RecordType type,
    const json& record
) {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot writer is finished"});
    }
    return writer_->append(type, json_bytes(record));
}

domain::Result<void> SnapshotWriter::append_root(const RootInfo& root) {
    summary_.roots.push_back(root);
    return append(crypto::RecordType::root, root_json(root));
}

domain::Result<void> SnapshotWriter::append_directory(const DirectoryInfo& directory) {
    return append(crypto::RecordType::directory, {
        {"schema", "cpcp.directory.v1"},
        {"root", directory.root},
        {"path", directory.path},
        {"mtime", {
            {"seconds", uint_string(static_cast<std::uint64_t>(directory.mtime_seconds))},
            {"nanoseconds", directory.mtime_nanoseconds},
        }},
        {"mode", directory.mode},
    });
}

domain::Result<void> SnapshotWriter::append_file_header(const FileInfo& file) {
    return append(crypto::RecordType::file_header, {
        {"schema", "cpcp.file.v1"},
        {"sequence", uint_string(file.sequence)},
        {"root", file.root},
        {"path", file.path},
        {"size", uint_string(file.size)},
        {"chunk_count", uint_string(file.chunk_count)},
        {"file_id", crypto::to_hex(file.file_id)},
        {"mtime", {
            {"seconds", uint_string(static_cast<std::uint64_t>(file.mtime_seconds))},
            {"nanoseconds", file.mtime_nanoseconds},
        }},
        {"mode", file.mode},
    });
}

domain::Result<void> SnapshotWriter::append_chunk_batch(const ChunkBatch& batch) {
    json chunks = json::array();
    for (const auto& chunk : batch.chunks) {
        chunks.push_back({
            {"id", crypto::to_hex(chunk.chunk_id)},
            {"plain", chunk.plaintext_length},
            {"stored", uint_string(chunk.stored_length)},
        });
    }
    return append(crypto::RecordType::chunk_batch, {
        {"schema", "cpcp.chunk-batch.v1"},
        {"file", uint_string(batch.file)},
        {"batch", uint_string(batch.batch)},
        {"chunks", chunks},
    });
}

domain::Result<void> SnapshotWriter::append_file_end(const FileEnd& end) {
    return append(crypto::RecordType::file_end, {
        {"schema", "cpcp.file-end.v1"},
        {"file", uint_string(end.file)},
        {"chunk_count", uint_string(end.chunk_count)},
        {"file_id", crypto::to_hex(end.file_id)},
    });
}

domain::Result<void> SnapshotWriter::append_policy_skip(const PolicySkip& skip) {
    ++selection_stats_.policy_skipped_entries;
    return append(crypto::RecordType::policy_skip, {
        {"schema", "cpcp.policy-skip.v1"},
        {"root", skip.root},
        {"path", skip.path},
        {"reason", skip.reason},
    });
}

domain::Result<void> SnapshotWriter::append_failure(const FailureInfo& failure) {
    ++selection_stats_.failed_entries;
    return append(crypto::RecordType::failure, {
        {"schema", "cpcp.failure.v1"},
        {"root", failure.root},
        {"path", failure.path},
        {"reason", failure.reason},
    });
}

domain::Result<SnapshotSummary> SnapshotWriter::finish(
    SnapshotStats stats,
    std::string status,
    bool interrupt_after_main_for_testing
) {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot writer is already finished"});
    }
    if ((status != "complete" && status != "partial")
        || (status == "complete" && selection_stats_.failed_entries != 0)
        || (status == "partial" && selection_stats_.failed_entries == 0)) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot status does not match its failure records"});
    }
    stats.selection = selection_stats_;
    summary_.status = std::move(status);
    summary_.stats = stats;
    const auto final = writer_->finalize(json_bytes({
        {"schema", "cpcp.snapshot-final.v1"},
        {"status", summary_.status},
        {"stats", stats_json(stats)},
    }));
    if (!final) {
        return std::unexpected(final.error());
    }

    const auto temporary = repository_ / "tmp"
        / (snapshot_basename(summary_.context.generation, summary_.context.snapshot_uuid) + ".part");
    const auto inspect_main = [&](const std::filesystem::path& path) -> domain::Result<void> {
        storage::SessionSpoolReader reader;
        const auto opened = reader.open(path, snapshot_key_, summary_.context, crypto::StreamDomain::snapshot);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        std::size_t root_index = 0;
        bool header_seen = false;
        while (true) {
            auto record = reader.next();
            if (!record) {
                return std::unexpected(record.error());
            }
            if (!record->has_value()) {
                break;
            }
            if ((*record)->type == crypto::RecordType::root) {
                const auto root = parse_root(**record);
                if (!root || root_index >= summary_.roots.size()
                    || root_json(*root) != root_json(summary_.roots[root_index])) {
                    return std::unexpected(Error{ErrorCode::integrity, "snapshot root sequence mismatch"});
                }
                ++root_index;
            } else if ((*record)->type == crypto::RecordType::snapshot_header) {
                const auto header = parse_snapshot_header(**record);
                if (!header || header_seen
                    || header->selection_policy.unsupported != summary_.selection_policy.unsupported
                    || header->selection_policy.one_file_system != summary_.selection_policy.one_file_system
                    || header->selection_policy.exclusions != summary_.selection_policy.exclusions) {
                    return std::unexpected(Error{ErrorCode::integrity, "snapshot header semantics mismatch"});
                }
                header_seen = true;
                summary_.created_seconds = header->created_seconds;
                summary_.created_nanoseconds = header->created_nanoseconds;
                summary_.has_parent = header->has_parent;
                summary_.parent_uuid = header->parent_uuid;
                summary_.parent_summary_digest = header->parent_summary_digest;
            } else if ((*record)->type == crypto::RecordType::final_summary) {
                const auto final_stats = parse_final_stats(**record);
                const auto final_status = parse_final_status(**record);
                if (!final_stats || !final_status || stats_json(*final_stats) != stats_json(stats)
                    || *final_status != summary_.status) {
                    return std::unexpected(Error{ErrorCode::integrity, "snapshot final semantics mismatch"});
                }
            }
        }
        if (!header_seen || root_index != summary_.roots.size()) {
            return std::unexpected(Error{ErrorCode::integrity, "snapshot is missing required identity records"});
        }
        const auto digest = reader.ciphertext_digest();
        if (!digest) {
            return std::unexpected(digest.error());
        }
        summary_.main_ciphertext_digest = *digest;
        summary_.main_stored_length = reader.stored_length();
        return {};
    };

    const auto main_final = snapshot_main_path(repository_, summary_);
    if (std::filesystem::exists(main_final)) {
        const auto inspected = inspect_main(main_final);
        if (!inspected) {
            return std::unexpected(inspected.error());
        }
        std::error_code error;
        std::filesystem::remove(temporary, error);
        if (error) {
            return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
        }
    } else {
        const auto inspected = inspect_main(temporary);
        if (!inspected) {
            return std::unexpected(inspected.error());
        }
        const auto published = platform::publish_no_replace(temporary, main_final);
        if (!published) {
            return std::unexpected(published.error());
        }
        const auto synced = platform::sync_directory(repository_ / "snapshots");
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }

    const auto summary_final = snapshot_summary_path(repository_, summary_);
    if (std::filesystem::exists(summary_final)) {
        const auto existing = read_summary_file(summary_final, snapshot_key_);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        if (summary_json(*existing) != summary_json(summary_)) {
            return std::unexpected(Error{ErrorCode::integrity, "existing snapshot summary does not match the session"});
        }
        finished_ = true;
        return *existing;
    }
    if (interrupt_after_main_for_testing) {
        return std::unexpected(Error{
            ErrorCode::cancellation,
            "snapshot main published before summary; resume session " + domain::hex_encode(summary_.session_uuid),
        });
    }

    const auto summary_temp = repository_ / "tmp"
        / (snapshot_basename(summary_.context.generation, summary_.context.snapshot_uuid) + ".summary.part");
    std::error_code summary_temporary_error;
    std::filesystem::remove(summary_temp, summary_temporary_error);
    if (summary_temporary_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, summary_temporary_error.message()});
    }
    const auto written = write_summary_file(summary_temp, snapshot_key_, summary_);
    if (!written) {
        return std::unexpected(written.error());
    }
    const auto verified = read_summary_file(summary_temp, snapshot_key_);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    const auto published = platform::publish_no_replace(summary_temp, summary_final);
    if (!published) {
        return std::unexpected(published.error());
    }
    const auto synced = platform::sync_directory(repository_ / "snapshots");
    if (!synced) {
        return std::unexpected(synced.error());
    }
    finished_ = true;
    return summary_;
}

domain::Result<void> SnapshotWriter::abort() {
    if (finished_) {
        return std::unexpected(Error{ErrorCode::usage, "snapshot writer is not active"});
    }
    auto closed = writer_->abort();
    if (!closed) {
        return closed;
    }
    finished_ = true;
    const auto basename = snapshot_basename(summary_.context.generation, summary_.context.snapshot_uuid);
    std::error_code error;
    std::filesystem::remove(repository_ / "tmp" / (basename + ".part"), error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    std::filesystem::remove(repository_ / "tmp" / (basename + ".summary.part"), error);
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    return {};
}

domain::Result<SnapshotReader> SnapshotReader::open(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key,
    const SnapshotSummary& summary
) {
    auto key = crypto::derive_key(master_key, crypto::KeyPurpose::snapshot_encryption);
    if (!key) {
        return std::unexpected(key.error());
    }
    auto reader = std::make_unique<storage::SessionSpoolReader>();
    const auto path = snapshot_main_path(repository, summary);
    const auto opened = reader->open(path, *key, summary.context, crypto::StreamDomain::snapshot);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    return SnapshotReader(config, summary, std::move(key).value(), std::move(reader));
}

SnapshotReader::SnapshotReader(
    RepositoryConfig config,
    SnapshotSummary summary,
    crypto::SecureKey snapshot_key,
    std::unique_ptr<storage::SessionSpoolReader> reader
) : config_(std::move(config)),
    summary_(std::move(summary)),
    snapshot_key_(std::move(snapshot_key)),
    reader_(std::move(reader)) {
}

domain::Result<std::optional<storage::SpoolRecord>> SnapshotReader::next() {
    auto record = reader_->next();
    if (!record || !record->has_value()) {
        return record;
    }
    if ((*record)->type == crypto::RecordType::final_summary) {
        auto digest = reader_->ciphertext_digest();
        if (!digest || *digest != summary_.main_ciphertext_digest
            || reader_->stored_length() != summary_.main_stored_length) {
            return std::unexpected(Error{ErrorCode::integrity, "snapshot main digest or length mismatch"});
        }
        auto finished = reader_->finish();
        if (!finished) {
            return std::unexpected(finished.error());
        }
    }
    return record;
}

const SnapshotSummary& SnapshotReader::summary() const {
    return summary_;
}

domain::Result<std::vector<SnapshotSummary>> list_snapshots(
    const std::filesystem::path& repository,
    const RepositoryConfig& config,
    const crypto::SecureKey& master_key
) {
    std::vector<SnapshotSummary> summaries;
    static_cast<void>(config);
    auto snapshot_key = crypto::derive_key(master_key, crypto::KeyPurpose::snapshot_encryption);
    if (!snapshot_key) {
        return std::unexpected(snapshot_key.error());
    }
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(repository / "snapshots", error)) {
        if (error) {
            return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
        }
        if (entry.path().extension() != ".summary") {
            continue;
        }
        auto summary = read_summary_file(entry.path(), *snapshot_key);
        if (!summary) {
            return std::unexpected(summary.error());
        }
        const auto main_path = snapshot_main_path(repository, *summary);
        const auto size = std::filesystem::file_size(main_path, error);
        if (error || size != summary->main_stored_length) {
            return std::unexpected(Error{ErrorCode::integrity, "snapshot main size mismatch"});
        }
        summaries.push_back(std::move(*summary));
    }
    std::ranges::sort(summaries, [](const SnapshotSummary& left, const SnapshotSummary& right) {
        return left.context.generation < right.context.generation;
    });
    return summaries;
}

}
