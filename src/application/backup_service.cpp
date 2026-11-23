#include "application/backup_service.hpp"

#include "application/inspection_service.hpp"
#include "crypto/file_identity.hpp"
#include "platform/cancellation.hpp"
#include "platform/lock.hpp"
#include "repository/chunk_set.hpp"
#include "repository/chunk_store.hpp"
#include "repository/journal.hpp"
#include "repository/snapshot_index.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;
using nlohmann::json;
using repository::ChunkBatch;
using repository::DirectoryInfo;
using repository::FailureInfo;
using repository::FileEnd;
using repository::FileInfo;
using repository::JournalRecordType;
using repository::PolicySkip;
using repository::RootInfo;
using repository::SnapshotStats;

namespace {

struct SessionSpec {
    crypto::SnapshotContext context;
    std::vector<RootInfo> roots;
    repository::SelectionPolicy selection;
    bool allow_partial = false;
    bool has_parent = false;
    domain::Uuid parent_uuid{};
};

struct ActiveFile {
    FileInfo info;
    platform::FileMetadata source;
    domain::Uuid spool_uuid{};
    std::unique_ptr<storage::SessionSpoolWriter> descriptors;
    crypto::FileIdentityBuilder identity;
    std::uint64_t next_offset = 0;
    std::uint64_t next_batch = 0;
    std::uint64_t new_chunks = 0;
    std::uint64_t deduplicated_chunks = 0;
};

std::string hex(const domain::Uuid& value) {
    return domain::hex_encode(value);
}

domain::Bytes json_bytes(const json& document) {
    const auto text = document.dump();
    const auto view = std::as_bytes(std::span(text));
    return domain::Bytes(view.begin(), view.end());
}

json root_json(const RootInfo& root) {
    return {
        {"index", root.index},
        {"uuid", hex(root.uuid)},
        {"label", root.label},
        {"path", root.path},
    };
}

json file_json(const FileInfo& file) {
    return {
        {"schema", "cpcp.file.v1"},
        {"sequence", std::to_string(file.sequence)},
        {"root", file.root},
        {"path", file.path},
        {"size", std::to_string(file.size)},
        {"chunk_count", std::to_string(file.chunk_count)},
        {"file_id", crypto::to_hex(file.file_id)},
        {"mtime", {
            {"seconds", std::to_string(file.mtime_seconds)},
            {"nanoseconds", file.mtime_nanoseconds},
        }},
        {"mode", file.mode},
    };
}

json source_json(const platform::FileMetadata& source) {
    return {
        {"size", std::to_string(source.size)},
        {"mtime_seconds", std::to_string(source.mtime_seconds)},
        {"mtime_nanoseconds", source.mtime_nanoseconds},
        {"device", std::to_string(source.device)},
        {"inode", std::to_string(source.inode)},
        {"mode", source.mode},
    };
}

domain::Result<std::uint64_t> uint_value(const json& value) {
    if (!value.is_string()) {
        return std::unexpected(Error{ErrorCode::integrity, "expected a decimal string"});
    }
    const auto text = value.get<std::string>();
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid decimal string"});
    }
    return result;
}

domain::Result<std::int64_t> int_value(const json& value) {
    if (!value.is_string()) {
        return std::unexpected(Error{ErrorCode::integrity, "expected a signed decimal string"});
    }
    const auto text = value.get<std::string>();
    std::int64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid signed decimal string"});
    }
    return result;
}

domain::Result<SessionSpec> parse_session(const json& payload) {
    try {
        SessionSpec spec;
        const auto& context = payload.at("context");
        spec.context.repository_uuid = domain::hex_decode<16>(context.at("repository").get<std::string>()).value();
        spec.context.storage_epoch = domain::hex_decode<16>(context.at("epoch").get<std::string>()).value();
        spec.context.snapshot_uuid = domain::hex_decode<16>(context.at("snapshot").get<std::string>()).value();
        spec.context.lineage_uuid = domain::hex_decode<16>(context.at("lineage").get<std::string>()).value();
        spec.context.session_uuid = domain::hex_decode<16>(context.at("session").get<std::string>()).value();
        const auto generation = uint_value(context.at("generation"));
        if (!generation) {
            return std::unexpected(generation.error());
        }
        spec.context.generation = *generation;
        for (const auto& root : payload.at("roots")) {
            spec.roots.push_back(RootInfo{
                root.at("index").get<std::uint32_t>(),
                domain::hex_decode<16>(root.at("uuid").get<std::string>()).value(),
                root.at("label").get<std::string>(),
                root.at("path").get<std::string>(),
            });
        }
        spec.selection.unsupported = payload.at("unsupported").get<std::string>();
        spec.selection.one_file_system = payload.at("one_file_system").get<bool>();
        spec.allow_partial = payload.at("allow_partial").get<bool>();
        spec.has_parent = payload.at("has_parent").get<bool>();
        if (spec.has_parent) {
            spec.parent_uuid = domain::hex_decode<16>(payload.at("parent").get<std::string>()).value();
        }
        return spec;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

json session_json(const SessionSpec& spec, bool has_parent) {
    auto roots = json::array();
    for (const auto& root : spec.roots) {
        roots.push_back(root_json(root));
    }
    return {
        {"context", {
            {"repository", hex(spec.context.repository_uuid)},
            {"epoch", hex(spec.context.storage_epoch)},
            {"snapshot", hex(spec.context.snapshot_uuid)},
            {"lineage", hex(spec.context.lineage_uuid)},
            {"session", hex(spec.context.session_uuid)},
            {"generation", std::to_string(spec.context.generation)},
        }},
        {"roots", roots},
        {"unsupported", spec.selection.unsupported},
        {"one_file_system", spec.selection.one_file_system},
        {"allow_partial", spec.allow_partial},
        {"has_parent", has_parent},
        {"parent", has_parent ? json(hex(spec.parent_uuid)) : json(nullptr)},
    };
}

domain::Result<FileInfo> parse_file(const json& payload) {
    const auto text = payload.dump();
    const auto view = std::as_bytes(std::span(text));
    return repository::parse_file_header(storage::SpoolRecord{
        crypto::RecordType::file_header,
        domain::Bytes(view.begin(), view.end()),
    });
}

domain::Result<platform::FileMetadata> parse_source(const json& payload) {
    try {
        platform::FileMetadata source;
        const auto size = uint_value(payload.at("size"));
        const auto seconds = int_value(payload.at("mtime_seconds"));
        const auto device = uint_value(payload.at("device"));
        const auto inode = uint_value(payload.at("inode"));
        if (!size || !seconds || !device || !inode) {
            return std::unexpected(Error{ErrorCode::integrity, "invalid source identity"});
        }
        source.size = *size;
        source.mtime_seconds = static_cast<std::int64_t>(*seconds);
        source.mtime_nanoseconds = payload.at("mtime_nanoseconds").get<std::uint32_t>();
        source.device = *device;
        source.inode = *inode;
        source.mode = payload.at("mode").get<std::uint32_t>();
        return source;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<ChunkBatch> parse_chunks(const json& payload) {
    const auto text = payload.dump();
    const auto view = std::as_bytes(std::span(text));
    return repository::parse_chunk_batch(storage::SpoolRecord{
        crypto::RecordType::chunk_batch,
        domain::Bytes(view.begin(), view.end()),
    });
}

json chunks_json(const ChunkBatch& batch) {
    auto chunks = json::array();
    for (const auto& chunk : batch.chunks) {
        chunks.push_back({
            {"id", crypto::to_hex(chunk.chunk_id)},
            {"plain", chunk.plaintext_length},
            {"stored", std::to_string(chunk.stored_length)},
        });
    }
    return {
        {"schema", "cpcp.chunk-batch.v1"},
        {"file", std::to_string(batch.file)},
        {"batch", std::to_string(batch.batch)},
        {"chunks", chunks},
    };
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
    return "hex:" + domain::hex_encode(std::as_bytes(std::span(path)));
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

std::string relative_path(const std::filesystem::path& root, const std::filesystem::path& path) {
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

DirectoryInfo directory_info(std::uint32_t root, std::string path, const std::filesystem::path& native) {
    const auto time = std::filesystem::file_time_type::clock::to_sys(std::filesystem::last_write_time(native));
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch());
    const auto seconds = std::chrono::floor<std::chrono::seconds>(nanoseconds);
    return DirectoryInfo{
        root,
        std::move(path),
        seconds.count(),
        static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(nanoseconds - seconds).count()),
        static_cast<std::uint32_t>(std::filesystem::status(native).permissions()),
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

domain::Result<std::size_t> read_chunk(platform::BinaryFile& file, std::span<std::byte> output) {
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

std::filesystem::path spool_path(
    const std::filesystem::path& repository,
    const domain::Uuid& session,
    const domain::Uuid& spool
) {
    return repository / "sessions" / (hex(session) + "-" + hex(spool) + ".spool");
}

crypto::SnapshotContext spool_context(
    const crypto::SnapshotContext& session,
    const domain::Uuid& spool
) {
    auto context = session;
    context.snapshot_uuid = spool;
    context.lineage_uuid = spool;
    return context;
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
    auto set = repository::ChunkSetBuilder::create(repository / "tmp" / "base-evidence", id_key);
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
    const auto commitment = set->finish();
    if (!commitment || *commitment != parent.stats.chunk_set_commitment) {
        return std::unexpected(Error{ErrorCode::integrity, "base chunk-set commitment mismatch"});
    }
    return {};
}

domain::Result<void> clean_session_files(
    const std::filesystem::path& repository,
    const domain::Uuid& session
) {
    const auto prefix = hex(session);
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(repository / "sessions", error)) {
        if (entry.path().filename().string().starts_with(prefix)) {
            std::filesystem::remove(entry.path(), error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
        }
    }
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    return {};
}

struct Runtime {
    std::filesystem::path repository;
    repository::RepositoryConfig config;
    crypto::SecureKey master;
    SessionSpec spec;
    std::optional<repository::SnapshotSummary> parent;
    repository::SessionJournal journal;
    repository::ChunkStore store;
    crypto::SecureKey id_key;
    crypto::SecureKey journal_key;
    repository::ChunkSetBuilder chunk_set;
    repository::SnapshotWriter writer;
    repository::SnapshotPathIndex processed;
    repository::SnapshotPathIndex seen;
    SnapshotStats stats;
    std::uint64_t skipped = 0;
    std::uint64_t failed = 0;
    std::uint64_t next_file = 0;
    std::uint64_t chunks_this_invocation = 0;
    std::uint64_t interrupt_after = 0;
    bool interrupt_main = false;
};

domain::Result<void> checkpoint_interruption(Runtime& runtime) {
    ++runtime.chunks_this_invocation;
    if (runtime.interrupt_after != 0 && runtime.chunks_this_invocation == runtime.interrupt_after) {
        return std::unexpected(Error{
            ErrorCode::cancellation,
            "backup interrupted after checkpoint; resume session " + hex(runtime.spec.context.session_uuid),
        });
    }
    return platform::check_cancellation();
}

domain::Result<void> replay_descriptor(
    Runtime& runtime,
    const crypto::ChunkDescriptor& descriptor
) {
    const auto reused = runtime.store.reuse(descriptor);
    if (!reused) {
        return std::unexpected(reused.error());
    }
    const auto added = runtime.chunk_set.add(descriptor);
    if (!added) {
        return added;
    }
    ++runtime.stats.chunk_references;
    ++runtime.chunks_this_invocation;
    return {};
}

domain::Result<void> capture_file(
    Runtime& runtime,
    const RootInfo& root,
    const std::filesystem::path& native_path,
    const std::string& relative,
    std::optional<ActiveFile> active
) {
    auto file = platform::BinaryFile::open_read(native_path);
    if (!file) {
        const auto failed = runtime.writer.append_failure(FailureInfo{root.index, relative, file.error().message});
        if (!failed) {
            return failed;
        }
        ++runtime.failed;
        const auto journaled = runtime.journal.append(JournalRecordType::failure, {
            {"schema", "cpcp.failure.v1"},
            {"root", root.index},
            {"path", relative},
            {"reason", file.error().message},
        }, true);
        if (!journaled) {
            return std::unexpected(journaled.error());
        }
        return {};
    }

    const auto before_result = file->metadata();
    if (!before_result) {
        return std::unexpected(before_result.error());
    }
    auto before = *before_result;
    if (active && !same_identity(before, active->source)) {
        return std::unexpected(Error{
            ErrorCode::source_changed,
            "resumed source identity changed for " + relative + "; use --restart-files",
        });
    }
    const auto sequence = active ? active->info.sequence : runtime.next_file++;
    const auto spool_uuid = active ? active->spool_uuid : crypto::random_uuid();
    if (!active) {
        ActiveFile created;
        created.info.sequence = sequence;
        created.info.root = root.index;
        created.info.path = relative;
        created.source = before;
        created.spool_uuid = spool_uuid;
        created.descriptors = std::make_unique<storage::SessionSpoolWriter>();
        const auto created_spool = created.descriptors->create(
            spool_path(runtime.repository, runtime.spec.context.session_uuid, spool_uuid),
            runtime.journal_key,
            spool_context(runtime.spec.context, spool_uuid),
            crypto::StreamDomain::session_spool
        );
        if (!created_spool) {
            return std::unexpected(created_spool.error());
        }
        const auto expected = before.size / runtime.config.chunk_size + (before.size % runtime.config.chunk_size == 0 ? 0 : 1);
        const auto initialized = created.identity.initialize(runtime.id_key, before.size, expected, runtime.config.chunk_size);
        if (!initialized) {
            return std::unexpected(initialized.error());
        }
        const auto begun = runtime.journal.append(JournalRecordType::file_begin, {
            {"sequence", std::to_string(sequence)},
            {"root", root.index},
            {"path", relative},
            {"source", source_json(before)},
        }, true);
        if (!begun) {
            return std::unexpected(begun.error());
        }
        active.emplace(std::move(created));
    }

    std::vector<std::byte> buffer(runtime.config.chunk_size);
    ChunkBatch batch;
    batch.file = sequence;
    batch.batch = active->next_batch;
    std::uint64_t batch_new = 0;
    std::uint64_t batch_deduplicated = 0;
    if (active->next_offset != 0) {
        const auto positioned = file->seek(active->next_offset);
        if (!positioned) {
            return std::unexpected(positioned.error());
        }
    }
    while (true) {
        const auto count = read_chunk(*file, buffer);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            break;
        }
        const auto chunk = runtime.store.put(std::span(buffer).first(*count));
        if (!chunk) {
            return std::unexpected(chunk.error());
        }
        const crypto::ChunkDescriptor descriptor{chunk->id, chunk->plaintext_length, chunk->stored_length};
        const auto appended = active->identity.append(std::span(&descriptor, 1));
        if (!appended) {
            return std::unexpected(appended.error());
        }
        const auto added = runtime.chunk_set.add(descriptor);
        if (!added) {
            return added;
        }
        batch.chunks.push_back(descriptor);
        active->next_offset += *count;
        ++runtime.stats.chunk_references;
        if (chunk->already_present) {
            ++active->deduplicated_chunks;
            ++batch_deduplicated;
        } else {
            ++active->new_chunks;
            ++batch_new;
        }
        if (batch.chunks.size() == 64) {
            const auto spooled = active->descriptors->append(crypto::RecordType::chunk_batch, json_bytes(chunks_json(batch)));
            if (!spooled) {
                return spooled;
            }
            const auto journaled = runtime.journal.append(JournalRecordType::chunks, {
                {"batch", chunks_json(batch)},
                {"new_chunks", batch_new},
                {"deduplicated_chunks", batch_deduplicated},
            }, true);
            if (!journaled) {
                return std::unexpected(journaled.error());
            }
            ++batch.batch;
            active->next_batch = batch.batch;
            batch.chunks.clear();
            batch_new = 0;
            batch_deduplicated = 0;
        }
        const auto interrupted = checkpoint_interruption(runtime);
        if (!interrupted) {
            return std::unexpected(interrupted.error());
        }
    }

    const auto after_result = file->metadata();
    if (!after_result || !same_identity(before, *after_result)) {
        return std::unexpected(Error{ErrorCode::source_changed, "source file changed during backup: " + relative});
    }
    if (!batch.chunks.empty()) {
        const auto spooled = active->descriptors->append(crypto::RecordType::chunk_batch, json_bytes(chunks_json(batch)));
        if (!spooled) {
            return spooled;
        }
        const auto journaled = runtime.journal.append(JournalRecordType::chunks, {
            {"batch", chunks_json(batch)},
            {"new_chunks", batch_new},
            {"deduplicated_chunks", batch_deduplicated},
        }, true);
        if (!journaled) {
            return std::unexpected(journaled.error());
        }
    }
    const auto finalized = active->descriptors->finalize({});
    if (!finalized) {
        return std::unexpected(finalized.error());
    }
    const auto file_id = active->identity.finish();
    if (!file_id) {
        return std::unexpected(file_id.error());
    }
    active->info.size = before.size;
    active->info.chunk_count = active->identity.seen_chunks();
    active->info.file_id = *file_id;
    active->info.mtime_seconds = before.mtime_seconds;
    active->info.mtime_nanoseconds = before.mtime_nanoseconds;
    active->info.mode = before.mode;

    const auto completed = runtime.journal.append(JournalRecordType::file_complete, {
        {"file", file_json(active->info)},
        {"source", source_json(before)},
        {"spool", hex(active->spool_uuid)},
        {"new_chunks", active->new_chunks},
        {"deduplicated_chunks", active->deduplicated_chunks},
    }, true);
    if (!completed) {
        return std::unexpected(completed.error());
    }
    auto appended = runtime.writer.append_file_header(active->info);
    if (!appended) {
        return appended;
    }
    storage::SessionSpoolReader replay;
    const auto opened = replay.open(
        spool_path(runtime.repository, runtime.spec.context.session_uuid, active->spool_uuid),
        runtime.journal_key,
        spool_context(runtime.spec.context, active->spool_uuid),
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
        appended = runtime.writer.append_chunk_batch(*parsed);
        if (!appended) {
            return appended;
        }
    }
    appended = runtime.writer.append_file_end(FileEnd{sequence, active->info.chunk_count, *file_id});
    if (!appended) {
        return appended;
    }
    ++runtime.stats.files;
    runtime.stats.logical_bytes += before.size;
    runtime.stats.new_chunks += active->new_chunks;
    runtime.stats.deduplicated_chunks += active->deduplicated_chunks;
    return {};
}

domain::Result<BackupReport> execute(Runtime runtime, bool resumed) {
    std::vector<std::uint64_t> restarts(runtime.spec.roots.size(), 0);
    std::map<std::uint32_t, std::filesystem::path> source_paths;
    for (const auto& root : runtime.spec.roots) {
        source_paths[root.index] = root.path;
    }
    std::optional<std::uint64_t> active_sequence;
    std::uint64_t maximum_sequence = 0;
    bool has_committed_record = false;
    const auto analyzed = runtime.journal.replay([&](const repository::JournalRecord& record) -> domain::Result<void> {
        if (record.type == JournalRecordType::file_begin) {
            active_sequence = uint_value(record.payload.at("sequence")).value();
            maximum_sequence = std::max(maximum_sequence, *active_sequence + 1);
        } else if (record.type == JournalRecordType::file_complete) {
            active_sequence.reset();
            const auto file = parse_file(record.payload.at("file"));
            if (!file) {
                return std::unexpected(file.error());
            }
            maximum_sequence = std::max(maximum_sequence, file->sequence + 1);
        } else if (record.type == JournalRecordType::restart_files || record.type == JournalRecordType::remap_root) {
            if (record.type == JournalRecordType::restart_files) {
                std::ranges::fill(restarts, record.sequence + 1);
                active_sequence.reset();
            } else {
                const auto root_uuid = domain::hex_decode<16>(record.payload.at("root_uuid").get<std::string>()).value();
                const auto root = std::ranges::find_if(runtime.spec.roots, [&](const RootInfo& candidate) {
                    return candidate.uuid == root_uuid;
                });
                if (root == runtime.spec.roots.end()) {
                    return std::unexpected(Error{ErrorCode::integrity, "journal remap references an unknown root"});
                }
                source_paths[root->index] = record.payload.at("path").get<std::string>();
                restarts[root->index] = record.sequence + 1;
                active_sequence.reset();
            }
        } else if (record.type == JournalRecordType::committed) {
            has_committed_record = true;
        }
        return {};
    });
    if (!analyzed) {
        return std::unexpected(analyzed.error());
    }
    runtime.next_file = maximum_sequence;

    const auto summaries = repository::list_snapshots(runtime.repository, runtime.config, runtime.master);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    const auto existing = std::ranges::find_if(*summaries, [&](const repository::SnapshotSummary& summary) {
        return summary.context.snapshot_uuid == runtime.spec.context.snapshot_uuid;
    });
    if (existing != summaries->end()) {
        const auto verified = verify_snapshot_manifest(runtime.repository, runtime.config, runtime.master, *existing, runtime.store, false);
        if (!verified) {
            return std::unexpected(verified.error());
        }
        const auto closed = runtime.journal.close();
        if (!closed) {
            return std::unexpected(closed.error());
        }
        const auto cleaned = clean_session_files(runtime.repository, runtime.spec.context.session_uuid);
        if (!cleaned) {
            return std::unexpected(cleaned.error());
        }
        return BackupReport{*existing, existing->stats.selection ? existing->stats.selection->policy_skipped_entries : 0, runtime.spec.context.session_uuid, true};
    }
    if (has_committed_record) {
        return std::unexpected(Error{ErrorCode::integrity, "committed session has no active summary"});
    }
    if (!summaries->empty() && summaries->back().context.generation >= runtime.spec.context.generation) {
        return std::unexpected(Error{ErrorCode::conflict, "snapshot generation advanced; discard this session and start a new backup"});
    }

    for (const auto& root : runtime.spec.roots) {
        const auto appended = runtime.writer.append_root(root);
        if (!appended) {
            return std::unexpected(appended.error());
        }
    }

    std::optional<ActiveFile> active;
    const auto replayed = runtime.journal.replay([&](const repository::JournalRecord& record) -> domain::Result<void> {
        const auto root_for_payload = [&](std::uint32_t index) -> domain::Result<const RootInfo*> {
            const auto root = std::ranges::find_if(runtime.spec.roots, [&](const RootInfo& candidate) {
                return candidate.index == index;
            });
            if (root == runtime.spec.roots.end()) {
                return std::unexpected(Error{ErrorCode::integrity, "journal record references an unknown root"});
            }
            return &*root;
        };
        if (record.type == JournalRecordType::directory) {
            const auto text = record.payload.dump();
            const auto view = std::as_bytes(std::span(text));
            const auto directory = repository::parse_directory(storage::SpoolRecord{crypto::RecordType::directory, domain::Bytes(view.begin(), view.end())});
            if (!directory) {
                return std::unexpected(directory.error());
            }
            const auto root = root_for_payload(directory->root);
            if (!root) {
                return std::unexpected(root.error());
            }
            const auto appended = runtime.writer.append_directory(*directory);
            if (!appended) {
                return appended;
            }
            repository::SnapshotPathMetadata metadata;
            metadata.type = repository::SnapshotEntryType::directory;
            metadata.mtime_seconds = directory->mtime_seconds;
            metadata.mtime_nanoseconds = directory->mtime_nanoseconds;
            metadata.mode = directory->mode;
            const auto added = runtime.processed.add((*root)->uuid, directory->path, metadata);
            if (!added) {
                return added;
            }
            ++runtime.stats.directories;
        } else if (record.type == JournalRecordType::policy_skip || record.type == JournalRecordType::failure) {
            const auto index = record.payload.at("root").get<std::uint32_t>();
            if (record.sequence < restarts.at(index)) {
                return {};
            }
            if (record.type == JournalRecordType::policy_skip) {
                const auto skipped = repository::PolicySkip{index, record.payload.at("path").get<std::string>(), record.payload.at("reason").get<std::string>()};
                const auto appended = runtime.writer.append_policy_skip(skipped);
                if (!appended) {
                    return appended;
                }
                ++runtime.skipped;
            } else {
                const auto failure = repository::FailureInfo{index, record.payload.at("path").get<std::string>(), record.payload.at("reason").get<std::string>()};
                const auto appended = runtime.writer.append_failure(failure);
                if (!appended) {
                    return appended;
                }
                ++runtime.failed;
            }
            const auto root = root_for_payload(index);
            if (!root) {
                return std::unexpected(root.error());
            }
            return runtime.processed.add((*root)->uuid, record.payload.at("path").get<std::string>(), {});
        } else if (record.type == JournalRecordType::file_complete) {
            const auto file = parse_file(record.payload.at("file"));
            if (!file) {
                return std::unexpected(file.error());
            }
            if (record.sequence < restarts.at(file->root)) {
                return {};
            }
            const auto root = root_for_payload(file->root);
            if (!root) {
                return std::unexpected(root.error());
            }
            auto appended = runtime.writer.append_file_header(*file);
            if (!appended) {
                return appended;
            }
            const auto spool = domain::hex_decode<16>(record.payload.at("spool").get<std::string>()).value();
            storage::SessionSpoolReader descriptors;
            const auto opened = descriptors.open(
                spool_path(runtime.repository, runtime.spec.context.session_uuid, spool),
                runtime.journal_key,
                spool_context(runtime.spec.context, spool),
                crypto::StreamDomain::session_spool
            );
            if (!opened) {
                return std::unexpected(opened.error());
            }
            while (true) {
                auto item = descriptors.next();
                if (!item) {
                    return std::unexpected(item.error());
                }
                if (!item->has_value()) {
                    break;
                }
                if ((*item)->type != crypto::RecordType::chunk_batch) {
                    continue;
                }
                const auto batch = repository::parse_chunk_batch(**item);
                if (!batch) {
                    return std::unexpected(batch.error());
                }
                for (const auto& descriptor : batch->chunks) {
                    const auto replayed_descriptor = replay_descriptor(runtime, descriptor);
                    if (!replayed_descriptor) {
                        return replayed_descriptor;
                    }
                }
                appended = runtime.writer.append_chunk_batch(*batch);
                if (!appended) {
                    return appended;
                }
            }
            appended = runtime.writer.append_file_end(FileEnd{file->sequence, file->chunk_count, file->file_id});
            if (!appended) {
                return appended;
            }
            repository::SnapshotPathMetadata metadata;
            metadata.type = repository::SnapshotEntryType::file;
            metadata.size = file->size;
            metadata.mtime_seconds = file->mtime_seconds;
            metadata.mtime_nanoseconds = file->mtime_nanoseconds;
            metadata.mode = file->mode;
            metadata.file_id = file->file_id;
            const auto source = parse_source(record.payload.at("source"));
            if (!source) {
                return std::unexpected(source.error());
            }
            metadata.device = source->device;
            metadata.inode = source->inode;
            const auto added = runtime.processed.add((*root)->uuid, file->path, metadata);
            if (!added) {
                return added;
            }
            ++runtime.stats.files;
            runtime.stats.logical_bytes += file->size;
            runtime.stats.new_chunks += record.payload.at("new_chunks").get<std::uint64_t>();
            runtime.stats.deduplicated_chunks += record.payload.at("deduplicated_chunks").get<std::uint64_t>();
        } else if (record.type == JournalRecordType::file_begin && active_sequence
            && uint_value(record.payload.at("sequence")).value() == *active_sequence) {
            const auto sequence = uint_value(record.payload.at("sequence")).value();
            const auto source = parse_source(record.payload.at("source"));
            if (!source) {
                return std::unexpected(source.error());
            }
            ActiveFile created;
            created.info.sequence = sequence;
            created.info.root = record.payload.at("root").get<std::uint32_t>();
            created.info.path = record.payload.at("path").get<std::string>();
            created.source = *source;
            created.spool_uuid = crypto::random_uuid();
            created.descriptors = std::make_unique<storage::SessionSpoolWriter>();
            const auto created_spool = created.descriptors->create(
                spool_path(runtime.repository, runtime.spec.context.session_uuid, created.spool_uuid),
                runtime.journal_key,
                spool_context(runtime.spec.context, created.spool_uuid),
                crypto::StreamDomain::session_spool
            );
            if (!created_spool) {
                return std::unexpected(created_spool.error());
            }
            const auto expected = source->size / runtime.config.chunk_size + (source->size % runtime.config.chunk_size == 0 ? 0 : 1);
            const auto initialized = created.identity.initialize(runtime.id_key, source->size, expected, runtime.config.chunk_size);
            if (!initialized) {
                return std::unexpected(initialized.error());
            }
            active.emplace(std::move(created));
        } else if (record.type == JournalRecordType::chunks && active) {
            const auto batch = parse_chunks(record.payload.at("batch"));
            if (!batch || batch->file != active->info.sequence || batch->batch != active->next_batch) {
                return std::unexpected(Error{ErrorCode::integrity, "journal chunk sequence mismatch"});
            }
            const auto spooled = active->descriptors->append(crypto::RecordType::chunk_batch, json_bytes(chunks_json(*batch)));
            if (!spooled) {
                return spooled;
            }
            for (const auto& descriptor : batch->chunks) {
                const auto appended = active->identity.append(std::span(&descriptor, 1));
                if (!appended) {
                    return std::unexpected(appended.error());
                }
                const auto replayed_descriptor = replay_descriptor(runtime, descriptor);
                if (!replayed_descriptor) {
                    return replayed_descriptor;
                }
                active->next_offset += descriptor.plaintext_length;
            }
            active->next_batch++;
            active->new_chunks += record.payload.at("new_chunks").get<std::uint64_t>();
            active->deduplicated_chunks += record.payload.at("deduplicated_chunks").get<std::uint64_t>();
        }
        return {};
    });
    if (!replayed) {
        return std::unexpected(replayed.error());
    }
    const auto processed_finished = runtime.processed.finish();
    if (!processed_finished) {
        return std::unexpected(processed_finished.error());
    }

    const auto canonical_repository = std::filesystem::weakly_canonical(runtime.repository);
    for (const auto& root : runtime.spec.roots) {
        const auto native_root = source_paths.at(root.index);
        if (!std::filesystem::is_directory(native_root)) {
            return std::unexpected(Error{ErrorCode::permanent_io, "resumed source root is not a directory: " + native_root.string()});
        }
        const auto root_device = path_device(native_root);
        std::filesystem::recursive_directory_iterator iterator(native_root);
        const auto end = std::filesystem::recursive_directory_iterator();
        while (iterator != end) {
            const auto entry = *iterator;
            std::error_code error;
            const auto status = entry.symlink_status(error);
            if (error) {
                return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
            }
            const auto relative = relative_path(native_root, entry.path());
            const auto seen = runtime.seen.add(root.uuid, relative, {});
            if (!seen) {
                return std::unexpected(seen.error());
            }
            const auto advance = [&]() -> domain::Result<void> {
                iterator.increment(error);
                if (error) {
                    return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
                }
                return {};
            };
            if (!valid_utf8(relative)) {
                const auto selected = runtime.spec.selection.unsupported == "fail"
                    ? runtime.writer.append_failure(FailureInfo{root.index, display_path(relative), "non-UTF-8 filename"})
                    : runtime.writer.append_policy_skip(PolicySkip{root.index, display_path(relative), "non-UTF-8 filename"});
                if (!selected) {
                    return std::unexpected(selected.error());
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
            if (std::filesystem::is_directory(status)) {
                if (path_prefix(canonical_repository, entry.path())) {
                    iterator.disable_recursion_pending();
                    const auto advanced = advance();
                    if (!advanced) {
                        return std::unexpected(advanced.error());
                    }
                    continue;
                }
                const auto previous = runtime.processed.find(root.uuid, relative);
                if (!previous) {
                    return std::unexpected(previous.error());
                }
                if (*previous) {
                    const auto advanced = advance();
                    if (!advanced) {
                        return std::unexpected(advanced.error());
                    }
                    continue;
                }
                if (runtime.spec.selection.one_file_system && path_device(entry.path()) != root_device) {
                    const auto selected = runtime.writer.append_policy_skip(PolicySkip{root.index, relative, "filesystem boundary"});
                    if (!selected) {
                        return std::unexpected(selected.error());
                    }
                    ++runtime.skipped;
                    iterator.disable_recursion_pending();
                } else {
                    const auto directory = directory_info(root.index, relative, entry.path());
                    const auto appended = runtime.writer.append_directory(directory);
                    if (!appended) {
                        return std::unexpected(appended.error());
                    }
                    const auto journaled = runtime.journal.append(JournalRecordType::directory, {
                        {"schema", "cpcp.directory.v1"},
                        {"root", directory.root},
                        {"path", directory.path},
                        {"mtime", {{"seconds", std::to_string(directory.mtime_seconds)}, {"nanoseconds", directory.mtime_nanoseconds}}},
                        {"mode", directory.mode},
                    }, true);
                    if (!journaled) {
                        return std::unexpected(journaled.error());
                    }
                    ++runtime.stats.directories;
                }
                const auto advanced = advance();
                if (!advanced) {
                    return std::unexpected(advanced.error());
                }
                continue;
            }
            if (!std::filesystem::is_regular_file(status)) {
                const auto previous = runtime.processed.find(root.uuid, relative);
                if (!previous) {
                    return std::unexpected(previous.error());
                }
                if (!*previous) {
                    if (runtime.spec.selection.unsupported == "fail") {
                        const auto appended = runtime.writer.append_failure(FailureInfo{root.index, relative, "unsupported entry type"});
                        if (!appended) {
                            return std::unexpected(appended.error());
                        }
                        ++runtime.failed;
                        const auto journaled = runtime.journal.append(JournalRecordType::failure, {{"schema", "cpcp.failure.v1"}, {"root", root.index}, {"path", relative}, {"reason", "unsupported entry type"}}, true);
                        if (!journaled) {
                            return std::unexpected(journaled.error());
                        }
                    } else {
                        const auto appended = runtime.writer.append_policy_skip(PolicySkip{root.index, relative, "unsupported entry type"});
                        if (!appended) {
                            return std::unexpected(appended.error());
                        }
                        ++runtime.skipped;
                        const auto journaled = runtime.journal.append(JournalRecordType::policy_skip, {{"schema", "cpcp.policy-skip.v1"}, {"root", root.index}, {"path", relative}, {"reason", "unsupported entry type"}}, true);
                        if (!journaled) {
                            return std::unexpected(journaled.error());
                        }
                    }
                }
                const auto advanced = advance();
                if (!advanced) {
                    return std::unexpected(advanced.error());
                }
                continue;
            }
            const auto previous = runtime.processed.find(root.uuid, relative);
            if (!previous) {
                return std::unexpected(previous.error());
            }
            if (*previous) {
                auto file = platform::BinaryFile::open_read(entry.path());
                if (!file) {
                    return std::unexpected(file.error());
                }
                const auto metadata = file->metadata();
                if (!metadata) {
                    return std::unexpected(metadata.error());
                }
                if (metadata->size != (*previous)->size
                    || metadata->mtime_seconds != (*previous)->mtime_seconds
                    || metadata->mtime_nanoseconds != (*previous)->mtime_nanoseconds
                    || metadata->mode != (*previous)->mode
                    || metadata->device != (*previous)->device
                    || metadata->inode != (*previous)->inode) {
                    return std::unexpected(Error{ErrorCode::source_changed, "completed source file changed; use --restart-files: " + relative});
                }
                const auto advanced = advance();
                if (!advanced) {
                    return std::unexpected(advanced.error());
                }
                continue;
            }
            std::optional<ActiveFile> current;
            if (active && active->info.root == root.index && active->info.path == relative) {
                current.emplace(std::move(*active));
                active.reset();
            }
            const auto captured = capture_file(runtime, root, entry.path(), relative, std::move(current));
            if (!captured) {
                return std::unexpected(captured.error());
            }
            const auto advanced = advance();
            if (!advanced) {
                return std::unexpected(advanced.error());
            }
        }
    }
    const auto seen_finished = runtime.seen.finish();
    if (!seen_finished) {
        return std::unexpected(seen_finished.error());
    }
    const auto sources_verified = runtime.journal.replay([&](const repository::JournalRecord& record) -> domain::Result<void> {
        if (record.type != JournalRecordType::directory && record.type != JournalRecordType::file_complete) {
            return {};
        }
        std::uint32_t root_index = 0;
        std::string path;
        if (record.type == JournalRecordType::directory) {
            root_index = record.payload.at("root").get<std::uint32_t>();
            path = record.payload.at("path").get<std::string>();
        } else {
            const auto file = parse_file(record.payload.at("file"));
            if (!file) {
                return std::unexpected(file.error());
            }
            if (record.sequence < restarts.at(file->root)) {
                return {};
            }
            root_index = file->root;
            path = file->path;
        }
        const auto root = std::ranges::find_if(runtime.spec.roots, [&](const RootInfo& candidate) {
            return candidate.index == root_index;
        });
        if (root == runtime.spec.roots.end()) {
            return std::unexpected(Error{ErrorCode::integrity, "journal source check references an unknown root"});
        }
        const auto present = runtime.seen.find(root->uuid, path);
        if (!present) {
            return std::unexpected(present.error());
        }
        if (!*present) {
            return std::unexpected(Error{ErrorCode::source_changed, "a journaled source path is missing; use --restart-files: " + path});
        }
        return {};
    });
    if (!sources_verified) {
        return std::unexpected(sources_verified.error());
    }
    if (active) {
        return std::unexpected(Error{ErrorCode::source_changed, "resumed partial file is missing; use --restart-files"});
    }
    if (runtime.failed != 0 && !runtime.spec.allow_partial) {
        const auto aborted = runtime.writer.abort();
        if (!aborted) {
            return std::unexpected(aborted.error());
        }
        return std::unexpected(Error{ErrorCode::source_changed, std::to_string(runtime.failed) + " required entries failed; no snapshot was published; resume session " + hex(runtime.spec.context.session_uuid)});
    }
    const auto commitment = runtime.chunk_set.finish();
    if (!commitment) {
        return std::unexpected(commitment.error());
    }
    runtime.stats.chunk_set_commitment = *commitment;
    auto summary = runtime.writer.finish(
        runtime.stats,
        runtime.failed == 0 ? "complete" : "partial",
        runtime.interrupt_main
    );
    if (!summary) {
        return std::unexpected(summary.error());
    }
    const auto committed = runtime.journal.append(JournalRecordType::committed, {
        {"snapshot", hex(summary->context.snapshot_uuid)},
        {"main_digest", crypto::to_hex(summary->main_ciphertext_digest)},
    }, true);
    if (!committed) {
        return std::unexpected(committed.error());
    }
    const auto closed = runtime.journal.close();
    if (!closed) {
        return std::unexpected(closed.error());
    }
    const auto cleaned = clean_session_files(runtime.repository, runtime.spec.context.session_uuid);
    if (!cleaned) {
        return std::unexpected(cleaned.error());
    }
    return BackupReport{std::move(*summary), runtime.skipped, runtime.spec.context.session_uuid, resumed};
}

domain::Result<Runtime> make_runtime(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    SessionSpec spec,
    std::optional<repository::SnapshotSummary> parent,
    repository::SessionJournal journal,
    bool revalidate_all,
    std::uint64_t interrupt_after,
    bool interrupt_main
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto store = repository::ChunkStore::create(repository, unlocked->config, unlocked->master_key);
    if (!store) {
        return std::unexpected(store.error());
    }
    store->set_revalidate_all(revalidate_all);
    auto id_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::content_id);
    if (!id_key) {
        return std::unexpected(id_key.error());
    }
    auto journal_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::journal_encryption);
    if (!journal_key) {
        return std::unexpected(journal_key.error());
    }
    if (parent) {
        const auto evidence = add_base_evidence(repository, unlocked->config, unlocked->master_key, *parent, *store, *id_key);
        if (!evidence) {
            return std::unexpected(evidence.error());
        }
    }
    auto chunk_set = repository::ChunkSetBuilder::create(repository / "tmp" / "new-chunk-set", *id_key);
    if (!chunk_set) {
        return std::unexpected(chunk_set.error());
    }
    auto writer = repository::SnapshotWriter::create(
        repository,
        unlocked->config,
        unlocked->master_key,
        spec.context,
        spec.context.session_uuid,
        parent,
        spec.selection
    );
    if (!writer) {
        return std::unexpected(writer.error());
    }
    const auto temporary = std::filesystem::temp_directory_path() / ("cpcp-session-" + hex(spec.context.session_uuid));
    std::filesystem::remove_all(temporary);
    auto processed = repository::SnapshotPathIndex::create(temporary / "processed", *id_key);
    if (!processed) {
        return std::unexpected(processed.error());
    }
    auto seen = repository::SnapshotPathIndex::create(temporary / "seen", *id_key);
    if (!seen) {
        return std::unexpected(seen.error());
    }
    return Runtime{
        repository,
        std::move(unlocked->config),
        std::move(unlocked->master_key),
        std::move(spec),
        std::move(parent),
        std::move(journal),
        std::move(store).value(),
        std::move(id_key).value(),
        std::move(journal_key).value(),
        std::move(chunk_set).value(),
        std::move(writer).value(),
        std::move(processed).value(),
        std::move(seen).value(),
        {},
        0,
        0,
        0,
        0,
        interrupt_after,
        interrupt_main,
    };
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
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::backup(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    std::optional<repository::SnapshotSummary> parent;
    if (!options.no_parent && !summaries->empty()) {
        parent = summaries->back();
    }
    SessionSpec spec;
    spec.context.repository_uuid = unlocked->config.repository_uuid;
    spec.context.storage_epoch = unlocked->config.storage_epoch;
    spec.context.snapshot_uuid = crypto::random_uuid();
    spec.context.lineage_uuid = parent ? parent->context.lineage_uuid : crypto::random_uuid();
    spec.context.session_uuid = crypto::random_uuid();
    spec.context.generation = summaries->empty() ? 1 : summaries->back().context.generation + 1;
    spec.selection = repository::SelectionPolicy{options.unsupported_fail ? "fail" : "skip", !options.cross_file_systems};
    spec.allow_partial = options.allow_partial;
    spec.has_parent = parent.has_value();
    if (parent) {
        spec.parent_uuid = parent->context.snapshot_uuid;
    }
    const auto canonical_repository = std::filesystem::weakly_canonical(repository);
    std::vector<std::string> labels;
    for (const auto& input : roots) {
        const auto root = std::filesystem::weakly_canonical(input);
        if (!std::filesystem::is_directory(root)) {
            return std::unexpected(Error{ErrorCode::usage, "source root is not a directory"});
        }
        if (path_prefix(canonical_repository, root)) {
            return std::unexpected(Error{ErrorCode::usage, "repository cannot be its own source root"});
        }
        RootInfo info;
        info.index = static_cast<std::uint32_t>(labels.size());
        info.label = root.filename().empty() ? "root" : root.filename().string();
        if (std::ranges::find(labels, info.label) != labels.end()) {
            info.label += "-" + std::to_string(labels.size());
        }
        labels.push_back(info.label);
        info.path = root.string();
        info.uuid = crypto::random_uuid();
        if (parent) {
            const auto previous = std::ranges::find_if(parent->roots, [&](const RootInfo& candidate) {
                return candidate.path == info.path;
            });
            if (previous != parent->roots.end()) {
                info.uuid = previous->uuid;
            }
        }
        spec.roots.push_back(std::move(info));
    }
    auto journal = repository::SessionJournal::create(repository, unlocked->config, unlocked->master_key, spec.context.session_uuid);
    if (!journal) {
        return std::unexpected(journal.error());
    }
    const auto begun = journal->append(JournalRecordType::session, session_json(spec, parent.has_value()), true);
    if (!begun) {
        return std::unexpected(begun.error());
    }
    auto runtime = make_runtime(repository, password, std::move(spec), std::move(parent), std::move(journal).value(), options.revalidate_all, options.interrupt_after_chunks_for_testing, options.interrupt_after_main_for_testing);
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    return execute(std::move(runtime).value(), false);
}

domain::Result<BackupReport> backup_resume(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const domain::Uuid& session_uuid,
    const ResumeOptions& options
) {
    auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto locks = platform::RepositoryLocks::backup(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto journal = repository::SessionJournal::open(repository, unlocked->config, unlocked->master_key, session_uuid);
    if (!journal) {
        return std::unexpected(journal.error());
    }
    std::optional<SessionSpec> spec;
    const auto replayed = journal->replay([&](const repository::JournalRecord& record) -> domain::Result<void> {
        if (record.type == JournalRecordType::session) {
            if (spec) {
                return std::unexpected(Error{ErrorCode::integrity, "journal contains multiple session records"});
            }
            const auto parsed = parse_session(record.payload);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            spec = *parsed;
        }
        return {};
    });
    if (!replayed || !spec || spec->context.session_uuid != session_uuid || spec->context.repository_uuid != unlocked->config.repository_uuid) {
        return std::unexpected(Error{ErrorCode::integrity, "journal has no valid session identity"});
    }
    if (options.restart_files) {
        const auto restarted = journal->append(JournalRecordType::restart_files, {{"all", true}}, true);
        if (!restarted) {
            return std::unexpected(restarted.error());
        }
    }
    for (const auto& [root_text, path] : options.remap_roots) {
        const auto root_uuid = domain::hex_decode<16>(root_text);
        if (!root_uuid || !std::ranges::any_of(spec->roots, [&](const RootInfo& root) { return root.uuid == *root_uuid; })) {
            return std::unexpected(Error{ErrorCode::usage, "remap root UUID does not belong to the session"});
        }
        const auto canonical = std::filesystem::weakly_canonical(path);
        if (!std::filesystem::is_directory(canonical)) {
            return std::unexpected(Error{ErrorCode::usage, "remap destination is not a directory"});
        }
        const auto remapped = journal->append(JournalRecordType::remap_root, {{"root_uuid", root_text}, {"path", canonical.string()}}, true);
        if (!remapped) {
            return std::unexpected(remapped.error());
        }
    }
    const auto summaries = repository::list_snapshots(repository, unlocked->config, unlocked->master_key);
    if (!summaries) {
        return std::unexpected(summaries.error());
    }
    std::optional<repository::SnapshotSummary> parent;
    if (spec->has_parent) {
        const auto found = std::ranges::find_if(*summaries, [&](const repository::SnapshotSummary& summary) {
            return summary.context.snapshot_uuid == spec->parent_uuid;
        });
        if (found == summaries->end()) {
            return std::unexpected(Error{ErrorCode::conflict, "session parent is no longer active"});
        }
        parent = *found;
    }
    auto runtime = make_runtime(repository, password, std::move(*spec), std::move(parent), std::move(journal).value(), options.revalidate_all, options.interrupt_after_chunks_for_testing, options.interrupt_after_main_for_testing);
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    return execute(std::move(runtime).value(), true);
}

domain::Result<std::vector<BackupSessionStatus>> backup_status(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
) {
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto locks = platform::RepositoryLocks::read(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const auto journal_key = crypto::derive_key(unlocked->master_key, crypto::KeyPurpose::journal_encryption);
    if (!journal_key) {
        return std::unexpected(journal_key.error());
    }
    std::vector<BackupSessionStatus> result;
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(repository / "sessions", error)) {
        if (entry.path().extension() != ".journal") {
            continue;
        }
        const auto session = domain::hex_decode<16>(entry.path().stem().string());
        if (!session) {
            return std::unexpected(Error{ErrorCode::integrity, "invalid session journal filename"});
        }
        auto reader = repository::JournalReader::open(entry.path(), unlocked->config.repository_uuid, *session, *journal_key);
        if (!reader) {
            return std::unexpected(reader.error());
        }
        BackupSessionStatus status;
        status.session_uuid = *session;
        status.state = "active";
        while (true) {
            const auto record = reader->next();
            if (!record) {
                return std::unexpected(record.error());
            }
            if (!record->has_value()) {
                break;
            }
            ++status.records;
            if ((*record)->type == JournalRecordType::session) {
                const auto spec = parse_session((*record)->payload);
                if (!spec) {
                    return std::unexpected(spec.error());
                }
                status.snapshot_generation = spec->context.generation;
                status.roots = spec->roots;
            } else if ((*record)->type == JournalRecordType::committed) {
                status.state = "committed";
            }
        }
        status.torn_tail = reader->torn_tail();
        result.push_back(status);
    }
    if (error) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }
    std::ranges::sort(result, [](const BackupSessionStatus& left, const BackupSessionStatus& right) {
        return left.session_uuid < right.session_uuid;
    });
    return result;
}

domain::Result<void> backup_discard(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const domain::Uuid& session_uuid,
    bool confirmed
) {
    if (!confirmed) {
        return std::unexpected(Error{ErrorCode::usage, "discarding a session requires --yes"});
    }
    const auto unlocked = repository::load_config(repository, password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto journal = repository::SessionJournal::open(repository, unlocked->config, unlocked->master_key, session_uuid);
    if (!journal) {
        return std::unexpected(journal.error());
    }
    bool identified = false;
    const auto replayed = journal->replay([&](const repository::JournalRecord& record) -> domain::Result<void> {
        if (record.type == JournalRecordType::session) {
            identified = true;
        }
        return {};
    });
    if (!replayed || !identified) {
        return std::unexpected(Error{ErrorCode::integrity, "session journal has no authenticated identity"});
    }
    const auto closed = journal->close();
    if (!closed) {
        return closed;
    }
    return clean_session_files(repository, session_uuid);
}

}
