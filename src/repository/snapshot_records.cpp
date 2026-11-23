#include "repository/snapshot.hpp"

#include "domain/strict_json.hpp"

#include <charconv>

namespace cpcp::repository {

using domain::Error;
using domain::ErrorCode;
using nlohmann::json;

namespace {

json parse_document(const storage::SpoolRecord& record, std::string_view schema) {
    const auto document = domain::parse_bounded_json(record.plaintext);
    if (!document) {
        throw std::invalid_argument("invalid snapshot record JSON");
    }
    if (!document->is_object() || document->at("schema").get<std::string>() != schema) {
        throw std::invalid_argument("unexpected snapshot record schema");
    }
    return *document;
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

std::uint64_t require_uint_string(const json& object, std::string_view key) {
    const auto text = require_string(object, key);
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid unsigned integer string");
    }
    return result;
}

std::int64_t require_int_string(const json& object, std::string_view key) {
    const auto text = require_string(object, key);
    std::int64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid signed integer string");
    }
    return result;
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

SnapshotStats parse_stats(const json& object) {
    SnapshotStats stats;
    stats.files = require_uint_string(object, "files");
    stats.directories = require_uint_string(object, "directories");
    stats.logical_bytes = require_uint_string(object, "logical_bytes");
    stats.chunk_references = require_uint_string(object, "chunk_references");
    stats.new_chunks = require_uint_string(object, "new_chunks");
    stats.deduplicated_chunks = require_uint_string(object, "deduplicated_chunks");
    if (object.contains("source_reused_files")) {
        stats.source_reused_files = require_uint_string(object, "source_reused_files");
    }
    stats.chunk_set_commitment = require_hex<32>(object, "chunk_set_commitment");
    if (object.contains("selection")) {
        const auto& selection = object.at("selection");
        stats.selection = SelectionStats{
            require_uint_string(selection, "policy_skipped_entries"),
            require_uint_string(selection, "failed_entries"),
        };
    }
    return stats;
}

}

domain::Result<crypto::SnapshotContext> parse_snapshot_context(
    const storage::SpoolRecord& record
) {
    try {
        const auto document = parse_document(record, "cpcp.snapshot-context.v1");
        crypto::SnapshotContext context;
        context.repository_uuid = require_hex<16>(document, "repository_uuid");
        context.storage_epoch = require_hex<16>(document, "storage_epoch");
        context.snapshot_uuid = require_hex<16>(document, "snapshot_uuid");
        context.lineage_uuid = require_hex<16>(document, "lineage_uuid");
        context.generation = require_uint_string(document, "generation");
        context.session_uuid = require_hex<16>(document, "session_uuid");
        return context;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<SnapshotHeaderInfo> parse_snapshot_header(
    const storage::SpoolRecord& record
) {
    try {
        const auto document = parse_document(record, "cpcp.snapshot-header.v1");
        SnapshotHeaderInfo header;
        const auto& created = document.at("created_at");
        header.created_seconds = require_int_string(created, "seconds");
        header.created_nanoseconds = static_cast<std::uint32_t>(require_uint(created, "nanoseconds"));
        header.tool_version = require_string(document, "tool_version");
        if (document.contains("selection")) {
            const auto& selection = document.at("selection");
            header.selection_policy.unsupported = require_string(selection, "unsupported");
            header.selection_policy.one_file_system = selection.at("one_file_system").get<bool>();
            if (selection.contains("exclusions")) {
                header.selection_policy.exclusions = selection.at("exclusions").get<std::vector<std::string>>();
            }
            if (header.selection_policy.unsupported != "skip"
                && header.selection_policy.unsupported != "fail") {
                throw std::invalid_argument("invalid unsupported-entry policy");
            }
        }
        header.has_parent = document.at("has_parent").get<bool>();
        if (header.has_parent) {
            header.parent_uuid = require_hex<16>(document, "parent_uuid");
            header.parent_summary_digest = require_hex<32>(document, "parent_summary_digest");
        }
        return header;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<RootInfo> parse_root(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.root.v1");
        return RootInfo{
            static_cast<std::uint32_t>(require_uint(document, "index")),
            require_hex<16>(document, "uuid"),
            require_string(document, "label"),
            require_string(document, "path"),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<DirectoryInfo> parse_directory(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.directory.v1");
        const auto& mtime = document.at("mtime");
        return DirectoryInfo{
            static_cast<std::uint32_t>(require_uint(document, "root")),
            require_string(document, "path"),
            require_int_string(mtime, "seconds"),
            static_cast<std::uint32_t>(require_uint(mtime, "nanoseconds")),
            static_cast<std::uint32_t>(require_uint(document, "mode")),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<FileInfo> parse_file_header(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.file.v1");
        const auto& mtime = document.at("mtime");
        return FileInfo{
            require_uint_string(document, "sequence"),
            static_cast<std::uint32_t>(require_uint(document, "root")),
            require_string(document, "path"),
            require_uint_string(document, "size"),
            require_uint_string(document, "chunk_count"),
            require_hex<32>(document, "file_id"),
            require_int_string(mtime, "seconds"),
            static_cast<std::uint32_t>(require_uint(mtime, "nanoseconds")),
            static_cast<std::uint32_t>(require_uint(document, "mode")),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<ChunkBatch> parse_chunk_batch(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.chunk-batch.v1");
        ChunkBatch batch;
        batch.file = require_uint_string(document, "file");
        batch.batch = require_uint_string(document, "batch");
        for (const auto& chunk : document.at("chunks")) {
            batch.chunks.push_back(crypto::ChunkDescriptor{
                require_hex<32>(chunk, "id"),
                static_cast<std::uint32_t>(require_uint(chunk, "plain")),
                require_uint_string(chunk, "stored"),
                chunk.contains("version") ? static_cast<std::uint32_t>(require_uint(chunk, "version")) : 1,
                static_cast<std::uint16_t>(chunk.contains("encoding") ? require_uint(chunk, "encoding") : 0),
            });
        }
        return batch;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<FileEnd> parse_file_end(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.file-end.v1");
        return FileEnd{
            require_uint_string(document, "file"),
            require_uint_string(document, "chunk_count"),
            require_hex<32>(document, "file_id"),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<PolicySkip> parse_policy_skip(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.policy-skip.v1");
        return PolicySkip{
            static_cast<std::uint32_t>(require_uint(document, "root")),
            require_string(document, "path"),
            require_string(document, "reason"),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<FailureInfo> parse_failure(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.failure.v1");
        return FailureInfo{
            static_cast<std::uint32_t>(require_uint(document, "root")),
            require_string(document, "path"),
            require_string(document, "reason"),
        };
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<SnapshotStats> parse_final_stats(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.snapshot-final.v1");
        return parse_stats(document.at("stats"));
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

domain::Result<std::string> parse_final_status(const storage::SpoolRecord& record) {
    try {
        const auto document = parse_document(record, "cpcp.snapshot-final.v1");
        const auto status = require_string(document, "status");
        if (status != "complete" && status != "partial") {
            throw std::invalid_argument("invalid final snapshot status");
        }
        return status;
    } catch (const std::exception& error) {
        return std::unexpected(Error{ErrorCode::integrity, error.what()});
    }
}

}
