#include "cli/inspection_command.hpp"

#include "application/credentials.hpp"
#include "cli/errors.hpp"
#include "platform/lock.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <iostream>

namespace cpcp::cli {

using domain::Error;
using domain::ErrorCode;

namespace {

nlohmann::json stats_json(const repository::SnapshotStats& stats) {
    auto document = nlohmann::json{
        {"files", std::to_string(stats.files)},
        {"directories", std::to_string(stats.directories)},
        {"logical_bytes", std::to_string(stats.logical_bytes)},
        {"chunk_references", std::to_string(stats.chunk_references)},
        {"new_chunks", std::to_string(stats.new_chunks)},
        {"deduplicated_chunks", std::to_string(stats.deduplicated_chunks)},
        {"source_reused_files", std::to_string(stats.source_reused_files)},
    };
    if (stats.selection) {
        document["policy_skipped_entries"] = std::to_string(stats.selection->policy_skipped_entries);
        document["failed_entries"] = std::to_string(stats.selection->failed_entries);
    }
    return document;
}

nlohmann::json summary_json(const repository::SnapshotSummary& summary) {
    auto roots = nlohmann::json::array();
    for (const auto& root : summary.roots) {
        roots.push_back({
            {"index", root.index},
            {"uuid", domain::hex_encode(root.uuid)},
            {"label", root.label},
            {"path", root.path},
        });
    }
    return {
        {"generation", std::to_string(summary.context.generation)},
        {"snapshot_uuid", domain::hex_encode(summary.context.snapshot_uuid)},
        {"lineage_uuid", domain::hex_encode(summary.context.lineage_uuid)},
        {"status", summary.status},
        {"selection_policy", {
            {"unsupported", summary.selection_policy.unsupported},
            {"one_file_system", summary.selection_policy.one_file_system},
            {"exclusions", summary.selection_policy.exclusions},
        }},
        {"roots", roots},
        {"stats", stats_json(summary.stats)},
        {"verification_scope", "authenticated-summary-and-main-length"},
    };
}

domain::Result<application::SnapshotRequest> parse_snapshot_request(const std::string& selector) {
    application::SnapshotRequest request;
    if (selector == "latest") {
        return request;
    }
    if (selector == "latest-complete") {
        request.latest_complete = true;
        return request;
    }
    std::uint64_t generation = 0;
    const auto parsed = std::from_chars(
        selector.data(),
        selector.data() + selector.size(),
        generation
    );
    if (selector.empty() || parsed.ec != std::errc{} || parsed.ptr != selector.data() + selector.size()) {
        return std::unexpected(Error{ErrorCode::usage, "invalid snapshot generation"});
    }
    request.generation = generation;
    return request;
}

nlohmann::json entry_json(const application::SnapshotEntry& entry) {
    return {
        {"type", entry.type},
        {"root", entry.root},
        {"root_label", entry.root_label},
        {"path", entry.path},
        {"size", std::to_string(entry.size)},
        {"mtime", {
            {"seconds", std::to_string(entry.mtime_seconds)},
            {"nanoseconds", entry.mtime_nanoseconds},
        }},
        {"mode", entry.mode},
    };
}

}

int run_snapshot_list_command(const InspectionCommandOptions& options) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    if (!options.repo_read_only) {
        const auto locks = platform::RepositoryLocks::read(options.repository);
        if (!locks) {
            return report_error(locks.error());
        }
    }
    const auto unlocked = repository::load_config(options.repository, *password);
    if (!unlocked) {
        return report_error(unlocked.error());
    }
    const auto summaries = repository::list_snapshots(
        options.repository,
        unlocked->config,
        unlocked->master_key
    );
    if (!summaries) {
        return report_error(summaries.error());
    }

    if (options.config.json) {
        auto documents = nlohmann::json::array();
        for (const auto& summary : *summaries) {
            documents.push_back(summary_json(summary));
        }
        std::cout << nlohmann::json{
            {"schema", "cpcp.snapshot-list.v1"},
            {"degraded_redundancy", unlocked->degraded_redundancy},
            {"snapshots", documents},
        }.dump(2) << '\n';
    } else {
        for (const auto& summary : *summaries) {
            std::cout << summary.context.generation << "  " << summary.status << "  "
                      << summary.stats.files << " files\n";
        }
    }
    return 0;
}

int run_snapshot_show_command(
    const InspectionCommandOptions& options,
    std::uint64_t generation
) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    if (!options.repo_read_only) {
        const auto locks = platform::RepositoryLocks::read(options.repository);
        if (!locks) {
            return report_error(locks.error());
        }
    }
    const auto unlocked = repository::load_config(options.repository, *password);
    if (!unlocked) {
        return report_error(unlocked.error());
    }
    const auto summaries = repository::list_snapshots(
        options.repository,
        unlocked->config,
        unlocked->master_key
    );
    if (!summaries) {
        return report_error(summaries.error());
    }
    const auto summary = std::ranges::find_if(*summaries, [&](const repository::SnapshotSummary& candidate) {
        return candidate.context.generation == generation;
    });
    if (summary == summaries->end()) {
        return report_error(Error{ErrorCode::permanent_io, "snapshot generation was not found"});
    }

    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.snapshot-show.v1"},
            {"snapshot", summary_json(*summary)},
        }.dump(2) << '\n';
    } else {
        std::cout << "Generation: " << summary->context.generation << '\n'
                  << "Status: " << summary->status << '\n';
        for (const auto& root : summary->roots) {
            std::cout << "Root " << root.index << " (" << root.label << "): "
                      << root.path << '\n';
        }
    }
    return 0;
}

int run_restore_command(
    const InspectionCommandOptions& options,
    const std::string& selector,
    application::RestoreOptions restore
) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto request = parse_snapshot_request(selector);
    if (!request) {
        return report_error(request.error());
    }
    restore.repo_read_only = options.repo_read_only;
    restore.latest_complete = request->latest_complete;
    auto report = application::restore_snapshot(
        options.repository,
        *password,
        request->generation,
        restore
    );
    if (!report) {
        return report_error(report.error());
    }

    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.snapshot-restore.v1"},
            {"snapshot", std::to_string(report->snapshot_generation)},
            {"snapshot_status", report->snapshot_status},
            {"files", std::to_string(report->files)},
            {"directories", std::to_string(report->directories)},
            {"metadata_warnings", std::to_string(report->metadata_warnings)},
            {"destination", restore.destination.string()},
            {"verification_scope", "full-manifest-and-selected-chunks"},
        }.dump(2) << '\n';
    } else {
        std::cout << "Restored " << report->files << " files from snapshot "
                  << report->snapshot_generation << " (" << report->snapshot_status
                  << ") to " << restore.destination << '\n';
    }
    return 0;
}

int run_verify_command(
    const InspectionCommandOptions& options,
    bool deep,
    bool refresh_validation_cache
) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    auto report = application::verify_repository(
        options.repository,
        *password,
        application::VerifyOptions{deep, options.repo_read_only, refresh_validation_cache}
    );
    if (!report) {
        return report_error(report.error());
    }

    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.repo-verify.v1"},
            {"snapshots", std::to_string(report->snapshots)},
            {"chunks", std::to_string(report->chunks)},
            {"deep", deep},
            {"degraded_redundancy", report->degraded_redundancy},
            {"cache_updated", report->cache_updated},
            {"cache_error", report->cache_error.empty() ? nlohmann::json(nullptr) : nlohmann::json(report->cache_error)},
        }.dump(2) << '\n';
    } else {
        std::cout << "Verified " << report->snapshots << " snapshots and "
                  << report->chunks << " chunk references\n";
    }
    if (!report->cache_error.empty()) {
        std::cerr << "Warning: validation-cache refresh failed: " << report->cache_error << '\n';
    }
    return !report->cache_error.empty() || report->degraded_redundancy ? 3 : 0;
}

int run_repo_stats_command(const InspectionCommandOptions& options) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto report = application::repository_statistics(options.repository, *password);
    if (!report) {
        return report_error(report.error());
    }
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.repo-stats.v1"},
            {"snapshots", std::to_string(report->snapshots)},
            {"latest_generation", std::to_string(report->latest_generation)},
            {"logical_bytes", std::to_string(report->logical_bytes)},
            {"chunk_objects", std::to_string(report->chunk_objects)},
            {"chunk_stored_bytes", std::to_string(report->chunk_stored_bytes)},
            {"chunk_allocated_bytes", std::to_string(report->chunk_allocated_bytes)},
            {"snapshot_main_bytes", std::to_string(report->snapshot_main_bytes)},
            {"snapshot_summary_bytes", std::to_string(report->snapshot_summary_bytes)},
            {"session_files", std::to_string(report->session_files)},
            {"cache_files", std::to_string(report->cache_files)},
            {"quarantine_files", std::to_string(report->quarantine_files)},
            {"trash_files", std::to_string(report->trash_files)},
        }.dump(2) << '\n';
    } else {
        std::cout << "Snapshots: " << report->snapshots << "\nLogical bytes: " << report->logical_bytes
                  << "\nChunks: " << report->chunk_objects << "\nChunk stored bytes: "
                  << report->chunk_stored_bytes << "\nChunk allocated bytes: "
                  << report->chunk_allocated_bytes << "\nSession files: " << report->session_files
                  << "\nQuarantine files: " << report->quarantine_files
                  << "\nTrash files: " << report->trash_files << '\n';
    }
    return 0;
}

int run_snapshot_browse_command(
    const InspectionCommandOptions& options,
    const std::string& selector,
    const std::string& root_selector,
    application::BrowseOptions browse
) {
    if (options.config.json && options.ndjson) {
        return report_error(Error{ErrorCode::usage, "--json and --ndjson are mutually exclusive"});
    }
    const auto request = parse_snapshot_request(selector);
    if (!request) {
        return report_error(request.error());
    }
    browse.snapshot = *request;
    if (!root_selector.empty()) {
        if (root_selector.starts_with("index:")) {
            std::uint32_t index = 0;
            const auto* first = root_selector.data() + 6;
            const auto* last = root_selector.data() + root_selector.size();
            const auto parsed = std::from_chars(first, last, index);
            if (parsed.ec != std::errc{} || parsed.ptr != last) {
                return report_error(Error{ErrorCode::usage, "invalid root index"});
            }
            browse.root = index;
        } else if (root_selector.starts_with("label:") && root_selector.size() > 6) {
            browse.root_label = root_selector.substr(6);
        } else {
            return report_error(Error{ErrorCode::usage, "root selector must use index:<n> or label:<name>"});
        }
    }

    auto password = application::read_password(
        options.config.password_file,
        !options.config.json && !options.ndjson
    );
    if (!password) {
        return report_error(password.error());
    }

    constexpr std::size_t json_entry_limit = 4096;
    auto entries = nlohmann::json::array();
    bool header_written = false;
    const auto write_header = [&] {
        if (options.ndjson && !header_written) {
            std::cout << nlohmann::json{
                {"schema", "cpcp.snapshot-entries-header.v1"},
                {"operation", browse.glob.empty() ? "ls" : "find"},
            }.dump() << '\n';
            header_written = true;
        }
    };
    const auto sink = [&](const application::SnapshotEntry& entry) -> domain::Result<void> {
        write_header();
        if (options.config.json) {
            if (entries.size() == json_entry_limit) {
                return std::unexpected(Error{
                    ErrorCode::usage,
                    "snapshot result exceeds the bounded --json limit; use --ndjson",
                });
            }
            entries.push_back(entry_json(entry));
        } else if (options.ndjson) {
            auto document = entry_json(entry);
            document["schema"] = "cpcp.snapshot-entry.v1";
            std::cout << document.dump() << '\n';
        } else {
            std::cout << entry.type << "  " << entry.root_label << '/'
                      << entry.path << "  " << entry.size << " bytes\n";
        }
        if (!std::cout) {
            return std::unexpected(Error{ErrorCode::permanent_io, "failed to write snapshot entries"});
        }
        return {};
    };

    const auto report = application::browse_snapshot(
        options.repository,
        *password,
        browse,
        options.repo_read_only,
        sink
    );
    if (!report) {
        return report_error(report.error());
    }
    write_header();
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.snapshot-entries.v1"},
            {"snapshot", std::to_string(report->snapshot_generation)},
            {"snapshot_status", report->snapshot_status},
            {"entries", entries},
            {"verification_scope", "full-authenticated-manifest"},
        }.dump(2) << '\n';
    } else if (options.ndjson) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.snapshot-entries-summary.v1"},
            {"snapshot", std::to_string(report->snapshot_generation)},
            {"snapshot_status", report->snapshot_status},
            {"entries", std::to_string(report->entries)},
            {"verification_scope", "full-authenticated-manifest"},
        }.dump() << '\n';
    } else {
        std::cout << "Listed " << report->entries << " entries from snapshot "
                  << report->snapshot_generation << " (" << report->snapshot_status << ")\n";
    }
    if (!std::cout) {
        return report_error(Error{ErrorCode::permanent_io, "failed to write snapshot report"});
    }
    return 0;
}

}
