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
        }},
        {"roots", roots},
        {"stats", stats_json(summary.stats)},
        {"verification_scope", "authenticated-summary-and-main-length"},
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
    std::optional<std::uint64_t> generation;
    if (selector != "latest" && selector != "latest-complete") {
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(
            selector.data(),
            selector.data() + selector.size(),
            value
        );
        if (parsed.ec != std::errc{} || parsed.ptr != selector.data() + selector.size()) {
            return report_error(Error{ErrorCode::usage, "invalid snapshot generation"});
        }
        generation = value;
    }
    restore.repo_read_only = options.repo_read_only;
    restore.latest_complete = selector == "latest-complete";
    auto report = application::restore_snapshot(
        options.repository,
        *password,
        generation,
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
    bool deep
) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    auto report = application::verify_repository(
        options.repository,
        *password,
        application::VerifyOptions{deep, options.repo_read_only}
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
        }.dump(2) << '\n';
    } else {
        std::cout << "Verified " << report->snapshots << " snapshots and "
                  << report->chunks << " chunk references\n";
    }
    return 0;
}

}
