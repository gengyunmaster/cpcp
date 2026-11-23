#include "cli/backup_command.hpp"

#include "application/credentials.hpp"
#include "cli/errors.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <iostream>

namespace cpcp::cli {

namespace {

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
        return std::unexpected(domain::Error{domain::ErrorCode::usage, "invalid snapshot generation"});
    }
    request.generation = generation;
    return request;
}

nlohmann::json event_json(const application::CheckEvent& event) {
    return {
        {"root", event.root},
        {"path", event.path},
        {"status", event.status},
        {"reason", event.reason.empty() ? nlohmann::json(nullptr) : nlohmann::json(event.reason)},
        {"size", std::to_string(event.size)},
    };
}

domain::Result<domain::Uuid> parse_session_id(const std::string& text) {
    const auto session = domain::hex_decode<16>(text);
    if (!session) {
        return std::unexpected(domain::Error{domain::ErrorCode::usage, "session ID must be 32 lowercase hexadecimal characters"});
    }
    return *session;
}

}

int run_backup_add_command(
    const std::vector<std::filesystem::path>& roots,
    const BackupCommandOptions& options
) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    auto report = application::backup_add(options.repository, *password, roots, options.backup);
    if (!report) {
        return report_error(report.error());
    }

    const auto& snapshot = report->snapshot;
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.backup-add.v1"},
            {"generation", std::to_string(snapshot.context.generation)},
            {"snapshot_uuid", domain::hex_encode(snapshot.context.snapshot_uuid)},
            {"lineage_uuid", domain::hex_encode(snapshot.context.lineage_uuid)},
            {"status", snapshot.status},
            {"stats", {
                {"files", std::to_string(snapshot.stats.files)},
                {"directories", std::to_string(snapshot.stats.directories)},
                {"logical_bytes", std::to_string(snapshot.stats.logical_bytes)},
                {"chunk_references", std::to_string(snapshot.stats.chunk_references)},
                {"new_chunks", std::to_string(snapshot.stats.new_chunks)},
                {"deduplicated_chunks", std::to_string(snapshot.stats.deduplicated_chunks)},
            }},
            {"skipped_entries", std::to_string(report->skipped_entries)},
            {"failed_entries", std::to_string(snapshot.stats.selection
                ? snapshot.stats.selection->failed_entries
                : 0)},
        }.dump(2) << '\n';
    } else {
        std::cout << "Published snapshot " << snapshot.context.generation
                  << " with " << snapshot.stats.files << " files and "
                  << snapshot.stats.new_chunks << " new chunks\n";
    }
    return snapshot.status == "partial" ? 3 : 0;
}

int run_backup_check_command(
    const std::string& selector,
    const std::string& root_selector,
    const CheckCommandOptions& options
) {
    if (options.config.json && options.ndjson) {
        return report_error(domain::Error{
            domain::ErrorCode::usage,
            "--json and --ndjson are mutually exclusive",
        });
    }
    auto check = options.check;
    const auto request = parse_snapshot_request(selector);
    if (!request) {
        return report_error(request.error());
    }
    check.snapshot = *request;
    if (!root_selector.empty()) {
        if (root_selector.starts_with("index:")) {
            std::uint32_t index = 0;
            const auto* first = root_selector.data() + 6;
            const auto* last = root_selector.data() + root_selector.size();
            const auto parsed = std::from_chars(first, last, index);
            if (parsed.ec != std::errc{} || parsed.ptr != last) {
                return report_error(domain::Error{domain::ErrorCode::usage, "invalid root index"});
            }
            check.root = index;
        } else if (root_selector.starts_with("label:") && root_selector.size() > 6) {
            check.root_label = root_selector.substr(6);
        } else {
            return report_error(domain::Error{
                domain::ErrorCode::usage,
                "root selector must use index:<n> or label:<name>",
            });
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
                {"schema", "cpcp.check-header.v1"},
                {"operation", "backup check"},
            }.dump() << '\n';
            header_written = true;
        }
    };
    const auto sink = [&](const application::CheckEvent& event) -> domain::Result<void> {
        write_header();
        if (options.config.json) {
            if (entries.size() == json_entry_limit) {
                return std::unexpected(domain::Error{
                    domain::ErrorCode::usage,
                    "check result exceeds the bounded --json limit; use --ndjson",
                });
            }
            entries.push_back(event_json(event));
        } else if (options.ndjson) {
            auto document = event_json(event);
            document["schema"] = "cpcp.check-entry.v1";
            std::cout << document.dump() << '\n';
        } else {
            std::cout << event.status << "  " << event.path;
            if (!event.reason.empty()) {
                std::cout << "  " << event.reason;
            }
            std::cout << '\n';
        }
        if (!std::cout) {
            return std::unexpected(domain::Error{
                domain::ErrorCode::permanent_io,
                "failed to write check results",
            });
        }
        return {};
    };
    const auto report = application::check_backup(options.repository, *password, check, sink);
    if (!report) {
        return report_error(report.error());
    }
    write_header();
    const auto summary = nlohmann::json{
        {"total", std::to_string(report->total)},
        {"differences", std::to_string(report->differences)},
        {"repository_chunk_references", std::to_string(report->repository_chunk_references)},
    };
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.check.v1"},
            {"snapshot", std::to_string(report->snapshot_generation)},
            {"snapshot_status", report->snapshot_status},
            {"root", report->root},
            {"root_label", report->root_label},
            {"source", check.source.string()},
            {"mode", report->mode},
            {"summary", summary},
            {"files", entries},
        }.dump(2) << '\n';
    } else if (options.ndjson) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.check-summary.v1"},
            {"snapshot", std::to_string(report->snapshot_generation)},
            {"snapshot_status", report->snapshot_status},
            {"root", report->root},
            {"root_label", report->root_label},
            {"source", check.source.string()},
            {"mode", report->mode},
            {"summary", summary},
        }.dump() << '\n';
    } else {
        std::cout << "Checked " << report->total << " entries against snapshot "
                  << report->snapshot_generation << " using " << report->mode
                  << " mode; differences: " << report->differences << '\n';
    }
    if (!std::cout) {
        return report_error(domain::Error{
            domain::ErrorCode::permanent_io,
            "failed to write the check report",
        });
    }
    return report->differences == 0 ? 0 : 3;
}

int run_backup_status_command(const SessionCommandOptions& options) {
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto sessions = application::backup_status(options.repository, *password);
    if (!sessions) {
        return report_error(sessions.error());
    }
    if (options.config.json) {
        auto documents = nlohmann::json::array();
        for (const auto& session : *sessions) {
            auto roots = nlohmann::json::array();
            for (const auto& root : session.roots) {
                roots.push_back({
                    {"index", root.index},
                    {"uuid", domain::hex_encode(root.uuid)},
                    {"label", root.label},
                    {"path", root.path},
                });
            }
            documents.push_back({
                {"session", domain::hex_encode(session.session_uuid)},
                {"snapshot", std::to_string(session.snapshot_generation)},
                {"records", std::to_string(session.records)},
                {"state", session.state},
                {"torn_tail", session.torn_tail},
                {"roots", roots},
            });
        }
        std::cout << nlohmann::json{
            {"schema", "cpcp.backup-status.v1"},
            {"sessions", documents},
        }.dump(2) << '\n';
    } else {
        for (const auto& session : *sessions) {
            std::cout << domain::hex_encode(session.session_uuid) << "  snapshot "
                      << session.snapshot_generation << "  " << session.state << "  "
                      << session.records << " records\n";
            for (const auto& root : session.roots) {
                std::cout << "  root " << root.index << " " << domain::hex_encode(root.uuid)
                          << " " << root.label << " " << root.path << '\n';
            }
        }
    }
    return 0;
}

int run_backup_resume_command(
    const std::string& session,
    const application::ResumeOptions& resume,
    const SessionCommandOptions& options
) {
    const auto session_uuid = parse_session_id(session);
    if (!session_uuid) {
        return report_error(session_uuid.error());
    }
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto report = application::backup_resume(options.repository, *password, *session_uuid, resume);
    if (!report) {
        return report_error(report.error());
    }
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.backup-resume.v1"},
            {"session", session},
            {"generation", std::to_string(report->snapshot.context.generation)},
            {"snapshot_uuid", domain::hex_encode(report->snapshot.context.snapshot_uuid)},
            {"status", report->snapshot.status},
            {"resumed", report->resumed},
            {"stats", {
                {"files", std::to_string(report->snapshot.stats.files)},
                {"new_chunks", std::to_string(report->snapshot.stats.new_chunks)},
                {"deduplicated_chunks", std::to_string(report->snapshot.stats.deduplicated_chunks)},
            }},
        }.dump(2) << '\n';
    } else {
        std::cout << "Resumed session " << session << " and published snapshot "
                  << report->snapshot.context.generation << " (" << report->snapshot.status << ")\n";
    }
    return report->snapshot.status == "partial" ? 3 : 0;
}

int run_backup_discard_command(
    const std::string& session,
    bool confirmed,
    const SessionCommandOptions& options
) {
    const auto session_uuid = parse_session_id(session);
    if (!session_uuid) {
        return report_error(session_uuid.error());
    }
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto discarded = application::backup_discard(options.repository, *password, *session_uuid, confirmed);
    if (!discarded) {
        return report_error(discarded.error());
    }
    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.backup-discard.v1"},
            {"session", session},
            {"discarded", true},
        }.dump(2) << '\n';
    } else {
        std::cout << "Discarded resumable state for session " << session << '\n';
    }
    return 0;
}

}
