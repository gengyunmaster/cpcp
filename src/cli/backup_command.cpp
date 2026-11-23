#include "cli/backup_command.hpp"

#include "application/credentials.hpp"
#include "cli/errors.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

namespace cpcp::cli {

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
        }.dump(2) << '\n';
    } else {
        std::cout << "Published snapshot " << snapshot.context.generation
                  << " with " << snapshot.stats.files << " files and "
                  << snapshot.stats.new_chunks << " new chunks\n";
    }
    return 0;
}

}
