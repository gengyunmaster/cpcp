#include "cli/lifecycle_command.hpp"

#include "application/credentials.hpp"
#include "application/lifecycle_service.hpp"
#include "cli/errors.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

namespace cpcp::cli {

namespace {

int print_report(
    const RecoveryCommandOptions& options,
    std::string_view schema,
    const application::LifecycleReport& report
) {
    if (options.config.json) {
        auto moved = nlohmann::json::array();
        auto deleted = nlohmann::json::array();
        for (const auto& path : report.moved) {
            moved.push_back(path.string());
        }
        for (const auto& path : report.deleted) {
            deleted.push_back(path.string());
        }
        std::cout << nlohmann::json{
            {"schema", schema},
            {"moved", moved},
            {"deleted", deleted},
        }.dump(2) << '\n';
    } else {
        for (const auto& path : report.moved) {
            std::cout << "Moved to trash: " << path << '\n';
        }
        for (const auto& path : report.deleted) {
            std::cout << "Deleted: " << path << '\n';
        }
    }
    return 0;
}

}

int run_snapshot_forget_command(const RecoveryCommandOptions& options, std::uint64_t generation) {
    auto password = application::read_password(options.config.password_file, !options.config.json, options.config.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    const auto report = application::forget_snapshot(
        options.repository,
        *password,
        generation,
        options.dry_run,
        options.yes
    );
    if (!report) {
        return report_error(report.error());
    }
    return print_report(options, "cpcp.snapshot-forget.v1", *report);
}

int run_purge_quarantine_command(const RecoveryCommandOptions& options, std::chrono::seconds grace) {
    auto password = application::read_password(options.config.password_file, !options.config.json, options.config.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    const auto report = application::purge_quarantine(
        options.repository,
        *password,
        grace,
        options.dry_run,
        options.yes
    );
    if (!report) {
        return report_error(report.error());
    }
    return print_report(options, "cpcp.repo-purge-quarantine.v1", *report);
}

int run_gc_command(const RecoveryCommandOptions& options, std::chrono::seconds grace) {
    auto password = application::read_password(options.config.password_file, !options.config.json, options.config.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    const auto report = application::collect_garbage(
        options.repository,
        *password,
        grace,
        options.dry_run,
        options.yes
    );
    if (!report) {
        return report_error(report.error());
    }
    return print_report(options, "cpcp.repo-gc.v1", *report);
}

}
