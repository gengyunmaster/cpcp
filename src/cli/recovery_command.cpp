#include "cli/recovery_command.hpp"

#include "application/credentials.hpp"
#include "cli/errors.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <iostream>

namespace cpcp::cli {

using domain::Error;
using domain::ErrorCode;

namespace {

nlohmann::json report_json(const application::RecoveryReport& report) {
    auto moved = nlohmann::json::array();
    for (const auto& [source, target] : report.moved) {
        moved.push_back({{"source", source.string()}, {"target", target.string()}});
    }
    return {
        {"schema", "cpcp.repo-quarantine.v1"},
        {"moved", moved},
    };
}

}

int run_quarantine_command(
    const RecoveryCommandOptions& options,
    const std::string& selector
) {
    if (!options.dry_run && !options.yes) {
        return report_error(Error{ErrorCode::usage, "quarantine requires --dry-run or --yes"});
    }
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }

    application::RecoveryReport report;
    try {
        if (selector.starts_with("chunk:")) {
            const auto id = crypto::digest_from_hex(selector.substr(6));
            if (!id) {
                return report_error(id.error());
            }
            report = application::quarantine_chunk(
                options.repository,
                *password,
                *id,
                options.dry_run
            ).value();
        } else if (selector.starts_with("snapshot:")) {
            const auto text = selector.substr(9);
            std::uint64_t generation = 0;
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), generation);
            if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
                return report_error(Error{ErrorCode::usage, "invalid snapshot generation"});
            }
            report = application::quarantine_snapshot(
                options.repository,
                *password,
                generation,
                options.dry_run
            ).value();
        } else {
            return report_error(Error{ErrorCode::usage, "quarantine selector must be chunk:<id> or snapshot:<generation>"});
        }
    } catch (const std::exception& error) {
        return report_error(Error{ErrorCode::permanent_io, error.what()});
    }

    if (options.config.json) {
        std::cout << report_json(report).dump(2) << '\n';
    } else {
        for (const auto& [source, target] : report.moved) {
            std::cout << source << " -> " << target << '\n';
        }
    }
    return 0;
}

int run_repair_summary_command(
    const RecoveryCommandOptions& options,
    std::uint64_t generation
) {
    if (!options.yes) {
        return report_error(Error{ErrorCode::usage, "summary repair requires --yes"});
    }
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    auto summary = application::repair_summary(options.repository, *password, generation);
    if (!summary) {
        return report_error(summary.error());
    }

    if (options.config.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.repo-repair-summary.v1"},
            {"generation", std::to_string(summary->context.generation)},
            {"snapshot_uuid", domain::hex_encode(summary->context.snapshot_uuid)},
            {"main_digest", crypto::to_hex(summary->main_ciphertext_digest)},
        }.dump(2) << '\n';
    } else {
        std::cout << "Rebuilt summary for generation " << generation << '\n';
    }
    return 0;
}

int run_repair_config_command(const RecoveryCommandOptions& options) {
    if (!options.yes) {
        return report_error(Error{ErrorCode::usage, "configuration repair requires --yes"});
    }
    auto password = application::read_password(options.config.password_file, !options.config.json);
    if (!password) {
        return report_error(password.error());
    }
    const auto result = application::repair_config(options.repository, *password);
    if (!result) {
        return report_error(result.error());
    }

    if (options.config.json) {
        std::cout << nlohmann::json{{"schema", "cpcp.repo-repair-config.v1"}, {"repaired", true}}.dump(2) << '\n';
    } else {
        std::cout << "Repaired configuration replicas\n";
    }
    return 0;
}

}
