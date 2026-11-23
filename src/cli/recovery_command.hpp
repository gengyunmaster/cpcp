#pragma once

#include "application/recovery_service.hpp"
#include "cli/config_command.hpp"

#include <filesystem>
#include <string>

namespace cpcp::cli {

struct RecoveryCommandOptions {
    std::filesystem::path repository = ".";
    ConfigCommandOptions config;
    bool dry_run = false;
    bool yes = false;
};

int run_quarantine_command(
    const RecoveryCommandOptions& options,
    const std::string& selector
);
int run_repair_summary_command(
    const RecoveryCommandOptions& options,
    std::uint64_t generation
);
int run_repair_config_command(const RecoveryCommandOptions& options);

}
