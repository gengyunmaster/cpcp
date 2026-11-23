#pragma once

#include "application/inspection_service.hpp"
#include "cli/config_command.hpp"

#include <filesystem>
#include <string>

namespace cpcp::cli {

struct InspectionCommandOptions {
    std::filesystem::path repository = ".";
    ConfigCommandOptions config;
    bool repo_read_only = false;
};

int run_snapshot_list_command(const InspectionCommandOptions& options);
int run_snapshot_show_command(
    const InspectionCommandOptions& options,
    std::uint64_t generation
);
int run_restore_command(
    const InspectionCommandOptions& options,
    const std::string& selector,
    application::RestoreOptions restore
);
int run_verify_command(
    const InspectionCommandOptions& options,
    bool deep
);

}
