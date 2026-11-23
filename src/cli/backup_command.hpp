#pragma once

#include "application/backup_service.hpp"
#include "cli/config_command.hpp"

#include <filesystem>
#include <vector>

namespace cpcp::cli {

struct BackupCommandOptions {
    std::filesystem::path repository = ".";
    application::BackupOptions backup;
    ConfigCommandOptions config;
};

int run_backup_add_command(
    const std::vector<std::filesystem::path>& roots,
    const BackupCommandOptions& options
);

}
