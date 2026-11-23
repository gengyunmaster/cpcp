#pragma once

#include "application/backup_service.hpp"
#include "application/check_service.hpp"
#include "cli/config_command.hpp"

#include <filesystem>
#include <vector>

namespace cpcp::cli {

struct BackupCommandOptions {
    std::filesystem::path repository = ".";
    application::BackupOptions backup;
    ConfigCommandOptions config;
};

struct CheckCommandOptions {
    std::filesystem::path repository = ".";
    application::CheckOptions check;
    ConfigCommandOptions config;
    bool ndjson = false;
};

int run_backup_add_command(
    const std::vector<std::filesystem::path>& roots,
    const BackupCommandOptions& options
);
int run_backup_check_command(
    const std::string& selector,
    const std::string& root_selector,
    const CheckCommandOptions& options
);

}
