#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace cpcp::cli {

struct KeyCommandOptions {
    std::filesystem::path repository = ".";
    std::optional<std::filesystem::path> password_file;
    std::optional<std::filesystem::path> new_password_file;
    bool json = false;
};

int run_passwd_command(const KeyCommandOptions& options);
int run_key_list_command(const KeyCommandOptions& options);
int run_key_add_password_command(const KeyCommandOptions& options, const std::optional<std::string>& slot_id);
int run_key_add_recovery_command(const KeyCommandOptions& options, bool show_key);
int run_key_remove_command(const KeyCommandOptions& options, const std::string& slot_id, bool confirmed);
int run_rotate_epoch_command(const KeyCommandOptions& options);

}
