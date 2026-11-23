#include "cli/key_command.hpp"

#include "application/credentials.hpp"
#include "application/key_service.hpp"
#include "cli/errors.hpp"

#include <nlohmann/json.hpp>

#include <iostream>

namespace cpcp::cli {

int run_passwd_command(const KeyCommandOptions& options) {
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    auto replacement = application::read_password_prompt(options.new_password_file, !options.json, "New password: ");
    if (!replacement) {
        return report_error(replacement.error());
    }
    const auto changed = application::change_password(options.repository, *current, *replacement);
    if (!changed) {
        return report_error(changed.error());
    }
    if (options.json) {
        std::cout << nlohmann::json{{"schema", "cpcp.repo-passwd.v1"}, {"changed", true}}.dump(2) << '\n';
    } else {
        std::cout << "Replaced the authenticated password slot\n";
    }
    return 0;
}

int run_key_list_command(const KeyCommandOptions& options) {
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    const auto slots = application::list_key_slots(options.repository, *current);
    if (!slots) {
        return report_error(slots.error());
    }
    if (options.json) {
        auto documents = nlohmann::json::array();
        for (const auto& slot : *slots) {
            documents.push_back({
                {"id", slot.id},
                {"type", slot.type},
                {"memory_kib", std::to_string(slot.memory_kib)},
                {"iterations", std::to_string(slot.iterations)},
            });
        }
        std::cout << nlohmann::json{{"schema", "cpcp.key-list.v1"}, {"slots", documents}}.dump(2) << '\n';
    } else {
        for (const auto& slot : *slots) {
            std::cout << slot.id << "  " << slot.type << '\n';
        }
    }
    return 0;
}

int run_key_add_password_command(const KeyCommandOptions& options, const std::optional<std::string>& slot_id) {
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    auto added_password = application::read_password_prompt(options.new_password_file, !options.json, "New password: ");
    if (!added_password) {
        return report_error(added_password.error());
    }
    const auto added = application::add_password(options.repository, *current, *added_password, slot_id);
    if (!added) {
        return report_error(added.error());
    }
    if (options.json) {
        std::cout << nlohmann::json{{"schema", "cpcp.key-add-password.v1"}, {"slot", *added}}.dump(2) << '\n';
    } else {
        std::cout << "Added password slot " << *added << '\n';
    }
    return 0;
}

int run_key_add_recovery_command(const KeyCommandOptions& options, bool show_key) {
    if (!show_key) {
        return report_error(domain::Error{
            domain::ErrorCode::usage,
            "adding a recovery key requires --show-key so it can be stored offline",
        });
    }
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    auto added = application::add_recovery_key(options.repository, *current);
    if (!added) {
        return report_error(added.error());
    }
    const auto encoded = domain::hex_encode(added->key.bytes());
    if (options.json) {
        std::cout << nlohmann::json{
            {"schema", "cpcp.key-add-recovery.v1"},
            {"slot", added->slot_id},
            {"recovery_key", encoded},
        }.dump(2) << '\n';
    } else {
        std::cout << "Recovery slot: " << added->slot_id << "\nRecovery key: " << encoded
                  << "\nStore this key offline; it cannot be displayed again.\n";
    }
    return 0;
}

int run_key_remove_command(const KeyCommandOptions& options, const std::string& slot_id, bool confirmed) {
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    const auto removed = application::remove_key_slot(options.repository, *current, slot_id, confirmed);
    if (!removed) {
        return report_error(removed.error());
    }
    if (options.json) {
        std::cout << nlohmann::json{{"schema", "cpcp.key-remove.v1"}, {"slot", slot_id}, {"removed", true}}.dump(2) << '\n';
    } else {
        std::cout << "Removed key slot " << slot_id << '\n';
    }
    return 0;
}

int run_rotate_epoch_command(const KeyCommandOptions& options) {
    auto current = application::read_password(options.password_file, !options.json);
    if (!current) {
        return report_error(current.error());
    }
    const auto epoch = application::rotate_storage_epoch(options.repository, *current);
    if (!epoch) {
        return report_error(epoch.error());
    }
    if (options.json) {
        std::cout << nlohmann::json{{"schema", "cpcp.repo-rotate-epoch.v1"}, {"storage_epoch", domain::hex_encode(*epoch)}}.dump(2) << '\n';
    } else {
        std::cout << "Rotated storage epoch to " << domain::hex_encode(*epoch) << '\n';
    }
    return 0;
}

}
