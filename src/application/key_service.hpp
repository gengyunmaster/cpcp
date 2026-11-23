#pragma once

#include "repository/config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace cpcp::application {

struct KeySlotInfo {
    std::string id;
    std::string type;
    std::uint64_t memory_kib = 0;
    std::uint64_t iterations = 0;
};

struct RecoveryKeyReport {
    std::string slot_id;
    crypto::SecretBytes key;
};

domain::Result<void> change_password(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const crypto::SecretBytes& new_password
);
domain::Result<std::string> add_password(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const crypto::SecretBytes& new_password,
    const std::optional<std::string>& slot_id = std::nullopt
);
domain::Result<RecoveryKeyReport> add_recovery_key(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
);
domain::Result<void> remove_key_slot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const std::string& slot_id,
    bool confirmed
);
domain::Result<std::vector<KeySlotInfo>> list_key_slots(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
);
domain::Result<domain::Uuid> rotate_storage_epoch(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
);

}
