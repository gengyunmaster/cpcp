#include "application/key_service.hpp"

#include "crypto/password.hpp"
#include "platform/lock.hpp"

#include <algorithm>

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;

namespace {

domain::Result<void> save_updated_config(
    const std::filesystem::path& repository,
    repository::RepositoryConfig& config,
    const crypto::SecureKey& master_key
) {
    config.feature_versions["key_slots"] = 1;
    ++config.revision;
    const auto tag = repository::authenticate_config(config, master_key);
    if (!tag) {
        return std::unexpected(tag.error());
    }
    config.authentication_tag = *tag;
    return repository::replace_config_replicas(repository, config);
}

domain::Result<std::string> next_slot_id(
    const repository::RepositoryConfig& config,
    std::string_view prefix
) {
    for (std::uint64_t index = 1; index <= 64; ++index) {
        const auto candidate = std::string(prefix) + "-" + std::to_string(index);
        const auto used = std::ranges::any_of(config.key_slots, [&](const repository::KeySlot& slot) {
            return slot.id == candidate;
        });
        if (!used) {
            return candidate;
        }
    }
    return std::unexpected(Error{ErrorCode::conflict, "no key slot identifier is available"});
}

}

domain::Result<void> change_password(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const crypto::SecretBytes& new_password
) {
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto& config = unlocked->config;
    const auto slot = std::ranges::find_if(config.key_slots, [&](const repository::KeySlot& candidate) {
        return candidate.id == unlocked->authenticated_slot;
    });
    if (slot == config.key_slots.end() || slot->type != "password") {
        return std::unexpected(Error{ErrorCode::usage, "the authenticated slot is not a password slot"});
    }
    const auto index = static_cast<std::size_t>(std::distance(config.key_slots.begin(), slot));
    auto replacement = repository::create_key_slot(
        config,
        slot->id,
        "password",
        new_password,
        slot->kdf,
        unlocked->master_key
    );
    if (!replacement) {
        return std::unexpected(replacement.error());
    }
    config.key_slots[index] = std::move(*replacement);
    repository::set_key_slots(config, config.key_slots);
    return save_updated_config(repository, config, unlocked->master_key);
}

domain::Result<std::string> add_password(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const crypto::SecretBytes& new_password,
    const std::optional<std::string>& slot_id
) {
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto& config = unlocked->config;
    const auto id = slot_id
        ? domain::Result<std::string>(*slot_id)
        : next_slot_id(config, "password");
    if (!id || id->empty() || std::ranges::any_of(config.key_slots, [&](const repository::KeySlot& slot) {
        return slot.id == *id;
    })) {
        return std::unexpected(Error{ErrorCode::conflict, "key slot ID is empty or already exists"});
    }
    auto slot = repository::create_key_slot(
        config,
        *id,
        "password",
        new_password,
        config.kdf,
        unlocked->master_key
    );
    if (!slot) {
        return std::unexpected(slot.error());
    }
    config.key_slots.push_back(std::move(*slot));
    repository::set_key_slots(config, config.key_slots);
    const auto saved = save_updated_config(repository, config, unlocked->master_key);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    return *id;
}

domain::Result<RecoveryKeyReport> add_recovery_key(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
) {
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto key = crypto::SecretBytes::allocate(crypto::key_size);
    if (!key) {
        return std::unexpected(key.error());
    }
    crypto::fill_random(key->writable_bytes());
    const auto id = next_slot_id(unlocked->config, "recovery");
    if (!id) {
        return std::unexpected(id.error());
    }
    auto slot = repository::create_key_slot(
        unlocked->config,
        *id,
        "recovery",
        *key,
        unlocked->config.kdf,
        unlocked->master_key
    );
    if (!slot) {
        return std::unexpected(slot.error());
    }
    unlocked->config.key_slots.push_back(std::move(*slot));
    repository::set_key_slots(unlocked->config, unlocked->config.key_slots);
    const auto saved = save_updated_config(repository, unlocked->config, unlocked->master_key);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    return RecoveryKeyReport{*id, std::move(key).value()};
}

domain::Result<void> remove_key_slot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password,
    const std::string& slot_id,
    bool confirmed
) {
    if (!confirmed) {
        return std::unexpected(Error{ErrorCode::usage, "removing a key slot requires --yes"});
    }
    if (slot_id.empty()) {
        return std::unexpected(Error{ErrorCode::usage, "key slot ID cannot be empty"});
    }
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    auto& config = unlocked->config;
    if (slot_id == unlocked->authenticated_slot) {
        return std::unexpected(Error{ErrorCode::conflict, "the authenticated slot cannot be removed"});
    }
    if (config.key_slots.size() <= 1) {
        return std::unexpected(Error{ErrorCode::conflict, "the last usable key slot cannot be removed"});
    }
    const auto slot = std::ranges::find_if(config.key_slots, [&](const repository::KeySlot& candidate) {
        return candidate.id == slot_id;
    });
    if (slot == config.key_slots.end()) {
        return std::unexpected(Error{ErrorCode::permanent_io, "key slot was not found"});
    }
    config.key_slots.erase(slot);
    repository::set_key_slots(config, config.key_slots);
    return save_updated_config(repository, config, unlocked->master_key);
}

domain::Result<std::vector<KeySlotInfo>> list_key_slots(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
) {
    const auto locks = platform::RepositoryLocks::read(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    const auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    std::vector<KeySlotInfo> result;
    for (const auto& slot : unlocked->config.key_slots) {
        result.push_back(KeySlotInfo{slot.id, slot.type, slot.kdf.memory_kib, slot.kdf.iterations});
    }
    return result;
}

domain::Result<domain::Uuid> rotate_storage_epoch(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& current_password
) {
    const auto locks = platform::RepositoryLocks::maintenance(repository);
    if (!locks) {
        return std::unexpected(locks.error());
    }
    auto unlocked = repository::load_config(repository, current_password);
    if (!unlocked) {
        return std::unexpected(unlocked.error());
    }
    unlocked->config.storage_epoch = crypto::random_uuid();
    const auto saved = save_updated_config(repository, unlocked->config, unlocked->master_key);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    return unlocked->config.storage_epoch;
}

}
