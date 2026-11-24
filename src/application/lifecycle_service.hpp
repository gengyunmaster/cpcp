#pragma once

#include "crypto/secret.hpp"
#include "domain/result.hpp"

#include <chrono>
#include <filesystem>
#include <vector>

namespace cpcp::application {

struct LifecycleReport {
    std::vector<std::filesystem::path> moved;
    std::vector<std::filesystem::path> deleted;
};

domain::Result<LifecycleReport> forget_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation,
    bool dry_run,
    bool confirmed
);
domain::Result<LifecycleReport> purge_quarantine(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::chrono::seconds grace,
    bool dry_run,
    bool confirmed
);
domain::Result<LifecycleReport> collect_garbage(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::chrono::seconds grace,
    bool dry_run,
    bool confirmed
);

}
