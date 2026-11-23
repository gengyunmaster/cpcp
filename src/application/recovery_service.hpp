#pragma once

#include "application/inspection_service.hpp"

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace cpcp::application {

struct RecoveryReport {
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> moved;
};

domain::Result<RecoveryReport> quarantine_chunk(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const crypto::Digest& chunk_id,
    bool dry_run
);
domain::Result<RecoveryReport> quarantine_snapshot(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation,
    bool dry_run
);
domain::Result<repository::SnapshotSummary> repair_summary(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t generation
);
domain::Result<void> repair_config(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
);

}
