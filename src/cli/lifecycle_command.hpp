#pragma once

#include "cli/recovery_command.hpp"

#include <chrono>
#include <cstdint>

namespace cpcp::cli {

int run_snapshot_forget_command(
    const RecoveryCommandOptions& options,
    std::uint64_t generation
);
int run_purge_quarantine_command(
    const RecoveryCommandOptions& options,
    std::chrono::seconds grace
);
int run_gc_command(
    const RecoveryCommandOptions& options,
    std::chrono::seconds grace
);

}
