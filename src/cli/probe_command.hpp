#pragma once

#include "platform/durability_probe.hpp"

#include <filesystem>

namespace cpcp::cli {

int run_probe_command(
    const std::filesystem::path& directory,
    const platform::ProbeOptions& options,
    bool json
);

}
