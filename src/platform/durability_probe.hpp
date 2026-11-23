#pragma once

#include "domain/result.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace cpcp::platform {

struct ProbeOptions {
    bool write_test = false;
    std::size_t payload_size = 256 * 1024;
    std::uint32_t iterations = 1;
};

struct ProbeCheck {
    std::string name;
    bool passed;
    std::string detail;
};

struct ProbeTimings {
    std::uint64_t write_ns = 0;
    std::uint64_t flush_ns = 0;
    std::uint64_t readback_ns = 0;
    std::uint64_t publish_ns = 0;
    std::uint64_t directory_sync_ns = 0;
};

struct DurabilityReport {
    std::filesystem::path path;
    std::string filesystem;
    std::uint64_t available_bytes = 0;
    ProbeOptions options;
    std::vector<ProbeCheck> checks;
    ProbeTimings timings;

    bool supported() const;
};

domain::Result<DurabilityReport> probe_directory(
    const std::filesystem::path& directory,
    const ProbeOptions& options
);

}
