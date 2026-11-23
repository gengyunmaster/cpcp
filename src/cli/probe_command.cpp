#include "cli/probe_command.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <iostream>
#include <string>

namespace cpcp::cli {

namespace {

nlohmann::json report_json(const platform::DurabilityReport& report) {
    using nlohmann::json;
    json checks = json::array();
    for (const auto& check : report.checks) {
        checks.push_back({
            {"name", check.name},
            {"passed", check.passed},
            {"detail", check.detail},
        });
    }

    return {
        {"schema", "cpcp.repo-probe.v1"},
        {"path", report.path.string()},
        {"filesystem", report.filesystem},
        {"available_bytes", std::to_string(report.available_bytes)},
        {"supported", report.supported()},
        {"write_test", report.options.write_test},
        {"iterations", report.options.iterations},
        {"payload_size", std::to_string(report.options.payload_size)},
        {"checks", checks},
        {"timings_ns", {
            {"write", std::to_string(report.timings.write_ns)},
            {"flush", std::to_string(report.timings.flush_ns)},
            {"readback", std::to_string(report.timings.readback_ns)},
            {"publish", std::to_string(report.timings.publish_ns)},
            {"directory_sync", std::to_string(report.timings.directory_sync_ns)},
        }},
    };
}

}

int run_probe_command(
    const std::filesystem::path& directory,
    const platform::ProbeOptions& options,
    bool json
) {
    const auto result = platform::probe_directory(directory, options);
    if (!result) {
        std::cerr << "Error: " << result.error().message << '\n';
        return 1;
    }

    if (json) {
        std::cout << report_json(*result).dump(2) << '\n';
    } else {
        std::cout << "Path: " << result->path.string() << '\n'
                  << "Filesystem: " << result->filesystem << '\n'
                  << "Available bytes: " << result->available_bytes << '\n'
                  << "Write test: " << (result->options.write_test ? "enabled" : "disabled")
                  << '\n';
        for (const auto& check : result->checks) {
            std::cout << (check.passed ? "PASS " : "FAIL ") << check.name;
            if (!check.detail.empty()) {
                std::cout << ": " << check.detail;
            }
            std::cout << '\n';
        }
        if (result->options.write_test) {
            std::cout << "Iterations: " << result->options.iterations << '\n'
                      << "Payload bytes: " << result->options.payload_size << '\n'
                      << "Write ns: " << result->timings.write_ns << '\n'
                      << "Flush ns: " << result->timings.flush_ns << '\n'
                      << "Read-back ns: " << result->timings.readback_ns << '\n'
                      << "Publish ns: " << result->timings.publish_ns << '\n'
                      << "Directory sync ns: " << result->timings.directory_sync_ns << '\n';
        }
        std::cout << "Status: " << (result->supported() ? "supported" : "unsupported") << '\n';
    }
    return result->supported() ? 0 : 1;
}

}
