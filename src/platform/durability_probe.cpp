#include "platform/durability_probe.hpp"

#include "platform/binary_file.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <linux/magic.h>
#include <sys/statfs.h>
#elif defined(__APPLE__)
#include <sys/mount.h>
#endif

namespace cpcp::platform {

using domain::Error;
using domain::ErrorCode;
using Clock = std::chrono::steady_clock;

namespace {

std::uint64_t elapsed_ns(Clock::time_point start) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count()
    );
}

std::string filesystem_name(const std::filesystem::path& path) {
#if defined(__linux__)
    struct statfs status {};
    if (statfs(path.c_str(), &status) != 0) {
        return "unknown";
    }
    if (status.f_type == EXT4_SUPER_MAGIC) {
        return "ext4";
    }
    return "linux-magic-" + std::to_string(static_cast<unsigned long long>(status.f_type));
#elif defined(__APPLE__)
    struct statfs status {};
    if (statfs(path.c_str(), &status) != 0) {
        return "unknown";
    }
    return status.f_fstypename;
#else
    return "windows";
#endif
}

}

bool DurabilityReport::supported() const {
    return std::ranges::all_of(checks, [](const ProbeCheck& check) {
        return check.passed;
    });
}

domain::Result<DurabilityReport> probe_directory(
    const std::filesystem::path& directory,
    const ProbeOptions& options
) {
    namespace fs = std::filesystem;
    if (options.payload_size == 0 || options.payload_size > 64 * 1024 * 1024
        || options.iterations == 0 || options.iterations > 10000) {
        return std::unexpected(Error{ErrorCode::usage, "invalid probe size or iteration count"});
    }

    DurabilityReport report;
    report.options = options;
    std::error_code filesystem_error;
    report.path = fs::absolute(directory, filesystem_error).lexically_normal();
    if (filesystem_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
    }

    const auto status = fs::status(report.path, filesystem_error);
    if (filesystem_error || !fs::exists(status) || !fs::is_directory(status)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "probe target is not a directory"});
    }
    report.checks.push_back({"directory", true, ""});
    report.filesystem = filesystem_name(report.path);
    const auto space = fs::space(report.path, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(Error{ErrorCode::permanent_io, filesystem_error.message()});
    }
    report.available_bytes = space.available;
    report.checks.push_back({"space-query", true, ""});
    if (!options.write_test) {
        return report;
    }

    std::vector<std::byte> payload(options.payload_size);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index % 251);
    }
    std::vector<std::byte> readback(options.payload_size);
    std::random_device random;
    const auto prefix = "cpcp-probe-" + std::to_string(random()) + "-"
        + std::to_string(random());

    auto cleanup = [&](const fs::path& temporary, const fs::path& final) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        fs::remove(final, ignored);
    };
    auto fail = [&](const std::string& name, const std::string& detail,
                    const fs::path& temporary, const fs::path& final) {
        report.checks.push_back({name, false, detail});
        cleanup(temporary, final);
        return domain::Result<DurabilityReport>(std::move(report));
    };

    for (std::uint32_t iteration = 0; iteration < options.iterations; ++iteration) {
        const auto suffix = "-" + std::to_string(iteration);
        const auto temporary = report.path / (prefix + suffix + ".tmp");
        const auto final = report.path / (prefix + suffix + ".bin");

        auto writer = BinaryFile::create_new(temporary);
        if (!writer) {
            return fail("create", writer.error().message, temporary, final);
        }

        auto start = Clock::now();
        auto result = writer->write_all(payload);
        report.timings.write_ns += elapsed_ns(start);
        if (!result) {
            return fail("write", result.error().message, temporary, final);
        }

        start = Clock::now();
        result = writer->flush();
        report.timings.flush_ns += elapsed_ns(start);
        if (!result) {
            return fail("flush", result.error().message, temporary, final);
        }
        result = writer->close();
        if (!result) {
            return fail("close", result.error().message, temporary, final);
        }

        auto reader = BinaryFile::open_read(temporary);
        if (!reader) {
            return fail("readback-open", reader.error().message, temporary, final);
        }
        start = Clock::now();
        result = reader->read_exact(readback);
        if (result) {
            std::byte extra{};
            const auto extra_size = reader->read_some(std::span<std::byte>(&extra, 1));
            if (!extra_size) {
                result = std::unexpected(extra_size.error());
            } else if (*extra_size != 0) {
                result = std::unexpected(Error{ErrorCode::integrity, "probe file has trailing data"});
            }
        }
        if (result && readback != payload) {
            result = std::unexpected(Error{ErrorCode::integrity, "probe read-back mismatch"});
        }
        report.timings.readback_ns += elapsed_ns(start);
        if (!result) {
            return fail("readback", result.error().message, temporary, final);
        }
        result = reader->close();
        if (!result) {
            return fail("readback-close", result.error().message, temporary, final);
        }

        start = Clock::now();
        result = publish_no_replace(temporary, final);
        report.timings.publish_ns += elapsed_ns(start);
        if (!result) {
            return fail("publish", result.error().message, temporary, final);
        }

        start = Clock::now();
        result = sync_directory(report.path);
        report.timings.directory_sync_ns += elapsed_ns(start);
        if (!result) {
            return fail("directory-sync", result.error().message, temporary, final);
        }

        fs::remove(final, filesystem_error);
        if (filesystem_error) {
            return fail("cleanup", filesystem_error.message(), temporary, final);
        }
    }

    report.checks.push_back({"create", true, ""});
    report.checks.push_back({"write", true, ""});
    report.checks.push_back({"flush", true, ""});
    report.checks.push_back({"readback", true, ""});
    report.checks.push_back({"publish", true, ""});
    report.checks.push_back({"directory-sync", true, ""});
    return report;
}

}
