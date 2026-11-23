#include "application/repository_service.hpp"

#include "platform/binary_file.hpp"
#include "platform/durability_probe.hpp"

#include <filesystem>
#include <string>
#include <system_error>

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;

domain::Result<domain::Uuid> initialize_repository(
    const std::filesystem::path& directory,
    const crypto::SecretBytes& password,
    const repository::ConfigOptions& options
) {
    namespace fs = std::filesystem;
    std::error_code error;
    if (fs::exists(directory, error)) {
        if (error || !fs::is_directory(directory, error)) {
            return std::unexpected(Error{ErrorCode::permanent_io, "repository target is not a directory"});
        }
        if (!fs::is_empty(directory, error)) {
            return std::unexpected(Error{ErrorCode::conflict, "repository target is not empty"});
        }
    } else if (!fs::create_directories(directory, error)) {
        return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
    }

    const platform::ProbeOptions probe{.write_test = true, .payload_size = 65536, .iterations = 1};
    auto probe_result = platform::probe_directory(directory, probe);
    if (!probe_result) {
        return std::unexpected(probe_result.error());
    }
    if (!probe_result->supported()) {
        return std::unexpected(Error{
            ErrorCode::unsupported,
            "filesystem does not meet the repository durability requirements",
        });
    }

    const char* names[] = {
        "chunks",
        "snapshots",
        "sessions",
        "cache",
        "tmp",
        "quarantine",
        "trash",
    };
    for (const char* name : names) {
        if (!fs::create_directory(directory / name, error) && error) {
            return std::unexpected(Error{ErrorCode::permanent_io, error.message()});
        }
    }
    auto lock = platform::BinaryFile::create_new(directory / "lock");
    if (!lock) {
        return std::unexpected(lock.error());
    }
    auto close_result = lock->close();
    if (!close_result) {
        return std::unexpected(close_result.error());
    }

    auto config = repository::create_config(password, options);
    if (!config) {
        return std::unexpected(config.error());
    }
    auto written = repository::write_new_config_replicas(directory, *config);
    if (!written) {
        return std::unexpected(written.error());
    }
    return config->repository_uuid;
}

}
