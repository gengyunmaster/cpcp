#pragma once

#include "domain/result.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace cpcp::cli {

struct ConfigCommandOptions {
    std::optional<std::filesystem::path> password_file;
    std::optional<int> password_fd;
    std::string kdf_memory = "64MiB";
    std::uint64_t kdf_iterations = 3;
    std::string chunk_size = "8MiB";
    bool json = false;
};

int run_init_command(
    const std::filesystem::path& directory,
    const ConfigCommandOptions& options
);
int run_export_header_command(
    const std::filesystem::path& repository,
    const std::filesystem::path& output,
    const ConfigCommandOptions& options
);
int run_import_header_command(
    const std::filesystem::path& header,
    const std::filesystem::path& repository,
    const ConfigCommandOptions& options
);
domain::Result<std::uint64_t> parse_byte_size(const std::string& text);

}
