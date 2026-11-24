#include "cli/config_command.hpp"

#include "application/credentials.hpp"
#include "application/repository_service.hpp"
#include "cli/errors.hpp"
#include "repository/config.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <iostream>

namespace cpcp::cli {

using domain::Error;
using domain::ErrorCode;

domain::Result<std::uint64_t> parse_byte_size(const std::string& text) {
    if (text.empty()) {
        return std::unexpected(Error{ErrorCode::usage, "size cannot be empty"});
    }
    std::uint64_t multiplier = 1;
    std::string number = text;
    const auto suffix = [&](std::string_view value) {
        return text.size() >= value.size()
            && text.compare(text.size() - value.size(), value.size(), value) == 0;
    };
    if (suffix("GiB")) {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
        number.resize(number.size() - 3);
    } else if (suffix("MiB")) {
        multiplier = 1024ULL * 1024ULL;
        number.resize(number.size() - 3);
    } else if (suffix("KiB")) {
        multiplier = 1024ULL;
        number.resize(number.size() - 3);
    } else if (suffix("B")) {
        number.pop_back();
    }
    if (number.empty()) {
        return std::unexpected(Error{ErrorCode::usage, "size has no numeric value"});
    }

    std::uint64_t value = 0;
    const auto parsed = std::from_chars(number.data(), number.data() + number.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != number.data() + number.size()
        || value == 0 || value > std::numeric_limits<std::uint64_t>::max() / multiplier) {
        return std::unexpected(Error{ErrorCode::usage, "invalid byte size"});
    }
    return value * multiplier;
}

namespace {

domain::Result<crypto::PasswordKdfParameters> kdf_options(const ConfigCommandOptions& options) {
    const auto memory = parse_byte_size(options.kdf_memory);
    if (!memory || *memory % 1024 != 0) {
        return std::unexpected(Error{ErrorCode::usage, "KDF memory must be a whole KiB value"});
    }
    return crypto::PasswordKdfParameters{*memory / 1024, options.kdf_iterations};
}

void print_json(const nlohmann::json& document, bool enabled) {
    if (enabled) {
        std::cout << document.dump(2) << '\n';
    }
}

}

int run_init_command(
    const std::filesystem::path& directory,
    const ConfigCommandOptions& options
) {
    const auto memory = kdf_options(options);
    if (!memory) {
        return report_error(memory.error());
    }
    const auto chunk_size = parse_byte_size(options.chunk_size);
    if (!chunk_size || *chunk_size > std::numeric_limits<std::uint32_t>::max()) {
        return report_error(Error{ErrorCode::usage, "invalid chunk size"});
    }

    auto password = application::read_password(options.password_file, !options.json, options.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    repository::ConfigOptions config_options;
    config_options.kdf = *memory;
    config_options.chunk_size = static_cast<std::uint32_t>(*chunk_size);
    const auto uuid = application::initialize_repository(directory, *password, config_options);
    if (!uuid) {
        return report_error(uuid.error());
    }

    if (options.json) {
        print_json({
            {"schema", "cpcp.repo-init.v1"},
            {"repository", directory.string()},
            {"repository_uuid", domain::hex_encode(*uuid)},
            {"chunk_size", std::to_string(config_options.chunk_size)},
        }, true);
    } else {
        std::cout << "Initialized cpcp repository in " << directory << '\n';
    }
    return 0;
}

int run_export_header_command(
    const std::filesystem::path& repository,
    const std::filesystem::path& output,
    const ConfigCommandOptions& options
) {
    auto password = application::read_password(options.password_file, !options.json, options.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    auto unlocked = repository::load_config(repository, *password);
    if (!unlocked) {
        return report_error(unlocked.error());
    }
    const auto result = repository::export_config(unlocked->config, output);
    if (!result) {
        return report_error(result.error());
    }
    print_json({
        {"schema", "cpcp.repo-export-header.v1"},
        {"repository_uuid", domain::hex_encode(unlocked->config.repository_uuid)},
        {"output", output.string()},
        {"degraded_redundancy", unlocked->degraded_redundancy},
    }, options.json);
    if (!options.json) {
        std::cout << "Exported repository header to " << output << '\n';
    }
    if (unlocked->degraded_redundancy) {
        std::cerr << "Warning: only one valid configuration replica was used\n";
    }
    return 0;
}

int run_import_header_command(
    const std::filesystem::path& header,
    const std::filesystem::path& repository,
    const ConfigCommandOptions& options
) {
    auto password = application::read_password(options.password_file, !options.json, options.password_fd);
    if (!password) {
        return report_error(password.error());
    }
    auto imported = repository::import_config(header, repository, *password);
    if (!imported) {
        return report_error(imported.error());
    }
    auto unlocked = repository::load_config(repository, *password);
    if (!unlocked) {
        return report_error(unlocked.error());
    }
    print_json({
        {"schema", "cpcp.repo-import-header.v1"},
        {"repository_uuid", domain::hex_encode(unlocked->config.repository_uuid)},
    }, options.json);
    if (!options.json) {
        std::cout << "Imported repository header into " << repository << '\n';
    }
    return 0;
}

}
