#include "repository/config.hpp"

#include "platform/binary_file.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace cpcp::repository {

using domain::Bytes;
using domain::Error;
using domain::ErrorCode;

namespace {

Bytes string_bytes(const std::string& text) {
    const auto view = std::as_bytes(std::span(text));
    return Bytes(view.begin(), view.end());
}

domain::Result<Bytes> read_small_file(const std::filesystem::path& path) {
    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }

    Bytes output;
    std::array<std::byte, 4096> buffer{};
    while (true) {
        const auto count = file->read_some(buffer);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            break;
        }
        output.insert(
            output.end(),
            buffer.begin(),
            buffer.begin() + static_cast<std::ptrdiff_t>(*count)
        );
        if (output.size() > config_file_limit) {
            return std::unexpected(Error{ErrorCode::integrity, "configuration file is too large"});
        }
    }
    return output;
}

domain::Result<void> write_new_file(
    const std::filesystem::path& path,
    std::span<const std::byte> contents
) {
    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    auto result = file->write_all(contents);
    if (!result) {
        return result;
    }
    result = file->flush();
    if (!result) {
        return result;
    }
    return file->close();
}

}

domain::Result<void> write_new_config_replicas(
    const std::filesystem::path& repository,
    const RepositoryConfig& config
) {
    const auto serialized = serialize_config(config);
    if (!serialized) {
        return std::unexpected(serialized.error());
    }
    const Bytes bytes = string_bytes(*serialized);
    const std::filesystem::path names[] = {
        repository / "cpcp.config.json",
        repository / "cpcp.config.backup.json",
    };
    for (const auto& name : names) {
        const auto result = write_new_file(name, bytes);
        if (!result) {
            return result;
        }
    }
    return platform::sync_directory(repository);
}

domain::Result<UnlockedConfig> load_config(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
) {
    const std::filesystem::path names[] = {
        repository / "cpcp.config.json",
        repository / "cpcp.config.backup.json",
    };
    std::vector<UnlockedConfig> candidates;
    for (const auto& name : names) {
        const auto bytes = read_small_file(name);
        if (!bytes) {
            continue;
        }
        auto config = parse_config(*bytes);
        if (!config) {
            continue;
        }
        auto master = unlock_config(*config, password);
        if (!master) {
            continue;
        }
        candidates.push_back(UnlockedConfig{
            std::move(*config),
            std::move(master).value(),
            false,
        });
    }
    if (candidates.empty()) {
        return std::unexpected(Error{
            ErrorCode::authentication,
            "no readable configuration replica could be unlocked",
        });
    }

    const auto selected = std::ranges::max_element(
        candidates,
        [](const UnlockedConfig& left, const UnlockedConfig& right) {
            return left.config.revision < right.config.revision;
        }
    );
    const bool degraded = candidates.size() != 2
        || candidates[0].config.revision != candidates[1].config.revision;
    auto result = std::move(*selected);
    result.degraded_redundancy = degraded;
    return result;
}

domain::Result<void> export_config(
    const RepositoryConfig& config,
    const std::filesystem::path& output
) {
    const auto serialized = serialize_config(config);
    if (!serialized) {
        return std::unexpected(serialized.error());
    }
    const Bytes bytes = string_bytes(*serialized);
    return write_new_file(output, bytes);
}

domain::Result<void> import_config(
    const std::filesystem::path& header,
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password
) {
    const auto bytes = read_small_file(header);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto config = parse_config(*bytes);
    if (!config) {
        return std::unexpected(config.error());
    }
    auto master = unlock_config(*config, password);
    if (!master) {
        return std::unexpected(master.error());
    }

    if (!std::filesystem::exists(repository / "chunks")
        || !std::filesystem::exists(repository / "snapshots")) {
        return std::unexpected(Error{
            ErrorCode::permanent_io,
            "target does not contain repository object directories",
        });
    }
    if (std::filesystem::exists(repository / "cpcp.config.json")
        || std::filesystem::exists(repository / "cpcp.config.backup.json")) {
        return std::unexpected(Error{
            ErrorCode::conflict,
            "refusing to overwrite an existing repository configuration",
        });
    }
    return write_new_config_replicas(repository, *config);
}

}
