#pragma once

#include "application/inspection_service.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace cpcp::application {

struct CheckOptions {
    std::filesystem::path source;
    SnapshotRequest snapshot;
    std::optional<std::uint32_t> root;
    std::optional<std::string> root_label;
    std::string path;
    bool content = false;
    bool verify_repo = false;
    bool repo_read_only = false;
};

struct CheckEvent {
    std::uint32_t root = 0;
    std::string path;
    std::string status;
    std::string reason;
    std::uint64_t size = 0;
};

struct CheckReport {
    std::uint64_t snapshot_generation = 0;
    std::string snapshot_status;
    std::uint32_t root = 0;
    std::string root_label;
    std::string mode;
    std::uint64_t repository_chunk_references = 0;
    std::uint64_t total = 0;
    std::uint64_t differences = 0;
};

using CheckEventSink = std::function<domain::Result<void>(const CheckEvent&)>;

domain::Result<CheckReport> check_backup(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    const CheckOptions& options,
    const CheckEventSink& sink
);

}
