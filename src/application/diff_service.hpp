#pragma once

#include "crypto/secret.hpp"
#include "domain/result.hpp"

#include <filesystem>
#include <functional>
#include <string>

namespace cpcp::application {

struct DiffEvent {
    std::uint32_t root = 0;
    std::string path;
    std::string status;
    std::string reason;
};

struct DiffReport {
    std::uint64_t left = 0;
    std::uint64_t right = 0;
    std::string left_status;
    std::string right_status;
    std::uint64_t total = 0;
    std::uint64_t differences = 0;
};

using DiffEventSink = std::function<domain::Result<void>(const DiffEvent&)>;

domain::Result<DiffReport> diff_snapshots(
    const std::filesystem::path& repository,
    const crypto::SecretBytes& password,
    std::uint64_t left,
    std::uint64_t right,
    const DiffEventSink& sink
);

}
