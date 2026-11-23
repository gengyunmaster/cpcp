#pragma once

#include "domain/result.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <span>

namespace cpcp::domain {

struct JsonLimits {
    std::size_t bytes = 128 * 1024;
    std::size_t depth = 16;
    std::size_t string = 4096;
};

Result<nlohmann::json> parse_bounded_json(
    std::span<const std::byte> input,
    const JsonLimits& limits = {}
);

}
