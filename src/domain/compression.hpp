#pragma once

#include "domain/encoding.hpp"
#include "domain/result.hpp"

#include <cstddef>
#include <span>

namespace cpcp::domain {

Result<Bytes> compress_zstd(std::span<const std::byte> input);
Result<Bytes> decompress_zstd(std::span<const std::byte> input, std::size_t expected_size);

}
