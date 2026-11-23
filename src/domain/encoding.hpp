#pragma once

#include "domain/result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cpcp::domain {

using Bytes = std::vector<std::byte>;
using Uuid = std::array<std::byte, 16>;

inline constexpr std::size_t uuid_size = 16;

std::string hex_encode(std::span<const std::byte> bytes);

template<std::size_t N>
Result<std::array<std::byte, N>> hex_decode(std::string_view text) {
    if (text.size() != N * 2) {
        return fail<std::array<std::byte, N>>(
            ErrorCode::usage,
            "hexadecimal value has the wrong length"
        );
    }

    std::array<std::byte, N> output{};
    for (std::size_t index = 0; index < N; ++index) {
        const auto digit = [](char value) -> int {
            if (value >= '0' && value <= '9') {
                return value - '0';
            }
            if (value >= 'a' && value <= 'f') {
                return value - 'a' + 10;
            }
            if (value >= 'A' && value <= 'F') {
                return value - 'A' + 10;
            }
            return -1;
        };
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return fail<std::array<std::byte, N>>(
                ErrorCode::usage,
                "hexadecimal value contains an invalid character"
            );
        }
        output[index] = static_cast<std::byte>((high << 4) | low);
    }
    return output;
}

inline void append_le(Bytes& output, std::uint64_t value, std::size_t width) {
    for (std::size_t index = 0; index < width; ++index) {
        output.push_back(static_cast<std::byte>((value >> (index * 8)) & 0xffU));
    }
}

inline Result<std::uint64_t> read_le(
    std::span<const std::byte> input,
    std::size_t width
) {
    if (width == 0 || width > 8 || input.size() != width) {
        return fail<std::uint64_t>(ErrorCode::integrity, "invalid little-endian field");
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(input[index]))
            << (index * 8);
    }
    return value;
}

}
