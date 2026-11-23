#pragma once

#include <expected>
#include <string>
#include <utility>

namespace cpcp::domain {

enum class ErrorCode {
    usage,
    authentication,
    retryable_io,
    permanent_io,
    unsupported,
    source_changed,
    integrity,
    conflict,
    lock_busy,
    cancellation,
    internal,
};

struct Error {
    ErrorCode code;
    std::string message;
};

template<typename T>
using Result = std::expected<T, Error>;

template<typename T>
Result<T> fail(ErrorCode code, std::string message) {
    return std::unexpected(Error{code, std::move(message)});
}

}
