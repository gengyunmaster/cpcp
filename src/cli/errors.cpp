#include "cli/errors.hpp"

#include <iostream>

namespace cpcp::cli {

int exit_code(domain::ErrorCode code) {
    using domain::ErrorCode;
    switch (code) {
    case ErrorCode::usage:
        return 2;
    case ErrorCode::integrity:
        return 4;
    case ErrorCode::authentication:
        return 5;
    case ErrorCode::cancellation:
        return 130;
    case ErrorCode::retryable_io:
    case ErrorCode::permanent_io:
    case ErrorCode::unsupported:
    case ErrorCode::source_changed:
        return 3;
    case ErrorCode::conflict:
    case ErrorCode::lock_busy:
    case ErrorCode::internal:
        return 1;
    }
    return 1;
}

int report_error(const domain::Error& error) {
    std::cerr << "Error: " << error.message << '\n';
    return exit_code(error.code);
}

}
