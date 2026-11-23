#include "domain/result.hpp"

#include <catch2/catch_test_macros.hpp>

namespace {

using cpcp::domain::ErrorCode;
using cpcp::domain::Result;

TEST_CASE("Result preserves a successful value") {
    const Result<int> result = 42;

    REQUIRE(result.has_value());
    REQUIRE(*result == 42);
}

TEST_CASE("Result preserves a typed error") {
    const auto result = cpcp::domain::fail<int>(
        ErrorCode::integrity,
        "chunk digest mismatch"
    );

    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error().code == ErrorCode::integrity);
    REQUIRE(result.error().message == "chunk digest mismatch");
}

}
