#include "platform/cancellation.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("cancellation is reported through the typed cancellation error") {
    cpcp::platform::reset_cancellation_for_test();
    REQUIRE(cpcp::platform::check_cancellation());
    cpcp::platform::request_cancellation_for_test();
    const auto result = cpcp::platform::check_cancellation();

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::cancellation);
    cpcp::platform::reset_cancellation_for_test();
}
