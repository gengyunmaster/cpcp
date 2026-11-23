#pragma once

#include "domain/result.hpp"

namespace cpcp::platform {

domain::Result<void> install_cancellation_handler();
domain::Result<void> check_cancellation();
void request_cancellation_for_test();
void reset_cancellation_for_test();

}
