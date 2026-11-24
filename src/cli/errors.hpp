#pragma once

#include "domain/result.hpp"

namespace cpcp::cli {

int exit_code(domain::ErrorCode code);
int report_error(const domain::Error& error);
void warn_lockless_repository(bool enabled);

}
