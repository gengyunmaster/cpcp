#include "platform/cancellation.hpp"

#include <atomic>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#endif

namespace cpcp::platform {

using domain::Error;
using domain::ErrorCode;

namespace {

std::atomic_bool cancelled = false;

#ifdef _WIN32
BOOL WINAPI handle_ctrl(DWORD type) {
    if (type == CTRL_C_EVENT) {
        cancelled.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}
#else
void handle_sigint(int) {
    cancelled.store(true, std::memory_order_relaxed);
}
#endif

}

domain::Result<void> install_cancellation_handler() {
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(handle_ctrl, TRUE)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot install console cancellation handler"});
    }
#else
    struct sigaction action {};
    action.sa_handler = handle_sigint;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGINT, &action, nullptr) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot install SIGINT handler"});
    }
#endif
    return {};
}

domain::Result<void> check_cancellation() {
    if (cancelled.load(std::memory_order_relaxed)) {
        return std::unexpected(Error{ErrorCode::cancellation, "operation cancelled"});
    }
    return {};
}

void request_cancellation_for_test() {
    cancelled.store(true, std::memory_order_relaxed);
}

void reset_cancellation_for_test() {
    cancelled.store(false, std::memory_order_relaxed);
}

}
