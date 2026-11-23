#include "application/credentials.hpp"

#include "domain/encoding.hpp"
#include "platform/binary_file.hpp"

#include <array>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace cpcp::application {

using domain::Error;
using domain::ErrorCode;

namespace {

domain::Result<crypto::SecretBytes> from_line(std::string line) {
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    if (line.empty() || line.size() > 1024
        || line.find_first_of("\r\n") != std::string::npos) {
        return std::unexpected(Error{ErrorCode::usage, "password must be one nonempty line"});
    }
    if (line.find('\0') != std::string::npos) {
        return std::unexpected(Error{ErrorCode::usage, "password cannot contain NUL"});
    }

    domain::Bytes bytes;
    bytes.reserve(line.size());
    for (const char value : line) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return crypto::SecretBytes::copy(bytes);
}

domain::Result<crypto::SecretBytes> read_file(const std::filesystem::path& path) {
#ifndef _WIN32
    const auto status = std::filesystem::symlink_status(path);
    const auto permissions = status.permissions();
    constexpr auto exposed = std::filesystem::perms::group_read
        | std::filesystem::perms::group_write
        | std::filesystem::perms::group_exec
        | std::filesystem::perms::others_read
        | std::filesystem::perms::others_write
        | std::filesystem::perms::others_exec;
    if ((permissions & exposed) != std::filesystem::perms::none) {
        return std::unexpected(Error{
            ErrorCode::usage,
            "password file permissions allow group or other access",
        });
    }
#endif

    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    std::string line;
    std::array<char, 1025> buffer{};
    while (true) {
        const auto count = file->read_some(
            std::span<std::byte>(reinterpret_cast<std::byte*>(buffer.data()), buffer.size())
        );
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            break;
        }
        line.append(buffer.data(), *count);
        if (line.size() > 1024) {
            return std::unexpected(Error{ErrorCode::usage, "password exceeds 1024 bytes"});
        }
    }
    return from_line(std::move(line));
}

domain::Result<crypto::SecretBytes> read_prompt() {
#ifndef _WIN32
    if (isatty(STDIN_FILENO) == 0) {
        return std::unexpected(Error{
            ErrorCode::usage,
            "password input is unavailable in non-interactive mode",
        });
    }
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot read terminal settings"});
    }
    termios hidden = original;
    hidden.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot disable terminal echo"});
    }
#else
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
    DWORD original = 0;
    if (console == INVALID_HANDLE_VALUE || !GetConsoleMode(console, &original)) {
        return std::unexpected(Error{ErrorCode::usage, "password input requires a console or file"});
    }
    if (!SetConsoleMode(console, original & ~static_cast<DWORD>(ENABLE_ECHO_INPUT))) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot disable console echo"});
    }
#endif

    std::cerr << "Password: ";
    std::string line;
    std::getline(std::cin, line);
#ifndef _WIN32
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
#else
    SetConsoleMode(console, original);
#endif
    std::cerr << '\n';
    return from_line(std::move(line));
}

}

domain::Result<crypto::SecretBytes> read_password(
    const std::optional<std::filesystem::path>& password_file,
    bool allow_prompt
) {
    if (password_file) {
        return read_file(*password_file);
    }
    if (!allow_prompt) {
        return std::unexpected(Error{
            ErrorCode::usage,
            "use --password-file in non-interactive mode",
        });
    }
    return read_prompt();
}

}
