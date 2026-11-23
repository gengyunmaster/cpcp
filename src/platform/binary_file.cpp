#include "platform/binary_file.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#include <string>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/fs.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <stdio.h>
#endif
#endif

namespace cpcp::platform {

using domain::Error;
using domain::ErrorCode;

namespace {

#ifndef _WIN32
std::string native_error(int error) {
    return std::generic_category().message(error);
}
#endif

domain::Result<void> close_native(std::intptr_t handle) {
#ifdef _WIN32
    if (!CloseHandle(reinterpret_cast<HANDLE>(handle))) {
        return std::unexpected(Error{ErrorCode::permanent_io, "CloseHandle failed"});
    }
#else
    if (close(static_cast<int>(handle)) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
    return {};
}

}

BinaryFile::BinaryFile(std::intptr_t handle) : handle_(handle) {
}

domain::Result<BinaryFile> BinaryFile::create_new(const std::filesystem::path& path) {
#ifdef _WIN32
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(Error{ErrorCode::permanent_io, "CreateFileW failed"});
    }
    return BinaryFile(reinterpret_cast<std::intptr_t>(handle));
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int handle = open(path.c_str(), flags, S_IRUSR | S_IWUSR);
    if (handle < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    return BinaryFile(handle);
#endif
}

domain::Result<BinaryFile> BinaryFile::open_read(const std::filesystem::path& path) {
#ifdef _WIN32
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(Error{ErrorCode::permanent_io, "CreateFileW failed"});
    }
    return BinaryFile(reinterpret_cast<std::intptr_t>(handle));
#else
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int handle = open(path.c_str(), flags);
    if (handle < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    struct stat status {};
    if (fstat(handle, &status) != 0 || !S_ISREG(status.st_mode)) {
        ::close(handle);
        return std::unexpected(Error{ErrorCode::permanent_io, "file is not a regular file"});
    }
    return BinaryFile(handle);
#endif
}

BinaryFile::BinaryFile(BinaryFile&& other) noexcept
    : handle_(std::exchange(other.handle_, -1)) {
}

BinaryFile& BinaryFile::operator=(BinaryFile&& other) noexcept {
    if (this != &other) {
        if (is_open()) {
            std::ignore = close();
        }
        handle_ = std::exchange(other.handle_, -1);
    }
    return *this;
}

BinaryFile::~BinaryFile() {
    if (is_open()) {
        std::ignore = close();
    }
}

bool BinaryFile::is_open() const {
    return handle_ != -1;
}

domain::Result<void> BinaryFile::write_all(std::span<const std::byte> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
#ifdef _WIN32
        const auto remaining = bytes.size() - offset;
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            remaining,
            std::numeric_limits<DWORD>::max()
        ));
        DWORD written = 0;
        if (!WriteFile(
                reinterpret_cast<HANDLE>(handle_),
                bytes.data() + offset,
                requested,
                &written,
                nullptr
            )) {
            return std::unexpected(Error{ErrorCode::permanent_io, "WriteFile failed"});
        }
#else
        const ssize_t written = write(
            static_cast<int>(handle_),
            bytes.data() + offset,
            bytes.size() - offset
        );
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0) {
            return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
        }
#endif
        if (written == 0) {
            return std::unexpected(Error{ErrorCode::permanent_io, "zero-length file write"});
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

domain::Result<std::size_t> BinaryFile::read_some(std::span<std::byte> output) {
    if (output.empty()) {
        return std::size_t{0};
    }
#ifdef _WIN32
    const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
        output.size(),
        std::numeric_limits<DWORD>::max()
    ));
    DWORD count = 0;
    if (!ReadFile(
            reinterpret_cast<HANDLE>(handle_),
            output.data(),
            requested,
            &count,
            nullptr
        )) {
        return std::unexpected(Error{ErrorCode::permanent_io, "ReadFile failed"});
    }
#else
    ssize_t count = 0;
    do {
        count = read(static_cast<int>(handle_), output.data(), output.size());
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
    return static_cast<std::size_t>(count);
}

domain::Result<void> BinaryFile::read_exact(std::span<std::byte> output) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count = read_some(output.subspan(offset));
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return std::unexpected(Error{ErrorCode::integrity, "unexpected end of file"});
        }
        offset += *count;
    }
    return {};
}

domain::Result<void> BinaryFile::flush() {
#ifdef _WIN32
    if (!FlushFileBuffers(reinterpret_cast<HANDLE>(handle_))) {
        return std::unexpected(Error{ErrorCode::permanent_io, "FlushFileBuffers failed"});
    }
#elif defined(__APPLE__)
    if (fcntl(static_cast<int>(handle_), F_FULLFSYNC) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#else
    if (fsync(static_cast<int>(handle_)) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
    return {};
}

domain::Result<void> BinaryFile::close() {
    if (!is_open()) {
        return {};
    }
    const auto handle = std::exchange(handle_, -1);
    return close_native(handle);
}

domain::Result<void> sync_directory(const std::filesystem::path& path) {
#ifdef _WIN32
    static_cast<void>(path);
    return std::unexpected(Error{
        ErrorCode::unsupported,
        "directory synchronization is not yet implemented on Windows",
    });
#else
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    const int directory = open(path.c_str(), flags);
    if (directory < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#ifdef __APPLE__
    const int result = fcntl(directory, F_FULLFSYNC);
#else
    const int result = fsync(directory);
#endif
    const int error = errno;
    close(directory);
    if (result != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(error)});
    }
    return {};
#endif
}

domain::Result<void> publish_no_replace(
    const std::filesystem::path& temporary,
    const std::filesystem::path& final
) {
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), final.c_str(), MOVEFILE_WRITE_THROUGH)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "MoveFileExW failed"});
    }
    return {};
#elif defined(__linux__) && defined(SYS_renameat2)
    if (syscall(
            SYS_renameat2,
            AT_FDCWD,
            temporary.c_str(),
            AT_FDCWD,
            final.c_str(),
            RENAME_NOREPLACE
        ) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    return {};
#elif defined(__APPLE__)
    if (renamex_np(temporary.c_str(), final.c_str(), RENAME_EXCL) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    return {};
#else
    return std::unexpected(Error{
        ErrorCode::unsupported,
        "atomic no-replace publication is unsupported on this platform",
    });
#endif
}

}
