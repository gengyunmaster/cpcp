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
        FILE_SHARE_READ,
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

domain::Result<BinaryFile> BinaryFile::open_read_write(const std::filesystem::path& path) {
#ifdef _WIN32
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
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
    int flags = O_RDWR | O_CLOEXEC;
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

domain::Result<void> BinaryFile::seek(std::uint64_t offset) {
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::unexpected(Error{ErrorCode::permanent_io, "file offset is out of range"});
    }
#ifdef _WIN32
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(reinterpret_cast<HANDLE>(handle_), position, nullptr, FILE_BEGIN)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "SetFilePointerEx failed"});
    }
#else
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(Error{ErrorCode::permanent_io, "file offset is out of range"});
    }
    off_t positioned = 0;
    do {
        positioned = lseek(static_cast<int>(handle_), static_cast<off_t>(offset), SEEK_SET);
    } while (positioned < 0 && errno == EINTR);
    if (positioned < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
    return {};
}

domain::Result<void> BinaryFile::truncate(std::uint64_t size) {
    const auto positioned = seek(size);
    if (!positioned) {
        return positioned;
    }
#ifdef _WIN32
    if (!SetEndOfFile(reinterpret_cast<HANDLE>(handle_))) {
        return std::unexpected(Error{ErrorCode::permanent_io, "SetEndOfFile failed"});
    }
#else
    if (size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        return std::unexpected(Error{ErrorCode::permanent_io, "file size is out of range"});
    }
    if (ftruncate(static_cast<int>(handle_), static_cast<off_t>(size)) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
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

domain::Result<FileMetadata> BinaryFile::metadata() const {
    FileMetadata metadata;
#ifdef _WIN32
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(reinterpret_cast<HANDLE>(handle_), &size)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "GetFileSizeEx failed"});
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(handle_), &info)) {
        return std::unexpected(Error{ErrorCode::permanent_io, "GetFileInformationByHandle failed"});
    }
    metadata.size = static_cast<std::uint64_t>(size.QuadPart);
    ULARGE_INTEGER ticks;
    ticks.LowPart = info.ftLastWriteTime.dwLowDateTime;
    ticks.HighPart = info.ftLastWriteTime.dwHighDateTime;
    constexpr std::uint64_t epoch_seconds = 11644473600ULL;
    constexpr std::uint64_t ticks_per_second = 10000000ULL;
    const auto seconds = ticks.QuadPart / ticks_per_second;
    metadata.mtime_seconds = static_cast<std::int64_t>(seconds) - static_cast<std::int64_t>(epoch_seconds);
    metadata.mtime_nanoseconds = static_cast<std::uint32_t>(
        (ticks.QuadPart % ticks_per_second) * 100
    );
    metadata.device = info.dwVolumeSerialNumber;
    metadata.inode = static_cast<std::uint64_t>(info.nFileIndexHigh) << 32
        | info.nFileIndexLow;
    metadata.mode = (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
    return metadata;
#else
    struct stat status {};
    if (fstat(static_cast<int>(handle_), &status) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    metadata.size = static_cast<std::uint64_t>(status.st_size);
#ifdef __APPLE__
    metadata.mtime_seconds = status.st_mtimespec.tv_sec;
    metadata.mtime_nanoseconds = static_cast<std::uint32_t>(status.st_mtimespec.tv_nsec);
#else
    metadata.mtime_seconds = status.st_mtim.tv_sec;
    metadata.mtime_nanoseconds = static_cast<std::uint32_t>(status.st_mtim.tv_nsec);
#endif
    metadata.device = static_cast<std::uint64_t>(status.st_dev);
    metadata.inode = status.st_ino;
    metadata.mode = static_cast<std::uint32_t>(status.st_mode & 07777);
    metadata.uid = static_cast<std::uint64_t>(status.st_uid);
    metadata.gid = static_cast<std::uint64_t>(status.st_gid);
    metadata.has_ownership = true;
    return metadata;
#endif
}

domain::Result<void> set_modification_time(
    const std::filesystem::path& path,
    std::int64_t seconds,
    std::uint32_t nanoseconds
) {
    if (nanoseconds > 999999999) {
        return std::unexpected(Error{ErrorCode::usage, "invalid modification timestamp"});
    }
#ifdef _WIN32
    constexpr std::int64_t epoch_seconds = 11644473600LL;
    constexpr std::uint64_t ticks_per_second = 10000000ULL;
    if (seconds < -epoch_seconds || seconds > std::numeric_limits<std::int64_t>::max() - epoch_seconds) {
        return std::unexpected(Error{ErrorCode::unsupported, "timestamp is outside the NTFS range"});
    }
    const auto windows_seconds = static_cast<std::uint64_t>(seconds + epoch_seconds);
    const auto fractional_ticks = static_cast<std::uint64_t>(nanoseconds / 100);
    if (windows_seconds > (std::numeric_limits<std::uint64_t>::max() - fractional_ticks) / ticks_per_second) {
        return std::unexpected(Error{ErrorCode::unsupported, "timestamp is outside the NTFS range"});
    }
    const auto ticks = windows_seconds * ticks_per_second + fractional_ticks;
    HANDLE handle = CreateFileW(
        path.c_str(),
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(Error{ErrorCode::permanent_io, "CreateFileW failed while setting the timestamp"});
    }
    FILETIME write_time{};
    write_time.dwLowDateTime = static_cast<DWORD>(ticks & 0xffffffffULL);
    write_time.dwHighDateTime = static_cast<DWORD>(ticks >> 32U);
    const auto succeeded = SetFileTime(handle, nullptr, nullptr, &write_time);
    const auto error = GetLastError();
    CloseHandle(handle);
    if (!succeeded) {
        return std::unexpected(Error{ErrorCode::permanent_io, "SetFileTime failed with error " + std::to_string(error)});
    }
#else
    timespec times[2]{};
    times[0].tv_nsec = UTIME_OMIT;
    times[1].tv_sec = static_cast<time_t>(seconds);
    times[1].tv_nsec = static_cast<long>(nanoseconds);
    if (utimensat(AT_FDCWD, path.c_str(), times, AT_SYMLINK_NOFOLLOW) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
#endif
    return {};
}

domain::Result<void> set_ownership(
    const std::filesystem::path& path,
    std::uint64_t uid,
    std::uint64_t gid
) {
#ifdef _WIN32
    static_cast<void>(path);
    static_cast<void>(uid);
    static_cast<void>(gid);
    return std::unexpected(Error{ErrorCode::unsupported, "POSIX ownership restoration is unavailable on Windows"});
#else
    if (uid > std::numeric_limits<uid_t>::max() || gid > std::numeric_limits<gid_t>::max()) {
        return std::unexpected(Error{ErrorCode::usage, "ownership value is out of range"});
    }
    if (lchown(path.c_str(), static_cast<uid_t>(uid), static_cast<gid_t>(gid)) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    return {};
#endif
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

domain::Result<void> replace_file(
    const std::filesystem::path& temporary,
    const std::filesystem::path& final
) {
#ifdef _WIN32
    if (!MoveFileExW(
            temporary.c_str(),
            final.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        )) {
        return std::unexpected(Error{ErrorCode::permanent_io, "MoveFileExW failed"});
    }
    return {};
#else
    if (rename(temporary.c_str(), final.c_str()) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, native_error(errno)});
    }
    return {};
#endif
}

}
