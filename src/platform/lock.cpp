#include "platform/lock.hpp"

#include "platform/binary_file.hpp"

#include <cerrno>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace cpcp::platform {

using domain::Error;
using domain::ErrorCode;

FileLock::FileLock(std::intptr_t handle) : handle_(handle) {
}

domain::Result<FileLock> FileLock::acquire(
    const std::filesystem::path& path,
    LockMode mode
) {
    if (!std::filesystem::exists(path)) {
        auto created = BinaryFile::create_new(path);
        if (created) {
            const auto closed = created->close();
            if (!closed) {
                return std::unexpected(closed.error());
            }
        }
    }
#ifdef _WIN32
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot open repository lock"});
    }
    FileLock result(reinterpret_cast<std::intptr_t>(handle));
    const DWORD flags = mode == LockMode::exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;
    if (!LockFileEx(
            handle,
            flags | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            MAXDWORD,
            MAXDWORD,
            reinterpret_cast<LPOVERLAPPED>(&result.overlapped_)
        )) {
        CloseHandle(handle);
        return std::unexpected(Error{ErrorCode::lock_busy, "repository is locked"});
    }
    return result;
#else
    const int handle = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (handle < 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot open repository lock"});
    }
    const int operation = mode == LockMode::exclusive ? LOCK_EX : LOCK_SH;
    if (flock(handle, operation | LOCK_NB) != 0) {
        close(handle);
        return std::unexpected(Error{ErrorCode::lock_busy, "repository is locked"});
    }
    return FileLock(handle);
#endif
}

FileLock::FileLock(FileLock&& other) noexcept
    : handle_(std::exchange(other.handle_, -1)) {
#ifdef _WIN32
    overlapped_ = std::exchange(other.overlapped_, 0);
#endif
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        if (locked()) {
            std::ignore = release();
        }
        handle_ = std::exchange(other.handle_, -1);
#ifdef _WIN32
        overlapped_ = std::exchange(other.overlapped_, 0);
#endif
    }
    return *this;
}

FileLock::~FileLock() {
    if (locked()) {
        std::ignore = release();
    }
}

domain::Result<void> FileLock::release() {
    if (!locked()) {
        return {};
    }
    const auto handle = std::exchange(handle_, -1);
#ifdef _WIN32
    if (!UnlockFileEx(
            reinterpret_cast<HANDLE>(handle),
            0,
            MAXDWORD,
            MAXDWORD,
            reinterpret_cast<LPOVERLAPPED>(&overlapped_)
        )
        || !CloseHandle(reinterpret_cast<HANDLE>(handle))) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot release repository lock"});
    }
#else
    if (flock(static_cast<int>(handle), LOCK_UN) != 0 || close(static_cast<int>(handle)) != 0) {
        return std::unexpected(Error{ErrorCode::permanent_io, "cannot release repository lock"});
    }
#endif
    return {};
}

bool FileLock::locked() const {
    return handle_ != -1;
}

domain::Result<RepositoryLocks> RepositoryLocks::backup(
    const std::filesystem::path& repository
) {
    RepositoryLocks result;
    auto lifecycle = FileLock::acquire(repository / "lock", LockMode::shared);
    if (!lifecycle) {
        return std::unexpected(lifecycle.error());
    }
    result.locks_.push_back(std::move(lifecycle).value());
    auto writer = FileLock::acquire(repository / "backup.lock", LockMode::exclusive);
    if (!writer) {
        return std::unexpected(writer.error());
    }
    result.locks_.push_back(std::move(writer).value());
    return result;
}

domain::Result<RepositoryLocks> RepositoryLocks::read(
    const std::filesystem::path& repository
) {
    RepositoryLocks result;
    auto lifecycle = FileLock::acquire(repository / "lock", LockMode::shared);
    if (!lifecycle) {
        return std::unexpected(lifecycle.error());
    }
    result.locks_.push_back(std::move(lifecycle).value());
    return result;
}

domain::Result<RepositoryLocks> RepositoryLocks::maintenance(
    const std::filesystem::path& repository
) {
    RepositoryLocks result;
    auto lifecycle = FileLock::acquire(repository / "lock", LockMode::exclusive);
    if (!lifecycle) {
        return std::unexpected(lifecycle.error());
    }
    result.locks_.push_back(std::move(lifecycle).value());
    auto writer = FileLock::acquire(repository / "backup.lock", LockMode::exclusive);
    if (!writer) {
        return std::unexpected(writer.error());
    }
    result.locks_.push_back(std::move(writer).value());
    return result;
}

}
