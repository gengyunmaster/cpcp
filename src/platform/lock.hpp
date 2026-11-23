#pragma once

#include "domain/result.hpp"

#include <cstdint>
#include <filesystem>
#include <vector>

namespace cpcp::platform {

enum class LockMode {
    shared,
    exclusive,
};

class FileLock {
public:
    static domain::Result<FileLock> acquire(
        const std::filesystem::path& path,
        LockMode mode
    );

    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;
    ~FileLock();

    domain::Result<void> release();
    bool locked() const;

private:
    explicit FileLock(std::intptr_t handle);

    std::intptr_t handle_ = -1;
#ifdef _WIN32
    std::uint64_t overlapped_ = 0;
#endif
};

class RepositoryLocks {
public:
    static domain::Result<RepositoryLocks> backup(const std::filesystem::path& repository);
    static domain::Result<RepositoryLocks> read(const std::filesystem::path& repository);
    static domain::Result<RepositoryLocks> maintenance(const std::filesystem::path& repository);

private:
    std::vector<FileLock> locks_;
};

}
