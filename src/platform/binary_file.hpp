#pragma once

#include "domain/result.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>

namespace cpcp::platform {

class BinaryFile {
public:
    static domain::Result<BinaryFile> create_new(const std::filesystem::path& path);
    static domain::Result<BinaryFile> open_read(const std::filesystem::path& path);

    BinaryFile(const BinaryFile&) = delete;
    BinaryFile& operator=(const BinaryFile&) = delete;
    BinaryFile(BinaryFile&& other) noexcept;
    BinaryFile& operator=(BinaryFile&& other) noexcept;
    ~BinaryFile();

    domain::Result<void> write_all(std::span<const std::byte> bytes);
    domain::Result<std::size_t> read_some(std::span<std::byte> output);
    domain::Result<void> read_exact(std::span<std::byte> output);
    domain::Result<void> flush();
    domain::Result<void> close();
    bool is_open() const;

private:
    explicit BinaryFile(std::intptr_t handle);

    std::intptr_t handle_ = -1;
};

domain::Result<void> sync_directory(const std::filesystem::path& path);
domain::Result<void> publish_no_replace(
    const std::filesystem::path& temporary,
    const std::filesystem::path& final
);

}
