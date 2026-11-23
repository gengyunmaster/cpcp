#include "platform/binary_file.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <string>

namespace {

using cpcp::platform::BinaryFile;

class TestDirectory {
public:
    TestDirectory() {
        path_ = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "native-file-test";
        std::filesystem::remove_all(path_);
        std::filesystem::create_directories(path_);
    }

    ~TestDirectory() {
        std::filesystem::remove_all(path_);
    }

    std::filesystem::path path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

TEST_CASE("native binary files write flush and read exact bytes") {
    TestDirectory directory;
    const auto path = directory.path() / "data.bin";
    const std::array<std::byte, 4> expected{
        std::byte{0},
        std::byte{1},
        std::byte{2},
        std::byte{255},
    };

    auto writer = BinaryFile::create_new(path).value();
    REQUIRE(writer.write_all(expected));
    REQUIRE(writer.flush());
    REQUIRE(writer.close());

    auto reader = BinaryFile::open_read(path).value();
    std::array<std::byte, 4> actual{};
    REQUIRE(reader.read_exact(actual));
    REQUIRE(actual == expected);
    std::array<std::byte, 1> extra{};
    REQUIRE(reader.read_some(extra).value() == 0);
}

TEST_CASE("native no-replace publication preserves an existing destination") {
    TestDirectory directory;
    const auto temporary = directory.path() / "temporary";
    const auto final = directory.path() / "final";
    const std::array<std::byte, 1> value{std::byte{7}};

    auto writer = BinaryFile::create_new(temporary).value();
    REQUIRE(writer.write_all(value));
    REQUIRE(writer.flush());
    REQUIRE(writer.close());
    REQUIRE(cpcp::platform::publish_no_replace(temporary, final));
    REQUIRE(cpcp::platform::sync_directory(directory.path()));

    auto second = BinaryFile::create_new(temporary).value();
    REQUIRE(second.close());
    REQUIRE_FALSE(cpcp::platform::publish_no_replace(temporary, final));

    auto reader = BinaryFile::open_read(final).value();
    std::array<std::byte, 1> actual{};
    REQUIRE(reader.read_exact(actual));
    REQUIRE(actual == value);
}

}
