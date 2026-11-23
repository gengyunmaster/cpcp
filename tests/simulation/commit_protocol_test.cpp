#include "storage/simulated_filesystem.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace {

using cpcp::storage::SimulatedFilesystem;

SimulatedFilesystem::Bytes payload() {
    const std::string text = "complete chunk";
    SimulatedFilesystem::Bytes result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

TEST_CASE("all small persistence orders preserve the publication state machine") {
    const auto expected = payload();

    for (unsigned int mask = 0; mask < 4; ++mask) {
        for (unsigned int reverse = 0; reverse < 2; ++reverse) {
            SimulatedFilesystem fs;
            REQUIRE(fs.write_file("/tmp.part", expected));
            REQUIRE(fs.sync_file("/tmp.part"));
            REQUIRE(fs.publish_no_replace("/tmp.part", "/chunk"));
            REQUIRE(fs.sync_directory("/"));

            std::vector<std::size_t> order;
            const std::size_t first = reverse == 0 ? 0 : 1;
            const std::size_t second = reverse == 0 ? 1 : 0;
            if ((mask & (1U << first)) != 0) {
                order.push_back(first);
            }
            if ((mask & (1U << second)) != 0) {
                order.push_back(second);
            }
            REQUIRE(fs.crash(order));

            const bool directory_persisted = (mask & 2U) != 0;
            const bool data_persisted = (mask & 1U) != 0;
            REQUIRE(fs.durable_exists("/chunk") == directory_persisted);
            if (directory_persisted) {
                const auto actual = fs.durable_read("/chunk").value();
                if (data_persisted) {
                    REQUIRE(actual == expected);
                } else {
                    REQUIRE(actual.empty());
                }
            }
        }
    }
}

}
