#include "storage/simulated_filesystem.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace {

using cpcp::domain::ErrorCode;
using cpcp::storage::SimulatedFilesystem;
using cpcp::storage::SimulatedOperation;

SimulatedFilesystem::Bytes bytes(const std::string& text) {
    SimulatedFilesystem::Bytes result;
    result.reserve(text.size());
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

TEST_CASE("crash can persist a directory entry without file data") {
    SimulatedFilesystem fs;
    const auto payload = bytes("verified payload");
    REQUIRE(fs.write_file("/tmp.part", payload));
    REQUIRE(fs.sync_file("/tmp.part"));
    REQUIRE(fs.publish_no_replace("/tmp.part", "/chunk"));
    REQUIRE(fs.sync_directory("/"));
    REQUIRE(fs.pending_operation_count() == 2);

    const std::size_t order[] = {1};
    REQUIRE(fs.crash(order));

    REQUIRE(fs.durable_exists("/chunk"));
    REQUIRE(fs.durable_read("/chunk")->empty());
}

TEST_CASE("file sync follows node identity across publication") {
    SimulatedFilesystem fs;
    const auto payload = bytes("verified payload");
    REQUIRE(fs.write_file("/tmp.part", payload));
    REQUIRE(fs.sync_file("/tmp.part"));
    REQUIRE(fs.publish_no_replace("/tmp.part", "/chunk"));
    REQUIRE(fs.sync_directory("/"));

    const std::size_t order[] = {1, 0};
    REQUIRE(fs.crash(order));

    REQUIRE(fs.durable_read("/chunk").value() == payload);
}

TEST_CASE("clean shutdown persists data and directory entries") {
    SimulatedFilesystem fs;
    const auto payload = bytes("verified payload");
    REQUIRE(fs.write_file("/tmp.part", payload));
    REQUIRE(fs.sync_file("/tmp.part"));
    REQUIRE(fs.publish_no_replace("/tmp.part", "/chunk"));
    REQUIRE(fs.sync_directory("/"));

    REQUIRE(fs.clean_shutdown());

    REQUIRE(fs.durable_read("/chunk").value() == payload);
    REQUIRE(fs.read_file("/chunk").value() == payload);
}

TEST_CASE("a crash without pending persistence loses unpublished names") {
    SimulatedFilesystem fs;
    REQUIRE(fs.write_file("/tmp.part", bytes("payload")));
    REQUIRE(fs.sync_file("/tmp.part"));
    REQUIRE(fs.publish_no_replace("/tmp.part", "/chunk"));
    REQUIRE(fs.sync_directory("/"));

    REQUIRE(fs.crash());

    REQUIRE_FALSE(fs.durable_exists("/chunk"));
    REQUIRE_FALSE(fs.volatile_exists("/chunk"));
}

TEST_CASE("injected write failure leaves an explicit torn prefix") {
    SimulatedFilesystem fs;
    fs.inject_failure(
        SimulatedOperation::write_file,
        ErrorCode::retryable_io,
        1,
        3
    );

    const auto result = fs.write_file("/tmp.part", bytes("abcdef"));

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == ErrorCode::retryable_io);
    REQUIRE(fs.read_file("/tmp.part").value() == bytes("abc"));
}

TEST_CASE("publication never replaces an existing destination") {
    SimulatedFilesystem fs;
    REQUIRE(fs.write_file("/chunk", bytes("old")));
    REQUIRE(fs.write_file("/tmp.part", bytes("new")));

    const auto result = fs.publish_no_replace("/tmp.part", "/chunk");

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == ErrorCode::conflict);
    REQUIRE(fs.read_file("/chunk").value() == bytes("old"));
}

TEST_CASE("seeded random failure schedules are reproducible") {
    SimulatedFilesystem first;
    SimulatedFilesystem second;
    first.enable_random_failures(SimulatedOperation::write_file, 0.5, 9173);
    second.enable_random_failures(SimulatedOperation::write_file, 0.5, 9173);
    std::vector<bool> first_results;
    std::vector<bool> second_results;

    for (int index = 0; index < 32; ++index) {
        const auto path = "/file-" + std::to_string(index);
        first_results.push_back(first.write_file(path, bytes("x")).has_value());
        second_results.push_back(second.write_file(path, bytes("x")).has_value());
    }

    REQUIRE(first_results == second_results);
}

TEST_CASE("crash rejects duplicate persistence operations") {
    SimulatedFilesystem fs;
    REQUIRE(fs.write_file("/tmp.part", bytes("payload")));
    REQUIRE(fs.sync_file("/tmp.part"));
    const std::size_t duplicate[] = {0, 0};

    const auto result = fs.crash(duplicate);

    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == ErrorCode::usage);
    REQUIRE(fs.pending_operation_count() == 1);
}

}
