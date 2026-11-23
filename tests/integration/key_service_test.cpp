#include "application/backup_service.hpp"
#include "application/inspection_service.hpp"
#include "application/key_service.hpp"
#include "application/repository_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

cpcp::crypto::SecretBytes secret(const std::string& text) {
    cpcp::domain::Bytes bytes;
    for (const char value : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return cpcp::crypto::SecretBytes::copy(bytes).value();
}

TEST_CASE("password and recovery slots preserve the repository master key") {
    const auto root = std::filesystem::path(CPCP_TEST_TEMP_DIR) / "key-service-test";
    std::filesystem::remove_all(root);
    const auto repository = root / "repo";
    const auto source = root / "source";
    std::filesystem::create_directories(source);
    {
        std::ofstream output(source / "a.txt");
        output << "hello";
    }
    cpcp::repository::ConfigOptions config;
    config.kdf = {8192, 1};
    config.chunk_size = 1024 * 1024;
    REQUIRE(cpcp::application::initialize_repository(repository, secret("first"), config));
    REQUIRE(cpcp::application::backup_add(repository, secret("first"), {source}, {}));

    REQUIRE(cpcp::application::change_password(repository, secret("first"), secret("second")));
    REQUIRE_FALSE(cpcp::repository::load_config(repository, secret("first")));
    const auto second = cpcp::repository::load_config(repository, secret("second")).value();
    REQUIRE(second.authenticated_slot == "password-1");
    REQUIRE(second.config.key_slots.size() == 1);
    REQUIRE(second.config.revision == 2);

    REQUIRE(cpcp::application::add_password(repository, secret("second"), secret("third"), "password-2").value() == "password-2");
    REQUIRE(cpcp::repository::load_config(repository, secret("second")));
    REQUIRE(cpcp::repository::load_config(repository, secret("third")));
    auto recovery = cpcp::application::add_recovery_key(repository, secret("second")).value();
    REQUIRE(recovery.key.size() == cpcp::crypto::key_size);
    REQUIRE(cpcp::repository::load_config(repository, recovery.key));

    const auto slots = cpcp::application::list_key_slots(repository, secret("second")).value();
    REQUIRE(slots.size() == 3);
    REQUIRE(slots[0].type == "password");
    REQUIRE(slots[1].type == "password");
    REQUIRE(slots[2].type == "recovery");

    REQUIRE(cpcp::application::change_password(repository, secret("second"), secret("fourth")));
    REQUIRE_FALSE(cpcp::repository::load_config(repository, secret("second")));
    REQUIRE(cpcp::repository::load_config(repository, secret("third")));
    REQUIRE(cpcp::repository::load_config(repository, recovery.key));
    REQUIRE_FALSE(cpcp::application::remove_key_slot(repository, recovery.key, recovery.slot_id, true));
    REQUIRE(cpcp::application::remove_key_slot(repository, secret("fourth"), "password-2", true));
    REQUIRE_FALSE(cpcp::repository::load_config(repository, secret("third")));
    REQUIRE(cpcp::application::remove_key_slot(repository, secret("fourth"), recovery.slot_id, true));
    REQUIRE_FALSE(cpcp::repository::load_config(repository, recovery.key));
    REQUIRE(cpcp::application::verify_repository(
        repository,
        secret("fourth"),
        cpcp::application::VerifyOptions{true, false}
    ));

    const auto before = cpcp::repository::load_config(repository, secret("fourth")).value();
    const auto epoch = cpcp::application::rotate_storage_epoch(repository, secret("fourth")).value();
    REQUIRE(epoch != before.config.storage_epoch);
    const auto after = cpcp::repository::load_config(repository, secret("fourth")).value();
    REQUIRE(after.config.storage_epoch == epoch);
    REQUIRE(after.config.repository_uuid == before.config.repository_uuid);
    REQUIRE(after.config.revision == before.config.revision + 1);
    REQUIRE(cpcp::application::verify_repository(
        repository,
        secret("fourth"),
        cpcp::application::VerifyOptions{true, false}
    ));
    std::filesystem::remove_all(root);
}

}
