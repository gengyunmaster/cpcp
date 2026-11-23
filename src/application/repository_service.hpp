#pragma once

#include "crypto/secret.hpp"
#include "domain/result.hpp"
#include "repository/config.hpp"

#include <filesystem>

namespace cpcp::application {

domain::Result<domain::Uuid> initialize_repository(
    const std::filesystem::path& directory,
    const crypto::SecretBytes& password,
    const repository::ConfigOptions& options
);

}
