#pragma once

#include "crypto/secret.hpp"
#include "domain/result.hpp"

#include <filesystem>
#include <optional>

namespace cpcp::application {

domain::Result<crypto::SecretBytes> read_password(
    const std::optional<std::filesystem::path>& password_file,
    bool allow_prompt
);

}
