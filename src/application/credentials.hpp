#pragma once

#include "crypto/secret.hpp"
#include "domain/result.hpp"

#include <filesystem>
#include <optional>
#include <string_view>

namespace cpcp::application {

domain::Result<crypto::SecretBytes> read_password(
    const std::optional<std::filesystem::path>& password_file,
    bool allow_prompt
);
domain::Result<crypto::SecretBytes> read_password_prompt(
    const std::optional<std::filesystem::path>& password_file,
    bool allow_prompt,
    std::string_view prompt
);

}
