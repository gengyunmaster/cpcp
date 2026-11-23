#include "crypto/aead.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>

namespace {

using cpcp::crypto::Bytes;
using cpcp::crypto::SealedObject;
using cpcp::crypto::SecureKey;

SecureKey test_key() {
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>(index);
    }
    return SecureKey::from_bytes(bytes).value();
}

Bytes bytes(const std::string& text) {
    Bytes result;
    for (const char value : text) {
        result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

Bytes from_hex(const std::string& text) {
    Bytes result;
    for (std::size_t index = 0; index < text.size(); index += 2) {
        result.push_back(static_cast<std::byte>(std::stoul(text.substr(index, 2), nullptr, 16)));
    }
    return result;
}

TEST_CASE("single object decryption matches an independent PyNaCl vector") {
    SealedObject object;
    for (std::size_t index = 0; index < object.nonce.size(); ++index) {
        object.nonce[index] = static_cast<std::byte>(index);
    }
    object.ciphertext = from_hex("f6a76313ff339409fedcbd0044b1fc36a2669517b5");

    const auto plaintext = cpcp::crypto::open_object(
        test_key(),
        bytes("cpcp.test.aad"),
        object
    );

    REQUIRE(plaintext.value() == bytes("hello"));
}

TEST_CASE("single object round trip rejects wrong AAD and tampering") {
    const auto key = test_key();
    const auto aad = bytes("cpcp.chunk.v1");
    const auto sealed = cpcp::crypto::seal_object(key, aad, bytes("payload")).value();

    const auto opened = cpcp::crypto::open_object(key, aad, sealed);
    REQUIRE(opened.value() == bytes("payload"));
    REQUIRE_FALSE(cpcp::crypto::open_object(key, bytes("wrong"), sealed));

    auto tampered = sealed;
    tampered.ciphertext.front() ^= std::byte{1};
    const auto result = cpcp::crypto::open_object(key, aad, tampered);
    REQUIRE_FALSE(result);
    REQUIRE(result.error().code == cpcp::domain::ErrorCode::integrity);
}

TEST_CASE("ciphertext digest uses SHA-256") {
    const auto digest = cpcp::crypto::compute_ciphertext_digest(bytes("abc")).value();

    REQUIRE(
        cpcp::crypto::to_hex(digest)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

}
