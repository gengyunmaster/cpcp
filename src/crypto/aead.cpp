#include "crypto/aead.hpp"

#include <sodium.h>

namespace cpcp::crypto {

using domain::Error;
using domain::ErrorCode;

domain::Result<SealedObject> seal_object(
    const SecureKey& key,
    std::span<const std::byte> aad,
    std::span<const std::byte> plaintext
) {
    SealedObject object;
    randombytes_buf(object.nonce.data(), object.nonce.size());
    object.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_size = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(object.ciphertext.data()),
            &ciphertext_size,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<unsigned long long>(plaintext.size()),
            reinterpret_cast<const unsigned char*>(aad.data()),
            static_cast<unsigned long long>(aad.size()),
            nullptr,
            reinterpret_cast<const unsigned char*>(object.nonce.data()),
            reinterpret_cast<const unsigned char*>(key.bytes().data())
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "authenticated encryption failed"});
    }
    object.ciphertext.resize(static_cast<std::size_t>(ciphertext_size));
    return object;
}

domain::Result<Bytes> open_object(
    const SecureKey& key,
    std::span<const std::byte> aad,
    const SealedObject& object
) {
    if (object.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::unexpected(Error{ErrorCode::integrity, "ciphertext is shorter than its tag"});
    }

    Bytes plaintext(object.ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_size = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(plaintext.data()),
            &plaintext_size,
            nullptr,
            reinterpret_cast<const unsigned char*>(object.ciphertext.data()),
            static_cast<unsigned long long>(object.ciphertext.size()),
            reinterpret_cast<const unsigned char*>(aad.data()),
            static_cast<unsigned long long>(aad.size()),
            reinterpret_cast<const unsigned char*>(object.nonce.data()),
            reinterpret_cast<const unsigned char*>(key.bytes().data())
        ) != 0) {
        if (!plaintext.empty()) {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        return std::unexpected(Error{ErrorCode::integrity, "object authentication failed"});
    }
    plaintext.resize(static_cast<std::size_t>(plaintext_size));
    return plaintext;
}

domain::Result<Digest> compute_ciphertext_digest(std::span<const std::byte> bytes) {
    Digest digest;
    if (crypto_hash_sha256(
            reinterpret_cast<unsigned char*>(digest.data()),
            reinterpret_cast<const unsigned char*>(bytes.data()),
            static_cast<unsigned long long>(bytes.size())
        ) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "ciphertext digest failed"});
    }
    return digest;
}

}
