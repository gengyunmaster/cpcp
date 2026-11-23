#!/usr/bin/env python3

import hashlib
import hmac
import struct

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)

KEY = bytes(range(32))


def chunk_id(data: bytes) -> bytes:
    payload = b"cpcp.chunk.v1" + struct.pack("<Q", len(data)) + data
    return hmac.new(KEY, payload, hashlib.sha256).digest()


def main() -> None:
    hello = chunk_id(b"hello")
    world = chunk_id(b"world")
    assert hello.hex() == "1d2ad3fb87be975582421b6449e6a4d7941c6ef4afd13ef46d68a9aadcde25ce"
    assert world.hex() == "4a0157b363763d273f1068b949d1c3876b44d14e3bbe2236ce8bfb6a717fb688"
    file_payload = (
        b"cpcp.file.v1"
        + struct.pack("<QQ", 10, 2)
        + hello
        + struct.pack("<I", 5)
        + world
        + struct.pack("<I", 5)
    )
    assert hmac.new(KEY, file_payload, hashlib.sha256).hexdigest() == (
        "e7a49e51fb17276070548aec8d9a0bd46e6568e0b4a88e78aa6ec07685bc278b"
    )

    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        b"hello",
        b"cpcp.test.aad",
        bytes(range(24)),
        KEY,
    )
    assert ciphertext.hex() == "f6a76313ff339409fedcbd0044b1fc36a2669517b5"

    encoder = crypto_secretstream_xchacha20poly1305_state()
    header = crypto_secretstream_xchacha20poly1305_init_push(encoder, KEY)
    aad = b"cpcp.snapshot.v1" + struct.pack("<Q", 0) + b"\x01"
    message_ciphertext = crypto_secretstream_xchacha20poly1305_push(
        encoder,
        b"frame-zero",
        aad,
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    )
    final_aad = b"cpcp.snapshot.v1" + struct.pack("<Q", 1) + b"\xff"
    final_ciphertext = crypto_secretstream_xchacha20poly1305_push(
        encoder,
        b"final",
        final_aad,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    )

    decoder = crypto_secretstream_xchacha20poly1305_state()
    crypto_secretstream_xchacha20poly1305_init_pull(decoder, header, KEY)
    message, tag = crypto_secretstream_xchacha20poly1305_pull(
        decoder,
        message_ciphertext,
        aad,
    )
    assert message == b"frame-zero"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    message, tag = crypto_secretstream_xchacha20poly1305_pull(
        decoder,
        final_ciphertext,
        final_aad,
    )
    assert message == b"final"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL

    decoder = crypto_secretstream_xchacha20poly1305_state()
    crypto_secretstream_xchacha20poly1305_init_pull(decoder, header, KEY)
    try:
        crypto_secretstream_xchacha20poly1305_pull(
            decoder,
            message_ciphertext,
            b"wrong-aad",
        )
    except Exception:
        pass
    else:
        raise AssertionError("wrong AAD was accepted")

    print("Independent content-ID, AEAD, and secretstream vectors passed")


if __name__ == "__main__":
    main()
