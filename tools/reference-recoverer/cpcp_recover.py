#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import stat
import struct
import sys
from pathlib import Path

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_state,
)
from nacl.pwhash import argon2id


class RecoverError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def integrity(message):
    raise RecoverError(4, message)


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def text(value):
    encoded = value.encode("utf-8")
    return u32(len(encoded)) + encoded


def blob(value):
    return u32(len(value)) + value


def kdf(master, purpose):
    contexts = {
        "chunk": b"chunk001",
        "snapshot": b"snap0001",
        "journal": b"jrnl0001",
        "id": b"idkey001",
        "config": b"conf0001",
        "cache": b"cach0001",
    }
    salt = u64(1) + bytes(8)
    personal = contexts[purpose] + bytes(8)
    return hashlib.blake2b(
        b"",
        key=master,
        salt=salt,
        person=personal,
        digest_size=32,
    ).digest()


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def xchacha_decrypt(key, nonce, aad, ciphertext):
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext,
            aad,
            nonce,
            key,
        )
    except Exception as error:
        raise RecoverError(4, "AEAD authentication failed") from error


def parse_json(data):
    if len(data) > 1024 * 1024:
        integrity("JSON value exceeds the size limit")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                integrity("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        integrity("non-finite JSON number")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except RecoverError:
        raise
    except Exception as error:
        integrity(f"invalid JSON: {error}")
    depth = 0
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            depth += 1
            if depth > 16:
                integrity("JSON nesting exceeds the limit")
            stack.extend(current.values())
        elif isinstance(current, list):
            depth += 1
            if depth > 16:
                integrity("JSON nesting exceeds the limit")
            stack.extend(current)
    return value


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        integrity("unexpected end of file")
    return data


def config_wrap_aad(config):
    slot = config["key_slots"][0]
    return (
        b"cpcp.master-key.v1"
        + bytes.fromhex(config["repository_uuid"])
        + u32(config["format_version"])
        + text(slot["id"])
        + text(slot["type"])
        + b"argon2id"
        + u64(int(config["kdf"]["memory_kib"]))
        + u64(int(config["kdf"]["iterations"]))
        + bytes.fromhex(slot["salt"])
    )


def config_auth_bytes(config):
    slot = config["key_slots"][0]
    wrapped = slot["wrapped_mk"]
    return (
        b"cpcp.config.v1"
        + u32(config["format_version"])
        + u64(int(config["revision"]))
        + bytes.fromhex(config["repository_uuid"])
        + bytes.fromhex(config["storage_epoch"])
        + u64(int(config["created_at"]["seconds"]))
        + u32(config["created_at"]["nanoseconds"])
        + u32(config["chunk_size"])
        + text(config["cipher_suite"])
        + text(config["hash_algorithm"])
        + b"argon2id"
        + u64(int(config["kdf"]["memory_kib"]))
        + u64(int(config["kdf"]["iterations"]))
        + text(slot["id"])
        + text(slot["type"])
        + bytes.fromhex(slot["salt"])
        + bytes.fromhex(wrapped["nonce"])
        + blob(bytes.fromhex(wrapped["ciphertext"]))
    )


def unlock_config(config, password):
    if config.get("magic") != "CPCP" or len(config.get("key_slots", [])) != 1:
        raise RecoverError(5, "invalid repository configuration")
    slot = config["key_slots"][0]
    if slot["type"] != "password":
        raise RecoverError(5, "unsupported key slot")
    salt = bytes.fromhex(slot["salt"])
    try:
        kek = argon2id.kdf(
            32,
            password,
            salt,
            opslimit=int(config["kdf"]["iterations"]),
            memlimit=int(config["kdf"]["memory_kib"]) * 1024,
        )
        master = xchacha_decrypt(
            kek,
            bytes.fromhex(slot["wrapped_mk"]["nonce"]),
            config_wrap_aad(config),
            bytes.fromhex(slot["wrapped_mk"]["ciphertext"]),
        )
    except RecoverError as error:
        raise RecoverError(5, "password or key-slot authentication failed") from error
    if len(master) != 32:
        raise RecoverError(5, "invalid master key length")
    expected = hmac_sha256(kdf(master, "config"), config_auth_bytes(config))
    if not hmac.compare_digest(expected, bytes.fromhex(config["authentication_tag"])):
        raise RecoverError(5, "configuration authentication failed")
    return master


def load_config(repository, password):
    candidates = []
    for name in ("cpcp.config.json", "cpcp.config.backup.json"):
        path = repository / name
        if not path.exists():
            continue
        try:
            config = parse_json(path.read_bytes())
            master = unlock_config(config, password)
            candidates.append((config, master))
        except RecoverError:
            continue
    if not candidates:
        raise RecoverError(5, "no configuration replica could be unlocked")
    candidates.sort(key=lambda item: int(item[0]["revision"]), reverse=True)
    config, master = candidates[0]
    return config, master, len(candidates) != 2


def summary_aad(context):
    return (
        b"cpcp.summary.v1"
        + context["repository_uuid"]
        + context["storage_epoch"]
        + context["snapshot_uuid"]
        + context["lineage_uuid"]
        + u64(context["generation"])
    )


def context_from_json(document):
    return {
        "repository_uuid": bytes.fromhex(document["repository_uuid"]),
        "storage_epoch": bytes.fromhex(document["storage_epoch"]),
        "snapshot_uuid": bytes.fromhex(document["snapshot_uuid"]),
        "lineage_uuid": bytes.fromhex(document["lineage_uuid"]),
        "generation": int(document["generation"]),
        "session_uuid": bytes.fromhex(document["session_uuid"]),
    }


def read_summary(repository, snapshot_key):
    summaries = []
    for path in (repository / "snapshots").glob("*.summary"):
        with path.open("rb") as stream:
            if read_exact(stream, 4) != b"CPSM":
                integrity("invalid summary magic")
            version = read_exact(stream, 4)
            if version != b"\x01\x00\x00\x00":
                integrity("unsupported summary version")
            context = {
                "repository_uuid": read_exact(stream, 16),
                "storage_epoch": read_exact(stream, 16),
                "snapshot_uuid": read_exact(stream, 16),
                "lineage_uuid": read_exact(stream, 16),
                "generation": struct.unpack("<Q", read_exact(stream, 8))[0],
                "session_uuid": read_exact(stream, 16),
            }
            nonce = read_exact(stream, 24)
            length = struct.unpack("<I", read_exact(stream, 4))[0]
            if length > 1024 * 1024:
                integrity("summary exceeds the size limit")
            ciphertext = read_exact(stream, length)
            if stream.read(1):
                integrity("summary has trailing data")
            document = parse_json(
                xchacha_decrypt(snapshot_key, nonce, summary_aad(context), ciphertext)
            )
            if document.get("schema") != "cpcp.snapshot-summary.v1":
                integrity("unsupported summary schema")
            if context_from_json(document) != context:
                integrity("summary header and payload context mismatch")
            main = path.with_suffix(".snap")
            if not main.exists() or main.stat().st_size != int(document["main"]["stored_length"]):
                integrity("snapshot main length mismatch")
            document["path"] = path
            document["main_path"] = main
            summaries.append(document)
    summaries.sort(key=lambda item: item["generation"])
    return summaries


def frame_aad(context, index, record_type):
    return (
        b"cpcp.snapshot.v1"
        + context["repository_uuid"]
        + context["storage_epoch"]
        + context["snapshot_uuid"]
        + context["lineage_uuid"]
        + u64(context["generation"])
        + u64(index)
        + bytes([record_type])
    )


class MainReader:
    def __init__(self, path, key, expected_context=None):
        self.path = path
        self.key = key
        self.file = path.open("rb")
        self.digest = hashlib.sha256()
        self.stored_length = 0
        self.index = 0
        self.done = False
        if read_exact(self.file, 6) != b"CPSN\x01\x00":
            integrity("invalid snapshot magic")
        self.digest.update(b"CPSN\x01\x00")
        self.stored_length += 6
        self.context = self.read_context()
        if expected_context is not None and self.context != expected_context:
            integrity("snapshot outer context mismatch")
        stream_header = read_exact(self.file, 24)
        self.digest.update(stream_header)
        self.stored_length += 24
        self.state = crypto_secretstream_xchacha20poly1305_state()
        crypto_secretstream_xchacha20poly1305_init_pull(
            self.state,
            stream_header,
            key,
        )

    def read_context(self):
        fields = {}
        for name in (
            "repository_uuid",
            "storage_epoch",
            "snapshot_uuid",
            "lineage_uuid",
        ):
            value = read_exact(self.file, 16)
            fields[name] = value
            self.digest.update(value)
            self.stored_length += 16
        fields["generation"] = struct.unpack("<Q", read_exact(self.file, 8))[0]
        self.digest.update(u64(fields["generation"]))
        self.stored_length += 8
        fields["session_uuid"] = read_exact(self.file, 16)
        self.digest.update(fields["session_uuid"])
        self.stored_length += 16
        return fields

    def next(self):
        if self.done:
            return None
        header = read_exact(self.file, 13)
        index, record_type, length = struct.unpack("<QBI", header)
        if length > 1024 * 1024 + 17:
            integrity("snapshot frame exceeds the size limit")
        ciphertext = read_exact(self.file, length)
        aad = frame_aad(self.context, index, record_type)
        try:
            plaintext, tag = crypto_secretstream_xchacha20poly1305_pull(
                self.state,
                ciphertext,
                aad,
            )
        except Exception as error:
            raise RecoverError(4, "snapshot frame authentication failed") from error
        if index != self.index:
            integrity("snapshot frame sequence mismatch")
        if record_type == 255 and tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            integrity("final record tag mismatch")
        if record_type != 255 and tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
            integrity("snapshot record tag mismatch")
        self.digest.update(header)
        self.digest.update(ciphertext)
        self.stored_length += 13 + length
        self.index += 1
        if record_type == 255:
            if self.file.read(1):
                integrity("snapshot has data after FINAL")
            self.done = True
        return record_type, plaintext

    def finish(self):
        if not self.done:
            integrity("snapshot is missing FINAL")
        return self.digest.digest(), self.stored_length


class FileIdentity:
    def __init__(self, key, file_length, chunk_count, chunk_size):
        expected = file_length // chunk_size + (file_length % chunk_size != 0)
        if expected != chunk_count:
            integrity("chunk count does not match file length")
        self.key = key
        self.file_length = file_length
        self.chunk_count = chunk_count
        self.chunk_size = chunk_size
        self.next_offset = 0
        self.seen = 0
        self.state = hmac.new(key, digestmod=hashlib.sha256)
        self.state.update(b"cpcp.file.v1" + u64(file_length) + u64(chunk_count))

    def append(self, descriptor):
        chunk_id, plain_length, stored_length = descriptor
        if plain_length == 0 or plain_length > self.chunk_size:
            integrity("invalid chunk length")
        if self.seen + 1 < self.chunk_count and plain_length != self.chunk_size:
            integrity("non-final chunk is not full")
        if plain_length > self.file_length - self.next_offset:
            integrity("chunk exceeds file length")
        self.state.update(chunk_id + u32(plain_length))
        self.next_offset += plain_length
        self.seen += 1

    def finish(self):
        if self.seen != self.chunk_count or self.next_offset != self.file_length:
            integrity("incomplete file continuation")
        return self.state.digest()


def chunk_path(repository, chunk_id):
    value = chunk_id.hex()
    return repository / "chunks" / value[:2] / value[2:4] / value


def read_chunk(repository, repository_uuid, key, id_key, descriptor):
    chunk_id, plain_length, stored_length = descriptor
    path = chunk_path(repository, chunk_id)
    if not path.is_file() or path.is_symlink() or path.stat().st_size != stored_length:
        integrity("chunk metadata mismatch")
    with path.open("rb") as stream:
        if read_exact(stream, 8) != b"CPCK\x01\x00\x00\x00":
            integrity("invalid chunk envelope")
        if struct.unpack("<Q", read_exact(stream, 8))[0] != plain_length:
            integrity("chunk plaintext length mismatch")
        nonce = read_exact(stream, 24)
        ciphertext = read_exact(stream, plain_length + 16)
        if stream.read(1):
            integrity("chunk has trailing data")
    aad = (
        b"cpcp.chunk.object.v1"
        + repository_uuid
        + chunk_id
        + u64(plain_length)
        + b"\x00\x00"
    )
    plaintext = xchacha_decrypt(key, nonce, aad, ciphertext)
    if hmac_sha256(id_key, b"cpcp.chunk.v1" + u64(len(plaintext)) + plaintext) != chunk_id:
        integrity("chunk content ID mismatch")
    return plaintext


def inspect_chunk(repository, descriptor):
    chunk_id, _, stored_length = descriptor
    path = chunk_path(repository, chunk_id)
    if not path.is_file() or path.is_symlink() or path.stat().st_size != stored_length:
        integrity("chunk metadata mismatch")


def validate_manifest(summary, snapshot_key, id_key, chunk_key, deep=False):
    reader = MainReader(summary["main_path"], snapshot_key, context_from_json(summary))
    current = None
    identity = None
    expected_batch = 0
    while True:
        record = reader.next()
        if record is None:
            break
        record_type, payload = record
        if record_type == 4:
            current = parse_json(payload)
            identity = FileIdentity(
                id_key,
                int(current["size"]),
                int(current["chunk_count"]),
                summary["chunk_size"],
            )
            expected_batch = 0
        elif record_type == 5:
            batch = parse_json(payload)
            if current is None or int(batch["file"]) != int(current["sequence"]) or int(batch["batch"]) != expected_batch:
                integrity("chunk batch sequence mismatch")
            expected_batch += 1
            for item in batch["chunks"]:
                descriptor = (
                    bytes.fromhex(item["id"]),
                    item["plain"],
                    int(item["stored"]),
                )
                identity.append(descriptor)
                if deep:
                    read_chunk(summary["repository"], bytes.fromhex(summary["repository_uuid"]), chunk_key, id_key, descriptor)
                else:
                    inspect_chunk(summary["repository"], descriptor)
        elif record_type == 6:
            end = parse_json(payload)
            if current is None or int(end["file"]) != int(current["sequence"]):
                integrity("file-end sequence mismatch")
            if int(end["chunk_count"]) != int(current["chunk_count"]):
                integrity("file-end chunk count mismatch")
            if end["file_id"] != current["file_id"] or identity.finish().hex() != current["file_id"]:
                integrity("file identity mismatch")
            current = None
            identity = None
        elif record_type == 255:
            final = parse_json(payload)
            if final["status"] != summary["status"] or final["stats"] != summary["stats"]:
                integrity("snapshot final summary mismatch")
    if current is not None:
        integrity("snapshot ends with an incomplete file")
    digest, stored_length = reader.finish()
    if digest.hex() != summary["main"]["digest"] or stored_length != int(summary["main"]["stored_length"]):
        integrity("snapshot main digest or length mismatch")


def safe_label(label):
    reserved = {"CON", "PRN", "AUX", "NUL"}
    return bool(label) and label not in {".", ".."} and label not in reserved and not any(value in label for value in "/\\:")


def safe_relative(path):
    parts = Path(path).parts
    return not Path(path).is_absolute() and ".." not in parts


def restore(summary, snapshot_key, id_key, chunk_key, destination):
    reader = MainReader(summary["main_path"], snapshot_key, context_from_json(summary))
    current = None
    identity = None
    output = None
    expected_batch = 0
    directories = []
    while True:
        record = reader.next()
        if record is None:
            break
        record_type, payload = record
        if record_type == 9:
            directory = parse_json(payload)
            root = next(root for root in summary["roots"] if root["index"] == directory["root"])
            if not safe_label(root["label"]) or not safe_relative(directory["path"]):
                integrity("unsafe restore path")
            target = destination / root["label"] / directory["path"]
            target.mkdir(parents=True, exist_ok=True)
            depth = len(Path(directory["path"]).parts) + 1 if directory["path"] else 1
            while len(directories) >= depth:
                path, mode, seconds, nanoseconds = directories.pop()
                os.chmod(path, mode & ~0o6000)
                os.utime(path, ns=(seconds * 1_000_000_000 + nanoseconds,) * 2)
            directories.append((target, directory["mode"], int(directory["mtime"]["seconds"]), directory["mtime"]["nanoseconds"]))
        elif record_type == 4:
            current = parse_json(payload)
            root = next(root for root in summary["roots"] if root["index"] == current["root"])
            if not current["path"] or not safe_label(root["label"]) or not safe_relative(current["path"]):
                integrity("unsafe file path")
            identity = FileIdentity(
                id_key,
                int(current["size"]),
                int(current["chunk_count"]),
                summary["chunk_size"],
            )
            expected_batch = 0
            target = destination / root["label"] / current["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            output = target.open("xb")
        elif record_type == 5:
            batch = parse_json(payload)
            if current is None or int(batch["file"]) != int(current["sequence"]) or int(batch["batch"]) != expected_batch:
                integrity("restore batch sequence mismatch")
            expected_batch += 1
            for item in batch["chunks"]:
                descriptor = (
                    bytes.fromhex(item["id"]),
                    item["plain"],
                    int(item["stored"]),
                )
                plaintext = read_chunk(summary["repository"], bytes.fromhex(summary["repository_uuid"]), chunk_key, id_key, descriptor)
                identity.append(descriptor)
                output.write(plaintext)
        elif record_type == 6:
            end = parse_json(payload)
            if current is None or int(end["file"]) != int(current["sequence"]):
                integrity("restore file-end mismatch")
            if int(end["chunk_count"]) != int(current["chunk_count"]):
                integrity("restore chunk count mismatch")
            if end["file_id"] != current["file_id"] or identity.finish().hex() != current["file_id"]:
                integrity("restored file identity mismatch")
            output.close()
            os.chmod(output.name, current["mode"] & ~0o6000)
            timestamp = int(current["mtime"]["seconds"]) * 1_000_000_000 + current["mtime"]["nanoseconds"]
            os.utime(output.name, ns=(timestamp, timestamp))
            current = None
            identity = None
            output = None
    if current is not None:
        integrity("restore ended with an incomplete file")
    while directories:
        path, mode, seconds, nanoseconds = directories.pop()
        os.chmod(path, mode & ~0o6000)
        os.utime(path, ns=(seconds * 1_000_000_000 + nanoseconds,) * 2)
    digest, stored_length = reader.finish()
    if digest.hex() != summary["main"]["digest"] or stored_length != int(summary["main"]["stored_length"]):
        integrity("restore digest mismatch")


def recover(repository, destination, password, generation=None):
    config, master, _ = load_config(repository, password)
    snapshot_key = kdf(master, "snapshot")
    id_key = kdf(master, "id")
    chunk_key = kdf(master, "chunk")
    summaries = read_summary(repository, snapshot_key)
    if not summaries:
        raise RecoverError(1, "no snapshots are available")
    summary = summaries[-1] if generation is None else next(
        (item for item in summaries if item["generation"] == generation),
        None,
    )
    if summary is None:
        raise RecoverError(1, "snapshot generation was not found")
    summary["repository"] = repository
    summary["chunk_size"] = config["chunk_size"]
    validate_manifest(summary, snapshot_key, id_key, chunk_key)
    destination.mkdir(parents=True, exist_ok=True)
    restore(summary, snapshot_key, id_key, chunk_key, destination)


def main():
    parser = argparse.ArgumentParser(description="Independent read-only cpcp recovery tool")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--to", required=True, type=Path)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--generation", type=int)
    args = parser.parse_args()
    try:
        password = args.password_file.read_bytes()
        if password.endswith(b"\n"):
            password = password[:-1]
        if password.endswith(b"\r"):
            password = password[:-1]
        if not password or len(password) > 1024 or b"\n" in password or b"\r" in password:
            raise RecoverError(2, "invalid password file")
        recover(args.repo, args.to, password, args.generation)
    except RecoverError as error:
        print(f"Error: {error}", file=sys.stderr)
        return error.code
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
