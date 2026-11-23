#include "storage/session_spool.hpp"

#include "domain/encoding.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <sodium.h>

namespace cpcp::storage {

using crypto::Bytes;
using crypto::RecordType;
using crypto::SnapshotFrame;
using domain::Error;
using domain::ErrorCode;

namespace {

constexpr std::size_t file_header_size = 6;
constexpr std::size_t frame_header_size = 13;

void append_u64(Bytes& output, std::uint64_t value) {
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_u32(Bytes& output, std::uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

std::uint64_t decode_u64(std::span<const std::byte> input) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(input[index]))
            << (index * 8);
    }
    return value;
}

std::uint32_t decode_u32(std::span<const std::byte> input) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned int>(input[index]))
            << (index * 8);
    }
    return value;
}

}

domain::Result<void> SessionSpoolWriter::create(
    const std::filesystem::path& path,
    const crypto::SecureKey& key,
    const crypto::SnapshotContext& context,
    crypto::StreamDomain domain
) {
    if (file_ || encoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool writer is already initialized"});
    }

    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    file_.emplace(std::move(file).value());
    encoder_.emplace(context, key, domain);

    const Bytes header{
        std::byte{'C'},
        domain == crypto::StreamDomain::snapshot ? std::byte{'N'} : std::byte{'P'},
        std::byte{'S'},
        std::byte{'P'},
        std::byte{1},
        std::byte{0},
    };
    auto result = file_->write_all(header);
    if (!result) {
        return result;
    }
    if (domain == crypto::StreamDomain::snapshot) {
        result = file_->write_all(context.repository_uuid);
        if (!result) {
            return result;
        }
        result = file_->write_all(context.storage_epoch);
        if (!result) {
            return result;
        }
        result = file_->write_all(context.snapshot_uuid);
        if (!result) {
            return result;
        }
        result = file_->write_all(context.lineage_uuid);
        if (!result) {
            return result;
        }
        Bytes generation;
        domain::append_le(generation, context.generation, 8);
        result = file_->write_all(generation);
        if (!result) {
            return result;
        }
        result = file_->write_all(context.session_uuid);
        if (!result) {
            return result;
        }
    }
    return file_->write_all(encoder_->header());
}

domain::Result<void> SessionSpoolWriter::write_frame(const SnapshotFrame& frame) {
    Bytes header;
    header.reserve(frame_header_size);
    append_u64(header, frame.index);
    header.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(frame.type)));
    append_u32(header, static_cast<std::uint32_t>(frame.ciphertext.size()));

    auto result = file_->write_all(header);
    if (!result) {
        return result;
    }
    return file_->write_all(frame.ciphertext);
}

domain::Result<void> SessionSpoolWriter::append(
    RecordType type,
    std::span<const std::byte> plaintext
) {
    if (!file_ || !encoder_ || finalized_) {
        return std::unexpected(Error{ErrorCode::usage, "spool writer is not available"});
    }
    auto frame = encoder_->push(type, plaintext);
    if (!frame) {
        return std::unexpected(frame.error());
    }
    return write_frame(*frame);
}

domain::Result<void> SessionSpoolWriter::finalize(std::span<const std::byte> summary) {
    auto result = append(RecordType::final_summary, summary);
    if (!result) {
        return result;
    }
    finalized_ = true;
    result = file_->flush();
    if (!result) {
        return result;
    }
    return file_->close();
}

bool SessionSpoolWriter::finalized() const {
    return finalized_;
}

domain::Result<void> SessionSpoolReader::open(
    const std::filesystem::path& path,
    const crypto::SecureKey& key,
    const crypto::SnapshotContext& context,
    crypto::StreamDomain domain
) {
    if (file_ || decoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool reader is already initialized"});
    }

    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    file_.emplace(std::move(file).value());
    if (crypto_hash_sha256_init(&digest_state_) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "spool digest initialization failed"});
    }

    std::array<std::byte, file_header_size> header{};
    auto result = read_tracked(header);
    if (!result) {
        return result;
    }
    const Bytes expected{
        std::byte{'C'},
        domain == crypto::StreamDomain::snapshot ? std::byte{'N'} : std::byte{'P'},
        std::byte{'S'},
        std::byte{'P'},
        std::byte{1},
        std::byte{0},
    };
    if (!std::ranges::equal(header, expected)) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid session spool header"});
    }

    std::array<std::byte, crypto::snapshot_header_size> stream_header{};
    if (domain == crypto::StreamDomain::snapshot) {
        crypto::SnapshotContext embedded;
        result = read_tracked(embedded.repository_uuid);
        if (!result) {
            return std::unexpected(result.error());
        }
        result = read_tracked(embedded.storage_epoch);
        if (!result) {
            return std::unexpected(result.error());
        }
        result = read_tracked(embedded.snapshot_uuid);
        if (!result) {
            return std::unexpected(result.error());
        }
        result = read_tracked(embedded.lineage_uuid);
        if (!result) {
            return std::unexpected(result.error());
        }
        std::array<std::byte, 8> generation{};
        result = read_tracked(generation);
        if (!result) {
            return std::unexpected(result.error());
        }
        embedded.generation = domain::read_le(generation, 8).value();
        result = read_tracked(embedded.session_uuid);
        if (!result) {
            return std::unexpected(result.error());
        }
        const bool empty_context = std::ranges::all_of(context.repository_uuid, [](std::byte value) {
            return value == std::byte{0};
        });
        if (!empty_context && embedded != context) {
            return std::unexpected(Error{ErrorCode::integrity, "snapshot header context mismatch"});
        }
        context_ = embedded;
    } else {
        context_ = context;
    }
    result = read_tracked(stream_header);
    if (!result) {
        return result;
    }
    decoder_.emplace(context_, key, stream_header, domain);
    return {};
}

domain::Result<void> SessionSpoolReader::read_tracked(std::span<std::byte> output) {
    auto result = file_->read_exact(output);
    if (result) {
        update_digest(output);
        stored_length_ += output.size();
    }
    return result;
}

void SessionSpoolReader::update_digest(std::span<const std::byte> bytes) {
    crypto_hash_sha256_update(
        &digest_state_,
        reinterpret_cast<const unsigned char*>(bytes.data()),
        static_cast<unsigned long long>(bytes.size())
    );
}

domain::Result<std::optional<SpoolRecord>> SessionSpoolReader::next() {
    if (!file_ || !decoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool reader is not initialized"});
    }
    if (done_) {
        return std::optional<SpoolRecord>{};
    }

    std::array<std::byte, frame_header_size> header{};
    auto result = read_tracked(header);
    if (!result) {
        return std::unexpected(result.error());
    }
    const std::uint64_t index = decode_u64(std::span(header).first(8));
    const auto type = static_cast<RecordType>(std::to_integer<std::uint8_t>(header[8]));
    const std::uint32_t length = decode_u32(std::span(header).subspan(9, 4));
    if (length < crypto_secretstream_xchacha20poly1305_ABYTES
        || length > crypto::snapshot_frame_limit + crypto_secretstream_xchacha20poly1305_ABYTES) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid spool frame length"});
    }

    Bytes ciphertext(length);
    result = read_tracked(ciphertext);
    if (!result) {
        return std::unexpected(result.error());
    }
    const SnapshotFrame frame{index, type, ciphertext};
    auto plaintext = decoder_->pull(frame);
    if (!plaintext) {
        return std::unexpected(plaintext.error());
    }

    if (type == RecordType::final_summary) {
        std::array<std::byte, 1> trailing{};
        const auto trailing_size = file_->read_some(trailing);
        if (!trailing_size) {
            return std::unexpected(trailing_size.error());
        }
        if (*trailing_size != 0) {
            return std::unexpected(Error{ErrorCode::integrity, "spool contains data after FINAL"});
        }
        done_ = true;
    }
    return std::optional<SpoolRecord>{
        SpoolRecord{type, std::move(plaintext).value()},
    };
}

domain::Result<void> SessionSpoolReader::finish() const {
    if (!decoder_ || !done_) {
        return std::unexpected(Error{ErrorCode::integrity, "spool is missing FINAL"});
    }
    return decoder_->finish();
}

domain::Result<crypto::Digest> SessionSpoolReader::ciphertext_digest() const {
    if (!done_) {
        return std::unexpected(Error{ErrorCode::usage, "spool digest requires FINAL"});
    }
    crypto_hash_sha256_state state = digest_state_;
    crypto::Digest digest;
    if (crypto_hash_sha256_final(&state, reinterpret_cast<unsigned char*>(digest.data())) != 0) {
        return std::unexpected(Error{ErrorCode::internal, "spool digest finalization failed"});
    }
    return digest;
}

std::uint64_t SessionSpoolReader::stored_length() const {
    return stored_length_;
}

const crypto::SnapshotContext& SessionSpoolReader::context() const {
    return context_;
}

}
