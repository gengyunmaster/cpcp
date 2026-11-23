#include "storage/session_spool.hpp"

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
    const crypto::SnapshotContext& context
) {
    if (file_ || encoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool writer is already initialized"});
    }

    auto file = platform::BinaryFile::create_new(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    file_.emplace(std::move(file).value());
    encoder_.emplace(context, key, crypto::StreamDomain::session_spool);

    const Bytes header{
        std::byte{'C'},
        std::byte{'P'},
        std::byte{'S'},
        std::byte{'P'},
        std::byte{1},
        std::byte{0},
    };
    auto result = file_->write_all(header);
    if (!result) {
        return result;
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
    const crypto::SnapshotContext& context
) {
    if (file_ || decoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool reader is already initialized"});
    }

    auto file = platform::BinaryFile::open_read(path);
    if (!file) {
        return std::unexpected(file.error());
    }
    file_.emplace(std::move(file).value());

    std::array<std::byte, file_header_size> header{};
    auto result = file_->read_exact(header);
    if (!result) {
        return result;
    }
    const Bytes expected{
        std::byte{'C'},
        std::byte{'P'},
        std::byte{'S'},
        std::byte{'P'},
        std::byte{1},
        std::byte{0},
    };
    if (!std::ranges::equal(header, expected)) {
        return std::unexpected(Error{ErrorCode::integrity, "invalid session spool header"});
    }

    std::array<std::byte, crypto::snapshot_header_size> stream_header{};
    result = file_->read_exact(stream_header);
    if (!result) {
        return result;
    }
    decoder_.emplace(context, key, stream_header, crypto::StreamDomain::session_spool);
    return {};
}

domain::Result<std::optional<SpoolRecord>> SessionSpoolReader::next() {
    if (!file_ || !decoder_) {
        return std::unexpected(Error{ErrorCode::usage, "spool reader is not initialized"});
    }
    if (done_) {
        return std::optional<SpoolRecord>{};
    }

    std::array<std::byte, frame_header_size> header{};
    auto result = file_->read_exact(header);
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
    result = file_->read_exact(ciphertext);
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

}
