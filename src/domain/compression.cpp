#include "domain/compression.hpp"

#include <zstd.h>

namespace cpcp::domain {

Result<Bytes> compress_zstd(std::span<const std::byte> input) {
    const auto bound = ZSTD_compressBound(input.size());
    Bytes output(bound);
    const auto compressed = ZSTD_compress(
        output.data(),
        output.size(),
        input.data(),
        input.size(),
        3
    );
    if (ZSTD_isError(compressed) != 0) {
        return fail<Bytes>(ErrorCode::internal, ZSTD_getErrorName(compressed));
    }
    output.resize(compressed);
    return output;
}

Result<Bytes> decompress_zstd(std::span<const std::byte> input, std::size_t expected_size) {
    Bytes output(expected_size);
    const auto decompressed = ZSTD_decompress(
        output.data(),
        output.size(),
        input.data(),
        input.size()
    );
    if (ZSTD_isError(decompressed) != 0 || decompressed != expected_size) {
        return fail<Bytes>(ErrorCode::integrity, "invalid zstd payload or decompressed length");
    }
    return output;
}

}
