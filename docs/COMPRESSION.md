# cpcp Compression Formats

> Status: Implemented zstd chunk envelopes v2 and compressed snapshot batches

## 1. Chunk envelope v2

Version 1 objects remain readable and are never rewritten. New objects use this envelope:

```text
"CPCK"[4]
version_u16_le = 2
content_encoding_u16_le: 0 = none, 1 = zstd
plaintext_length_u64_le
encoded_length_u64_le
nonce[24]
ciphertext[encoded_length + 16]
```

The stored length is `64 + encoded_length`. AAD is:

```text
"cpcp.chunk.object.v2" || repository_uuid || chunk_id
|| plaintext_length_u64_le || content_encoding_u16_le || encoded_length_u64_le
```

zstd uses compression level 3 and is selected only when it is smaller than the original bytes. Otherwise encoding `none` is used. Decryption authenticates before decompression. Decompression is bounded by the authenticated expected plaintext length and is followed by plaintext-length and content-ID verification.

Chunk descriptors in snapshot batches add numeric `version` and `encoding` fields. Older descriptors without them mean version 1 and encoding 0. Mixed v1/v2 repositories are supported for deduplication, validation, restore, and cache evidence.

## 2. Compressed snapshot batches

Chunk-batch records may carry this plaintext payload inside their existing secretstream frames:

```text
"CPZ1"[4]
plaintext_length_u32_le
zstd_compressed_json[]
```

The record type, frame index, snapshot/session context, and other AAD semantics do not change. The compressed envelope is used only when smaller than the original JSON. Its decompressed JSON is limited to 1,048,576 bytes. Authentication succeeds before decompression; decoded records retain their original record type and strict JSON validation.

Older readers that do not support `CPZ1` reject it as an invalid record rather than silently interpreting it as another schema. Session descriptor spools and main snapshots share this encoding.

## 3. Independent recovery and validation

The locked C++ dependency is vcpkg `zstd`; the locked independent-reader dependency is Python `zstandard`. Tests cover compressed round trips, mixed-version metadata, content-ID validation, deep verification, cache evidence, resume, and independent Python restoration of C++-written repositories.
