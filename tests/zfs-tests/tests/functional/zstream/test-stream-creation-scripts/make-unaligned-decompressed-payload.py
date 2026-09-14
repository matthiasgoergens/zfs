#!/usr/bin/env python3
"""Derive the unaligned decompression fixture from its exact source."""

#
# SPDX-License-Identifier: CDDL-1.0
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# https://opensource.org/license/CDDL-1.0.
#

import bz2
import hashlib
import struct
from pathlib import Path

HEADER_SIZE = 312
CHECKSUM_OFFSET = 280
UINT64_MASK = (1 << 64) - 1
SOURCE_SHA256 = (
    "60d55a501d08fc6b01cb38f67b485fcdc500246ca4450fd4425a697798d417b8"
)

DRR_OBJECT_NUMBER_OFFSET = 8
DRR_OBJECT_BONUS_SIZE_OFFSET = 28
DRR_OBJECT_RAW_BONUS_SIZE_OFFSET = 36
DRR_WRITE_LOGICAL_SIZE_OFFSET = 32
DRR_WRITE_COMPRESSION_TYPE_OFFSET = 50
DRR_WRITE_COMPRESSED_SIZE_OFFSET = 96
DRR_WRITE_EMBEDDED_SIZE_OFFSET = 52
DRR_END_CHECKSUM_OFFSET = 8

DRR_BEGIN = 0
DRR_OBJECT = 1
DRR_WRITE = 3
DRR_END = 5
DRR_WRITE_EMBEDDED = 8


def fletcher4(data, state):
    """Extend a native-endian Fletcher-4 checksum."""
    if len(data) % 4 != 0:
        raise ValueError("Fletcher-4 input is not 32-bit aligned")

    a, b, c, d = state
    for (word,) in struct.iter_unpack("<I", data):
        a = (a + word) & UINT64_MASK
        b = (b + a) & UINT64_MASK
        c = (c + b) & UINT64_MASK
        d = (d + c) & UINT64_MASK
    return a, b, c, d


def payload_size(header):
    """Return the payload size of a little-endian replay record."""
    record_type = struct.unpack_from("<I", header)[0]

    if record_type == DRR_BEGIN:
        return struct.unpack_from("<I", header, 4)[0]
    if record_type == DRR_OBJECT:
        bonus_size = struct.unpack_from(
            "<I", header, DRR_OBJECT_BONUS_SIZE_OFFSET
        )[0]
        raw_bonus_size = struct.unpack_from(
            "<I", header, DRR_OBJECT_RAW_BONUS_SIZE_OFFSET
        )[0]
        if raw_bonus_size != 0:
            return raw_bonus_size
        return (bonus_size + 7) & ~7
    if record_type == DRR_WRITE:
        compressed = header[DRR_WRITE_COMPRESSION_TYPE_OFFSET] != 0
        size_offset = (
            DRR_WRITE_COMPRESSED_SIZE_OFFSET
            if compressed
            else DRR_WRITE_LOGICAL_SIZE_OFFSET
        )
        return struct.unpack_from("<Q", header, size_offset)[0]
    if record_type == DRR_WRITE_EMBEDDED:
        size = struct.unpack_from(
            "<I", header, DRR_WRITE_EMBEDDED_SIZE_OFFSET
        )[0]
        return (size + 7) & ~7
    return 0


def replacement_payload(size):
    """Return aligned LZ4 input which expands to 4,097 zero bytes."""
    encoded = (
        bytes.fromhex("0000001a1f000100")
        + b"\xff" * 15
        + bytes.fromhex("f7500000000000")
    )
    if len(encoded) > size:
        raise ValueError("replacement payload does not fit")
    return encoded + bytes(size - len(encoded))


def rewrite_stream(source):
    """Rewrite object 2 and regenerate the stream's rolling checksums."""
    output = bytearray()
    checksum = (0, 0, 0, 0)
    offset = 0
    replacements = 0

    while offset < len(source):
        header = bytearray(source[offset:offset + HEADER_SIZE])
        if len(header) != HEADER_SIZE:
            raise ValueError(f"short record header at offset {offset}")

        record_type = struct.unpack_from("<I", header)[0]
        size = payload_size(header)
        payload_start = offset + HEADER_SIZE
        payload = bytearray(source[payload_start:payload_start + size])
        if len(payload) != size:
            raise ValueError(f"short payload at offset {payload_start}")

        object_number = struct.unpack_from(
            "<Q", header, DRR_OBJECT_NUMBER_OFFSET
        )[0]
        if record_type == DRR_WRITE and object_number == 2:
            if replacements != 0:
                raise ValueError("multiple object 2 WRITE records")
            if size != 4096:
                raise ValueError("unexpected object 2 payload size")

            # drr_logical_size and drr_compressiontype, respectively.
            struct.pack_into(
                "<Q", header, DRR_WRITE_LOGICAL_SIZE_OFFSET, 4097
            )
            header[DRR_WRITE_COMPRESSION_TYPE_OFFSET] = 15
            payload = bytearray(replacement_payload(size))
            replacements += 1

        if record_type == DRR_BEGIN:
            checksum = (0, 0, 0, 0)
        elif record_type == DRR_END:
            checksum_end = DRR_END_CHECKSUM_OFFSET + 32
            header[DRR_END_CHECKSUM_OFFSET:checksum_end] = struct.pack(
                "<QQQQ", *checksum
            )

        checksum = fletcher4(header[:CHECKSUM_OFFSET], checksum)
        if record_type != DRR_BEGIN:
            header[CHECKSUM_OFFSET:] = struct.pack("<QQQQ", *checksum)

        if record_type == DRR_END:
            checksum = (0, 0, 0, 0)
        else:
            checksum = fletcher4(header[CHECKSUM_OFFSET:], checksum)
            checksum = fletcher4(payload, checksum)

        output.extend(header)
        output.extend(payload)
        offset = payload_start + size

    if replacements != 1:
        raise ValueError(f"expected one object 2 WRITE, found {replacements}")
    return bytes(output)


def main():
    zstream_dir = Path(__file__).resolve().parent.parent
    source_path = zstream_dir / "decompress.zsend.bz2"
    output_path = zstream_dir / "unaligned-decompressed-payload.zsend.bz2"

    source_compressed = source_path.read_bytes()
    source_hash = hashlib.sha256(source_compressed).hexdigest()
    if source_hash != SOURCE_SHA256:
        raise ValueError(
            f"unexpected {source_path.name} SHA-256: {source_hash}"
        )

    source = bz2.decompress(source_compressed)
    output = bz2.compress(rewrite_stream(source), compresslevel=9)
    output_path.write_bytes(output)
    print(output_path)


if __name__ == "__main__":
    main()
