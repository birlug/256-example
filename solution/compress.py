import struct
import sys
from pathlib import Path

from .codec import lz, varint
from .file_format import MAGIC, Chunk, parse_chunks, unwrap_input
from .generate import Parm
from .reconstruct import MODE_RAW, Rec, raw_fallback, reconstruct, try_crack
from .transform import invert


def compress_chunk(chunk: Chunk, idx: int, logical: bytes, parm: Parm, index, cache, ctx):
    try:
        cracked = try_crack(chunk, idx, logical, parm, index, cache)
        if cracked is not None:
            mode, state = cracked
            rec = Rec(chunk.type, chunk.flags, chunk.transform, len(logical), mode)
            if reconstruct(rec, state, parm, ctx) == logical:
                return mode, state
    except Exception:
        pass
    return MODE_RAW, raw_fallback(logical)


def compress(blob: bytes) -> bytes:
    chunks = parse_chunks(blob)
    parm_chunk = next(c for c in chunks if c.type == b"PARM")
    parm_raw = invert(parm_chunk)[:128]
    parm = Parm.from_bytes(parm_raw)

    logicals = [invert(c) for c in chunks]
    index: dict[bytes, list[int]] = {}
    for i, lg in enumerate(logicals):
        index.setdefault(lg[:32], []).append(i)

    layout = [len(c.payload) for c in chunks]
    ctx = {"layout": layout, "cache": {i: lg for i, lg in enumerate(logicals)}}

    records: list[tuple[Chunk, int, int]] = []
    states: list[bytes] = []
    for i, chunk in enumerate(chunks):
        mode, state = compress_chunk(
            chunk, i, logicals[i], parm, index, logicals, ctx
        )
        records.append((chunk, len(logicals[i]), mode))
        states.append(state)

    meta = bytearray(struct.pack("<H", len(records)))
    for (chunk, length, mode), state in zip(records, states):
        meta += struct.pack(
            "<4sBBIB", chunk.type, chunk.flags, chunk.transform, length, mode
        )
        meta += varint(len(state))
    meta += blob[16:48]
    meta_z = lz(bytes(meta))
    return b"UJP1" + struct.pack("<I", len(meta_z)) + meta_z + parm_raw + b"".join(states)


def compress_input(data: bytes) -> bytes:
    wrap = 0 if data.startswith(MAGIC) else 1
    return bytes([wrap]) + compress(unwrap_input(data))


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args:
        return 2
    if args[0] == "--compress":
        src, dst = args[1], args[2]
        Path(dst).write_bytes(compress_input(Path(src).read_bytes()))
        return 0
    if args[0] == "--decompress":
        from .decompress import decompress_output
        src, dst = args[1], args[2]
        Path(dst).write_bytes(decompress_output(Path(src).read_bytes()))
        return 0
    src, dst = args
    Path(dst).write_bytes(compress_input(Path(src).read_bytes()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
