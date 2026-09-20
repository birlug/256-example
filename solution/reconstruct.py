import hashlib
import struct
from dataclasses import dataclass

from .codec import (
    filter_up,
    logs_delta,
    logs_undelta,
    lz,
    pack_lsb,
    ramp_add,
    ramp_sub,
    sparse_decode,
    sparse_encode,
    unfilter_up,
    unlz,
    unpack_lsb,
    xor_bytes,
)
from .file_format import CHUNK_OVERHEAD, HEADER_SIZE, Chunk
from .generate import (
    IMG_W,
    IRRATIONALS,
    Parm,
    bytebeat,
    encode_ca,
    encode_hash,
    encode_mtst,
    encode_prng,
    encode_seq2,
    encode_van_eck,
    image_skeleton,
    irrational_bytes,
    mtst_state,
    solve_linrec,
    wave_skeleton,
)

MODE_RAW = 0
MODE_GEN = 1
MODE_STATE = 2
MODE_RESID = 3
MODE_SPARSE = 4
MODE_LOGS = 5
MODE_FILTER = 6
MODE_TOC = 7
MODE_DUP = 8


@dataclass(frozen=True, slots=True)
class Rec:
    type: bytes
    flags: int
    transform: int
    length: int
    mode: int


def try_crack(chunk: Chunk, idx: int, logical: bytes, parm: Parm, index, cache):
    n, flags = len(logical), chunk.flags
    t = chunk.type

    if t == b"TOC ":
        return MODE_TOC, b""
    if t == b"PARM":
        return MODE_RAW, b"\xff" + logical
    if t == b"A181":
        return MODE_GEN, b""
    if t == b"CNST":
        return MODE_GEN, b""
    if t == b"CA30":
        width = 256
        row0 = logical[:width]
        single = (1 << (width * 8 // 2)).to_bytes(width, "big")
        return (MODE_STATE, b"\x00") if row0 == single else (MODE_STATE, b"\x01" + row0)
    if t == b"PRNG":
        return MODE_STATE, logical[:8]
    if t == b"MTST":
        return MODE_STATE, mtst_state(logical)
    if t == b"HASH":
        h0 = logical[:32]
        if h0 == hashlib.sha256(b"").digest():
            return MODE_STATE, b"\x00"
        return MODE_STATE, b"\x01" + h0
    if t == b"SEQ2":
        if (flags & 7) == 7:
            terms = [int.from_bytes(logical[i * 4:i * 4 + 4], "little")
                     for i in range(min(24, n // 4))]
            coeffs = solve_linrec(terms)
            if coeffs is None:
                return None
            return MODE_STATE, struct.pack("<4I", *coeffs) + logical[:16]
        return MODE_GEN, b""
    if t == b"WAVE":
        if (flags % 6) < 3:
            return MODE_GEN, b""
        skel = wave_skeleton(parm, n // 2)
        lsb = xor_bytes(skel, logical[:len(skel)])
        if any(b > 1 for b in lsb[:4096]):
            return None
        return MODE_RESID, lz(pack_lsb(lsb))
    if t == b"IMG ":
        if flags == 2:
            rows = n // IMG_W
            return MODE_FILTER, lz(filter_up(logical[:rows * IMG_W], IMG_W))
        channels = 1 if flags == 0 else 3
        rowlen = IMG_W * channels
        rows = n // rowlen
        skel = image_skeleton(parm, rows, channels)[:rows * rowlen]
        lsb = xor_bytes(skel, logical[:len(skel)])
        if any(b > 1 for b in lsb[:4096]):
            return None
        return MODE_RESID, lz(pack_lsb(lsb))
    if t == b"SPRS":
        return MODE_SPARSE, lz(sparse_encode(logical))
    if t == b"LOGS":
        return MODE_LOGS, lz(logs_delta(logical))
    if t == b"RAND":
        return MODE_RAW, b"\xff" + logical
    if t == b"DUP ":
        for dmode, cand in ((0, xor_bytes(logical, b"\x5a" * n)),
                            (1, logical[::-1]),
                            (2, ramp_sub(logical))):
            for src_idx in index.get(cand[:32], ()):
                if src_idx < idx and cache[src_idx][:n] == cand:
                    return MODE_DUP, struct.pack("<HB", src_idx, dmode)
        return None
    return None


def reconstruct(rec: Rec, state: bytes, parm: Parm, ctx: dict) -> bytes:
    t, n, flags = rec.type, rec.length, rec.flags
    mode = rec.mode

    if mode == MODE_RAW:
        return unlz(state) if state[:1] != b"\xff" else state[1:]
    if mode == MODE_TOC:
        offs, pos = [], HEADER_SIZE
        for length in ctx["layout"]:
            offs.append(pos)
            pos += CHUNK_OVERHEAD + length
        return b"".join(struct.pack(">I", o) for o in offs)[:n].ljust(n, b"\x00")
    if mode == MODE_DUP:
        src_idx, dmode = struct.unpack("<HB", state)
        src = ctx["cache"][src_idx][:n]
        if dmode == 0:
            return xor_bytes(src, b"\x5a" * len(src))
        if dmode == 1:
            return src[::-1]
        return ramp_add(src)
    if t == b"A181":
        return encode_van_eck(flags, n)
    if t == b"CA30":
        return encode_ca(flags, state, n)
    if t == b"PRNG":
        return encode_prng(flags, state, n)
    if t == b"MTST":
        return encode_mtst(state, n)
    if t == b"HASH":
        return encode_hash(state, n)
    if t == b"CNST":
        return irrational_bytes(IRRATIONALS[flags & 3], n)
    if t == b"SEQ2":
        return encode_seq2(flags, state, n)
    if t == b"WAVE":
        if (flags % 6) < 3:
            return bytebeat(flags % 6, n)
        skel = wave_skeleton(parm, n // 2)
        lsb = unpack_lsb(unlz(state))[:len(skel)]
        return xor_bytes(skel, lsb)[:n].ljust(n, b"\x00")
    if t == b"IMG ":
        if flags == 2:
            return unfilter_up(unlz(state), IMG_W).ljust(n, b"\x00")[:n]
        channels = 1 if flags == 0 else 3
        rowlen = IMG_W * channels
        rows = n // rowlen
        skel = image_skeleton(parm, rows, channels)[:rows * rowlen]
        lsb = unpack_lsb(unlz(state))[:len(skel)]
        return xor_bytes(skel, lsb).ljust(n, b"\x00")[:n]
    if t == b"SPRS":
        return sparse_decode(unlz(state), n)
    if t == b"LOGS":
        return logs_undelta(unlz(state))
    return unlz(state)


def raw_fallback(logical: bytes) -> bytes:
    packed = lz(logical)
    return packed if len(packed) < len(logical) else b"\xff" + logical
