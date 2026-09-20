import base64
import hashlib
import struct
import zlib

from .codec import read_varint, unlz
from .file_format import HEADER_SIZE, MAGIC
from .generate import Parm
from .reconstruct import Rec, reconstruct
from .transform import apply


def decompress(packed: bytes) -> bytes:
    mlen = struct.unpack_from("<I", packed, 4)[0]
    meta = unlz(packed[8:8 + mlen])
    pos = 8 + mlen
    parm_raw = packed[pos:pos + 128]
    pos += 128
    parm = Parm.from_bytes(parm_raw)

    n = struct.unpack_from("<H", meta, 0)[0]
    mp = 2
    recs: list[Rec] = []
    slens: list[int] = []
    for _ in range(n):
        type_id, flags, xform, length, mode = struct.unpack_from("<4sBBIB", meta, mp)
        mp += 11
        slen, mp = read_varint(meta, mp)
        recs.append(Rec(type_id, flags, xform, length, mode))
        slens.append(slen)
    keyblob = meta[mp:mp + 16]
    params = struct.unpack_from(">4I", meta, mp + 16)

    ctx = {"layout": [r.length for r in recs], "cache": {}}
    out = bytearray(
        MAGIC + bytes([1]) + struct.pack(">HH", len(recs), 1) + keyblob
        + struct.pack(">4I", *params) + b"\x00" * 32
    )

    for i, (rec, slen) in enumerate(zip(recs, slens)):
        state = packed[pos:pos + slen]
        pos += slen
        if rec.type == b"PARM":
            logical = parm_raw
        else:
            logical = reconstruct(rec, state, parm, ctx)
        ctx["cache"][i] = logical
        stored = apply(rec.transform, logical, rec.type)
        hdr = struct.pack(">I4sBB", rec.length, rec.type, rec.flags, rec.transform)
        out += hdr + stored + struct.pack(">I", zlib.crc32(hdr[4:] + stored) & 0xFFFFFFFF)

    out[0x30:0x50] = hashlib.sha256(bytes(out[HEADER_SIZE:])).digest()
    return bytes(out)


def decompress_output(data: bytes) -> bytes:
    blob = decompress(data[1:])
    return base64.b64encode(blob) if data[0] else blob
