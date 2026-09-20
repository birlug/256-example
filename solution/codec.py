import lzma
import struct

_ADD_TBL = [bytes(((i + r) & 0xFF) for i in range(256)) for r in range(256)]
_SUB_TBL = [bytes(((i - r) & 0xFF) for i in range(256)) for r in range(256)]
_ADD_CLR1 = [bytes((((i + c) & 0xFF) & 0xFE) for i in range(256)) for c in range(256)]
_BIT_SET = [bytes(((1 << (7 - j)) if (i & 1) else 0) for i in range(256)) for j in range(8)]
_BIT_GET = [bytes((1 if (i >> (7 - j)) & 1 else 0) for i in range(256)) for j in range(8)]

LZ_FILTERS = [{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME}]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def ramp_add(data: bytes) -> bytes:
    out = bytearray(data)
    for r in range(256):
        sl = out[r::256]
        if not sl:
            break
        out[r::256] = sl.translate(_ADD_TBL[r])
    return bytes(out)


def ramp_sub(data: bytes) -> bytes:
    out = bytearray(data)
    for r in range(256):
        sl = out[r::256]
        if not sl:
            break
        out[r::256] = sl.translate(_SUB_TBL[r])
    return bytes(out)


def pack_lsb(data: bytes) -> bytes:
    pad = (-len(data)) % 8
    if pad:
        data = data + b"\x00" * pad
    acc = 0
    for j in range(8):
        acc |= int.from_bytes(data[j::8].translate(_BIT_SET[j]), "big")
    return acc.to_bytes(len(data) // 8, "big")


def unpack_lsb(packed: bytes) -> bytes:
    out = bytearray(len(packed) * 8)
    for j in range(8):
        out[j::8] = packed.translate(_BIT_GET[j])
    return bytes(out)


def lz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=LZ_FILTERS)


def unlz(data: bytes) -> bytes:
    return lzma.decompress(data, format=lzma.FORMAT_RAW, filters=LZ_FILTERS)


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def sparse_encode(data: bytes) -> bytes:
    out = bytearray()
    prev = -1
    for i, b in enumerate(data):
        if b:
            base = i * 8
            for j in range(8):
                if (b >> (7 - j)) & 1:
                    pos = base + j
                    out += varint(pos - prev - 1)
                    prev = pos
    return bytes(out)


def sparse_decode(blob: bytes, n: int) -> bytes:
    out = bytearray(n)
    pos, prev = 0, -1
    while pos < len(blob):
        gap, pos = _read_varint(blob, pos)
        bit = prev + 1 + gap
        out[bit >> 3] |= 1 << (7 - (bit & 7))
        prev = bit
    return bytes(out)


def read_varint(buf: bytes, pos: int):
    return _read_varint(buf, pos)


def _read_varint(buf: bytes, pos: int):
    shift, val = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7


def logs_delta(data: bytes) -> bytes:
    lines = data.split(b"\n")
    prev = 0
    for i in range(len(lines) - 1):
        ln = lines[i]
        p = 0
        while p < len(ln) and 48 <= ln[p] <= 57:
            p += 1
        if p == 0 or p == len(ln):
            continue
        num = int(ln[:p])
        lines[i] = str(num - prev).encode() + ln[p:]
        prev = num
    return b"\n".join(lines)


def logs_undelta(data: bytes) -> bytes:
    lines = data.split(b"\n")
    prev = 0
    for i in range(len(lines) - 1):
        ln = lines[i]
        p = 1 if (ln[:1] == b"-") else 0
        while p < len(ln) and 48 <= ln[p] <= 57:
            p += 1
        if p == 0 or p == len(ln):
            continue
        num = prev + int(ln[:p])
        lines[i] = str(num).encode() + ln[p:]
        prev = num
    return b"\n".join(lines)


def filter_up(data: bytes, rowlen: int) -> bytes:
    out = bytearray(data[:rowlen])
    for off in range(rowlen, len(data), rowlen):
        prev = data[off - rowlen:off]
        cur = data[off:off + rowlen]
        out += bytes((x - y) & 0xFF for x, y in zip(cur, prev))
    return bytes(out)


def unfilter_up(data: bytes, rowlen: int) -> bytes:
    out = bytearray(data[:rowlen])
    for off in range(rowlen, len(data), rowlen):
        prev = bytes(out[off - rowlen:off])
        cur = data[off:off + rowlen]
        out += bytes((x + y) & 0xFF for x, y in zip(cur, prev))
    return bytes(out)


def pack_u32s(values) -> bytes:
    return b"".join(struct.pack("<I", v) for v in values)
