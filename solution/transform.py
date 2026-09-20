import hashlib

from .codec import ramp_add, ramp_sub, xor_bytes
from .file_format import Chunk

STRIDES = (2, 3, 4, 7)


def tile(key: bytes, n: int) -> bytes:
    return (key * (-(-n // len(key))))[:n]


def xform_mask(type_id: bytes, xform: int, length: int, n: int) -> bytes:
    seed = hashlib.sha256(type_id + bytes([xform]) + length.to_bytes(4, "big")).digest()
    key, counter = b"", 0
    while len(key) < 251:
        key += hashlib.sha256(seed + counter.to_bytes(2, "big")).digest()
        counter += 1
    return tile(key[:251], n)


def interleave(data: bytes, stride: int) -> bytes:
    part = len(data) // stride
    out = bytearray(len(data))
    for k in range(stride):
        out[k::stride] = data[k * part:(k + 1) * part]
    return bytes(out)


def deinterleave(data: bytes, stride: int) -> bytes:
    part = len(data) // stride
    out = bytearray(len(data))
    for k in range(stride):
        out[k * part:(k + 1) * part] = data[k::stride]
    return bytes(out)


def cumsum(data: bytes) -> bytes:
    total, out = 0, bytearray(len(data))
    for i, b in enumerate(data):
        total = (total + b) & 0xFF
        out[i] = total
    return bytes(out)


def undiff(data: bytes) -> bytes:
    prev, out = 0, bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = (b - prev) & 0xFF
        prev = b
    return bytes(out)


def apply(xform: int, data: bytes, type_id: bytes) -> bytes:
    kind, param = xform & 7, xform >> 3
    if kind == 0:
        return data
    if kind == 1:
        return xor_bytes(data, xform_mask(type_id, xform, len(data), len(data)))
    if kind == 2:
        return ramp_add(data)
    if kind == 3:
        return interleave(data, STRIDES[param & 3])
    if kind == 4:
        return data[::-1]
    if kind == 5:
        return cumsum(data)
    raise ValueError(xform)


def invert(chunk: Chunk) -> bytes:
    xform, data, type_id = chunk.transform, chunk.payload, chunk.type
    kind, param = xform & 7, xform >> 3
    if kind == 0:
        return data
    if kind == 1:
        return xor_bytes(data, xform_mask(type_id, xform, len(data), len(data)))
    if kind == 2:
        return ramp_sub(data)
    if kind == 3:
        return deinterleave(data, STRIDES[param & 3])
    if kind == 4:
        return data[::-1]
    if kind == 5:
        return undiff(data)
    raise ValueError(xform)
