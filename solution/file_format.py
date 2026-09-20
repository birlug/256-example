import base64
import struct
from dataclasses import dataclass

MAGIC = b"UNCLEJACKIE"
HEADER_SIZE = 80
CHUNK_PREFIX = struct.Struct(">I 4s B B")
CHUNK_OVERHEAD = CHUNK_PREFIX.size + 4


@dataclass(frozen=True, slots=True)
class Chunk:
    type: bytes
    flags: int
    transform: int
    payload: bytes


def unwrap_input(data: bytes) -> bytes:
    if data.startswith(MAGIC):
        return data
    return base64.b64decode(data)


def parse_chunks(blob: bytes) -> list[Chunk]:
    chunks: list[Chunk] = []
    pos = HEADER_SIZE
    while pos < len(blob):
        length, type_id, flags, transform = CHUNK_PREFIX.unpack_from(blob, pos)
        payload_at = pos + CHUNK_PREFIX.size
        payload = blob[payload_at:payload_at + length]
        chunks.append(Chunk(type_id, flags, transform, payload))
        pos += CHUNK_OVERHEAD + length
    return chunks
