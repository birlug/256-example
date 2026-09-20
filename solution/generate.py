import hashlib
import math
import struct
from array import array
from dataclasses import dataclass
from itertools import accumulate
from math import isqrt

from .codec import _ADD_CLR1, pack_u32s

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
XORSHIFT_MULT = 0x2545F4914F6CDD1D
LCG_MULT = 6364136223846793005
MT_TWIST = 0x9908B0DF
SPLIT_GAMMA = 0x9E3779B97F4A7C15
IMG_W = 2048
SEQ2_NAMES = [
    "recaman", "hofq", "collatz", "primegaps", "kolakoski", "partitions",
    "unused", "linrec",
]
CA_RULES = (30, 45, 110, 150, 30, 90, 30, 105)
IRRATIONALS = (2, 3, 5, 7)


@dataclass(frozen=True, slots=True)
class Parm:
    img_seed: int
    img_step: int
    wave_f1: int
    wave_f2: int
    wave_f3: int
    wave_amp: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Parm":
        v = struct.unpack(">32I", raw[:128])
        return cls(v[0], v[1], v[5], v[6], v[7], v[8])


def splitmix64(x: int) -> int:
    x = (x + SPLIT_GAMMA) & M64
    z = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


def van_eck(start: int, n: int) -> array:
    last = array("q", bytes(8 * (n + start + 8)))
    seen = bytearray(n + start + 8)
    out = array("I", bytes(4 * n))
    cur = start
    for i in range(n):
        out[i] = cur
        nxt = i - last[cur] if seen[cur] else 0
        seen[cur] = 1
        last[cur] = i
        cur = nxt
    return out


def encode_van_eck(flags: int, n: int) -> bytes:
    enc, start = flags & 7, (flags >> 3) & 31
    if enc == 0:
        return pack_u32s(van_eck(start, n // 4))
    if enc == 1:
        seq = van_eck(start, n // 2)
        return b"".join(struct.pack("<H", v & 0xFFFF) for v in seq)
    if enc == 2:
        terms = (n // 3) * 2
        seq = van_eck(start, terms)
        out = bytearray()
        for i in range(0, terms, 2):
            a, b = seq[i] & 0xFFF, seq[i + 1] & 0xFFF
            out += bytes([a & 0xFF, ((a >> 8) & 0x0F) | ((b & 0x0F) << 4), (b >> 4) & 0xFF])
        return bytes(out[:n].ljust(n, b"\x00"))
    seq = van_eck(start, n // 4 + 1)
    return b"".join(struct.pack("<i", seq[i + 1] - seq[i]) for i in range(n // 4))


def ca_rows(rule: int, width_bits: int, row0: int, nrows: int) -> list[int]:
    mask = (1 << width_bits) - 1
    top = width_bits - 1
    cur = row0 & mask
    rows = [cur]
    patterns = [p for p in range(8) if (rule >> p) & 1]
    for _ in range(nrows - 1):
        left = ((cur << 1) | (cur >> top)) & mask
        right = ((cur >> 1) | ((cur & 1) << top)) & mask
        nl, nc, nr = left ^ mask, cur ^ mask, right ^ mask
        nxt = 0
        for p in patterns:
            t = left if (p & 4) else nl
            t &= cur if (p & 2) else nc
            t &= right if (p & 1) else nr
            nxt |= t
        cur = nxt & mask
        rows.append(cur)
    return rows


def encode_ca(flags: int, state: bytes, n: int) -> bytes:
    rule = CA_RULES[flags & 7]
    width = 256
    wbits = width * 8
    row0 = (1 << (wbits // 2)) if state[0] == 0 else int.from_bytes(state[1:1 + width], "big")
    rows = ca_rows(rule, wbits, row0, n // width)
    return b"".join(r.to_bytes(width, "big") for r in rows)


def xorshift_step(x: int) -> int:
    x ^= x >> 12
    x = (x ^ ((x << 25) & M64)) & M64
    x ^= x >> 27
    return x


def xorshift_from_first_output(out0: int, count: int) -> bytes:
    inv = pow(XORSHIFT_MULT, -1, 1 << 64)
    x = (out0 * inv) & M64
    out = bytearray()
    for _ in range(count):
        out += ((x * XORSHIFT_MULT) & M64).to_bytes(8, "little")
        x = xorshift_step(x)
    return bytes(out)


def lcg_from_first_output(out0: int, count: int) -> bytes:
    out = bytearray()
    x = out0 & M64
    for _ in range(count):
        out += x.to_bytes(8, "little")
        x = (x * LCG_MULT + 1442695040888963407) & M64
    return bytes(out)


def encode_prng(flags: int, state: bytes, n: int) -> bytes:
    out0 = int.from_bytes(state[:8], "little")
    if (flags & 3) == 1:
        return lcg_from_first_output(out0, n // 8)[:n]
    return xorshift_from_first_output(out0, n // 8)[:n]


def _unshift_right(y: int, s: int) -> int:
    x = y
    for _ in range(32 // s + 1):
        x = y ^ (x >> s)
    return x & M32


def _unshift_left(y: int, s: int, mask: int) -> int:
    x = y
    for _ in range(32 // s + 1):
        x = y ^ ((x << s) & mask)
    return x & M32


def untemper(y: int) -> int:
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    return _unshift_right(y, 11)


class MT19937:
    def __init__(self, words: list[int]):
        self.mt = list(words)
        self.idx = 0

    def _twist(self) -> None:
        mt = self.mt
        for i in range(624):
            y = (mt[i] & 0x80000000) | (mt[(i + 1) % 624] & 0x7FFFFFFF)
            n = mt[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                n ^= MT_TWIST
            mt[i] = n
        self.idx = 0

    def u32(self) -> int:
        if self.idx >= 624:
            self._twist()
        y = self.mt[self.idx]
        self.idx += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        return (y ^ (y >> 18)) & M32

    def stream(self, count: int) -> bytes:
        out = bytearray()
        for _ in range(count):
            out += self.u32().to_bytes(4, "little")
        return bytes(out)


def encode_mtst(state: bytes, n: int) -> bytes:
    words = list(struct.unpack("<624I", state))
    return MT19937(words).stream(n // 4)[:n]


def mtst_state(logical: bytes) -> bytes:
    words = [untemper(int.from_bytes(logical[i * 4:i * 4 + 4], "little")) for i in range(624)]
    return struct.pack("<624I", *words)


def sha_chain(h0: bytes, count: int) -> bytes:
    out, h = bytearray(), h0
    for _ in range(count):
        out += h
        h = hashlib.sha256(h).digest()
    return bytes(out)


def encode_hash(state: bytes, n: int) -> bytes:
    h0 = hashlib.sha256(b"").digest() if state[0] == 0 else state[1:33]
    return sha_chain(h0, n // 32)[:n]


def irrational_bytes(d: int, n: int) -> bytes:
    v = isqrt(d << (16 * n))
    return (v & ((1 << (8 * n)) - 1)).to_bytes(n, "big")


def bytebeat(formula: int, n: int) -> bytes:
    out = bytearray(n)
    if formula == 0:
        for t in range(n):
            out[t] = (t * (t >> 8 | t >> 9) & 46 & t >> 8) & 0xFF
    elif formula == 1:
        for t in range(n):
            out[t] = ((t >> 6 | t | t >> (t >> 16)) * 10 + ((t >> 11) & 7)) & 0xFF
    else:
        for t in range(n):
            out[t] = (t * (((t >> 12) | (t >> 8)) & (63 & (t >> 4)))) & 0xFF
    return bytes(out)


def recaman(n: int) -> array:
    out = array("I", bytes(4 * n))
    seen, cur = {0}, 0
    for i in range(n):
        out[i] = cur & M32
        nxt = cur - (i + 1)
        if nxt < 0 or nxt in seen:
            nxt = cur + (i + 1)
        seen.add(nxt)
        cur = nxt
    return out


def hofstadter_q(n: int) -> array:
    q = array("I", bytes(4 * (n + 2)))
    q[0] = q[1] = 1
    for i in range(2, n):
        q[i] = (q[i - q[i - 1]] if i - q[i - 1] >= 0 else 1) + (
            q[i - q[i - 2]] if i - q[i - 2] >= 0 else 1)
    return q[:n]


def collatz_lengths(n: int) -> array:
    memo = array("I", bytes(4 * (n + 1)))
    for i in range(2, n + 1):
        c, steps = i, 0
        while c != 1 and not (c <= n and memo[c]):
            c = c >> 1 if not c & 1 else 3 * c + 1
            steps += 1
        memo[i] = steps + (memo[c] if c <= n else 0)
    return memo


def prime_gaps(count: int) -> bytes:
    limit = max(1000, int(count * 16) + 1000)
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            sieve[p * p::p] = bytearray(len(sieve[p * p::p]))
    out, prev = bytearray(), None
    for p in range(2, limit):
        if sieve[p]:
            if prev is not None:
                g = p - prev
                out.append(g if g < 256 else 255)
                if len(out) >= count:
                    break
            prev = p
    return bytes(out[:count])


def kolakoski_bits(nbytes: int) -> bytes:
    n = nbytes * 8
    seq = bytearray([1, 2, 2])
    i = 2
    while len(seq) < n:
        seq.extend([1 if len(seq) % 2 == 0 else 2] * seq[i])
        i += 1
    out = bytearray(nbytes)
    for i in range(nbytes):
        v = 0
        for j in range(8):
            v = (v << 1) | (seq[i * 8 + j] - 1)
        out[i] = v
    return bytes(out)


def partitions_mod(n: int) -> array:
    p = array("I", bytes(4 * (n + 1)))
    p[0] = 1
    for i in range(1, n + 1):
        total, k = 0, 1
        while True:
            g1 = k * (3 * k - 1) // 2
            g2 = k * (3 * k + 1) // 2
            if g1 > i and g2 > i:
                break
            s = 1 if k % 2 else -1
            if g1 <= i:
                total += s * p[i - g1]
            if g2 <= i:
                total += s * p[i - g2]
            k += 1
        p[i] = total & M32
    return p


def linear_recurrence(coeffs, init, n: int) -> array:
    k = len(coeffs)
    out = array("I", bytes(4 * n))
    for i in range(min(k, n)):
        out[i] = init[i] & M32
    for i in range(k, n):
        acc = 0
        for j in range(k):
            acc += coeffs[j] * out[i - 1 - j]
        out[i] = acc & M32
    return out


def solve_linrec(terms: list[int], k: int = 4):
    if len(terms) < k + k + 4:
        return None
    mod = 1 << 32
    mat = [[terms[i - 1 - j] for j in range(k)] + [terms[i]]
           for i in range(k, min(len(terms), k + 16))]
    used = [False] * len(mat)
    pivots = []
    for col in range(k):
        pr = next((r for r in range(len(mat)) if not used[r] and mat[r][col] & 1), None)
        if pr is None:
            return None
        used[pr] = True
        inv = pow(mat[pr][col], -1, mod)
        mat[pr] = [(v * inv) % mod for v in mat[pr]]
        for r in range(len(mat)):
            if r != pr and mat[r][col]:
                f = mat[r][col]
                mat[r] = [(a - f * b) % mod for a, b in zip(mat[r], mat[pr])]
        pivots.append((col, pr))
    coeffs = [0] * k
    for col, pr in pivots:
        coeffs[col] = mat[pr][k]
    return coeffs


def encode_seq2(flags: int, state: bytes, n: int) -> bytes:
    name = SEQ2_NAMES[flags & 7]
    off = ((flags >> 3) & 3) * 4096
    if name == "recaman":
        s = recaman(n // 4 + off)
        return pack_u32s(s[i] for i in range(off, off + n // 4))
    if name == "hofq":
        s = hofstadter_q(n // 4 + off + 2)
        return pack_u32s(s[i] & M32 for i in range(off, off + n // 4))
    if name == "collatz":
        s = collatz_lengths(n // 4 + off + 1)
        return pack_u32s(s[i] for i in range(off, off + n // 4))
    if name == "primegaps":
        return prime_gaps(n + off)[off:off + n]
    if name == "kolakoski":
        return kolakoski_bits(n + off)[off:off + n]
    if name == "partitions":
        s = partitions_mod(n // 4 + off)
        return pack_u32s(s[i] for i in range(off, off + n // 4))
    coeffs = list(struct.unpack("<4I", state[:16]))
    init = list(struct.unpack("<4I", state[16:32]))
    return pack_u32s(linear_recurrence(coeffs, init, n // 4))


def walk_table(seed: int, n: int, step: int, nonzero: bool = False) -> bytes:
    x = seed | 1
    steps = bytearray(n)
    span = 2 * step if nonzero else 2 * step + 1
    for i in range(n):
        x = splitmix64(x)
        d = x % span
        if nonzero:
            d = d - step if d < step else d - step + 1
        else:
            d -= step
        steps[i] = d & 0xFF
    return bytes(v & 0xFF for v in accumulate(steps))


def image_skeleton(parm: Parm, rows: int, channels: int) -> bytes:
    w = IMG_W
    seed = parm.img_seed
    step = 1 + (parm.img_step % 3)
    planes = []
    for ch in range(channels):
        fx = walk_table(seed ^ (0x9E37 * (ch + 1)), w, step)
        fy = walk_table(seed ^ (0xC2B2 * (ch + 1)), rows, 2, nonzero=True)
        warp = walk_table(seed ^ (0x27D4 * (ch + 1)), rows, 3, nonzero=True)
        rows_out = []
        for y in range(rows):
            sh = warp[y] * (w // 256) % w
            rows_out.append((fx[sh:] + fx[:sh]).translate(_ADD_CLR1[fy[y]]))
        planes.append(rows_out)
    if channels == 1:
        return b"".join(planes[0])
    out = bytearray()
    for y in range(rows):
        row = bytearray(w * channels)
        for ch in range(channels):
            row[ch::channels] = planes[ch][y]
        out += row
    return bytes(out)


def wave_skeleton(parm: Parm, samples: int) -> bytes:
    f1, f2, f3, amp = parm.wave_f1, parm.wave_f2, parm.wave_f3, parm.wave_amp
    sine = [int(math.sin(i * math.pi / 512) * 8192) for i in range(1024)]
    out = bytearray()
    for i in range(samples):
        v = (sine[(i * f1 >> 3) & 1023] + sine[(i * f2 >> 4) & 1023]
             + sine[(i * f3 >> 5) & 1023]) * amp >> 8
        out += struct.pack("<h", max(-32768, min(32767, v)) & ~0x3 | 0)
    return bytes(out)
