#!/usr/bin/env python3
"""Example solution: embed the whole file, never look at the input.

  --compress    writes an empty output (the bytes already live in payload.b64)
  --decompress  dumps payload.b64

This round-trips, but the score is roughly the size of the challenge itself.
"""

import sys
from pathlib import Path

PAYLOAD = Path(__file__).with_name("payload.b64")


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in ("--compress", "--decompress"):
        sys.stderr.write("usage: solution.py --compress|--decompress <in> <out>\n")
        return 2
    mode, _src, dst = argv[1], argv[2], argv[3]
    if mode == "--compress":
        Path(dst).write_bytes(b"")
    else:
        Path(dst).write_bytes(PAYLOAD.read_bytes())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
